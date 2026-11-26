//! Synchronous cipherlog writer (SPEC.md 2, 3, 4). It formats, compresses and encrypts on the calling thread: the
//! reference implementation for samples, tests and the `write` command, not a queue-based app writer (SPEC.md 7:
//! rules 3.1 and 3.2 are about the mobile libraries, so there is no queue and no flush timer here).

use crate::armor::armor;
use crate::errno::errno_name;
use crate::format::{
    FLAG_FINAL, FormatError, HEADER_LEN, MAX_RECORD_PLAINTEXT, VERSION, encode_bundle, encode_header, encrypt_record, hex, random_bytes,
};
use crate::text::{Level, format_line, iso_time, sanitize_name};
use flate2::{Compress, Compression, FlushCompress, Status};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

// ---------- one encrypted file ----------

/// Record encryption, injectable to test crypto failures. `Err` carries the error's type name.
pub type EncryptFn = Rc<dyn Fn(&[u8; 32], &[u8; 16], u32, u8, &[u8]) -> Result<Vec<u8>, String>>;

pub fn default_encrypt() -> EncryptFn {
    Rc::new(|k, id, seq, flags, pt| encrypt_record(k, id, seq, flags, pt).map_err(|_| "FormatError".to_string()))
}

/// One `.cipherlog` file: header, one raw deflate stream (level 6, window 15), records with seq 0, 1, 2 …
///
/// The header and every record come back as bytes from `new`, `flush` and `finish`, for the caller to write.
pub struct FileWriter {
    pub file_id: [u8; 16],
    pub created_at: u64,
    file_key: Zeroizing<[u8; 32]>,
    seq: u32,
    pending: Vec<u8>,
    deflate: Compress,
    finished: bool,
    encrypt: EncryptFn,
    pub bytes_written: u64,
    pub records: u64,
}

/// Why a file operation failed: an I/O error, or a crypto or compression error (by type name).
#[derive(Debug)]
pub enum WriteFail {
    Io(io::Error),
    Crypto(String),
}

impl From<io::Error> for WriteFail {
    fn from(e: io::Error) -> Self {
        WriteFail::Io(e)
    }
}

impl FileWriter {
    /// A new file with a random file key and file id; returns the writer and the 118-byte header.
    pub fn new(
        public_key: &[u8; 32],
        platform: u8,
        process: u8,
        created_at: u64,
        encrypt: Option<EncryptFn>,
    ) -> Result<(FileWriter, Vec<u8>), WriteFail> {
        let crypto = |e: FormatError| WriteFail::Crypto(format!("FormatError: {e}"));
        let file_key = Zeroizing::new(random_bytes::<32>().map_err(crypto)?);
        let file_id = random_bytes::<16>().map_err(crypto)?;
        let header = encode_header(public_key, &file_key, &file_id, created_at, platform, process)
            .map_err(|_| WriteFail::Crypto("FormatError".into()))?;
        let w = FileWriter {
            file_id,
            created_at,
            file_key,
            seq: 0,
            pending: Vec::new(),
            deflate: Compress::new(Compression::new(6), false),
            finished: false,
            encrypt: encrypt.unwrap_or_else(default_encrypt),
            bytes_written: header.len() as u64,
            records: 0,
        };
        Ok((w, header))
    }

    pub fn file_id_hex8(&self) -> String {
        hex(&self.file_id)[..8].to_string()
    }
    pub fn is_finished(&self) -> bool {
        self.finished
    }
    pub fn has_unflushed(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Adds text to the compressed stream; nothing reaches the file until flush.
    pub fn write(&mut self, text: &str) {
        if !self.finished {
            self.pending.extend_from_slice(text.as_bytes());
        }
    }

    fn compress(&mut self, flush: FlushCompress) -> Result<Vec<u8>, WriteFail> {
        let input = std::mem::take(&mut self.pending);
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut consumed = 0;
        loop {
            let (bi, bo) = (self.deflate.total_in(), self.deflate.total_out());
            let st = self.deflate.compress(&input[consumed..], &mut buf, flush).map_err(|_| WriteFail::Crypto("CompressError".into()))?;
            consumed += (self.deflate.total_in() - bi) as usize;
            let produced = (self.deflate.total_out() - bo) as usize;
            out.extend_from_slice(&buf[..produced]);
            let done = match flush {
                FlushCompress::Finish => st == Status::StreamEnd,
                _ => consumed == input.len() && produced < buf.len(),
            };
            if done {
                return Ok(out);
            }
        }
    }

    fn records_for(&mut self, data: &[u8], final_flag: bool) -> Result<Vec<u8>, WriteFail> {
        let mut out = Vec::new();
        let mut off = 0;
        loop {
            let end = data.len().min(off + MAX_RECORD_PLAINTEXT);
            let piece = &data[off..end];
            off = end;
            let last = off >= data.len();
            let flags = if last && final_flag { FLAG_FINAL } else { 0 };
            let rec = (self.encrypt)(&self.file_key, &self.file_id, self.seq, flags, piece).map_err(WriteFail::Crypto)?;
            self.seq = self.seq.checked_add(1).ok_or_else(|| WriteFail::Crypto("SeqExhausted".into()))?;
            self.records += 1;
            self.bytes_written += rec.len() as u64;
            out.extend_from_slice(&rec);
            if last {
                return Ok(out);
            }
        }
    }

    /// Z_SYNC_FLUSH; the bytes produced since the previous record become the next record(s).
    pub fn flush(&mut self) -> Result<Vec<u8>, WriteFail> {
        if self.finished || self.pending.is_empty() {
            return Ok(Vec::new());
        }
        let data = self.compress(FlushCompress::Sync)?;
        if data.is_empty() {
            return Ok(Vec::new());
        }
        self.records_for(&data, false)
    }

    /// Z_FINISH and the `final` record. Nothing can follow.
    pub fn finish(&mut self) -> Result<Vec<u8>, WriteFail> {
        if self.finished {
            return Ok(Vec::new());
        }
        let data = self.compress(FlushCompress::Finish)?;
        self.finished = true;
        let r = self.records_for(&data, true);
        self.file_key.zeroize();
        r
    }

    /// Drops the stream without a final record (simulates a crash; used for samples and tests).
    pub fn abandon(&mut self) {
        self.finished = true;
        self.pending.zeroize();
        self.file_key.zeroize();
    }
}

// ---------- device block ----------

/// A device collector: `Err` carries the error's type name (`<name> · failed <type>`).
pub struct Collector {
    pub name: String,
    pub collect: Box<dyn Fn() -> Result<Vec<String>, String>>,
}

impl Collector {
    pub fn new(name: &str, collect: impl Fn() -> Result<Vec<String>, String> + 'static) -> Self {
        Collector { name: name.to_string(), collect: Box::new(collect) }
    }
}

/// The diagnostics callback: receives the one `cipherlog off: <reason>` line.
pub type Diagnostics = Box<dyn FnMut(&str)>;

/// The scrub hook: `Err` carries the error's type name (`<scrub failed <type>>`).
pub type Scrub = Box<dyn Fn(&str) -> Result<String, String>>;

pub fn device_block_lines(file_id_hex8: &str, platform: u8, process: u8, collectors: &[Collector], scrub: Option<&Scrub>) -> Vec<String> {
    let mut lines = vec![format!("cipherlog {VERSION} · file {file_id_hex8} · platform {platform} · process {process}")];
    for c in collectors {
        match (c.collect)() {
            Ok(texts) => {
                for t in texts {
                    let text = match scrub {
                        None => t,
                        Some(s) => s(&t).unwrap_or_else(|e| format!("<scrub failed {e}>")),
                    };
                    lines.push(format!("{} · {text}", c.name));
                }
            }
            Err(e) => lines.push(format!("{} · failed {e}", c.name)),
        }
    }
    lines
}

// ---------- file operations (injectable for failure tests) ----------

pub struct FileStat {
    pub size: u64,
    pub mtime_ms: i64,
    pub is_directory: bool,
}

fn mtime_ms(m: &fs::Metadata) -> i64 {
    m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_millis() as i64)
}

/// File operations of the writer; every method has the real implementation as its default.
pub trait FileOps {
    /// Creates a new file exclusively with mode 0600 (never opens an existing one).
    fn create(&self, file: &Path) -> io::Result<File> {
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(file)
    }
    fn append(&self, handle: &mut File, data: &[u8]) -> io::Result<()> {
        handle.write_all(data)
    }
    /// Names in a directory; a missing directory is empty.
    fn list(&self, dir: &Path) -> io::Result<Vec<String>> {
        match fs::read_dir(dir) {
            Ok(rd) => Ok(rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(vec![]),
            Err(e) => Err(e),
        }
    }
    fn stat(&self, file: &Path) -> io::Result<FileStat> {
        let m = fs::metadata(file)?;
        Ok(FileStat { size: m.len(), mtime_ms: mtime_ms(&m), is_directory: m.is_dir() })
    }
    /// Removes a file, or a directory with its contents; a missing one is not an error.
    fn remove(&self, file: &Path) -> io::Result<()> {
        let r = match fs::symlink_metadata(file) {
            Ok(m) if m.is_dir() => fs::remove_dir_all(file),
            Ok(_) => fs::remove_file(file),
            Err(e) => Err(e),
        };
        match r {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
    fn mkdirp(&self, dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)
    }
    fn read(&self, file: &Path) -> io::Result<Vec<u8>> {
        fs::read(file)
    }
    /// Writes a new file exclusively with mode 0600.
    fn write_new(&self, file: &Path, data: &[u8]) -> io::Result<()> {
        let mut f = self.create(file)?;
        f.write_all(data)
    }
}

pub struct StdFileOps;
impl FileOps for StdFileOps {}

// ---------- the rotating writer (SPEC 3) ----------

pub const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024;
pub const DEFAULT_MAX_PROCESS_BYTES: u64 = 2 * 1024 * 1024;
pub const DEFAULT_KEEP_FRESH_FOR_MS: i64 = 10 * 60 * 1000;
pub const DEFAULT_MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;
const OPEN_RETRY_MS: i64 = 60 * 1000;
const EXPORT_MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const RECENT_SMALL: usize = 4 * 1024;

/// A name of SPEC.md 3.5: `(process name, createdAt, fileId hex8)`.
pub fn parse_file_name(n: &str) -> Option<(&str, u64, &str)> {
    let stem = n.strip_suffix(".cipherlog")?;
    if stem.len() < 1 + 1 + 13 + 1 + 8 || !stem.is_ascii() {
        return None;
    }
    let (rest, id) = stem.split_at(stem.len() - 8);
    let rest = rest.strip_suffix('-')?;
    let (name, created) = rest.split_at(rest.len().checked_sub(13)?);
    let name = name.strip_suffix('-')?;
    let ok_name = (1..=32).contains(&name.len()) && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c));
    let ok = ok_name && created.bytes().all(|c| c.is_ascii_digit()) && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    ok.then(|| (name, created.parse().unwrap(), id))
}

fn is_export_dir(n: &str) -> bool {
    n.len() == 32 && n.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

pub struct CipherLogConfig {
    pub directory: PathBuf,
    /// Raw X25519 public key.
    pub key: [u8; 32],
    pub platform: u8,
    pub process: u8,
    pub process_name: String,
    pub collectors: Vec<Collector>,
    pub scrub: Option<Scrub>,
    pub diagnostics: Option<Diagnostics>,
    pub max_file_bytes: u64,
    pub max_process_bytes: u64,
    pub keep_fresh_for_ms: i64,
    pub max_bundle_bytes: u64,
    /// Export root that `wipe` clears, in addition to roots used by `export_bundle`.
    pub export_root: Option<PathBuf>,
    /// Clock in ms since the Unix epoch (default: the system clock).
    pub clock: Option<Box<dyn FnMut() -> i64>>,
    pub file_ops: Option<Box<dyn FileOps>>,
    pub encrypt_record: Option<EncryptFn>,
}

impl CipherLogConfig {
    pub fn new(directory: impl Into<PathBuf>, key: [u8; 32], platform: u8, process: u8, process_name: &str) -> Self {
        CipherLogConfig {
            directory: directory.into(),
            key,
            platform,
            process,
            process_name: process_name.to_string(),
            collectors: vec![],
            scrub: None,
            diagnostics: None,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_process_bytes: DEFAULT_MAX_PROCESS_BYTES,
            keep_fresh_for_ms: DEFAULT_KEEP_FRESH_FOR_MS,
            max_bundle_bytes: DEFAULT_MAX_BUNDLE_BYTES,
            export_root: None,
            clock: None,
            file_ops: None,
            encrypt_record: None,
        }
    }
}

struct OpenFile {
    writer: FileWriter,
    handle: File,
    name: String,
    path: PathBuf,
}

pub struct CipherLog {
    c: CipherLogConfig,
    fs: Box<dyn FileOps>,
    clock: Box<dyn FnMut() -> i64>,
    process_name: String,
    current: Option<OpenFile>,
    off: bool,
    closed: bool,
    next_open_at: i64,
    not_written: u64,
    this_run: BTreeSet<String>,
    export_roots: Vec<PathBuf>,
    /// createdAt of the last file this writer opened: a new file takes at least the next millisecond (SPEC 3.5).
    last_created_at: i64,
}

impl CipherLog {
    pub fn new(mut config: CipherLogConfig) -> Self {
        let fs = config.file_ops.take().unwrap_or_else(|| Box::new(StdFileOps));
        let clock = config.clock.take().unwrap_or_else(|| Box::new(now_ms));
        let mut export_roots = vec![];
        if let Some(r) = &config.export_root {
            export_roots.push(r.clone());
        }
        let mut log = CipherLog {
            process_name: sanitize_name(Some(&config.process_name)),
            c: config,
            fs,
            clock,
            current: None,
            off: false,
            closed: false,
            next_open_at: 0,
            not_written: 0,
            this_run: BTreeSet::new(),
            export_roots,
            last_created_at: -1,
        };
        log.try_open();
        log
    }

    pub fn is_on(&self) -> bool {
        !self.off
    }

    /// Path of the file being written, if any.
    pub fn current_path(&self) -> Option<&Path> {
        self.current.as_ref().map(|c| c.path.as_path())
    }

    fn now(&mut self) -> i64 {
        (self.clock)()
    }

    fn diagnostics(&mut self, line: &str) {
        if let Some(d) = self.c.diagnostics.as_mut() {
            d(line);
        }
    }

    fn turn_off(&mut self, reason: &str) {
        if self.off {
            return;
        }
        self.off = true;
        if let Some(mut cur) = self.current.take() {
            cur.writer.abandon();
        }
        self.diagnostics(&format!("cipherlog off: {reason}"));
    }

    fn fail_reason(e: &WriteFail) -> String {
        match e {
            WriteFail::Io(e) => match e.raw_os_error().and_then(errno_name) {
                Some("ENOSPC" | "EDQUOT") => "disk full".into(),
                Some(code) => format!("write failed ({code})"),
                None => format!("write failed ({:?})", e.kind()),
            },
            WriteFail::Crypto(t) => format!("crypto error ({t})"),
        }
    }

    /// Runs file/crypto work on the current file; any failure turns the writer off. Returns false when off.
    fn guarded(&mut self, f: impl FnOnce(&mut OpenFile, &dyn FileOps) -> Result<(), WriteFail>) -> bool {
        if self.off {
            return false;
        }
        let Some(cur) = self.current.as_mut() else { return true };
        match f(cur, self.fs.as_ref()) {
            Ok(()) => true,
            Err(e) => {
                self.turn_off(&Self::fail_reason(&e));
                false
            }
        }
    }

    fn try_open(&mut self) {
        if self.off || self.closed || self.current.is_some() {
            return;
        }
        let clock_now = self.now();
        let now = clock_now.max(self.last_created_at + 1);
        // Built in memory first: the fileId names the file.
        let (mut writer, header) =
            match FileWriter::new(&self.c.key, self.c.platform, self.c.process, now as u64, self.c.encrypt_record.clone()) {
                Ok(w) => w,
                Err(e) => {
                    self.turn_off(&Self::fail_reason(&e));
                    return;
                }
            };
        let name = format!("{}-{:013}-{}.cipherlog", self.process_name, now, writer.file_id_hex8());
        let file = self.c.directory.join(&name);
        let handle = match self.fs.mkdirp(&self.c.directory).and_then(|_| self.fs.create(&file)) {
            Ok(h) => h,
            Err(e) => {
                writer.abandon();
                // SPEC.md 3.6: disk full while opening turns the writer off; anything else is retried a minute later.
                if matches!(e.raw_os_error().and_then(errno_name), Some("ENOSPC" | "EDQUOT")) {
                    self.turn_off("disk full");
                } else {
                    self.next_open_at = clock_now + OPEN_RETRY_MS;
                }
                return;
            }
        };
        self.last_created_at = now;
        self.current = Some(OpenFile { writer, handle, name: name.clone(), path: file.clone() });
        self.this_run.insert(name);
        if !self.guarded(|cur, fs| Ok(fs.append(&mut cur.handle, &header)?)) {
            // The header did not reach the file: leave no empty file behind (readers would see a 0-byte entry).
            let _ = self.fs.remove(&file);
            return;
        }
        let hex8 = self.current.as_ref().unwrap().writer.file_id_hex8();
        for line in device_block_lines(&hex8, self.c.platform, self.c.process, &self.c.collectors, self.c.scrub.as_ref()) {
            self.write_line(now, Level::I, "device", &line);
        }
        if self.not_written > 0 {
            let n = self.not_written;
            self.write_line(now, Level::W, "cipherlog", &format!("not written {n} lines"));
            self.not_written = 0;
        }
        if !self.flush_writer() {
            return;
        }
        self.retention();
    }

    fn write_line(&mut self, time: i64, level: Level, category: &str, message: &str) {
        let line = format_line(time, level, &self.process_name, Some(category), message);
        self.guarded(|cur, _| {
            cur.writer.write(&line);
            Ok(())
        });
    }

    fn flush_writer(&mut self) -> bool {
        self.guarded(|cur, fs| {
            let b = cur.writer.flush()?;
            if !b.is_empty() {
                fs.append(&mut cur.handle, &b)?;
            }
            Ok(())
        })
    }

    /// SPEC.md 3.7: another process's wipe may have deleted the current file; then it is dropped without `final` and a
    /// new file opens.
    fn check_current_exists(&mut self) {
        let gone = match &self.current {
            Some(cur) => matches!(self.fs.stat(&cur.path), Err(e) if e.kind() == io::ErrorKind::NotFound),
            None => false,
        };
        if gone {
            if let Some(mut cur) = self.current.take() {
                cur.writer.abandon();
            }
            self.try_open();
        }
    }

    pub fn log(&mut self, level: Level, category: Option<&str>, message: &str) {
        if self.off || self.closed {
            return;
        }
        if self.current.as_ref().is_some_and(|c| !c.writer.has_unflushed()) {
            self.check_current_exists();
        }
        if self.current.is_none() {
            if self.now() >= self.next_open_at {
                self.try_open();
            }
            if self.off {
                return;
            }
            if self.current.is_none() {
                self.not_written += 1;
                return;
            }
        }
        let text = match &self.c.scrub {
            None => message.to_string(),
            Some(s) => s(message).unwrap_or_else(|e| format!("<scrub failed {e}>")),
        };
        let t = self.now();
        self.write_line(t, level, category.unwrap_or("-"), &text);
        if level >= Level::W {
            self.flush_now();
        }
    }

    fn flush_now(&mut self) {
        if self.current.is_none() || self.off {
            return;
        }
        if !self.flush_writer() {
            return;
        }
        if self.current.as_ref().is_some_and(|c| c.writer.bytes_written >= self.c.max_file_bytes) {
            self.rotate();
        }
    }

    /// Synchronous; the timeout of the API shape is not needed here.
    pub fn flush(&mut self) {
        self.flush_now();
    }

    fn finish_current(&mut self) {
        if self.current.is_none() {
            return;
        }
        self.guarded(|cur, fs| {
            let b = cur.writer.finish()?;
            fs.append(&mut cur.handle, &b)?;
            Ok(())
        });
        if self.off {
            return;
        }
        self.current = None;
    }

    fn rotate(&mut self) {
        self.finish_current();
        if self.off {
            return;
        }
        self.try_open();
    }

    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.flush_now();
        self.finish_current();
        self.closed = true;
    }

    fn files_in(&self, dir: &Path, process_name: Option<&str>) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .fs
            .list(dir)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|n| {
                let (p, created, _) = parse_file_name(&n)?;
                if process_name.is_some_and(|w| w != p) {
                    return None;
                }
                Some((n.clone(), created))
            })
            .collect();
        out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        out
    }

    /// Keeps this process's files under max_process_bytes; never deletes files modified within keep_fresh_for.
    fn retention(&mut self) {
        let files: Vec<(PathBuf, FileStat)> = self
            .files_in(&self.c.directory, Some(&self.process_name))
            .into_iter()
            .filter_map(|(n, _)| {
                let p = self.c.directory.join(n);
                self.fs.stat(&p).ok().map(|s| (p, s))
            })
            .collect();
        let mut total: u64 = files.iter().map(|f| f.1.size).sum();
        let now = self.now();
        let cur = self.current.as_ref().map(|c| c.path.clone());
        for (p, s) in files {
            if total <= self.c.max_process_bytes {
                break;
            }
            if cur.as_ref() == Some(&p) || now - s.mtime_ms < self.c.keep_fresh_for_ms {
                continue;
            }
            if self.fs.remove(&p).is_ok() {
                total -= s.size;
            }
        }
    }

    /// Closes the current file, deletes all cipherlog files of every process and all exports, opens a new file.
    /// After `close` it still deletes but opens nothing; while off it deletes and stays off.
    pub fn wipe(&mut self) {
        self.flush_now();
        self.finish_current();
        for (n, _) in self.files_in(&self.c.directory, None) {
            let _ = self.fs.remove(&self.c.directory.join(n));
        }
        for root in &self.export_roots {
            for n in self.fs.list(root).unwrap_or_default() {
                if is_export_dir(&n) {
                    let _ = self.fs.remove(&root.join(n));
                }
            }
        }
        self.this_run.clear();
        if !self.off {
            self.next_open_at = 0;
            self.try_open();
        }
    }

    /// A fresh in-memory file with only the device block, closed with final.
    fn device_now_file(&mut self) -> Result<Vec<u8>, WriteFail> {
        let now = self.now();
        let (mut w, mut bytes) = FileWriter::new(&self.c.key, self.c.platform, self.c.process, now as u64, self.c.encrypt_record.clone())?;
        for line in device_block_lines(&w.file_id_hex8(), self.c.platform, self.c.process, &self.c.collectors, self.c.scrub.as_ref()) {
            w.write(&format_line(now, Level::I, &self.process_name, Some("device"), &line));
        }
        bytes.extend(w.finish()?);
        Ok(bytes)
    }

    /// Bundle bytes of all files of all processes (newest first until max_bundle_bytes) plus `device now`.
    pub fn build_support_bundle(&mut self) -> Result<Vec<u8>, WriteFail> {
        self.flush_now();
        let device = self.device_now_file()?;
        let mut total = 4 + 4 + device.len() as u64;
        let mut chosen: Vec<Vec<u8>> = vec![];
        for (n, _) in self.files_in(&self.c.directory, None).into_iter().rev() {
            let Ok(bytes) = self.fs.read(&self.c.directory.join(n)) else { continue };
            // A file shorter than a header (another process between create and header write) carries nothing.
            if bytes.len() < HEADER_LEN {
                continue;
            }
            if total + 4 + bytes.len() as u64 > self.c.max_bundle_bytes {
                break;
            }
            total += 4 + bytes.len() as u64;
            chosen.push(bytes);
        }
        chosen.reverse();
        chosen.push(device);
        Ok(encode_bundle(&chosen))
    }

    /// Writes `<root>/<random id>/cipherlog-<UTC yyyyMMdd-HHmm>.cipherlogs` (armored: `.cipherlogs.txt`, SPEC.md 4.1)
    /// and deletes export folders older than 7 days.
    pub fn export_bundle(&mut self, root: &Path, armored: bool) -> Result<PathBuf, WriteFail> {
        if !self.export_roots.iter().any(|r| r == root) {
            self.export_roots.push(root.to_path_buf());
        }
        let now = self.now();
        for n in self.fs.list(root).unwrap_or_default() {
            if !is_export_dir(&n) {
                continue;
            }
            let p = root.join(&n);
            let Ok(s) = self.fs.stat(&p) else { continue };
            if !s.is_directory {
                continue;
            }
            // Age: the newest file inside, or the folder itself when it is empty (SPEC.md 4).
            let inside = self.fs.list(&p).unwrap_or_default();
            let newest = inside.iter().filter_map(|f| self.fs.stat(&p.join(f)).ok()).map(|f| f.mtime_ms).max().unwrap_or(s.mtime_ms);
            if now - newest > EXPORT_MAX_AGE_MS {
                let _ = self.fs.remove(&p);
            }
        }
        let bundle = self.build_support_bundle()?;
        let d = iso_time(now);
        let stamp = format!("{}{}{}-{}{}", &d[0..4], &d[5..7], &d[8..10], &d[11..13], &d[14..16]);
        let dir = root.join(hex(&random_bytes::<16>().map_err(|e| WriteFail::Crypto(e.0))?));
        self.fs.mkdirp(&dir)?;
        let file = if armored {
            let p = dir.join(format!("cipherlog-{stamp}.cipherlogs.txt"));
            self.fs.write_new(&p, armor(&bundle).as_bytes())?;
            p
        } else {
            let p = dir.join(format!("cipherlog-{stamp}.cipherlogs"));
            self.fs.write_new(&p, &bundle)?;
            p
        };
        Ok(file)
    }

    /// The current file after a flush, plus the previous one when the current one is under 4 KiB.
    pub fn recent_bundle(&mut self) -> Vec<u8> {
        if !self.off && !self.closed {
            self.check_current_exists();
        }
        self.flush_now();
        let files = self.files_in(&self.c.directory, Some(&self.process_name));
        let cur_name = self.current.as_ref().map(|c| c.name.clone());
        let idx = match &cur_name {
            Some(n) => files.iter().position(|f| &f.0 == n),
            None => Some(files.len()),
        };
        let cur_bytes = cur_name.as_ref().and_then(|n| self.fs.read(&self.c.directory.join(n)).ok());
        let mut out = vec![];
        if cur_bytes.as_ref().is_none_or(|b| b.len() < RECENT_SMALL)
            && let Some(i) = idx
            && i > 0
            && let Ok(b) = self.fs.read(&self.c.directory.join(&files[i - 1].0))
        {
            out.push(b);
        }
        if let Some(b) = cur_bytes {
            out.push(b);
        }
        encode_bundle(&out)
    }

    /// The newest file of the previous run of this process, or `None`.
    pub fn previous_run_bundle(&self) -> Option<Vec<u8>> {
        let files = self.files_in(&self.c.directory, Some(&self.process_name));
        let last = files.iter().rev().find(|f| !self.this_run.contains(&f.0))?;
        self.fs.read(&self.c.directory.join(&last.0)).ok().map(|b| encode_bundle(&[b]))
    }
}
