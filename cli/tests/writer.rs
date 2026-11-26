// Ported from the writer and review tests of the retired TypeScript CLI.
mod common;

use cipherlog::format::{decode_bundle, encrypt_record, hex, open_header};
use cipherlog::reader::{FileResult, ReadBudget, read_bytes, read_file};
use cipherlog::text::{Level, format_line, sanitize_field, sanitize_name};
use cipherlog::writer::*;
use common::*;
use std::cell::{Cell, RefCell};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, SystemTime};

type Diags = Rc<RefCell<Vec<String>>>;

fn config(dir: &Path) -> (CipherLogConfig, Diags) {
    let diags: Diags = Rc::default();
    let d = diags.clone();
    let mut c = CipherLogConfig::new(dir, pub_key(), 3, 1, "app");
    c.diagnostics = Some(Box::new(move |l| d.borrow_mut().push(l.to_string())));
    c.clock = Some(Box::new(step_clock(T0, 7)));
    (c, diags)
}

fn make(dir: &Path) -> (CipherLog, Diags) {
    let (c, d) = config(dir);
    (CipherLog::new(c), d)
}

fn files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".cipherlog"))
        .collect();
    v.sort();
    v
}

fn read(dir: &Path, n: &str) -> FileResult {
    read_file(&fs::read(dir.join(n)).unwrap(), &key_ring(), n, &mut ReadBudget::default())
}

fn text(r: &FileResult) -> String {
    String::from_utf8(r.text.clone()).unwrap()
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).unwrap();
    hex(&b)
}

fn size(p: &Path) -> u64 {
    fs::metadata(p).unwrap().len()
}

#[test]
fn line_sanitising() {
    assert_eq!(sanitize_field("a\r\nb\rc\nd"), "a\\nb\\nc\\nd");
    assert_eq!(sanitize_name(Some("net/http 2")), "net_http_2");
    assert_eq!(format_line(0, Level::E, "a b", None, "x\ny"), "1970-01-01T00:00:00.000Z E a_b -: x\\ny\n");
}

#[test]
fn device_block_collectors_one_failing_scrub_file_name() {
    let dir = tmp_dir("dev");
    let (mut c, _) = config(&dir);
    c.collectors = vec![
        Collector::new("phone", || Ok(vec!["TestPhone1,1 · TestOS 1.0".into()])),
        Collector::new("app", || Err("ThrowsError".into())),
        Collector::new("empty", || Ok(vec![])),
        Collector::new("after", || Ok(vec!["still here".into()])),
    ];
    c.scrub = Some(Box::new(|s: &str| {
        Ok(match s.find("secret=") {
            Some(i) => {
                let end = s[i + 7..].find(|ch: char| !ch.is_alphanumeric()).map_or(s.len(), |e| i + 7 + e);
                format!("{}secret=<private>{}", &s[..i], &s[end..])
            }
            None => s.to_string(),
        })
    }));
    let mut log = CipherLog::new(c);
    log.log(Level::I, Some("auth"), "token secret=abc123 ok");
    log.log(Level::D, Some("multi"), "one\ntwo");
    log.close();
    let names = files(&dir);
    assert_eq!(names.len(), 1);
    let (p, created, id) = parse_file_name(&names[0]).unwrap();
    assert_eq!(p, "app");
    assert_eq!(created, T0 as u64);
    let r = read(&dir, &names[0]);
    assert_eq!(id, &hex(&r.header.as_ref().unwrap().file_id)[..8]);
    let t = text(&r);
    let lines: Vec<&str> = t.split('\n').collect();
    assert_eq!(lines[0], format!("2026-11-18T11:06:40.000Z I app device: cipherlog 0.1.0-alpha.1 · file {id} · platform 3 · process 1"));
    assert!(lines[1].ends_with(" I app device: phone · TestPhone1,1 · TestOS 1.0"));
    assert!(lines[2].ends_with(" I app device: app · failed ThrowsError"));
    assert!(lines[3].ends_with(" I app device: after · still here"));
    assert!(lines[4].ends_with(" I app auth: token secret=<private> ok"));
    assert!(lines[5].ends_with(" D app multi: one\\ntwo"));
    assert!(r.closed);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::metadata(dir.join(&names[0])).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn a_failing_scrub_writes_its_type_name() {
    let dir = tmp_dir("scrubfail");
    let (mut c, _) = config(&dir);
    c.scrub = Some(Box::new(|_: &str| Err("ScrubError".into())));
    let mut log = CipherLog::new(c);
    log.log(Level::W, Some("x"), "secret");
    log.close();
    let t = text(&read(&dir, &files(&dir)[0]));
    assert!(t.contains(" W app x: <scrub failed ScrubError>\n"));
    assert!(!t.contains("secret"));
}

#[test]
fn never_appends_to_an_existing_file() {
    let dir = tmp_dir("wx");
    let p = dir.join("x.cipherlog");
    fs::write(&p, "old").unwrap();
    assert_eq!(StdFileOps.create(&p).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
}

#[test]
fn new_key_and_seq_0_per_file_a_new_file_at_every_start() {
    let dir = tmp_dir("keys");
    for i in 0..2 {
        let (mut c, _) = config(&dir);
        c.clock = Some(Box::new(step_clock(T0 + i * 1000, 7)));
        let mut log = CipherLog::new(c);
        log.log(Level::W, Some("x"), &format!("run {i}"));
        log.close();
    }
    let names = files(&dir);
    assert_eq!(names.len(), 2);
    let ha = open_header(&fs::read(dir.join(&names[0])).unwrap(), &priv_key()).unwrap();
    let hb = open_header(&fs::read(dir.join(&names[1])).unwrap(), &priv_key()).unwrap();
    assert_ne!(*ha.file_key, *hb.file_key);
    assert_ne!(ha.file_id, hb.file_id);
    for n in &names {
        let bytes = fs::read(dir.join(n)).unwrap();
        assert_eq!(u32::from_be_bytes(bytes[122..126].try_into().unwrap()), 0, "first seq is 0");
        assert_eq!(read(&dir, n).stopped_by, None);
    }
}

#[test]
fn rotation_at_max_file_bytes_old_file_gets_final_all_text_kept_in_order() {
    let dir = tmp_dir("rot");
    let (mut c, _) = config(&dir);
    c.max_file_bytes = 2048;
    c.max_process_bytes = 1 << 30;
    let mut log = CipherLog::new(c);
    for i in 0..300 {
        log.log(if i % 10 == 0 { Level::W } else { Level::I }, Some("loop"), &format!("line {i} {}", random_hex(8)));
    }
    log.close();
    let names = files(&dir);
    assert!(names.len() >= 3, "files: {}", names.len());
    let mut all = vec![];
    for n in &names {
        let r = read(&dir, n);
        assert!(r.closed, "{n}");
        assert_eq!(r.stopped_by, None);
        assert!(size(&dir.join(n)) < 2048 + 4096, "rotation keeps files near the limit");
        all.extend(text(&r).split('\n').filter(|l| l.contains(" loop: ")).map(str::to_string));
    }
    assert_eq!(all.len(), 300);
    for (i, l) in all.iter().enumerate() {
        assert!(l.contains(&format!(" loop: line {i} ")), "{l}");
    }
}

#[test]
fn a_frozen_clock_still_gives_every_new_file_a_later_created_at() {
    let dir = tmp_dir("frozen");
    let (mut c, _) = config(&dir);
    c.max_file_bytes = 512;
    c.max_process_bytes = 1 << 30;
    c.clock = Some(Box::new(|| T0));
    let mut log = CipherLog::new(c);
    for i in 0..60 {
        log.log(Level::W, Some("loop"), &format!("line {i} {}", random_hex(16)));
    }
    log.close();
    let names = files(&dir);
    assert!(names.len() >= 3, "files: {}", names.len());
    for (i, n) in names.iter().enumerate() {
        assert_eq!(parse_file_name(n).unwrap().1, T0 as u64 + i as u64);
        assert_eq!(read(&dir, n).header.unwrap().created_at, T0 as u64 + i as u64);
    }
}

#[test]
fn collector_lines_go_through_scrub() {
    let dir = tmp_dir("cscrub");
    let (mut c, _) = config(&dir);
    c.collectors = vec![Collector::new("acct", || Ok(vec!["user secret=abc".into()]))];
    c.scrub = Some(Box::new(|s: &str| Ok(s.replace("secret=abc", "secret=<private>"))));
    let mut log = CipherLog::new(c);
    log.close();
    let t = text(&read(&dir, &files(&dir)[0]));
    assert!(t.contains(" device: acct · user secret=<private>\n"));
    assert!(!t.contains("abc"));
}

#[test]
fn retention_keeps_the_process_total_under_max_process_bytes_oldest_first() {
    let dir = tmp_dir("ret");
    // Another process in the same directory is never touched.
    let other = dir.join(format!("other-{T0}-00000000.cipherlog"));
    fs::write(&other, vec![0u8; 100_000]).unwrap();
    let (mut c, _) = config(&dir);
    c.max_file_bytes = 4096;
    c.max_process_bytes = 16_384;
    c.clock = Some(Box::new(step_clock(now_ms() + 60 * 60 * 1000, 1)));
    let mut log = CipherLog::new(c);
    for i in 0..2000 {
        log.log(Level::W, Some("r"), &format!("{i} {}", random_hex(18)));
    }
    log.close();
    let mine: Vec<String> = files(&dir).into_iter().filter(|n| n.starts_with("app-")).collect();
    assert!(mine.len() >= 2);
    let total_without_newest: u64 = mine[..mine.len() - 1].iter().map(|n| size(&dir.join(n))).sum();
    assert!(total_without_newest <= 16_384, "total {total_without_newest}");
    assert!(other.exists());
    assert!(text(&read(&dir, mine.last().unwrap())).contains(" r: 1999 "));
}

#[test]
fn retention_never_deletes_files_modified_within_keep_fresh_for() {
    let dir = tmp_dir("fresh");
    let (mut c, _) = config(&dir);
    c.max_file_bytes = 4096;
    c.max_process_bytes = 8192;
    c.clock = Some(Box::new(step_clock(now_ms(), 1)));
    let mut log = CipherLog::new(c);
    for i in 0..600 {
        log.log(Level::W, Some("r"), &format!("{i} {}", random_hex(18)));
    }
    log.close();
    let names = files(&dir);
    let total: u64 = names.iter().map(|n| size(&dir.join(n))).sum();
    assert!(total > 8192 * 2, "all files are fresh, so none was deleted");
    assert!(text(&read(&dir, &names[0])).contains(" r: 0 "));
}

#[test]
fn wipe_deletes_all_files_of_all_processes_and_exports_then_opens_a_new_file() {
    let dir = tmp_dir("wipe");
    let export_root = tmp_dir("wipe-exp");
    let (mut a, _) = make(&dir);
    let mut b = CipherLog::new(CipherLogConfig::new(&dir, pub_key(), 3, 2, "widget"));
    a.log(Level::W, Some("x"), "a before");
    b.log(Level::W, Some("x"), "b before");
    let exported = a.export_bundle(&export_root, false).unwrap();
    assert!(exported.exists());
    let armored = a.export_bundle(&export_root, true).unwrap();
    assert!(armored.to_string_lossy().ends_with(".cipherlogs.txt"));
    fs::write(dir.join("unrelated.txt"), "keep").unwrap();
    fs::create_dir(export_root.join("not-an-export")).unwrap();
    a.wipe();
    let left = files(&dir);
    assert_eq!(left.len(), 1);
    assert!(left[0].starts_with("app-"));
    let roots: Vec<_> = fs::read_dir(&export_root).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(roots, vec![std::ffi::OsString::from("not-an-export")], "only export folders go");
    assert!(dir.join("unrelated.txt").exists());
    a.log(Level::W, Some("x"), "a after");
    a.close();
    let t = text(&read(&dir, &left[0]));
    assert!(t.contains(" device: cipherlog "));
    assert!(t.contains("a after"));
    assert!(!t.contains("before"));
    assert!(a.is_on());
    // The other process's file was deleted under it: its next batch opens a new file (SPEC.md 3.7).
    b.log(Level::W, Some("x"), "b after");
    b.close();
    let widget: Vec<String> = files(&dir).into_iter().filter(|n| n.starts_with("widget-")).collect();
    assert_eq!(widget.len(), 1);
    let wt = read(&dir, &widget[0]);
    assert!(wt.closed);
    assert!(text(&wt).contains("b after") && !text(&wt).contains("b before"));
}

#[test]
fn wipe_after_close_deletes_the_files_and_opens_nothing() {
    let dir = tmp_dir("wipeclosed");
    let (mut log, _) = make(&dir);
    log.log(Level::I, Some("a"), "x");
    log.close();
    assert_eq!(files(&dir).len(), 1);
    log.wipe();
    assert!(files(&dir).is_empty());
}

#[test]
fn export_bundle_round_trip_with_device_now_old_export_folders_deleted() {
    let dir = tmp_dir("exp");
    let root = tmp_dir("exp-root");
    let old = root.join("ab".repeat(16));
    fs::create_dir(&old).unwrap();
    File::open(&old).unwrap().set_modified(SystemTime::now() - Duration::from_secs(8 * 24 * 3600)).unwrap();
    let young = root.join("cd".repeat(16));
    fs::create_dir(&young).unwrap();
    // Age is the newest file inside (SPEC.md 4): an old folder with a fresh file stays, one with old files goes.
    let eight_days_ago = SystemTime::now() - Duration::from_secs(8 * 24 * 3600);
    let old_dir_fresh_file = root.join("ef".repeat(16));
    fs::create_dir(&old_dir_fresh_file).unwrap();
    fs::write(old_dir_fresh_file.join("cipherlog-x.cipherlogs"), b"x").unwrap();
    File::open(&old_dir_fresh_file).unwrap().set_modified(eight_days_ago).unwrap();
    let old_files = root.join("01".repeat(16));
    fs::create_dir(&old_files).unwrap();
    fs::write(old_files.join("cipherlog-y.cipherlogs"), b"y").unwrap();
    File::options().write(true).open(old_files.join("cipherlog-y.cipherlogs")).unwrap().set_modified(eight_days_ago).unwrap();
    File::open(&old_files).unwrap().set_modified(SystemTime::now()).unwrap();
    let (mut c, _) = config(&dir);
    c.clock = Some(Box::new(step_clock(now_ms(), 1)));
    c.collectors = vec![Collector::new("phone", || Ok(vec!["P1".into()]))];
    let mut log = CipherLog::new(c);
    log.log(Level::E, Some("x"), "an error");
    let p = log.export_bundle(&root, false).unwrap();
    assert!(!old.exists());
    assert!(young.exists());
    assert!(old_dir_fresh_file.exists());
    assert!(!old_files.exists());
    let name = p.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with("cipherlog-") && name.ends_with(".cipherlogs") && name.len() == "cipherlog-20261126-1000.cipherlogs".len(),
        "{name}"
    );
    let folder = p.parent().unwrap().file_name().unwrap().to_string_lossy().into_owned();
    assert!(folder.len() == 32 && folder.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    let res = read_bytes(&fs::read(&p).unwrap(), &key_ring(), "e", &mut ReadBudget::default());
    assert_eq!(res.files.len(), 2);
    assert!(text(&res.files[0]).contains("an error"));
    assert!(!res.files[0].closed);
    let dev = &res.files[1];
    assert!(dev.closed);
    let t = text(dev);
    let dev_lines: Vec<&str> = t.trim().split('\n').collect();
    assert_eq!(dev_lines.len(), 2);
    assert!(dev_lines[1].ends_with(" device: phone · P1"));
    // Armored by request: the same bundle as text.
    let a = log.export_bundle(&root, true).unwrap();
    let res = read_bytes(&fs::read(&a).unwrap(), &key_ring(), "a", &mut ReadBudget::default());
    assert!(res.notes.is_empty());
    assert_eq!(res.files.len(), 2);
    log.close();
}

#[test]
fn support_bundle_stays_within_4_mib_dropping_the_oldest_files() {
    let dir = tmp_dir("cap");
    let (mut c, _) = config(&dir);
    c.max_file_bytes = 512 * 1024;
    c.max_process_bytes = 1 << 30;
    c.clock = Some(Box::new(step_clock(now_ms(), 1)));
    let mut log = CipherLog::new(c);
    for i in 0..1800 {
        // Random hex compresses to about half: about 3 KB per line on disk.
        log.log(Level::I, Some("big"), &format!("{i} {}", random_hex(3000)));
        if i % 20 == 0 {
            log.flush();
        }
    }
    log.flush();
    let names = files(&dir);
    let total: u64 = names.iter().map(|n| size(&dir.join(n))).sum();
    assert!(total > 4 * 1024 * 1024, "need more than 4 MiB of files, have {total}");
    let bundle = log.build_support_bundle().unwrap();
    assert!(bundle.len() <= 4 * 1024 * 1024, "bundle {}", bundle.len());
    let ids: Vec<String> = read_bytes(&bundle, &key_ring(), "b", &mut ReadBudget::default())
        .files
        .iter()
        .map(|f| hex(&f.header.as_ref().unwrap().file_id)[..8].to_string())
        .collect();
    let id_of = |n: &str| parse_file_name(n).unwrap().2.to_string();
    assert!(!ids.contains(&id_of(&names[0])), "oldest dropped");
    assert!(ids.contains(&id_of(names.last().unwrap())), "newest kept");
    assert_eq!(decode_bundle(&bundle).files.len(), ids.len());
    log.close();
}

#[test]
fn recent_bundle_current_plus_previous_when_current_is_under_4_kib() {
    let dir = tmp_dir("recent");
    let (mut c, _) = config(&dir);
    c.max_file_bytes = 8192;
    c.max_process_bytes = 1 << 30;
    let mut log = CipherLog::new(c);
    let mut i = 0;
    while i < 400 && files(&dir).len() < 2 {
        log.log(Level::W, Some("x"), &format!("{i} {}", random_hex(16)));
        i += 1;
    }
    log.log(Level::W, Some("x"), "small current");
    let small = read_bytes(&log.recent_bundle(), &key_ring(), "r", &mut ReadBudget::default());
    assert_eq!(small.files.len(), 2);
    assert!(small.files[0].closed);
    assert!(text(&small.files[1]).contains("small current"));
    let cur: PathBuf = log.current_path().unwrap().to_path_buf();
    let mut i = 0;
    while i < 100 && size(&cur) < 4096 {
        for _ in 0..5 {
            log.log(Level::I, Some("x"), &format!("{i} {}", random_hex(32)));
        }
        log.flush();
        i += 1;
    }
    assert_eq!(log.current_path().unwrap(), cur, "no rotation in between");
    assert!(size(&cur) >= 4096);
    let big = read_bytes(&log.recent_bundle(), &key_ring(), "r", &mut ReadBudget::default());
    assert_eq!(big.files.len(), 1);
    log.close();
    // With no open file: the newest file of this process.
    let after = read_bytes(&log.recent_bundle(), &key_ring(), "r", &mut ReadBudget::default());
    assert_eq!(after.files.len(), 1);
    assert!(after.files[0].closed);
}

#[test]
fn previous_run_bundle_the_newest_file_of_the_previous_run() {
    let dir = tmp_dir("prev");
    let (mut first, _) = make(&dir);
    assert!(first.previous_run_bundle().is_none());
    first.log(Level::E, Some("x"), "crashed here");
    first.flush(); // no close: a crash
    std::mem::forget(first);
    let (mut c, _) = config(&dir);
    c.clock = Some(Box::new(step_clock(T0 + 5000, 7)));
    let mut second = CipherLog::new(c);
    let b = second.previous_run_bundle().unwrap();
    let r = read_bytes(&b, &key_ring(), "p", &mut ReadBudget::default());
    assert_eq!(r.files.len(), 1);
    assert!(text(&r.files[0]).contains("crashed here"));
    assert!(!r.files[0].closed);
    second.close();
}

/// File operations that fail on demand.
struct Failing {
    append_error: Rc<Cell<Option<i32>>>,
    create_error: Rc<Cell<Option<i32>>>,
    creates: Rc<Cell<u32>>,
}

impl FileOps for Failing {
    fn create(&self, file: &Path) -> io::Result<File> {
        self.creates.set(self.creates.get() + 1);
        match self.create_error.get() {
            Some(e) => Err(io::Error::from_raw_os_error(e)),
            None => StdFileOps.create(file),
        }
    }
    fn append(&self, handle: &mut File, data: &[u8]) -> io::Result<()> {
        match self.append_error.get() {
            Some(e) => Err(io::Error::from_raw_os_error(e)),
            None => StdFileOps.append(handle, data),
        }
    }
}

type Switch = Rc<Cell<Option<i32>>>;

fn failing() -> (Failing, Switch, Switch, Rc<Cell<u32>>) {
    let f = Failing { append_error: Rc::default(), create_error: Rc::default(), creates: Rc::default() };
    let (a, c, n) = (f.append_error.clone(), f.create_error.clone(), f.creates.clone());
    (f, a, c, n)
}

const ENOSPC: i32 = 28;
const EACCES: i32 = 13;
const EIO: i32 = 5;

#[test]
fn disk_full_turns_the_writer_off_with_exactly_one_diagnostics_line() {
    let dir = tmp_dir("full");
    let (ops, append, _, _) = failing();
    let (mut c, diags) = config(&dir);
    c.file_ops = Some(Box::new(ops));
    let mut log = CipherLog::new(c);
    log.log(Level::W, Some("x"), "written");
    append.set(Some(ENOSPC));
    log.log(Level::W, Some("x"), "fails");
    append.set(None);
    log.log(Level::W, Some("x"), "dropped");
    log.flush();
    log.close();
    assert!(!log.is_on());
    let t = text(&read(&dir, &files(&dir)[0]));
    assert!(t.contains("written"));
    assert!(!t.contains("dropped"));
    log.wipe();
    assert_eq!(*diags.borrow(), vec!["cipherlog off: disk full"]);
    assert!(files(&dir).is_empty(), "wipe while off still deletes");
}

#[test]
fn another_write_error_names_the_errno() {
    let dir = tmp_dir("eio");
    let (ops, append, _, _) = failing();
    let (mut c, diags) = config(&dir);
    c.file_ops = Some(Box::new(ops));
    let mut log = CipherLog::new(c);
    append.set(Some(EIO));
    log.log(Level::W, Some("x"), "fails");
    assert_eq!(*diags.borrow(), vec!["cipherlog off: write failed (EIO)"]);
}

#[test]
fn a_crypto_failure_turns_the_writer_off_with_exactly_one_diagnostics_line() {
    let dir = tmp_dir("crypto");
    let n = Rc::new(Cell::new(0));
    let (mut c, diags) = config(&dir);
    let n2 = n.clone();
    c.encrypt_record = Some(Rc::new(move |k: &[u8; 32], id: &[u8; 16], seq: u32, flags: u8, pt: &[u8]| {
        n2.set(n2.get() + 1);
        if n2.get() > 2 {
            return Err("SealError".to_string());
        }
        encrypt_record(k, id, seq, flags, pt).map_err(|_| "FormatError".to_string())
    }));
    let mut log = CipherLog::new(c);
    for i in 0..5 {
        log.log(Level::W, Some("x"), &format!("l{i}"));
    }
    log.close();
    assert_eq!(*diags.borrow(), vec!["cipherlog off: crypto error (SealError)"]);
    assert!(!log.is_on());
    assert_eq!(read(&dir, &files(&dir)[0]).records, 2);
}

#[test]
fn open_failure_retries_at_most_once_a_minute_then_writes_the_not_written_count() {
    let dir = tmp_dir("open");
    let (ops, _, create, creates) = failing();
    create.set(Some(EACCES));
    let t = Rc::new(Cell::new(T0));
    let (mut c, diags) = config(&dir);
    c.file_ops = Some(Box::new(ops));
    let t2 = t.clone();
    c.clock = Some(Box::new(move || t2.get()));
    let mut log = CipherLog::new(c);
    assert_eq!(creates.get(), 1);
    for i in 0..5 {
        log.log(Level::I, Some("x"), &format!("lost {i}"));
        t.set(t.get() + 10_000);
    }
    assert_eq!(creates.get(), 1, "no retry within a minute");
    t.set(t.get() + 10_000); // 60 s after the first attempt
    log.log(Level::I, Some("x"), "lost 5");
    assert_eq!(creates.get(), 2);
    create.set(None);
    log.log(Level::I, Some("x"), "lost 6");
    assert_eq!(creates.get(), 2);
    t.set(t.get() + 60_000);
    log.log(Level::I, Some("x"), "kept");
    assert_eq!(creates.get(), 3);
    log.close();
    assert!(diags.borrow().is_empty());
    assert!(log.is_on());
    let tx = text(&read(&dir, &files(&dir)[0]));
    let lines: Vec<&str> = tx.split('\n').collect();
    let w = lines.iter().position(|l| l.contains(" W app cipherlog: ")).unwrap();
    assert!(lines[w].ends_with(" W app cipherlog: not written 7 lines"), "{}", lines[w]);
    assert!(lines.iter().position(|l| l.contains("kept")).unwrap() > w);
    assert!(!lines.iter().any(|l| l.contains("lost")));
}

#[test]
fn disk_full_while_opening_turns_the_writer_off() {
    let dir = tmp_dir("openfull");
    let (ops, _, create, _) = failing();
    create.set(Some(ENOSPC));
    let (mut c, diags) = config(&dir);
    c.file_ops = Some(Box::new(ops));
    let log = CipherLog::new(c);
    assert!(!log.is_on());
    assert_eq!(*diags.borrow(), vec!["cipherlog off: disk full"]);
}

#[test]
fn a_failed_header_write_leaves_no_empty_file_behind() {
    let dir = tmp_dir("hdr");
    let (ops, append, _, _) = failing();
    append.set(Some(ENOSPC));
    let (mut c, diags) = config(&dir);
    c.file_ops = Some(Box::new(ops));
    let log = CipherLog::new(c);
    assert!(!log.is_on());
    assert_eq!(*diags.borrow(), vec!["cipherlog off: disk full"]);
    assert!(files(&dir).is_empty());
}

#[test]
fn exports_skip_files_shorter_than_a_header() {
    let dir = tmp_dir("short");
    let (mut log, _) = make(&dir);
    log.log(Level::I, Some("a"), "x");
    fs::write(dir.join(format!("other-{T0}-00000000.cipherlog")), b"").unwrap();
    let r = read_bytes(&log.build_support_bundle().unwrap(), &key_ring(), "b", &mut ReadBudget::default());
    log.close();
    assert_eq!(r.files.len(), 2, "own file + device now");
    assert!(r.files.iter().all(|f| f.opened));
}

#[test]
fn file_names_parse_like_the_reference_pattern() {
    assert_eq!(parse_file_name("app-1795000000000-0123abcd.cipherlog"), Some(("app", 1_795_000_000_000, "0123abcd")));
    assert_eq!(parse_file_name("a-b.c_d-1795000000000-0123abcd.cipherlog"), Some(("a-b.c_d", 1_795_000_000_000, "0123abcd")));
    for bad in [
        "app-179500000000-0123abcd.cipherlog",
        "app-1795000000000-0123ABCD.cipherlog",
        "-1795000000000-0123abcd.cipherlog",
        "app 1-1795000000000-0123abcd.cipherlog",
        &format!("{}-1795000000000-0123abcd.cipherlog", "a".repeat(33)),
        "app-1795000000000-0123abcd.cipherlogs",
    ] {
        assert_eq!(parse_file_name(bad), None, "{bad}");
    }
}
