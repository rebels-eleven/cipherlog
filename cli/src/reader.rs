//! Reader, SPEC.md 5.

use crate::armor::dearmor;
use crate::format::{
    CAPPED_NOTE, FLAG_FINAL, HEADER_LEN, INFLATE_CAP, MAGIC, TOTAL_INFLATE_CAP, decode_bundle, decrypt_record, hex, inflate_stream,
    is_bundle, open_header, peek_header,
};
use crate::text::{iso_time, parse_iso_time};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const SOURCE_NOT_VERIFIED: &str = "source not verified: anyone with the public key can make a cipherlog file";

/// The clear parts of a decrypted header (no file key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderMeta {
    pub key_id: [u8; 8],
    pub file_id: [u8; 16],
    pub created_at: u64,
    pub platform: u8,
    pub process: u8,
}

#[derive(Clone, Debug, Default)]
pub struct FileResult {
    /// File name, or `<bundle>#<n>` for a bundle entry. Untrusted: print it through `safe_text`.
    pub name: String,
    pub key_id: Option<String>,
    pub header: Option<HeaderMeta>,
    /// False when skipped (unknown key, header does not open, not a cipherlog file).
    pub opened: bool,
    /// A `final` record was read.
    pub closed: bool,
    /// Records read and authenticated.
    pub records: u64,
    /// Set when a bad record ended the file: the reason (`truncated`, `authentication failed`, …).
    pub stopped_by: Option<String>,
    pub notes: Vec<String>,
    /// Decompressed text (UTF-8 bytes) of all good records.
    pub text: Vec<u8>,
    /// Set by `mark_duplicates` when another opened copy of the same file (same fileId) is shown instead.
    pub duplicate_of: Option<String>,
}

pub struct ReadResult {
    pub files: Vec<FileResult>,
    pub notes: Vec<String>,
}

/// Private keys by keyId hex; wiped when dropped.
pub type KeyRing = HashMap<String, Zeroizing<[u8; 32]>>;

/// What is left of the total output budget of one read call (SPEC.md 5.4), shared by all files and inputs.
pub struct ReadBudget {
    pub total: usize,
    pub left: usize,
}

impl ReadBudget {
    pub fn new(total: usize) -> Self {
        ReadBudget { total, left: total }
    }
}

impl Default for ReadBudget {
    fn default() -> Self {
        ReadBudget::new(TOTAL_INFLATE_CAP)
    }
}

fn size_text(n: usize) -> String {
    if n.is_multiple_of(1024 * 1024) { format!("{} MiB", n / (1024 * 1024)) } else { format!("{n} bytes") }
}

pub fn read_file(bytes: &[u8], keys: &KeyRing, name: &str, budget: &mut ReadBudget) -> FileResult {
    let mut r = FileResult { name: name.to_string(), ..Default::default() };
    if bytes.len() >= 4 && &bytes[..4] != MAGIC {
        r.notes.push("not a cipherlog file (magic), skipped".into());
        return r;
    }
    if bytes.len() < HEADER_LEN {
        r.notes.push("shorter than a header, skipped".into());
        return r;
    }
    let key_id = hex(&peek_header(bytes).expect("length and magic checked"));
    r.key_id = Some(key_id.clone());
    let Some(private_key) = keys.get(&key_id) else {
        r.notes.push(format!("unknown keyId {key_id}, skipped"));
        return r;
    };
    let Ok(h) = open_header(bytes, private_key) else {
        r.notes.push("header does not open, skipped".into());
        return r;
    };
    r.opened = true;
    r.header =
        Some(HeaderMeta { key_id: h.key_id, file_id: h.file_id, created_at: h.created_at, platform: h.platform, process: h.process });
    let mut compressed = Vec::new();
    let mut off = HEADER_LEN;
    let mut seq: u32 = 0;
    while off < bytes.len() {
        if r.closed {
            r.stopped_by = Some("data after final".into());
            break;
        }
        match decrypt_record(&h.file_key, &h.file_id, seq, bytes, off) {
            Ok(rec) => {
                compressed.extend_from_slice(&rec.plaintext);
                off += rec.size;
                seq = seq.wrapping_add(1);
                r.records += 1;
                if rec.flags & FLAG_FINAL != 0 {
                    r.closed = true;
                }
            }
            Err(e) => {
                r.stopped_by = Some(e.reason);
                break;
            }
        }
    }
    drop(h);
    if let Some(s) = &r.stopped_by {
        r.notes.push(format!("readable up to record {} ({s})", r.records));
    }
    r.notes.push(if r.closed { "closed" } else { "not closed (crash or still open), completeness unknown" }.into());
    if !compressed.is_empty() {
        let total_note = format!("total output capped at {}", size_text(budget.total));
        if budget.left == 0 {
            r.notes.push(total_note);
        } else {
            let cap = INFLATE_CAP.min(budget.left);
            let inf = inflate_stream(&compressed, cap, if cap < INFLATE_CAP { &total_note } else { CAPPED_NOTE });
            if let Some(n) = inf.note {
                r.notes.push(n);
            }
            budget.left -= inf.text.len();
            r.text = inf.text;
        }
    }
    r
}

/// A file, a bundle or an armored bundle (SPEC.md 4.1); `name` labels the results. Files of one call share `budget`.
pub fn read_bytes(bytes: &[u8], keys: &KeyRing, name: &str, budget: &mut ReadBudget) -> ReadResult {
    if is_bundle(bytes) {
        return read_binary(bytes, keys, name, budget);
    }
    let binary_file = bytes.len() >= 4 && &bytes[..4] == MAGIC;
    if !binary_file {
        match dearmor(bytes) {
            // Armor inside armor is not unwrapped twice.
            Some(Ok(inner)) => return read_binary(&inner, keys, name, budget),
            Some(Err(e)) => return ReadResult { files: vec![], notes: vec![format!("{}: {e}", safe_text(name))] },
            None => {}
        }
    }
    read_binary(bytes, keys, name, budget)
}

/// A bundle or a single file, never armor.
fn read_binary(bytes: &[u8], keys: &KeyRing, name: &str, budget: &mut ReadBudget) -> ReadResult {
    if is_bundle(bytes) {
        let b = decode_bundle(bytes);
        let files = b.files.iter().enumerate().map(|(i, f)| read_file(f, keys, &format!("{name}#{}", i + 1), budget)).collect();
        let notes = b.note.map(|n| vec![format!("{}: {n}", safe_text(name))]).unwrap_or_default();
        return ReadResult { files, notes };
    }
    ReadResult { files: vec![read_file(bytes, keys, name, budget)], notes: vec![] }
}

/// The same file opened more than once is shown once: the copy with the most records (the first on a tie).
pub fn mark_duplicates(files: &mut [FileResult]) {
    let mut best: HashMap<[u8; 16], usize> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        let (true, Some(h)) = (f.opened, &f.header) else { continue };
        match best.get(&h.file_id) {
            Some(&b) if files[b].records >= f.records => {}
            _ => {
                best.insert(h.file_id, i);
            }
        }
    }
    for i in 0..files.len() {
        let (true, Some(h)) = (files[i].opened, &files[i].header) else { continue };
        let b = best[&h.file_id];
        if b == i {
            continue;
        }
        let bname = files[b].name.clone();
        files[i].notes.push(format!("duplicate of {}, lines shown once", safe_text(&bname)));
        files[i].duplicate_of = Some(bname);
    }
}

pub fn platform_name(p: u8) -> String {
    match p {
        0 => "unknown".into(),
        1 => "Apple".into(),
        2 => "Android".into(),
        3 => "JVM".into(),
        n => n.to_string(),
    }
}

pub fn describe_file(f: &FileResult) -> String {
    let mut parts = vec![safe_text(&f.name)];
    if let Some(k) = &f.key_id {
        parts.push(format!("keyId {k}"));
    }
    if let Some(h) = &f.header {
        parts.push(format!("file {}", &hex(&h.file_id)[..8]));
        parts.push(format!("platform {} ({})", h.platform, platform_name(h.platform)));
        parts.push(format!("process {}", h.process));
        parts.push(format!("created {}", iso_time(h.created_at as i64)));
        parts.push(format!("{} records", f.records));
    }
    format!("{}: {}", parts.join(" · "), f.notes.join("; "))
}

// ---------- cleaning ----------

/// Characters removed from decrypted lines: C0 except tab and newline, DEL, C1, and the invisible format characters
/// that reorder or hide text on a terminal (Trojan Source). ZWNJ and ZWJ stay: emoji sequences and scripts need them.
fn removed(c: char) -> bool {
    matches!(c,
        '\u{0}'..='\u{8}' | '\u{b}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{61c}' | '\u{200b}' | '\u{200e}' | '\u{200f}'
        | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

/// Byte length of an ANSI escape sequence at the start of `s`, if one starts there (the same alternatives, in the same
/// order, as the TypeScript reader's expression): CSI, OSC (ended by BEL or ST), DCS/SOS/PM/APC (ended by ST), a
/// two-character escape, and the 8-bit CSI. Works on the string in place: no per-character copy of a block.
fn ansi_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    // Every character the sequences are made of, except their payloads, is ASCII; the 8-bit CSI is U+009B (2 bytes).
    let at = |k: usize| b.get(k).copied();
    let csi_tail = |mut k: usize| {
        while at(k).is_some_and(|c| (b'0'..=b'?').contains(&c)) {
            k += 1;
        }
        while at(k).is_some_and(|c| (b' '..=b'/').contains(&c)) {
            k += 1;
        }
        at(k).is_some_and(|c| (b'@'..=b'~').contains(&c)).then_some(k + 1)
    };
    if s.starts_with('\u{9b}') {
        return csi_tail(2);
    }
    if at(0)? != 0x1b {
        return None;
    }
    let c1 = at(1)?;
    if c1 == b'['
        && let Some(end) = csi_tail(2)
    {
        return Some(end);
    }
    // A payload ends at a byte that is ASCII, so byte search stays on character boundaries.
    if c1 == b']' {
        let k = 2 + b[2..].iter().position(|&c| c == 0x07 || c == 0x1b || c == b'\n').unwrap_or(b.len() - 2);
        if at(k) == Some(0x07) {
            return Some(k + 1);
        }
        if at(k) == Some(0x1b) && at(k + 1) == Some(b'\\') {
            return Some(k + 2);
        }
    }
    if matches!(c1, b'P' | b'X' | b'^' | b'_') {
        let k = 2 + b[2..].iter().position(|&c| c == 0x1b || c == b'\n').unwrap_or(b.len() - 2);
        if at(k) == Some(0x1b) && at(k + 1) == Some(b'\\') {
            return Some(k + 2);
        }
    }
    if (b'@'..=b'Z').contains(&c1) || (b'\\'..=b'_').contains(&c1) {
        return Some(2);
    }
    None
}

/// Removes ANSI escape sequences, then control characters (tab and newline kept) and bidi/invisible characters.
pub fn clean_block(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    clean_into(s, &mut out);
    out
}

/// `clean_block`, appended to `out`. Memory: `out` grows by at most `s.len()`; nothing else is allocated.
pub fn clean_into(s: &str, out: &mut String) {
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        if let Some(n) = ansi_len(rest) {
            i += n;
            continue;
        }
        let c = rest.chars().next().expect("i is on a character boundary");
        if !removed(c) {
            out.push(c);
        }
        i += c.len_utf8();
    }
}

/// `clean_block` for one line: newlines are removed too.
pub fn clean_line(s: &str) -> String {
    clean_block(s).replace('\n', "")
}

/// For untrusted text outside the log lines (file names, paths, error texts): control, line-breaking and
/// bidi/invisible characters are shown as `\xNN` / `\uNNNN`, so a crafted name cannot forge or erase report lines.
pub fn safe_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let n = c as u32;
        let unsafe_char = matches!(c,
            '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{61c}' | '\u{200b}'..='\u{200f}' | '\u{2028}' | '\u{2029}'
            | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}');
        if !unsafe_char {
            out.push(c);
        } else if n < 0x100 {
            out.push_str(&format!("\\x{n:02x}"));
        } else {
            out.push_str(&format!("\\u{n:04x}"));
        }
    }
    out
}

// ---------- merge ----------

struct Group {
    time: i64,
    file: usize,
    start: usize,
    end: usize,
}

/// Lines of all files merged by time, stable; a line without a time keeps the time of the line before it (the file's
/// createdAt at its start). Returns cleaned blocks of whole lines in order, each ending with `\n`, lazily: memory
/// stays bounded by the texts themselves. Files marked `duplicate_of` are left out.
pub fn merged_blocks(files: &[FileResult]) -> impl Iterator<Item = String> + '_ {
    let mut groups: Vec<Group> = Vec::new();
    for (fi, f) in files.iter().enumerate() {
        if !f.opened || f.duplicate_of.is_some() || f.text.is_empty() {
            continue;
        }
        let t = &f.text;
        let mut group_start = 0;
        let mut group_time = f.header.as_ref().map_or(0, |h| h.created_at as i64);
        let mut pos = 0;
        while pos < t.len() {
            let nl = t[pos..].iter().position(|&b| b == b'\n').map_or(t.len(), |k| pos + k);
            if nl - pos >= 25
                && t[pos + 24] == b' '
                && let Some(time) = parse_iso_time(&t[pos..pos + 24])
            {
                if pos > group_start {
                    groups.push(Group { time: group_time, file: fi, start: group_start, end: pos });
                }
                group_start = pos;
                group_time = time;
            }
            pos = nl + 1;
        }
        if t.len() > group_start {
            groups.push(Group { time: group_time, file: fi, start: group_start, end: t.len() });
        }
    }
    // Stable: equal times keep file order, then position.
    groups.sort_by_key(|g| g.time);
    groups.into_iter().map(move |g| {
        let block = String::from_utf8_lossy(&files[g.file].text[g.start..g.end]);
        // One byte more than the block: the newline below never makes the String reallocate (double) a big block.
        let mut cleaned = String::with_capacity(block.len() + 1);
        clean_into(&block, &mut cleaned);
        if !cleaned.ends_with('\n') {
            cleaned.push('\n');
        }
        cleaned
    })
}

pub struct MergedLine {
    pub time: i64,
    pub line: String,
}

/// `merged_blocks` as one entry per line with its sort time (tests and small inputs).
pub fn merge_lines(files: &[FileResult]) -> Vec<MergedLine> {
    let mut out = Vec::new();
    let mut last = 0;
    for block in merged_blocks(files) {
        if block.len() >= 25
            && block.as_bytes()[24] == b' '
            && let Some(t) = parse_iso_time(&block.as_bytes()[..24])
        {
            last = t;
        }
        for line in block[..block.len() - 1].split('\n') {
            out.push(MergedLine { time: last, line: line.to_string() });
        }
    }
    out
}
