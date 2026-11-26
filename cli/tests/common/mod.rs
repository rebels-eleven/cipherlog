#![allow(dead_code)]

use cipherlog::format::unhex;
use cipherlog::reader::KeyRing;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use zeroize::Zeroizing;

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}
pub fn vectors() -> PathBuf {
    root().join("vectors")
}

pub struct TestKey {
    pub public_hex: String,
    pub private_hex: String,
    pub key_id: String,
}

pub fn test_key() -> TestKey {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(vectors().join("test-key.json")).unwrap()).unwrap();
    let g = |k: &str| v[k].as_str().unwrap().to_string();
    TestKey { public_hex: g("publicKey"), private_hex: g("privateKey"), key_id: g("keyId") }
}

pub fn pub_key() -> [u8; 32] {
    unhex(&test_key().public_hex).unwrap().try_into().unwrap()
}
pub fn priv_key() -> [u8; 32] {
    unhex(&test_key().private_hex).unwrap().try_into().unwrap()
}
pub fn key_ring() -> KeyRing {
    let mut k = KeyRing::new();
    k.insert(test_key().key_id, Zeroizing::new(priv_key()));
    k
}

pub fn hx(s: &str) -> Vec<u8> {
    unhex(s).unwrap()
}

static N: AtomicU32 = AtomicU32::new(0);

/// A new empty directory under the target directory.
pub fn tmp_dir(tag: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "cipherlog-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Deterministic clock: start, then +step ms per call.
pub fn step_clock(start: i64, step: i64) -> impl FnMut() -> i64 {
    let mut t = start;
    move || {
        let v = t;
        t += step;
        v
    }
}

pub const T0: i64 = 1_795_000_000_000;

/// Offsets of records in a file (no decryption).
pub fn record_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut out = vec![];
    let mut off = 118;
    while off + 9 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        if off + 9 + len > bytes.len() {
            break;
        }
        out.push(off);
        off += 9 + len;
    }
    out
}

/// A closed file of the given lines, written by the `write` command's builder.
pub fn file_of(lines: &[&str]) -> Vec<u8> {
    let input = lines.join("\n") + "\n";
    cipherlog::cli::write_file_bytes(&pub_key(), &input, "t", 1, 3, &mut step_clock(T0, 7)).unwrap()
}

/// Raw deflate of `data` in one go (level 6).
pub fn deflate(data: &[u8], finish: bool) -> Vec<u8> {
    use flate2::{Compress, Compression, FlushCompress, Status};
    let mut c = Compress::new(Compression::new(6), false);
    let mut out = Vec::with_capacity(data.len() / 2 + 1024);
    let flush = if finish { FlushCompress::Finish } else { FlushCompress::Sync };
    loop {
        let consumed = c.total_in() as usize;
        if out.capacity() - out.len() < 1024 {
            out.reserve(out.capacity());
        }
        let st = c.compress_vec(&data[consumed..], &mut out, flush).unwrap();
        if finish && st == Status::StreamEnd {
            return out;
        }
        if !finish && c.total_in() as usize == data.len() && out.capacity() - out.len() >= 1024 {
            return out;
        }
    }
}
