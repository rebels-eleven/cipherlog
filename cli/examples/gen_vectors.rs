//! Regenerates `vectors/test-key.json` and `vectors/records.json` (SPEC.md 8), byte for byte as
//! the retired TypeScript generator wrote them for the same test key.
//!
//!     cargo run --example gen_vectors -- [--out-dir <dir>] [--new-header]
//!
//! The default directory is `../vectors`. The key is read from `<dir>/test-key.json` (a new one is generated when there
//! is none). Records and rejections are deterministic. The header is not (HPKE encryption is randomized), so it is an
//! open-only vector: the header already in `<dir>/records.json` is kept when it opens with the key and holds the fixed
//! test values, so regenerating changes nothing; `--new-header` (or no usable header) seals a fresh one.

use cipherlog::format::{encrypt_record, header_info_bytes, hex, hpke_seal, key_id_of, open_header, public_key_from_private, unhex};
use flate2::{Compress, Compression, FlushCompress, Status};
use std::path::{Path, PathBuf};

/// A JSON value with ordered keys, printed as `JSON.stringify(value, null, 2)` does.
pub enum J {
    S(String),
    N(i64),
    B(bool),
    A(Vec<J>),
    O(Vec<(&'static str, J)>),
}

fn s(v: impl Into<String>) -> J {
    J::S(v.into())
}

impl J {
    fn write(&self, out: &mut String, indent: usize) {
        let pad = |n: usize| "  ".repeat(n);
        match self {
            J::S(v) => out.push_str(&serde_json::to_string(v).expect("string")),
            J::N(n) => out.push_str(&n.to_string()),
            J::B(b) => out.push_str(if *b { "true" } else { "false" }),
            J::A(items) if items.is_empty() => out.push_str("[]"),
            J::O(items) if items.is_empty() => out.push_str("{}"),
            J::A(items) => {
                out.push_str("[\n");
                for (i, v) in items.iter().enumerate() {
                    out.push_str(&pad(indent + 1));
                    v.write(out, indent + 1);
                    out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
                }
                out.push_str(&pad(indent));
                out.push(']');
            }
            J::O(items) => {
                out.push_str("{\n");
                for (i, (k, v)) in items.iter().enumerate() {
                    out.push_str(&pad(indent + 1));
                    out.push_str(&serde_json::to_string(k).expect("string"));
                    out.push_str(": ");
                    v.write(out, indent + 1);
                    out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
                }
                out.push_str(&pad(indent));
                out.push('}');
            }
        }
    }

    pub fn pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }
}

const FILE_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const FILE_ID: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
const CREATED_AT: u64 = 1_795_000_000_123;
const PLATFORM: u8 = 1;
const PROCESS: u8 = 2;

fn arr<const N: usize>(h: &str) -> [u8; N] {
    unhex(h).expect("hex").try_into().expect("length")
}

/// Raw deflate (level 6, window 15, memLevel 8) of "hello cipherlog\n" with a sync flush, then "bye\n" with finish.
fn deflate_pieces() -> (Vec<u8>, Vec<u8>) {
    let mut c = Compress::new(Compression::new(6), false);
    let mut run = |input: &[u8], flush: FlushCompress| {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        let mut consumed = 0;
        loop {
            let (bi, bo) = (c.total_in(), c.total_out());
            let st = c.compress(&input[consumed..], &mut buf, flush).expect("deflate");
            consumed += (c.total_in() - bi) as usize;
            let n = (c.total_out() - bo) as usize;
            out.extend_from_slice(&buf[..n]);
            let done = match flush {
                FlushCompress::Finish => st == Status::StreamEnd,
                _ => consumed == input.len() && n < buf.len(),
            };
            if done {
                return out;
            }
        }
    };
    let p0 = run(b"hello cipherlog\n", FlushCompress::Sync);
    let p1 = run(b"bye\n", FlushCompress::Finish);
    (p0, p1)
}

/// The test key file (`note`, `publicKey`, `privateKey`, `keyId`) and the public and private key.
pub fn key_file(existing: Option<&str>) -> (String, [u8; 32], [u8; 32]) {
    let (note, public, private) = match existing {
        Some(text) => {
            let v: serde_json::Value = serde_json::from_str(text).expect("test-key.json is JSON");
            let get = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
            (get("note"), arr::<32>(&get("publicKey").expect("publicKey")), arr::<32>(&get("privateKey").expect("privateKey")))
        }
        None => {
            let kp = cipherlog::format::generate_key_pair();
            (Some("TEST ONLY. Never ship this key in an app.".into()), kp.public_key, *kp.private_key)
        }
    };
    assert_eq!(public_key_from_private(&private).expect("key"), public, "test-key.json: keys do not match");
    let mut fields = vec![];
    if let Some(n) = note {
        fields.push(("note", s(n)));
    }
    fields.push(("publicKey", s(hex(&public))));
    fields.push(("privateKey", s(hex(&private))));
    fields.push(("keyId", s(hex(&key_id_of(&public)))));
    (J::O(fields).pretty(), public, private)
}

/// The header in an existing records.json, when it opens with `private` and holds the fixed test values.
pub fn reusable_header(existing: Option<&str>, private: &[u8; 32]) -> Option<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_str(existing?).ok()?;
    let h = unhex(v.get("header")?.get("hex")?.as_str()?)?;
    let o = open_header(&h, private).ok()?;
    let fixed = *o.file_key == arr::<32>(FILE_KEY)
        && o.file_id == arr::<16>(FILE_ID)
        && o.created_at == CREATED_AT
        && o.platform == PLATFORM
        && o.process == PROCESS;
    fixed.then_some(h)
}

/// A record sealed as SPEC.md 2.2 says, without the writer's checks (the vectors need a reserved flag bit too).
fn raw_record(file_key: &[u8; 32], file_id: &[u8; 16], seq: u32, flags: u8, plain: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let len = plain.len() as u32 + 16;
    let aad = [b"cipherlog-rec-v1".as_slice(), file_id, &len.to_be_bytes(), &seq.to_be_bytes(), &[flags]].concat();
    let mut nonce = [0u8; 12];
    nonce[8..].copy_from_slice(&seq.to_be_bytes());
    let ct =
        chacha20poly1305::ChaCha20Poly1305::new(file_key.into()).encrypt(&nonce.into(), Payload { msg: plain, aad: &aad }).expect("seal");
    if flags & !1 == 0 {
        assert_eq!(encrypt_record(file_key, file_id, seq, flags, plain).expect("record")[9..], ct[..], "library agrees");
    }
    [len.to_be_bytes().as_slice(), &seq.to_be_bytes(), &[flags], &ct].concat()
}

fn flip(b: &[u8], i: usize) -> String {
    let mut b = b.to_vec();
    b[i] ^= 1;
    hex(&b)
}

/// The text of records.json for the key; `header` is reused when given, else a fresh one is sealed.
pub fn records_json(public: &[u8; 32], header: Option<Vec<u8>>) -> (String, usize, usize) {
    let key_id = key_id_of(public);
    let file_key = arr::<32>(FILE_KEY);
    let file_id = arr::<16>(FILE_ID);
    let info = header_info_bytes(&key_id);
    let header = header.unwrap_or_else(|| {
        let mut pt = Vec::new();
        pt.extend_from_slice(&file_key);
        pt.extend_from_slice(&file_id);
        pt.extend_from_slice(&CREATED_AT.to_be_bytes());
        pt.extend_from_slice(&[PLATFORM, PROCESS]);
        let (enc, sealed) = hpke_seal(public, &info, &[], &pt).expect("seal");
        [b"CPL1".as_slice(), &key_id, &enc, &sealed].concat()
    });
    assert_eq!(header.len(), 118, "header length");

    let record = |seq: u32, flags: u8, plain: &[u8]| raw_record(&file_key, &file_id, seq, flags, plain);
    let (p0, p1) = deflate_pieces();
    let cases: Vec<(&str, u32, u8, Vec<u8>)> =
        vec![("first record", 0, 0, p0.clone()), ("empty plaintext", 1, 0, vec![]), ("final record", 2, 1, p1)];
    let recs: Vec<Vec<u8>> = cases.iter().map(|c| record(c.1, c.2, &c.3)).collect();
    let good: Vec<u8> = recs.concat();
    let r0 = &recs[0];
    let reserved = record(0, 2, &p0);
    let cut = |h: String| h[..h.len() - 2].to_string();
    let rejections: Vec<(&str, String, u32, &str)> = vec![
        ("len changed", flip(r0, 3), 0, "truncated"),
        ("seq changed", flip(r0, 7), 0, "seq 1, expected 0"),
        ("flags changed", flip(r0, 8), 0, "authentication failed"),
        ("reserved flag bit", hex(&reserved), 0, "reserved flag bits 0x02"),
        ("ciphertext changed", flip(r0, 9), 0, "authentication failed"),
        ("tag changed", flip(r0, r0.len() - 1), 0, "authentication failed"),
        ("wrong expected seq", hex(r0), 1, "seq 0, expected 1"),
        ("bad seq and cut short", cut(flip(r0, 7)), 0, "truncated"),
        ("reserved flag bit and cut short", cut(hex(&reserved)), 0, "truncated"),
    ];
    let doc = J::O(vec![
        ("note", s("cipherlog-v1 vectors, SPEC.md 8. Test key only.")),
        ("keyId", s(hex(&key_id))),
        (
            "header",
            J::O(vec![
                ("hex", s(hex(&header))),
                ("fileKey", s(FILE_KEY)),
                ("fileId", s(FILE_ID)),
                ("createdAt", J::N(CREATED_AT as i64)),
                ("platform", J::N(PLATFORM as i64)),
                ("process", J::N(PROCESS as i64)),
                ("info", s(hex(&info))),
            ]),
        ),
        (
            "records",
            J::A(
                cases
                    .iter()
                    .zip(&recs)
                    .map(|(c, r)| {
                        J::O(vec![
                            ("name", s(c.0)),
                            ("seq", J::N(c.1 as i64)),
                            ("flags", J::N(c.2 as i64)),
                            ("plaintext", s(hex(&c.3))),
                            ("record", s(hex(r))),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "file",
            J::O(vec![("hex", s(hex(&[header.as_slice(), &good].concat()))), ("text", s("hello cipherlog\nbye\n")), ("final", J::B(true))]),
        ),
        (
            "rejections",
            J::A(
                rejections
                    .into_iter()
                    .map(|(name, rec, seq, reason)| {
                        J::O(vec![("name", s(name)), ("record", s(rec)), ("seq", J::N(seq as i64)), ("reason", s(reason))])
                    })
                    .collect(),
            ),
        ),
        (
            "rejectionOrder",
            s("SPEC.md 5.3: length bounds, truncated, seq, flags, AEAD; reason is the exact text after \"readable up to record N (\""),
        ),
    ]);
    (doc.pretty(), header.len(), good.len())
}

#[allow(dead_code)]
fn main() {
    let mut out_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors"));
    let mut new_header = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out-dir" => out_dir = PathBuf::from(args.next().expect("--out-dir needs a directory")),
            "--new-header" => new_header = true,
            _ => {
                eprintln!("usage: gen_vectors [--out-dir <dir>] [--new-header]");
                std::process::exit(2);
            }
        }
    }
    let read = |p: &Path| std::fs::read_to_string(p).ok();
    let key_path = out_dir.join("test-key.json");
    let records_path = out_dir.join("records.json");
    let (key_text, public, private) = key_file(read(&key_path).as_deref());
    std::fs::write(&key_path, key_text).expect("write test-key.json");
    let header = if new_header { None } else { reusable_header(read(&records_path).as_deref(), &private) };
    let reused = header.is_some();
    let (text, header_len, good_len) = records_json(&public, header);
    std::fs::write(&records_path, text).expect("write records.json");
    println!("ok {} {header_len} {good_len}{}", hex(&key_id_of(&public)), if reused { " (header kept)" } else { " (new header)" });
}
