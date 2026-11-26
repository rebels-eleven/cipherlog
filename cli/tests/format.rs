// Ported from the format tests of the retired TypeScript CLI, plus the record vectors with exact reasons and the armor format.
mod common;

use cipherlog::armor::{armor, dearmor};
use cipherlog::format::*;
use cipherlog::reader::{ReadBudget, read_bytes, read_file};
use common::*;

struct V {
    v: serde_json::Value,
}

impl V {
    fn load() -> V {
        V { v: serde_json::from_str(&std::fs::read_to_string(vectors().join("records.json")).unwrap()).unwrap() }
    }
    fn file_key(&self) -> [u8; 32] {
        hx(self.v["header"]["fileKey"].as_str().unwrap()).try_into().unwrap()
    }
    fn file_id(&self) -> [u8; 16] {
        hx(self.v["header"]["fileId"].as_str().unwrap()).try_into().unwrap()
    }
    fn list(&self, k: &str) -> Vec<serde_json::Value> {
        self.v[k].as_array().unwrap().clone()
    }
}

fn s(v: &serde_json::Value, k: &str) -> String {
    v[k].as_str().unwrap().to_string()
}
fn n(v: &serde_json::Value, k: &str) -> u64 {
    v[k].as_u64().unwrap()
}

#[test]
fn key_id_of_the_test_key() {
    let k = test_key();
    assert_eq!(hex(&key_id_of(&pub_key())), k.key_id);
    assert_eq!(V::load().v["keyId"].as_str().unwrap(), k.key_id);
    assert_eq!(public_key_from_private(&priv_key()).unwrap(), pub_key());
}

#[test]
fn records_json_every_record_encrypts_byte_exact_and_decrypts() {
    let v = V::load();
    for c in v.list("records") {
        let (seq, flags) = (n(&c, "seq") as u32, n(&c, "flags") as u8);
        let rec = encrypt_record(&v.file_key(), &v.file_id(), seq, flags, &hx(&s(&c, "plaintext"))).unwrap();
        assert_eq!(hex(&rec), s(&c, "record"), "{}", s(&c, "name"));
        let d = decrypt_record(&v.file_key(), &v.file_id(), seq, &hx(&s(&c, "record")), 0).unwrap();
        assert_eq!(hex(&d.plaintext), s(&c, "plaintext"));
        assert_eq!(d.flags, flags);
        assert_eq!(d.seq, seq);
        assert_eq!(d.size, hx(&s(&c, "record")).len());
    }
}

#[test]
fn records_json_every_rejection_gives_the_vector_reason() {
    let v = V::load();
    let rej = v.list("rejections");
    assert!(rej.len() >= 9);
    for c in rej {
        let e = decrypt_record(&v.file_key(), &v.file_id(), n(&c, "seq") as u32, &hx(&s(&c, "record")), 0)
            .err()
            .unwrap_or_else(|| panic!("{} accepted", s(&c, "name")));
        assert_eq!(e.reason, s(&c, "reason"), "{}", s(&c, "name"));
    }
}

#[test]
fn records_json_header_opens_with_the_test_private_key() {
    let v = V::load();
    let h = &v.v["header"];
    let bytes = hx(&s(h, "hex"));
    assert_eq!(bytes.len(), HEADER_LEN);
    let o = open_header(&bytes, &priv_key()).unwrap();
    assert_eq!(hex(&*o.file_key), s(h, "fileKey"));
    assert_eq!(hex(&o.file_id), s(h, "fileId"));
    assert_eq!(o.created_at, n(h, "createdAt"));
    assert_eq!(o.platform as u64, n(h, "platform"));
    assert_eq!(o.process as u64, n(h, "process"));
    assert_eq!(hex(&o.key_id), test_key().key_id);
    assert_eq!(hex(&header_info_bytes(&o.key_id)), s(h, "info"));
}

#[test]
fn records_json_whole_file_reads_to_the_expected_text_closed() {
    let v = V::load();
    let f = &v.v["file"];
    let r = read_file(&hx(&s(f, "hex")), &key_ring(), "vector", &mut ReadBudget::default());
    assert_eq!(String::from_utf8(r.text).unwrap(), s(f, "text"));
    assert_eq!(r.closed, f["final"].as_bool().unwrap());
    assert_eq!(r.records, 3);
    assert_eq!(r.stopped_by, None);
}

#[test]
fn header_made_here_opens_and_any_changed_byte_or_wrong_key_fails() {
    let created_at = 1_795_000_000_999;
    let (fk, fi) = ([7u8; 32], [9u8; 16]);
    let header = encode_header(&pub_key(), &fk, &fi, created_at, 3, 200).unwrap();
    assert_eq!(header.len(), 118);
    assert_eq!(&header[..4], b"CPL1");
    // The bare HPKE layer gives the plaintext of SPEC.md 2.1.
    let pt = hpke_open(&priv_key(), &header[12..44], &header_info_bytes(&key_id_of(&pub_key())), &[], &header[44..118]).unwrap();
    assert_eq!(&pt[..32], &fk);
    assert_eq!(&pt[32..48], &fi);
    assert_eq!(u64::from_be_bytes(pt[48..56].try_into().unwrap()), created_at);
    assert_eq!([pt[56], pt[57]], [3, 200]);
    let h = open_header(&header, &priv_key()).unwrap();
    assert_eq!(h.created_at, created_at);
    assert!(open_header(&header, &generate_key_pair().private_key).is_err());
    for i in [4, 20, 60, 117] {
        let mut bad = header.clone();
        bad[i] ^= 1;
        assert!(open_header(&bad, &priv_key()).is_err(), "byte {i}");
    }
    // createdAt past 2^53 - 1 is not written and not read.
    assert!(encode_header(&pub_key(), &fk, &fi, MAX_SAFE_INTEGER + 1, 0, 0).is_err());
}

#[test]
fn generated_key_pairs_are_consistent() {
    let kp = generate_key_pair();
    assert_eq!(public_key_from_private(&kp.private_key).unwrap(), kp.public_key);
    assert_eq!(kp.key_id, key_id_of(&kp.public_key));
    assert_ne!(kp.public_key, generate_key_pair().public_key);
}

fn raw_rec(len: u32, seq: u32, flags: u8) -> Vec<u8> {
    let mut b = vec![0u8; 9 + len.min(70_000) as usize];
    b[..4].copy_from_slice(&len.to_be_bytes());
    b[4..8].copy_from_slice(&seq.to_be_bytes());
    b[8] = flags;
    b
}

#[test]
fn length_bounds_and_reserved_flags() {
    let v = V::load();
    let (k, id) = (v.file_key(), v.file_id());
    let reason = |b: &[u8]| decrypt_record(&k, &id, 0, b, 0).err().unwrap().reason;
    assert_eq!(reason(&raw_rec(15, 0, 0)), "bad length 15");
    assert_eq!(reason(&raw_rec(65_553, 0, 0)), "bad length 65553");
    assert_eq!(reason(&raw_rec(0, 0, 0)), "bad length 0");
    assert!(encrypt_record(&k, &id, 0, 0, &vec![0; MAX_RECORD_PLAINTEXT + 1]).is_err());
    assert!(encrypt_record(&k, &id, 0, 2, &[0]).is_err());
    let big = encrypt_record(&k, &id, 0, 0, &vec![1; MAX_RECORD_PLAINTEXT]).unwrap();
    assert_eq!(u32::from_be_bytes(big[..4].try_into().unwrap()), 65_552);
    assert_eq!(decrypt_record(&k, &id, 0, &big, 0).unwrap().plaintext.len(), 65_536);
    assert!(encrypt_record(&k, &id, 0, 0x80, &[]).is_err());
    // A record with a reserved bit set (validly sealed) is rejected before the AEAD.
    let mut sealed = encrypt_record(&k, &id, 0, 0, &[]).unwrap();
    sealed[8] = 0x04;
    assert_eq!(reason(&sealed), "reserved flag bits 0x04");
    // Fewer than 9 bytes, or a body cut short: truncated.
    assert_eq!(reason(&big[..8]), "truncated");
    assert_eq!(reason(&big[..big.len() - 1]), "truncated");
}

#[test]
fn bundle_encode_decode_and_a_bad_length() {
    let (a, b, c) = (b"aaa".to_vec(), vec![], b"cccc".to_vec());
    let bundle = encode_bundle(&[&a, &b, &c]);
    assert_eq!(&bundle[..4], b"CPB1");
    let d = decode_bundle(&bundle);
    assert_eq!(d.files, vec![&a[..], &b[..], &c[..]]);
    assert_eq!(d.note, None);
    let mut bad = bundle.clone();
    bad[4 + 4 + 3..4 + 4 + 3 + 4].copy_from_slice(&1000u32.to_be_bytes());
    let d = decode_bundle(&bad);
    assert_eq!(d.files, vec![&a[..]]);
    assert_eq!(d.note.unwrap(), "bad length at entry 2, bundle ends");
    let mut tail = bundle.clone();
    tail.extend_from_slice(&[0, 0]);
    assert!(decode_bundle(&tail).note.unwrap().contains("bad length"));
}

#[test]
fn inflate_output_is_capped_at_64_mib() {
    let ok = inflate_stream(&deflate(&[65; 1024], true), INFLATE_CAP, CAPPED_NOTE);
    assert_eq!(ok.text.len(), 1024);
    assert_eq!(ok.note, None);
    let bomb = deflate(&vec![0u8; 64 * 1024 * 1024 + 1], true);
    let r = inflate_stream(&bomb, INFLATE_CAP, CAPPED_NOTE);
    assert_eq!(r.note.as_deref(), Some("output capped at 64 MiB"));
    // The text up to the cap is kept.
    assert!(r.text.len() <= 64 * 1024 * 1024 && r.text.len() > 64 * 1024 * 1024 - 1024, "{}", r.text.len());
    // A small cap on real text keeps a prefix of the text.
    let text = "0123456789\n".repeat(5000).into_bytes();
    let small = inflate_stream(&deflate(&text, true), 1000, CAPPED_NOTE);
    assert_eq!(small.note.as_deref(), Some("output capped at 64 MiB"));
    assert!(small.text.len() <= 1000 && small.text.len() > 700, "{}", small.text.len());
    assert_eq!(small.text[..], text[..small.text.len()]);
    // Exactly the cap is not over it.
    let exact = inflate_stream(&deflate(&[66; 1000], true), 1000, CAPPED_NOTE);
    assert_eq!((exact.text.len(), exact.note), (1000, None));
}

#[test]
fn inflate_keeps_unfinished_streams_and_text_up_to_damage() {
    let r = inflate_stream(&hx("ca48cdc9c95748ce2cc8482dcac94fe702000000ffff"), INFLATE_CAP, CAPPED_NOTE);
    assert_eq!(r.text, b"hello cipherlog\n");
    assert_eq!(r.note, None);
    // Cut anywhere: a prefix of the text, never a note (an unfinished stream is not damage).
    let text = "line of text number ✓\n".repeat(300).into_bytes();
    let full = deflate(&text, false);
    for cut in 0..full.len() {
        let r = inflate_stream(&full[..cut], INFLATE_CAP, CAPPED_NOTE);
        assert_eq!(r.note, None, "cut {cut}");
        assert_eq!(r.text[..], text[..r.text.len()], "cut {cut}");
    }
    assert_eq!(inflate_stream(&full, INFLATE_CAP, CAPPED_NOTE).text, text);
    let good = deflate(&"kept line\n".repeat(100).into_bytes(), false);
    let mut damaged = good.clone();
    damaged.extend_from_slice(&[0x07, 0, 0]);
    let r = inflate_stream(&damaged, INFLATE_CAP, CAPPED_NOTE);
    assert_eq!(r.note.as_deref(), Some(DAMAGED_NOTE));
    assert_eq!(r.text, "kept line\n".repeat(100).into_bytes());
    // Damage after more than one output chunk keeps everything before it.
    let long = "0123456789abcdef\n".repeat(20_000).into_bytes();
    let mut d = deflate(&long, false);
    d.extend_from_slice(&[0x07, 0, 0]);
    let r = inflate_stream(&d, INFLATE_CAP, CAPPED_NOTE);
    assert_eq!(r.note.as_deref(), Some(DAMAGED_NOTE));
    assert_eq!(r.text, long);
}

#[test]
fn inflate_of_a_bomb_under_a_small_cap_names_the_cap_given() {
    let r = inflate_stream(&deflate(&vec![0; 100_000], true), 1000, "total output capped at 1000 bytes");
    assert_eq!(r.note.as_deref(), Some("total output capped at 1000 bytes"));
    assert!(r.text.len() <= 1000);
}

#[test]
fn version_matches_the_other_implementations() {
    assert_eq!(VERSION, "0.1.0-alpha.1");
    let pkg = root().join("cli").join("package.json");
    if let Ok(t) = std::fs::read_to_string(pkg) {
        let v: serde_json::Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["version"].as_str().unwrap(), VERSION);
    }
    for gradle in [root().join("kotlin").join("gradle.properties"), root().join("android").join("gradle.properties")] {
        if let Ok(t) = std::fs::read_to_string(gradle) {
            assert!(t.lines().any(|l| l == format!("VERSION_NAME={VERSION}")) || !t.contains("VERSION_NAME="), "{t}");
        }
    }
}

// ---------- armor (SPEC.md 4.1) ----------

#[test]
fn armor_round_trip_of_a_real_bundle() {
    let a = file_of(&["first"]);
    let b = file_of(&["W net: second"]);
    let bundle = encode_bundle(&[&a, &b]);
    let text = armor(&bundle);
    assert!(text.starts_with("-----BEGIN CIPHERLOG BUNDLE-----\n"));
    assert!(text.ends_with("\n-----END CIPHERLOG BUNDLE-----\n"));
    assert!(text.lines().all(|l| l.len() <= 76 || l.starts_with("-----")));
    assert_eq!(dearmor(text.as_bytes()).unwrap().unwrap(), bundle);
    let r = read_bytes(text.as_bytes(), &key_ring(), "mail.cipherlogs.txt", &mut ReadBudget::default());
    assert!(r.notes.is_empty(), "{:?}", r.notes);
    assert_eq!(r.files.len(), 2);
    assert_eq!(r.files[0].name, "mail.cipherlogs.txt#1");
    assert!(r.files.iter().all(|f| f.opened && f.closed));
    // A mail client's \r\n, indentation, a greeting and a signature.
    let mailed = format!("Hi, logs attached below.\r\n\r\n  {}\r\n-- \r\nSent from my phone\r\n", text.trim_end().replace('\n', "\r\n  "));
    assert_eq!(dearmor(mailed.as_bytes()).unwrap().unwrap(), bundle);
}

#[test]
fn hostile_armor_is_rejected_with_a_note() {
    let bundle = encode_bundle(&[&file_of(&["x"])]);
    let text = armor(&bundle);
    let lines: Vec<&str> = text.lines().collect();
    let body = &lines[1..lines.len() - 1];
    let with_inner = |inner: &str| format!("{}\n{}\n{inner}\n{}\n", lines[0], body.join("\n"), lines[lines.len() - 1]);
    let cases: Vec<(String, &str)> = vec![
        (with_inner("not base64!"), "after BEGIN is not base64"),
        (with_inner("\u{1b}[2Jabc"), "after BEGIN is not base64"),
        (format!("{}\n{}\n", lines[0], body.join("\n")), "armor: no -----END CIPHERLOG BUNDLE----- line"),
        (text.replacen(&body[0][..4], "AB=C", 1), "armor: base64 is cut or badly padded"),
        (format!("{}\nZm9vY\n{}\n", lines[0], lines[lines.len() - 1]), "armor: base64 is cut or badly padded"),
        (format!("{}\nZm8===\n{}\n", lines[0], lines[lines.len() - 1]), "armor: base64 is cut or badly padded"),
        (format!("{}\nZm9v-_\n{}\n", lines[0], lines[lines.len() - 1]), "armor: line 1 after BEGIN is not base64"),
    ];
    for (input, want) in cases {
        let e = dearmor(input.as_bytes()).unwrap().unwrap_err();
        assert!(e.contains(want), "{e:?} should contain {want:?}");
        let r = read_bytes(input.as_bytes(), &key_ring(), "evil\u{1b}[31m.txt", &mut ReadBudget::default());
        assert!(r.files.is_empty());
        assert_eq!(r.notes.len(), 1);
        assert!(r.notes[0].starts_with("evil\\x1b[31m.txt: armor: "), "{}", r.notes[0]);
        assert!(!r.notes[0].contains('\u{1b}'));
    }
    // No BEGIN line: not armor at all, read as a (non-cipherlog) file.
    assert!(dearmor(b"hello").is_none());
    let r = read_bytes(b"hello", &key_ring(), "x.txt", &mut ReadBudget::default());
    assert_eq!(r.files[0].notes, vec!["not a cipherlog file (magic), skipped"]);
    // Armor holding a single file (not a bundle) still reads.
    let one = armor(&file_of(&["single"]));
    let r = read_bytes(one.as_bytes(), &key_ring(), "one.txt", &mut ReadBudget::default());
    assert_eq!(r.files.len(), 1);
    assert!(String::from_utf8_lossy(&r.files[0].text).contains("single"));
}

/// vectors/armor.json and vectors/keys.json: the cases every implementation shares.
#[test]
fn shared_armor_vectors() {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(vectors().join("armor.json")).unwrap()).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() > 20);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let input = c["text"].as_str().unwrap().as_bytes();
        let got = dearmor(input);
        match c.get("bytes") {
            Some(b) => {
                assert_eq!(hex(&got.expect(name).expect(name)), b.as_str().unwrap(), "{name}");
                assert!(cipherlog::armor::looks_armored(input), "{name}");
            }
            None => {
                let want = c["error"].as_str().unwrap();
                match got {
                    Some(r) => assert_eq!(r.unwrap_err(), want, "{name}"),
                    None => assert!(want.starts_with("armor: no -----BEGIN"), "{name}: not armored, expected {want}"),
                }
            }
        }
    }
}

#[test]
fn shared_key_vectors() {
    use cipherlog::keys::{parse_private_key_string, parse_public_key_string};
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(vectors().join("keys.json")).unwrap()).unwrap();
    let priv_hex: String =
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(vectors().join("test-key.json")).unwrap()).unwrap()["privateKey"]
            .as_str()
            .unwrap()
            .into();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() > 20);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let input = c["input"].as_str().unwrap();
        let got = if c["kind"] == "private" { parse_private_key_string(input).map(|k| *k) } else { parse_public_key_string(input) };
        match c.get("key") {
            Some(k) => assert_eq!(hex(&got.expect(name)), k.as_str().unwrap(), "{name}"),
            None => {
                let e = got.expect_err(name);
                assert_eq!(e, format!("cipherlog key: {}", c["error"].as_str().unwrap()), "{name}");
                assert!(!e.to_lowercase().contains(&priv_hex[..8]), "{name}");
            }
        }
    }
}
