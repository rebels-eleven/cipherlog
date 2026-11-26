// examples/gen_vectors.rs reproduces the committed vectors/records.json and vectors/test-key.json byte for byte (the
// randomized header is kept from the committed file), so Node is not needed to regenerate them.
#[allow(dead_code)]
#[path = "../examples/gen_vectors.rs"]
mod gen_vectors;

use std::path::PathBuf;

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("vectors")
}

#[test]
fn regenerates_the_committed_vectors_byte_for_byte() {
    let key_text = std::fs::read_to_string(vectors().join("test-key.json")).unwrap();
    let records = std::fs::read_to_string(vectors().join("records.json")).unwrap();
    let (key_out, public, private) = gen_vectors::key_file(Some(&key_text));
    assert_eq!(key_out, key_text);
    let header = gen_vectors::reusable_header(Some(&records), &private).expect("committed header opens with the test key");
    let (out, header_len, good_len) = gen_vectors::records_json(&public, Some(header));
    assert_eq!((header_len, good_len), (118, 103));
    assert_eq!(out, records);
}

#[test]
fn a_fresh_header_changes_only_the_header_and_file_hex() {
    let key_text = std::fs::read_to_string(vectors().join("test-key.json")).unwrap();
    let records = std::fs::read_to_string(vectors().join("records.json")).unwrap();
    let (_, public, private) = gen_vectors::key_file(Some(&key_text));
    let (out, _, _) = gen_vectors::records_json(&public, None);
    let strip = |s: &str| s.lines().filter(|l| !l.trim_start().starts_with("\"hex\"")).collect::<Vec<_>>().join("\n");
    assert_eq!(strip(&out), strip(&records));
    assert!(gen_vectors::reusable_header(Some(&out), &private).is_some(), "the new header opens");
    assert_ne!(out, records);
}
