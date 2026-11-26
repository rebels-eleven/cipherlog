//! Writes `vectors/samples/rust/` (SPEC.md 8) with the test key from `vectors/test-key.json`.
//!
//!     cargo run --example make_samples -- [<dir>]

use std::path::PathBuf;

fn main() {
    let vectors = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors"));
    let dir = std::env::args().nth(1).map_or_else(|| vectors.join("samples").join("rust"), PathBuf::from);
    let key: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vectors.join("test-key.json")).expect("vectors/test-key.json")).expect("JSON");
    let public = cipherlog::keys::parse_public_key(key["publicKey"].as_str().expect("publicKey"), "publicKey").expect("public key");
    cipherlog::samples::write_samples(&public, &dir).expect("write samples");
    println!("samples written to {}", dir.display());
}
