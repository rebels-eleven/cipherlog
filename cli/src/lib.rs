//! cipherlog: app logs encrypted at write time to the developer's X25519 public key.
//!
//! The `cipherlog-v1` format (SPEC.md): reader, synchronous reference writer, key strings, armored bundles, and the
//! `cipherlog` command line.

pub mod armor;
pub mod cli;
pub mod errno;
pub mod format;
pub mod keys;
pub mod reader;
pub mod samples;
pub mod text;
pub mod writer;
