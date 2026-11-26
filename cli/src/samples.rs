//! The sample files of `vectors/samples/rust/` (SPEC.md 8): sample.cipherlog, expected.txt, unclosed.cipherlog,
//! unclosed.expected.txt, sample.cipherlogs and its armored form sample.cipherlogs.txt. Encrypted to the given
//! (test) public key; the text is deterministic (fixed clock), the keys are random.

use crate::armor::armor;
use crate::format::encode_bundle;
use crate::text::{Level, format_line};
use crate::writer::{Collector, FileWriter, WriteFail, device_block_lines};
use std::io;
use std::path::Path;

const PROCESS_NAME: &str = "sample.app";

const EVENTS: &[(Level, &str, &str)] = &[
    (Level::D, "net", "GET /v1/items 200 in 84 ms"),
    (Level::I, "ui", "screen opened: Home"),
    (Level::N, "sync", "cursor moved to 41"),
    (Level::I, "i18n", "Привет, мир · こんにちは · emoji 🦭👍🏽"),
    (Level::W, "net", "retry 1 after timeout"),
    (Level::I, "ui", "tap at 120,480"),
    (Level::D, "cache", "hit ratio 0.93"),
    (Level::E, "store", "DecodingError: field \"id\" missing"),
    (Level::I, "multi", "first line\nsecond line\r\nthird\rend"),
    (Level::I, "ctl", "bell \u{7} esc \u{1b}[31m del \u{7f} c1 \u{85} tab \t ok"),
    (Level::N, "", "no category"),
    (Level::I, "bad name/with spaces & ünïcode-and-more-than-thirty-two-characters", "category sanitised"),
    (Level::D, "net", "GET /v1/items 304"),
    (Level::W, "disk", "free space 120 MB"),
    (Level::I, "ui", "screen closed: Home"),
    (Level::F, "core", "assertion failed: state == ready"),
    (Level::I, "app", "background"),
    (Level::D, "bg", "refresh scheduled in 900 s"),
    (Level::I, "app", "foreground"),
    (Level::E, "net", "URLError: offline"),
    (Level::I, "app", "last line before the end"),
];

pub struct Sample {
    pub bytes: Vec<u8>,
    pub text: String,
}

/// One sample file: the device block (with a `phone` collector), then the events 137 ms apart, flushing after `W` and
/// above. `closed` ends it with `final`; otherwise it ends after a flush, and one more line is written but never
/// flushed (so it is not in the file, nor in the expected text).
pub fn build_sample(public_key: &[u8; 32], closed: bool, start: i64) -> Result<Sample, WriteFail> {
    let mut t = start;
    let mut clock = || {
        let v = t;
        t += 137;
        v
    };
    let mut text = String::new();
    let created_at = clock();
    let (mut w, mut bytes) = FileWriter::new(public_key, 0, 1, created_at as u64, None)?;
    let mut put = |w: &mut FileWriter, time: i64, level: Level, cat: &str, msg: &str| {
        let line = format_line(time, level, PROCESS_NAME, Some(cat), msg);
        w.write(&line);
        text.push_str(&line);
    };
    let phone = Collector::new("phone", || Ok(vec!["TestPhone1,1".into(), "TestOS 1.0 · ru-RU".into()]));
    for l in device_block_lines(&w.file_id_hex8(), 0, 1, &[phone], None) {
        put(&mut w, created_at, Level::I, "device", &l);
    }
    bytes.extend(w.flush()?);
    for &(level, cat, msg) in EVENTS {
        put(&mut w, clock(), level, cat, msg);
        if level >= Level::W {
            bytes.extend(w.flush()?);
        }
    }
    if closed {
        bytes.extend(w.finish()?);
    } else {
        bytes.extend(w.flush()?);
        w.write(&format_line(clock(), Level::I, PROCESS_NAME, Some("lost"), "this line was never flushed"));
        w.abandon();
    }
    Ok(Sample { bytes, text })
}

pub fn write_samples(public_key: &[u8; 32], dir: &Path) -> io::Result<()> {
    let to_io = |e: WriteFail| io::Error::other(format!("{e:?}"));
    std::fs::create_dir_all(dir)?;
    let closed = build_sample(public_key, true, 1_795_000_000_000).map_err(to_io)?;
    let open = build_sample(public_key, false, 1_795_000_100_000).map_err(to_io)?;
    let bundle = encode_bundle(&[&closed.bytes, &open.bytes]);
    std::fs::write(dir.join("sample.cipherlog"), &closed.bytes)?;
    std::fs::write(dir.join("expected.txt"), &closed.text)?;
    std::fs::write(dir.join("unclosed.cipherlog"), &open.bytes)?;
    std::fs::write(dir.join("unclosed.expected.txt"), &open.text)?;
    std::fs::write(dir.join("sample.cipherlogs.txt"), armor(&bundle))?;
    std::fs::write(dir.join("sample.cipherlogs"), bundle)?;
    Ok(())
}
