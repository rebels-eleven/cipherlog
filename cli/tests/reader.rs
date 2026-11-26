// Ported from the reader and review tests of the retired TypeScript CLI (reader limits, reason order, report safety,
// duplicates), plus every vectors/samples/* directory, armored bundles included.
mod common;

use cipherlog::cli::{Input, open_report, write_file_bytes};
use cipherlog::format::{HEADER_LEN, TOTAL_INFLATE_CAP, encode_bundle, generate_key_pair, hex};
use cipherlog::reader::*;
use cipherlog::samples::build_sample;
use common::*;
use std::fs;

fn rf(bytes: &[u8], name: &str) -> FileResult {
    read_file(bytes, &key_ring(), name, &mut ReadBudget::default())
}

fn txt(r: &FileResult) -> String {
    String::from_utf8(r.text.clone()).unwrap()
}

fn sample_file(lines: usize) -> Vec<u8> {
    let input: String = (0..lines).map(|i| format!("{}line {i} ✓\n", if i % 3 == 0 { "W net: " } else { "" })).collect();
    write_file_bytes(&pub_key(), &input, "t", 1, 3, &mut step_clock(T0, 7)).unwrap()
}

#[test]
fn round_trip_write_read() {
    let s = build_sample(&pub_key(), true, T0).unwrap();
    let r = rf(&s.bytes, "x");
    assert_eq!(txt(&r), s.text);
    assert!(r.closed);
    assert_eq!(r.notes, vec!["closed"]);
    let h = r.header.unwrap();
    assert_eq!((h.platform, h.process, h.created_at), (0, 1, T0 as u64));
}

#[test]
fn truncation_at_every_byte_of_the_last_record_keeps_earlier_records() {
    let full = sample_file(10);
    let offs = record_offsets(&full);
    assert!(offs.len() >= 3);
    let last = *offs.last().unwrap();
    let full_text = txt(&rf(&full, "f"));
    let before = rf(&full[..last], "f");
    assert_eq!(before.records as usize, offs.len() - 1);
    assert!(!before.closed);
    assert_eq!(before.stopped_by, None);
    assert!(before.notes.contains(&"not closed (crash or still open), completeness unknown".to_string()));
    for cut in last + 1..full.len() {
        let r = rf(&full[..cut], "f");
        assert_eq!(r.records as usize, offs.len() - 1, "cut {cut}");
        assert!(!r.closed);
        assert_eq!(r.stopped_by.as_deref(), Some("truncated"));
        assert!(r.notes.contains(&format!("readable up to record {} (truncated)", offs.len() - 1)));
        assert!(r.notes.contains(&"not closed (crash or still open), completeness unknown".to_string()));
        assert_eq!(txt(&r), txt(&before));
        assert!(full_text.starts_with(&txt(&r)));
    }
}

#[test]
fn truncation_inside_the_header_skips_the_file_with_a_note() {
    let full = sample_file(3);
    for cut in [0, 3, 4, 50, 117] {
        let r = rf(&full[..cut], "f");
        assert!(!r.opened);
        assert_eq!(r.notes.len(), 1, "{:?}", r.notes);
    }
}

#[test]
fn corruption_in_the_middle_stops_at_that_record_with_a_note() {
    let full = sample_file(12);
    let offs = record_offsets(&full);
    assert!(offs.len() >= 4);
    let mut bad = full.clone();
    bad[offs[2] + 12] ^= 0x40;
    let r = rf(&bad, "f");
    assert_eq!(r.records, 2);
    assert_eq!(r.stopped_by.as_deref(), Some("authentication failed"));
    assert!(r.notes.contains(&"readable up to record 2 (authentication failed)".to_string()));
    assert!(!r.closed);
    assert_eq!(r.text, rf(&full[..offs[2]], "f").text);
    // Swapped records: seq out of order.
    let swapped = [&full[..offs[1]], &full[offs[2]..offs[3]], &full[offs[1]..offs[2]], &full[offs[3]..]].concat();
    let s = rf(&swapped, "f");
    assert_eq!(s.records, 1);
    assert_eq!(s.stopped_by.as_deref(), Some("seq 2, expected 1"));
}

#[test]
fn a_file_without_final_is_marked_not_closed() {
    let s = build_sample(&pub_key(), false, T0).unwrap();
    let r = rf(&s.bytes, "u");
    assert!(!r.closed);
    assert_eq!(txt(&r), s.text);
    assert!(r.notes.contains(&"not closed (crash or still open), completeness unknown".to_string()));
}

#[test]
fn nothing_may_follow_final() {
    let full = sample_file(3);
    let offs = record_offsets(&full);
    let r = rf(&[&full[..], &full[offs[0]..offs[1]]].concat(), "f");
    assert_eq!(r.stopped_by.as_deref(), Some("data after final"));
    assert_eq!(r.records as usize, offs.len());
    assert!(r.notes.contains(&format!("readable up to record {} (data after final)", offs.len())));
}

#[test]
fn unknown_key_id_is_skipped_with_a_note_other_files_still_read() {
    let other = generate_key_pair();
    let foreign = write_file_bytes(&other.public_key, "x\n", "o", 1, 0, &mut step_clock(T0, 1)).unwrap();
    let mine = sample_file(2);
    let res = read_bytes(&encode_bundle(&[&foreign, &mine]), &key_ring(), "b.cipherlogs", &mut ReadBudget::default());
    assert_eq!(res.files.len(), 2);
    assert!(!res.files[0].opened);
    assert_eq!(res.files[0].notes, vec![format!("unknown keyId {}, skipped", hex(&other.key_id))]);
    assert!(res.files[1].opened);
    assert_eq!(res.files[0].name, "b.cipherlogs#1");
}

#[test]
fn a_header_that_does_not_open_is_skipped_with_a_note() {
    let mut bad = sample_file(2);
    bad[100] ^= 1;
    let r = rf(&bad, "f");
    assert!(!r.opened);
    assert_eq!(r.notes, vec!["header does not open, skipped"]);
}

fn fake(lines: &[&str]) -> FileResult {
    FileResult { opened: true, text: (lines.join("\n") + "\n").into_bytes(), ..Default::default() }
}

#[test]
fn merge_by_time_is_stable_across_files_output_is_cleaned() {
    let a = fake(&["2026-01-01T00:00:00.002Z I a x: a2", "2026-01-01T00:00:00.001Z I a x: a1"]);
    let b = fake(&["2026-01-01T00:00:00.001Z I b x: b1 \u{1b}[31mred\u{1b}[0m \u{7}", "continuation without time"]);
    let m: Vec<String> = merge_lines(&[a, b]).into_iter().map(|l| l.line).collect();
    assert_eq!(
        m,
        vec![
            "2026-01-01T00:00:00.001Z I a x: a1",
            "2026-01-01T00:00:00.001Z I b x: b1 red ",
            "continuation without time",
            "2026-01-01T00:00:00.002Z I a x: a2",
        ]
    );
    assert_eq!(clean_line("a\u{1b}]0;title\u{7}b\u{9b}2Jc\td\u{0}"), "abc\td");
}

#[test]
fn ansi_forms_are_removed_like_the_reference() {
    // OSC ended by ST, DCS, two-character escapes, an unterminated CSI/OSC (only ESC and its next char go).
    assert_eq!(clean_line("a\u{1b}]8;;http://e\u{1b}\\b"), "ab");
    assert_eq!(clean_line("a\u{1b}Pq#0\u{1b}\\b"), "ab");
    assert_eq!(clean_line("a\u{1b}cb\u{1b}7c"), "acb7c");
    assert_eq!(clean_line("x\u{1b}Pabc"), "xabc");
    assert_eq!(clean_line("x\u{1b}^q"), "xq");
    assert_eq!(clean_line("x\u{9b}31mY"), "xY");
    assert_eq!(clean_line("x\u{1b}[?25hY"), "xY");
    assert_eq!(clean_line("a\u{1b}]unterminated"), "aunterminated");
    assert_eq!(clean_line("a\u{1b}[12"), "a[12");
    assert_eq!(clean_line("tab\tkept\r"), "tab\tkept");
    // Non-ASCII around and inside sequences: the in-place scan stays on character boundaries.
    assert_eq!(clean_line("é\u{1b}]título ✓\u{7}ñ"), "éñ");
    assert_eq!(clean_line("é\u{1b}Pdatos ✓\u{1b}\\ñ"), "éñ");
    assert_eq!(clean_line("\u{1b}é"), "é");
    assert_eq!(clean_line("ü\u{9b}"), "ü");
    assert_eq!(clean_line("ü\u{9b}é"), "üé");
    assert_eq!(clean_line("ü\u{9b}31mé"), "üé");
    assert_eq!(clean_line("a\u{1b}]x\u{1b}é"), "axé");
    assert_eq!(clean_block("line ✓\n\u{1b}[1mbold\u{1b}[0m\n"), "line ✓\nbold\n");
    // Times that V8 rejects do not start a group: the line sorts with the one before.
    let a = fake(&["2026-01-01T00:00:00.005Z I a x: first", "2026-13-01T00:00:00.000Z I a x: bad month"]);
    let b = fake(&["2026-01-01T00:00:00.006Z I b x: later"]);
    let m: Vec<String> = merge_lines(&[a, b]).into_iter().map(|l| l.line).collect();
    assert_eq!(m[1], "2026-13-01T00:00:00.000Z I a x: bad month");
}

#[test]
fn inflate_of_a_cut_stream_keeps_what_it_can() {
    let r = cipherlog::format::inflate_stream(
        &hx("ca48cdc9c95748ce2cc8482dcac94fe702000000ffff"),
        cipherlog::format::INFLATE_CAP,
        cipherlog::format::CAPPED_NOTE,
    );
    assert_eq!(r.text, b"hello cipherlog\n");
}

fn read_expected(p: &std::path::Path) -> Option<String> {
    fs::read_to_string(p).ok()
}

#[test]
fn every_vectors_samples_directory_opens_with_the_expected_text_and_status() {
    let root = vectors().join("samples");
    let mut dirs: Vec<String> = fs::read_dir(&root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    dirs.sort();
    assert!(dirs.contains(&"rust".to_string()), "own samples (vectors/samples/rust) must exist: cargo run --example make_samples");
    for d in &dirs {
        let p = |f: &str| root.join(d).join(f);
        let mut texts = vec![];
        for (file, exp, closed) in [("sample.cipherlog", "expected.txt", true), ("unclosed.cipherlog", "unclosed.expected.txt", false)] {
            let (Ok(bytes), Some(expected)) = (fs::read(p(file)), read_expected(&p(exp))) else {
                assert_ne!(d, "rust", "missing {file} in own samples");
                continue;
            };
            let r = rf(&bytes, &format!("{d}/{file}"));
            assert!(r.opened, "{d}/{file}: {:?}", r.notes);
            assert_eq!(r.stopped_by, None, "{d}/{file}: {:?}", r.notes);
            assert_eq!(txt(&r), expected, "{d}/{file} text");
            assert_eq!(r.closed, closed, "{d}/{file} closed");
            // SPEC.md 4.1: an armored payload may be a single file as well as a bundle.
            let a =
                read_bytes(cipherlog::armor::armor(&bytes).as_bytes(), &key_ring(), &format!("{d}/{file}.txt"), &mut ReadBudget::default());
            assert!(a.notes.is_empty(), "{d}/{file} armored: {:?}", a.notes);
            assert_eq!(a.files.len(), 1, "{d}/{file} armored");
            assert_eq!(txt(&a.files[0]), expected, "{d}/{file} armored text");
            assert_eq!(a.files[0].closed, closed, "{d}/{file} armored closed");
            texts.push(expected);
        }
        for bundle in ["sample.cipherlogs", "sample.cipherlogs.txt"] {
            let Ok(bytes) = fs::read(p(bundle)) else {
                assert!(d != "rust", "missing {bundle} in own samples");
                continue;
            };
            let b = read_bytes(&bytes, &key_ring(), &format!("{d}/{bundle}"), &mut ReadBudget::default());
            assert!(b.notes.is_empty(), "{d}/{bundle}: {:?}", b.notes);
            assert_eq!(b.files.len(), 2, "{d}/{bundle} entries");
            assert_eq!(b.files.iter().map(|f| f.closed).collect::<Vec<_>>(), vec![true, false], "{d}/{bundle} status");
            if texts.len() == 2 {
                assert_eq!(b.files.iter().map(txt).collect::<Vec<_>>(), texts, "{d}/{bundle} texts");
            }
        }
    }
}

#[test]
fn own_sample_meets_the_content_requirements() {
    let dir = vectors().join("samples").join("rust");
    let text = fs::read_to_string(dir.join("expected.txt")).unwrap();
    let lines: Vec<&str> = text.split('\n').filter(|l| !l.is_empty()).collect();
    assert!(lines.len() >= 20);
    for l in ["D", "I", "N", "W", "E", "F"] {
        assert!(lines.iter().any(|x| x.split(' ').nth(1) == Some(l)), "{l}");
    }
    assert!(!text.is_ascii());
    assert!(lines.iter().any(|l| l.contains(" device: phone · ")));
    let r = rf(&fs::read(dir.join("sample.cipherlog")).unwrap(), "s");
    assert!(r.records >= 3);
}

// ---------- review tests ----------

#[test]
fn total_output_is_capped_across_the_files_of_one_read() {
    let f = file_of(&[&"x".repeat(600)]);
    let one = rf(&f, "one").text.len();
    let r = read_bytes(&encode_bundle(&[&f, &f, &f]), &key_ring(), "b", &mut ReadBudget::new(one + 100));
    let note = format!("total output capped at {} bytes", one + 100);
    assert_eq!(r.files[0].text.len(), one);
    assert_eq!(r.files[1].text.len(), 100);
    assert!(r.files[1].notes.contains(&note), "{:?}", r.files[1].notes);
    assert_eq!(r.files[2].text.len(), 0);
    assert!(r.files[2].notes.contains(&note));
    assert_eq!(TOTAL_INFLATE_CAP, 256 * 1024 * 1024);
    // The budget is shared by every input of one report.
    let inputs = [Input { name: "a".into(), bytes: f.clone() }, Input { name: "b".into(), bytes: f.clone() }];
    let (text, _) = open_report(&inputs, &key_ring(), &[], Some(ReadBudget::new(one + 100)));
    assert!(text.contains("total output capped"));
    // The default budget is named in MiB.
    let mut b = ReadBudget { left: 0, ..Default::default() };
    let r = read_file(&f, &key_ring(), "x", &mut b);
    assert!(r.notes.contains(&"total output capped at 256 MiB".to_string()));
}

#[test]
fn a_zero_length_bundle_entry_is_skipped_later_entries_still_read() {
    let (a, b) = (file_of(&["first"]), file_of(&["second"]));
    let r = read_bytes(&encode_bundle(&[&a[..], &[], &b[..]]), &key_ring(), "z", &mut ReadBudget::default());
    assert!(r.notes.is_empty());
    assert_eq!(r.files.len(), 3);
    assert!(txt(&r.files[0]).contains("first"));
    assert_eq!(r.files[1].notes, vec!["shorter than a header, skipped"]);
    assert!(txt(&r.files[2]).contains("second"));
}

#[test]
fn report_file_names_and_read_errors_cannot_inject_terminal_escapes_or_lines() {
    let f = file_of(&["hello"]);
    let evil = "x\u{1b}[2K\rsource not verified: FAKE\nverified-ok.cipherlog";
    let (text, _) = open_report(
        &[Input { name: evil.into(), bytes: f }],
        &key_ring(),
        &["/tmp/a\u{1b}]8;;http://e\u{7}b: cannot read (ENOENT)".into()],
        None,
    );
    assert!(!text.contains('\u{1b}') && !text.contains('\r'));
    let lines: Vec<&str> = text.split('\n').collect();
    assert_eq!(lines.iter().filter(|l| l.starts_with("source not verified")).count(), 1);
    assert!(lines.iter().any(|l| l.starts_with("x\\x1b[2K\\x0dsource not verified: FAKE\\x0averified-ok.cipherlog · keyId")));
    assert!(lines.iter().any(|l| l.starts_with("/tmp/a\\x1b]8;;http://e\\x07b: cannot read")));
    assert_eq!(safe_text("ok name.cipherlog"), "ok name.cipherlog");
    // A bundle note carries the escaped name too.
    let mut cut = encode_bundle(&[&file_of(&["y"])]);
    cut.truncate(cut.len() - 5);
    let (text, _) = open_report(&[Input { name: "b\u{202e}.cipherlogs".into(), bytes: cut }], &key_ring(), &[], None);
    assert!(text.contains("b\\u202e.cipherlogs: bad length at entry 1, bundle ends"), "{text}");
}

#[test]
fn bidi_and_invisible_format_characters_are_removed_from_lines() {
    assert_eq!(clean_line("hello \u{202e}evil\u{202c} do\u{200b}ne"), "hello evil done");
    assert_eq!(clean_line("family 1\u{200d}2"), "family 1\u{200d}2", "ZWJ stays (emoji sequences)");
    assert_eq!(clean_line("a\u{200c}b"), "a\u{200c}b", "ZWNJ stays");
    for c in ['\u{61c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{2060}', '\u{2064}', '\u{2066}', '\u{2069}', '\u{feff}'] {
        assert_eq!(clean_line(&format!("a{c}b")), "ab", "U+{:04X}", c as u32);
    }
    assert_eq!(safe_text("a\u{202e}b"), "a\\u202eb");
    assert_eq!(safe_text("a\u{2028}b\u{85}c"), "a\\u2028b\\x85c");
}

#[test]
fn the_same_file_opened_twice_is_shown_once() {
    let f = file_of(&["only once"]);
    let inp = |n: &str, b: &[u8]| Input { name: n.into(), bytes: b.to_vec() };
    let (text, _) = open_report(&[inp("a.cipherlog", &f), inp("b.cipherlog", &f)], &key_ring(), &[], None);
    assert_eq!(text.split('\n').filter(|l| l.ends_with("only once")).count(), 1);
    assert!(text.lines().any(|l| l.starts_with("b.cipherlog · ") && l.ends_with("duplicate of a.cipherlog, lines shown once")), "{text}");
    // A longer copy (more records) wins over a truncated one.
    let (text2, _) = open_report(&[inp("cut", &f[..HEADER_LEN + 20]), inp("full", &f)], &key_ring(), &[], None);
    assert!(text2.lines().any(|l| l.starts_with("cut · ") && l.contains("duplicate of full")), "{text2}");
}

#[test]
fn report_layout_and_merge_across_inputs() {
    let a = file_of(&["W net: one"]);
    let (text, any) = open_report(&[Input { name: "a.cipherlog".into(), bytes: a }], &key_ring(), &[], None);
    assert!(any);
    let lines: Vec<&str> = text.split('\n').collect();
    assert_eq!(lines[0], SOURCE_NOT_VERIFIED);
    assert!(lines[1].starts_with("a.cipherlog · keyId dacb47e7a1ba0cf1 · file "));
    assert!(lines[1].ends_with(" · platform 3 (JVM) · process 1 · created 2026-11-18T11:06:40.000Z · 3 records: closed"), "{}", lines[1]);
    assert_eq!(lines[2], "");
    assert!(lines[3].starts_with("2026-11-18T11:06:40.000Z I t device: cipherlog 0.1.0-alpha.1 · file "), "{}", lines[3]);
    assert!(text.ends_with(" W t net: one\n"));
    let (none, any) = open_report(&[Input { name: "x".into(), bytes: b"nope".to_vec() }], &key_ring(), &[], None);
    assert!(!any);
    assert!(none.contains("x: not a cipherlog file (magic), skipped"));
}
