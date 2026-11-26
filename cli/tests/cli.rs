// Ported from the CLI tests of the retired TypeScript CLI: the binary, run as a user runs it, with a fake `op` on PATH.
mod common;

use cipherlog::format::{hex, key_id_of, public_key_from_private, unhex};
use cipherlog::keys::{PRIVATE_PREFIX, PUBLIC_PREFIX, parse_private_key, parse_public_key};
use cipherlog::reader::{ReadBudget, SOURCE_NOT_VERIFIED, read_file};
use common::*;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_cipherlog");

struct Out {
    code: i32,
    out: String,
    err: String,
}

fn run_env(args: &[&str], input: &str, env: &[(&str, String)]) -> Out {
    let mut cmd = Command::new(BIN);
    cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(input.as_bytes());
    drop(stdin);
    let o = child.wait_with_output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&o.stdout).into(),
        err: String::from_utf8_lossy(&o.stderr).into(),
    }
}

fn run(args: &[&str]) -> Out {
    run_env(args, "", &[])
}

fn keyfile() -> String {
    vectors().join("test-key.json").to_string_lossy().into_owned()
}

fn p(dir: &Path, f: &str) -> String {
    dir.join(f).to_string_lossy().into_owned()
}

fn mode(f: &str) -> u32 {
    fs::metadata(f).unwrap().permissions().mode() & 0o777
}

#[test]
fn keyid() {
    let k = test_key();
    let r = run(&["keyid", &k.public_hex]);
    assert_eq!(r.code, 0);
    assert_eq!(r.out, format!("{}\n", k.key_id));
    let r = run(&["keyid", &format!("{PUBLIC_PREFIX}{}", k.public_hex)]);
    assert_eq!((r.code, r.out), (0, format!("{}\n", k.key_id)));
    let r = run(&["keyid", &format!("{PUBLIC_PREFIX}{}", k.public_hex.to_uppercase())]);
    assert_eq!(r.code, 0, "uppercase hex");
    assert_eq!(run(&["keyid", "zz"]).code, 2);
    let r = run(&["keyid", &format!("{PRIVATE_PREFIX}{}", k.private_hex)]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("this is a PRIVATE key"), "{}", r.err);
    assert!(!r.err.contains(&k.private_hex[..16]));
    let r = run(&["keyid", &format!("{PUBLIC_PREFIX}{}", &k.public_hex[..62])]);
    assert!(r.err.contains("expected 64 hex characters after the prefix, got 62"), "{}", r.err);
    assert_eq!(run(&["keyid"]).code, 2);
}

#[test]
fn help_version_and_usage_errors() {
    let r = run(&[]);
    assert_eq!(r.code, 2);
    assert!(r.out.starts_with("cipherlog 0.1.0-alpha.1\n"));
    assert_eq!(run(&["help"]).code, 0);
    assert_eq!(run(&["--help"]).code, 0);
    assert_eq!(run(&["-h"]).code, 0);
    assert_eq!(run(&["--version"]).out, "0.1.0-alpha.1\n");
    let r = run(&["frob"]);
    assert_eq!(r.code, 2);
    assert!(r.err.starts_with("cipherlog: unknown command frob\n\ncipherlog 0.1.0-alpha.1"));
    let r = run(&["open", "x", "--key", "k", "--bogus", "1"]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("Unknown option '--bogus'"), "{}", r.err);
    let r = run(&["open", "x", "--key"]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("Option '--key <value>' argument missing"), "{}", r.err);
    assert!(run(&["open", "x", "--key", "--out"]).err.contains("ambiguous"));
    assert!(run(&["keygen", "extra"]).err.contains("Unexpected argument 'extra'"));
    assert_eq!(run(&["open", "--key", "k"]).code, 2, "open needs a file");
    assert_eq!(run(&["open", "x"]).code, 2, "open needs --key");
    assert!(run(&["write", "--out", "x"]).err.contains("write needs --pub and --out"));
}

#[test]
fn keygen_out_0600_json_prints_only_public_key_and_key_id_refuses_to_overwrite() {
    let dir = tmp_dir("kg");
    let file = p(&dir, "key.json");
    let r = run(&["keygen", "--out", &file]);
    assert_eq!(r.code, 0, "{}", r.err);
    let j: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    let g = |k: &str| j[k].as_str().unwrap().to_string();
    assert_eq!(mode(&file), 0o600);
    let private: [u8; 32] = unhex(&g("privateKey")).unwrap().try_into().unwrap();
    assert_eq!(hex(&public_key_from_private(&private).unwrap()), g("publicKey"));
    assert_eq!(hex(&key_id_of(&unhex(&g("publicKey")).unwrap().try_into().unwrap())), g("keyId"));
    assert_eq!(g("publicKeyString"), format!("{PUBLIC_PREFIX}{}", g("publicKey")));
    assert_eq!(g("privateKeyString"), format!("{PRIVATE_PREFIX}{}", g("privateKey")));
    assert_eq!(*parse_private_key(&g("privateKeyString"), "k").unwrap(), private);
    assert_eq!(r.out, format!("publicKey {}\nkeyId {}\n", g("publicKeyString"), g("keyId")));
    assert_eq!(
        parse_public_key(r.out.lines().next().unwrap().strip_prefix("publicKey ").unwrap(), "k").unwrap(),
        public_key_from_private(&private).unwrap()
    );
    for s in [&r.out, &r.err] {
        assert!(!s.contains(&g("privateKey")) && !s.contains(&g("privateKey").to_uppercase()));
    }
    let again = run(&["keygen", "--out", &file]);
    assert_eq!(again.code, 2);
    assert!(again.err.contains("exists; not overwriting"));
    let j2: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(j2["privateKey"], j["privateKey"]);
    assert_eq!(run(&["keygen"]).code, 2, "needs one of --out / --op-vault");
    assert_eq!(run(&["keygen", "--out", &p(&dir, "b.json"), "--op-vault", "v"]).code, 2, "not both");
    assert_eq!(run(&["keygen", "--out", &p(&dir, "c.json"), "--op-title", "t"]).code, 2, "--op-title needs --op-vault");
    assert!(!dir.join("b.json").exists() && !dir.join("c.json").exists());
    // The key file opens files written to its public key.
    let a = p(&dir, "a.cipherlog");
    assert_eq!(run_env(&["write", "--pub", &g("publicKeyString"), "--out", &a], "hi\n", &[]).code, 0);
    let o = run(&["open", &a, "--key", &file]);
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(o.out.contains(" I cli -: hi\n"));
}

/// A fake `op` (a shell script) that logs every call, stores the item of `op item create` and answers `op read`.
fn fake_op(dir: &Path) -> PathBuf {
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let script = r#"#!/bin/sh
log="$FAKE_OP_LOG"
n=$(ls "$log" | grep -c '^call-.*\.argv$')
call="$log/call-$n"
for a in "$@"; do printf '%s\n' "$a"; done > "$call.argv"
if [ "$1" = "read" ]; then
  : > "$call.stdin"
  field="${2##*/}"
  sed -n "s/.*\"id\":\"$field\"[^}]*\"value\":\"\([^\"]*\)\".*/\1/p" "$log/item.json"
  exit 0
fi
if [ "$1" = "item" ] && [ "$2" = "list" ]; then
  : > "$call.stdin"
  if [ -f "$log/item.json" ]; then
    sed -n 's/^{"title":"\([^"]*\)".*/[{"id":"x","title":"\1"}]/p' "$log/item.json"
  else
    printf '[]'
  fi
  exit 0
fi
cat > "$call.stdin"
if [ "$1" = "item" ] && [ "$2" = "create" ]; then
  cp "$call.stdin" "$log/item.json"
  printf '{"id":"x"}'
  exit 0
fi
exit 3
"#;
    let f = bin.join("op");
    fs::write(&f, script).unwrap();
    fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

fn calls(dir: &Path) -> Vec<(Vec<String>, String)> {
    (0..)
        .map_while(|i| {
            let argv = fs::read_to_string(dir.join(format!("call-{i}.argv"))).ok()?;
            let stdin = fs::read_to_string(dir.join(format!("call-{i}.stdin"))).unwrap_or_default();
            Some((argv.lines().map(str::to_string).collect(), stdin))
        })
        .collect()
}

#[test]
fn keygen_op_vault_passes_the_item_on_stdin_never_in_argv_open_reads_it_back_via_op_read() {
    let dir = tmp_dir("op");
    let log = tmp_dir("oplog");
    let bin = fake_op(&dir);
    let env = [("PATH", format!("{}:{}", bin.display(), std::env::var("PATH").unwrap())), ("FAKE_OP_LOG", log.to_string_lossy().into())];
    let r = run_env(&["keygen", "--op-vault", "Dev Keys", "--op-title", "cipherlog test"], "", &env);
    assert_eq!(r.code, 0, "{}", r.err);
    let c = calls(&log);
    assert_eq!(c.len(), 2);
    assert_eq!(c[0].0, vec!["item", "list", "--vault", "Dev Keys", "--format", "json"]);
    let c = &c[1..];
    assert_eq!(c[0].0, vec!["item", "create", "--vault", "Dev Keys", "-"]);
    let item: serde_json::Value = serde_json::from_str(&c[0].1).unwrap();
    assert_eq!(item["title"], "cipherlog test");
    assert_eq!(item["category"], "PASSWORD");
    let fields = item["fields"].as_array().unwrap();
    let field = |id: &str| fields.iter().find(|f| f["id"] == id).unwrap().clone();
    let pw = field("password");
    assert_eq!(pw["type"], "CONCEALED");
    assert_eq!(pw["purpose"], "PASSWORD");
    let private_string = pw["value"].as_str().unwrap().to_string();
    let private = parse_private_key(&private_string, "password").unwrap();
    assert!(private_string.starts_with(PRIVATE_PREFIX));
    let private_hex = &private_string[PRIVATE_PREFIX.len()..];
    assert!(!c[0].0.join(" ").contains(private_hex));
    assert!(!r.out.contains(private_hex) && !r.err.contains(private_hex));
    let public = format!("{PUBLIC_PREFIX}{}", hex(&public_key_from_private(&private).unwrap()));
    assert_eq!(field("publicKey")["value"], public.as_str());
    let key_id = field("keyId")["value"].as_str().unwrap().to_string();
    assert_eq!(r.out, format!("publicKey {public}\nkeyId {key_id}\n"));
    assert!(r.err.contains("op://Dev Keys/cipherlog test/password"), "{}", r.err);

    // Write with the new public key, open with the op:// reference.
    let file = p(&dir, "w.cipherlog");
    assert_eq!(run_env(&["write", "--pub", &public, "--out", &file], "hello from op\n", &[]).code, 0);
    let o = run_env(&["open", &file, "--key", "op://Dev Keys/cipherlog test/password"], "", &env);
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(o.out.contains("hello from op"));
    assert_eq!(calls(&log)[2].0, vec!["read", "op://Dev Keys/cipherlog test/password"]);
    // Rotating with the same title is refused before anything is created: `op://vault/title` would match two items.
    let again = run_env(&["keygen", "--op-vault", "Dev Keys", "--op-title", "cipherlog test"], "", &env);
    assert_eq!(again.code, 2, "{}", again.err);
    assert!(again.err.contains("already has an item titled \"cipherlog test\""), "{}", again.err);
    assert_eq!(again.out, "");
    let c = calls(&log);
    assert_eq!(c.len(), 4, "a list and no create");
    assert_eq!(c[3].0[..2], ["item", "list"]);
    // A default title names the keyId.
    let r = run_env(&["keygen", "--op-vault", "v"], "", &env);
    assert_eq!(r.code, 0);
    let item: serde_json::Value = serde_json::from_str(&calls(&log)[5].1).unwrap();
    let kid = r.out.lines().nth(1).unwrap().strip_prefix("keyId ").unwrap();
    assert_eq!(item["title"], format!("cipherlog key {kid}").as_str());
    // A reference op cannot read is a usage error.
    let bad = run_env(&["open", &file, "--key", "op://v/missing/nothing"], "", &env);
    assert_eq!(bad.code, 2, "{}", bad.err);
}

#[test]
fn keygen_op_vault_op_failure_exits_non_zero_and_saves_nothing() {
    let dir = tmp_dir("opfail");
    let r = run_env(&["keygen", "--op-vault", "v"], "", &[("PATH", dir.to_string_lossy().into())]);
    assert_eq!(r.code, 1);
    assert_eq!(r.out, "");
    assert!(r.err.contains("op item list failed (ENOENT); the private key was not saved anywhere"), "{}", r.err);
    // op lists the vault but cannot create the item.
    let bin = dir.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join("op"), "#!/bin/sh\nif [ \"$2\" = list ]; then printf '[]'; exit 0; fi\ncat >/dev/null\nexit 5\n").unwrap();
    fs::set_permissions(bin.join("op"), fs::Permissions::from_mode(0o755)).unwrap();
    let r = run_env(&["keygen", "--op-vault", "v"], "", &[("PATH", format!("{}:/usr/bin:/bin", bin.display()))]);
    assert_eq!(r.code, 1);
    assert_eq!(r.out, "");
    assert!(r.err.contains("op item create failed (exit 5); the private key was not saved anywhere"), "{}", r.err);
    // op exits non-zero.
    fs::write(bin.join("op"), "#!/bin/sh\ncat >/dev/null\nexit 4\n").unwrap();
    fs::set_permissions(bin.join("op"), fs::Permissions::from_mode(0o755)).unwrap();
    let r = run_env(&["keygen", "--op-vault", "v"], "", &[("PATH", format!("{}:/usr/bin:/bin", bin.display()))]);
    assert_eq!(r.code, 1);
    assert_eq!(r.out, "");
    assert!(r.err.contains("(exit 4)"), "{}", r.err);
}

#[test]
fn write_then_open_header_line_notes_merged_clean_lines_out_is_0600_and_never_overwrites() {
    let dir = tmp_dir("open");
    let a = p(&dir, "a.cipherlog");
    let k = test_key();
    let input = "W net: timeout \u{1b}[31mred\u{1b}[0m\nplain message\nE store: failed\n";
    let w =
        run_env(&["write", "--pub", &k.public_hex, "--out", &a, "--process-name", "demo", "--process", "7", "--platform", "2"], input, &[]);
    assert_eq!(w.code, 0, "{}", w.err);
    assert_eq!(mode(&a), 0o600);
    assert_ne!(run_env(&["write", "--pub", &k.public_hex, "--out", &a], input, &[]).code, 0, "refuses overwrite");
    let r = read_file(&fs::read(&a).unwrap(), &key_ring(), "a", &mut ReadBudget::default());
    assert!(r.closed);
    assert_eq!(r.header.as_ref().unwrap().process, 7);
    assert_eq!(r.header.as_ref().unwrap().platform, 2);

    let bundle = vectors().join("samples").join("cli").join("sample.cipherlogs");
    let o = run(&["open", &a, &bundle.to_string_lossy(), "--key", &keyfile()]);
    assert_eq!(o.code, 0, "{}", o.err);
    let lines: Vec<&str> = o.out.split('\n').collect();
    assert_eq!(lines[0], SOURCE_NOT_VERIFIED);
    let l1 = lines[1];
    assert!(l1.starts_with("a.cipherlog · keyId dacb47e7a1ba0cf1 · file "), "{l1}");
    assert!(l1.contains(" · platform 2 (Android) · process 7 · created ") && l1.ends_with(" records: closed"), "{l1}");
    assert!(o.out.contains("sample.cipherlogs#2 ") && o.out.contains(": not closed (crash or still open), completeness unknown"));
    assert!(o.out.contains(" W demo net: timeout \u{fffd}[31mred\u{fffd}[0m\n"));
    assert!(o.out.contains(" I demo -: plain message\n"));
    assert!(o.out.contains(" E demo store: failed\n"));
    assert!(!o.out.chars().any(|c| matches!(c, '\u{0}'..='\u{8}' | '\u{b}'..='\u{1f}' | '\u{7f}')));
    let empty = lines.iter().position(|l| l.is_empty()).unwrap();
    let times: Vec<&str> = lines[empty + 1..].iter().filter(|l| !l.is_empty()).map(|l| &l[..24]).collect();
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted, "merged by time");

    let out = p(&dir, "out.txt");
    assert_eq!(run(&["open", &a, "--key", &keyfile(), "--out", &out]).code, 0);
    assert_eq!(mode(&out), 0o600);
    assert!(fs::read_to_string(&out).unwrap().contains("plain message"));
    let again = run(&["open", &a, "--key", &keyfile(), "--out", &out]);
    assert_eq!(again.code, 2);
    assert!(again.err.contains("exists; not overwriting"));
}

#[test]
fn open_exits_non_zero_only_when_nothing_could_be_read() {
    let dir = tmp_dir("none");
    let other = p(&dir, "k.json");
    assert_eq!(run(&["keygen", "--out", &other]).code, 0);
    let a = p(&dir, "a.cipherlog");
    run_env(&["write", "--pub", &test_key().public_hex, "--out", &a], "x\n", &[]);
    let unknown = run(&["open", &a, "--key", &other]);
    assert_eq!(unknown.code, 1);
    assert!(unknown.out.contains("unknown keyId dacb47e7a1ba0cf1, skipped"));
    let missing = run(&["open", &a, &p(&dir, "missing.cipherlog"), "--key", &keyfile()]);
    assert_eq!(missing.code, 0);
    assert!(missing.out.contains("missing.cipherlog: cannot read (ENOENT)"), "{}", missing.out);
    let k = test_key();
    let hex_key = p(&dir, "priv.hex");
    fs::write(&hex_key, format!("{}\n", k.private_hex)).unwrap();
    assert_eq!(run(&["open", &a, "--key", &other, "--key", &hex_key]).code, 0, "repeatable --key, hex file");
    let str_key = p(&dir, "priv.txt");
    fs::write(&str_key, format!("{PRIVATE_PREFIX}{}\n", k.private_hex.to_uppercase())).unwrap();
    assert_eq!(run(&["open", &a, "--key", &str_key]).code, 0, "key string file, uppercase hex");
    // Only unreadable inputs: exit 1.
    assert_eq!(run(&["open", &p(&dir, "missing.cipherlog"), "--key", &keyfile()]).code, 1);
    // A missing key file: exit 1 with Node's message form.
    let r = run(&["open", &a, "--key", &p(&dir, "nokey.json")]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("ENOENT: no such file or directory, open '"), "{}", r.err);
}

#[test]
fn key_errors_never_echo_the_private_key() {
    let dir = tmp_dir("keyerr");
    let k = test_key();
    let a = p(&dir, "a.cipherlog");
    run_env(&["write", "--pub", &k.public_hex, "--out", &a], "x\n", &[]);
    let cases = [
        format!("{PRIVATE_PREFIX}{}", &k.private_hex[..63]),
        format!("{PRIVATE_PREFIX}{}g", &k.private_hex[..63]),
        format!("{PRIVATE_PREFIX}{} extra", k.private_hex),
        format!("{{\"privateKey\": \"{}zz\"}}", &k.private_hex[..62]),
        format!("{PUBLIC_PREFIX}{}", k.private_hex),
    ];
    for (i, text) in cases.iter().enumerate() {
        let f = p(&dir, &format!("bad{i}.key"));
        fs::write(&f, text).unwrap();
        let r = run(&["open", &a, "--key", &f]);
        assert_eq!(r.code, 2, "{text}: {}", r.err);
        for s in [&r.out, &r.err] {
            assert!(!s.contains(&k.private_hex[..20]) && !s.contains(&k.private_hex[40..]), "echoed: {s}");
        }
    }
    // A mistyped key in place of a file (no such file) is not echoed in the ENOENT error either.
    let h = &k.private_hex;
    let near_misses = [
        h[..63].to_string(),
        format!("{h}0"),
        format!("{}x{}", &h[..30], &h[31..]),
        format!("{h}'"),
        format!("\u{a0}{h}"),
        format!("CIPHERLOG-PRIV-V1:{h}"),
        format!("{PRIVATE_PREFIX}{}", &h[..63]),
        format!("cipherlog-priv-v1 {h}"),
    ];
    for spec in near_misses {
        let r = run(&["open", &a, "--key", &spec]);
        assert_ne!(r.code, 0, "{spec}");
        for i in 0..h.len() - 12 {
            assert!(!r.err.contains(&h[i..i + 12]) && !r.out.contains(&h[i..i + 12]), "echoed {spec:?}: {}", r.err);
        }
    }
    // A plain missing path is still named.
    let r = run(&["open", &a, "--key", &p(&dir, "cipherlog-key.json")]);
    assert!(r.err.contains("ENOENT: no such file or directory, open '") && r.err.contains("cipherlog-key.json"), "{}", r.err);
    // The key itself in place of a file is refused without echoing it.
    for spec in [format!("{PRIVATE_PREFIX}{}", k.private_hex), k.private_hex.clone()] {
        let r = run(&["open", &a, "--key", &spec]);
        assert_eq!(r.code, 2);
        assert!(r.err.contains("not the key itself"), "{}", r.err);
        assert!(!r.err.contains(&k.private_hex[..20]));
    }
}

#[test]
fn open_reads_armored_bundles_and_reports_bad_armor() {
    let dir = tmp_dir("armor");
    let txt = vectors().join("samples").join("rust").join("sample.cipherlogs.txt");
    let o = run(&["open", &txt.to_string_lossy(), "--key", &keyfile()]);
    assert_eq!(o.code, 0, "{}", o.err);
    assert!(o.out.contains("sample.cipherlogs.txt#1 · keyId dacb47e7a1ba0cf1"));
    assert!(o.out.contains("assertion failed: state == ready"));
    let bad = p(&dir, "bad.cipherlogs.txt");
    fs::write(&bad, "-----BEGIN CIPHERLOG BUNDLE-----\nQ1BC!MQ==\n-----END CIPHERLOG BUNDLE-----\n").unwrap();
    let o = run(&["open", &bad, "--key", &keyfile()]);
    assert_eq!(o.code, 1);
    assert!(o.out.contains("bad.cipherlogs.txt: armor: line 1 after BEGIN is not base64"), "{}", o.out);
}

/// vectors/cli-open.expected.txt is the report of the retired TypeScript reference CLI on the frozen cli and kotlin
/// samples; the Rust CLI must print it byte for byte.
#[test]
fn open_with_the_frozen_samples_matches_the_retired_typescript_cli() {
    let mut args: Vec<String> = vec!["open".into()];
    for d in ["cli", "kotlin"] {
        for f in ["sample.cipherlogs", "sample.cipherlog", "unclosed.cipherlog"] {
            args.push(vectors().join("samples").join(d).join(f).to_string_lossy().into());
        }
    }
    args.extend(["--key".into(), keyfile()]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let rs = run(&refs);
    assert_eq!(rs.code, 0, "{}", rs.err);
    assert_eq!(rs.out, fs::read_to_string(vectors().join("cli-open.expected.txt")).unwrap(), "report differs from the frozen one");
}
