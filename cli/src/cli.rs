//! cipherlog command line: keygen, keyid, open, write.

use crate::errno::{io_code, node_message};
use crate::format::{VERSION, generate_key_pair, hex, key_id_of, public_key_from_private};
use crate::keys::{PRIVATE_PREFIX, parse_private_key, parse_public_key, private_key_from_text, private_key_string, public_key_string};
use crate::reader::{KeyRing, ReadBudget, SOURCE_NOT_VERIFIED, describe_file, mark_duplicates, merged_blocks, read_bytes, safe_text};
use crate::text::{Level, format_line};
use crate::writer::{FileWriter, WriteFail, device_block_lines, now_ms};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use zeroize::{Zeroize, Zeroizing};

pub fn usage() -> String {
    format!(
        "cipherlog {VERSION}

  cipherlog keygen (--out <file> | --op-vault <vault> [--op-title <title>])
  cipherlog keyid <public key: cipherlog-pub-v1:… or 64 hex>
  cipherlog open <files or bundles (.cipherlog, .cipherlogs, .cipherlogs.txt)...> --key <file | op://vault/item/field> [--key …] [--out <file>]
  cipherlog write --pub <public key> --out <file> [--process-name <name>] [--process <u8>] [--platform <u8>]
"
    )
}

/// An error in how the command was called: exit code 2 and the usage text.
#[derive(Debug)]
pub struct UsageError(pub String);

/// What ends a command early: a usage error (exit 2) or another failure (exit 1, the message alone).
#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Other(String),
}

impl From<UsageError> for CliError {
    fn from(e: UsageError) -> Self {
        CliError::Usage(e.0)
    }
}

fn usage_err<T>(m: impl Into<String>) -> Result<T, CliError> {
    Err(CliError::Usage(m.into()))
}

// ---------- arguments (the rules of Node's util.parseArgs, strict) ----------

#[derive(Default)]
pub struct Parsed {
    pub values: HashMap<String, Vec<String>>,
    pub positionals: Vec<String>,
}

impl Parsed {
    /// The last value of a string option.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(|v| v.last()).map(String::as_str)
    }
}

pub fn parse_args(args: &[String], options: &[&str], allow_positionals: bool) -> Result<Parsed, UsageError> {
    let mut p = Parsed::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "--" {
            p.positionals.extend(args[i..].iter().cloned());
            break;
        }
        if let Some(body) = a.strip_prefix("--") {
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            if !options.contains(&name) {
                return Err(UsageError(format!("Unknown option '--{name}'")));
            }
            let value = match inline {
                Some(v) => v,
                None => match args.get(i) {
                    None => return Err(UsageError(format!("Option '--{name} <value>' argument missing"))),
                    Some(v) if v.len() > 1 && v.starts_with('-') => {
                        return Err(UsageError(format!(
                            "Option '--{name}' argument is ambiguous. To specify an option argument starting with a dash use '--{name}=-XYZ'."
                        )));
                    }
                    Some(v) => {
                        i += 1;
                        v.clone()
                    }
                },
            };
            p.values.entry(name.to_string()).or_default().push(value);
        } else if a.len() > 1 && a.starts_with('-') {
            return Err(UsageError(format!("Unknown option '{a}'")));
        } else if allow_positionals {
            p.positionals.push(a.clone());
        } else {
            return Err(UsageError(format!("Unexpected argument '{a}'. This command does not take positional arguments")));
        }
    }
    Ok(p)
}

fn parse_u8(s: Option<&str>, what: &str, dflt: u8) -> Result<u8, CliError> {
    match s {
        None => Ok(dflt),
        Some(s) if (1..=3).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit()) => {
            s.parse::<u16>().ok().and_then(|n| u8::try_from(n).ok()).map_or_else(|| usage_err(format!("{what} must be 0..255")), Ok)
        }
        Some(_) => usage_err(format!("{what} must be 0..255")),
    }
}

/// Writes a new file with mode 0600; refuses to overwrite.
fn write_new_private(file: &str, data: &[u8]) -> Result<(), CliError> {
    let mut f = open_new_private(file)?;
    f.write_all(data).map_err(|e| CliError::Other(node_message(&e, "write", file)))
}

fn open_new_private(file: &str) -> Result<std::fs::File, CliError> {
    match OpenOptions::new().write(true).create_new(true).mode(0o600).open(file) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => usage_err(format!("{file} exists; not overwriting")),
        Err(e) => Err(CliError::Other(node_message(&e, "open", file))),
    }
}

/// A JSON string literal, as JSON.stringify writes it.
fn js(s: &str) -> String {
    serde_json::to_string(s).expect("strings serialize")
}

// ---------- keygen ----------

/// Appends `s` as a JSON string to `out`, which the caller sized so nothing reallocates. Only for strings that need no
/// escaping (hex, key strings, key ids), so no temporary copy of a key is made.
fn push_plain_json(out: &mut String, s: &str) {
    assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-'), "needs no JSON escaping");
    out.push('"');
    out.push_str(s);
    out.push('"');
}

/// The 1Password item, as one line of JSON for `op item create … -` on stdin. Wiped when dropped; the private key is
/// copied into it once, into a buffer sized up front (no reallocation leaves a copy behind).
pub fn op_item_template(title: &str, private_key: &str, public_key: &str, key_id: &str) -> Zeroizing<String> {
    let title = js(title);
    let mut out = Zeroizing::new(String::with_capacity(320 + title.len() + private_key.len() + public_key.len() + key_id.len()));
    out.push_str("{\"title\":");
    out.push_str(&title);
    out.push_str(",\"category\":\"PASSWORD\",\"fields\":[{\"id\":\"password\",\"type\":\"CONCEALED\",\"purpose\":\"PASSWORD\",\"label\":\"password\",\"value\":");
    push_plain_json(&mut out, private_key);
    out.push_str("},{\"id\":\"publicKey\",\"type\":\"STRING\",\"label\":\"publicKey\",\"value\":");
    push_plain_json(&mut out, public_key);
    out.push_str("},{\"id\":\"keyId\",\"type\":\"STRING\",\"label\":\"keyId\",\"value\":");
    push_plain_json(&mut out, key_id);
    out.push_str("}]}");
    out
}

/// The key file of `keygen --out` (JSON). Wiped when dropped; like `op_item_template`, built without temporary copies
/// of the private key.
pub fn key_file_json(public_key: &[u8; 32], private_key: &[u8; 32]) -> Zeroizing<String> {
    let private_hex = Zeroizing::new(hex(private_key));
    let private = private_key_string(private_key);
    let public = public_key_string(public_key);
    let key_id = hex(&key_id_of(public_key));
    let mut out = Zeroizing::new(String::with_capacity(160 + 2 * private.len() + 2 * public.len() + key_id.len()));
    out.push_str("{\n  \"publicKey\": ");
    push_plain_json(&mut out, &hex(public_key));
    out.push_str(",\n  \"privateKey\": ");
    push_plain_json(&mut out, &private_hex);
    out.push_str(",\n  \"keyId\": ");
    push_plain_json(&mut out, &key_id);
    out.push_str(",\n  \"publicKeyString\": ");
    push_plain_json(&mut out, &public);
    out.push_str(",\n  \"privateKeyString\": ");
    push_plain_json(&mut out, &private);
    out.push_str("\n}\n");
    out
}

/// Titles of the items in a 1Password vault (`op item list --vault V --format json`).
fn op_item_titles(vault: &str) -> Result<Vec<String>, String> {
    let out = Command::new("op")
        .args(["item", "list", "--vault", vault, "--format", "json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| io_code(&e))?;
    if !out.status.success() {
        return Err(format!("exit {}", out.status.code().map_or("null".to_string(), |c| c.to_string())));
    }
    let items: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|_| "unexpected output".to_string())?;
    let items = items.as_array().ok_or_else(|| "unexpected output".to_string())?;
    Ok(items.iter().filter_map(|i| i.get("title").and_then(|t| t.as_str()).map(str::to_string)).collect())
}

fn keygen(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> Result<i32, CliError> {
    let p = parse_args(args, &["out", "op-vault", "op-title"], false)?;
    let (file, vault) = (p.get("out"), p.get("op-vault"));
    if file.is_none() == vault.is_none() {
        return usage_err("keygen needs exactly one of --out or --op-vault");
    }
    if p.get("op-title").is_some() && vault.is_none() {
        return usage_err("--op-title needs --op-vault");
    }
    let kp = generate_key_pair();
    let public = public_key_string(&kp.public_key);
    let key_id = hex(&kp.key_id);
    let private = private_key_string(&kp.private_key);
    if let Some(file) = file {
        let json = key_file_json(&kp.public_key, &kp.private_key);
        write_new_private(file, json.as_bytes())?;
    } else {
        let vault = vault.expect("checked");
        let title = p.get("op-title").map_or_else(|| format!("cipherlog key {key_id}"), str::to_string);
        // `op://vault/title/field` names an item by title, and `op read` fails when two items match: a second item
        // with the same title (a key rotation with the same --op-title) would break the old reference and the new one.
        match op_item_titles(vault) {
            Ok(titles) if titles.contains(&title) => {
                return usage_err(format!(
                    "1Password vault {vault} already has an item titled \"{title}\"; a second one would make op://{vault}/{title}/password match two items. Choose another --op-title (without one, the title carries the key id)"
                ));
            }
            Ok(_) => {}
            Err(why) => {
                let _ = writeln!(err, "cipherlog: op item list failed ({why}); the private key was not saved anywhere");
                return Ok(1);
            }
        }
        let template = op_item_template(&title, &private, &public, &key_id);
        // The template goes on stdin, never in argv: arguments are visible to other processes.
        let r = Command::new("op")
            .args(["item", "create", "--vault", vault, "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .and_then(|mut child| {
                let w = child.stdin.take().expect("piped").write_all(template.as_bytes());
                let status = child.wait()?;
                // A child that exits without reading its input is judged by its exit status alone.
                if let Err(e) = w
                    && e.kind() != io::ErrorKind::BrokenPipe
                {
                    return Err(e);
                }
                Ok(status)
            });
        drop(template);
        let why = match r {
            Err(e) => Some(io_code(&e)),
            Ok(s) if !s.success() => Some(format!("exit {}", s.code().map_or("null".to_string(), |c| c.to_string()))),
            Ok(_) => None,
        };
        if let Some(why) = why {
            let _ = writeln!(err, "cipherlog: op item create failed ({why}); the private key was not saved anywhere");
            return Ok(1);
        }
        let _ = writeln!(err, "saved in 1Password: op://{vault}/{title}/password");
    }
    drop(private);
    drop(kp);
    let _ = write!(out, "publicKey {public}\nkeyId {key_id}\n");
    Ok(0)
}

// ---------- keys for open ----------

const OP_READ_MAX: u64 = 1 << 20;

/// A private key from a key file or a 1Password reference (`op://vault/item/field`, read with `op read`).
pub fn load_key(spec: &str) -> Result<Zeroizing<[u8; 32]>, CliError> {
    if spec.starts_with("op://") {
        let child = Command::new("op").args(["read", spec]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn();
        let Ok(mut child) = child else { return usage_err(format!("op read failed for {spec}")) };
        // One buffer of the full size, read into in place: `read_to_end` into a growing Vec would free partial copies
        // of the key on every reallocation without wiping them.
        let mut buf = Zeroizing::new(vec![0u8; OP_READ_MAX as usize + 1]);
        let mut n = 0;
        let mut stdout = child.stdout.take().expect("piped");
        let read = loop {
            if n == buf.len() {
                break Ok(());
            }
            match stdout.read(&mut buf[n..]) {
                Ok(0) => break Ok(()),
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => break Err(e),
            }
        };
        drop(stdout);
        if read.is_err() || n as u64 > OP_READ_MAX {
            let _ = child.kill();
            let _ = child.wait();
            return usage_err(format!("op read failed for {spec}"));
        }
        match child.wait() {
            Ok(s) if s.success() => {}
            _ => return usage_err(format!("op read failed for {spec}")),
        }
        let text = Zeroizing::new(String::from_utf8_lossy(&buf[..n]).into_owned());
        return private_key_from_text(&text, spec).map_err(CliError::Usage);
    }
    // A key passed as the argument itself would sit in the shell history and the process list: refuse it, and do not
    // echo it in a "cannot read" error either.
    if (spec.trim_start().starts_with(PRIVATE_PREFIX) || parse_private_key(spec, "").is_ok()) && !std::path::Path::new(spec).exists() {
        return usage_err("--key takes a key file or an op:// reference, not the key itself");
    }
    let mut bytes = Zeroizing::new(std::fs::read(spec).map_err(|e| CliError::Other(key_read_error(&e, spec)))?);
    let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
    bytes.zeroize();
    private_key_from_text(&text, spec).map_err(CliError::Usage)
}

/// Whether a `--key` argument looks like private key material rather than a path: it holds the private prefix (any
/// case, or its tail), or 32 or more hex digits in runs of 8 or more (a key with a digit missing or added, a stray quote
/// or space). A file named `cipherlog-….json` is still a path.
pub fn looks_like_key_material(spec: &str) -> bool {
    let lower = spec.to_ascii_lowercase();
    if lower.contains("cipherlog-priv") || lower.contains("priv-v1") {
        return true;
    }
    let mut digits = 0;
    let mut run = 0;
    for c in spec.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_hexdigit() {
            run += 1;
        } else {
            if run >= 8 {
                digits += run;
            }
            run = 0;
        }
    }
    digits >= 32
}

/// The error for a `--key` file that cannot be read. A mistyped key given in place of a file is not echoed (SPEC.md
/// 1.1: an error never shows a private key, nor most of one).
fn key_read_error(e: &io::Error, spec: &str) -> String {
    if looks_like_key_material(spec) {
        format!(
            "{}: cannot read the --key file (the argument is not shown: it looks like a key; --key takes a key file or an op:// reference)",
            io_code(e)
        )
    } else {
        node_message(e, "open", spec)
    }
}

// ---------- open ----------

/// One input of a report: its name (the base name of the path) and bytes.
pub struct Input {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Writes the report in pieces to `write`: the banner, one status line per file, the notes, an empty line, then the
/// merged lines. Every string that comes from outside (file names, paths) goes through `safe_text`; decrypted lines
/// are cleaned. One read budget covers all inputs (SPEC.md 5.4). Returns whether any file was opened.
pub fn write_report(
    inputs: &[Input],
    keys: &KeyRing,
    read_errors: &[String],
    write: &mut dyn FnMut(&str) -> io::Result<()>,
    budget: &mut ReadBudget,
) -> io::Result<bool> {
    let mut files = Vec::new();
    let mut notes: Vec<String> = read_errors.to_vec();
    for i in inputs {
        let r = read_bytes(&i.bytes, keys, &i.name, budget);
        files.extend(r.files);
        notes.extend(r.notes);
    }
    mark_duplicates(&mut files);
    let mut head = vec![SOURCE_NOT_VERIFIED.to_string()];
    head.extend(files.iter().map(describe_file));
    head.extend(notes.iter().map(|n| safe_text(n)));
    write(&(head.join("\n") + "\n\n"))?;
    let mut pending = String::new();
    for block in merged_blocks(&files) {
        // Small blocks are batched into one write; a big one (a file without timestamped lines is a single block of up
        // to 64 MiB) is written as it is, never copied into `pending`.
        if block.len() >= 1 << 20 {
            if !pending.is_empty() {
                write(&pending)?;
                pending.clear();
            }
            write(&block)?;
            continue;
        }
        pending.push_str(&block);
        if pending.len() >= 1 << 20 {
            write(&pending)?;
            pending.clear();
        }
    }
    if !pending.is_empty() {
        write(&pending)?;
    }
    Ok(files.iter().any(|f| f.opened))
}

/// The whole report as one string (tests and small inputs; `open` streams it instead).
pub fn open_report(inputs: &[Input], keys: &KeyRing, read_errors: &[String], budget: Option<ReadBudget>) -> (String, bool) {
    let mut text = String::new();
    let mut budget = budget.unwrap_or_default();
    let any = write_report(
        inputs,
        keys,
        read_errors,
        &mut |c| {
            text.push_str(c);
            Ok(())
        },
        &mut budget,
    )
    .expect("writing to a string does not fail");
    (text, any)
}

/// Node's `path.basename` for a POSIX path.
fn basename(p: &str) -> &str {
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "";
    }
    t.rsplit('/').next().unwrap_or(t)
}

fn open(args: &[String], out: &mut dyn Write) -> Result<i32, CliError> {
    let p = parse_args(args, &["key", "out"], true)?;
    if p.positionals.is_empty() {
        return usage_err("open needs at least one file");
    }
    let key_specs = p.values.get("key").cloned().unwrap_or_default();
    if key_specs.is_empty() {
        return usage_err("open needs --key");
    }
    let mut keys: KeyRing = HashMap::new();
    for k in &key_specs {
        let private = load_key(k)?;
        let public = public_key_from_private(&private).map_err(|e| CliError::Other(e.0))?;
        keys.insert(hex(&key_id_of(&public)), private);
    }
    let mut inputs = Vec::new();
    let mut read_errors = Vec::new();
    for path in &p.positionals {
        match std::fs::read(path) {
            Ok(bytes) => inputs.push(Input { name: basename(path).to_string(), bytes }),
            Err(e) => read_errors.push(format!("{path}: cannot read ({})", io_code(&e))),
        }
    }
    let mut budget = ReadBudget::default();
    // A reader that quits the pager or closes the pipe early only ends the output; the exit code still says whether
    // anything could be read.
    let to_stream = |w: &mut dyn Write, budget: &mut ReadBudget| {
        let mut ok = true;
        let mut sink = |c: &str| {
            if ok && w.write_all(c.as_bytes()).is_err() {
                ok = false;
            }
            Ok(())
        };
        let any = write_report(&inputs, &keys, &read_errors, &mut sink, budget).unwrap_or(false);
        let _ = w.flush();
        any
    };
    let any_read = if let Some(file) = p.get("out") {
        let mut f = open_new_private(file)?;
        write_report(&inputs, &keys, &read_errors, &mut |c| f.write_all(c.as_bytes()), &mut budget)
            .map_err(|e| CliError::Other(node_message(&e, "write", file)))?
    } else if io::stdout().is_terminal() {
        match Command::new("less").arg("-R").stdin(Stdio::piped()).spawn() {
            Ok(mut less) => {
                let mut stdin = less.stdin.take().expect("piped");
                let any = to_stream(&mut stdin, &mut budget);
                drop(stdin);
                let _ = less.wait();
                any
            }
            Err(_) => to_stream(out, &mut budget),
        }
    } else {
        to_stream(out, &mut budget)
    };
    drop(keys);
    Ok(if any_read { 0 } else { 1 })
}

// ---------- write ----------

/// `[<level> <category>: ]<message>`: the level and category when the line starts with them.
fn split_input_line(raw: &str) -> Option<(Level, &str, &str)> {
    let mut chars = raw.chars();
    let level = Level::from_letter(chars.next()?)?;
    let rest = chars.as_str().strip_prefix(' ')?;
    let n = rest.bytes().take_while(|c| c.is_ascii_alphanumeric() || b"._-".contains(c)).count();
    if !(1..=32).contains(&n) {
        return None;
    }
    let message = rest[n..].strip_prefix(": ")?;
    Some((level, &rest[..n], message))
}

/// Builds a closed file from input lines `[<level> <category>: ]<message>`; `clock` gives the time of each line.
pub fn write_file_bytes(
    public_key: &[u8; 32],
    input: &str,
    process_name: &str,
    process: u8,
    platform: u8,
    clock: &mut dyn FnMut() -> i64,
) -> Result<Vec<u8>, WriteFail> {
    let created_at = clock();
    let (mut w, mut bytes) = FileWriter::new(public_key, platform, process, created_at as u64, None)?;
    for l in device_block_lines(&w.file_id_hex8(), platform, process, &[], None) {
        w.write(&format_line(created_at, Level::I, process_name, Some("device"), &l));
    }
    bytes.extend(w.flush()?);
    let mut lines: Vec<&str> = input.split('\n').collect();
    let last = lines.len() - 1;
    for l in &mut lines[..last] {
        *l = l.strip_suffix('\r').unwrap_or(l);
    }
    if lines.last() == Some(&"") {
        lines.pop();
    }
    for raw in lines {
        let (level, category, message) = match split_input_line(raw) {
            Some((l, c, m)) => (l, c, m),
            None => (Level::I, "-", raw),
        };
        w.write(&format_line(clock(), level, process_name, Some(category), message));
        if level >= Level::W {
            bytes.extend(w.flush()?);
        }
    }
    bytes.extend(w.finish()?);
    Ok(bytes)
}

fn write_cmd(args: &[String]) -> Result<i32, CliError> {
    let p = parse_args(args, &["pub", "out", "process-name", "process", "platform"], false)?;
    let (Some(public), Some(file)) = (p.get("pub").filter(|s| !s.is_empty()), p.get("out").filter(|s| !s.is_empty())) else {
        return usage_err("write needs --pub and --out");
    };
    let public_key = parse_public_key(public, "--pub").map_err(CliError::Usage)?;
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw).map_err(|e| CliError::Other(format!("cannot read stdin ({})", io_code(&e))))?;
    let input = String::from_utf8_lossy(&raw);
    let process = parse_u8(p.get("process"), "--process", 1)?;
    let platform = parse_u8(p.get("platform"), "--platform", 0)?;
    let bytes = write_file_bytes(&public_key, &input, p.get("process-name").unwrap_or("cli"), process, platform, &mut now_ms)
        .map_err(|e| CliError::Other(format!("{e:?}")))?;
    write_new_private(file, &bytes)?;
    Ok(0)
}

// ---------- main ----------

pub fn main(argv: &[String]) -> i32 {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr();
    let (cmd, rest) = match argv.split_first() {
        Some((c, r)) => (Some(c.as_str()), r),
        None => (None, &[][..]),
    };
    let r: Result<i32, CliError> = match cmd {
        Some("keygen") => keygen(rest, &mut stdout, &mut stderr),
        Some("keyid") => {
            if rest.len() != 1 {
                usage_err("keyid needs one public key")
            } else {
                parse_public_key(&rest[0], "public key").map_err(CliError::Usage).map(|k| {
                    let _ = writeln!(stdout, "{}", hex(&key_id_of(&k)));
                    0
                })
            }
        }
        Some("open") => open(rest, &mut stdout),
        Some("write") => write_cmd(rest),
        Some("--version") => {
            let _ = writeln!(stdout, "{VERSION}");
            Ok(0)
        }
        None | Some("-h" | "--help" | "help") => {
            let _ = write!(stdout, "{}", usage());
            Ok(if cmd.is_none() { 2 } else { 0 })
        }
        Some(c) => usage_err(format!("unknown command {c}")),
    };
    let _ = stdout.flush();
    match r {
        Ok(code) => code,
        Err(CliError::Usage(m)) => {
            let _ = write!(stderr, "cipherlog: {m}\n\n{}", usage());
            2
        }
        Err(CliError::Other(m)) => {
            let _ = writeln!(stderr, "cipherlog: {m}");
            1
        }
    }
}
