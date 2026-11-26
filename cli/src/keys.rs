//! Key strings (SPEC.md 1.1) and the key forms the CLI reads: `cipherlog-pub-v1:` / `cipherlog-priv-v1:` strings, the
//! older 64-hex form, and key files (JSON from `cipherlog keygen --out`, or one key string or hex line).
//!
//! Errors name the problem and never contain the private key or any part of it.

use crate::format::{hex, unhex};
use zeroize::{Zeroize, Zeroizing};

pub const PUBLIC_PREFIX: &str = "cipherlog-pub-v1:";
pub const PRIVATE_PREFIX: &str = "cipherlog-priv-v1:";

pub fn public_key_string(public_key: &[u8; 32]) -> String {
    format!("{PUBLIC_PREFIX}{}", hex(public_key))
}

/// The private key string; the caller keeps it in a wiped buffer.
pub fn private_key_string(private_key: &[u8; 32]) -> Zeroizing<String> {
    let mut h = hex(private_key);
    // Sized up front: a growing String would free partial copies of the key without wiping them.
    let mut s = Zeroizing::new(String::with_capacity(PRIVATE_PREFIX.len() + h.len()));
    s.push_str(PRIVATE_PREFIX);
    s.push_str(&h);
    h.zeroize();
    s
}

/// What a key string was expected to be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Public,
    Private,
}

impl Kind {
    fn prefix(self) -> &'static str {
        match self {
            Kind::Public => PUBLIC_PREFIX,
            Kind::Private => PRIVATE_PREFIX,
        }
    }
}

/// Space, tab, CR and LF: the only characters trimmed around a key string (SPEC.md 1.1).
fn trim_key(text: &str) -> &str {
    text.trim_matches([' ', '\t', '\r', '\n'])
}

/// A printable form of one character for an error about a public key (control and invisible ones as `U+XXXX`).
fn shown(c: char) -> String {
    if ('\u{21}'..'\u{7f}').contains(&c) { format!("\"{c}\"") } else { format!("U+{:04X}", c as u32) }
}

/// Parses `<prefix><64 hex>` (SPEC.md 1.1) after trimming space, tab, CR and LF. `Err` is the message shared by every
/// implementation (vectors/keys.json) without the `cipherlog key: ` prefix; it never contains a private key.
fn parse_key_string(text: &str, kind: Kind) -> Result<Zeroizing<[u8; 32]>, String> {
    let t = trim_key(text);
    if t.is_empty() {
        return Err("the key string is empty".into());
    }
    let prefix = kind.prefix();
    let Some(body) = t.strip_prefix(prefix) else {
        return Err(match kind {
            Kind::Public if t.starts_with(PRIVATE_PREFIX) => {
                "this is a PRIVATE key (cipherlog-priv-v1:…); an app ships only the public key (cipherlog-pub-v1:…)".into()
            }
            Kind::Private if t.starts_with(PUBLIC_PREFIX) => {
                "this is a public key (cipherlog-pub-v1:…); opening logs needs the private key (cipherlog-priv-v1:…)".into()
            }
            _ => format!("the key string must start with {prefix}"),
        });
    };
    // Characters first, then the length; only a public key's character is shown.
    if let Some((i, c)) = body.chars().enumerate().find(|(_, c)| !c.is_ascii_hexdigit()) {
        let what = if kind == Kind::Public { format!(" ({})", shown(c)) } else { String::new() };
        return Err(format!("character {} after the prefix is not a hex digit{what}", i + 1));
    }
    if body.len() != 64 {
        return Err(format!("expected 64 hex characters after the prefix, got {}", body.len()));
    }
    let mut v = unhex(body).expect("checked hex");
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&v);
    v.zeroize();
    Ok(out)
}

/// A public key string exactly as SPEC.md 1.1 (and vectors/keys.json) defines it; errors start with `cipherlog key: `.
pub fn parse_public_key_string(text: &str) -> Result<[u8; 32], String> {
    parse_key_string(text, Kind::Public).map(|k| *k).map_err(|e| format!("cipherlog key: {e}"))
}

/// A private key string exactly as SPEC.md 1.1 defines it; errors start with `cipherlog key: ` and never echo the key.
pub fn parse_private_key_string(text: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    parse_key_string(text, Kind::Private).map_err(|e| format!("cipherlog key: {e}"))
}

/// The form of key files (`vectors/test-key.json`): exactly 64 hex characters (after trimming whitespace).
fn parse_raw_hex(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    let t = trim_key(text);
    if t.len() != 64 || !t.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut v = unhex(t)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&v);
    v.zeroize();
    Some(out)
}

/// A public key as `cipherlog-pub-v1:<hex>` or as 64 hex characters. `what` names it in the error.
pub fn parse_public_key(text: &str, what: &str) -> Result<[u8; 32], String> {
    if trim_key(text).starts_with("cipherlog-") {
        return parse_key_string(text, Kind::Public).map(|k| *k).map_err(|e| format!("{what}: {e}"));
    }
    parse_raw_hex(text).map(|k| *k).ok_or_else(|| format!("{what} must be {PUBLIC_PREFIX}<64 hex characters> or 64 hex characters"))
}

/// A private key as `cipherlog-priv-v1:<hex>` or as 64 hex characters. The error never contains the key.
pub fn parse_private_key(text: &str, what: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    if trim_key(text).starts_with("cipherlog-") {
        return parse_key_string(text, Kind::Private).map_err(|e| format!("{what}: {e}"));
    }
    parse_raw_hex(text).ok_or_else(|| format!("{what} must be {PRIVATE_PREFIX}<64 hex characters> or 64 hex characters"))
}

/// Wipes every string inside a JSON value (a key file may hold the private key in more than one field).
fn wipe_json(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(a) => a.iter_mut().for_each(wipe_json),
        serde_json::Value::Object(o) => o.values_mut().for_each(wipe_json),
        _ => {}
    }
}

/// A private key from the text of a key file or of `op read`: JSON with `privateKey` (hex or key string; or
/// `privateKeyString`), a key string, or 64 hex characters. `source` names the origin in errors.
pub fn private_key_from_text(text: &str, source: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    // Space, tab, CR and LF only (SPEC.md 1.1): `str::trim` would also drop a no-break space or U+3000, which every
    // other parser rejects.
    let t = trim_key(text);
    if t.starts_with('{') {
        let mut j: serde_json::Value = serde_json::from_str(t).map_err(|_| format!("{source}: not valid JSON"))?;
        let field = ["privateKey", "privateKeyString"].into_iter().find_map(|f| j.get(f).and_then(|v| v.as_str()));
        let r = match field {
            Some(s) => parse_private_key(s, &format!("{source}: privateKey")),
            None => Err(format!("{source}: no \"privateKey\"")),
        };
        wipe_json(&mut j);
        return r;
    }
    parse_private_key(t, &format!("{source}: private key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB: &str = "ecd8b29e913351f6a28fda6e663ad350273ed38a9b44fe8f1b8116a236154170";
    const PRIV: &str = "5856624c8e530d58d179b4aff156af9b220175f5d16ae8dcf201c1bd7fe3d251";

    #[test]
    fn strings_round_trip_and_accept_uppercase_and_whitespace() {
        let p: [u8; 32] = unhex(PUB).unwrap().try_into().unwrap();
        let s = public_key_string(&p);
        assert_eq!(s, format!("cipherlog-pub-v1:{PUB}"));
        assert_eq!(parse_public_key(&s, "k").unwrap(), p);
        assert_eq!(parse_public_key(&format!("  {}\n", s.to_uppercase().replace("CIPHERLOG-PUB-V1:", PUBLIC_PREFIX)), "k").unwrap(), p);
        assert_eq!(parse_public_key(PUB, "k").unwrap(), p, "older 64-hex form");
        let k: [u8; 32] = unhex(PRIV).unwrap().try_into().unwrap();
        let ps = private_key_string(&k);
        assert_eq!(*parse_private_key(&ps, "k").unwrap(), k);
        assert_eq!(*parse_private_key(&format!("\t{}\r\n", ps.as_str()), "k").unwrap(), k);
    }

    #[test]
    fn errors_name_the_problem_and_never_echo_a_private_key() {
        let cases = [
            (format!("cipherlog-priv-v2:{PRIV}"), "must start with cipherlog-priv-v1:"),
            (format!("cipherlog-priv-v1:{}", &PRIV[..63]), "got 63"),
            (format!("cipherlog-priv-v1:{}0", PRIV), "got 65"),
            (format!("cipherlog-priv-v1:{}g", &PRIV[..63]), "character 64 after the prefix is not a hex digit"),
            (format!("cipherlog-priv-v1:{} trailing", PRIV), "character 65 after the prefix is not a hex digit"),
            (format!("cipherlog-pub-v1:{PRIV}"), "this is a public key"),
            (format!("key: cipherlog-priv-v1:{PRIV}"), "must be cipherlog-priv-v1:"),
            (PRIV[..60].to_string(), "must be cipherlog-priv-v1:"),
        ];
        for (input, want) in cases {
            let e = parse_private_key(&input, "--key").err().unwrap_or_else(|| panic!("accepted {want}"));
            assert!(e.contains(want), "{e:?} should contain {want:?}");
            for i in 0..PRIV.len() - 8 {
                assert!(!e.contains(&PRIV[i..i + 8]), "error echoes key material: {e}");
            }
        }
        let e = parse_public_key(&format!("cipherlog-priv-v1:{PRIV}"), "--pub").unwrap_err();
        assert!(e.contains("this is a PRIVATE key"), "{e}");
        assert!(!e.contains(&PRIV[..16]));
    }

    #[test]
    fn key_files() {
        let k: [u8; 32] = unhex(PRIV).unwrap().try_into().unwrap();
        let ps = private_key_string(&k);
        for text in [
            format!("{{\"privateKey\": \"{PRIV}\"}}"),
            format!("{{\"privateKey\": \"{}\"}}", ps.as_str()),
            format!("{{\"privateKeyString\": \"{}\"}}", ps.as_str()),
            format!("{PRIV}\n"),
            format!("{}\n", ps.as_str()),
        ] {
            assert_eq!(*private_key_from_text(&text, "f").unwrap(), k, "{text}");
        }
        // SPEC.md 1.1: only space, tab, CR and LF are trimmed, in a key file as in a key string.
        for (pad, name) in [("\u{a0}", "no-break space"), ("\u{3000}", "ideographic space"), ("\u{2003}", "em space")] {
            for text in [
                format!("{pad}{}", ps.as_str()),
                format!("{}{pad}\n", ps.as_str()),
                format!("{pad}{PRIV}"),
                format!("{pad}{{\"privateKey\": \"{PRIV}\"}}"),
            ] {
                assert!(private_key_from_text(&text, "f").is_err(), "{name} accepted: {text:?}");
            }
        }
        assert_eq!(*private_key_from_text(&format!(" \t\r\n{}\r\n", ps.as_str()), "f").unwrap(), k);
        assert_eq!(private_key_from_text("{nope", "f").unwrap_err(), "f: not valid JSON");
        assert_eq!(private_key_from_text("{\"publicKey\":\"x\"}", "f").unwrap_err(), "f: no \"privateKey\"");
    }
}
