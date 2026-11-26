//! Armored bundles (`*.cipherlogs.txt`, SPEC.md 4.1): base64 between BEGIN and END lines, for mail.

pub const BEGIN: &str = "-----BEGIN CIPHERLOG BUNDLE-----";
pub const END: &str = "-----END CIPHERLOG BUNDLE-----";
const LINE: usize = 76;
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// RFC 4648 base64, standard alphabet, with padding.
pub fn base64(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// The armored text of bundle bytes: BEGIN line, base64 in lines of 76 characters, END line, each ending with `\n`.
pub fn armor(bundle: &[u8]) -> String {
    let b = base64(bundle);
    let mut out = String::with_capacity(b.len() + b.len() / LINE + BEGIN.len() + END.len() + 4);
    out.push_str(BEGIN);
    out.push('\n');
    for chunk in b.as_bytes().chunks(LINE) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

fn is_base64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'='
}

fn value(c: u8) -> u32 {
    (match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    }) as u32
}

/// Space, tab and `\r`: the only characters ignored around an armor line (SPEC.md 4.1).
fn trim(line: &[u8]) -> &[u8] {
    let blank = |c: &u8| matches!(c, b' ' | b'\t' | b'\r');
    let start = line.iter().position(|c| !blank(c)).unwrap_or(line.len());
    let end = line.iter().rposition(|c| !blank(c)).map_or(start, |i| i + 1);
    &line[start..end]
}

fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split(|&b| b == b'\n').map(trim)
}

/// Whether `bytes` hold a BEGIN line: a line that is exactly the marker once space, tab and `\r` around it are removed.
pub fn looks_armored(bytes: &[u8]) -> bool {
    lines(bytes).any(|l| l == BEGIN.as_bytes())
}

/// Finds an armored bundle in `bytes` (SPEC.md 4.1). `None` when there is no BEGIN line (not armored); otherwise the
/// bundle bytes, or the error every implementation shares (vectors/armor.json): `armor: line N after BEGIN is not
/// base64` (N counts from 1 at the line after BEGIN, blank lines included), `armor: no -----END CIPHERLOG BUNDLE-----
/// line` or `armor: base64 is cut or badly padded`. Lines end at `\n`; space, tab and `\r` around a line are ignored;
/// the BEGIN line is the first line that is exactly the marker; blank lines between the markers are skipped.
pub fn dearmor(bytes: &[u8]) -> Option<Result<Vec<u8>, String>> {
    let mut lines = lines(bytes);
    lines.by_ref().find(|l| *l == BEGIN.as_bytes())?;
    let mut b64: Vec<u8> = Vec::new();
    for (i, l) in lines.enumerate() {
        if l == END.as_bytes() {
            return Some(decode(&b64).ok_or_else(|| "armor: base64 is cut or badly padded".to_string()));
        }
        if !l.iter().all(|&c| is_base64(c)) {
            return Some(Err(format!("armor: line {} after BEGIN is not base64", i + 1)));
        }
        b64.extend_from_slice(l);
    }
    Some(Err(format!("armor: no {END} line")))
}

/// Strict padded base64 of characters already checked to be base64 or `=`; non-canonical padding bits are accepted.
fn decode(chars: &[u8]) -> Option<Vec<u8>> {
    let pad = chars.iter().rev().take_while(|&&c| c == b'=').count();
    let body = &chars[..chars.len() - pad];
    if !chars.len().is_multiple_of(4) || pad > 2 || body.contains(&b'=') {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for q in body.chunks(4) {
        let n = q.iter().enumerate().fold(0u32, |a, (i, &c)| a | value(c) << (18 - 6 * i));
        out.push((n >> 16) as u8);
        if q.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if q.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        for (i, o) in
            [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")]
        {
            assert_eq!(base64(i.as_bytes()), o);
            let a = armor(i.as_bytes());
            assert_eq!(dearmor(a.as_bytes()).unwrap().unwrap(), i.as_bytes());
        }
    }

    #[test]
    fn lines_of_76() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let a = armor(&data);
        let lines: Vec<&str> = a.split_terminator('\n').collect();
        assert_eq!(lines[0], BEGIN);
        assert_eq!(*lines.last().unwrap(), END);
        let inner = &lines[1..lines.len() - 1];
        assert!(inner[..inner.len() - 1].iter().all(|l| l.len() == 76));
        assert!(inner.last().unwrap().len() <= 76);
        assert!(a.ends_with("-----\n"));
        assert_eq!(dearmor(a.as_bytes()).unwrap().unwrap(), data);
    }
}
