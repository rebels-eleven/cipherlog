//! Text line format, SPEC.md 2.4, and UTC time stamps.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    D,
    I,
    N,
    W,
    E,
    F,
}

impl Level {
    pub const ALL: [Level; 6] = [Level::D, Level::I, Level::N, Level::W, Level::E, Level::F];

    pub fn letter(self) -> char {
        match self {
            Level::D => 'D',
            Level::I => 'I',
            Level::N => 'N',
            Level::W => 'W',
            Level::E => 'E',
            Level::F => 'F',
        }
    }

    pub fn from_letter(c: char) -> Option<Level> {
        Level::ALL.into_iter().find(|l| l.letter() == c)
    }
}

/// Newlines become the two characters `\n`; other C0 controls (not tab), DEL and C1 controls become U+FFFD. (A Rust
/// string has no unpaired surrogates, so the third rule of SPEC.md 2.4 holds by construction.)
pub fn sanitize_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\r' => {
                if it.peek() == Some(&'\n') {
                    it.next();
                }
                out.push_str("\\n");
            }
            '\n' => out.push_str("\\n"),
            '\t' => out.push('\t'),
            '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

/// Process name and category: the first 32 code points, each outside `[A-Za-z0-9._-]` becomes `_`; empty or missing
/// becomes `-`.
pub fn sanitize_name(s: Option<&str>) -> String {
    match s {
        None | Some("") => "-".to_string(),
        Some(s) => s.chars().take(32).map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }).collect(),
    }
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// ISO 8601 UTC with milliseconds, as JavaScript's `Date.prototype.toISOString` (years past 9999 as `+YYYYYY`).
pub fn iso_time(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, mo, d) = civil_from_days(days);
    let year = if (0..=9999).contains(&y) {
        format!("{y:04}")
    } else if y > 9999 {
        format!("+{y:06}")
    } else {
        format!("-{:06}", -y)
    };
    format!("{year}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000)
}

/// Parses `YYYY-MM-DDTHH:MM:SS.sssZ` with the rules of V8's `Date.parse` (month 1–12, day 1–31 rolling over into the
/// next month, hour 24 only as 24:00:00.000); `None` where `Date.parse` gives NaN.
pub fn parse_iso_time(s: &[u8]) -> Option<i64> {
    if s.len() != 24 {
        return None;
    }
    let shape = b"dddd-dd-ddTdd:dd:dd.dddZ";
    for (c, p) in s.iter().zip(shape) {
        if (*p == b'd' && !c.is_ascii_digit()) || (*p != b'd' && c != p) {
            return None;
        }
    }
    let n = |a: usize, b: usize| s[a..b].iter().fold(0i64, |v, c| v * 10 + (c - b'0') as i64);
    let (y, mo, d, h, mi, se, ms) = (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19), n(20, 23));
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || mi > 59 || se > 59 || h > 24 {
        return None;
    }
    if h == 24 && (mi != 0 || se != 0 || ms != 0) {
        return None;
    }
    let days = days_from_civil(y, mo as u32, 1) + d - 1;
    Some(days * 86_400_000 + h * 3_600_000 + mi * 60_000 + se * 1000 + ms)
}

pub fn format_line(time_ms: i64, level: Level, process_name: &str, category: Option<&str>, message: &str) -> String {
    format!(
        "{} {} {} {}: {}\n",
        iso_time(time_ms),
        level.letter(),
        sanitize_name(Some(process_name)),
        sanitize_name(category),
        sanitize_field(message)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_sanitising() {
        assert_eq!(sanitize_field("a\r\nb\rc\nd"), "a\\nb\\nc\\nd");
        assert_eq!(sanitize_field("x\u{0}\u{7}\u{1b}\u{7f}\u{85}\u{9f}\ty"), "x\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{fffd}\u{fffd}\ty");
        assert_eq!(sanitize_field("keep \u{2028} \u{2029}"), "keep \u{2028} \u{2029}");
        assert_eq!(sanitize_name(Some("net/http 2")), "net_http_2");
        assert_eq!(sanitize_name(Some(&"a".repeat(40))), "a".repeat(32));
        assert_eq!(sanitize_name(Some("ünï")), "_n_");
        assert_eq!(sanitize_name(Some("")), "-");
        assert_eq!(sanitize_name(None), "-");
        assert_eq!(format_line(0, Level::E, "a b", None, "x\ny"), "1970-01-01T00:00:00.000Z E a_b -: x\\ny\n");
    }

    #[test]
    fn iso_times_like_javascript() {
        assert_eq!(iso_time(1_795_000_000_123), "2026-11-18T11:06:40.123Z");
        assert_eq!(iso_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(253_402_300_800_000), "+010000-01-01T00:00:00.000Z");
        assert_eq!(iso_time(8_640_000_000_000_000), "+275760-09-13T00:00:00.000Z");
        let line = format_line(parse_iso_time(b"2026-11-26T10:00:00.123Z").unwrap(), Level::I, "app", Some("spotify"), "connect");
        assert_eq!(line, "2026-11-26T10:00:00.123Z I app spotify: connect\n");
    }

    #[test]
    fn parse_like_v8() {
        let cases: [(&str, Option<i64>); 13] = [
            ("2026-02-30T00:00:00.000Z", Some(1_772_409_600_000)),
            ("2026-02-29T00:00:00.000Z", Some(1_772_323_200_000)),
            ("2024-02-30T00:00:00.000Z", Some(1_709_251_200_000)),
            ("2026-13-01T00:00:00.000Z", None),
            ("2026-00-01T00:00:00.000Z", None),
            ("2026-01-00T00:00:00.000Z", None),
            ("2026-01-32T00:00:00.000Z", None),
            ("2026-04-31T00:00:00.000Z", Some(1_777_593_600_000)),
            ("2026-01-01T24:00:00.000Z", Some(1_767_312_000_000)),
            ("2026-01-01T24:00:00.001Z", None),
            ("2026-01-01T23:60:00.000Z", None),
            ("2026-01-01T23:59:60.000Z", None),
            ("0000-01-01T00:00:00.000Z", Some(-62_167_219_200_000)),
        ];
        for (s, want) in cases {
            assert_eq!(parse_iso_time(s.as_bytes()), want, "{s}");
        }
    }
}
