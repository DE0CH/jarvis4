//! Small helpers the Go code had from its standard library.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Go's os.WriteFile: create (with `mode`) or truncate, write
pub fn write_file(p: &Path, b: &[u8], mode: u32) -> std::io::Result<()> {
    let mut f = create_file(p, mode)?;
    f.write_all(b)
}

/// Go's os.OpenFile(p, O_CREATE|O_TRUNC|O_WRONLY, mode)
pub fn create_file(p: &Path, mode: u32) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(p)
}

/// The first `n` bytes of `s` (Go's s[:min(n, len(s))]), cut back to a character boundary
pub fn clip_bytes(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut i = n;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

pub fn file_exists(p: &Path) -> bool {
    std::fs::metadata(p).is_ok()
}

/// Go's time.Now().UTC().Format(time.RFC3339)
pub fn now_rfc3339() -> String {
    let t = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// unix seconds now
pub fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// sleep on a plain thread
pub fn sleep(d: std::time::Duration) {
    std::thread::sleep(d)
}

/// A lazily compiled regex (the pattern is a literal: a bad one fails every test at once)
#[macro_export]
macro_rules! re {
    ($name:ident = $pat:expr) => {
        pub static $name: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| regex::Regex::new($pat).unwrap_or_else(|e| panic!("{e}")));
    };
}

/// Go's strings.Cut
pub fn cut<'a>(s: &'a str, sep: &str) -> (&'a str, &'a str, bool) {
    match s.split_once(sep) {
        Some((a, b)) => (a, b, true),
        None => (s, "", false),
    }
}

/// Go's fmt.Sprint of a JSON value decoded into `any` (float64 as %v: shortest, exponent from 1e21 and below 1e-4)
pub fn go_sprint(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Null => "<nil>".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => go_float_g(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => s.clone(),
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(go_sprint).collect::<Vec<_>>().join(" ")
        ),
        Value::Object(m) => format!(
            "map[{}]",
            m.iter()
                .map(|(k, v)| format!("{k}:{}", go_sprint(v)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

/// Go's strconv.FormatFloat(x, 'g', -1, 64) as %v prints a float64
pub fn go_float_g(x: f64) -> String {
    let a = x.abs();
    if a != 0.0 && !(1e-4..1e21).contains(&a) {
        let s = format!("{x:e}"); // 1e21, 1.5e-5
        let (m, e) = s.split_once('e').unwrap_or((&s, "0"));
        let e: i32 = e.parse().unwrap_or(0);
        return format!("{m}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs());
    }
    format!("{x}")
}

/// Go's strconv.FormatFloat(x, 'f', -1, 64)
pub fn go_float_f(x: f64) -> String {
    format!("{x}")
}

/// Go's url.PathEscape: one path segment, escaped (unreserved characters and $&+:=@ stay)
pub fn path_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~$&+:=@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// a URL path decoded (Go's URL.Path)
pub fn path_unescape(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Go's strconv.Quote (as %q prints a string): \" \\ and the named escapes; characters Go doesn't count as printable
/// (controls, format characters, separators other than the space) as \x / \u / \U
pub fn go_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if !go_printable(c) => {
                if (c as u32) < 0x10000 {
                    out.push_str(&format!("\\u{:04x}", c as u32))
                } else {
                    out.push_str(&format!("\\U{:08x}", c as u32))
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Go's unicode.IsPrint, for the characters that matter here: controls, format characters and the separators other
/// than the ASCII space are not printable
fn go_printable(c: char) -> bool {
    let u = c as u32;
    !(c.is_control()
        || matches!(u, 0xA0 | 0xAD | 0x1680 | 0x180E | 0x2000..=0x200F | 0x2028..=0x202F | 0x205F..=0x2064 | 0x2066..=0x206F | 0x3000 | 0xFEFF | 0xFFF9..=0xFFFB)
        || (0xE000..=0xF8FF).contains(&u)
        || (0xF0000..).contains(&u))
}

/// Go's strings.Join(strings.Fields(s), " ")
pub fn fields_join(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Go's time.ParseDuration: a sequence of decimal numbers with units (ns us µs ms s m h), optional sign
pub fn parse_go_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let orig = s;
    let mut s = s;
    let mut neg = false;
    if let Some(r) = s.strip_prefix('-') {
        neg = true;
        s = r;
    } else if let Some(r) = s.strip_prefix('+') {
        s = r;
    }
    if s == "0" {
        return Ok(std::time::Duration::ZERO);
    }
    if s.is_empty() {
        anyhow::bail!("time: invalid duration {}", go_quote(orig));
    }
    let mut total = 0f64;
    while !s.is_empty() {
        let n = s
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(s.len());
        if n == 0 {
            anyhow::bail!("time: invalid duration {}", go_quote(orig));
        }
        let v: f64 = s[..n]
            .parse()
            .map_err(|_| anyhow::anyhow!("time: invalid duration {}", go_quote(orig)))?;
        s = &s[n..];
        let u = s
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(s.len());
        let mult = match &s[..u] {
            "ns" => 1e-9,
            "us" | "µs" | "μs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "" => anyhow::bail!("time: missing unit in duration {}", go_quote(orig)),
            x => anyhow::bail!(
                "time: unknown unit {} in duration {}",
                go_quote(x),
                go_quote(orig)
            ),
        };
        total += v * mult;
        s = &s[u..];
    }
    if neg {
        anyhow::bail!("negative duration {}", go_quote(orig));
    }
    Ok(std::time::Duration::from_secs_f64(total))
}

/// RFC 3339 parsed (Go's time.Parse(time.RFC3339, …)) → unix seconds
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

/// unix seconds → RFC 3339 in UTC, whole seconds (Go's t.UTC().Format(time.RFC3339))
pub fn format_rfc3339(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// Go's json.MarshalIndent(v, "", " ")
pub fn marshal_indent1<T: serde::Serialize>(v: &T) -> String {
    let mut buf = Vec::new();
    let f = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, f);
    let _ = v.serialize(&mut ser);
    let s = String::from_utf8(buf).unwrap_or_default();
    s.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// Go's clip: the first n bytes and "…" when longer (cut back to a character boundary)
pub fn clip(s: &str, n: usize) -> String {
    if s.len() > n {
        return format!("{}…", clip_bytes(s, n));
    }
    s.to_string()
}

/// a command's stdout, the command killed once `limit` passes (Go's exec.CommandContext(ctx…).Output() with a
/// deadline); what it printed until then
pub fn output_timeout(
    mut cmd: std::process::Command,
    limit: std::time::Duration,
) -> (Vec<u8>, Option<std::process::ExitStatus>) {
    use std::io::Read;
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let Ok(mut child) = cmd.spawn() else {
        return (vec![], None);
    };
    let mut so = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut b = vec![];
        if let Some(s) = so.as_mut() {
            let _ = s.read_to_end(&mut b);
        }
        b
    });
    let start = std::time::Instant::now();
    let st = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if start.elapsed() >= limit => {
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => sleep(std::time::Duration::from_millis(20)),
            Err(_) => break None,
        }
    };
    (reader.join().unwrap_or_default(), st)
}
