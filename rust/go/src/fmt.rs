//! Go fmt/strconv/strings/time helpers: what the Go code printed, the Rust code prints the same.

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

/// Go's time.Duration.String(): 1h2m3s, 1.5s, 300ms, 0s
pub fn duration_string(d: std::time::Duration) -> String {
    let ns = d.as_nanos();
    if ns == 0 {
        return "0s".into();
    }
    if ns < 1_000 {
        return format!("{ns}ns");
    }
    if ns < 1_000_000 {
        return format!("{}µs", trim_frac(ns as f64 / 1e3));
    }
    if ns < 1_000_000_000 {
        return format!("{}ms", trim_frac(ns as f64 / 1e6));
    }
    let secs = ns / 1_000_000_000;
    let frac = ns % 1_000_000_000;
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if h > 0 || m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if frac == 0 {
        out.push_str(&format!("{s}s"));
    } else {
        let f = format!("{frac:09}");
        out.push_str(&format!("{s}.{}s", f.trim_end_matches('0')));
    }
    out
}

fn trim_frac(x: f64) -> String {
    let s = format!("{x:.9}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as D;

    #[test]
    fn durations_as_go_prints_them() {
        for (d, s) in [
            (D::ZERO, "0s"),
            (D::from_millis(300), "300ms"),
            (D::from_millis(1500), "1.5s"),
            (D::from_secs(3600), "1h0m0s"),
            (D::from_secs(3723), "1h2m3s"),
            (D::from_secs(90), "1m30s"),
            (D::from_micros(1500), "1.5ms"),
        ] {
            assert_eq!(duration_string(d), s);
        }
    }
}
