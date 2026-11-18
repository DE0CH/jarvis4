//! Go's time.Time as encoding/json writes it: RFC 3339 with nanoseconds, trailing zeros of the fraction dropped
//! (time.RFC3339Nano), the zone as Z or ±hh:mm; the zero time is 0001-01-01T00:00:00Z.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

/// a Go time.Time: None is the zero time
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoTime(pub Option<OffsetDateTime>);

impl GoTime {
    pub fn now() -> Self {
        GoTime(Some(OffsetDateTime::now_utc()))
    }

    pub fn from_unix(secs: i64) -> Self {
        GoTime(OffsetDateTime::from_unix_timestamp(secs).ok())
    }

    pub fn from_unix_nanos(n: i128) -> Self {
        GoTime(OffsetDateTime::from_unix_timestamp_nanos(n).ok())
    }

    /// Go's t.IsZero()
    pub fn is_zero(&self) -> bool {
        self.0.is_none()
    }

    /// Go's t.Unix() (the zero time's is -62135596800)
    pub fn unix(&self) -> i64 {
        self.0.map_or(-62135596800, |t| t.unix_timestamp())
    }

    pub fn unix_nanos(&self) -> i128 {
        self.0
            .map_or(-62135596800 * 1_000_000_000, |t| t.unix_timestamp_nanos())
    }

    /// Go's t.Add(d)
    pub fn add(&self, d: Duration) -> Self {
        match self.0 {
            Some(t) => GoTime(t.checked_add(d)),
            None => GoTime::from_unix_nanos(self.unix_nanos() + d.whole_nanoseconds()),
        }
    }

    pub fn add_std(&self, d: std::time::Duration) -> Self {
        self.add(Duration::try_from(d).unwrap_or(Duration::MAX))
    }

    /// Go's t.Sub(u)
    pub fn sub(&self, u: &GoTime) -> Duration {
        Duration::nanoseconds_i128(self.unix_nanos() - u.unix_nanos())
    }

    /// Go's time.Since(t)
    pub fn since(&self) -> Duration {
        GoTime::now().sub(self)
    }

    pub fn before(&self, u: &GoTime) -> bool {
        self.unix_nanos() < u.unix_nanos()
    }

    pub fn after(&self, u: &GoTime) -> bool {
        self.unix_nanos() > u.unix_nanos()
    }

    /// Go's t.UTC()
    pub fn utc(&self) -> Self {
        GoTime(self.0.map(|t| t.to_offset(UtcOffset::UTC)))
    }

    /// Go's t.Format(time.RFC3339Nano)
    pub fn rfc3339_nano(&self) -> String {
        let t = self
            .0
            .unwrap_or(time::macros::datetime!(0001-01-01 0:00 UTC));
        let mut s = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        );
        let ns = t.nanosecond();
        if ns != 0 {
            let f = format!("{ns:09}");
            s.push('.');
            s.push_str(f.trim_end_matches('0'));
        }
        s.push_str(&zone(t.offset()));
        s
    }

    /// Go's t.Format(time.RFC3339): whole seconds
    pub fn rfc3339(&self) -> String {
        let t = self
            .0
            .unwrap_or(time::macros::datetime!(0001-01-01 0:00 UTC));
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
            zone(t.offset())
        )
    }

    /// Go's time.Parse(time.RFC3339, s) (any fraction)
    pub fn parse(s: &str) -> Option<GoTime> {
        let t = OffsetDateTime::parse(s, &Rfc3339).ok()?;
        if t.unix_timestamp() == -62135596800 && t.nanosecond() == 0 {
            return Some(GoTime(None));
        }
        Some(GoTime(Some(t)))
    }
}

fn zone(o: UtcOffset) -> String {
    if o.is_utc() {
        return "Z".into();
    }
    let (h, m, _) = o.as_hms();
    format!(
        "{}{:02}:{:02}",
        if o.is_negative() { '-' } else { '+' },
        h.unsigned_abs(),
        m.unsigned_abs()
    )
}

impl Serialize for GoTime {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.rfc3339_nano())
    }
}

impl<'de> Deserialize<'de> for GoTime {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        GoTime::parse(&s).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "parsing time {s:?} as \"2006-01-02T15:04:05Z07:00\""
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_as_go() {
        let t = GoTime::from_unix_nanos(1_791_700_000_120_000_000);
        assert_eq!(t.rfc3339_nano(), "2026-10-11T06:26:40.12Z");
        assert_eq!(t.rfc3339(), "2026-10-11T06:26:40Z");
        assert_eq!(GoTime::default().rfc3339_nano(), "0001-01-01T00:00:00Z");
        assert_eq!(
            GoTime::parse("2026-10-11T14:26:40.5+08:00").map(|t| t.rfc3339_nano()),
            Some("2026-10-11T14:26:40.5+08:00".into())
        );
        assert!(GoTime::parse("0001-01-01T00:00:00Z").is_some_and(|t| t.is_zero()));
        let j = serde_json::to_string(&t).unwrap_or_default();
        assert_eq!(j, "\"2026-10-11T06:26:40.12Z\"");
        let back: GoTime = serde_json::from_str(&j).unwrap_or_default();
        assert_eq!(back, t);
    }
}
