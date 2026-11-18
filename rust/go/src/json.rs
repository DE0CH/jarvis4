//! JSON as Go's encoding/json reads and writes it. Reading: unknown fields are ignored and a null is the zero value
//! (Go's `json.Unmarshal`); here every null object member is dropped before decoding into types whose fields default,
//! which gives the same values. Writing: `jarvis_sig::go_json` (Go's escaping of < > & U+2028 U+2029).

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn strip_nulls(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.retain(|_, x| !x.is_null());
            m.values_mut().for_each(strip_nulls);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_nulls),
        _ => {}
    }
}

/// `b` decoded as Go's `json.Unmarshal` would (trailing data refused, as Go does). The stripped value is decoded from
/// its text, not from the Value itself, so a `RawValue` field (Go's json.RawMessage) decodes too.
pub fn unmarshal<T: DeserializeOwned>(b: &[u8]) -> Result<T, serde_json::Error> {
    let mut v: Value = serde_json::from_slice(b)?;
    strip_nulls(&mut v);
    serde_json::from_str(&serde_json::to_string(&v)?)
}

/// `v` encoded as Go's `json.Marshal` would
pub fn marshal<T: Serialize + ?Sized>(v: &T) -> String {
    jarvis_sig::go_json(v).unwrap_or_else(|_| "null".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize, Default, Debug, PartialEq)]
    #[serde(default)]
    struct T {
        a: String,
        b: Vec<String>,
        c: Option<Box<T>>,
    }

    #[test]
    fn nulls_are_zero_values_and_unknown_fields_ignored() {
        let t: T = unmarshal(br#"{"a":null,"b":null,"c":{"a":"x","b":null},"zz":1}"#)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(t.a, "");
        assert!(t.b.is_empty());
        assert_eq!(t.c.map(|c| c.a), Some("x".into()));
        assert!(unmarshal::<T>(br#"{"a":"x"} {}"#).is_err(), "trailing data");
    }

    #[test]
    fn raw_values_decode() {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct R {
            raw: Option<Box<serde_json::value::RawValue>>,
        }
        let r: R =
            unmarshal(br#"{"raw": {"b": 1, "a": [null]}}"#).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            r.raw.map(|x| x.get().to_string()),
            Some(r#"{"a":[null],"b":1}"#.into())
        );
    }
}
