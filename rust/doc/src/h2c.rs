//! The keys of objects nobody holds (sources and the sink): each is a P-256 point hashed
//! from the object's name (RFC 9380, P256_XMD:SHA-256_SSWU_RO_), so its discrete log is unknown to everyone.

use p256::NistP256;
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;

/// the domain separation tag of every object key
pub const DST: &str = "jarvis2-object-v1";

/// The uncompressed point of `msg` under `dst` (P256_XMD:SHA-256_SSWU_RO_)
pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Option<Vec<u8>> {
    let p = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[dst]).ok()?;
    Some(p.to_affine().to_encoded_point(false).as_bytes().to_vec())
}

/// An object's signing or encryption key (`use_` is "signing" or "encryption"), base64 like every key
pub fn object_key(object: &str, use_: &str) -> String {
    // the inputs are short: expand_message_xmd can't refuse them
    let pt = hash_to_curve(
        format!("jarvis2 {object} {use_}").as_bytes(),
        DST.as_bytes(),
    )
    .unwrap_or_default();
    jarvis_sig::b64(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9380 J.1.1 (P256_XMD:SHA-256_SSWU_RO_)
    #[test]
    fn rfc9380_vectors() {
        let dst = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
        for (msg, x, y) in [
            (
                "",
                "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
                "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
            ),
            (
                "abc",
                "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
                "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
            ),
            (
                "abcdef0123456789",
                "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
                "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
            ),
        ] {
            let pt = hash_to_curve(msg.as_bytes(), dst).unwrap_or_default();
            assert_eq!(hex::encode(&pt[1..]), format!("{x}{y}"), "msg {msg:?}");
        }
    }

    /// what the Go kernel's ObjectKey gave (2026-11-17)
    #[test]
    fn object_keys_match_go() {
        assert_eq!(
            object_key("sink", "signing"),
            "BHAAnVBdEyaQxX6aYixnp0VVJ4aRoFOAgWFuUfULvM0ctqjogYQbJOw97dbNK3ZBppqqtMtzfELM/all9hu2pZA="
        );
        assert_eq!(
            object_key("source-0123456789abcdef0123456789abcdef", "encryption"),
            "BBbcSdAUP/krvX41Q1AZYOMOwMTouHv2YMsxEekfpSuqeaDfUU3AX9RK/wV/gjKAcuFATKATCSTbyepWyDfCe00="
        );
    }

    #[test]
    fn object_keys_differ() {
        let mut seen = std::collections::HashSet::new();
        for o in ["sink", "source-00", "source-01"] {
            for u in ["signing", "encryption"] {
                let k = object_key(o, u);
                assert_eq!(k, object_key(o, u));
                assert!(seen.insert(k), "{o} {u}");
            }
        }
    }
}
