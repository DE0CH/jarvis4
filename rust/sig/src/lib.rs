//! The kernel's cryptography, the Rust port of kernel/sig (sig.go): all P-256 (the only curve the iPhone's Secure
//! Enclave has), the same formats as the Go code and core/crypto.go: ECDSA P-256 / SHA-256 DER signatures over the exact
//! payload bytes, base64; sealing to one public key = ephemeral ECDH + HKDF-SHA256 + AES-256-GCM. Points travel as
//! base64 of the 65-byte uncompressed encoding.
//!
//! Documents open strictly, as in Go (`DisallowUnknownFields` + no trailing data): the target types carry
//! `#[serde(deny_unknown_fields)]`, and serde_json refuses trailing data. serde also matches field names exactly and
//! refuses a repeated field, where Go's decoder is case-insensitive and keeps the last: a document Go signed with
//! its own field names opens the same; anything else is refused here, never accepted.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hkdf::Hkdf;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod identity;
pub use identity::{
    Component, Error as IdentityError, Identity, Roster, Trust, check_identity, open_roster,
    store_key,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad signature")]
    BadSignature,
    #[error("not PEM")]
    NotPem,
    #[error("not a P-256 key")]
    NotP256,
    #[error("bad public key")]
    BadPublicKey,
    #[error("bad base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("sealed data too short")]
    SealedTooShort,
    #[error("sealed data doesn't open")]
    Unseal,
}

/// base64 (standard, padded), as Go's `sig.B64`
pub fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

/// base64 decoded (standard, padded)
pub fn unb64(s: &str) -> Result<Vec<u8>, Error> {
    Ok(B64.decode(s)?)
}

// ---- signing --------------------------------------------------------------------------------------------------

/// A P-256 signing key
pub struct Signer {
    key: SigningKey,
}

impl Signer {
    pub fn generate() -> Self {
        Self {
            key: SigningKey::random(&mut OsRng),
        }
    }

    /// A PKCS#8 P-256 private key in PEM (the box key)
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        if !pem.contains("-----BEGIN") {
            return Err(Error::NotPem);
        }
        SecretKey::from_pkcs8_pem(pem)
            .map(|k| Self { key: k.into() })
            .map_err(|_| Error::NotP256)
    }

    /// The key as PKCS#8 PEM (what openssl genpkey writes; the e2e's box and root keys)
    pub fn to_pkcs8_pem(&self) -> String {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        SecretKey::from(&self.key)
            .to_pkcs8_pem(LineEnding::LF)
            .map(|z| z.to_string())
            .unwrap_or_default()
    }

    /// The raw 32-byte scalar (the machine keeps its private halves this way)
    pub fn from_scalar(b: &[u8]) -> Result<Self, Error> {
        SigningKey::from_slice(b)
            .map(|key| Self { key })
            .map_err(|_| Error::NotP256)
    }

    pub fn scalar(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }

    /// base64 of a DER ECDSA signature over sha256(payload)
    pub fn sign(&self, payload: &[u8]) -> String {
        let s: Signature = self.key.sign(payload);
        let der: DerSignature = s.to_der();
        b64(der.as_bytes())
    }

    /// base64 of the uncompressed public point
    pub fn public_key(&self) -> String {
        b64(VerifyingKey::from(&self.key)
            .to_encoded_point(false)
            .as_bytes())
    }

    /// `v` marshalled as Go's `json.Marshal` would ([`go_json`]) and signed
    pub fn sign_json<T: Serialize>(&self, v: &T) -> Result<Doc, Error> {
        let payload = go_json(v)?;
        let sig = self.sign(payload.as_bytes());
        Ok(Doc { payload, sig })
    }
}

fn verifying_key(raw: &str) -> Result<VerifyingKey, Error> {
    let b = unb64(raw)?;
    VerifyingKey::from_sec1_bytes(&b).map_err(|_| Error::BadPublicKey)
}

/// A DER signature by `public` over `payload`. High-S signatures verify, as in Go's `ecdsa.VerifyASN1` (Go signs
/// without normalising S, so half of every Go signature is high-S).
pub fn verify(public: &str, payload: &[u8], sig_b64: &str) -> bool {
    let (Ok(vk), Ok(raw)) = (verifying_key(public), unb64(sig_b64)) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(&raw) else {
        return false;
    };
    let sig = sig.normalize_s().unwrap_or(sig);
    vk.verify(payload, &sig).is_ok()
}

// ---- signed documents -----------------------------------------------------------------------------------------

/// A payload (exact JSON bytes as a string) and its signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Doc {
    pub payload: String,
    pub sig: String,
}

impl Doc {
    /// hex sha256 of the payload
    pub fn id(&self) -> String {
        hex::encode(Sha256::digest(self.payload.as_bytes()))
    }

    /// The payload as `T` when `public` signed it; unknown fields refuse it (a document means exactly what it says)
    pub fn open<T: DeserializeOwned>(&self, public: &str) -> Result<T, Error> {
        if !verify(public, self.payload.as_bytes(), &self.sig) {
            return Err(Error::BadSignature);
        }
        strict_json(self.payload.as_bytes())
    }
}

/// `v` as Go's `json.Marshal` writes it: serde_json's compact form with `<`, `>`, `&`, U+2028 and U+2029 escaped as
/// `\u003c` …, as Go escapes them (a Go reader re-marshalling a document gets the same bytes). These characters
/// only ever stand inside JSON strings, so replacing them in the output is exact. Floats: keep them out of signed
/// documents (Go and serde write some exponents differently).
pub fn go_json<T: Serialize + ?Sized>(v: &T) -> Result<String, Error> {
    let s = serde_json::to_string(v)?;
    if !s.contains(['<', '>', '&', '\u{2028}', '\u{2029}']) {
        return Ok(s);
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Decode refusing trailing data (unknown fields: the type's `deny_unknown_fields`)
pub fn strict_json<T: DeserializeOwned>(b: &[u8]) -> Result<T, Error> {
    Ok(serde_json::from_slice(b)?)
}

// ---- sealing to one public key --------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    /// the ephemeral public key
    pub e: String,
    /// AES-GCM(nonce || ciphertext) under HKDF(x(e·R), info)
    pub data: String,
}

fn kdf(shared_x: &[u8], info: &str) -> Aes256Gcm {
    let mut k = [0u8; 32];
    // 32 bytes is far under HKDF-SHA256's limit, so expand cannot fail
    let _ = Hkdf::<Sha256>::new(None, shared_x).expand(info.as_bytes(), &mut k);
    Aes256Gcm::new(&k.into())
}

fn public_from_b64(raw: &str) -> Result<PublicKey, Error> {
    PublicKey::from_sec1_bytes(&unb64(raw)?).map_err(|_| Error::BadPublicKey)
}

pub fn seal_to(recipient: &str, plain: &[u8], info: &str) -> Result<Sealed, Error> {
    let r = public_from_b64(recipient)?;
    let e = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let x = e.diffie_hellman(&r);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = kdf(x.raw_secret_bytes(), info)
        .encrypt(&Nonce::from(nonce), plain)
        .map_err(|_| Error::Unseal)?;
    let mut data = nonce.to_vec();
    data.extend_from_slice(&ct);
    Ok(Sealed {
        e: b64(e.public_key().to_encoded_point(false).as_bytes()),
        data: b64(&data),
    })
}

/// A P-256 private key for opening sealed data (the machine's encryption key)
pub struct Opener {
    key: SecretKey,
}

impl Opener {
    pub fn generate() -> Self {
        Self {
            key: SecretKey::random(&mut OsRng),
        }
    }

    pub fn from_scalar(b: &[u8]) -> Result<Self, Error> {
        SecretKey::from_slice(b)
            .map(|key| Self { key })
            .map_err(|_| Error::NotP256)
    }

    pub fn scalar(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }

    /// base64 of the uncompressed public point
    pub fn public_key(&self) -> String {
        b64(self.key.public_key().to_encoded_point(false).as_bytes())
    }

    pub fn open(&self, s: &Sealed, info: &str) -> Result<Vec<u8>, Error> {
        let e = public_from_b64(&s.e)?;
        let x = p256::ecdh::diffie_hellman(self.key.to_nonzero_scalar(), e.as_affine());
        let d = unb64(&s.data)?;
        if d.len() < 12 + 16 {
            return Err(Error::SealedTooShort);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&d[..12]);
        kdf(x.raw_secret_bytes(), info)
            .decrypt(&Nonce::from(nonce), &d[12..])
            .map_err(|_| Error::Unseal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let s = Signer::generate();
        let sig = s.sign(b"payload");
        assert!(verify(&s.public_key(), b"payload", &sig));
        assert!(!verify(&s.public_key(), b"payloaD", &sig));
        assert!(!verify(&Signer::generate().public_key(), b"payload", &sig));
        assert!(!verify("not base64!", b"payload", &sig));
    }

    #[test]
    fn docs_open_strictly() {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct T {
            a: u32,
        }
        let s = Signer::generate();
        let d = s.sign_json(&T { a: 1 }).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.open::<T>(&s.public_key()).ok(), Some(T { a: 1 }));
        let extra = Doc {
            sig: s.sign(br#"{"a":1,"b":2}"#),
            payload: r#"{"a":1,"b":2}"#.into(),
        };
        assert!(
            extra.open::<T>(&s.public_key()).is_err(),
            "an unknown field opened"
        );
        let trailing = Doc {
            sig: s.sign(br#"{"a":1} {}"#),
            payload: r#"{"a":1} {}"#.into(),
        };
        assert!(
            trailing.open::<T>(&s.public_key()).is_err(),
            "trailing data opened"
        );
        let forged = Doc {
            sig: d.sig.clone(),
            payload: r#"{"a":2}"#.into(),
        };
        assert!(matches!(
            forged.open::<T>(&s.public_key()),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn seal_round_trip() {
        let o = Opener::generate();
        let s = seal_to(&o.public_key(), b"secret", "info").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(o.open(&s, "info").ok().as_deref(), Some(&b"secret"[..]));
        assert!(o.open(&s, "other info").is_err());
        assert!(Opener::generate().open(&s, "info").is_err());
    }
}
