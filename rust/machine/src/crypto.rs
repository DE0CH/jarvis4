//! The machine's keys and the core's formats (core/crypto.go): P-256 ECDSA over SHA-256 (DER, base64), documents,
//! sealing (ephemeral ECDH + HKDF-SHA256 + AES-256-GCM), all from jarvis-sig.

use crate::gojson;
use crate::paths;
use anyhow::{Context, Result, anyhow};
use jarvis_sig::{Opener, Sealed, Signer, b64, unb64};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// A payload (exact JSON bytes) and its signature
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SignedDoc {
    pub payload: String,
    pub sig: String,
}

impl From<jarvis_sig::Doc> for SignedDoc {
    fn from(d: jarvis_sig::Doc) -> Self {
        Self {
            payload: d.payload,
            sig: d.sig,
        }
    }
}

impl SignedDoc {
    pub fn as_sig_doc(&self) -> jarvis_sig::Doc {
        jarvis_sig::Doc {
            payload: self.payload.clone(),
            sig: self.sig.clone(),
        }
    }
}

/// private.json: the private halves (raw scalars, base64)
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Private {
    pub enc: String,
    pub sig: String,
}

/// The machine's private keys
pub struct Keys {
    pub enc: Opener,
    pub sig: Signer,
}

impl Keys {
    pub fn generate() -> Self {
        Self {
            enc: Opener::generate(),
            sig: Signer::generate(),
        }
    }

    /// private.json's bytes
    pub fn private_json(&self) -> String {
        gojson::marshal(&Private {
            enc: b64(&self.enc.scalar()),
            sig: b64(&self.sig.scalar()),
        })
    }

    /// keys.json's bytes: the public halves
    pub fn public_json(&self) -> String {
        let mut m = std::collections::BTreeMap::new();
        m.insert("encryptionKey", self.enc.public_key());
        m.insert("signingKey", self.sig.public_key());
        gojson::marshal(&m)
    }
}

pub fn load_private() -> Result<Keys> {
    let b = std::fs::read(paths::priv_path())?;
    let p: Private = gojson::unmarshal(&b)?;
    Ok(Keys {
        enc: Opener::from_scalar(&unb64(&p.enc)?)?,
        sig: Signer::from_scalar(&unb64(&p.sig)?)?,
    })
}

/// base64 DER ECDSA signature over sha256(payload)
pub fn sign(k: &Signer, payload: &[u8]) -> String {
    k.sign(payload)
}

pub fn verify(public: &str, payload: &[u8], sig: &str) -> bool {
    jarvis_sig::verify(public, payload, sig)
}

/// The payload as `T` when `public` signed it (decoded as Go's json.Unmarshal: unknown fields ignored)
pub fn verify_doc<T: DeserializeOwned>(public: &str, d: Option<&SignedDoc>) -> Result<T> {
    let d = d.ok_or_else(|| anyhow!("bad signature"))?;
    if !verify(public, d.payload.as_bytes(), &d.sig) {
        return Err(anyhow!("bad signature"));
    }
    Ok(gojson::unmarshal(d.payload.as_bytes())?)
}

/// ephemeral ECDH + HKDF-SHA256 + AES-256-GCM (nonce ‖ ciphertext ‖ tag), as core.SealTo
pub fn open_sealed(k: &Opener, e: &str, data: &str, info: &str) -> Result<Vec<u8>> {
    k.open(
        &Sealed {
            e: e.into(),
            data: data.into(),
        },
        info,
    )
    .context("sealed data doesn't open")
}

/// hex sha256
pub fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

/// Go's os.ReadFile + strings.TrimSpace, refusing an empty file
pub fn read_trim(p: &std::path::Path) -> Result<String> {
    let s = std::fs::read_to_string(p)?;
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("{} is empty", p.display()));
    }
    Ok(s.to_string())
}
