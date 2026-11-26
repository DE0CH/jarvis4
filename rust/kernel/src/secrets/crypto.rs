//! The cryptography of secrets (kernel/secrets/crypto.go), all P-256 (the only curve the iPhone's Secure Enclave has):
//! a store's data key is wrapped to the COMBINED public key P + K (phone + secrets): unwrapping needs the phone's share
//! p·E and secrets' share k·E — Diffie–Hellman with the recipient split in two. Signing and sealing to one public key
//! are jarvis_sig's. Points travel as base64 of the 65-byte uncompressed X9.63 encoding.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use p256::elliptic_curve::point::DecompressPoint as _;
use p256::elliptic_curve::sec1::{FromEncodedPoint as _, ToEncodedPoint as _};
use p256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

fn point(raw: &[u8]) -> Result<ProjectivePoint> {
    let ep = EncodedPoint::from_bytes(raw).map_err(|_| anyhow!("bad point"))?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .map(ProjectivePoint::from)
        .ok_or_else(|| anyhow!("bad point"))
}

fn bytes(p: &ProjectivePoint) -> Result<Vec<u8>> {
    let e = p.to_affine().to_encoded_point(false);
    if e.as_bytes().len() != 65 {
        return Err(anyhow!("the point at infinity"));
    }
    Ok(e.as_bytes().to_vec())
}

/// P + Q, uncompressed
pub fn add_points(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    bytes(&(point(a)? + point(b)?))
}

/// k·P, uncompressed (k: 32 bytes, big-endian, below the order)
pub fn scalar_mult(k: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
    if k.len() != 32 {
        return Err(anyhow!("a scalar is 32 bytes"));
    }
    let s = Option::<Scalar>::from(Scalar::from_repr(*FieldBytes::from_slice(k)))
        .ok_or_else(|| anyhow!("scalar out of range"))?;
    bytes(&(point(raw)? * s))
}

/// the two points whose x-coordinate is x (the Enclave's key agreement returns only x)
pub fn points_with_x(x: &[u8]) -> Result<Vec<Vec<u8>>> {
    if x.len() != 32 {
        return Err(anyhow!("x must be 32 bytes"));
    }
    let fx = FieldBytes::from_slice(x);
    let mut out = vec![];
    for odd in [false, true] {
        let p = Option::<AffinePoint>::from(AffinePoint::decompress(fx, (odd as u8).into()))
            .ok_or_else(|| anyhow!("x is not on the curve"))?;
        out.push(p.to_encoded_point(false).as_bytes().to_vec());
    }
    Ok(out)
}

fn x_of(p: &[u8]) -> &[u8] {
    &p[1..33]
}

pub fn kdf(secret: &[u8], info: &str) -> [u8; 32] {
    let mut k = [0u8; 32];
    // 32 bytes is far under HKDF-SHA256's limit, so expand cannot fail
    let _ = Hkdf::<Sha256>::new(None, secret).expand(info.as_bytes(), &mut k);
    k
}

/// nonce || AES-256-GCM(plain, aad)
pub fn gcm_seal(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    use rand_core::RngCore as _;
    let c = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    // encrypting into memory cannot fail
    if let Ok(ct) = c.encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad }) {
        out.extend(ct);
    }
    out
}

pub fn gcm_open(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 12 + 16 {
        return Err(anyhow!("sealed data too short"));
    }
    let c = Aes256Gcm::new(key.into());
    c.decrypt(
        Nonce::from_slice(&sealed[..12]),
        Payload {
            msg: &sealed[12..],
            aad,
        },
    )
    .map_err(|_| anyhow!("cipher: message authentication failed"))
}

/// a store's data key, wrapped to the combined key P + K
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKey {
    /// the ephemeral public point e·G
    pub e: String,
    /// AES-GCM(data key) under HKDF(x(e·(P+K)))
    pub wrapped: String,
}

pub const INFO_STORE: &str = "jarvis2/store-data-key";

/// the phone's x(p·E) + secrets' k → the data key (tries both points with that x)
pub fn unwrap_with_shares(w: &WrappedKey, phone_share_x: &[u8], agreement_scalar: &[u8]) -> Result<Vec<u8>> {
    let eb = jarvis_sig::unb64(&w.e)?;
    let core_share = scalar_mult(agreement_scalar, &eb)?;
    let cands = points_with_x(phone_share_x)?;
    let wrapped = jarvis_sig::unb64(&w.wrapped)?;
    for c in cands {
        let Ok(sum) = add_points(&c, &core_share) else {
            continue;
        };
        if let Ok(dk) = gcm_open(&kdf(x_of(&sum), INFO_STORE), &wrapped, &[]) {
            return Ok(dk);
        }
    }
    Err(anyhow!("the phone's share doesn't open this store"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a data key wrapped to P + K opens with the phone's x(p·E) and secrets' k, either root of x
    #[test]
    fn a_store_key_opens_with_both_shares() {
        let p = jarvis_sig::Opener::generate();
        let k = jarvis_sig::Opener::generate();
        let combined = jarvis_sig::store_key(&p.public_key(), &k.public_key()).unwrap_or_default();
        let e = jarvis_sig::Opener::generate();
        let cb = jarvis_sig::unb64(&combined).unwrap_or_default();
        let shared = scalar_mult(&e.scalar(), &cb).unwrap_or_default();
        let dk = b"0123456789abcdef0123456789abcdef";
        let w = WrappedKey {
            e: e.public_key(),
            wrapped: jarvis_sig::b64(&gcm_seal(&kdf(x_of(&shared), INFO_STORE), dk, &[])),
        };
        let eb = jarvis_sig::unb64(&w.e).unwrap_or_default();
        let phone_share = scalar_mult(&p.scalar(), &eb).unwrap_or_default();
        let got = unwrap_with_shares(&w, x_of(&phone_share), &k.scalar());
        assert_eq!(got.ok().as_deref(), Some(&dk[..]));
        let wrong = jarvis_sig::Opener::generate();
        let other = scalar_mult(&wrong.scalar(), &eb).unwrap_or_default();
        assert!(unwrap_with_shares(&w, x_of(&other), &k.scalar()).is_err());
    }
}
