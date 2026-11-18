//! The router's secrets in the database, sealed (docs/STATE.md 2.3): the Claude accounts (claudeaccounts.rs,
//! claudelogin.rs) and the holder keys (grants.rs). The router holds them in plaintext (it refreshes the logins, it
//! signs as the holders), but the database and its S3 backups only ever see AES-256-GCM ciphertext under the seal key:
//! ROUTER_SEAL_KEY (base64, 32 bytes; Secret router-seal). Each row names its key (key_id = the key's sha256, first 16
//! hex) and binds its name as additional data, so a row can't be moved to another name. A rotation: ROUTER_SEAL_KEY
//! the new key, ROUTER_SEAL_KEY_OLD the previous one; rows under the old key are read with it and resealed under the
//! new one at start.

use crate::state::State;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct SealKey {
    pub id: String,
    key: Aes256Gcm,
}

/// the current seal key and the previous one (a rotation)
#[derive(Clone)]
pub struct Sealer {
    pub cur: SealKey,
    pub old: Option<SealKey>,
}

fn new_seal_key(raw: &[u8]) -> Result<SealKey> {
    if raw.len() != 32 {
        bail!("a seal key is 32 bytes, not {}", raw.len());
    }
    let key = Aes256Gcm::new_from_slice(raw).map_err(|e| anyhow!("{e}"))?;
    Ok(SealKey {
        id: hex::encode(&Sha256::digest(raw)[..8]),
        key,
    })
}

fn key_from(v: &str) -> Result<SealKey> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(v.trim())
        .map_err(|_| anyhow!("seal key: not base64"))?;
    new_seal_key(&raw)
}

/// ROUTER_SEAL_KEY (and ROUTER_SEAL_KEY_OLD); a throwaway router (ROUTER_THROWAWAY=1) with none gets a random key for
/// its life
pub fn sealer_from_env() -> Result<Sealer> {
    let cur = std::env::var("ROUTER_SEAL_KEY").unwrap_or_default();
    if cur.is_empty() {
        if std::env::var("ROUTER_THROWAWAY").as_deref() != Ok("1") {
            bail!(
                "ROUTER_SEAL_KEY is required (Secret router-seal), or ROUTER_THROWAWAY=1 for a throwaway router"
            );
        }
        return Ok(random_sealer());
    }
    let old = match std::env::var("ROUTER_SEAL_KEY_OLD") {
        Ok(v) if !v.is_empty() => Some(key_from(&v)?),
        _ => None,
    };
    Ok(Sealer {
        cur: key_from(&cur)?,
        old,
    })
}

pub fn random_sealer() -> Sealer {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    Sealer {
        cur: new_seal_key(&raw).unwrap_or_else(|e| panic!("{e}")),
        old: None,
    }
}

impl Sealer {
    pub fn seal(&self, name: &str, plain: &[u8]) -> (String, Vec<u8>, Vec<u8>) {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let body = self
            .cur
            .key
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plain,
                    aad: name.as_bytes(),
                },
            )
            .unwrap_or_default();
        (self.cur.id.clone(), nonce.to_vec(), body)
    }

    pub fn open(&self, name: &str, key_id: &str, nonce: &[u8], body: &[u8]) -> Result<Vec<u8>> {
        for k in std::iter::once(&self.cur).chain(self.old.iter()) {
            if k.id == key_id {
                let Ok(nonce) = <[u8; 12]>::try_from(nonce) else {
                    bail!("cipher: message authentication failed");
                };
                return k
                    .key
                    .decrypt(
                        &Nonce::from(nonce),
                        Payload {
                            msg: body,
                            aad: name.as_bytes(),
                        },
                    )
                    .map_err(|_| anyhow!("cipher: message authentication failed"));
            }
        }
        bail!("sealed {name}: under key {key_id}, which this router doesn't have")
    }
}

impl State {
    fn sealed_db(&self) -> Result<(&crate::db::DB, &Sealer)> {
        match (self.db(), &self.seal) {
            (Some(db), Some(s)) => Ok((db, s)),
            _ => bail!("sealed: no database"),
        }
    }

    /// a sealed document, opened (None: none)
    pub fn read_sealed(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let (db, seal) = self.sealed_db()?;
        let mut c = db.conn()?;
        let Some(r) = c.query_opt(
            "SELECT key_id, nonce, body FROM sealed_docs WHERE name = $1",
            &[&name],
        )?
        else {
            return Ok(None);
        };
        let (kid, nonce, body): (String, Vec<u8>, Vec<u8>) = (r.get(0), r.get(1), r.get(2));
        seal.open(name, &kid, &nonce, &body).map(Some)
    }

    /// a document sealed and stored (replacing)
    pub fn write_sealed(&self, name: &str, plain: &[u8]) -> Result<()> {
        let (db, seal) = self.sealed_db()?;
        let (kid, nonce, body) = seal.seal(name, plain);
        db.conn()?.execute(
            "INSERT INTO sealed_docs (name, key_id, nonce, body, updated_at) VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (name) DO UPDATE SET key_id = excluded.key_id, nonce = excluded.nonce, body = excluded.body, updated_at = now()",
            &[&name, &kid, &nonce, &body],
        )?;
        Ok(())
    }

    /// a notification on the mq channel (mq.rs), for the other replica's waiters; best effort
    pub fn notify_mq(&self, payload: &str) {
        let Some(db) = self.db() else { return };
        let r = db
            .conn()
            .and_then(|mut c| Ok(c.execute("SELECT pg_notify('mq', $1)", &[&payload])?));
        if let Err(e) = r {
            crate::logf!("mq: notify {payload}: {e:#}");
        }
    }

    /// gone
    pub fn delete_sealed(&self, name: &str) -> Result<()> {
        let (db, _) = self.sealed_db()?;
        db.conn()?
            .execute("DELETE FROM sealed_docs WHERE name = $1", &[&name])?;
        Ok(())
    }

    /// the names under prefix
    pub fn list_sealed(&self, prefix: &str) -> Result<Vec<String>> {
        let (db, _) = self.sealed_db()?;
        Ok(db
            .conn()?
            .query(
                "SELECT name FROM sealed_docs WHERE starts_with(name, $1) ORDER BY name",
                &[&prefix],
            )?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }

    /// rows under the previous key, resealed under the current one (a rotation's second half)
    pub(crate) fn reseal_old(&self) -> Result<()> {
        let Some(seal) = &self.seal else {
            return Ok(());
        };
        if seal.old.is_none() {
            return Ok(());
        }
        let Some(db) = self.db() else { return Ok(()) };
        let names: Vec<String> = db
            .conn()?
            .query(
                "SELECT name FROM sealed_docs WHERE key_id <> $1",
                &[&seal.cur.id],
            )?
            .iter()
            .map(|r| r.get(0))
            .collect();
        for n in &names {
            let b = self
                .read_sealed(n)
                .map_err(|e| anyhow!("reseal {n}: {e:#}"))?
                .ok_or_else(|| anyhow!("reseal {n}: <nil>"))?;
            self.write_sealed(n, &b)?;
        }
        if !names.is_empty() {
            crate::logf!(
                "sealed: {} documents resealed under key {}",
                names.len(),
                seal.cur.id
            );
        }
        Ok(())
    }
}
