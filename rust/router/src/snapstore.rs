//! Machines' snapshots in object storage (docs/STATE.md 2.2, step 5): the tarball is the object
//! snapshots/<machine>.tar.gz of jarvis4-snapshots-de0ch (objstore.rs), streamed straight in as the machine sends it
//! (no copy on the router's disk, no growth in its memory beyond the upload's parts), hashed and read for its facts on
//! the way; the row of `snapshots` says whether it is pending (streamed, unsigned) or committed (the machine signed its
//! sha256). A booting machine whose state is its predecessor's snapshot gets a row naming the predecessor's object. The
//! carried secrets beside it (carry.rs) are rows of router_docs (carry/<machine>). The Go router's one-time import of
//! the volume's snapshots/ is not carried over.

use crate::objstore::ObjReader;
use crate::router::Router;
use crate::tails::{SnapshotFacts, read_snapshot_facts_from};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// the largest snapshot a machine may send
pub const SNAPSHOT_MAX: u64 = 32 << 30;

/// a machine's snapshot row
#[derive(Debug, Clone, Default)]
pub struct Snap {
    pub machine: String,
    pub key: String,
    pub sha256: String,
    pub sig: String,
    pub state: String,
    pub bytes: i64,
    pub facts: Option<SnapshotFacts>,
    pub committed_at: GoTime,
}

/// no streamed snapshot with that sha256
#[derive(Debug)]
pub struct NoSnap;

impl std::fmt::Display for NoSnap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no streamed snapshot with that sha256")
    }
}

impl std::error::Error for NoSnap {}

pub fn snap_key(machine: &str) -> String {
    format!("snapshots/{machine}.tar.gz")
}

/// a reader that hashes, counts and copies (into the facts' pipe) what passes through
struct Tee<R: Read> {
    r: R,
    h: Sha256,
    n: u64,
    pipe: Option<std::io::PipeWriter>,
}

impl<R: Read> Read for Tee<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let k = self.r.read(buf)?;
        self.h.update(&buf[..k]);
        self.n += k as u64;
        if let Some(p) = self.pipe.as_mut()
            && p.write_all(&buf[..k]).is_err()
        {
            self.pipe = None; // the facts' reader is done: the upload goes on
        }
        Ok(k)
    }
}

/// a snapshot's bytes into sink, hashed, counted and read for their facts on the way (at most SNAPSHOT_MAX) → (sha256,
/// size, facts)
pub fn snap_ingest(
    body: &mut dyn Read,
    sink: impl FnOnce(&mut dyn Read) -> Result<()>,
) -> std::result::Result<(String, i64, Option<SnapshotFacts>), (anyhow::Error, i64)> {
    let (pr, pw) = std::io::pipe().map_err(|e| (anyhow::Error::from(e), 0))?;
    let facts = std::thread::spawn(move || {
        let mut pr = pr;
        let f = read_snapshot_facts_from(&mut pr).ok();
        let _ = std::io::copy(&mut pr, &mut std::io::sink()); // whatever the reader left: the upload must not stall
        f
    });
    let mut tee = Tee { r: body.take(SNAPSHOT_MAX + 1), h: Sha256::new(), n: 0, pipe: Some(pw) };
    let res = sink(&mut tee);
    tee.pipe = None;
    let facts = facts.join().unwrap_or(None);
    let n = tee.n as i64;
    if let Err(e) = res {
        return Err((e, n));
    }
    if tee.n > SNAPSHOT_MAX {
        return Err((anyhow!("body over {SNAPSHOT_MAX} bytes"), n));
    }
    Ok((hex::encode(tee.h.finalize()), n, facts))
}

impl Router {
    fn snap_db(&self) -> Result<&crate::db::DB> {
        self.st.db().ok_or_else(|| anyhow!("snapshots: no database"))
    }

    /// the machine's snapshot row (None: none)
    pub fn snap(&self, machine: &str) -> Option<Snap> {
        let res = (|| -> Result<Option<Snap>> {
            let row = self.snap_db()?.conn()?.query_opt(
                "SELECT machine_id, object_key, sha256, sig, state, bytes, facts::text, committed_at FROM snapshots WHERE machine_id = $1",
                &[&machine],
            )?;
            Ok(row.map(|r| {
                let facts: Option<String> = r.get(6);
                let at: Option<time::OffsetDateTime> = r.get(7);
                Snap {
                    machine: r.get(0),
                    key: r.get(1),
                    sha256: r.get(2),
                    sig: r.get(3),
                    state: r.get(4),
                    bytes: r.get(5),
                    facts: facts.filter(|f| f != "null").and_then(|f| jarvis_go::unmarshal(f.as_bytes()).ok()),
                    committed_at: GoTime(at),
                }
            }))
        })();
        res.unwrap_or_else(|e| {
            crate::logf!("snapshots: {machine}: {e:#}");
            None
        })
    }

    /// the session's machine whose committed snapshot has this sha256 ("" when none)
    pub fn snap_machine_with(&self, session_id: &str, sum: &str) -> String {
        let machines: Vec<String> = self.st.do_(|d| {
            d.machines
                .iter()
                .filter(|(_, sid)| *sid == session_id)
                .map(|(m, _)| m.clone())
                .collect()
        });
        machines
            .into_iter()
            .find(|m| self.snap(m).is_some_and(|s| s.state == "committed" && s.sha256 == sum))
            .unwrap_or_default()
    }

    /// the sha256 of the session's newest committed snapshot that its machine's key signed ("" when none)
    pub fn newest_snap_sum(&self, session_id: &str) -> String {
        let (m, cert, _) = self.latest_snapshot(session_id); // archive.rs
        if m.is_empty() || cert.is_none() {
            return String::new();
        }
        let key = self.st.do_(|d| d.started.get(&m).map(|st| st.signing_key.clone()).unwrap_or_default());
        match self.snap(&m) {
            Some(s) if !key.is_empty() && jarvis_sig::verify(&key, s.sha256.as_bytes(), &s.sig) => s.sha256,
            _ => String::new(),
        }
    }

    /// the machine has a committed (signed) snapshot
    pub fn have_snap(&self, machine: &str) -> bool {
        self.snap(machine).is_some_and(|s| s.state == "committed")
    }

    /// body into the machine's snapshot object, hashed and read for its facts on the way → pending; (sha256, size)
    pub fn snap_stream(&self, machine: &str, body: &mut dyn Read) -> std::result::Result<(String, i64), (anyhow::Error, i64)> {
        let key = snap_key(machine);
        let (sum, n, facts) = snap_ingest(body, |b| self.objects.put(&key, b, -1))?;
        self.snap_pending(machine, &key, &sum, n, facts.as_ref()).map_err(|e| (e, n))?;
        Ok((sum, n))
    }

    /// the machine's row names key, with that hash, size and facts, waiting for its signature
    pub fn snap_pending(&self, machine: &str, key: &str, sum: &str, n: i64, facts: Option<&SnapshotFacts>) -> Result<()> {
        let fb: Option<String> = facts.map(jarvis_go::marshal);
        self.snap_db()?.conn()?.execute(
            "INSERT INTO snapshots (machine_id, object_key, sha256, sig, bytes, state, facts) VALUES ($1, $2, $3, '', $4, 'pending', $5::text::jsonb)
             ON CONFLICT (machine_id) DO UPDATE SET object_key = excluded.object_key, sha256 = excluded.sha256, sig = '', bytes = excluded.bytes,
             state = 'pending', facts = excluded.facts, committed_at = NULL",
            &[&machine, &key, &sum, &n, &fb],
        )?;
        Ok(())
    }

    /// the pending snapshot with this sha256, signed by the machine → committed
    pub fn snap_commit(&self, machine: &str, sum: &str, sig: &str) -> Result<()> {
        let n = self.snap_db()?.conn()?.execute(
            "UPDATE snapshots SET state = 'committed', sig = $3, committed_at = now() WHERE machine_id = $1 AND sha256 = $2",
            &[&machine, &sum, &sig],
        )?;
        if n != 1 {
            return Err(NoSnap.into());
        }
        Ok(())
    }

    /// the machine's snapshot is its predecessor's object (a booting machine's state), signed by the machine
    pub fn snap_carry(&self, machine: &str, pred: &str, sum: &str, sig: &str) -> Result<()> {
        if !self.snap(pred).is_some_and(|p| p.state == "committed" && p.sha256 == sum) {
            return Err(anyhow!("the predecessor {pred} has no committed snapshot with that sha256"));
        }
        self.snap_db()?.conn()?.execute(
            "INSERT INTO snapshots (machine_id, object_key, sha256, sig, bytes, state, facts, committed_at)
             SELECT $1, object_key, sha256, $2, bytes, 'committed', facts, now() FROM snapshots WHERE machine_id = $3
             ON CONFLICT (machine_id) DO UPDATE SET object_key = excluded.object_key, sha256 = excluded.sha256, sig = excluded.sig,
             bytes = excluded.bytes, state = 'committed', facts = excluded.facts, committed_at = now()",
            &[&machine, &sig, &pred],
        )?;
        Ok(())
    }

    /// a whole committed snapshot from a reader (the older POST /m/snapshot, tests)
    pub fn snap_put_whole(&self, machine: &str, body: &mut dyn Read, sig: &str) -> Result<()> {
        let (sum, _) = self.snap_stream(machine, body).map_err(|(e, _)| e)?;
        self.snap_commit(machine, &sum, sig)
    }

    /// the snapshot's bytes
    pub fn snap_open(&self, s: &Snap) -> Result<ObjReader> {
        self.objects.get(&s.key)
    }

    /// what the snapshot holds (read when it streamed in; read now from the object when it wasn't)
    pub fn snap_facts(&self, s: &Snap) -> Result<SnapshotFacts> {
        if let Some(f) = &s.facts {
            return Ok(f.clone());
        }
        let mut rd = self.snap_open(s)?;
        let f = read_snapshot_facts_from(&mut rd)?;
        let fb = jarvis_go::marshal(&f);
        if let Ok(db) = self.snap_db()
            && let Ok(mut c) = db.conn()
        {
            let _ = c.execute("UPDATE snapshots SET facts = $2::text::jsonb WHERE object_key = $1", &[&s.key, &fb]);
        }
        Ok(f)
    }

    /// the snapshot copied to a scratch file, its signature beside it (.sig) (the archive walks it several times); the
    /// caller removes both
    pub fn snap_to_file(&self, s: &Snap, dir: &Path) -> Result<PathBuf> {
        crate::util::mkdir_all_0700(dir)?;
        let p = dir.join(format!("snap-{}.tar.gz", crate::util::rand_id()));
        let res = (|| -> Result<()> {
            let mut f = crate::util::create_0600(&p)?;
            let mut rd = self.snap_open(s)?;
            std::io::copy(&mut rd, &mut f)?;
            f.sync_all().ok();
            // the archive copies it beside (jarvis2/snapshot.sig)
            crate::util::write_file_0600(&PathBuf::from(format!("{}.sig", p.display())), s.sig.as_bytes())
        })();
        if let Err(e) = res {
            let _ = std::fs::remove_file(&p);
            return Err(e);
        }
        Ok(p)
    }

    /// the machine's snapshot row gone, and its object once no other row names it
    pub fn snap_drop(&self, machine: &str) {
        let res = (|| -> Result<()> {
            let mut c = self.snap_db()?.conn()?;
            let Some(row) = c.query_opt("DELETE FROM snapshots WHERE machine_id = $1 RETURNING object_key", &[&machine])? else {
                return Ok(());
            };
            let key: String = row.get(0);
            let others: bool = c
                .query_one("SELECT EXISTS (SELECT 1 FROM snapshots WHERE object_key = $1)", &[&key])?
                .get(0);
            if !others && let Err(e) = self.objects.delete(&key) {
                crate::logf!("snapshots: deleting {key}: {e:#}");
            }
            Ok(())
        })();
        if let Err(e) = res {
            crate::logf!("snapshots: dropping {machine}: {e:#}");
        }
    }

    /// the facts of the machine's snapshot
    pub fn snap_facts_of(&self, machine: &str) -> Result<SnapshotFacts> {
        let s = self.snap(machine).ok_or_else(|| anyhow!("no snapshot of {machine}"))?;
        self.snap_facts(&s)
    }

    /// the machine ids of rows that start with prefix (the restores' rows)
    pub fn snaps_like(&self, prefix: &str) -> Vec<String> {
        let Ok(db) = self.snap_db() else { return vec![] };
        let Ok(mut c) = db.conn() else { return vec![] };
        c.query("SELECT machine_id FROM snapshots WHERE starts_with(machine_id, $1)", &[&prefix])
            .map(|rows| rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
            .unwrap_or_default()
    }
}
