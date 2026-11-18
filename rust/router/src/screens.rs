//! The machine's pushed pane (rust/machine/src/screen.rs), one row per session in session_screens: the router runs as
//! replicas and the push reaches any of them, so it lives in the database, not in a replica's memory; and apart from
//! the versioned records, so a push every 2 s doesn't make every replica read the whole state again.

use crate::router::Router;
use crate::state::State;
use crate::terminal::TermSnap;
use crate::types::Session;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use std::time::Duration;

impl State {
    /// the session's latest pane, from its running machine
    pub fn put_screen(&self, session: &str, machine: &str, snap: &TermSnap) -> Result<()> {
        let db = self.db().ok_or_else(|| anyhow!("screens: no database"))?;
        let b = jarvis_go::marshal(snap);
        db.conn()?.execute(
            "INSERT INTO session_screens (session_id, machine_id, snap, at) VALUES ($1, $2, $3::text::jsonb, now())
		ON CONFLICT (session_id) DO UPDATE SET machine_id = excluded.machine_id, snap = excluded.snap, at = excluded.at",
            &[&session, &machine, &b],
        )?;
        Ok(())
    }

    /// the latest pane this machine of the session pushed, and how long ago (None: none from that machine)
    pub fn screen(&self, session: &str, machine: &str) -> Option<(TermSnap, Duration)> {
        let mut c = self.db()?.conn().ok()?;
        let row = c
            .query_opt(
                "SELECT snap::text, extract(epoch FROM now() - at)::float8 FROM session_screens WHERE session_id = $1 AND machine_id = $2",
                &[&session, &machine],
            )
            .ok()??;
        let b: String = row.get(0);
        let age: f64 = row.get(1);
        let snap = jarvis_go::unmarshal(b.as_bytes()).ok()?;
        Some((snap, Duration::from_secs_f64(age.max(0.0))))
    }

    /// a session that ended (destroyed) leaves no pane behind
    pub fn drop_screen(&self, session: &str) {
        let Some(db) = self.db() else { return };
        if let Ok(mut c) = db.conn() {
            let _ = c.execute(
                "DELETE FROM session_screens WHERE session_id = $1",
                &[&session],
            );
        }
    }
}

pub fn screens_on_destroy(r: &Arc<Router>, s: &Session) {
    r.st.drop_screen(&s.id);
}
