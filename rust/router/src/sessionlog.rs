//! Each session's two logs in the database (docs/STATE.md step 4): the lifecycle log (lifecycle.rs: its operations and
//! their entries) and the supervisor's lines (supervisorlog.rs), rows of session_log in the order they were written;
//! and the old core's input log (vouch.rs, session ""). The Go router's one-time import of the volume's jsonl files is
//! not carried over: every router that runs this code has made it already.

use crate::state::State;
use anyhow::{Result, anyhow};

pub const LOG_LIFECYCLE: &str = "lifecycle";
pub const LOG_SUPERVISOR: &str = "supervisor";
/// the old core's input log (vouch.rs), session ""
pub const LOG_INPUT: &str = "input";

impl State {
    fn log_db(&self) -> Result<&crate::db::DB> {
        self.db().ok_or_else(|| anyhow!("logs: no database"))
    }

    /// lines (JSON each) onto a session's log
    pub fn append_log(&self, session: &str, kind: &str, lines: &[&[u8]]) -> Result<()> {
        let mut c = self.log_db()?.conn()?;
        let mut tx = c.transaction()?;
        for l in lines {
            let s = std::str::from_utf8(l)?;
            tx.execute(
                "INSERT INTO session_log (session_id, kind, line) VALUES ($1, $2, $3::text::jsonb)",
                &[&session, &kind, &s],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn log_rows(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<Vec<u8>>> {
        let mut c = self.log_db()?.conn()?;
        Ok(c.query(sql, params)?
            .into_iter()
            .map(|r| r.get::<_, String>(0).into_bytes())
            .collect())
    }

    /// a session's log, oldest first
    pub fn read_log(&self, session: &str, kind: &str) -> Result<Vec<Vec<u8>>> {
        self.log_rows(
            "SELECT line::text FROM session_log WHERE session_id = $1 AND kind = $2 ORDER BY n",
            &[&session, &kind],
        )
    }

    /// a session's newest n lines, oldest first
    pub fn tail_log(&self, session: &str, kind: &str, n: i64) -> Result<Vec<Vec<u8>>> {
        self.log_rows(
            "SELECT line::text FROM (SELECT n, line FROM session_log WHERE session_id = $1 AND kind = $2
             ORDER BY n DESC LIMIT $3) t ORDER BY n",
            &[&session, &kind, &n],
        )
    }

    /// the size of a session's log (its lines' JSON)
    pub fn log_bytes(&self, session: &str, kind: &str) -> i64 {
        let Ok(db) = self.log_db() else { return 0 };
        let Ok(mut c) = db.conn() else { return 0 };
        c.query_one(
            "SELECT coalesce(sum(octet_length(line::text)), 0)::bigint FROM session_log WHERE session_id = $1 AND kind = $2",
            &[&session, &kind],
        )
        .map(|r| r.get::<_, i64>(0))
        .unwrap_or(0)
    }

    /// a session's log becomes lines (one transaction)
    pub fn replace_log(&self, session: &str, kind: &str, lines: &[Vec<u8>]) -> Result<()> {
        let mut c = self.log_db()?.conn()?;
        let mut tx = c.transaction()?;
        tx.execute(
            "DELETE FROM session_log WHERE session_id = $1 AND kind = $2",
            &[&session, &kind],
        )?;
        for l in lines {
            let s = std::str::from_utf8(l)?;
            tx.execute(
                "INSERT INTO session_log (session_id, kind, line) VALUES ($1, $2, $3::text::jsonb)",
                &[&session, &kind, &s],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// a session's log gone (its archive holds it)
    pub fn drop_log(&self, session: &str, kind: &str) {
        let res = self.log_db().and_then(|db| {
            db.conn()?.execute(
                "DELETE FROM session_log WHERE session_id = $1 AND kind = $2",
                &[&session, &kind],
            )?;
            Ok(())
        });
        if let Err(e) = res {
            crate::logf!("logs: dropping {session}'s {kind} log: {e:#}");
        }
    }

    /// the sessions that have a log of this kind
    pub fn log_sessions(&self, kind: &str) -> Vec<String> {
        let Ok(db) = self.log_db() else { return vec![] };
        let Ok(mut c) = db.conn() else { return vec![] };
        c.query(
            "SELECT DISTINCT session_id FROM session_log WHERE kind = $1",
            &[&kind],
        )
        .map(|rows| rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
        .unwrap_or_default()
    }
}
