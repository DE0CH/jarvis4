//! The router's database (docs/STATE.md, step 6): Postgres at DATABASE_URL (the Cluster jarvis4-db, role router;
//! Secret router-db). Schema changes are the embedded migrations/NNNN_*.sql, applied in order at start under a
//! Postgres advisory lock (so two replicas starting together apply each once), each in its own transaction with its
//! row in schema_migrations. A new router migrates while the old one still serves (a rollout), so a migration only
//! adds (tables, nullable columns); what the old code needs is dropped one release later. GET /healthz and
//! /setup/status report what status says.

use anyhow::{Context, Result, anyhow, bail};
use postgres::{Client, NoTls};
use r2d2::{Pool, PooledConnection};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static MIGRATIONS: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/migrations");

/// the advisory lock key the migrations run under ("jarvis4-migrate")
const MIGRATION_LOCK: i64 = 0x6a3473_6d6967;

pub struct Migration {
    pub version: i32,
    pub name: String,
    pub sql: String,
}

pub fn migrations() -> Result<Vec<Migration>> {
    let mut ms = vec![];
    for f in MIGRATIONS.files() {
        let name = f
            .path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (n, _) = name.split_once('_').unwrap_or(("", ""));
        let v: i32 = match n.parse() {
            Ok(v) if name.ends_with(".sql") => v,
            _ => bail!("migrations/{name}: not NNNN_name.sql"),
        };
        ms.push(Migration {
            version: v,
            name,
            sql: f.contents_utf8().unwrap_or_default().to_string(),
        });
    }
    ms.sort_by_key(|m| m.version);
    for (i, m) in ms.iter().enumerate() {
        if m.version != i as i32 + 1 {
            bail!("migrations: {} out of sequence (want {:04})", m.name, i + 1);
        }
    }
    Ok(ms)
}

/// what the pool hands out: a plain or a TLS connection (sslmode=require: encrypted, nothing verified, as libpq)
pub enum Manager {
    Plain(r2d2_postgres::PostgresConnectionManager<NoTls>),
    Tls(r2d2_postgres::PostgresConnectionManager<tokio_postgres_rustls::MakeRustlsConnect>),
}

impl r2d2::ManageConnection for Manager {
    type Connection = Client;
    type Error = postgres::Error;

    fn connect(&self) -> Result<Client, postgres::Error> {
        match self {
            Manager::Plain(m) => m.connect(),
            Manager::Tls(m) => m.connect(),
        }
    }

    fn is_valid(&self, c: &mut Client) -> Result<(), postgres::Error> {
        c.simple_query("").map(|_| ())
    }

    fn has_broken(&self, c: &mut Client) -> bool {
        c.is_closed()
    }
}

pub type Conn = PooledConnection<Manager>;

#[derive(Clone)]
pub struct DB {
    pub pool: Pool<Manager>,
    pub url: String,
    /// set by close
    pub done: Arc<AtomicBool>,
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// the connection settings of url, and whether it asks for TLS (sslmode require/verify-*; prefer counts as disable)
fn parse_url(url: &str) -> Result<(postgres::Config, bool)> {
    // tokio-postgres knows sslmode disable/prefer/require only; the verify modes are require here (as libpq's
    // require is: encrypted, the server's certificate not checked)
    let mut tls = false;
    let mut cleaned = url.to_string();
    if let Some((base, q)) = url.split_once('?') {
        let mut kept = vec![];
        for kv in q.split('&') {
            match kv.split_once('=') {
                Some(("sslmode", m)) => {
                    tls = matches!(m, "require" | "verify-ca" | "verify-full");
                    if !matches!(
                        m,
                        "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full"
                    ) {
                        bail!("DATABASE_URL: sslmode {m:?} is invalid");
                    }
                }
                _ => kept.push(kv),
            }
        }
        cleaned = if kept.is_empty() {
            base.to_string()
        } else {
            format!("{base}?{}", kept.join("&"))
        };
    }
    let cfg: postgres::Config = cleaned.parse().map_err(|e| anyhow!("DATABASE_URL: {e}"))?;
    Ok((cfg, tls))
}

/// how url's connections are made (TLS when it asks for it)
pub fn manager_for(url: &str) -> Result<Manager> {
    let (mut cfg, tls) = parse_url(url)?;
    cfg.connect_timeout(Duration::from_secs(10));
    Ok(if tls {
        let rc = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        cfg.ssl_mode(postgres::config::SslMode::Require);
        Manager::Tls(r2d2_postgres::PostgresConnectionManager::new(
            cfg,
            tokio_postgres_rustls::MakeRustlsConnect::new(rc),
        ))
    } else {
        Manager::Plain(r2d2_postgres::PostgresConnectionManager::new(cfg, NoTls))
    })
}

/// one connection of its own, outside the pool (a LISTEN)
pub fn connect_one(url: &str) -> Result<Client> {
    Ok(r2d2::ManageConnection::connect(&manager_for(url)?)?)
}

impl DB {
    /// a pool on url, the migrations applied
    pub fn open(url: &str) -> Result<DB> {
        let manager = manager_for(url)?;
        // opened as they are needed, as pgxpool does (an idle router holds one or two)
        let pool = Pool::builder()
            .max_size(8)
            .min_idle(Some(0))
            .connection_timeout(Duration::from_secs(30))
            .build(manager)
            .context("the database")?;
        let db = DB {
            pool,
            url: url.to_string(),
            done: Arc::new(AtomicBool::new(false)),
        };
        db.migrate()?;
        Ok(db)
    }

    pub fn conn(&self) -> Result<Conn> {
        self.pool.get().map_err(|e| anyhow!("the database: {e}"))
    }

    pub fn close(&self) {
        self.done.store(true, Ordering::SeqCst);
    }

    pub fn closed(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    fn migrate(&self) -> Result<()> {
        let ms = migrations()?;
        let mut c = self.conn()?;
        c.execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK])?;
        let r = (|| -> Result<()> {
            c.batch_execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, name text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now())",
            )?;
            let have: i32 = c
                .query_one(
                    "SELECT coalesce(max(version), 0) FROM schema_migrations",
                    &[],
                )?
                .get(0);
            if have as usize > ms.len() {
                bail!(
                    "the database is at schema {have}, newer than this router's {}: refusing to run an older router on it",
                    ms.len()
                );
            }
            for m in &ms[have as usize..] {
                let mut tx = c.transaction()?;
                tx.batch_execute(&m.sql)
                    .and_then(|_| {
                        tx.execute(
                            "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
                            &[&m.version, &m.name],
                        )
                    })
                    .with_context(|| format!("migration {}", m.name))?;
                tx.commit()
                    .with_context(|| format!("migration {}", m.name))?;
                logf!("db: applied migration {}", m.name);
            }
            Ok(())
        })();
        let _ = c.execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK]);
        r
    }

    /// the primary reachable, the schema version, each replica's replay lag (as the primary sees it)
    pub fn status(&self) -> DBStatus {
        let want = migrations().map(|m| m.len() as i32).unwrap_or(0);
        let mut st = DBStatus {
            want,
            ..Default::default()
        };
        let r = (|| -> Result<()> {
            let mut c = self.conn()?;
            let row = c.query_one(
                "SELECT pg_is_in_recovery(), coalesce((SELECT max(version) FROM schema_migrations), 0)",
                &[],
            )?;
            let recovery: bool = row.get(0);
            st.schema = row.get(1);
            st.primary = !recovery;
            if let Ok(rows) = c.query(
                "SELECT coalesce(application_name, ''), coalesce(state, ''), coalesce(sync_state, ''),
		extract(epoch FROM replay_lag)::float8 * 1000 FROM pg_stat_replication",
                &[],
            ) {
                for r in rows {
                    st.replicas.push(DBReplica {
                        name: r.get(0),
                        state: r.get(1),
                        sync: r.get(2),
                        replay_ms: r.get(3),
                    });
                }
            }
            Ok(())
        })();
        match r {
            Err(e) => st.error = format!("{e:#}"),
            Ok(()) if !st.primary => st.error = "connected to a replica, not the primary".into(),
            Ok(()) if st.schema != st.want => {
                st.error = format!("schema {}, this router wants {}", st.schema, st.want)
            }
            Ok(()) => st.ok = true,
        }
        st
    }
}

/// what /healthz and /setup/status show
#[derive(Debug, Clone, Default, Serialize)]
pub struct DBStatus {
    pub ok: bool,
    pub primary: bool,
    pub schema: i32,
    pub want: i32,
    pub replicas: Vec<DBReplica>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DBReplica {
    pub name: String,
    pub state: String,
    pub sync: String,
    /// null when the role can't see it (pg_read_all_stats) or none yet
    #[serde(rename = "replayLagMs")]
    pub replay_ms: Option<f64>,
}

/// the database at url, migrated; until it answers, tried again with a growing wait (a router can do nothing without
/// its records)
pub fn open_db_wait(url: &str) -> DB {
    let mut wait = Duration::from_secs(1);
    loop {
        match DB::open(url) {
            Ok(db) => {
                logf!(
                    "db: connected, schema {}",
                    migrations().map(|m| m.len()).unwrap_or(0)
                );
                return db;
            }
            Err(e) => logf!(
                "db: {e:#} (again in {})",
                jarvis_go::fmt::duration_string(wait)
            ),
        }
        std::thread::sleep(wait);
        wait = (wait * 2).min(Duration::from_secs(30));
    }
}
