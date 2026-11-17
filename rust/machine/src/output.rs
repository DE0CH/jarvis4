//! An AWS machine's own logs to Grafana (router/awslogs.go; docs/PLAN-aws.md "Logs"). On Fly, Fly reads the machine's
//! stdout and stderr; an EC2 instance's container output goes only to the instance's journal, so on AWS the machine
//! sends it itself, through the router:
//!
//!   - its output: the keeper (PID 1) makes fd 1 and 2 a pipe at its start (tee_output), so its own lines and every
//!     child's that inherits them pass through it; each line goes on to the original stdout and into output.log;
//!   - the host's journal (ship_host_journal): the instance's systemd units, read with journalctl from the host's disk,
//!     which the keeper mounts read only (or the kernel's bind of the journal, when it has one). The kernel's messages
//!     are left out: the router reads them from the serial console.
//!
//! supervisor-core pushes both files (push_outputs), like the supervisor log, to POST /m/machine-output, signed with
//! the machine's key. Every value the supervisor holds is replaced first (the secret redactor).

use crate::client::Client;
use crate::session::{privileged, session};
use crate::supervisorlog::{LogLine, push_lines_from};
use crate::{gojson, logf, on_aws, paths, util};
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime};

/// the spawner's bind of the host's journal (docs/PLAN-aws.md "Logs")
const HOST_JOURNAL_BIND: &str = "/run/jarvis-host/journal";
/// a file this far ahead of its push takes no more lines (two fit /run/jarvis, 256 MB)
const SHIP_FILE_CAP: u64 = 32 << 20;
const SUPERVISOR_LOG_ROLL: u64 = 2 << 20;
const OUTPUT_PUSH_EVERY: Duration = Duration::from_secs(2);

fn host_root_dir() -> PathBuf {
    PathBuf::from(paths::KEEPER_DIR).join("host")
}

fn host_root_mount() -> PathBuf {
    host_root_dir().join("root")
}

static KEEPER_STARTED: LazyLock<SystemTime> = LazyLock::new(SystemTime::now);

/// one {"at","text"} line file supervisor-core pushes to /m/machine-output as source
pub struct ShipFile {
    source: &'static str,
    path: fn() -> PathBuf,
    /// the writer's (the keeper's tee and journal reader): lines not kept since the cap
    dropped: Mutex<usize>,
}

pub static OUTPUT_SHIP: ShipFile = ShipFile {
    source: "machine",
    path: paths::output_log_path,
    dropped: Mutex::new(0),
};
pub static JOURNAL_SHIP: ShipFile = ShipFile {
    source: "journal",
    path: paths::journal_log_path,
    dropped: Mutex::new(0),
};

fn rfc3339_nano(t: SystemTime) -> String {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    jarvis_doc::rfc3339_nano(
        time::OffsetDateTime::from_unix_timestamp_nanos(d.as_nanos() as i128)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH),
    )
}

impl ShipFile {
    fn sent_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.sent", (self.path)().display()))
    }

    /// One line at `at` (the file goes to user claude, as the supervisor log does). Past the cap unpushed, lines are
    /// counted, not kept; the count is the next line.
    pub fn add(&self, at: SystemTime, text: &str) {
        let mut dropped = self.dropped.lock().unwrap_or_else(|e| e.into_inner());
        let p = (self.path)();
        if let Ok(md) = std::fs::metadata(&p)
            && md.len().saturating_sub(read_offset_of(&self.sent_path())) > SHIP_FILE_CAP
        {
            *dropped += 1;
            return;
        }
        let mut b = String::new();
        if *dropped > 0 {
            let l = LogLine {
                at: rfc3339_nano(at),
                text: format!(
                    "[jarvis] {} {} lines not sent: the router didn't take them in time",
                    *dropped, self.source
                ),
            };
            b += &format!("{}\n", gojson::marshal(&l));
        }
        let l = LogLine {
            at: rfc3339_nano(at),
            text: text.to_string(),
        };
        b += &format!("{}\n", gojson::marshal(&l));
        // the directory isn't there yet (the keeper's first lines): the journal has them
        let Ok(mut f) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&p)
        else {
            return;
        };
        if privileged() {
            let s = session();
            let _ = std::os::unix::fs::fchown(&f, Some(s.uid), Some(s.gid));
        }
        if f.write_all(b.as_bytes()).is_ok() {
            *dropped = 0;
        }
    }

    /// what is new in the file, pushed; rotated once all of it is pushed and it is big (as push_log_once)
    pub fn push_once(&self, c: &Client) -> Result<()> {
        let p = (self.path)();
        let mut extra = serde_json::Map::new();
        extra.insert("source".into(), self.source.into());
        let mut off = read_offset_of(&self.sent_path());
        let r = push_lines_from(c, &p, off, "/m/machine-output", &extra);
        off += r.as_ref().map(|n| *n).unwrap_or_else(|(n, _)| *n);
        let _ = util::write_file(&self.sent_path(), off.to_string().as_bytes(), 0o600);
        if let Err((_, e)) = r {
            return Err(e);
        }
        if let Ok(md) = std::fs::metadata(&p)
            && md.len() >= SUPERVISOR_LOG_ROLL
            && off >= md.len()
        {
            let old = PathBuf::from(format!("{}.old", p.display()));
            if std::fs::rename(&p, &old).is_ok() {
                util::sleep(Duration::from_millis(50));
                let _ = push_lines_from(c, &old, off, "/m/machine-output", &extra);
                let _ = std::fs::remove_file(&old);
                let _ = util::write_file(&self.sent_path(), b"0", 0o600);
            }
        }
        Ok(())
    }
}

fn read_offset_of(p: &Path) -> u64 {
    crate::crypto::read_trim(p)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

static PUSH_OUTPUTS_MU: Mutex<()> = Mutex::new(());

/// both files, now (the loop's round, and the teardown's last)
pub fn push_outputs_once(c: &Client) {
    if !on_aws() {
        return;
    }
    let _g = PUSH_OUTPUTS_MU.lock().unwrap_or_else(|e| e.into_inner());
    let _ = OUTPUT_SHIP.push_once(c);
    let _ = JOURNAL_SHIP.push_once(c);
}

/// supervisor-core's push loop for an AWS machine's output and host journal
pub fn push_outputs(c: &Client) {
    loop {
        push_outputs_once(c);
        util::sleep(OUTPUT_PUSH_EVERY);
    }
}

// ---- the keeper's tee --------------------------------------------------------------------------------------------

/// fd 1 and 2 of the keeper become a pipe; each line goes on to the original stdout and into output.log. Children
/// started after this inherit the pipe. A write to the original that fails is dropped; the file still takes the line.
pub fn tee_output() -> Result<()> {
    let _ = *KEEPER_STARTED;
    let (r, w) = std::io::pipe()?;
    let orig = nix::unistd::dup(std::io::stdout())?;
    nix::fcntl::fcntl(
        &orig,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )?;
    nix::unistd::dup2_stdout(&w)?;
    nix::unistd::dup2_stderr(&w)?;
    drop(w);
    let out = Arc::new(Mutex::new(std::fs::File::from(orig)));
    {
        // a panic's message goes straight to the journal too: the tee dies with this process
        let out = out.clone();
        std::panic::set_hook(Box::new(move |info| {
            if let Ok(mut o) = out.lock() {
                let _ = writeln!(o, "{info}");
            }
        }));
    }
    std::thread::spawn(move || tee_lines(r, &out, &OUTPUT_SHIP));
    Ok(())
}

/// each line of r to out and into f (a line longer than 16 KB is cut into pieces)
fn tee_lines(r: std::io::PipeReader, out: &Mutex<std::fs::File>, f: &ShipFile) {
    let mut br = BufReader::with_capacity(16 << 10, r);
    loop {
        let buf = match br.fill_buf() {
            Ok([]) | Err(_) => return,
            Ok(b) => b,
        };
        let (n, line) = match buf.iter().position(|c| *c == b'\n') {
            Some(i) => (i + 1, buf[..=i].to_vec()),
            None if buf.len() >= 16 << 10 => (buf.len(), buf.to_vec()),
            None => {
                // a partial line: wait for more (or the end)
                let n = buf.len();
                let mut more = buf.to_vec();
                br.consume(n);
                let mut rest = vec![];
                let _ = (&mut br)
                    .take((16 << 10) as u64)
                    .read_until(b'\n', &mut rest);
                more.extend_from_slice(&rest);
                if more.is_empty() {
                    return;
                }
                if let Ok(mut o) = out.lock() {
                    let _ = o.write_all(&more);
                }
                let t = String::from_utf8_lossy(&more)
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                if !t.is_empty() {
                    f.add(SystemTime::now(), &t);
                }
                if rest.is_empty() {
                    return;
                }
                continue;
            }
        };
        br.consume(n);
        if let Ok(mut o) = out.lock() {
            let _ = o.write_all(&line);
        }
        let t = String::from_utf8_lossy(&line)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        if !t.is_empty() {
            f.add(SystemTime::now(), &t);
        }
    }
}

use std::io::Read;

// ---- the host's journal --------------------------------------------------------------------------------------------

/// the directory with the host's journal: the kernel's bind, else the host's ROOT partition mounted read only
fn host_journal() -> Result<PathBuf> {
    if std::fs::metadata(HOST_JOURNAL_BIND).is_ok_and(|m| m.is_dir()) {
        return Ok(PathBuf::from(HOST_JOURNAL_BIND));
    }
    let dev = root_partition()?;
    std::fs::create_dir_all(host_root_mount())?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(host_root_dir(), std::fs::Permissions::from_mode(0o700));
    if !host_root_mount().join("var/log/journal").exists() {
        mount_read_only(&dev, &host_root_mount())?;
    }
    Ok(host_root_mount().join("var/log/journal"))
}

/// dev on dir, read only. The host has it mounted read-write, and the kernel refuses a read-only mount of a filesystem
/// that is mounted read-write (EBUSY), so it is mounted as the host has it and the mount itself then made read only
fn mount_read_only(dev: &str, dir: &Path) -> Result<()> {
    use nix::mount::{MntFlags, MsFlags, mount, umount2};
    let flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    let mut last = anyhow!("no filesystem tried");
    for fs in ["ext4", "btrfs", "xfs"] {
        match mount(
            Some(dev),
            dir,
            Some(fs),
            flags | MsFlags::MS_RDONLY,
            None::<&str>,
        ) {
            Ok(()) => return Ok(()),
            Err(nix::errno::Errno::EBUSY) => {
                match mount(Some(dev), dir, Some(fs), flags, None::<&str>) {
                    Ok(()) => {
                        if let Err(e) = mount(
                            None::<&str>,
                            dir,
                            None::<&str>,
                            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY | flags,
                            None::<&str>,
                        ) {
                            let _ = umount2(dir, MntFlags::MNT_DETACH);
                            bail!("making {} read only: {e}", dir.display());
                        }
                        return Ok(());
                    }
                    Err(e) => last = e.into(),
                }
            }
            Err(e) => last = e.into(),
        }
    }
    bail!("mounting {dev} read only: {last}")
}

/// the device of the partition named ROOT (Flatcar's root filesystem, where its journal is)
fn root_partition() -> Result<String> {
    for e in std::fs::read_dir("/sys/class/block")?.flatten() {
        let Ok(b) = std::fs::read_to_string(e.path().join("uevent")) else {
            continue;
        };
        let (mut name, mut devname) = ("", "");
        for l in b.lines() {
            if let Some(v) = l.strip_prefix("PARTNAME=") {
                name = v;
            }
            if let Some(v) = l.strip_prefix("DEVNAME=") {
                devname = v;
            }
        }
        if name == "ROOT" && !devname.is_empty() {
            return Ok(format!("/dev/{devname}"));
        }
    }
    bail!("no partition named ROOT")
}

/// the fields of journalctl -o json the shipper uses
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct JournalEntry {
    #[serde(rename = "__CURSOR")]
    pub cursor: String,
    /// µs
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    pub realtime: String,
    /// a string, or an array of bytes when it isn't UTF-8
    #[serde(rename = "MESSAGE")]
    pub message: Option<Box<RawValue>>,
    #[serde(rename = "_SYSTEMD_UNIT")]
    pub unit: String,
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    pub ident: String,
    #[serde(rename = "_COMM")]
    pub comm: String,
    #[serde(rename = "_TRANSPORT")]
    pub transport: String,
}

/// An entry as one shipped line ("" = left out): the kernel's (the console has them) and the session unit's docker
/// client from the keeper's start on (that is the container's output, which the output file has)
pub fn journal_line(e: &JournalEntry, since: SystemTime) -> (SystemTime, String) {
    let us: u64 = e.realtime.parse().unwrap_or(0);
    let at = SystemTime::UNIX_EPOCH + Duration::from_micros(us);
    if e.transport == "kernel" {
        return (at, String::new());
    }
    if e.unit == "jarvis4-session.service" && e.comm == "docker" && at >= since {
        return (at, String::new());
    }
    let raw = e.message.as_ref().map(|m| m.get()).unwrap_or("null");
    let msg = match serde_json::from_str::<String>(raw) {
        Ok(s) => s,
        Err(_) => {
            let bs: Vec<u8> = serde_json::from_str::<Vec<i64>>(raw)
                .map(|v| v.into_iter().map(|i| i as u8).collect())
                .unwrap_or_default();
            String::from_utf8_lossy(&bs).into_owned()
        }
    };
    let msg = msg.trim_end_matches(['\r', '\n']);
    if msg.is_empty() {
        return (at, String::new());
    }
    let mut who = if e.ident.is_empty() {
        e.comm.clone()
    } else {
        e.ident.clone()
    };
    if !e.unit.is_empty() && e.unit != "init.scope" {
        who = format!("{} {who}", e.unit);
    }
    (at, format!("{who}: {msg}"))
}

/// the keeper's reader of the host's journal from this boot's start, followed for the machine's life; a reader that
/// ends starts again after its last entry
pub fn ship_host_journal(stopping: &AtomicBool) {
    let jdir = match host_journal() {
        Ok(d) => d,
        Err(e) => {
            logf!("the host's journal: {e:#} (not sent; the router still reads the console)");
            return;
        }
    };
    logf!(
        "the host's journal: sending what {} holds of this boot",
        jdir.display()
    );
    let mut cursor = String::new();
    while !stopping.load(Ordering::SeqCst) {
        let j = jdir.to_string_lossy().into_owned();
        let mut args = vec![
            "-D".to_string(),
            j,
            "-b".into(),
            "-f".into(),
            "--no-tail".into(),
            "-o".into(),
            "json".into(),
            "--no-pager".into(),
            "--output-fields=MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_COMM,_TRANSPORT".into(),
        ];
        if !cursor.is_empty() {
            args.push(format!("--after-cursor={cursor}"));
        }
        let child = std::process::Command::new("journalctl")
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                logf!("the host's journal: {e}");
                return;
            }
        };
        if let Some(out) = child.stdout.take() {
            for line in BufReader::with_capacity(64 << 10, out).lines() {
                let Ok(line) = line else { break };
                let Ok(e) = serde_json::from_str::<JournalEntry>(&line) else {
                    continue;
                };
                if !e.cursor.is_empty() {
                    cursor = e.cursor.clone();
                }
                let (at, t) = journal_line(&e, *KEEPER_STARTED);
                if !t.is_empty() {
                    JOURNAL_SHIP.add(at, &t);
                }
            }
        }
        let _ = child.wait();
        util::sleep(Duration::from_secs(5));
    }
}
