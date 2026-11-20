//! The harness's own words in the supervisor log (Deyao, 2026-10-26): the harness launcher (session-entrypoint,
//! harness-*.sh) writes its steps to stdout as tagged lines ("[dsh] dsh web exited …", "[entrypoint] …"). The keeper
//! copies those lines, and only those, into the supervisor log (tag "harness"), from where they go the way every
//! supervisor line goes: through the secret redactor, to the router, shown only to Deyao's login. Anything else on the
//! harness's stdout (a program's own output, which may quote a prompt) stays on the console.

use crate::re;
use crate::supervisorlog::{FileLog, MAX_LOG_LINE};
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Mutex;
use std::time::Instant;

re!(HARNESS_LINE_TAG = r"^\[[a-z0-9-]{2,24}\] ");

/// lines at once, refilled at the rate a minute
const HARNESS_LOG_BURST: f64 = 60.0;
const HARNESS_LOG_RATE: f64 = 30.0;

/// the rate-limited sink of the harness's tagged lines
pub struct HarnessLog {
    inner: Mutex<(Box<dyn Write + Send>, f64, Instant, usize)>,
}

impl HarnessLog {
    pub fn new(out: Box<dyn Write + Send>) -> HarnessLog {
        HarnessLog {
            inner: Mutex::new((out, HARNESS_LOG_BURST, Instant::now(), 0)),
        }
    }

    /// the keeper's sink: lines tagged "harness" in the supervisor log
    pub fn supervisor() -> HarnessLog {
        HarnessLog::new(Box::new(FileLog::new("harness")))
    }

    /// tests: the last refill moved back by d
    #[cfg(test)]
    pub fn backdate(&self, d: std::time::Duration) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.2 -= d;
    }

    pub fn line(&self, s: &str) {
        if !HARNESS_LINE_TAG.is_match(s) {
            return;
        }
        let s = crate::util::clip_bytes(s, MAX_LOG_LINE);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        g.1 = HARNESS_LOG_BURST.min(g.1 + (now - g.2).as_secs_f64() / 60.0 * HARNESS_LOG_RATE);
        g.2 = now;
        if g.1 < 1.0 {
            g.3 += 1;
            return;
        }
        g.1 -= 1.0;
        if g.3 > 0 {
            let d = g.3;
            let _ = g
                .0
                .write_all(format!("({d} harness lines left out: too many at once)\n").as_bytes());
            g.3 = 0;
        }
        let _ = g.0.write_all(format!("{s}\n").as_bytes());
    }
}

/// The harness's stdout and stderr: a pipe whose lines go to the console as before and, when tagged, to sink. The write
/// end goes to the harness; the read end is drained until every holder of the write end (the harness's background loops
/// too) is gone.
pub fn harness_stdout(sink: std::sync::Arc<HarnessLog>) -> std::io::Result<std::io::PipeWriter> {
    let (r, w) = std::io::pipe()?;
    std::thread::spawn(move || {
        let mut br = BufReader::with_capacity(64 << 10, r);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match (&mut br).take(1 << 20).read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = buf.strip_suffix(b"\n").unwrap_or(&buf);
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(line);
                    let _ = out.write_all(b"\n");
                    drop(out);
                    sink.line(&String::from_utf8_lossy(line));
                }
            }
        }
        let _ = std::io::copy(&mut br, &mut std::io::stdout()); // the rest to the console only
    });
    Ok(w)
}
