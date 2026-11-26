"""Watch check runner (k8s/services/apps/watch/watch.yaml): runs a session's watch check script (bash) and answers its exit code and
output. The router (rust/router/src/watches.rs) is its only caller and decides everything else: when a check is due, what an
exit means, the delivery into the session.

It holds nothing: no secrets, no service account, no volume, and its NetworkPolicy lets it reach only DNS and the public
internet (not the router, the core or anything else on the box). A check gets a clean environment (PATH, HOME and
TMPDIR = a throwaway directory, LANG, WATCH_NAME), a hard timeout, capped output, and its process group is killed
when it ends; while no check runs, every other process in the container is killed too, so nothing a check starts
outlives it for long.

  POST /run {"script": "...", "name": "x", "timeout": 90}  ->  {"exit": n, "stdout": "...", "stderr": "...", "timedOut": b, "ms": n}
  GET  /healthz   the process answers (liveness)
  GET  /readyz    takes checks; 503 once SIGTERM arrived

Two replicas, rolled one at a time (k8s/services/apps/watch/watch.yaml). On SIGTERM a replica answers not-ready, keeps serving
DRAIN_S while the Service drops it, waits for the checks it is running (at most MAX_TIMEOUT), then exits.
"""
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_SCRIPT = 64 * 1024
MAX_TIMEOUT = 90
STDOUT_CAP = 16 * 1024
STDERR_CAP = 4 * 1024
PARALLEL = int(os.environ.get("WATCH_PARALLEL", "4"))

DRAIN_S = float(os.environ.get("DRAIN_S", "5"))

_slots = threading.BoundedSemaphore(PARALLEL)
_inflight = 0
_lock = threading.Lock()
_draining = threading.Event()
_active = 0  # requests being handled (a check waiting for a slot counts too)


def run_check(script, name, timeout):
    d = tempfile.mkdtemp(prefix="watch-")
    try:
        path = os.path.join(d, "check.sh")
        with open(path, "w") as f:
            f.write(script)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": d, "TMPDIR": d, "LANG": "C.UTF-8", "WATCH_NAME": name}
        t0 = time.monotonic()
        p = subprocess.Popen(["/bin/bash", path], cwd=d, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _killpg(p.pid)
            out, err = p.communicate()
        _killpg(p.pid)  # whatever it left running in its group
        code = 124 if timed_out else p.returncode
        if code is not None and code < 0:
            code = 128 - code
        return {"exit": code, "stdout": out[:STDOUT_CAP].decode("utf-8", "replace"), "stderr": err[-STDERR_CAP:].decode("utf-8", "replace"),
                "timedOut": timed_out, "ms": int((time.monotonic() - t0) * 1000)}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _killpg(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def reap_strays():
    """No check runs: every process but this one goes (a check that left its group with setsid)."""
    me = os.getpid()
    for e in os.listdir("/proc"):
        if e.isdigit() and int(e) not in (me, 1):
            try:
                os.kill(int(e), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        if _draining.is_set():
            self.send_header("Connection", "close")  # the router's kept-alive connection moves to a replica that stays
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, fmt, *a):
        pass

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        if self.path == "/readyz":
            return self._send(503 if _draining.is_set() else 200, {"ready": not _draining.is_set()})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        global _active
        with _lock:
            _active += 1
        try:
            self._post()
        finally:
            with _lock:
                _active -= 1

    def _post(self):
        global _inflight
        if self.path != "/run":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_SCRIPT + 4096:
            return self._send(413, {"error": "too large"})
        try:
            b = json.loads(self.rfile.read(n) or b"{}")
            script, name = str(b.get("script") or ""), str(b.get("name") or "")[:40]
            timeout = max(1, min(MAX_TIMEOUT, int(b.get("timeout") or MAX_TIMEOUT)))
        except Exception:
            return self._send(400, {"error": "bad JSON"})
        if not script.strip() or len(script.encode()) > MAX_SCRIPT:
            return self._send(400, {"error": "script is empty or too long"})
        if not _slots.acquire(timeout=30):
            return self._send(503, {"error": "busy"})
        try:
            with _lock:
                _inflight += 1
            res = run_check(script, name, timeout)
        finally:
            with _lock:
                _inflight -= 1
                if _inflight == 0:
                    reap_strays()
            _slots.release()
        self._send(200, res)


def drain_and_stop(server):
    """SIGTERM: not ready at once, serve DRAIN_S more, then wait for running checks and stop."""
    time.sleep(DRAIN_S)
    deadline = time.time() + MAX_TIMEOUT + 30
    while time.time() < deadline:
        with _lock:
            if _active == 0:
                break
        time.sleep(0.2)
    print(f"SIGTERM: drained ({_active} still running)", flush=True)
    server.shutdown()


def main():
    port = int(os.environ.get("PORT", "8095"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)

    def on_term(signum, frame):
        if not _draining.is_set():
            _draining.set()
            print("SIGTERM: draining", flush=True)
            threading.Thread(target=drain_and_stop, args=(server,), daemon=True).start()

    signal.signal(signal.SIGTERM, on_term)
    server.serve_forever()


if __name__ == "__main__":
    main()
