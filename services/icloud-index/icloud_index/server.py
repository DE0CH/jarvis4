"""iCloud index service: answers searches, and (on the replica holding the writer lease) runs the indexer.

Jarvis 4: the router forwards /api/icloud/* (the app) and /m/api/icloud/* (sessions) here. Never exposed on its own.
API: docs/API.md "iCloud index".
  GET  /search?q=…&limit=&kind=&ext=&under=&after=&before=&mode=hybrid|keyword|semantic&rerank=&full=
  GET  /file?path=…      one file's record and all its extracted text
  GET  /status           counts, spend, listing, the file being read now, errors; this replica, the writer, the previous replica
  POST /relist           list iCloud now (instead of waiting for the daily listing)
  POST /retry            give failed files another go
  GET  /healthz          liveness: the process answers
  GET  /ready            readiness: 200 once the database is open, 503 from SIGTERM on

Replicas (zero-downtime rollouts, lease.py): every replica serves; the one holding the writer lease lists, reads,
spends, embeds and backs up. On SIGTERM a replica answers /ready 503, keeps serving for DRAIN_MS while the Service
drops it, stops its indexer (a file half read doesn't count as a try), releases the lease, lets in-flight requests
finish and exits; the other replica takes the lease within TICK_S. A killed writer's lease lapses after 45 s.
env: INDEX_DB, WORK_DIR, RCLONE_CONFIG, ICLOUD_CONF_FILE, OPENROUTER_API, LOBSTER_TOKEN, AI_BUDGET_USD,
     LIST_INTERVAL_H, VISION_MODEL, AUDIO_MODEL, EMBED_MODEL, EMBED_DIMS, RERANK_MODEL, PORT, NO_INDEX,
     STORAGEBOX_HOST/USER/PASSWORD, SEED_REQUIRED, BACKUP_INTERVAL_H (backup.py: the copy on the Storage Box),
     POD_NAME (the lease holder's name; default the hostname), DRAIN_MS (default 6000), TICK_S (default 5)
"""
import json, os, signal, sys, threading, time, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from . import ai, backup, db as D, indexer as I, lease as L, search as S

KINDS = {"text", "pdf", "office", "iwork", "image", "raw", "audio", "video", "archive", "other"}


def log(m):
    print(f"{I.now()} {m}", flush=True)


def memory_mb():
    try:
        for line in open("/proc/self/status"):
            if line.startswith("VmRSS:"): return round(int(line.split()[1]) / 1024)
    except Exception: pass
    return None


class Replica:
    """One replica: the searcher, the lease and, while it is the writer, an indexer."""

    def __init__(self, db_file, start_indexer=True, tick_s=None, drain_ms=None, holder=None, ttl=L.TTL_S):
        self.db_file = db_file
        self.start_indexer = start_indexer
        self.tick_s = float(tick_s if tick_s is not None else os.environ.get("TICK_S", "5"))
        self.drain_ms = int(drain_ms if drain_ms is not None else os.environ.get("DRAIN_MS", "6000"))
        self.searcher = S.Searcher(db_file)
        self.lease = L.Lease(D.connect(db_file), holder=holder, ttl=ttl)
        self.lock = threading.Lock()      # the searcher's connection is shared by the request threads
        self.state_lock = threading.Lock()  # writer transitions
        self.writer = False
        self.draining = False
        self.ready = False
        self.idx = None                    # the indexer, only while this replica is the writer
        self.started = L.iso(time.time())
        self.seen_version = 0
        self.inflight = 0
        self.inflight_lock = threading.Lock()
        self.beats = 0
        self._stop_ticks = threading.Event()

    # ----------------------------------------------------------------- lease
    def fence(self):
        return self.writer and not self.draining and self.lease.held()

    def become_writer(self):
        log(f"writer lease taken ({self.lease.holder})")
        if not self.start_indexer:
            return
        self.idx = I.Indexer(self.db_file, self.searcher)
        self.idx.fence = self.fence
        self.idx.on_change = self.changed
        self.idx.start()

    def stop_writing(self, why, wait_s=10.0):
        """Stops the indexer; a file it was reading doesn't count as a crash try."""
        idx, self.idx = self.idx, None
        if not idx:
            return
        idx.stop_all()
        deadline = time.time() + wait_s
        for t in idx.threads:
            t.join(max(0.0, deadline - time.time()))
        cur = idx.status.get("current")
        if cur and cur.get("id") and any(t.is_alive() for t in idx.threads if t.name == "worker_loop"):
            # still inside a file (ffmpeg, a download): the process ends before it finishes, so give its try back now
            try:
                with self.lease.mu: self.lease.db.execute("UPDATE files SET tries=max(tries-1, 0) WHERE id=?", (cur["id"],))
            except Exception as e: log(f"stop: {e}")
        log(f"indexer stopped ({why})")

    def changed(self):
        try:
            self.lease.bump_index_version(); self.seen_version = self.lease.index_version()
        except Exception as e:
            log(f"index version: {e}")

    def tick(self):
        if self.draining:
            return
        with self.state_lock:
            if self.draining:
                return
            was = self.writer
            try:
                self.writer = self.lease.try_acquire()
            except Exception as e:
                log(f"lease: {e}")
                self.writer = False
            if self.writer and not was:
                self.become_writer()
            if was and not self.writer:
                log("writer lease lost")
                self.stop_writing("lease lost")
            if self.writer and self.idx:
                if self.lease.take("relist"): self.idx.relist_now.set()
                if self.lease.take("retry"): self.retry_now()
                try: self.lease.write("indexer_status", self.idx.status)
                except Exception: pass
            v = self.lease.index_version()
            if v != self.seen_version:
                self.seen_version = v
                self.searcher.dirty = True
            self.beats += 1
            if self.writer or self.beats % 3 == 0:
                try: self.lease.heartbeat(memory=memory_mb(), role="writer" if self.writer else "reader")
                except Exception: pass

    def tick_loop(self):
        while not self._stop_ticks.wait(self.tick_s):
            try: self.tick()
            except Exception as e: log(f"tick: {e}")

    def retry_now(self):
        with self.lease.mu: self.lease.db.execute("UPDATE files SET state='new', tries=0 WHERE state='error'")
        if self.idx: self.idx.wake.set()

    # ----------------------------------------------------------------- life
    def start(self):
        for _ in range(60):  # the other replica may hold a long write transaction: retry, never stop serving for it
            try:
                self.lease.run_started({"started": self.started, "memory": memory_mb()}); break
            except Exception as e:
                log(f"run record: {e}"); time.sleep(1)
        prev = (self.lease.read("run:" + self.lease.holder) or {}).get("restartedAfter")
        if prev: log(f"this container restarted; the previous run: {json.dumps(prev)}")
        self.seen_version = self.lease.index_version()
        self.ready = True
        self.tick()
        threading.Thread(target=self.tick_loop, daemon=True, name="lease").start()

    def shutdown(self, signame="SIGTERM"):
        if self.draining:
            return
        self.draining = True  # /ready answers 503 from now on; fence() is False, so nothing more is written
        log(f"{signame}: draining (not ready; serving {self.drain_ms} ms more while the Service drops this replica)")
        time.sleep(self.drain_ms / 1000)
        self._stop_ticks.set()
        with self.state_lock:
            was = self.writer
            self.stop_writing(signame)
            try:
                if was: self.lease.release()
                self.lease.run_ended(f"{signame} (rollout, scale-down or drain)")
            except Exception as e:
                log(f"shutdown: {e}")
            self.writer = False
        deadline = time.time() + 20
        while time.time() < deadline:
            with self.inflight_lock:
                if self.inflight == 0: break
            time.sleep(0.1)
        log(f"{signame}: stopped cleanly" + (", writer lease handed back" if was else ""))

    # ----------------------------------------------------------------- answers
    def status(self):
        db = self.searcher.db
        by = lambda col: {r[0]: r[1] for r in db.execute(f"SELECT {col}, count(*) FROM files GROUP BY {col}")}
        g = lambda k, d=None: D.kv_get(db, k, d)
        me = self.lease.read("run:" + self.lease.holder) or {}
        indexer = self.idx.status if (self.writer and self.idx) else (self.lease.read("indexer_status") or {})
        return {"ok": True, "files": db.execute("SELECT count(*) FROM files").fetchone()[0], "states": by("state"), "kinds": by("kind"),
                "chunks": db.execute("SELECT count(*) FROM chunks").fetchone()[0], "vectors": db.execute("SELECT count(*) FROM emb").fetchone()[0],
                "vectorsLoaded": len(self.searcher.hashes),
                "aiSpentUsd": round(float(g("ai_spent", 0) or 0), 4), "aiBudgetUsd": I.AI_BUDGET_USD, "embedSpentUsd": round(float(g("embed_spent", 0) or 0), 4),
                "lastListing": json.loads(g("last_list", "null") or "null"), "listError": g("list_error"),
                "models": {"vision": ai.VISION_MODEL, "audio": ai.AUDIO_MODEL, "embed": ai.EMBED_MODEL, "rerank": S.RERANK_MODEL},
                "indexer": indexer,
                "replica": {"pod": self.lease.holder, "started": self.started, "role": "writer" if self.writer else "reader", "draining": self.draining,
                            "memoryMB": memory_mb(), "restartsInPod": me.get("restarts", 0), "restartedAfter": me.get("restartedAfter")},
                "writer": self.lease.current(), "previousReplica": self.lease.previous_run(), "indexVersion": self.lease.index_version(),
                "errors": [dict(r) for r in db.execute("SELECT path, error, tries FROM files WHERE state='error' ORDER BY rowid DESC LIMIT 10")]}

    def handler(self):
        rep = self

        class H(BaseHTTPRequestHandler):
            def reply(self, code, obj):
                b = json.dumps(obj, ensure_ascii=False).encode()
                self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(b)))
                if rep.draining: self.send_header("Connection", "close")  # the router's kept-alive connection moves to a replica that stays
                self.end_headers(); self.wfile.write(b)

            def log_message(self, *a):
                pass

            def handle_one_request(self):
                with rep.inflight_lock: rep.inflight += 1
                try: super().handle_one_request()
                finally:
                    with rep.inflight_lock: rep.inflight -= 1

            def do_GET(self):
                u = urllib.parse.urlparse(self.path); q = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
                try:
                    if u.path == "/healthz": return self.reply(200, {"ok": True})
                    if u.path == "/ready": return self.reply(200 if rep.ready and not rep.draining else 503, {"ready": rep.ready, "draining": rep.draining})
                    if u.path == "/status":
                        with rep.lock: return self.reply(200, rep.status())
                    if u.path == "/file":
                        with rep.lock: r = rep.searcher.file(q.get("path", ""))
                        return self.reply(200, r) if r else self.reply(404, {"error": "no such file in the index"})
                    if u.path == "/search":
                        text = (q.get("q") or "").strip()
                        if not text: return self.reply(400, {"error": "q is required"})
                        if len(text) > 1000: return self.reply(400, {"error": "q is too long (max 1000 chars)"})
                        if q.get("kind") and not set(q["kind"].split(",")) <= KINDS: return self.reply(400, {"error": f"kind must be among {sorted(KINDS)}"})
                        b = lambda v, d: d if v in (None, "") else v.lower() not in ("0", "false", "no", "off")
                        o = {"q": text, "limit": max(1, min(int(q.get("limit") or 10), 100)), "kind": q.get("kind"), "ext": q.get("ext"), "under": q.get("under"),
                             "after": q.get("after"), "before": q.get("before"), "mode": q.get("mode") if q.get("mode") in ("hybrid", "keyword", "semantic") else "hybrid",
                             "rerank": b(q.get("rerank"), True), "full": b(q.get("full"), False)}
                        with rep.lock: return self.reply(200, rep.searcher.search(o))
                    self.reply(404, {"error": "not found"})
                except Exception as e:
                    self.reply(500, {"error": f"{type(e).__name__}: {e}"})

            def do_POST(self):
                try:
                    if self.path.startswith("/relist"):
                        if rep.writer and rep.idx: rep.idx.relist_now.set()
                        else: rep.lease.request("relist")  # the writer picks it up at its next tick
                        return self.reply(202, {"started": True})
                    if self.path.startswith("/retry"):
                        if rep.writer: rep.retry_now()
                        else: rep.lease.request("retry")
                        return self.reply(202, {"started": True})
                    self.reply(404, {"error": "not found"})
                except Exception as e:
                    self.reply(500, {"error": f"{type(e).__name__}: {e}"})
        return H


def main():
    db_file = os.environ.get("INDEX_DB", "/data/index.db")
    os.makedirs(os.path.dirname(db_file) or ".", exist_ok=True)
    for d in (os.environ.get("TMPDIR"), os.environ.get("XDG_CACHE_HOME")):  # on the volume: the root filesystem is read-only
        if d: os.makedirs(d, exist_ok=True)
    print(f"seed: {backup.seed(db_file)}", flush=True)  # a missing database starts from its copy, never from nothing
    D.connect(db_file).close()
    rep = Replica(db_file, start_indexer=os.environ.get("NO_INDEX", "") not in ("1", "true"))
    port = int(os.environ.get("PORT", "8091"))
    srv = ThreadingHTTPServer((os.environ.get("HOST", "0.0.0.0"), port), rep.handler())
    srv.daemon_threads = True

    def on_term(signum, frame):
        def go():
            rep.shutdown(signal.Signals(signum).name)
            srv.shutdown()
        threading.Thread(target=go, daemon=True).start()
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    rep.start()
    if rep.start_indexer:
        backup.backup_loop(db_file, writer=lambda: rep.writer and not rep.draining)
    log(f"icloud index on :{port}, db {db_file}, replica {rep.lease.holder}")
    srv.serve_forever()
    sys.exit(0)


if __name__ == "__main__":
    main()
