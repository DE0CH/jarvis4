"""Who writes: the writer lease, in the index database itself (the Python twin of DE0CH/services search/lib/lease.js).

Two replicas share ONE SQLite file on the volume (both pods on the box's one node; WAL). Both serve searches; exactly
one, the WRITER, lists iCloud, reads files, spends the AI budget, embeds and backs up. The lease is a kv row
('writer' = {holder, since, until}), taken and renewed inside BEGIN IMMEDIATE every tick:
  - a replica that stops cleanly (SIGTERM: a rollout, a drain) stops its indexer and releases the lease, so the
    other takes it within one tick;
  - a replica that died (OOM kill, crash) stops renewing, and the lease lapses after TTL_S.
The writer bumps kv 'index_version' whenever embeddings changed; readers reload their vectors when it moves.
POST /relist and /retry on a reader leave a request (kv 'relist_at', 'retry_at') for the writer's next tick.
kv 'run:<pod>' keeps each replica's start, last heartbeat and how it ended, so /status can say why the previous copy
went away even when the kill left it no time to say so.
"""
import functools, json, os, socket, threading, time
from datetime import datetime, timezone

from . import db as D

TTL_S = 45.0


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def parse(s):
    try:
        return datetime.strptime(s.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except Exception:
        try: return datetime.strptime(s.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z").timestamp()
        except Exception: return 0.0


def locked(fn):
    """One connection, several threads (the tick, request threads): one lease operation at a time on it."""
    @functools.wraps(fn)
    def w(self, *a, **k):
        with self.mu:
            return fn(self, *a, **k)
    return w


class Lease:
    def __init__(self, conn, holder=None, ttl=TTL_S, now=time.time):
        self.db, self.holder, self.ttl, self.now = conn, holder or os.environ.get("POD_NAME") or socket.gethostname(), ttl, now
        self.mu = threading.RLock()

    @locked
    def read(self, k):
        v = D.kv_get(self.db, k)
        if v is None: return None
        try: return json.loads(v)
        except Exception: return v

    @locked
    def write(self, k, v):
        D.kv_set(self.db, k, json.dumps(v))

    @locked
    def _tx(self, fn):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            r = fn()
            self.db.execute("COMMIT")
            return r
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    @locked
    def current(self):
        return self.read("writer")

    @locked
    def held(self):
        cur = self.current()
        return bool(cur and cur.get("holder") == self.holder and cur.get("until", 0) > self.now())

    @locked
    def try_acquire(self):
        """Takes or renews the lease; True when this replica is the writer afterwards."""
        # a plain read first (WAL: no lock), so a reader never queues behind the writer's transactions just to learn
        # that the lease is still held
        peek = self.current()
        if peek and peek.get("holder") != self.holder and peek.get("until", 0) > self.now():
            return False

        def take():
            cur, t = self.current(), self.now()
            if cur and cur.get("holder") != self.holder and cur.get("until", 0) > t:
                return False
            since = cur["since"] if cur and cur.get("holder") == self.holder else iso(t)
            self.write("writer", {"holder": self.holder, "since": since, "until": t + self.ttl})
            return True
        return self._tx(take)

    @locked
    def release(self):
        def rel():
            cur = self.current()
            if cur and cur.get("holder") == self.holder:
                self.db.execute("DELETE FROM kv WHERE k='writer'")
        self._tx(rel)

    @locked
    def index_version(self):
        return int(self.read("index_version") or 0)

    @locked
    def bump_index_version(self):
        self._tx(lambda: self.write("index_version", self.index_version() + 1))

    # requests a reader leaves for the writer
    @locked
    def request(self, what):
        self.write(what + "_at", {"at": iso(self.now()), "by": self.holder})

    @locked
    def take(self, what):
        def t():
            r = self.read(what + "_at")
            if r is not None: self.db.execute("DELETE FROM kv WHERE k=?", (what + "_at",))
            return r
        return self._tx(t)

    # run records ---------------------------------------------------------------------------------------------------
    @locked
    def runs(self):
        out = []
        for (v,) in self.db.execute("SELECT v FROM kv WHERE k LIKE 'run:%'"):
            try: out.append(json.loads(v))
            except Exception: pass
        return out

    @locked
    def run_started(self, info):
        t = self.now()
        for r in self.runs():  # records older than a week, or of pods that ended cleanly a day ago, go
            seen = parse(r.get("lastSeen") or r.get("started") or "")
            if r.get("pod") != self.holder and (t - seen > 7 * 86400 or (r.get("ended") and t - seen > 86400)):
                self.db.execute("DELETE FROM kv WHERE k=?", ("run:" + r["pod"],))
        mine = self.read("run:" + self.holder)
        # the same pod again = k8s restarted this container: its previous run had no clean exit unless it recorded one
        after = None
        if mine:
            after = {"started": mine.get("started"), "lastSeen": mine.get("lastSeen"),
                     "ended": mine.get("ended") or {"how": "no clean exit: killed (OOM kill or crash)", "lastMemory": mine.get("memory")}}
        self.write("run:" + self.holder, {"pod": self.holder, **info, "lastSeen": info.get("started"),
                                          "restarts": (mine.get("restarts", 0) + 1) if mine else 0, "restartedAfter": after})

    @locked
    def heartbeat(self, **extra):
        r = self.read("run:" + self.holder) or {"pod": self.holder}
        r.update(extra); r["lastSeen"] = iso(self.now())
        self.write("run:" + self.holder, r)

    @locked
    def run_ended(self, how):
        self.heartbeat(ended={"at": iso(self.now()), "how": how})

    @locked
    def previous_run(self):
        """The latest replica other than this one that is gone: ended cleanly (how) or went silent for 2 min (killed)."""
        t = self.now()
        gone = [r for r in self.runs() if r.get("pod") != self.holder and (r.get("ended") or t - parse(r.get("lastSeen") or "") > 120)]
        if not gone: return None
        key = lambda r: parse((r.get("ended") or {}).get("at") or r.get("lastSeen") or "")
        r = max(gone, key=key)
        return {"pod": r.get("pod"), "started": r.get("started"), "lastSeen": r.get("lastSeen"),
                "ended": r.get("ended") or {"how": "no clean exit: killed (OOM kill, crash or node loss), see the logs for the reason", "lastMemory": r.get("memory")}}
