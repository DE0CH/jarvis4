"""The index's copy on the Storage Box (claude-records/.jarvis4-services/<name>.gz).

The index is expensive to rebuild (weeks of reading iCloud and the AI budget, whose ledger `ai_spent` lives in
it), so:
  seed(db_file)   before the database is opened: a missing database is restored from the copy. With
                  SEED_REQUIRED=1 (the default in k8s) a missing copy is an error, not a fresh start: a fresh
                  index would forget what the budget already paid for and spend it again.
  backup(db_file) SQLite's online backup -> gzip -> age -> PUT <name>.gz.age.part -> MOVE <name>.gz.age; every
                  BACKUP_INTERVAL_H hours (backup_loop).
The index is identity-level (Deyao, 2026-10-13: as private as the iCloud login), and the Storage Box is readable by
more than this pod, so the copy is age-encrypted: `<name>.gz.age`, to BACKUP_AGE_RECIPIENT (public, in the manifest),
opened with BACKUP_AGE_KEY (the private key, only in this pod's SOPS part). A plain `<name>.gz` (the one-time import
from Jarvis 1) is read only with SEED_PLAIN_OK=1, and the first backup deletes it.
env: STORAGEBOX_HOST/USER/PASSWORD (STORAGEBOX_SCHEME for tests), SEED_NAME (default: the db file's name),
     BACKUP_AGE_RECIPIENT, BACKUP_AGE_KEY, SEED_PLAIN_OK."""
import base64, gzip, os, shutil, sqlite3, subprocess, tempfile, threading, time, urllib.error, urllib.parse, urllib.request

DIR = "claude-records/.jarvis4-services"


class NoSeed(Exception):
    pass


def _dav(env):
    h, u, p = env.get("STORAGEBOX_HOST"), env.get("STORAGEBOX_USER"), env.get("STORAGEBOX_PASSWORD")
    if not (h and u and p):
        return None
    auth = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
    base = f"{env.get('STORAGEBOX_SCHEME', 'https')}://{h}/"
    return auth, lambda path: base + urllib.parse.quote(path)


def _get(url, auth):
    """-> the open response, or None on 404"""
    try:
        return urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": auth}), timeout=3600)
    except urllib.error.HTTPError as e:
        if e.code == 404: return None
        raise


def seed(db_file, env=os.environ, log=print):
    """Two replicas start on one volume: a file lock next to the database lets one seed while the other waits, then
    finds the database there."""
    if os.path.exists(db_file):
        return "exists"
    import fcntl
    with open(db_file + ".seed.lock", "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            return _seed(db_file, env, log)
        finally:
            fcntl.flock(lk, fcntl.LOCK_UN)


def _seed(db_file, env, log):
    if os.path.exists(db_file):
        return "exists"
    required = env.get("SEED_REQUIRED", "") in ("1", "true")
    d = _dav(env)
    if not d:
        if required: raise NoSeed("SEED_REQUIRED and no Storage Box credentials")
        return "none"
    auth, url = d
    name = env.get("SEED_NAME") or os.path.basename(db_file)
    tmp = db_file + ".seed"
    r = _get(url(f"{DIR}/{name}.gz.age"), auth)
    if r is not None:
        key = env.get("BACKUP_AGE_KEY")
        if not key: raise NoSeed(f"{name}.gz.age is there but BACKUP_AGE_KEY isn't set")
        work = tempfile.mkdtemp(prefix="seed-")
        try:
            kf = os.path.join(work, "key"); fd = os.open(kf, os.O_WRONLY | os.O_CREAT, 0o600)
            with os.fdopen(fd, "w") as f: f.write(key.strip() + "\n")
            p = subprocess.Popen(["age", "-d", "-i", kf], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            def feed():
                with r: shutil.copyfileobj(r, p.stdin, 1 << 22)
                p.stdin.close()
            t = threading.Thread(target=feed, daemon=True); t.start()
            with gzip.GzipFile(fileobj=p.stdout) as g, open(tmp, "wb") as f:
                shutil.copyfileobj(g, f, 1 << 22)
            t.join(); p.wait()
            if p.returncode != 0: raise RuntimeError(f"age -d failed ({p.returncode})")
        finally:
            shutil.rmtree(work, ignore_errors=True)
    elif env.get("SEED_PLAIN_OK", "") in ("1", "true") and (r := _get(url(f"{DIR}/{name}.gz"), auth)) is not None:
        with r, gzip.GzipFile(fileobj=r) as g, open(tmp, "wb") as f:
            shutil.copyfileobj(g, f, 1 << 22)
    else:
        if required: raise NoSeed(f"SEED_REQUIRED and no {DIR}/{name}.gz.age on the Storage Box")
        return "none"
    os.replace(tmp, db_file)
    log(f"seeded {db_file} from the Storage Box ({os.path.getsize(db_file)} bytes)")
    return "seeded"


def backup(db_file, env=os.environ, log=print):
    d = _dav(env)
    if not d:
        return False
    auth, url = d
    name = env.get("SEED_NAME") or os.path.basename(db_file)
    work = tempfile.mkdtemp(prefix="backup-")
    rcpt = env.get("BACKUP_AGE_RECIPIENT")
    if not rcpt:
        log("backup: no BACKUP_AGE_RECIPIENT, nothing written"); return False
    raw, gz = os.path.join(work, name), os.path.join(work, name + ".gz.age")
    try:
        src, dst = sqlite3.connect(db_file, timeout=120), sqlite3.connect(raw)
        src.backup(dst); src.close(); dst.close()
        with open(gz, "wb") as out:
            p = subprocess.Popen(["age", "-r", rcpt], stdin=subprocess.PIPE, stdout=out)
            with open(raw, "rb") as f, gzip.GzipFile(fileobj=p.stdin, mode="wb", compresslevel=3) as g:
                shutil.copyfileobj(f, g, 1 << 22)
            p.stdin.close(); p.wait()
            if p.returncode != 0: raise RuntimeError(f"age -r failed ({p.returncode})")
        os.remove(raw)
        size = os.path.getsize(gz)
        with open(gz, "rb") as f:
            urllib.request.urlopen(urllib.request.Request(url(f"{DIR}/{name}.gz.age.part"), method="PUT", data=f,
                                   headers={"Authorization": auth, "Content-Length": str(size)}), timeout=3600).read()
        urllib.request.urlopen(urllib.request.Request(url(f"{DIR}/{name}.gz.age.part"), method="MOVE",
                               headers={"Authorization": auth, "Destination": url(f"{DIR}/{name}.gz.age"), "Overwrite": "T"}), timeout=600).read()
        try:  # the plain import copy, if it is still there, goes once an encrypted one exists
            urllib.request.urlopen(urllib.request.Request(url(f"{DIR}/{name}.gz"), method="DELETE", headers={"Authorization": auth}), timeout=120).read()
        except urllib.error.HTTPError as e:
            if e.code != 404: raise
        log(f"backup: {name}.gz.age ({size} bytes) on the Storage Box")
        return True
    finally:
        shutil.rmtree(work, ignore_errors=True)


def backup_loop(db_file, env=os.environ, log=print, writer=lambda: True):
    """Every BACKUP_INTERVAL_H hours while this replica is the writer (writer()); a reader never backs up. The last
    backup's time is kv 'last_backup' in the database, so a new writer keeps the rhythm instead of starting over."""
    h = float(env.get("BACKUP_INTERVAL_H", "24") or 0)
    if h <= 0 or not _dav(env):
        return

    def last(conn):
        try: return float(conn.execute("SELECT v FROM kv WHERE k='last_backup'").fetchone()[0])
        except Exception: return 0.0

    def run():
        time.sleep(600)
        conn = sqlite3.connect(db_file, timeout=120, isolation_level=None)
        while True:
            if writer() and time.time() - last(conn) >= h * 3600:
                try:
                    if backup(db_file, env, log) and writer():
                        conn.execute("INSERT INTO kv(k,v) VALUES('last_backup',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(time.time()),))
                except Exception as e: log(f"backup failed: {type(e).__name__}: {e}")
            time.sleep(300)
    threading.Thread(target=run, daemon=True, name="backup").start()
