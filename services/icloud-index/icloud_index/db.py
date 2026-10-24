"""The index: one SQLite file on the pod's PVC.

  files       one row per iCloud file (path, iCloud id, size, mtime) + where its extraction stands
                state: new (to extract) | done | error | wait-ai (needs the AI budget raised)
  chunks      the searchable text of a file, in parts (a PDF page, a slide, a video timestamp…)
                src: text | ocr | vision | frames | speech | members | meta
  chunks_fts  FTS5 over chunk text (contentless, rowid = chunks.id)
  names_fts   FTS5 over each file's name and folder (rowid = files.id) — every file is findable by
              name the moment it is listed, long before its content is extracted
  emb         embedding per chunk-text hash (so a rename or a duplicate costs nothing)
  aicache     AI results keyed by file content, so duplicates and re-extracts never pay twice
  kv          counters and flags (spend, last listing, notices sent)

CJK has no word boundaries: text goes into FTS with every CJK character spaced apart (cjk_space),
and a CJK query run becomes a phrase or its bigrams (search.py) — exact substring matching at
any length, the same scheme as the transcript search (DE0CH/services search/lib/db.js).
"""
import re
import sqlite3

CJK = re.compile(r"([぀-ヿ㐀-䶿一-鿿豈-﫿가-힯\U00020000-\U0002ffff])")


def cjk_space(t):
    return CJK.sub(r" \1 ", t or "")


def name_text(path):
    """What names_fts indexes for a path: the file name, and the folders above it."""
    d, _, n = path.rpartition("/")
    # split camelCase and digit runs too (IMG_2811 -> IMG 2811, HKPassport -> HK Passport)
    split = lambda s: re.sub(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])", " ", s)
    return cjk_space(n + " " + split(n)), cjk_space(d + " " + split(d))


def connect(file):
    db = sqlite3.connect(file, timeout=60, check_same_thread=False, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS files(
      id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL, fid TEXT, size INTEGER, mtime TEXT, ext TEXT,
      kind TEXT, state TEXT NOT NULL DEFAULT 'new', prio INTEGER DEFAULT 5, tries INTEGER DEFAULT 0,
      error TEXT, note TEXT, ckey TEXT, extracted_at TEXT, cost REAL DEFAULT 0, seen TEXT);
    CREATE INDEX IF NOT EXISTS files_fid ON files(fid);
    CREATE INDEX IF NOT EXISTS files_queue ON files(state, prio, mtime);
    CREATE TABLE IF NOT EXISTS chunks(
      id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL, part TEXT, src TEXT NOT NULL, text TEXT NOT NULL, hash TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS chunks_file ON chunks(file_id);
    CREATE INDEX IF NOT EXISTS chunks_hash ON chunks(hash);
    CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(text, content='', contentless_delete=1, tokenize='unicode61 remove_diacritics 2');
    CREATE VIRTUAL TABLE IF NOT EXISTS names_fts USING fts5(name, dir, content='', contentless_delete=1, tokenize='unicode61 remove_diacritics 2');
    CREATE TABLE IF NOT EXISTS emb(hash TEXT PRIMARY KEY, vec BLOB NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS aicache(ckey TEXT NOT NULL, stage TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(ckey, stage)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
    """)
    return db


def kv_get(db, k, default=None):
    r = db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


def kv_set(db, k, v):
    db.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, None if v is None else str(v)))


def kv_add(db, k, amount):
    db.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=CAST(v AS REAL)+excluded.v", (k, amount))


def index_name(db, file_id, path):
    n, d = name_text(path)
    db.execute("DELETE FROM names_fts WHERE rowid=?", (file_id,))
    db.execute("INSERT INTO names_fts(rowid, name, dir) VALUES(?,?,?)", (file_id, n, d))


def drop_chunks(db, file_id):
    ids = [r[0] for r in db.execute("SELECT id FROM chunks WHERE file_id=?", (file_id,))]
    for i in ids:
        db.execute("DELETE FROM chunks_fts WHERE rowid=?", (i,))
    db.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
    return ids


def drop_file(db, file_id):
    drop_chunks(db, file_id)
    db.execute("DELETE FROM names_fts WHERE rowid=?", (file_id,))
    db.execute("DELETE FROM files WHERE id=?", (file_id,))
