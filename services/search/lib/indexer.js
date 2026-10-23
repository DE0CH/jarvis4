// Incremental indexer: crawl claude-records/ on the Storage Box, (re)index what changed.
//
// What is indexed
//   <archive dir>/transcript-<sid>.jsonl | <sid>.jsonl   archived sessions        (source archive)
//   .paused/<machineId>/<sid>.jsonl                      pause snapshots          (source paused)
//   .live/<machineId>/<sid>.jsonl                        running sessions — synced every few
//                                                        minutes by the session image  (source live)
//   <archive dir>/**.{md,txt,html,log}                   records, reports, chat logs  (kind doc)
//   .jarvis4-records/<date> <title>.tar.gz               Jarvis 4's archives: one .tar.gz each (the router's
//                                                        archivetar.go); its transcript-*.jsonl and artifacts/** docs
//                                                        are indexed as members, <archive>/<name>, with the archive
//                                                        as their dir. The member list is cached per archive etag
//                                                        (kv), and a run reads each changed archive once, up to the
//                                                        first jarvis2/ entry (the snapshot is never read).
//
// The unit of work is a GROUP: every copy of one transcript (same <sid>: its live copy, its pause
// snapshot, the archive, and the archive made again after a Restore) — or a single doc file. When
// any member of a group is new / changed / gone, the whole group is dropped and rebuilt, oldest
// copy first, with entries deduplicated by their uuid (extract.js skipUuid). That keeps hits
// unique whatever order copies appear and disappear in; embeddings are cached by text hash, so a
// rebuild only pays for text that is actually new.
const fs = require("fs");
const path = require("path");
const { extractTranscript, extractDoc } = require("./extract");
const { cjkSpace } = require("./db");
const { pool, tmpFile, ROOT } = require("./source");
const tar = require("./tar");
const { embedDocs, vecToBlob, EMBED_MODEL } = require("./embed");

const SID_RE = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$/;
const DOC_RE = /\.(md|txt|html?|log)$/i;
const DOC_MAX = 1.5 * 1024 * 1024;
const SKIP_DIRS = [`${ROOT}/.index`, `${ROOT}/oxford-migration`];
const skipDir = (p) => SKIP_DIRS.includes(p) || /\/(node_modules|\.git)$/.test(p);
const J4 = ".jarvis4-records";
// an archive's members that are read at all: the ones before its first jarvis2/ entry (archivetar.go's order)
const memberEnd = (name) => name.startsWith("jarvis2/") || name.startsWith("discord/");

// path -> { type: transcript|doc|meta, grp, source, dir, machineId } or null (not indexed)
function classify(p) {
  const rel = p.slice(ROOT.length + 1), seg = rel.split("/");
  if (seg.length < 2) return null;
  if (seg[0] === J4) return seg.length === 2 && p.endsWith(".tar.gz") ? { type: "archive", dir: p } : null;
  const special = seg[0] === ".paused" ? "paused" : seg[0] === ".live" ? "live" : null;
  if (seg[0].startsWith(".") && !special) return null;
  if (special) {
    if (seg.length !== 3 || !p.endsWith(".jsonl")) return null;
    const sid = (p.match(SID_RE) || [])[1];
    return { type: "transcript", grp: sid || p, sid: sid || null, source: special, dir: null, machineId: seg[1] };
  }
  const dir = `${ROOT}/${seg[0]}`;
  if (seg.length === 2 && seg[1] === "session.json") return { type: "meta", dir };
  if (p.endsWith(".jsonl")) {
    const sid = (p.match(SID_RE) || [])[1];
    return { type: "transcript", grp: sid || p, sid: sid || null, source: "archive", dir, machineId: null };
  }
  if (DOC_RE.test(p)) return { type: "doc", grp: p, source: "archive", dir };
  return null;
}

// a member of a Jarvis 4 archive: <archive>/<name in it>
function classifyMember(archive, name) {
  const p = `${archive}/${name}`;
  if (name.endsWith(".jsonl")) {
    const sid = (p.match(SID_RE) || [])[1];
    return { type: "transcript", grp: sid || p, sid: sid || null, source: "archive", dir: archive, machineId: null };
  }
  if (DOC_RE.test(name)) return { type: "doc", grp: p, source: "archive", dir: archive };
  return null;
}

const dirTitle = (dir) => (dir ? path.basename(dir).replace(/\.tar\.gz$/, "").replace(/^\d{4}-\d{2}-\d{2} /, "") : null);
const dirDate = (dir) => (dir && (path.basename(dir).match(/^\d{4}-\d{2}-\d{2}/) || [])[0]) || null;
const SOURCE_ORDER = { archive: 0, paused: 1, live: 2 };

class Indexer {
  constructor(db, source, log = console.log) {
    this.db = db; this.source = source; this.log = log;
    this.running = null; this.again = false; this.stopping = false;
    this.status = { state: "idle", lastRun: null, lastError: null, billing: false };
    const d = db;
    this.q = {
      files: d.prepare("SELECT path, etag, size, grp FROM files"),
      uuidGrp: d.prepare("SELECT grp FROM uuids WHERE uuid = ?"),
      delFts: d.prepare("DELETE FROM chunks_fts WHERE rowid IN (SELECT id FROM chunks WHERE grp = ?)"),
      delChunks: d.prepare("DELETE FROM chunks WHERE grp = ?"),
      delUuids: d.prepare("DELETE FROM uuids WHERE grp = ?"),
      delFiles: d.prepare("DELETE FROM files WHERE grp = ?"),
      delSession: d.prepare("DELETE FROM sessions WHERE sid = ?"),
      insChunk: d.prepare("INSERT INTO chunks(file, grp, sid, dir, title, source, kind, date, ts, line_from, line_to, text, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"),
      insFts: d.prepare("INSERT INTO chunks_fts(rowid, text, title) VALUES (?,?,?)"),
      insUuid: d.prepare("INSERT OR IGNORE INTO uuids(uuid, grp) VALUES (?,?)"),
      insFile: d.prepare("INSERT OR REPLACE INTO files(path, etag, size, grp, indexed_at, chunks, note) VALUES (?,?,?,?,?,?,?)"),
      insSession: d.prepare("INSERT OR REPLACE INTO sessions(sid, title, dir, source, machine_id, date, first_ts, last_ts, cwd, model, meta) VALUES (?,?,?,?,?,?,?,?,?,?,?)"),
      missing: d.prepare("SELECT c.hash, c.title, c.text FROM chunks c LEFT JOIN emb e ON e.hash = c.hash AND e.model = ? WHERE e.hash IS NULL GROUP BY c.hash"),
      insEmb: d.prepare("INSERT OR REPLACE INTO emb(hash, model, vec) VALUES (?,?,?)"),
    };
  }

  // one run at a time; a request that arrives mid-run queues exactly one more
  run(opts = {}) {
    if (this.stopping) return Promise.resolve();
    if (this.running) { this.again = true; return this.running; }
    this.running = this._run(opts).catch((e) => { this.status.lastError = e.message; this.status.billing = !!e.billing; this.log(`index run failed: ${e.stack || e.message}`); })
      .finally(() => { this.running = null; this.status.state = "idle"; if (this.again && !this.stopping) { this.again = false; this.run(); } });
    return this.running;
  }

  async _run({ full = false } = {}) {
    const t0 = Date.now(); this.status.state = "crawling";
    const dirMeta = new Map();
    this.extracted = new Map(); this.extractDir = null;
    try { await this._crawl(full, dirMeta, t0); } finally { if (this.extractDir) fs.rmSync(this.extractDir, { recursive: true, force: true }); this.extracted = null; this.extractDir = null; }
  }

  // an archive's members ({ name, size } up to the first jarvis2/ entry) and its session.json, cached by etag; a
  // changed archive is read once, its transcripts and docs kept in this run's extract dir
  async _members(f) {
    const key = `archive:${f.path}`, row = this.db.prepare("SELECT v FROM kv WHERE k = ?").get(key);
    const cached = row && JSON.parse(row.v);
    if (cached && cached.etag === f.etag) return cached;
    if (!this.extractDir) this.extractDir = fs.mkdtempSync(path.join(require("os").tmpdir(), "tsearch-x-"));
    const members = [], metaTmp = path.join(this.extractDir, `${this.extracted.size}-session.json`);
    let meta = null, sawMeta = false;
    await tar.walk(await this.source.open(f.path), (e) => {
      if (memberEnd(e.name)) return "stop";
      if (e.type !== "file") return;
      if (e.name === "session.json") { sawMeta = true; return metaTmp; }
      if (!classifyMember(f.path, e.name)) return;
      members.push({ name: e.name, size: e.size });
      const local = path.join(this.extractDir, `${this.extracted.size}-${path.basename(e.name).replace(/[^\w.-]/g, "_")}`);
      this.extracted.set(`${f.path}/${e.name}`, local);
      return local;
    });
    if (sawMeta) { try { meta = JSON.parse(fs.readFileSync(metaTmp, "utf8")); } catch { /* the title falls back to the name */ } }
    const out = { etag: f.etag, members, meta };
    this.db.prepare("INSERT OR REPLACE INTO kv(k, v) VALUES (?, ?)").run(key, JSON.stringify(out));
    return out;
  }

  // one member of an archive into dst: from this run's extract dir, else read out of the archive
  async _fetchMember(f, dst) {
    const have = this.extracted && this.extracted.get(f.path);
    if (have && fs.existsSync(have)) { fs.copyFileSync(have, dst); return; }
    let found = false;
    await tar.walk(await this.source.open(f.archive), (e) => {
      if (found || memberEnd(e.name)) return "stop";
      if (e.name === f.member && e.type === "file") { found = true; return dst; }
    });
    if (!found) throw new Error(`${f.member} is not in ${f.archive}`);
  }

  async _crawl(full, dirMeta, t0) {
    const listing = [];
    for (const f of await this.source.list(skipDir)) {
      const c = classify(f.path);
      if (!c) continue;
      if (c.type !== "archive") { listing.push({ ...f, c }); continue; }
      let m;
      try { m = await this._members(f); } catch (e) {
        this.log(`archive ${f.path}: ${e.message}`); // what it held last time stays indexed
        const row = this.db.prepare("SELECT v FROM kv WHERE k = ?").get(`archive:${f.path}`);
        if (!row) continue;
        m = JSON.parse(row.v); f.etag = m.etag;
      }
      if (m.meta) dirMeta.set(f.path, m.meta);
      for (const x of m.members) listing.push({ path: `${f.path}/${x.name}`, size: x.size, etag: f.etag, archive: f.path, member: x.name, c: classifyMember(f.path, x.name) });
    }
    for (const row of this.db.prepare("SELECT k FROM kv WHERE k LIKE 'archive:%'").all()) { // a deleted archive's cache goes
      if (!listing.some((f) => f.archive === row.k.slice(8))) this.db.prepare("DELETE FROM kv WHERE k = ?").run(row.k);
    }
    const metaFiles = listing.filter((f) => f.c.type === "meta");
    const items = listing.filter((f) => f.c.type !== "meta" && !(f.c.type === "doc" && f.size > DOC_MAX));
    const known = new Map(this.q.files.all().map((r) => [r.path, r]));
    const groups = new Map(), dirty = new Set();
    for (const f of items) { if (!groups.has(f.c.grp)) groups.set(f.c.grp, []); groups.get(f.c.grp).push(f); const k = known.get(f.path); if (full || !k || k.etag !== f.etag || k.size !== f.size) dirty.add(f.c.grp); }
    const listed = new Set(items.map((f) => f.path));
    for (const [p, k] of known) if (!listed.has(p)) dirty.add(k.grp); // a copy went away
    const gone = [...dirty].filter((g) => !groups.has(g));
    this.log(`crawl: ${items.length} files in ${groups.size} groups, ${dirty.size} to (re)index, ${gone.length} gone`);

    // archive-dir titles (session.json) are only needed for dirs being rebuilt
    const needDirs = new Set([...dirty].flatMap((g) => (groups.get(g) || []).map((f) => f.c.dir)).filter(Boolean));
    await pool(metaFiles.filter((f) => needDirs.has(f.c.dir)), 6, async (f) => {
      const tmp = tmpFile("session.json");
      try { await this.source.fetchTo(f.path, tmp); dirMeta.set(f.c.dir, JSON.parse(fs.readFileSync(tmp, "utf8"))); } catch { /* title falls back to the dir name */ }
      finally { fs.rmSync(path.dirname(tmp), { recursive: true, force: true }); }
    });

    this.status.state = "indexing";
    for (const g of gone) this.db.transaction(() => this._drop(g))();
    let done = 0;
    // oldest archive first, so that when two different transcripts share history (a `--resume`
    // that started a new file), the original keeps it
    const order = [...dirty].filter((g) => groups.has(g)).sort((a, b) => String(groups.get(a)[0].c.dir || "~").localeCompare(String(groups.get(b)[0].c.dir || "~")));
    for (const g of order) {
      if (this.stopping) { this.log(`index run stopped after ${done}/${order.length} groups (stopping)`); break; }
      try { await this._group(g, groups.get(g), dirMeta); }
      catch (e) { this.log(`group ${g}: ${e.message}`); this.status.lastError = `${g}: ${e.message}`; }
      this.status.progress = `${++done}/${order.length}`;
    }
    if (this.stopping) { if (done && this.onChange) this.onChange(); return; }
    this.status.state = "embedding";
    const embedded = await this._embed();
    this.db.exec("DELETE FROM emb WHERE hash NOT IN (SELECT hash FROM chunks)");
    const counts = this.db.prepare("SELECT (SELECT count(*) FROM chunks) chunks, (SELECT count(*) FROM sessions) sessions, (SELECT count(*) FROM files) files, (SELECT count(*) FROM emb) vectors").get();
    this.status.lastRun = { at: new Date().toISOString(), seconds: Math.round((Date.now() - t0) / 1000), reindexed: order.length, gone: gone.length, embedded, ...counts };
    if (embedded !== null) { this.status.lastError = null; this.status.billing = false; }
    delete this.status.progress;
    this.log(`index run: ${JSON.stringify(this.status.lastRun)}`);
    if ((order.length || gone.length || embedded) && this.onChange) this.onChange();
  }

  // stop at the next group / embedding batch (each is its own transaction, so the index stays consistent and the next
  // writer carries on incrementally); resolves when the current run has ended
  async stop() { this.stopping = true; this.again = false; if (this.running) await this.running; }

  _drop(grp) { this.q.delFts.run(grp); this.q.delChunks.run(grp); this.q.delUuids.run(grp); this.q.delFiles.run(grp); this.q.delSession.run(grp); }

  async _group(grp, files, dirMeta) {
    files = files.slice().sort((a, b) => SOURCE_ORDER[a.c.source] - SOURCE_ORDER[b.c.source] || a.path.localeCompare(b.path));
    const seen = new Set(), results = [];
    for (const f of files) {
      const tmp = tmpFile(path.basename(f.path));
      try {
        if (f.archive) await this._fetchMember(f, tmp); else await this.source.fetchTo(f.path, tmp);
        if (f.c.type === "doc") results.push({ f, chunks: extractDoc(path.relative(f.c.dir, f.path), fs.readFileSync(tmp, "utf8")), uuids: [], meta: null });
        else {
          const r = await extractTranscript(tmp, { skipUuid: (u) => { if (seen.has(u)) return true; const o = this.q.uuidGrp.get(u); return !!o && o.grp !== grp; } });
          r.uuids.forEach((u) => seen.add(u));
          results.push({ f, ...r });
        }
      } finally { fs.rmSync(path.dirname(tmp), { recursive: true, force: true }); }
    }
    const now = new Date().toISOString();
    this.db.transaction(() => {
      this._drop(grp);
      let session = null;
      for (const { f, chunks, uuids, meta } of results) {
        const dm = dirMeta.get(f.c.dir) || {};
        const relay = meta && meta.relay, empty = meta && !meta.entries;
        const title = (meta && meta.title) || dm.title || dirTitle(f.c.dir) || (f.c.machineId ? `session ${f.c.machineId}` : "untitled");
        const date0 = ((meta && meta.firstTs) || dirDate(f.c.dir) || "").slice(0, 10) || null;
        if (!relay) for (const c of chunks) {
          const { lastInsertRowid: id } = this.q.insChunk.run(f.path, grp, f.c.sid || null, f.c.dir, title, f.c.source, c.kind, (c.ts || "").slice(0, 10) || date0, c.ts, c.lineFrom, c.lineTo, c.text, c.hash);
          this.q.insFts.run(id, cjkSpace(c.text), cjkSpace(title));
        }
        for (const u of uuids) this.q.insUuid.run(u, grp);
        this.q.insFile.run(f.path, f.etag, f.size, grp, now, relay ? 0 : chunks.length, relay ? "relay" : empty ? "empty" : null);
        if (meta && !relay && !empty && f.c.sid) {
          // the newest copy decides where the session is NOW (live > paused > archive); the dir is
          // the latest archive it has
          session = {
            sid: f.c.sid, title, dir: f.c.dir || (session && session.dir) || null, source: f.c.source, machineId: f.c.machineId || dm.id || (session && session.machineId) || null,
            date: (session && session.date) || date0, firstTs: (session && session.firstTs) || meta.firstTs, lastTs: meta.lastTs || (session && session.lastTs), cwd: meta.cwd, model: meta.model,
            meta: JSON.stringify({ environment: dm.environment, repos: dm.repos, machineName: dm.machineName }),
          };
        }
      }
      if (session) this.q.insSession.run(session.sid, session.title, session.dir, session.source, session.machineId, session.date, session.firstTs, session.lastTs, session.cwd, session.model, session.meta);
    })();
  }

  // embeds every chunk text that has no vector yet; null = failed (the keyword index still works)
  async _embed() {
    const todo = this.q.missing.all(EMBED_MODEL);
    if (!todo.length) return 0;
    const batches = []; let cur = [], chars = 0;
    for (const t of todo) { if (cur.length >= 48 || chars > 60000) { batches.push(cur); cur = []; chars = 0; } cur.push(t); chars += t.text.length; }
    if (cur.length) batches.push(cur);
    let n = 0, failed = null;
    await pool(batches, 4, async (b) => {
      if (failed || this.stopping) return;
      try {
        const vecs = await embedDocs(b.map((t) => `Session: ${t.title}\n${t.text}`));
        this.db.transaction(() => b.forEach((t, i) => this.q.insEmb.run(t.hash, EMBED_MODEL, vecToBlob(vecs[i]))))();
        n += b.length; this.status.progress = `${n}/${todo.length} embedded`;
      } catch (e) { failed = e; }
    });
    if (failed) { this.status.lastError = `embedding: ${failed.message}`; this.status.billing = !!failed.billing; this.log(`embedding failed after ${n}/${todo.length}: ${failed.message}`); return null; }
    return n;
  }
}

module.exports = { Indexer, classify, classifyMember };
