// Transcript search service (Jarvis 4: k8s/services/apps/search, namespace jarvis2-services). The router forwards
// /api/search* (the app) and /m/api/search* (sessions) here; it is never exposed on its own. Hybrid keyword +
// semantic search over every session transcript of both Jarvises on the Storage Box (archives, Jarvis 1's
// .paused/ snapshots, .live/ copies of running sessions) and the task records. API: docs/API.md "Transcript search".
//
// env: SEARCH_DB (sqlite path on the PVC), STORAGEBOX_HOST/USER/PASSWORD, OPENROUTER_API,
//      INDEX_INTERVAL_S (crawl period, default 600), PORT (8090), LOCAL_ROOT (dev: a local mirror),
//      BACKUP_INTERVAL_H (copy to the Storage Box, default 24; 0 = off), MEMORY_LIMIT (bytes, from the pod's limit)
//
// Replicas (k8s/services/apps/search/search.yaml): every replica serves; one holds the writer lease (lease.js) and runs the crawl,
// the embeddings and the backup. GET /readyz is 200 once the vectors are loaded and until SIGTERM; on SIGTERM a
// replica stops answering ready, keeps serving for DRAIN_MS while the Service drops it, stops its index run, hands
// the lease back, finishes in-flight requests and exits. /status says when this copy started and why the previous
// one ended (its own run records, plus the pod's last termination from Kubernetes when it can read it).
const express = require("express");
const path = require("path");
const fs = require("fs");
const { open } = require("./db");
const source = require("./source");
const { Indexer } = require("./indexer");
const { Searcher } = require("./query");
const { EMBED_MODEL, RERANK_MODEL } = require("./embed");
const { Lease } = require("./lease");
const kube = require("./kube");

const log = (m) => console.log(`${new Date().toISOString()} ${m}`);
const DB_FILE = process.env.SEARCH_DB || path.join(process.cwd(), "search.db");
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
fs.mkdirSync(require("os").tmpdir(), { recursive: true }); // TMPDIR points into the PVC (k8s/search)
const dbcopy = require("./dbcopy");
let db, searcher, indexer, lease;
const STARTED = new Date().toISOString();
const POD = process.env.POD_NAME || require("os").hostname();
let ready = false, draining = false, writer = false, seenVersion = 0, inflight = 0;
const DRAIN_MS = +(process.env.DRAIN_MS || 5000);
const mem = { peakRss: 0 };
const mb = (b) => Math.round(b / 1048576);
function memory() {
  const m = process.memoryUsage();
  if (m.rss > mem.peakRss) mem.peakRss = m.rss;
  const limit = +process.env.MEMORY_LIMIT || null;
  return { rssMB: mb(m.rss), peakRssMB: mb(mem.peakRss), heapUsedMB: mb(m.heapUsed), arrayBuffersMB: mb(m.arrayBuffers), externalMB: mb(m.external), limitMB: limit ? mb(limit) : null, ofLimit: limit ? +(m.rss / limit).toFixed(2) : null };
}

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  inflight++; res.on("close", () => inflight--);
  if (draining) res.set("Connection", "close"); // the router's kept-alive connection moves to a replica that stays
  next();
});
const bool = (v, d) => (v == null || v === "" ? d : !/^(0|false|no|off)$/i.test(String(v)));
const KINDS = new Set(["msg", "tool", "doc"]);
const STATES = new Set(["live", "paused", "archive"]);
const DATE = /^\d{4}-\d{2}-\d{2}$/;

app.get("/search", async (req, res) => {
  const s = req.query, q = String(s.q || "").trim();
  if (!q) return res.status(400).json({ error: "q is required" });
  if (q.length > 2000) return res.status(400).json({ error: "q is too long (max 2000 chars)" });
  const kinds = String(s.kind || "").split(",").map((k) => k.trim()).filter((k) => KINDS.has(k));
  for (const k of ["after", "before"]) if (s[k] && !DATE.test(s[k])) return res.status(400).json({ error: `${k} must be YYYY-MM-DD` });
  const mode = ["hybrid", "keyword", "semantic"].includes(s.mode) ? s.mode : "hybrid";
  try {
    res.json(await searcher.search({
      q, mode, kinds, after: s.after, before: s.before, session: s.session ? String(s.session) : null, states: String(s.state || "").split(",").map((x) => x.trim()).filter((x) => STATES.has(x)), archived: bool(s.archived, false),
      limit: Math.min(Math.max(parseInt(s.limit, 10) || 10, 1), 50), rerank: bool(s.rerank, true), group: bool(s.group, false), full: bool(s.full, false),
    }));
  } catch (e) { log(`search failed: ${e.stack || e.message}`); res.status(500).json({ error: e.message }); }
});

app.get("/context", (req, res) => {
  const n = (v, d) => Math.min(Math.max(parseInt(v, 10) || d, 0), 30);
  const c = searcher.context(parseInt(req.query.id, 10), n(req.query.before, 3), n(req.query.after, 3));
  if (!c) return res.status(404).json({ error: "no such chunk" });
  res.json(c);
});

app.get("/status", async (req, res) => {
  const counts = db.prepare("SELECT (SELECT count(*) FROM chunks) chunks, (SELECT count(*) FROM sessions) sessions, (SELECT count(*) FROM files) files, (SELECT count(*) FROM emb) vectors").get();
  const kinds = Object.fromEntries(db.prepare("SELECT kind, count(*) n FROM chunks GROUP BY kind").all().map((r) => [r.kind, r.n]));
  const states = Object.fromEntries(db.prepare("SELECT source, count(*) n FROM sessions GROUP BY source").all().map((r) => [r.source, r.n]));
  const span = db.prepare("SELECT min(date) first, max(date) last FROM chunks WHERE date IS NOT NULL").get();
  const self = lease.read(`run:${POD}`) || {};
  const replica = { pod: POD, started: STARTED, role: writer ? "writer" : "reader", draining, memory: memory(), restartsInPod: self.restarts || 0, restartedAfter: self.restartedAfter || null, kubernetes: await kube.ownPod().catch((e) => ({ error: e.message })) };
  res.json({ ok: true, ...counts, kinds, sessions_by_state: states, span, vectorsLoaded: searcher.ids.length, embedModel: EMBED_MODEL, rerankModel: RERANK_MODEL,
    replica, writer: lease.current(), previousReplica: lease.previousRun(), indexVersion: lease.indexVersion(), indexer: writer ? indexer.status : (lease.read("indexer_status") || indexer.status) });
});

// the router pokes this after an archive, so a finished session is searchable at once
app.post("/reindex", (req, res) => {
  const full = bool(req.query.full, false);
  if (writer) indexer.run({ full }); else lease.requestReindex(full); // a reader leaves it for the writer's next tick
  res.status(202).json({ started: true, by: writer ? POD : "the writer", indexer: indexer.status });
});

// liveness: the process answers; readiness: vectors loaded and not stopping
app.get("/healthz", (req, res) => res.json({ ok: true }));
app.get("/readyz", (req, res) => res.status(ready && !draining ? 200 : 503).json({ ready, draining }));

// every TICK_MS: renew/take the writer lease, pick up a reindex request, reload when the writer changed the index,
// record a heartbeat with the memory reading (the last one is what /status shows after a kill)
const TICK_MS = 10000;
let beats = 0;
function tick() {
  if (draining) return;
  try {
    const was = writer;
    writer = lease.tryAcquire();
    if (writer && !was) { log(`writer lease taken (${POD})`); indexer.stopping = false; startWriter(); }
    if (!writer && was) { log("writer lease lost"); indexer.stop(); }
    if (writer) { const r = lease.takeReindex(); if (r) indexer.run({ full: !!r.full }); lease.write("indexer_status", indexer.status); }
    const v = lease.indexVersion();
    if (v !== seenVersion) { seenVersion = v; if (!writer) searcher.load(); }
    if (writer || ++beats % 3 === 0) lease.heartbeat({ memory: memory(), role: writer ? "writer" : "reader" });
  } catch (e) { log(`tick: ${e.message}`); }
}

let writerStarted = false;
function startWriter() {
  if (writerStarted || bool(process.env.NO_INDEX, false)) return;
  writerStarted = true;
  indexer.run();
  setInterval(() => { if (writer && !draining) indexer.run(); }, Math.max(60, +(process.env.INDEX_INTERVAL_S || 600)) * 1000).unref();
  if (!process.env.LOCAL_ROOT) dbcopy.backupLoop(db, path.basename(DB_FILE), process.env, log, () => writer && !draining);
}

async function shutdown(signal) {
  if (draining) return;
  draining = true;
  log(`${signal}: draining (not ready; serving ${DRAIN_MS} ms more while the Service drops this replica)`);
  await new Promise((r) => setTimeout(r, DRAIN_MS));
  // the index run stops at its next group; past 15 s exit anyway (a group is one transaction, nothing half-written)
  await Promise.race([indexer.stop(), new Promise((r) => setTimeout(r, 15000))]);
  server.close();
  const t0 = Date.now();
  while (inflight > 0 && Date.now() - t0 < 5000) await new Promise((r) => setTimeout(r, 100));
  try { if (writer) lease.release(); lease.runEnded(`${signal} (rollout, scale-down or drain)`); } catch (e) { log(`shutdown: ${e.message}`); }
  log(`${signal}: stopped cleanly${writer ? ", writer lease handed back" : ""}`);
  process.exit(0);
}

let server;
async function main() {
  // a new volume starts from the copy on the Storage Box (its embeddings are paid for), not from nothing
  if (!process.env.LOCAL_ROOT) log(`seed: ${await dbcopy.seed(DB_FILE, process.env, log)}`);
  db = open(DB_FILE);
  lease = new Lease(db, { holder: POD });
  // another replica may hold a long write transaction: retry, and never let the record stop this replica serving
  for (let i = 0; ; i++) {
    try { lease.runStarted({ started: STARTED, memory: memory() }); break; }
    catch (e) { if (i >= 60) { log(`run record not written: ${e.message}`); break; } await new Promise((r) => setTimeout(r, 500)); }
  }
  const prev = (lease.read(`run:${POD}`) || {}).restartedAfter;
  if (prev) log(`restarted in the same pod; the previous run: ${JSON.stringify(prev)}`);
  seenVersion = lease.indexVersion();
  searcher = new Searcher(db, log);
  await searcher.load();
  indexer = new Indexer(db, source.fromEnv(), log);
  indexer.onChange = () => { searcher.load(); try { lease.bumpIndexVersion(); seenVersion = lease.indexVersion(); } catch (e) { log(`index version: ${e.message}`); } };
  log(`memory after load: ${JSON.stringify(memory())}`);
  const port = +(process.env.PORT || 8090);
  server = app.listen(port, process.env.HOST || "0.0.0.0", () => {
    log(`transcript search on :${port}, db ${DB_FILE}, pod ${POD}`);
    ready = true;
    tick();
    setInterval(tick, TICK_MS).unref();
    setInterval(() => log(`memory: ${JSON.stringify(memory())}`), 300000).unref();
  });
  server.keepAliveTimeout = 65000;
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
main().catch((e) => { log(`start failed: ${e.stack || e.message}`); try { lease && lease.runEnded(`start failed: ${e.message}`); } catch { /* the db may be what failed */ } process.exit(1); });
