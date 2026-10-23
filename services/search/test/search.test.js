// Transcript search: extraction, indexing (incl. the copies of one conversation that appear and
// disappear as a session goes live -> paused -> archived -> restored) and the keyword leg —
// against a local mirror, no network (embeddings need OPENROUTER_API; without it the index run
// reports the failure and the keyword index still works, which is what is asserted here).
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { extractTranscript, extractDoc, stripInjected } = require("../lib/extract");
const { open } = require("../lib/db");
const { local } = require("../lib/source");
const { Indexer, classify } = require("../lib/indexer");
const { Searcher, parseQuery } = require("../lib/query");

const SID = "11111111-2222-3333-4444-555555555555";
let n = 0;
const entry = (type, content, extra = {}) => JSON.stringify({ type, uuid: `u-${extra.u || ++n}`, sessionId: SID, timestamp: "2026-09-01T10:00:00Z", message: { role: type, content }, ...extra });
const convo = (more = []) => [
  JSON.stringify({ type: "ai-title", aiTitle: "Train tickets", sessionId: SID }),
  entry("user", "帮我买一张去北京的火车票 <system-reminder>ignore me</system-reminder>", { u: 1 }),
  entry("assistant", [{ type: "thinking", thinking: "need the 12306 API" }, { type: "text", text: "I will query 12306 for tickets." }, { type: "tool_use", id: "t1", name: "Bash", input: { command: "curl https://kyfw.12306.cn/otn/leftTicket/query", description: "Query tickets" } }], { u: 2 }),
  entry("user", [{ type: "tool_result", tool_use_id: "t1", content: [{ type: "text", text: "HTTP 200 " + "A".repeat(500) + " PREPAY_RECAPTCHA_FAILED" }, { type: "image", source: {} }] }], { u: 3 }),
  ...more,
].join("\n") + "\n";

function mirror(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ts-test-"));
  for (const [p, body] of Object.entries(files)) { const f = path.join(root, "claude-records", p); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, body); }
  return root;
}
const quiet = () => {};

test("extract: two streams, injected text and blobs dropped, relay transcripts flagged", async () => {
  const root = mirror({ "a/t.jsonl": convo(), "a/relay.jsonl": entry("user", "You are a delivery relay. Do exactly this") + "\n" });
  const r = await extractTranscript(path.join(root, "claude-records/a/t.jsonl"));
  assert.equal(r.meta.title, "Train tickets");
  const msg = r.chunks.filter((c) => c.kind === "msg").map((c) => c.text).join("\n"), tool = r.chunks.filter((c) => c.kind === "tool").map((c) => c.text).join("\n");
  assert.match(msg, /\[Deyao\] 帮我买一张去北京的火车票/); assert.doesNotMatch(msg, /ignore me/);
  assert.match(msg, /\[Claude \(thinking\)\] need the 12306 API/);
  assert.match(tool, /\[Bash\] # Query tickets\n\$ curl/); assert.match(tool, /\[→ Bash\] HTTP 200 \[blob\] PREPAY_RECAPTCHA_FAILED\n\[image\]/);
  assert.equal((await extractTranscript(path.join(root, "claude-records/a/relay.jsonl"))).meta.relay, true);
  assert.equal(stripInjected("<system-reminder>x</system-reminder>"), "");
  assert.equal(extractDoc("r.html", "<h1>Report</h1><script>x()</script><p>Body &amp; more</p>")[0].text, "[r.html] Report\n\n[r.html] Body & more");
});

test("classify: what is indexed and as what", () => {
  assert.deepEqual(classify(`claude-records/2026-09-01 X/transcript-${SID}.jsonl`), { type: "transcript", grp: SID, sid: SID, source: "archive", dir: "claude-records/2026-09-01 X", machineId: null });
  assert.equal(classify(`claude-records/.paused/m1/${SID}.jsonl`).source, "paused");
  assert.equal(classify(`claude-records/.live/m1/${SID}.jsonl`).source, "live");
  assert.equal(classify("claude-records/.paused/m1/workspace.tar.gz"), null);
  assert.equal(classify("claude-records/2026-09-01 X/artifacts/record.md").type, "doc");
  assert.equal(classify("claude-records/2026-09-01 X/artifacts/shot.png"), null);
});

test("parseQuery: phrases must match, identifiers and CJK become phrases", () => {
  const q = parseQuery('LOBSTER_TOKEN 车票 "exact words"');
  assert.deepEqual(q.phrases, ['"exact words"']);
  assert.deepEqual(q.words, ['"lobster token"', '"车 票"']);
});

test("index: copies of one conversation never double up, and survive going live -> archived", async () => {
  const live = `.live/m1/${SID}.jsonl`, arch = `2026-09-01 Train tickets/transcript-${SID}.jsonl`;
  const root = mirror({ [live]: convo(), "2026-09-01 Train tickets/artifacts/record.md": "# Record\n\nBooked the G123 to Beijing." });
  const db = open(":memory:"), ix = new Indexer(db, local(root), quiet), s = new Searcher(db, quiet);
  delete process.env.OPENROUTER_API;
  await ix.run();
  const count = () => db.prepare("SELECT count(*) n FROM chunks WHERE kind != 'doc'").get().n;
  const before = count();
  assert.ok(before >= 2);
  assert.equal(db.prepare("SELECT source FROM sessions WHERE sid = ?").get(SID).source, "live");
  const kw = (q, extra) => s.search({ q, mode: "keyword", ...extra });
  assert.equal((await kw("火车票")).hits[0].title, "Train tickets");      // 3-char CJK
  assert.equal((await kw("车票")).hits.length, 1);                        // 2-char CJK (no trigram index could)
  assert.equal((await kw("ticket")).hits.length >= 1, true);              // stemming: tickets
  assert.equal((await kw("PREPAY_RECAPTCHA_FAILED", { kinds: ["tool"] })).hits[0].kind, "tool");
  assert.equal((await kw("G123 Beijing", { kinds: ["doc"] })).hits[0].kind, "doc");
  assert.equal((await kw("ticket", { after: "2027-01-01" })).hits.length, 0);

  // the session is destroyed: the archive appears (with two more turns), the live copy goes
  fs.mkdirSync(path.join(root, "claude-records", path.dirname(arch)), { recursive: true });
  fs.writeFileSync(path.join(root, "claude-records", arch), convo([entry("user", "now book the return leg", { u: 4 }), entry("assistant", "Return leg booked.", { u: 5 })]));
  fs.rmSync(path.join(root, "claude-records/.live"), { recursive: true });
  await ix.run();
  assert.equal(db.prepare("SELECT source, dir FROM sessions WHERE sid = ?").get(SID).source, "archive");
  assert.equal((await kw("return leg")).hits.length, 1);
  assert.equal((await kw("火车票")).hits.length, 1, "the shared history is indexed once");

  // restored and archived AGAIN under a new dir, same uuid, longer: still once
  const again = `2026-09-02 Train tickets/transcript-${SID}.jsonl`;
  fs.mkdirSync(path.join(root, "claude-records", path.dirname(again)), { recursive: true });
  fs.writeFileSync(path.join(root, "claude-records", again), convo([entry("user", "now book the return leg", { u: 4 }), entry("assistant", "Return leg booked.", { u: 5 }), entry("user", "and a hotel near the station", { u: 6 })]));
  await ix.run();
  assert.equal((await kw("火车票")).hits.length, 1);
  assert.equal((await kw("hotel station")).hits.length, 1);
  const ctx = s.context((await kw("hotel station")).hits[0].id, 5, 5);
  assert.ok(ctx.chunks.some((c) => c.hit) && ctx.chunks.length >= 2);

  // nothing changed -> nothing re-indexed
  await ix.run();
  assert.equal(ix.status.lastRun.reindexed, 0);
});

test("filters: state = the session's current state; archived = text read from an archive", async () => {
  // destroyed, then restored and running again: its archive and its live copy share the uuid
  const arch = `2026-09-01 Train tickets/transcript-${SID}.jsonl`, live = `.live/m2/${SID}.jsonl`;
  const root = mirror({ [arch]: convo(), [live]: convo([entry("user", "now book the return leg", { u: 4 })]) });
  const db = open(":memory:"), ix = new Indexer(db, local(root), quiet), s = new Searcher(db, quiet);
  delete process.env.OPENROUTER_API;
  await ix.run();
  const kw = (q, extra) => s.search({ q, mode: "keyword", group: true, ...extra });
  // the running session is found by the part of its conversation first read from the archive
  const g = (await kw("火车票", { states: ["live", "paused"] })).sessions;
  assert.equal(g.length, 1);
  assert.equal(g[0].machineId, "m2");
  assert.equal((await kw("火车票", { states: ["archive"] })).sessions.length, 0);
  // the Previous tab: the archived part only, keyed by the archive dir
  assert.equal((await kw("火车票", { archived: true })).sessions[0].dir, "claude-records/2026-09-01 Train tickets");
  assert.equal((await kw("return leg", { archived: true })).sessions.length, 0);
  assert.equal((await kw("return leg", { states: ["live"] })).sessions.length, 1);
});

// Jarvis 4's archives: one .tar.gz each in claude-records/.jarvis4-records/ (the router's archivetar.go); members are
// indexed as <archive>/<name> with the archive as their dir, read once per change and never past jarvis2/
test("index: a Jarvis 4 .tar.gz archive", async () => {
  const { execFileSync } = require("child_process");
  const { walk } = require("../lib/tar");
  const root = mirror({});
  const src = fs.mkdtempSync(path.join(os.tmpdir(), "ts-arch-"));
  const longDir = "artifacts/" + "deep-folder-name/".repeat(8); // > 100 chars: a PAX path record
  const put = (p, body) => { fs.mkdirSync(path.join(src, path.dirname(p)), { recursive: true }); fs.writeFileSync(path.join(src, p), body); };
  put("session.json", JSON.stringify({ id: "s1", title: "Ferry booking", environment: "default" }));
  put(`transcript-${SID}.jsonl`, convo());
  put(longDir + "record.md", "# Record\n\nBooked the Shekou ferry at 09:15.");
  put("jarvis2/snapshot.tar.gz", "never read");
  const name = "2026-10-22 Ferry booking.tar.gz", rel = `.jarvis4-records/${name}`, file = path.join(root, "claude-records", rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  execFileSync("tar", ["--format=pax", "-czf", file, "-C", src, "session.json", `transcript-${SID}.jsonl`, "artifacts", "jarvis2"]);
  fs.writeFileSync(path.join(root, "claude-records/.jarvis4-records/index.json"), "[]");

  // the reader: every member, PAX long names whole; "stop" ends the walk
  const seen = [];
  await walk(fs.createReadStream(file), (e) => { seen.push(e.name); });
  assert.ok(seen.includes(longDir + "record.md"), seen.join(","));
  const early = [];
  await walk(fs.createReadStream(file), (e) => { early.push(e.name); if (e.name.startsWith("artifacts")) return "stop"; });
  assert.ok(!early.includes("jarvis2/snapshot.tar.gz"));

  const archive = `claude-records/${rel}`;
  assert.deepEqual(classify(archive), { type: "archive", dir: archive });
  assert.equal(classify("claude-records/.jarvis4-records/index.json"), null);
  const db = open(":memory:"), ix = new Indexer(db, local(root), quiet), s = new Searcher(db, quiet);
  delete process.env.OPENROUTER_API;
  await ix.run();
  const kw = (q, extra) => s.search({ q, mode: "keyword", ...extra });
  const hit = (await kw("火车票")).hits[0];
  assert.equal(hit.title, "Train tickets");
  assert.equal(hit.dir, archive);
  assert.equal(hit.file, `${archive}/transcript-${SID}.jsonl`);
  assert.equal((await kw("Shekou ferry", { kinds: ["doc"] })).hits[0].file, `${archive}/${longDir}record.md`);
  assert.equal((await kw("never read")).hits.length, 0);
  assert.equal(db.prepare("SELECT dir FROM sessions WHERE sid = ?").get(SID).dir, archive);

  // unchanged: nothing re-indexed, and the archive isn't read again
  await ix.run();
  assert.equal(ix.status.lastRun.reindexed, 0);
  // the archive deleted (a purge): its text goes
  fs.rmSync(file);
  await ix.run();
  assert.equal((await kw("火车票")).hits.length, 0);
  assert.equal(db.prepare("SELECT count(*) n FROM kv WHERE k LIKE 'archive:%'").get().n, 0);
});
