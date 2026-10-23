// Where the transcripts come from: the Storage Box over WebDAV (production), or a local mirror
// of it (LOCAL_ROOT — development and tests). Both list { path, size, etag } under
// claude-records/, stream one file (open: Jarvis 4's .tar.gz archives) and fetch one file to a local temp path (transcripts reach 100+ MB, so they
// are streamed to disk and parsed from there, never held in memory).
const fs = require("fs");
const path = require("path");
const os = require("os");
const { pipeline } = require("stream/promises");
const { Readable } = require("stream");

const ROOT = "claude-records";
const MAX_DEPTH = 5;

async function pool(items, n, fn) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } }));
  return out;
}

function dav({ host, user, pass }) {
  const auth = "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
  const url = (p) => `https://${host}/` + p.split("/").map(encodeURIComponent).join("/");
  async function propfind(p) {
    let r, err;
    for (let i = 0; i < 3; i++) {
      try { r = await fetch(url(p) + "/", { method: "PROPFIND", headers: { Authorization: auth, Depth: "1" } }); if (r.ok) break; err = new Error(`PROPFIND ${p} -> ${r.status}`); }
      catch (e) { err = e; }
      await new Promise((s) => setTimeout(s, 1000 * (i + 1)));
    }
    if (!r || !r.ok) throw err;
    const xml = await r.text(), out = [];
    for (const m of xml.matchAll(/<D:response[^>]*>([\s\S]*?)<\/D:response>/g)) {
      const href = decodeURIComponent((m[1].match(/<D:href>([^<]+)/) || [])[1] || "").replace(/^\//, "");
      const size = (m[1].match(/getcontentlength>(\d+)/) || [])[1];
      const etag = (m[1].match(/getetag>([^<]+)/) || [])[1] || "";
      out.push({ path: href.replace(/\/$/, ""), dir: href.endsWith("/"), size: size ? +size : 0, etag: etag.replace(/&quot;/g, '"') });
    }
    return out.slice(1); // first response = the collection itself
  }
  async function walk(p, depth, skip) {
    const entries = await propfind(p), files = [], dirs = [];
    for (const e of entries) (e.dir ? dirs : files).push(e);
    const keep = dirs.filter((d) => depth < MAX_DEPTH && !skip(d.path));
    for (const sub of await pool(keep, depth === 0 ? 6 : 2, (d) => walk(d.path, depth + 1, skip))) files.push(...sub);
    return files;
  }
  return {
    list: (skip) => walk(ROOT, 0, skip),
    async fetchTo(p, dst) {
      const r = await fetch(url(p), { headers: { Authorization: auth } });
      if (!r.ok) throw new Error(`GET ${p} -> ${r.status}`);
      await pipeline(Readable.fromWeb(r.body), fs.createWriteStream(dst));
    },
    async open(p) {
      const r = await fetch(url(p), { headers: { Authorization: auth } });
      if (!r.ok) throw new Error(`GET ${p} -> ${r.status}`);
      return Readable.fromWeb(r.body);
    },
  };
}

function local(root) {
  function walk(rel, depth, skip, out) {
    for (const f of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
      const p = `${rel}/${f.name}`;
      if (f.isDirectory()) { if (depth < MAX_DEPTH && !skip(p)) walk(p, depth + 1, skip, out); }
      else { const st = fs.statSync(path.join(root, p)); out.push({ path: p, size: st.size, etag: `${st.size}-${Math.floor(st.mtimeMs)}` }); }
    }
    return out;
  }
  return {
    list: async (skip) => walk(ROOT, 0, skip, []),
    async fetchTo(p, dst) { fs.copyFileSync(path.join(root, p), dst); },
    async open(p) { return fs.createReadStream(path.join(root, p)); },
  };
}

function fromEnv(env = process.env) {
  if (env.LOCAL_ROOT) return local(env.LOCAL_ROOT);
  const { STORAGEBOX_HOST: host, STORAGEBOX_USER: user, STORAGEBOX_PASSWORD: pass } = env;
  if (!host || !user || !pass) throw new Error("STORAGEBOX_HOST/USER/PASSWORD are not set");
  return dav({ host, user, pass });
}

const tmpFile = (name) => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "tsearch-")), name.replace(/[^\w.-]/g, "_"));

module.exports = { fromEnv, dav, local, pool, tmpFile, ROOT };
