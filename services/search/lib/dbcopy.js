// The index's copy on the Storage Box (claude-records/.jarvis4-services/<name>.gz): the volume is seeded from it
// when it has no database yet (a new box, a lost volume, the move from Jarvis 1's box), and a fresh copy is
// written there every BACKUP_INTERVAL_H hours. The ".jarvis4-services" dir starts with a dot, so the crawl skips it.
//   seed(dbFile, env)          before the database is opened; a no-op when the file exists
//   backupLoop(db, name, env)  better-sqlite3's online backup -> gzip -> PUT <name>.gz.part -> MOVE <name>.gz
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { pipeline } = require("stream/promises");
const { Readable } = require("stream");

const DIR = "claude-records/.jarvis4-services";

function dav(env) {
  const { STORAGEBOX_HOST: host, STORAGEBOX_USER: user, STORAGEBOX_PASSWORD: pass } = env;
  if (!host || !user || !pass) return null;
  const auth = "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
  const url = (p) => `${env.STORAGEBOX_SCHEME || "https"}://${host}/` + p.split("/").map(encodeURIComponent).join("/");
  return { auth, url };
}

// -> "seeded" | "exists" | "none" (no copy on the Storage Box); throws when a copy exists but can't be read
async function seed(dbFile, env = process.env, log = console.log) {
  if (fs.existsSync(dbFile)) return "exists";
  const name = env.SEED_NAME || path.basename(dbFile);
  const d = dav(env);
  if (!d) return "none";
  const r = await fetch(d.url(`${DIR}/${name}.gz`), { headers: { Authorization: d.auth } });
  if (r.status === 404) return "none";
  if (!r.ok) throw new Error(`seed: GET ${name}.gz -> ${r.status}`);
  // replicas may seed the same new volume at once: each downloads to its own file and the first to link it wins
  const tmp = `${dbFile}.seed-${process.pid}-${require("os").hostname()}`;
  try {
    await pipeline(Readable.fromWeb(r.body), zlib.createGunzip(), fs.createWriteStream(tmp));
    try { fs.linkSync(tmp, dbFile); } catch (e) { if (e.code === "EEXIST") return "exists"; throw e; }
  } finally { fs.rmSync(tmp, { force: true }); }
  log(`seeded ${dbFile} from the Storage Box (${fs.statSync(dbFile).size} bytes)`);
  return "seeded";
}

async function backup(db, name, env = process.env, log = console.log) {
  const d = dav(env);
  if (!d) return false;
  const dir = path.join(require("os").tmpdir(), "backup");
  fs.mkdirSync(dir, { recursive: true });
  const raw = path.join(dir, name), gz = raw + ".gz";
  try {
    await db.backup(raw);
    await pipeline(fs.createReadStream(raw), zlib.createGzip({ level: 3 }), fs.createWriteStream(gz));
    fs.rmSync(raw, { force: true });
    const size = fs.statSync(gz).size;
    const put = await fetch(d.url(`${DIR}/${name}.gz.part`), { method: "PUT", headers: { Authorization: d.auth, "Content-Length": String(size) }, body: Readable.toWeb(fs.createReadStream(gz)), duplex: "half" });
    if (!put.ok) throw new Error(`PUT -> ${put.status}`);
    const mv = await fetch(d.url(`${DIR}/${name}.gz.part`), { method: "MOVE", headers: { Authorization: d.auth, Destination: d.url(`${DIR}/${name}.gz`), Overwrite: "T" } });
    if (!mv.ok) throw new Error(`MOVE -> ${mv.status}`);
    log(`backup: ${name}.gz (${size} bytes) on the Storage Box`);
    return true;
  } finally { fs.rmSync(raw, { force: true }); fs.rmSync(gz, { force: true }); }
}

// active(): only the writer backs up (lease.js); a replica that lost the lease skips its turn
function backupLoop(db, name, env = process.env, log = console.log, active = () => true) {
  const h = +(env.BACKUP_INTERVAL_H || 24);
  if (!(h > 0)) return;
  let busy = false;
  const run = () => { if (busy || !active()) return; busy = true; backup(db, name, env, log).catch((e) => log(`backup failed: ${e.message}`)).finally(() => { busy = false; }); };
  setTimeout(run, 10 * 60 * 1000).unref(); // the first one after the first crawl has settled
  setInterval(run, h * 3600 * 1000).unref();
}

module.exports = { seed, backup, backupLoop, DIR };
