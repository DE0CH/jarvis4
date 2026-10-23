// A streaming reader for Jarvis 4's archives (.tar.gz, written by the router's archive/tar: ustar headers with PAX
// records for long names). Nothing is held in memory but the current header: a member's bytes go to a file or are
// skipped, so a multi-GB snapshot at the end of an archive costs only the time to read past it.
const fs = require("fs");
const zlib = require("zlib");

function str(b, from, len) { const s = b.subarray(from, from + len); const z = s.indexOf(0); return (z < 0 ? s : s.subarray(0, z)).toString("utf8"); }
function num(b, from, len) {
  if (b[from] & 0x80) { let n = 0; for (let i = from + 1; i < from + len; i++) n = n * 256 + b[i]; return n; } // base-256
  return parseInt(str(b, from, len).trim() || "0", 8);
}
function pax(body) {
  const out = {}; let i = 0;
  while (i < body.length) {
    const sp = body.indexOf(0x20, i); if (sp < 0) break;
    const len = parseInt(body.subarray(i, sp).toString(), 10); if (!len) break;
    const rec = body.subarray(sp + 1, i + len - 1).toString("utf8"), eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

// walk(readable, onEntry): onEntry({ name, type: "file"|"link"|"dir"|…, size, linkname }) for each member, in order;
// it returns a path to write a regular file's bytes to, "stop" to end the walk, or nothing to skip it. Resolves when
// the archive (or the walk) ends.
async function walk(readable, onEntry) {
  const gz = readable.pipe(zlib.createGunzip());
  let buf = Buffer.alloc(0), state = "header", remaining = 0, pad = 0, fd = null, meta = null, ext = {}, longName = null, stopped = false;
  const finish = () => { if (fd !== null) { fs.closeSync(fd); fd = null; } };
  try {
    for await (const chunk of gz) {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      for (;;) {
        if (state === "header") {
          if (buf.length < 512) break;
          const h = buf.subarray(0, 512); buf = buf.subarray(512);
          if (h.every((x) => x === 0)) continue; // the end blocks
          const flag = String.fromCharCode(h[156] || 48), prefix = str(h, 345, 155);
          const size = ext.size !== undefined ? +ext.size : num(h, 124, 12);
          const name = ext.path || longName || (prefix ? prefix + "/" : "") + str(h, 0, 100);
          const linkname = ext.linkpath || str(h, 157, 100);
          remaining = size; pad = (512 - (size % 512)) % 512;
          if (flag === "x" || flag === "g" || flag === "L") { meta = { flag, parts: [] }; state = "meta"; continue; }
          ext = {}; longName = null;
          const type = flag === "0" || flag === "\0" || flag === "7" ? "file" : flag === "1" ? "link" : flag === "2" ? "symlink" : flag === "5" ? "dir" : flag;
          const to = onEntry({ name, type, size, linkname });
          if (to === "stop") { stopped = true; return; }
          if (to && type === "file") fd = fs.openSync(to, "w");
          state = "body";
        }
        if (state === "meta" || state === "body") {
          const n = Math.min(remaining, buf.length);
          if (n > 0) {
            if (state === "meta") meta.parts.push(Buffer.from(buf.subarray(0, n)));
            else if (fd !== null) fs.writeSync(fd, buf, 0, n);
            buf = buf.subarray(n); remaining -= n;
          }
          if (remaining > 0) break;
          if (state === "meta") {
            const body = Buffer.concat(meta.parts);
            if (meta.flag === "x") ext = pax(body); else if (meta.flag === "L") longName = str(body, 0, body.length);
          } else finish();
          state = "pad";
        }
        if (state === "pad") {
          if (buf.length < pad) break;
          buf = buf.subarray(pad); state = "header";
        }
      }
    }
  } finally {
    finish();
    if (stopped) { gz.destroy(); readable.destroy(); }
  }
}

module.exports = { walk };
