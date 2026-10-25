#!/usr/bin/env node
// The front of a `dsh` session's web UI (harness-dsh.sh): the cf-tunnel agent targets this, it forwards everything
// (HTTP and WebSocket upgrades) to dsh web on 127.0.0.1:$DSH_PORT. dsh guards its page with a per-process launch
// token; Cloudflare Access already admits only Deyao (or a paired device's service token) to
// https://<session id>-s.deyaochen.com/, so when dsh answers 401 to a page load the front redirects that request to
// the same path with ?token=<launch token> (read from ~/.dsh-run/token at that moment, as a restart changes it) and
// dsh answers with its signed cookie. Access stays the gate; the token is never served to anything Access didn't admit.
//   DSH_PORT (3080), FRONT_PORT (6770)
const http = require("http");
const net = require("net");
const fs = require("fs");
const path = require("path");

const UP = { host: "127.0.0.1", port: +(process.env.DSH_PORT || 3080) };
const PORT = +(process.env.FRONT_PORT || 6770);
const TOKEN = path.join(process.env.HOME || "/home/claude", ".dsh-run", "token");

function token() {
  try { return fs.readFileSync(TOKEN, "utf8").trim(); } catch { return ""; }
}

const server = http.createServer((req, res) => {
  const page = req.method === "GET" && /^\/(index\.html)?(\?|$)/.test(req.url) && !/[?&]token=/.test(req.url);
  const p = http.request({ ...UP, method: req.method, path: req.url, headers: req.headers }, (r) => {
    const t = token();
    if (page && r.statusCode === 401 && t) {
      r.resume();
      const u = new URL(req.url, "http://x");
      u.searchParams.set("token", t);
      res.writeHead(302, { location: u.pathname + u.search, "cache-control": "no-store" });
      return res.end();
    }
    res.writeHead(r.statusCode, r.headers);
    r.pipe(res);
  });
  p.on("error", () => { try { res.writeHead(502); res.end("dsh is starting"); } catch {} });
  req.pipe(p);
});

server.on("upgrade", (req, sock, head) => {
  const up = net.connect(UP.port, UP.host, () => {
    let h = `${req.method} ${req.url} HTTP/1.1\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) h += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
    up.write(h + "\r\n"); if (head && head.length) up.write(head);
    up.pipe(sock); sock.pipe(up);
  });
  up.on("error", () => sock.destroy()); sock.on("error", () => up.destroy());
});

server.listen(PORT, "127.0.0.1", () => console.log(`[dsh-front] 127.0.0.1:${PORT} -> dsh ${UP.host}:${UP.port}`));
