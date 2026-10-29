#!/usr/bin/env node
/**
 * Container-side tunnel agent (see tunnel.md).
 *
 * Opens an outbound WebSocket to the Cloudflare Worker (worker.js) and
 * proxies forwarded HTTP requests to the local content server.
 *
 * The container is ephemeral: everything not in the git repo must come from
 * the environment. So the credentials are read from environment variables
 * (set once in the CCR environment config, like LOBSTER_TOKEN etc.), NOT a
 * file on disk.
 *
 * Env:
 *   CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET
 *                       Access service token (REQUIRED). Minted by deploy.sh;
 *                       add both to the environment's variables.
 *   TUNNEL_ID           the tunnel id (default: the session id) -> https://<id>-s.deyaochen.com/
 *   TUNNEL_WORKER_URL   default wss://tunnel.deyaochen.com/__agent/<id>
 *   TUNNEL_TARGET       local origin to proxy to (default http://127.0.0.1:8899); tcp://HOST:PORT
 *                       carries each tunnelled WebSocket as a TCP connection to HOST:PORT instead
 *                       (binary frames = bytes: the session's sshd behind <id>-ssh.deyaochen.com)
 *   TUNNEL_AGENT_SECRET optional; only needed if the Worker was deployed with
 *                       an AGENT_SECRET (defense-in-depth; off by default).
 *
 * Requires the `ws` package (npm install -g ws).
 */

const { execSync } = require("node:child_process");
const net = require("node:net");
try {
  module.paths.push(execSync("npm root -g").toString().trim());
} catch {}
const WebSocket = require("ws");

// Per-session tunnel id: each tunnel has its own id and is served on its own origin,
// https://<id>-s.deyaochen.com/ (see tunnel.md). Defaults to the session id; override with
// TUNNEL_ID. The id must be a DNS label, so it is lowercased and anything outside [a-z0-9-]
// becomes "-" (the Worker does the same, worker.js tunnelKey), max 61 chars.
const TUNNEL_HOST = process.env.TUNNEL_HOST || "tunnel.deyaochen.com";
const TUNNEL_ID = (
  process.env.TUNNEL_ID ||
  process.env.CLAUDE_CODE_SESSION_ID ||
  process.env.CLAUDE_CODE_CONTAINER_ID ||
  ""
).toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+/, "").slice(0, 61).replace(/-+$/, "");
if (!TUNNEL_ID && !process.env.TUNNEL_WORKER_URL) {
  console.error(
    "no tunnel id: set TUNNEL_ID (CLAUDE_CODE_SESSION_ID is used by default).",
  );
  process.exit(1);
}
const WORKER_URL = process.env.TUNNEL_WORKER_URL ||
  `wss://${TUNNEL_HOST}/__agent/${TUNNEL_ID}`;
const PUBLIC_URL = /-ssh$/.test(TUNNEL_ID)
  ? `ssh://${TUNNEL_ID.replace(/-ssh$/, "")}-ssh.deyaochen.com` // a session's ssh tunnel (jarvis-ssh)
  : `https://${TUNNEL_ID}-s.deyaochen.com/`;
const TARGET = process.env.TUNNEL_TARGET || "http://127.0.0.1:8899";
const AGENT_SECRET = process.env.TUNNEL_AGENT_SECRET; // optional
const ACCESS_ID = process.env.CF_ACCESS_CLIENT_ID;
const ACCESS_SECRET = process.env.CF_ACCESS_CLIENT_SECRET;
if (!ACCESS_ID || !ACCESS_SECRET) {
  console.error(
    "CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET are required " +
    "(set them in the environment; mint with cf-tunnel/deploy.sh).",
  );
  process.exit(1);
}

// Streaming protocol: response bodies are sent as res-start / res-chunk* /
// res-end messages so a body is never one giant WS message (Cloudflare caps
// WS messages at ~1MB, which the old single-message protocol hit on any file
// bigger than ~700KB). CHUNK*4/3 must stay well under that cap.
const CHUNK = 512 * 1024;
const WS_BUFFER_MAX = 8 * 1024 * 1024;
const MAX_INFLIGHT = 8; // unacked chunks per request (worker acks each write)
let backoff = 1000;

function connect() {
  const headers = {
    "CF-Access-Client-Id": ACCESS_ID,
    "CF-Access-Client-Secret": ACCESS_SECRET,
  };
  if (AGENT_SECRET) headers["x-agent-secret"] = AGENT_SECRET;
  const ws = new WebSocket(WORKER_URL, { headers });
  current = ws;
  let pingTimer;

  ws.on("open", () => {
    backoff = 1000;
    console.log(`[agent] connected to ${WORKER_URL}, proxying to ${TARGET}`);
    console.log(`[agent] public URL: ${PUBLIC_URL}`);
    // tell the Worker we take chunked request bodies (req-chunk); an older Worker ignores this
    try { ws.send(JSON.stringify({ type: "hello", features: ["req-chunk"] })); } catch {}
    // keep the socket warm through idle periods
    pingTimer = setInterval(() => {
      try { ws.send(JSON.stringify({ type: "ping" })); } catch {}
    }, 30_000);
  });

  const cancelled = new Set(); // req ids the worker told us to stop streaming
  const inflight = new Map();  // req id -> {count, wake, legacy}
  const locals = new Map();    // browser WebSocket id -> the local WebSocket carrying it
  const bodies = new Map();    // req id -> controller of the chunked request body being received

  // A browser opened a WebSocket on a tunnelled path: open the same path on the local target and
  // relay frames both ways (text as-is, binary as base64). Frames that arrive before the local
  // socket is open are queued.
  const openLocal = (msg) => {
    const send = (obj) => { try { ws.send(JSON.stringify(obj)); } catch {} };
    if (TARGET.startsWith("tcp://")) { openTCP(msg, send); return; }
    let local;
    try {
      local = new WebSocket(TARGET.replace(/^http/, "ws") + msg.path, msg.protocols || [], { headers: msg.headers || {} });
    } catch (e) {
      send({ type: "ws-close", id: msg.id, code: 1011, reason: "agent: " + e.message });
      return;
    }
    const entry = { local, queue: [] };
    locals.set(msg.id, entry);
    local.on("open", () => { for (const [data, binary] of entry.queue.splice(0)) local.send(data, { binary }); });
    local.on("message", (data, isBinary) => send(isBinary
      ? { type: "ws-msg", id: msg.id, data_b64: Buffer.from(data).toString("base64") }
      : { type: "ws-msg", id: msg.id, text: data.toString() }));
    const gone = (code, reason) => {
      if (locals.get(msg.id) !== entry) return;
      locals.delete(msg.id);
      send({ type: "ws-close", id: msg.id, code, reason: String(reason || "") });
    };
    local.on("close", (code, reason) => gone(code, reason));
    local.on("error", (e) => { gone(1011, "agent: local websocket failed: " + e.message); try { local.terminate(); } catch {} });
  };

  // tcp:// target: the WebSocket's binary frames are the bytes of one TCP connection. The socket is
  // wrapped in the local WebSocket's shape (readyState / send / close) for the ws-msg and ws-close paths.
  const openTCP = (msg, send) => {
    const u = new URL(TARGET);
    const sock = net.connect(Number(u.port), u.hostname);
    const local = {
      readyState: WebSocket.CONNECTING,
      send: (data) => sock.write(data),
      close: () => sock.end(),
      terminate: () => sock.destroy(),
    };
    const entry = { local, queue: [] };
    locals.set(msg.id, entry);
    sock.on("connect", () => {
      local.readyState = WebSocket.OPEN;
      for (const [data] of entry.queue.splice(0)) sock.write(data);
    });
    sock.on("data", (data) => send({ type: "ws-msg", id: msg.id, data_b64: data.toString("base64") }));
    const gone = (code, reason) => {
      if (locals.get(msg.id) !== entry) return;
      locals.delete(msg.id);
      send({ type: "ws-close", id: msg.id, code, reason });
    };
    sock.on("close", () => gone(1000, ""));
    sock.on("error", (e) => { gone(1011, "agent: local tcp failed: " + e.message); sock.destroy(); });
  };

  ws.on("message", async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (msg.type === "res-cancel") {
      cancelled.add(msg.id);
      const f = inflight.get(msg.id);
      if (f && f.wake) { const w = f.wake; f.wake = null; w(); }
      return;
    }
    if (msg.type === "res-ack") {
      const f = inflight.get(msg.id);
      if (f) {
        f.count--;
        if (f.wake) { const w = f.wake; f.wake = null; w(); }
      }
      return;
    }
    // Chunked request body (req with body_chunked, then req-chunk* + req-end, or req-abort):
    // fed into the local request as a stream, so an upload is never one giant WS message.
    if (msg.type === "req-chunk" || msg.type === "req-end" || msg.type === "req-abort") {
      const c = bodies.get(msg.id);
      if (!c) return;
      try {
        if (msg.type === "req-chunk") c.enqueue(new Uint8Array(Buffer.from(msg.data_b64, "base64")));
        else { bodies.delete(msg.id); if (msg.type === "req-end") c.close(); else c.error(new Error("request aborted by the worker")); }
      } catch {}
      return;
    }
    if (msg.type === "ws-open") { openLocal(msg); return; }
    if (msg.type === "ws-msg" || msg.type === "ws-close") {
      const entry = locals.get(msg.id);
      if (!entry) return;
      if (msg.type === "ws-close") { locals.delete(msg.id); try { entry.local.close(); } catch {} return; }
      const binary = !!msg.data_b64;
      const data = binary ? Buffer.from(msg.data_b64, "base64") : String(msg.text ?? "");
      if (entry.local.readyState === WebSocket.OPEN) entry.local.send(data, { binary });
      else entry.queue.push([data, binary]);
      return;
    }
    if (msg.type !== "req") return;
    const send = (obj) => ws.send(JSON.stringify(obj));
    let started = false;
    let body;
    if (msg.body_chunked) body = new ReadableStream({ start: (c) => { bodies.set(msg.id, c); } });
    else if (!["GET", "HEAD"].includes(msg.method) && msg.body_b64) body = Buffer.from(msg.body_b64, "base64");
    try {
      const resp = await fetch(TARGET + msg.path, {
        method: msg.method,
        headers: msg.headers,
        body,
        ...(msg.body_chunked ? { duplex: "half" } : {}),
        redirect: "manual",
      });
      const respHeaders = {};
      resp.headers.forEach((v, k) => { respHeaders[k] = v; });
      send({ type: "res-start", id: msg.id, status: resp.status, headers: respHeaders });
      started = true;
      if (resp.body && msg.method !== "HEAD") {
        const reader = resp.body.getReader();
        const flow = { count: 0, wake: null, legacy: false };
        inflight.set(msg.id, flow);
        let pending = Buffer.alloc(0);
        const sendChunks = async (final) => {
          while (pending.length >= CHUNK || (final && pending.length)) {
            if (cancelled.has(msg.id)) return false;
            const piece = pending.subarray(0, CHUNK);
            pending = pending.subarray(piece.length);
            send({ type: "res-chunk", id: msg.id, data_b64: piece.toString("base64") });
            flow.count++;
            // Window on worker acks: each ack means the client consumed a
            // chunk, so a slow client throttles us here. A worker that never
            // acks (stale deploy) is detected once and the window disabled.
            while (!flow.legacy && flow.count >= MAX_INFLIGHT && !cancelled.has(msg.id)) {
              const before = flow.count;
              await new Promise((r) => { flow.wake = r; setTimeout(r, 15_000); });
              if (flow.count === before && flow.count >= MAX_INFLIGHT) flow.legacy = true;
            }
            while (ws.bufferedAmount > WS_BUFFER_MAX) {
              await new Promise((r) => setTimeout(r, 50));
            }
          }
          return true;
        };
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          pending = pending.length ? Buffer.concat([pending, Buffer.from(value)]) : Buffer.from(value);
          if (!(await sendChunks(false))) { await reader.cancel().catch(() => {}); break; }
        }
        await sendChunks(true);
      }
    } catch (e) {
      if (!started) {
        try {
          send({ type: "res-start", id: msg.id, status: 502, headers: { "content-type": "text/plain" } });
          send({ type: "res-chunk", id: msg.id, data_b64: Buffer.from(`agent: local fetch failed: ${e.message}`).toString("base64") });
        } catch {}
      } else {
        console.error("[agent] stream failed:", e.message);
      }
    }
    cancelled.delete(msg.id);
    inflight.delete(msg.id);
    bodies.delete(msg.id);
    try { send({ type: "res-end", id: msg.id }); } catch (e) {
      console.error("[agent] send failed:", e.message);
    }
  });

  let retried = false;
  const retry = (why, delay) => {
    if (retried) return;
    retried = true;
    clearInterval(pingTimer);
    for (const [, entry] of locals) { try { entry.local.close(); } catch {} } // their browser ends died with the socket
    for (const [, c] of bodies) { try { c.error(new Error("tunnel socket closed")); } catch {} }
    bodies.clear();
    locals.clear();
    const wait = delay || backoff;
    console.error(`[agent] ${why}; reconnecting in ${wait}ms`);
    setTimeout(connect, wait);
    if (!delay) backoff = Math.min(backoff * 2, 30_000);
  };
  // 1012 "replaced": another agent with our tunnel id took over (normally the successor pod
  // during a redeploy). Reconnecting after 1 s would kick IT off and the two would swap every
  // second, failing every in-flight request — so stand back for a while; if we are the one
  // meant to live, the other side is gone by then.
  ws.on("close", (code, reason) => retry(`closed (${code} ${reason})`, code === 1012 ? 20_000 + Math.floor(Math.random() * 5000) : 0));
  ws.on("error", (e) => { ws.terminate(); retry(`error (${e.message})`); });
}

let current = null; // the live socket, for the shutdown handler
// Orderly shutdown (k8s SIGTERM on redeploy): close the socket so the Worker sees the agent
// gone immediately instead of holding requests against a dead socket until they time out.
let shuttingDown = false;
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, () => {
  if (shuttingDown) return; shuttingDown = true;
  console.error(`[agent] ${sig}: closing tunnel socket and exiting`);
  try { if (current && current.readyState === WebSocket.OPEN) current.close(1001, "agent shutting down"); } catch {}
  setTimeout(() => process.exit(0), 300);
});

connect();
