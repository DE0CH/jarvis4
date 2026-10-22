// This replica's own pod as Kubernetes sees it: restart count and the last termination (reason such as OOMKilled,
// exit code, times). Read with the pod's service account (k8s/cluster/services/search: Role search-self, get on pods in
// jarvis4-services); outside a cluster it reports that it can't. Cached for 30 s.
const fs = require("fs");
const https = require("https");
const os = require("os");

const SA = "/var/run/secrets/kubernetes.io/serviceaccount";
let cache = null;

function get(pathname) {
  return new Promise((resolve, reject) => {
    const token = fs.readFileSync(`${SA}/token`, "utf8").trim(), ca = fs.readFileSync(`${SA}/ca.crt`);
    const host = process.env.KUBERNETES_SERVICE_HOST || "kubernetes.default.svc", port = process.env.KUBERNETES_SERVICE_PORT || 443;
    const req = https.request({ host, port, path: pathname, ca, headers: { Authorization: `Bearer ${token}` }, timeout: 3000 }, (res) => {
      let b = ""; res.setEncoding("utf8"); res.on("data", (c) => (b += c));
      res.on("end", () => (res.statusCode === 200 ? resolve(JSON.parse(b)) : reject(new Error(`GET ${pathname} -> ${res.statusCode}`))));
    });
    req.on("timeout", () => req.destroy(new Error("timeout"))); req.on("error", reject); req.end();
  });
}

async function ownPod() {
  if (!fs.existsSync(`${SA}/token`)) return { available: false };
  if (cache && Date.now() - cache.at < 30000) return cache.v;
  const ns = fs.readFileSync(`${SA}/namespace`, "utf8").trim();
  const p = await get(`/api/v1/namespaces/${ns}/pods/${process.env.POD_NAME || os.hostname()}`);
  const c = ((p.status && p.status.containerStatuses) || [])[0] || {};
  const t = c.lastState && c.lastState.terminated;
  const v = { pod: p.metadata.name, podCreated: p.metadata.creationTimestamp, restarts: c.restartCount || 0, containerStarted: c.state && c.state.running && c.state.running.startedAt,
    lastTermination: t ? { reason: t.reason, exitCode: t.exitCode, signal: t.signal, startedAt: t.startedAt, finishedAt: t.finishedAt } : null };
  cache = { at: Date.now(), v };
  return v;
}

module.exports = { ownPod };
