#!/usr/bin/env python3
"""Cloudflare side of Jarvis 4 (idempotent): the tunnel, its DNS name, the two Access apps, the setup
session's service token. Writes TUNNEL_TOKEN (for the box) and SETUP_ACCESS_ID/SECRET (for the setup
session, Jarvis 1's default store as JARVIS2_SETUP_ACCESS_ID/SECRET) to OUT (mode 600); prints nothing secret.
The apps' audiences are not secret: they are in k8s/control/apps/router/router.yaml (the script prints them to check).

  CF_JARVIS2_INFRA_TOKEN  tunnel + Access apps + DNS (scoped token "jarvis2-infra")
  CLOUDFLARE_API          only to mint the setup service token (the scoped token can't)

  infra/cloudflare.py OUT
  infra/cloudflare.py --peer OUT
                               Jarvis 1's way to the Claude login (router/claudelogin.go /peer/*): the service token
                               jarvis1-claude-login (kept unless ROTATE=1; a new one's JARVIS2_LOGIN_ID/SECRET go to
                               OUT, mode 600) and the Access app jarvis4.deyaochen.com/peer admitting only it; prints
                               the app's audience and the token's client id (k8s/control/apps/router/router.yaml ACCESS_PEER_AUD,
                               JARVIS1_LOGIN_CLIENT_ID; neither is secret)
  infra/cloudflare.py --devices  only the paired apps' Access app (CF_JARVIS2_INFRA_TOKEN); prints its audience
  infra/cloudflare.py --cluster OUT
                               the one cluster's tunnel jarvis2-cluster (docs/PLAN-cluster.md step 2a): only
                               kernel-id.deyaochen.com → the kernel's read-only identity endpoints, behind the Access app
                               "Jarvis 4 kernel id" admitting only the service token jarvis2-kernel-id (the setup
                               session's; kept unless ROTATE=1). A new token's KERNEL_ID_ACCESS_ID/SECRET and the
                               tunnel's TUNNEL_TOKEN go to OUT (mode 600)
  infra/cloudflare.py --health OUT
                               the external uptime probe's way in (router/healthz.go GET /healthz): the service token
                               jarvis2-health-probe (kept unless ROTATE=1; a new one's HEALTH_PROBE_ID/SECRET go to OUT,
                               mode 600, for Grafana Synthetic Monitoring) and the Access app jarvis4.deyaochen.com/healthz
                               admitting only it; prints the app's audience and the token's client id
                               (k8s/control/apps/router/router.yaml ACCESS_HEALTH_AUD, HEALTH_CLIENT_ID; neither is secret)
Access apps (created Access first, then DNS, so the hostname is never reachable ungated):
  "Jarvis 4"        jarvis4.deyaochen.com         Deyao's email only (the app + web page)
  "Jarvis 4 setup"  jarvis4.deyaochen.com/setup   service token jarvis2-setup only (the setup session)
  "Jarvis 4 peer"   jarvis4.deyaochen.com/peer    service token jarvis1-claude-login only (Jarvis 1 reads the Claude login)
  "Jarvis 4 health" jarvis4.deyaochen.com/healthz service token jarvis2-health-probe only (Grafana's uptime probe)
  "Jarvis 4 devices" jarvis4.deyaochen.com/api/remotes and /api/sessions/*/start: Deyao's email, or ANY service token
                    of the account (Deyao's paired OpenClaw/Paseo apps); the router admits a token only when it is a
                    paired device's (router/devices.go). Audience: ACCESS_DEVICES_AUD in k8s/control/apps/router/router.yaml
Session machines don't come through Cloudflare at all (Fly's private network, docs/API.md).

A rehearsal box (infra/rehearse-recover.sh) gets its own of each, never production's:
  REHEARSAL=NAME infra/cloudflare.py OUT    tunnel NAME, hostname NAME.deyaochen.com, ONE Access app on the whole
                                            hostname whose only policy is the service token NAME (the test client
                                            and the setup calls both use it: SETUP_ACCESS_ID/SECRET in OUT)
  REHEARSAL=NAME infra/cloudflare.py --delete   removes that app, token, DNS record and tunnel
NAME must start with "jarvis2-rehearsal".
"""
import json, os, sys, urllib.request, urllib.error

ACCOUNT = "ee3b4deef856baf11e1a67b242438325"
ZONE = "f51ca95ee5e6c664372000f887c96a92"
HOST = "jarvis4.deyaochen.com"
EMAIL = "chendeyao000@gmail.com"
ORIGIN = "http://router.jarvis4-router.svc.cluster.local:8080"
API = "https://api.cloudflare.com/client/v4"


def call(method, path, body=None, token=None):
    req = urllib.request.Request(API + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + (token or os.environ["CF_JARVIS2_INFRA_TOKEN"]),
                                          "Content-Type": "application/json", "User-Agent": "jarvis2-infra/1"})
    try:
        r = json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        r = json.loads(e.read() or b"{}")
    if not r.get("success"):
        raise SystemExit(f"{method} {path}: {r.get('errors')}")
    return r["result"]


def access_app(name, domain, policy):
    apps = call("GET", f"/accounts/{ACCOUNT}/access/apps")
    app = next((a for a in apps if a.get("domain") == domain), None)
    body = {"name": name, "domain": domain, "type": "self_hosted", "session_duration": "720h",
            "app_launcher_visible": False, "auto_redirect_to_identity": False}
    app = call("PUT" if app else "POST", f"/accounts/{ACCOUNT}/access/apps" + (f"/{app['id']}" if app else ""), body)
    pols = call("GET", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies")
    for p in pols:
        call("DELETE", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies/{p['id']}")
    call("POST", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies", dict(policy, precedence=1))
    return app["aud"]


def dns(host, tid, name):
    recs = call("GET", f"/zones/{ZONE}/dns_records?name={host}")
    rec = {"type": "CNAME", "name": host, "content": f"{tid}.cfargotunnel.com", "proxied": True, "comment": f"{name} tunnel"}
    if recs:
        call("PUT", f"/zones/{ZONE}/dns_records/{recs[0]['id']}", rec)
    else:
        call("POST", f"/zones/{ZONE}/dns_records", rec)


def tunnel_and_dns(host, name, extra=()):
    """the tunnel NAME (remotely managed, ingress host → the router, plus EXTRA (host, origin) rules), then the DNS
    record; returns its token"""
    tunnels = call("GET", f"/accounts/{ACCOUNT}/cfd_tunnel?name={name}&is_deleted=false")
    tun = tunnels[0] if tunnels else call("POST", f"/accounts/{ACCOUNT}/cfd_tunnel", {"name": name, "config_src": "cloudflare"})
    call("PUT", f"/accounts/{ACCOUNT}/cfd_tunnel/{tun['id']}/configurations", {"config": {"ingress": [
        {"hostname": host, "service": ORIGIN}] + [{"hostname": h, "service": o} for h, o in extra] + [
        {"service": "http_status:404"}]}})
    token = call("GET", f"/accounts/{ACCOUNT}/cfd_tunnel/{tun['id']}/token")
    dns(host, tun["id"], name)
    return tun["id"], token


def peer(out):
    """Jarvis 1's service token for /peer (minted with CLOUDFLARE_API, which the scoped token can't), then its app"""
    big = os.environ["CLOUDFLARE_API"]
    toks = call("GET", f"/accounts/{ACCOUNT}/access/service_tokens", token=big)
    tok = next((t for t in toks if t["name"] == "jarvis1-claude-login"), None)
    if tok and os.environ.get("ROTATE"):
        tok = {"id": tok["id"]} | call("POST", f"/accounts/{ACCOUNT}/access/service_tokens/{tok['id']}/rotate", token=big)
        write_out(out, {"JARVIS2_LOGIN_ID": tok["client_id"], "JARVIS2_LOGIN_SECRET": tok["client_secret"]})
    elif not tok:
        tok = call("POST", f"/accounts/{ACCOUNT}/access/service_tokens", {"name": "jarvis1-claude-login", "duration": "8760h"}, token=big)
        write_out(out, {"JARVIS2_LOGIN_ID": tok["client_id"], "JARVIS2_LOGIN_SECRET": tok["client_secret"]})
    aud = access_app("Jarvis 4 peer", HOST + "/peer", {
        "name": "Jarvis 1", "decision": "non_identity", "include": [{"service_token": {"token_id": tok["id"]}}]})
    print(f"ok (k8s/control/apps/router/router.yaml): ACCESS_PEER_AUD={aud} JARVIS1_LOGIN_CLIENT_ID={tok['client_id']}")
def health(out):
    """the uptime probe's service token for /healthz (minted with CLOUDFLARE_API), then its app"""
    big = os.environ["CLOUDFLARE_API"]
    toks = call("GET", f"/accounts/{ACCOUNT}/access/service_tokens", token=big)
    tok = next((t for t in toks if t["name"] == "jarvis2-health-probe"), None)
    if tok and os.environ.get("ROTATE"):
        tok = {"id": tok["id"]} | call("POST", f"/accounts/{ACCOUNT}/access/service_tokens/{tok['id']}/rotate", token=big)
        write_out(out, {"HEALTH_PROBE_ID": tok["client_id"], "HEALTH_PROBE_SECRET": tok["client_secret"]})
    elif not tok:
        tok = call("POST", f"/accounts/{ACCOUNT}/access/service_tokens", {"name": "jarvis2-health-probe", "duration": "8760h"}, token=big)
        write_out(out, {"HEALTH_PROBE_ID": tok["client_id"], "HEALTH_PROBE_SECRET": tok["client_secret"]})
    aud = access_app("Jarvis 4 health", HOST + "/healthz", {
        "name": "uptime probe", "decision": "non_identity", "include": [{"service_token": {"token_id": tok["id"]}}]})
    print(f"ok (k8s/control/apps/router/router.yaml): ACCESS_HEALTH_AUD={aud} HEALTH_CLIENT_ID={tok['client_id']}")


DEVICE_PATHS = ["/api/remotes", "/api/sessions/*/start"]


def devices():
    """the paired apps' Access app: only the paths they call, Deyao's email or any service token (the router narrows
    the tokens to its paired devices)"""
    uris = [HOST + p for p in DEVICE_PATHS]
    apps = call("GET", f"/accounts/{ACCOUNT}/access/apps")
    app = next((a for a in apps if a.get("name") == "Jarvis 4 devices"), None)
    body = {"name": "Jarvis 4 devices", "domain": uris[0], "type": "self_hosted", "session_duration": "24h",
            "destinations": [{"type": "public", "uri": u} for u in uris],
            "app_launcher_visible": False, "auto_redirect_to_identity": False}
    app = call("PUT" if app else "POST", f"/accounts/{ACCOUNT}/access/apps" + (f"/{app['id']}" if app else ""), body)
    for p in call("GET", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies"):
        call("DELETE", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies/{p['id']}")
    call("POST", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies",
         {"name": "Deyao", "decision": "allow", "include": [{"email": {"email": EMAIL}}], "precedence": 1})
    call("POST", f"/accounts/{ACCOUNT}/access/apps/{app['id']}/policies",
         {"name": "paired apps (the router checks the device)", "decision": "non_identity",
          "include": [{"any_valid_service_token": {}}], "precedence": 2})
    print(f"ok: Access app 'Jarvis 4 devices' on {', '.join(uris)}; ACCESS_DEVICES_AUD={app['aud']}")


CLUSTER_ID_HOST = "kernel-id.deyaochen.com"
CLUSTER_ID_ORIGIN = "http://kernel-id.jarvis2-edge.svc.cluster.local:8080"


def cluster(out):
    """the one cluster's tunnel: only the kernel's identity endpoints, Access first, then the tunnel, DNS last"""
    big = os.environ["CLOUDFLARE_API"]
    vals = {}
    toks = call("GET", f"/accounts/{ACCOUNT}/access/service_tokens", token=big)
    tok = next((t for t in toks if t["name"] == "jarvis2-kernel-id"), None)
    if tok and os.environ.get("ROTATE"):
        tok = {"id": tok["id"]} | call("POST", f"/accounts/{ACCOUNT}/access/service_tokens/{tok['id']}/rotate", token=big)
        vals |= {"KERNEL_ID_ACCESS_ID": tok["client_id"], "KERNEL_ID_ACCESS_SECRET": tok["client_secret"]}
    elif not tok:
        tok = call("POST", f"/accounts/{ACCOUNT}/access/service_tokens", {"name": "jarvis2-kernel-id", "duration": "8760h"}, token=big)
        vals |= {"KERNEL_ID_ACCESS_ID": tok["client_id"], "KERNEL_ID_ACCESS_SECRET": tok["client_secret"]}
    access_app("Jarvis 4 kernel id", CLUSTER_ID_HOST, {
        "name": "setup session", "decision": "non_identity", "include": [{"service_token": {"token_id": tok["id"]}}]})
    tunnels = call("GET", f"/accounts/{ACCOUNT}/cfd_tunnel?name=jarvis2-cluster&is_deleted=false")
    tun = tunnels[0] if tunnels else call("POST", f"/accounts/{ACCOUNT}/cfd_tunnel", {"name": "jarvis2-cluster", "config_src": "cloudflare"})
    call("PUT", f"/accounts/{ACCOUNT}/cfd_tunnel/{tun['id']}/configurations", {"config": {"ingress": [
        {"hostname": CLUSTER_ID_HOST, "service": CLUSTER_ID_ORIGIN}, {"service": "http_status:404"}]}})
    vals["TUNNEL_TOKEN"] = call("GET", f"/accounts/{ACCOUNT}/cfd_tunnel/{tun['id']}/token")
    dns(CLUSTER_ID_HOST, tun["id"], "jarvis2-cluster")
    write_out(out, vals)
    print(f"ok: tunnel jarvis2-cluster {tun['id']}, https://{CLUSTER_ID_HOST}/ behind its Access app; values in {out}"
          + ("" if "KERNEL_ID_ACCESS_ID" in vals else " (the service token was kept: its secret is already in the infra store)"))


def write_out(out, vals):
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        for k, v in vals.items():
            f.write(f"{k}={v}\n")


def rehearsal(name, out):
    """a rehearsal box's own tunnel, hostname, Access app and service token (never production's)"""
    if not name.startswith("jarvis2-rehearsal"):
        raise SystemExit("REHEARSAL must start with jarvis2-rehearsal")
    host = f"{name}.deyaochen.com"
    big = os.environ["CLOUDFLARE_API"]
    if out == "--delete":
        for a in call("GET", f"/accounts/{ACCOUNT}/access/apps"):
            if a.get("domain") == host:
                call("DELETE", f"/accounts/{ACCOUNT}/access/apps/{a['id']}")
        for t in call("GET", f"/accounts/{ACCOUNT}/access/service_tokens", token=big):
            if t["name"] == name:
                call("DELETE", f"/accounts/{ACCOUNT}/access/service_tokens/{t['id']}", token=big)
        for r in call("GET", f"/zones/{ZONE}/dns_records?name={host}"):
            call("DELETE", f"/zones/{ZONE}/dns_records/{r['id']}")
        for t in call("GET", f"/accounts/{ACCOUNT}/cfd_tunnel?name={name}&is_deleted=false"):
            call("DELETE", f"/accounts/{ACCOUNT}/cfd_tunnel/{t['id']}/connections")
            call("DELETE", f"/accounts/{ACCOUNT}/cfd_tunnel/{t['id']}")
        print(f"ok: {name}'s Access app, service token, DNS record and tunnel are gone")
        return
    for t in call("GET", f"/accounts/{ACCOUNT}/access/service_tokens", token=big):
        if t["name"] == name:
            call("DELETE", f"/accounts/{ACCOUNT}/access/service_tokens/{t['id']}", token=big)
    t = call("POST", f"/accounts/{ACCOUNT}/access/service_tokens", {"name": name, "duration": "24h"}, token=big)
    vals = {"SETUP_ACCESS_ID": t["client_id"], "SETUP_ACCESS_SECRET": t["client_secret"]}
    access_app(f"Jarvis 4 rehearsal ({name})", host, {
        "name": "rehearsal client", "decision": "non_identity", "include": [{"service_token": {"token_id": t["id"]}}]})
    tid, vals["TUNNEL_TOKEN"] = tunnel_and_dns(host, name)
    write_out(out, vals)
    print(f"ok: rehearsal tunnel {tid} at https://{host}/ behind its own Access app; values in {out}")


def main():
    if sys.argv[1:2] == ["--peer"]:
        return peer(sys.argv[2])
    if sys.argv[1:2] == ["--health"]:
        return health(sys.argv[2])
    if sys.argv[1:] == ["--devices"]:
        return devices()
    if sys.argv[1:2] == ["--cluster"]:
        return cluster(sys.argv[2])
    if os.environ.get("REHEARSAL"):
        return rehearsal(os.environ["REHEARSAL"], sys.argv[1])
    out = sys.argv[1]
    vals = {}

    # 1. the setup session's service token (needs the broader token; kept unless ROTATE=1)
    toks = call("GET", f"/accounts/{ACCOUNT}/access/service_tokens", token=os.environ["CLOUDFLARE_API"])
    tok = next((t for t in toks if t["name"] == "jarvis2-setup"), None)
    prev = {}
    if os.path.exists(out):
        prev = dict(l.rstrip("\n").split("=", 1) for l in open(out) if "=" in l)
    if tok and not os.environ.get("ROTATE") and prev.get("SETUP_ACCESS_SECRET"):
        vals["SETUP_ACCESS_ID"], vals["SETUP_ACCESS_SECRET"] = prev["SETUP_ACCESS_ID"], prev["SETUP_ACCESS_SECRET"]
        tok_id = tok["id"]
    else:
        if tok:
            call("DELETE", f"/accounts/{ACCOUNT}/access/service_tokens/{tok['id']}", token=os.environ["CLOUDFLARE_API"])
        t = call("POST", f"/accounts/{ACCOUNT}/access/service_tokens", {"name": "jarvis2-setup", "duration": "8760h"},
                 token=os.environ["CLOUDFLARE_API"])
        vals["SETUP_ACCESS_ID"], vals["SETUP_ACCESS_SECRET"], tok_id = t["client_id"], t["client_secret"], t["id"]

    # 2. Access apps first
    aud = access_app("Jarvis 4", HOST, {"name": "Deyao", "decision": "allow", "include": [{"email": {"email": EMAIL}}]})
    setup_aud = access_app("Jarvis 4 setup", HOST + "/setup", {
        "name": "setup session", "decision": "non_identity", "include": [{"service_token": {"token_id": tok_id}}]})
    print(f"audiences (k8s/control/apps/router/router.yaml): ACCESS_APP_AUD={aud} ACCESS_SETUP_AUD={setup_aud}")

    # 3. the tunnel (remotely managed) and its ingress, then DNS last
    tid, vals["TUNNEL_TOKEN"] = tunnel_and_dns(HOST, "jarvis2")
    devices()

    write_out(out, vals)
    print(f"ok: tunnel {tid}, Access apps + setup service token ready; values in {out}")


if __name__ == "__main__":
    main()
