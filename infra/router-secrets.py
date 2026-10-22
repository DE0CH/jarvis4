#!/usr/bin/env python3
"""router-secrets.py — write a box's non-sensitive secrets into git, SOPS-encrypted to that box's age key; the box's
Flux decrypts them (k8s/flux/<box>.yaml, Kustomization <box>-secrets).

    infra/router-secrets.py --box control|services [--part PART] KEY[=SRC] …

--box picks the box (docs/DESIGN.md "The boxes"): its age key (keys/<box>-age.pub), its secrets directory
(k8s/<box>/secrets/) and its manifests (k8s/<box>/apps/<app>/, whose annotation the run bumps so the pod restarts with
the new Secret). Each box gets only its own parts:
  control   (default), backup, github, flyorgs, flypersonal, flyvolumes, browserbase, devices, alloy
  services  search, icloud-index, icloud-session, alloy
  cluster   alloy, tunnel (token=TUNNEL_TOKEN from infra/cloudflare.py --cluster)

SRC is `env:VAR` (default `env:KEY`) or `file:PATH`. A part is one Secret, rewritten whole each run, so name
every key of that part (nobody can read the old values back: only the box holds the age key):
  (default)      router.enc.yaml, Secret router-secrets — LOBSTER_TOKEN, Storage Box, tokens…
  --part backup  router-backup.enc.yaml, Secret router-secrets-backup — the backup bucket's read
                 credential (BACKUP_READ_ACCESS_KEY, BACKUP_READ_SECRET_KEY; infra/backup-read-key.py install)
  --part github  router-github.enc.yaml, Secret router-secrets-github — GITHUB_READ_TOKEN only (the
                 repo picker's list token), so it can be replaced without rewriting the default part. It is the
                 LAST envFrom in router.yaml, so it wins over the stale GITHUB_READ_TOKEN still in the default part
  --part flyorgs router-flyorgs.enc.yaml, Secret router-secrets-flyorgs — FLY_ORG_READ_TOKENS only:
                 {"<org slug>": "<read-only org token>"} for the Machines view's other orgs (router/flyorgs.go)
  --part flypersonal  router-flypersonal.enc.yaml — FLY_PERSONAL_READ_TOKEN only: org personal's read-only
                 token for the Machines view (infra/fly-personal-read-token.sh; router/flyorgs.go)
  --part flyvolumes  router-flyvolumes.enc.yaml — FLY_VOLUME_TOKEN only: the token that can do nothing but
                 delete volumes in jarvis4-sessions (infra/fly-volume-token.sh), for the leftover-volume sweep
                 (router/volsweep.go, DECISIONS 195)
  --part browserbase  router-browserbase.enc.yaml — BROWSERBASE_API_KEY only (router/bbbudget.go: the
                 spend DM reads the session list)
  --part devices router-devices.enc.yaml — CF_DEVICE_TOKENS_API only: the Cloudflare token "jarvis2-device-tokens"
                 (Access: Service Tokens read/write, nothing else) that mints and deletes the paired apps' tokens (router/devices.go)
  --part alloy   alloy.enc.yaml, Secret alloy in jarvis2-obs — GRAFANA_LOGS_URL/USER, GRAFANA_METRICS_URL/USER,
                 GRAFANA_WRITE_TOKEN: the host's Grafana Alloy reads it (infra/alloy/; no pod uses it, so no annotation)
  --part search  (services) search.enc.yaml, Secret search-secrets — STORAGEBOX_HOST/USER/PASSWORD and OPENROUTER_API
                 for transcript search (k8s/services/apps/search/)
  --part icloud-index    (services) icloud-index.enc.yaml, Secret icloud-index-secrets — OPENROUTER_API, LOBSTER_TOKEN,
                 STORAGEBOX_HOST/USER/PASSWORD for the iCloud index (k8s/services/apps/icloud-index/)
  --part icloud-session  (services) icloud-session.enc.yaml, Secret icloud-index-session — ICLOUD_RCLONE_CONF only (the
                 saved iCloud login, mounted as a file; write it again after a re-login, e.g.
                 ICLOUD_RCLONE_CONF=file:~/.config/rclone/rclone.conf)
Only for secrets that can't reach a code push (Deyao, 2026-10-09); the pods get them as env (envFrom). Prints names
only, never a value."""
import hashlib, json, os, re, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOXES = {  # box → (age recipient file, secrets dir, {part: manifest path under k8s/<box>/apps/})
    "control": ("keys/control-age.pub", "k8s/control/secrets", {
        "": "router/router.yaml", "backup": "router/router.yaml", "github": "router/router.yaml",
        "flyorgs": "router/router.yaml", "flypersonal": "router/router.yaml", "flyvolumes": "router/router.yaml", "browserbase": "router/router.yaml",
        "devices": "router/router.yaml", "alloy": None}),
    "services": ("keys/services-age.pub", "k8s/services/secrets", {
        "search": "search/search.yaml", "icloud-index": "icloud-index/icloud-index.yaml",
        "icloud-session": "icloud-index/icloud-index.yaml", "alloy": None}),
    "cluster": ("keys/cluster-age.pub", "k8s/cluster/secrets", {"alloy": None, "tunnel": None}),  # the one cluster (docs/PLAN-cluster.md)
}
PARTS = {  # part → (file, Secret name, annotation, namespace)
    "": ("router.enc.yaml", "router-secrets", "jarvis2/secrets-rev", "jarvis2-router"),
    "backup": ("router-backup.enc.yaml", "router-secrets-backup", "jarvis2/secrets-rev-backup", "jarvis2-router"),
    "github": ("router-github.enc.yaml", "router-secrets-github", "jarvis2/secrets-rev-github", "jarvis2-router"),
    "flyorgs": ("router-flyorgs.enc.yaml", "router-secrets-flyorgs", "jarvis2/secrets-rev-flyorgs", "jarvis2-router"),
    "flypersonal": ("router-flypersonal.enc.yaml", "router-secrets-flypersonal", "jarvis2/secrets-rev-flypersonal", "jarvis2-router"),
    "flyvolumes": ("router-flyvolumes.enc.yaml", "router-secrets-flyvolumes", "jarvis2/secrets-rev-flyvolumes", "jarvis2-router"),
    "browserbase": ("router-browserbase.enc.yaml", "router-secrets-browserbase", "jarvis2/secrets-rev-browserbase", "jarvis2-router"),
    "devices": ("router-devices.enc.yaml", "router-secrets-devices", "jarvis2/secrets-rev-devices", "jarvis2-router"),
    "search": ("search.enc.yaml", "search-secrets", "jarvis2/secrets-rev-search", "jarvis2-services"),
    "icloud-index": ("icloud-index.enc.yaml", "icloud-index-secrets", "jarvis2/secrets-rev-icloud-index", "jarvis2-services"),
    "icloud-session": ("icloud-session.enc.yaml", "icloud-index-session", "jarvis2/secrets-rev-icloud-session", "jarvis2-services"),
    "alloy": ("alloy.enc.yaml", "alloy", None, "jarvis2-obs"),
    "tunnel": ("tunnel.enc.yaml", "tunnel-token", None, "jarvis2-edge"),  # cluster: cloudflared's token (infra/cloudflare.py --cluster)
}


def main():
    args = sys.argv[1:]
    box, part = None, ""
    if args[:1] == ["--box"]:
        box, args = args[1], args[2:]
    if args[:1] == ["--part"]:
        part, args = args[1], args[2:]
    if not args or part not in PARTS or box not in BOXES:
        sys.exit(__doc__)
    keyfile, secdir, manifests = BOXES[box]
    fname, secret, annotation, namespace = PARTS[part]
    if part not in manifests:
        sys.exit(f"part {part or '(default)'} doesn't belong on the {box} box")
    manifest = manifests[part] and os.path.join("k8s", box, "apps", manifests[part])
    out = os.path.join(ROOT, secdir, fname)
    data = {}
    for arg in args:
        key, _, src = arg.partition("=")
        src = src or "env:" + key
        kind, _, ref = src.partition(":")
        if kind == "env":
            v = os.environ.get(ref)
        elif kind == "file":
            v = open(os.path.expanduser(ref)).read().strip()
        else:
            sys.exit(f"{key}: SRC is env:VAR or file:PATH")
        if not v:
            sys.exit(f"{key}: {src} is empty")
        data[key] = v
    recipient = open(os.path.join(ROOT, keyfile)).read().strip()
    doc = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": secret, "namespace": namespace},
           "type": "Opaque", "stringData": data}
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, dir=os.path.dirname(out)) as f:
        os.chmod(f.name, 0o600)
        json.dump(doc, f)  # JSON is YAML
        tmp = f.name
    try:
        enc = subprocess.run(["sops", "--encrypt", "--age", recipient, "--encrypted-regex", "^(data|stringData)$",
                              "--input-type", "yaml", "--output-type", "yaml", tmp], check=True, capture_output=True).stdout
    finally:
        os.remove(tmp)
    open(out, "wb").write(enc)
    kz = os.path.join(ROOT, secdir, "kustomization.yaml")
    s = open(kz).read()
    if "  - " + fname not in s:
        s = s.replace("resources: []", "resources:")
        open(kz, "w").write(s.rstrip("\n") + "\n  - " + fname + "\n")
    rev = hashlib.sha256(enc).hexdigest()[:12]
    if not annotation or not manifest:
        print("wrote", os.path.relpath(out, ROOT), "with", ", ".join(sorted(data)))
        return
    rp = os.path.join(ROOT, manifest)
    y = open(rp).read()  # read before opening for write: open(rp, "w") first would empty it
    if annotation + ': "' not in y:
        sys.exit(f"{rp}: no {annotation} annotation")
    open(rp, "w").write(re.sub(re.escape(annotation) + r': "[^"]*"', f'{annotation}: "{rev}"', y))
    print("wrote", os.path.relpath(out, ROOT), "with", ", ".join(sorted(data)), ";", annotation, rev)


main()
