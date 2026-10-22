#!/usr/bin/env python3
"""router-secrets.py — write the cluster's non-sensitive secrets into git, SOPS-encrypted to the cluster's age key
(keys/cluster-age.pub); Flux decrypts them (k8s/cluster/flux-sync.yaml).

    infra/router-secrets.py --box cluster [--part PART] KEY[=SRC] …

Each part is one Secret in k8s/cluster/secrets/, rewritten whole each run, so name every key of that part (nobody can
read the old values back: only the cluster holds the age key). A part used by a pod bumps that pod's annotation in its
manifest so it restarts with the new Secret. SRC is `env:VAR` (default `env:KEY`) or `file:PATH`.
  (default)      router.enc.yaml, Secret router-secrets (jarvis4-router) — LOBSTER_TOKEN, STORAGEBOX_HOST/USER/PASSWORD,
                 JARVIS2_TUNNEL_KEY, FLY_READ_TOKEN (infra/fly-read-token.sh: read-only on app jarvis4-sessions)
  --part wg      router-wg.enc.yaml, Secret router-wg — wg.conf only: the router's WireGuard peer jarvis4-box in Fly org
                 jarvis2-370 (`fly wireguard create jarvis2-370 lhr jarvis4-box FILE`; router/wg.go), mounted at /wg
  --part backup  router-backup.enc.yaml, Secret router-secrets-backup — the backup bucket's read credential
                 (BACKUP_READ_ACCESS_KEY, BACKUP_READ_SECRET_KEY; infra/backup-read-key.py)
  --part github  router-github.enc.yaml, Secret router-secrets-github — GITHUB_READ_TOKEN only (the repo picker's list
                 token). It is the LAST envFrom in router.yaml, so it wins over any other source of the same key
  --part flyorgs router-flyorgs.enc.yaml, Secret router-secrets-flyorgs — FLY_ORG_READ_TOKENS only:
                 {"<org slug>": "<read-only org token>"} for the Machines view's other orgs (router/flyorgs.go)
  --part flypersonal  router-flypersonal.enc.yaml — FLY_PERSONAL_READ_TOKEN only (infra/fly-personal-read-token.sh)
  --part flyvolumes  router-flyvolumes.enc.yaml — FLY_VOLUME_TOKEN only: the token that can do nothing but delete
                 volumes in jarvis4-sessions (infra/fly-volume-token.sh), for the leftover-volume sweep (router/volsweep.go)
  --part browserbase  router-browserbase.enc.yaml — BROWSERBASE_API_KEY only (router/bbbudget.go)
  --part devices router-devices.enc.yaml — CF_DEVICE_TOKENS_API only (router/devices.go)
  --part alloy   alloy.enc.yaml, Secret alloy in jarvis2-obs — GRAFANA_LOGS_URL/USER, GRAFANA_METRICS_URL/USER,
                 GRAFANA_WRITE_TOKEN: the host's Grafana Alloy reads it (infra/alloy/; no pod uses it)
  --part search  (k8s/cluster/services/secrets) search.enc.yaml, Secret search-secrets in jarvis4-services —
                 STORAGEBOX_HOST/USER/PASSWORD and OPENROUTER_API for transcript search
  --part icloud-index  (k8s/cluster/services/secrets) icloud-index.enc.yaml, Secret icloud-index-secrets — OPENROUTER_API,
                 LOBSTER_TOKEN, STORAGEBOX_HOST/USER/PASSWORD, BACKUP_AGE_KEY (the private half of the index copy's
                 age key, ICLOUD_BACKUP_AGE_KEY in the infra store)
  --part icloud-session  (k8s/cluster/services/secrets) icloud-session.enc.yaml, Secret icloud-index-session —
                 ICLOUD_RCLONE_CONF only (the saved iCloud login)
  --part tunnel  tunnel.enc.yaml, Secret tunnel-token in jarvis2-edge — token=TUNNEL_TOKEN (infra/cloudflare.py --cluster)
  --part postgres  postgres.enc.yaml, Secret postgres-s3 in jarvis4-db — ACCESS_KEY_ID, ACCESS_SECRET_KEY: the Object
                 Storage credential of the database's WAL archive and base backups (bucket jarvis4-db-de0ch,
                 k8s/cluster/postgres/db/), e.g. ACCESS_KEY_ID=env:HETZNER_S3_ACCESS_KEY
  --part db      router-db.enc.yaml, Secret router-db in jarvis4-router — DATABASE_URL only: the router's connection to
                 the database (router/db.go), DATABASE_URL=dburl:JARVIS4_DB_ROUTER_PASSWORD (the infra store's password of
                 role router, made into postgres://router:…@jarvis4-db-rw.jarvis4-db.svc.cluster.local:5432/jarvis4?sslmode=require)
  --part wg-b    router-wg-b.enc.yaml, Secret router-wg-b — wg.conf of the second machines' gateway's peer jarvis4-gw-b
                 (`fly wireguard create jarvis2-370 lhr jarvis4-gw-b FILE`; router/mgateway.go), wg.conf=file:FILE
  --part seal    router-seal.enc.yaml, Secret router-seal — ROUTER_SEAL_KEY only: the AES-256 key the router seals its secrets
                 in the database with (router/sealed.go; base64 of 32 random bytes; JARVIS4_ROUTER_SEAL_KEY in the infra
                 store). A rotation: the new key as ROUTER_SEAL_KEY and the old as ROUTER_SEAL_KEY_OLD, until it restarted
  --part objects router-objects.enc.yaml, Secret router-secrets-objects — OBJECTS_ACCESS_KEY / OBJECTS_SECRET_KEY: the
                 router's credential for jarvis4-snapshots-de0ch only (infra/objects-key.py install)
  --part postgres-app  postgres-app.enc.yaml, Secret jarvis4-db-router (basic-auth) in jarvis4-db — username=router and
                 password: the database owner, made at initdb (the same password is JARVIS4_DB_ROUTER_PASSWORD in the
                 infra store, for the router's own copy; docs/STATE.md)
Only for secrets that can't reach a code push (Deyao, 2026-10-09); the pods get them as env (envFrom) or files. Prints
names only, never a value."""
import hashlib, json, os, re, subprocess, sys, tempfile, urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RT = "router/router.yaml"  # under k8s/cluster/
BOXES = {  # box → (age recipient file, secrets dir, {part: manifest path under k8s/<box>/})
    "cluster": ("keys/cluster-age.pub", "k8s/cluster/secrets", {
        "": RT, "wg": RT, "backup": RT, "github": RT, "flyorgs": RT, "flypersonal": RT, "flyvolumes": RT,
        "browserbase": RT, "devices": RT, "alloy": None, "tunnel": None, "postgres": None, "postgres-app": None,
        "search": "services/search/search.yaml", "icloud-index": "services/icloud-index/icloud-index.yaml",
        "icloud-session": "services/icloud-index/icloud-index.yaml",
        "db": RT, "objects": RT, "seal": RT, "wg-b": RT}),
}
RNS = "jarvis4-router"
PARTS = {  # part → (file, Secret name, annotation, namespace)
    "": ("router.enc.yaml", "router-secrets", "jarvis2/secrets-rev", RNS),
    "wg": ("router-wg.enc.yaml", "router-wg", "jarvis2/secrets-rev-wg", RNS),
    "backup": ("router-backup.enc.yaml", "router-secrets-backup", "jarvis2/secrets-rev-backup", RNS),
    "github": ("router-github.enc.yaml", "router-secrets-github", "jarvis2/secrets-rev-github", RNS),
    "flyorgs": ("router-flyorgs.enc.yaml", "router-secrets-flyorgs", "jarvis2/secrets-rev-flyorgs", RNS),
    "flypersonal": ("router-flypersonal.enc.yaml", "router-secrets-flypersonal", "jarvis2/secrets-rev-flypersonal", RNS),
    "flyvolumes": ("router-flyvolumes.enc.yaml", "router-secrets-flyvolumes", "jarvis2/secrets-rev-flyvolumes", RNS),
    "browserbase": ("router-browserbase.enc.yaml", "router-secrets-browserbase", "jarvis2/secrets-rev-browserbase", RNS),
    "devices": ("router-devices.enc.yaml", "router-secrets-devices", "jarvis2/secrets-rev-devices", RNS),
    "wg-b": ("router-wg-b.enc.yaml", "router-wg-b", "jarvis2/secrets-rev-wg-b", RNS),  # m-gateway-1's peer jarvis4-gw-b
    "seal": ("router-seal.enc.yaml", "router-seal", "jarvis2/secrets-rev-seal", RNS),  # the router's seal key (router/sealed.go)
    "objects": ("router-objects.enc.yaml", "router-secrets-objects", "jarvis2/secrets-rev-objects", RNS),  # jarvis4-snapshots-de0ch (infra/objects-key.py)
    "db": ("router-db.enc.yaml", "router-db", "jarvis2/secrets-rev-db", RNS),  # the router's DATABASE_URL (docs/STATE.md)
    "alloy": ("alloy.enc.yaml", "alloy", None, "jarvis2-obs"),
    "tunnel": ("tunnel.enc.yaml", "tunnel-token", None, "jarvis2-edge"),
    "postgres": ("postgres.enc.yaml", "postgres-s3", None, "jarvis4-db"),  # the database's backups (docs/STATE.md)
    "postgres-app": ("postgres-app.enc.yaml", "jarvis4-db-router", None, "jarvis4-db"),  # the database owner's login
}
SVC = "jarvis4-services"
PARTS |= {  # the services' parts live next to them (k8s/cluster/services/secrets), applied only once that tree is listed
    "search": ("search.enc.yaml", "search-secrets", "jarvis2/secrets-rev-search", SVC),
    "icloud-index": ("icloud-index.enc.yaml", "icloud-index-secrets", "jarvis2/secrets-rev-icloud-index", SVC),
    "icloud-session": ("icloud-session.enc.yaml", "icloud-index-session", "jarvis2/secrets-rev-icloud-session", SVC),
}
PART_DIRS = {p: "k8s/cluster/services/secrets" for p in ("search", "icloud-index", "icloud-session")}
SECRET_TYPES = {"postgres-app": "kubernetes.io/basic-auth"}  # CloudNativePG's initdb secret is basic-auth


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
    manifest = manifests[part] and os.path.join("k8s", box, manifests[part])
    secdir = PART_DIRS.get(part, secdir)
    out = os.path.join(ROOT, secdir, fname)
    data = {}
    for arg in args:
        key, _, src = arg.partition("=")
        src = src or "env:" + key
        kind, _, ref = src.partition(":")
        if kind == "env":
            v = os.environ.get(ref)
        elif kind == "dburl":  # the router's DATABASE_URL from the role router's password in env var ref
            pw = os.environ.get(ref)
            v = pw and "postgres://router:" + urllib.parse.quote(pw, safe="") + \
                "@jarvis4-db-rw.jarvis4-db.svc.cluster.local:5432/jarvis4?sslmode=require"
        elif kind == "file":
            v = open(os.path.expanduser(ref)).read().strip()
        else:
            sys.exit(f"{key}: SRC is env:VAR, file:PATH or dburl:VAR")
        if not v:
            sys.exit(f"{key}: {src} is empty")
        data[key] = v
    recipient = open(os.path.join(ROOT, keyfile)).read().strip()
    doc = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": secret, "namespace": namespace},
           "type": SECRET_TYPES.get(part, "Opaque"), "stringData": data}
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
