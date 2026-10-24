#!/usr/bin/env python3
"""The trusted setup session's side of Jarvis 4 (docs/DESIGN.md, docs/API.md "Setup"), through the router's
/setup/* (Access service token jarvis2-setup + a signature by the setup key on every call; the router checks
both). Values never print.

  JARVIS2_SETUP_KEY               the setup key (PEM, P-256); or ~/.jarvis2/setup-key.pem
  JARVIS2_SETUP_ACCESS_ID/SECRET  the Access service token for /setup; or ~/.jarvis2/cloudflare.env
  HETZNER_S3_*                    the backup buckets (writes jarvis4-backup-de0ch, reads jarvis2-backup-de0ch)

  infra/setup.py status                the router's health: secret names present, session image, core up
  infra/setup.py services              the shared services as the router reaches them: a check run on the watch runner
  infra/setup.py identity              whether the core is empty or set up (and with which master public key),
                                       checked against keys/box.pub and the core's own signature
  infra/setup.py stores [--keys]       every store (the core's signed list) with the key NAMES it holds (--keys: each
                                       key's explanation and writer)
  infra/setup.py create NAME           a new, empty, NOT sensitive store (once per name)
  infra/setup.py write NAME KEY[=SRC]… [--explain KEY=TEXT]…
                                       write these keys of a store, one by one (the store's other keys are never read
                                       or touched); each value from this session's env var KEY, or SRC: another env var
                                       name, or file:PATH. Each is sealed to the store key (phone + core) and, for its
                                       backup, to the master key the core was set up with; the router backs it up first
                                       (keys/<store>/<key>.json) and asks the phone to refresh the running sessions that
                                       hold the store. A key name that has no explanation yet needs --explain
  infra/setup.py delete NAME KEY…      delete these keys of a store (the backup keeps their earlier versions)
  infra/setup.py versions NAME         the store's earlier versions the core keeps (number, time, what made it, key
                                       names), from the core's signed list; put one back with `request restore`
  infra/setup.py docs NAME [--about TEXT] [KEY=TEXT…]
                                       what a store and its keys are for (shown in the app, the web page, `jarvis2 stores
                                       --keys`); KEY= with no text removes one
  infra/setup.py mark-sensitive NAME   the one-way upgrade, in the core and in the backup
  infra/setup.py backup NAME KEY[=SRC]… [--not-sensitive]
                                       a store's backup only, for the next Recover; sensitive unless
                                       --not-sensitive
  infra/setup.py kernel-root-key       the root key the Jarvis 4 app registered with the router (Settings → Kernel):
                                       written to keys/root.pub and k8s/cluster/kernel/root.pub (the ConfigMap the
                                       kernel's components check their roster with, KERNEL_ROOT); commit both
  infra/setup.py kernel-roster [--copy blue|green]
                                       a kernel copy's roster (docs/PLAN-cluster.md "The roster", "Releases: the copy
                                       flip"; default: the copy that serves): every component's GET /identity read
                                       through kernel-id.deyaochen.com (KERNEL_ID_ACCESS_ID/SECRET), the serving roster's
                                       keys it no longer names as retired (all of them for the other copy; a restarted
                                       component's old keys for the serving one), with the retired keys a line still
                                       needs (the router's retiredInUse), and for the other copy the serving secrets as
                                       its secrets and its own empty secrets as secretsBoot; printed, sig.Roster.Payload
                                       made byte for byte, signed with the setup key and filed with the router; Deyao
                                       signs it with the root key in the app. The other copy's roster, once signed,
                                       starts the copy flip (router/kernelflip.go)
  infra/setup.py kernel-flipped        after a copy flip: k8s/cluster/kernel/active-kernel.txt names the copy that
                                       serves now, its Deployments' release hold goes, the other copy goes to replicas 0
                                       (infra/kernel-pin.py flipped); commit and push
  infra/setup.py kernel-fly-token FILE the kernel's spawner's Fly token (FILE: infra/fly-token.sh's), sealed to the
                                       spawner's key as the root key's current roster names it (checked against
                                       keys/root.pub); again after every spawner restart (and its new roster)
  infra/setup.py backup-core FILE      the core's Fly token, FLY_API_TOKEN from FILE (infra/fly-token.sh):
                                       sent to the core sealed to its key, and backed up as the `core` store
  infra/setup.py claude-accounts       the router's Claude accounts (no secrets): per account its email, expiry,
                                       refresh state, participants of the refresh protocol, the sessions using it,
                                       and which is the default (router/claudeaccounts.go)
  infra/setup.py claude-login          the same for the default account only
  infra/setup.py repos                 the router's repo list (repo, store, key fingerprint)
  infra/setup.py sessions [-v]         the router's sessions: id, current machine, state, title, and a failed one's reason
                                       and when (-v: also the autopilot's view, a lost machine's details)
  infra/setup.py lease take-over|hand-back DEVICE [--note TEXT]
                                       for Deyao: take a shared device over (agents refused) or hand it back
  infra/setup.py pause SESSION         cancel its wakeups and crons, then pause it (its snapshot if the machine answers)
  infra/setup.py resume SESSION        resume a paused session on its own image, no prompt (a pre-router-login Claude image:
                                       a resume-upgrade approval in the Inbox instead, DECISIONS 154)
  infra/setup.py restart SESSION       pause + resume as the app's Restart; wakeups and crons stay armed
  infra/setup.py destroy SESSION [--force]
                                       the app's Destroy: pause (its final snapshot), archive to the Storage Box, end
                                       the line, keep the record; a failed archive leaves it paused unless --force
  infra/setup.py requests              what waits in the phone's Inbox (requests and approvals)
  infra/setup.py jarvis1               Jarvis 1's paused sessions (its index) and each one's import state here
  infra/setup.py jarvis1 prepare ID… [--wait]
                                       the router hashes each paused Jarvis 1 session's files (in the background)
  infra/setup.py jarvis1 import ID [ID…] --stores a,b [--size S] [--prompt-file F] --why TEXT [--summary TEXT]
                                       a prepared one as a new Jarvis 4 session, waiting in the Inbox for Face ID
                                       (its cert names the import manifest's sha256; docs/API.md "Jarvis 1 import");
                                       several IDs (or --summary) file them as ONE batch, allowed under one Face ID
  infra/setup.py request add-repo OWNER/NAME --why TEXT [--sensitive]
  infra/setup.py request remove-repo OWNER/NAME --why TEXT
  infra/setup.py request grant SESSION HOLDER [--minutes N | --days N] --why TEXT
  infra/setup.py request unlock SESSION --why TEXT
  infra/setup.py request restore STORE VERSION --why TEXT
                                       a request in the Inbox of the Jarvis 4 app (docs/API.md "Requests"): Deyao
                                       reviews what would be signed and allows it with Face ID, or denies it. The
                                       router records it as from "Claude (setup session)"; --why is required
  infra/setup.py request batch (--file FILE | --item INTENT,key=value,…) --summary TEXT
                                       several requests as ONE Inbox entry (allowed together under one Face ID, or
                                       denied together): FILE is a JSON list of items, each {"intent": …} plus that
                                       intent's fields (repo/add, repo/remove, grant, unlock, add-store, new-session,
                                       jarvis1-import; docs/API.md "Batches"), each with an optional "explanation"

Everything is sealed to the master public key the core was set up with (Reset or Recover in the app), which
this script reads from the core's signed state, after checking the core's keys against keys/box.pub — so it
works only once the core is set up. A store the core never created (no `create` first) is sensitive.
On a box with no core (the cluster: NO_CORE=1) the router sends every store call to the kernel's serving secrets,
which has the core's store routes; its keys are checked against the root key's roster (keys/root.pub) instead.
"""
import base64, hashlib, json, os, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE = os.environ.get("JARVIS2_URL", "https://jarvis4.deyaochen.com")
D = os.path.expanduser("~/.jarvis2")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# what this script writes (store backups, sensitivity markers, the pins) goes to Jarvis 4's own bucket; Jarvis 2's
# (READ_BUCKET) is only read: the pins until Jarvis 4's bucket has its own (the router serves both to the Recover)
BUCKET = os.environ.get("JARVIS2_BACKUP_BUCKET", "jarvis4-backup-de0ch")
READ_BUCKET = os.environ.get("JARVIS2_BACKUP_READ_BUCKET", "jarvis2-backup-de0ch")

# ---- P-256 point addition (the combined key P + K; the cryptography library has no point add) ----------
_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff


def _pt(b64):
    raw = base64.b64decode(b64)
    assert len(raw) == 65 and raw[0] == 4
    return int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")


def _add(P, Q):
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2:
        raise SystemExit("P == ±K: refusing")
    l = (y2 - y1) * pow(x2 - x1, -1, _p) % _p
    x3 = (l * l - x1 - x2) % _p
    return x3, (l * (x1 - x3) - y1) % _p


def _pub(x, y):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big"))


def _kdf(secret, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode()).derive(secret)


def _gcm(key, plain, aad=None):
    n = os.urandom(12)
    return n + AESGCM(key).encrypt(n, plain, aad)


def _x963(pub):
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _verify(pub_b64, payload, sig_b64):
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ---- the router -------------------------------------------------------------------------------------------

def setup_key():
    pem = os.environ.get("JARVIS2_SETUP_KEY") or open(os.path.join(D, "setup-key.pem")).read()
    return serialization.load_pem_private_key(pem.encode(), None)


def access():
    i, s = os.environ.get("JARVIS2_SETUP_ACCESS_ID"), os.environ.get("JARVIS2_SETUP_ACCESS_SECRET")
    if not (i and s):
        v = dict(l.rstrip("\n").split("=", 1) for l in open(os.path.join(D, "cloudflare.env")) if "=" in l)
        i, s = v["SETUP_ACCESS_ID"], v["SETUP_ACCESS_SECRET"]
    return {"CF-Access-Client-Id": i, "CF-Access-Client-Secret": s}


def call(method, path, body=None):
    raw = json.dumps(body).encode() if body is not None else b""
    t = str(int(time.time()))
    msg = f"{method} {path} {t} {hashlib.sha256(raw).hexdigest()}".encode()
    h = dict(access(), **{"Content-Type": "application/json", "User-Agent": "jarvis2-setup/1", "X-Setup-Time": t,
                          "X-Setup-Sig": base64.b64encode(setup_key().sign(msg, ec.ECDSA(hashes.SHA256()))).decode()})
    req = urllib.request.Request(BASE + path, method=method, data=raw if body is not None else None, headers=h)
    try:
        return json.load(urllib.request.urlopen(req, timeout=60))
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            d = json.loads(b)
            msg = json.loads(d["payload"]).get("error") if "payload" in d else d
        except Exception:
            msg = b[:200]
        raise SystemExit(f"{path}: HTTP {e.code}: {msg}")


def keyfile(name):
    """keys/<name> from this checkout (JARVIS2_KEYS_DIR: another directory, for CI's stand-in keys)"""
    return open(os.path.join(os.environ.get("JARVIS2_KEYS_DIR") or os.path.join(ROOT, "keys"), name)).read().strip()


def identity():
    """the core's keys (checked against the box key, keys/box.pub) and its own signed state: {signingKey,
    agreementKey, master: the master public key it was set up with ("" while empty), phone: its keys or None}"""
    k = call("GET", "/setup/identity")
    if k.get("role") == "secrets":
        return kernel_identity(k)
    text = f"jarvis2-core-identity {k['signingKey']} {k['agreementKey']}".encode()
    if not _verify(keyfile("box.pub"), text, k.get("boxSig", "")):
        raise SystemExit("the core's identity isn't signed by this box's key (keys/box.pub)")
    d = k.get("state") or {}
    if not _verify(k["signingKey"], (d.get("payload") or "").encode(), d.get("sig") or ""):
        raise SystemExit("the core's state isn't signed by the core")
    st = json.loads(d["payload"])
    if st.get("kind") != "core-state":
        raise SystemExit("not the core's state")
    return {"signingKey": k["signingKey"], "agreementKey": k["agreementKey"], "master": st.get("master") or "", "phone": st.get("phone")}


def kernel_identity(k):
    """the kernel's secrets (a box with no core: the router's store calls go there): no box key, so its keys are checked
    against the root key's roster (keys/root.pub), then its own signed state; the same shape as identity()"""
    m = roster_members(call("GET", "/setup/kernel/roster").get("current")).get("secrets")
    if not m or m["signingKey"] != k.get("signingKey") or m["agreementKey"] != k.get("agreementKey"):
        raise SystemExit("the serving secrets' keys aren't the ones the root key's roster names")
    d = k.get("state") or {}
    if not _verify(k["signingKey"], (d.get("payload") or "").encode(), d.get("sig") or ""):
        raise SystemExit("secrets' state isn't signed by secrets")
    st = json.loads(d["payload"])
    if st.get("kind") != "secrets-state" or st.get("serving") != "serving":
        raise SystemExit("not the serving secrets' state")
    return {"signingKey": k["signingKey"], "agreementKey": k["agreementKey"], "master": st.get("master") or "",
            "phone": st.get("phone"), "kernel": True}


def set_up():
    """the core, only once it is set up (Reset or Recover in the app) by Deyao: the master key and the phone it names.
    Claim is first-come, so the core's word isn't enough (R1 audit): its master key must be the one pinned in the
    bucket, or its claim must be countersigned by Deyao's pinned device key (a Reset in his app)."""
    me = identity()
    if not me["master"] or not me["phone"]:
        raise SystemExit("the core is empty: Deyao sets it up in the app first (Reset or Recover)")
    trust(me)
    return me


# ---- whose core it is: the pins (pins.json in the bucket, signed by the setup key) ----------------------------
#
# master: the master public key the stores belong to; device: the app's long-lived device key (kept across Reset and
# Recover). A claim under the pinned master pins the device key it carries; a claim countersigned by the pinned device
# key moves the master pin (Deyao's Reset). Anything else — a core someone else claimed first — gets nothing from here.

def load_pins():
    o = None
    for b in dict.fromkeys([BUCKET, READ_BUCKET]):
        try:
            o = s3().get_object(Bucket=b, Key="pins.json")["Body"].read()
            break
        except Exception as e:
            if "NoSuchKey" not in str(e) and "404" not in str(e):
                raise
    if o is None:
        return {}
    d = json.loads(o)
    if not _verify(keyfile("setup.pub"), d["doc"].encode(), d["sig"]):
        raise SystemExit("pins.json in the bucket isn't signed by the setup key")
    p = json.loads(d["doc"])
    if p.get("kind") != "setup-pins":
        raise SystemExit("pins.json isn't the setup pins")
    return p


def save_pins(master, device):
    doc = json.dumps({"kind": "setup-pins", "master": master, "device": device, "at": int(time.time())})
    s3().put_object(Bucket=BUCKET, Key="pins.json", Body=json.dumps(signed(doc)).encode())


def claim_of(me):
    """the claim statement the core holds (checked: signed by its master key, naming this core and its phone), the
    device key it names (the app's long-lived key, inside the master-signed statement) and whether the router kept
    that device's countersignature over exactly this statement"""
    cc = call("GET", "/setup/core-cert")
    st_text = cc.get("statement") or ""
    if not _verify(me["master"], st_text.encode(), cc.get("masterSig") or ""):
        raise SystemExit("the core's claim isn't signed by its master key")
    st = json.loads(st_text)
    # a claim with the master key's seed names the keys the core takes from it as `identity` (core/continuity.go)
    named = st.get("identity") or st.get("core") or {}
    if st.get("master") != me["master"] or named.get("signingKey") != me["signingKey"] or \
            named.get("agreementKey") != me["agreementKey"] or st.get("phone") != me["phone"]:
        raise SystemExit("the core's claim names another master, core or phone")
    device = st.get("device") or ""
    countersigned = bool(device) and any(
        d.get("statement") == st_text and d.get("deviceKey") == device and _verify(device, st_text.encode(), d.get("deviceSig") or "")
        for d in call("GET", "/setup/claim-device"))
    return device, countersigned


def trust(me):
    pins = load_pins()
    if not pins.get("master"):
        raise SystemExit("no master key pinned yet: once the core is known to be Deyao's (a Recover by him), "
                         "run `infra/setup.py pin-master` (docs/RUNBOOK.md)")
    if me.get("kernel"):
        # secrets' keys are the root key's (its roster), and it was claimed with the master key it names: the stores'
        # master must be the pinned one (a Reset to a new master is pinned from the core's countersigned claim only)
        if pins["master"] != me["master"]:
            raise SystemExit("REFUSED: the kernel's secrets is set up with a master key that isn't the pinned one: nothing is written")
        return
    device, countersigned = claim_of(me)
    if pins["master"] == me["master"]:
        if device and device != pins.get("device"):  # his app's device key, named in a claim his master key signed
            save_pins(me["master"], device)
        return
    if pins.get("device") and device == pins["device"] and countersigned:
        save_pins(me["master"], device)  # Deyao's Reset: a new master, countersigned by his device
        print(f"note: new master key {me['master'][:16]}… pinned (its claim is countersigned by the pinned device key)", file=sys.stderr)
        return
    raise SystemExit("REFUSED: the core is set up with a master key that isn't the pinned one, and its claim isn't "
                     "countersigned by Deyao's device key. Someone other than Deyao's app may have claimed it: nothing "
                     "is written, backed up or sent. Restart the core from git (RUNBOOK \"Emptying the core\") and set it up in the app.")


# ---- stores ---------------------------------------------------------------------------------------------

def store_key(phone_agreement, core_agreement):
    """P + K, the key every store key is wrapped to (from the core's state, checked against the box key)"""
    return _pub(*_add(_pt(phone_agreement), _pt(core_agreement)))


def writer_text(store, key, e, data, backup_sha):
    """core.WriterText: what a key's writer signs"""
    sum_ = hashlib.sha256(data.encode()).hexdigest() if data else ""
    return f"jarvis2-store-key\n{store}\n{key}\n{e}\n{sum_}\n{backup_sha}"


def key_write(store, key, value, me, explanation=""):
    """router keyWriteIn for one key: the value sealed to the store key (AAD store\nkey), its backup sealed to the master
    key, both signed by the setup key (value None = a delete)"""
    req = {"delete": value is None, "explanation": explanation}
    e = data = bsha = ""
    if value is not None:
        dk = os.urandom(32)
        ek = ec.generate_private_key(ec.SECP256R1())
        shared_x = ek.exchange(ec.ECDH(), store_key(me["phone"]["agreementKey"], me["agreementKey"]))
        e = base64.b64encode(_x963(ek.public_key())).decode()
        aad = f"{store}\n{key}".encode()
        data = base64.b64encode(_gcm(dk, value.encode(), aad)).decode()
        b = seal_to(me["master"], value.encode(), "jarvis2/backup", aad)
        bsha = hashlib.sha256((b["e"] + "\n" + b["data"]).encode()).hexdigest()
        req.update({"wrapped": {"e": e, "wrapped": base64.b64encode(_gcm(_kdf(shared_x, "jarvis2/store-data-key"), dk)).decode()},
                    "data": data, "backup": b, "backupSha256": bsha})
        if me.get("kernel"):  # the live copy, sealed to secrets: an open unlock of the store gets the value at once
            req["live"] = seal_to(me["agreementKey"], value.encode(), f"jarvis2/live-key\n{store}\n{key}")
    req["sig"] = base64.b64encode(setup_key().sign(writer_text(store, key, e, data, bsha).encode(), ec.ECDSA(hashes.SHA256()))).decode()
    return req


# the stores this writer means to be NOT sensitive (created first); every other store it writes is sensitive. The
# core's open create_store lets anyone (the router) create a name first, so the writer checks the core's word against
# this list and marks a store sensitive before it writes into it (R1 audit). A change here is a visible commit.
NOT_SENSITIVE = ("default", "openrouter", "tunnel", "shopping") + tuple(
    n for n in os.environ.get("JARVIS2_NOT_SENSITIVE", "").split(",") if n)  # test boxes add their own (rehearsals)


def s3():
    import boto3
    return boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                        aws_access_key_id=os.environ["HETZNER_S3_ACCESS_KEY"], aws_secret_access_key=os.environ["HETZNER_S3_SECRET_KEY"])


def seal_to(pub_b64, plain, info, aad=None):
    """{e, data}: sealed to a P-256 public key — ECDH with a one-off key, HKDF-SHA256 (info), AES-256-GCM"""
    to = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(pub_b64))
    e = ec.generate_private_key(ec.SECP256R1())
    return {"e": base64.b64encode(_x963(e.public_key())).decode(),
            "data": base64.b64encode(_gcm(_kdf(e.exchange(ec.ECDH(), to), info), plain, aad)).decode()}


def signed(doc):
    """{doc, sig}: the document text and the setup key's signature over it"""
    return {"doc": doc, "sig": base64.b64encode(setup_key().sign(doc.encode(), ec.ECDSA(hashes.SHA256()))).decode()}


def backup(name, values, sensitive, master, at=None):
    """stores/<name>.json in the versioned bucket: the values sealed to the master key (info "jarvis2/backup",
    the store's name as associated data), signed by the setup key"""
    sealed = seal_to(master, json.dumps(values).encode(), "jarvis2/backup", name.encode())
    doc = json.dumps({"kind": "store-backup", "name": name, "sensitive": sensitive, "sealed": sealed,
                      "at": int(time.time()) if at is None else at})
    s3().put_object(Bucket=BUCKET, Key=f"stores/{name}.json", Body=json.dumps(signed(doc)).encode())


def mark_sensitive_backup(name):
    """sensitive/<name>.json: a signed marker; at a Recover a store with one is sensitive whatever its backup says"""
    doc = json.dumps({"kind": "store-sensitive", "name": name, "at": int(time.time())})
    s3().put_object(Bucket=BUCKET, Key=f"sensitive/{name}.json", Body=json.dumps(signed(doc)).encode())


def store_list():
    d = call("POST", "/setup/stores", {"nonce": "setup-" + str(int(time.time()))})
    return {s["name"]: s for s in json.loads(d["payload"])["stores"]}


def value(spec):
    key, _, src = spec.partition("=")
    src = src or key
    if src.startswith("file:"):
        return key, open(os.path.expanduser(src[5:])).read().strip()
    if src not in os.environ:
        raise SystemExit(f"not in this session's env: {src}")
    return key, os.environ[src]


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "status":
        print(json.dumps(call("GET", "/setup/status"), indent=1))
    elif cmd == "services":
        print(json.dumps(call("GET", "/setup/services"), indent=1))
    elif cmd == "identity":
        me = identity()
        print(f"set up with master key {me['master'][:16]}…" if me["master"] else "empty: waiting for Reset or Recover in the app")
    elif cmd == "stores":
        for s in call("GET", "/setup/stores/keys")["stores"]:
            flags = ["sensitive" if s["sensitive"] else "not-sensitive"] + (["empty"] if s["empty"] else []) + (["unlocked"] if s["unlocked"] else [])
            print(f"{s['name']} [{', '.join(flags)}]: {' '.join(s['keys'])}")
            if "--keys" in args:
                if s.get("about"):
                    print("  " + s["about"])
                for k in s.get("keyInfo") or []:
                    w = k.get("writer") or {}
                    by = f" [written by session {w.get('sessionLabel')} {w.get('session')}]" if w.get("by") == "machine" else ""
                    print(f"  {k['name']}: {k.get('explanation') or '(no explanation yet)'}{by}")
    elif cmd == "docs":
        about, rest = None, args[1:]
        if "--about" in rest:
            i = rest.index("--about")
            about, rest = rest[i + 1], rest[:i] + rest[i + 2:]
        body = {"store": args[0], "keys": dict(a.split("=", 1) for a in rest)}
        if about is not None:
            body["about"] = about
        call("POST", "/setup/store-docs", body)
        print(f"ok: {args[0]}: {len(body['keys'])} explanation(s)" + (" and its about text" if about is not None else "") + " kept")
    elif cmd == "delete":
        me = identity()  # a delete seals nothing (only the setup key signs it), so no master pin is needed
        for k in args[1:]:
            out = call("POST", f"/setup/stores/{args[0]}/keys/{k}", key_write(args[0], k, None, me))
            print(f"ok: {args[0]}: {k} deleted; sessions holding it get the change at their next pull with a new cert")
    elif cmd == "pin-master":
        me = identity()
        if not me["master"]:
            raise SystemExit("the core is empty")
        device, _ = claim_of(me)
        save_pins(me["master"], device or load_pins().get("device"))
        print(f"ok: master key {me['master'][:16]}… pinned" + (" with the app's device key" if device else ""))
    elif cmd == "create":
        if args[0] not in NOT_SENSITIVE:
            raise SystemExit(f"{args[0]} isn't in NOT_SENSITIVE (infra/setup.py): a store not listed there stays sensitive")
        me = set_up()
        call("POST", "/setup/stores/create", {"name": args[0]})
        # the backup says so too: a store with only key backups reads as sensitive offline and at a Recover (the core
        # makes a store sensitive on its first key unless it was created like this). Empty, and a second early, so a key
        # written in the same second still lays over it (tools/decrypt-backup.py skips key backups not after it)
        backup(args[0], {}, False, me["master"], at=int(time.time()) - 1)
        print(f"ok: store {args[0]} created (empty, not sensitive) and its not-sensitive backup written")
    elif cmd == "write":
        explain = {}
        while "--explain" in args:
            i = args.index("--explain")
            k, _, t = args[i + 1].partition("=")
            explain[k] = t
            del args[i:i + 2]
        name, vals = args[0], dict(value(a) for a in args[1:])
        me = set_up()
        want_sensitive = name not in NOT_SENSITIVE
        have = store_list().get(name)
        if want_sensitive and have is not None and not have["sensitive"]:
            # created not sensitive by someone else (the open create_store): upgraded before anything is in it
            call("POST", "/setup/stores/mark-sensitive", {"name": name})
            mark_sensitive_backup(name)
            print(f"note: {name} existed as not sensitive; marked sensitive before writing", file=sys.stderr)
        for k in sorted(vals):
            out = call("POST", f"/setup/stores/{name}/keys/{k}", key_write(name, k, vals[k], me, explain.get(k, "")))
            print(f"ok: {name}: {k} written (backed up first); sessions holding it get it at their next pull with a new cert")
        if want_sensitive and not store_list()[name]["sensitive"]:
            # the one-way upgrade, at once (it only adds protection), rather than stopping with it undone
            call("POST", "/setup/stores/mark-sensitive", {"name": name})
            mark_sensitive_backup(name)
            print(f"note: the core called {name} not sensitive after the write: marked sensitive now", file=sys.stderr)
        if explain:
            call("POST", "/setup/store-docs", {"store": name, "keys": explain})
    elif cmd == "versions":
        me = identity()
        d = call("POST", "/setup/stores/versions", {"store": args[0], "nonce": "setup-" + str(int(time.time()))})
        if not _verify(me["signingKey"], d["payload"].encode(), d["sig"]):
            raise SystemExit("the versions aren't signed by the core")
        v = json.loads(d["payload"])
        for x in v["versions"]:
            c = x["cause"]
            what = c["kind"] + (f" {c['key']}" if c.get("key") else "") + (f" by {c['writer']['by']}" if c.get("writer") else "") + \
                (f" of version {c['from']}" if c.get("from") else "")
            cur = " (current)" if x["version"] == v["current"] else ""
            print(f"{x['seq']}{cur} {x['at']} {what}: {len(x['keys'])} keys: {' '.join(k['name'] for k in x['keys'])}")
    elif cmd == "mark-sensitive":
        # no trust check: the one-way upgrade only adds protection, whoever answers
        call("POST", "/setup/stores/mark-sensitive", {"name": args[0]})
        mark_sensitive_backup(args[0])
        print(f"ok: {args[0]} is sensitive, in the core and in the backup")
    elif cmd == "backup":
        plain = "--not-sensitive" in args
        args = [a for a in args if a != "--not-sensitive"]
        backup(args[0], dict(value(a) for a in args[1:]), not plain, set_up()["master"])
        print(f"ok: backup of {args[0]} written (sensitive={not plain}); it comes in at the next Recover")
    elif cmd == "backup-core":
        me = set_up()
        tok = {"FLY_API_TOKEN": open(os.path.expanduser(args[0])).read().strip()}
        call("POST", "/setup/fly-token", {"sealed": seal_to(me["agreementKey"], json.dumps(tok).encode(), "jarvis2/fly-token")})
        backup("core", tok, True, me["master"])
        print("ok: the core has its Fly token, and the core store's backup is written")
    elif cmd == "kernel-fly-token":
        # the kernel's spawner (kernel/spawner): its identity checked against the root key's roster, the token sealed to it
        d = call("GET", "/setup/kernel/spawner/identity")
        ident = json.loads(d["payload"])
        if not _verify(ident["signingKey"], d["payload"].encode(), d["sig"]):
            raise SystemExit("the spawner's identity document isn't signed by the spawner")
        member = roster_members(call("GET", "/setup/kernel/roster").get("current")).get("spawner")
        if ident.get("role") != "spawner" or member != {k: ident.get(k) for k in ("role", "signingKey", "agreementKey")}:
            raise SystemExit("the spawner's keys aren't the ones the root key's current roster names (a restart? sign a new roster)")
        tok = {"FLY_API_TOKEN": open(os.path.expanduser(args[0])).read().strip()}
        call("POST", "/setup/kernel/spawner/fly-token", {"sealed": seal_to(ident["agreementKey"], json.dumps(tok).encode(), "jarvis2/fly-token")})
        print("ok: the kernel's spawner has its Fly token (send it again after the spawner restarts)")
    elif cmd == "kernel-root-key":
        k = call("GET", "/setup/kernel/root-key")["rootKey"]
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(k, validate=True))
        except Exception:
            raise SystemExit("the router's root key isn't a P-256 public key")
        write_root_key(k)
        print(f"ok: root key {k[:16]}… written to keys/root.pub and k8s/cluster/kernel/root.pub: commit and push both")
    elif cmd == "kernel-roster":
        kernel_roster(opt(args, "--copy"))
    elif cmd == "kernel-flipped":
        kernel_flipped()
    elif cmd == "claude-login":
        print(json.dumps(call("GET", "/setup/claude-login"), indent=1))
    elif cmd == "claude-accounts":
        print(json.dumps(call("GET", "/setup/claude-accounts"), indent=1))
    elif cmd == "repos":
        for r in call("GET", "/setup/repos")["repos"]:
            print(r["repo"], r["store"], r.get("fingerprint") or "no key yet", "sensitive" if r.get("sensitive") else "")
    elif cmd == "sessions":
        for s in call("GET", "/setup/sessions")["sessions"]:
            print(s["id"], s["machineId"] or "-", s["state"], s["title"])
            if s.get("error"):  # why it failed (router/failures.go), or what a stopped machine left (router/lostmachine.go)
                print("    error" + (f" (since {s['failedAt']})" if s.get("failedAt") else "") + ":", s["error"])
            if "-v" in args:  # the autopilot's view: status, background jobs, stall clock, last nudge
                print("   ", json.dumps({k: v for k, v in s.items() if k not in ("id", "machineId", "state", "title", "error")}, sort_keys=True))
    elif cmd == "lease":
        if len(args) < 2 or args[0] not in ("take-over", "hand-back"):
            raise SystemExit(__doc__)
        act, dev = args[0], args[1]
        note = opt(args, "--note")
        print(json.dumps(call("POST", f"/setup/leases/{dev}/{act}", {"note": note} if note is not None else {}), indent=1))
    elif cmd in ("resume", "restart"):
        print(json.dumps(call("POST", "/setup/sessions/" + args[0] + "/" + cmd, {})))
    elif cmd == "pause":
        # pause (the snapshot if the machine answers) and cancel its wakeups and crons first
        print(json.dumps(call("POST", "/setup/sessions/" + args[0] + "/pause", {})))
    elif cmd == "destroy":
        if not args or args[0].startswith("-") or any(a != "--force" for a in args[1:]):
            raise SystemExit("destroy SESSION [--force]")
        # force goes in the body, which the setup signature covers
        print(json.dumps(call("POST", "/setup/sessions/" + args[0] + "/destroy", {"force": "--force" in args[1:]})))
    elif cmd == "requests":
        out = call("GET", "/setup/requests")
        for q in out["requests"]:
            c = q.get("call") or {}
            print(q["id"], q["kind"], json.dumps(q.get("params") or {}, sort_keys=True), "from", q["callerText"], "·", c.get("method", ""), c.get("path", ""),
                  ("· batch " + q["batch"]) if q.get("batch") else "")
        for b in out.get("batches") or []:
            print(b["id"], "batch of", len(b["items"]), f"(+{b['preparing']} preparing)" if b.get("preparing") else "", "from", b["callerText"], "|", b["summary"])
    elif cmd == "request":
        print(json.dumps(file_request(args), indent=1))
    elif cmd == "jarvis1":
        jarvis1(args)
    else:
        raise SystemExit(__doc__)


# ---- the kernel's roster (docs/PLAN-cluster.md "The roster") ----------------------------------------------------

KERNEL_ROLES = ["notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible", "minter"]


def write_root_key(k):
    """keys/root.pub (what the app and setup sessions read) and the copy the kernel's ConfigMap is made from (no
    newline: it becomes KERNEL_ROOT)"""
    keys = os.environ.get("JARVIS2_KEYS_DIR") or os.path.join(ROOT, "keys")
    with open(os.path.join(keys, "root.pub"), "w") as f:
        f.write(k + "\n")
    with open(os.path.join(ROOT, "k8s", "cluster", "kernel", "root.pub"), "w") as f:
        f.write(k)


def go_json(s):
    """a JSON string exactly as Go's encoding/json writes it: UTF-8 kept, <, >, & and U+2028/U+2029 escaped"""
    out = json.dumps(s, ensure_ascii=False)
    for c, e in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        out = out.replace(c, e)
    return out


def roster_payload(copy, members, retired=(), boot=None):
    """sig.Roster.Payload byte for byte: json.Marshal(Roster{Kind, Copy, Members sorted by role, Retired sorted by role
    and signing key (omitted when none), SecretsBoot (omitted when none)}), the struct's field order, no spaces"""
    one = lambda m: "{" + ",".join(f'"{k}":{go_json(m[k])}' for k in ("role", "signingKey", "agreementKey")) + "}"
    ms = sorted(members, key=lambda m: m["role"].encode())
    out = '{"kind":"kernel-roster","copy":' + go_json(copy) + ',"members":[' + ",".join(one(m) for m in ms) + "]"
    rs = sorted(retired, key=lambda m: (m["role"].encode(), m["signingKey"].encode()))
    if rs:
        out += ',"retired":[' + ",".join(one(m) for m in rs) + "]"
    if boot:
        out += ',"secretsBoot":' + one(boot)
    return out + "}"


def roster_members(doc):
    """role → member of a roster the root key (keys/root.pub) signed ({} when there is none)"""
    return roster_open(doc).get("members", {})


def roster_open(doc):
    """a roster the root key (keys/root.pub) signed: {"copy", "members": role → member, "retired": [member…]} ({} when
    there is none)"""
    if not doc:
        return {}
    if not _verify(keyfile("root.pub"), doc["payload"].encode(), doc["sig"]):
        raise SystemExit("the router's current roster isn't signed by the root key (keys/root.pub)")
    r = json.loads(doc["payload"])
    return {"copy": r["copy"], "members": {m["role"]: m for m in r["members"]}, "retired": r.get("retired") or []}


def kernel_id(path):
    """GET kernel-id.deyaochen.com/<path> (the read-only identity gateway, behind Access)"""
    base = os.environ.get("KERNEL_ID_URL", "https://kernel-id.deyaochen.com")
    h = {"CF-Access-Client-Id": os.environ["KERNEL_ID_ACCESS_ID"], "CF-Access-Client-Secret": os.environ["KERNEL_ID_ACCESS_SECRET"],
         "User-Agent": "jarvis2-setup/1"}
    try:
        return json.load(urllib.request.urlopen(urllib.request.Request(base + path, headers=h), timeout=30))
    except urllib.error.HTTPError as e:
        raise SystemExit(f"kernel-id {path}: HTTP {e.code}: {e.read()[:200]!r}")


def component_identity(dep):
    """a component's identity as it answers GET /identity: self-signed (nobody vouches yet: the roster will)"""
    d = kernel_id(f"/{dep}/identity")
    if dep.startswith("secrets-"):
        m = {"role": d.get("role"), "signingKey": d.get("signingKey"), "agreementKey": d.get("agreementKey")}
        st = d.get("state") or {}
        if m["role"] != "secrets" or not _verify(m["signingKey"] or "", (st.get("payload") or "").encode(), st.get("sig") or ""):
            raise SystemExit(f"{dep}: not a secrets identity signed with its own key")
        return m, json.loads(st["payload"])
    m = json.loads(d["payload"])
    role = dep.rsplit("-", 1)[0]
    if m.get("role") != role or not _verify(m.get("signingKey") or "", d["payload"].encode(), d.get("sig") or ""):
        raise SystemExit(f"{dep}: not a {role} identity signed with its own key")
    return {k: m[k] for k in ("role", "signingKey", "agreementKey")}, None


def kernel_roster(copy=None):
    cur = call("GET", "/setup/kernel/roster")
    serving = cur["serving"]
    copy = copy or serving
    if copy not in ("blue", "green"):
        raise SystemExit("--copy: blue or green")
    now = roster_open(cur.get("current"))
    takeover = bool(now) and copy != serving  # the other copy: it takes over from the serving one
    members, boot = [], None
    for role in KERNEL_ROLES + ["secrets"]:
        dep = f"{role}-{copy}"
        m, state = component_identity(dep)
        if role == "secrets":
            empty = not state.get("master")
        if role == "secrets" and takeover:
            if state.get("master"):
                raise SystemExit(f"{dep} is set up: the copy that takes over starts with an empty secrets (its release restarts it)")
            boot, m = m, now["members"]["secrets"]  # it serves with the keys the kit derives: the serving secrets'
        members.append(m)
        extra = f" ({dep}: {state.get('serving')}, master {'set' if state.get('master') else 'none'})" if state else ""
        print(f"  {m['role']:10} signing {m['signingKey'][:24]}…  agreement {m['agreementKey'][:24]}…{extra}")
    keys = {m["signingKey"] for m in members}
    # retired: for the other copy every serving member (it takes over from them); and the serving roster's keys this
    # one no longer names that a line still holds something signed by (a restarted component's old keys; none when the
    # kernel started empty, so its new volumes serve)
    retired = [m for r, m in now.get("members", {}).items() if takeover and r != "secrets"]
    named = list(now.get("members", {}).values()) + now.get("retired", [])  # only keys the root key named
    still = [m for m in (cur.get("retiredInUse") or []) if m in named and m["role"] != "secrets"]
    for m in still:
        if m not in retired and m["signingKey"] not in keys:
            retired.append(m)
    for m in retired:
        print(f"  {m['role']:10} signing {m['signingKey'][:24]}…  (retired)")
    if boot:
        print(f"  {'secrets':10} signing {boot['signingKey'][:24]}…  (empty, takes over: secretsBoot)")
    payload = roster_payload(copy, members, retired, boot)
    setup_sig = base64.b64encode(setup_key().sign(payload.encode(), ec.ECDSA(hashes.SHA256()))).decode()
    out = call("POST", "/setup/kernel/roster", {"copy": copy, "payload": payload, "setupSig": setup_sig})
    if takeover:
        then = "Deyao signs it in the app: Settings → Kernel → Sign roster (the router then flips to it by itself; then infra/setup.py kernel-flipped)"
    elif empty:
        then = "its secrets is empty: Deyao Recovers it in the app (Settings → Kernel → Recover the kernel's secrets), which signs this roster with the keys his kit derives"
    else:
        then = "Deyao signs it in the app: Settings → Kernel → Sign roster"
    print(f"ok: roster {out['id'][:16]}… (copy {copy}, {len(retired)} retired) filed; {then}")


def kernel_flipped():
    """after a copy flip: active-kernel.txt names the serving copy, its hold goes, the other copy goes to replicas 0"""
    cur = call("GET", "/setup/kernel/roster")
    if cur.get("flip"):
        raise SystemExit(f"the flip to {cur['flip']['to']} isn't done ({cur['flip'].get('waiting') or 'under way'}): nothing changed")
    serving = cur["serving"]
    if roster_open(cur.get("current")).get("copy") != serving:
        raise SystemExit("the router's current roster isn't the serving copy's: nothing changed")
    kd = os.path.join(ROOT, "k8s", "cluster", "kernel")
    subprocess.run([sys.executable, os.path.join(ROOT, "infra", "kernel-pin.py"), "flipped", os.path.join(kd, "kernel.yaml"), serving], check=True)
    with open(os.path.join(kd, "active-kernel.txt"), "w") as f:
        f.write(serving + "\n")
    print(f"ok: {serving} serves: active-kernel.txt, its holds deleted and {'green' if serving == 'blue' else 'blue'} at replicas 0 in "
          "k8s/cluster/kernel/: commit and push")


def parse_item(spec):
    """--item INTENT,key=value,…: one batch item (numbers become numbers, true/false booleans, a|b lists)"""
    parts = spec.split(",")
    item = {"intent": parts[0]}
    for kv in parts[1:]:
        if "=" not in kv:
            raise SystemExit(f"--item {spec}: {kv!r} is not key=value")
        k, v = kv.split("=", 1)
        item[k] = int(v) if v.isdigit() else {"true": True, "false": False}.get(v, v.split("|") if "|" in v else v)
    return item


def opt(args, name, default=None):
    """--name VALUE out of args (args is changed)"""
    if name in args:
        i = args.index(name)
        if i + 1 >= len(args):
            raise SystemExit(f"{name} needs a value")
        v = args[i + 1]
        del args[i:i + 2]
        return v
    return default


def file_request(args):
    """infra/setup.py request KIND …: an Inbox request, signed with the setup key (the router names the caller)"""
    args = list(args)
    if args[:1] == ["batch"]:
        rest = args[1:]
        f, summary = opt(rest, "--file"), opt(rest, "--summary")
        inline = []
        while "--item" in rest:
            inline.append(parse_item(opt(rest, "--item")))
        if (not f and not inline) or not summary or rest:
            raise SystemExit("request batch (--file FILE | --item INTENT,key=value,…) --summary TEXT")
        items = json.load(open(os.path.expanduser(f))) if f else inline
        if not isinstance(items, list):
            raise SystemExit("FILE must hold a JSON list of items")
        return call("POST", "/setup/requests/batch", {"summary": summary, "items": items})
    why = opt(args, "--why")
    sensitive = "--sensitive" in args
    args = [a for a in args if a != "--sensitive"]
    minutes, days = opt(args, "--minutes"), opt(args, "--days")
    if not args or not why:
        raise SystemExit("request KIND … --why TEXT (see infra/setup.py without arguments)")
    kind, rest = args[0], args[1:]
    if kind in ("add-repo", "remove-repo") and len(rest) == 1:
        body = {"repo": rest[0], "explanation": why}
        if kind == "add-repo" and sensitive:
            body["sensitive"] = True
        return call("POST", "/setup/requests/repo/" + ("add" if kind == "add-repo" else "remove"), body)
    if kind == "grant" and len(rest) == 2:
        body = {"session": rest[0], "holder": rest[1], "explanation": why}
        if days:
            body["days"] = int(days)
        elif minutes:
            body["minutes"] = int(minutes)
        return call("POST", "/setup/requests/grant", body)
    if kind == "restore" and len(rest) == 2 and rest[1].isdigit():
        return call("POST", "/setup/requests/restore", {"store": rest[0], "seq": int(rest[1]), "explanation": why})
    if kind == "unlock" and len(rest) == 1:
        return call("POST", "/setup/requests/unlock", {"session": rest[0], "explanation": why})
    raise SystemExit(f"unknown request: {' '.join(args)} (see infra/setup.py without arguments)")


def jarvis1(args):
    """infra/setup.py jarvis1 [prepare ID… [--wait] | status ID | import ID --stores … --why …]"""
    args = list(args)
    if not args:
        for s in call("GET", "/setup/jarvis1/paused")["sessions"]:
            prep = (s.get("prepare") or {}).get("state") or ("ready" if s.get("sha256") else "-")
            made = ",".join(f"{x['id']}:{x['state']}" for x in s.get("sessions") or []) or "-"
            print(s["id"], prep, (s.get("sha256") or "")[:12] or "-", made, s.get("size"), "|", s.get("title"))
        return
    sub = args.pop(0)
    if sub == "prepare":
        wait = "--wait" in args
        ids = [a for a in args if a != "--wait"]
        for i in ids:
            call("POST", f"/setup/jarvis1/paused/{i}/prepare", {})
        while wait:
            states = {i: call("GET", f"/setup/jarvis1/paused/{i}") for i in ids}
            busy = [i for i, v in states.items() if (v.get("prepare") or {}).get("state") == "preparing"]
            for i, v in states.items():
                p = v.get("prepare") or {}
                print(i, p.get("state"), f"{p.get('bytesDone', 0) / 1e9:.2f}/{p.get('bytesTotal', 0) / 1e9:.2f} GB", p.get("file") or "",
                      (v.get("sha256") or "")[:12], p.get("error") or "")
            if not busy:
                break
            print("--")
            time.sleep(10)
    elif sub == "status" and len(args) == 1:
        print(json.dumps(call("GET", f"/setup/jarvis1/paused/{args[0]}"), indent=1))
    elif sub == "import" and args:
        why, stores, size, pf = opt(args, "--why"), opt(args, "--stores"), opt(args, "--size"), opt(args, "--prompt-file")
        summary = opt(args, "--summary")
        ids = args
        if not why or not stores or not ids:
            raise SystemExit("jarvis1 import ID [ID…] --stores a,b [--size S] [--prompt-file F] --why TEXT [--summary TEXT]")
        body = {"stores": [x for x in stores.split(",") if x], "explanation": why}
        if size:
            body["size"] = size
        if pf:
            body["prompt"] = open(os.path.expanduser(pf)).read()
        if len(ids) == 1 and not summary:
            print(json.dumps(call("POST", f"/setup/jarvis1/paused/{ids[0]}/import", body), indent=1))
            return
        # several: one batch (docs/API.md "Batches"), every import checked before any is filed
        summary = summary or f"Jarvis 1 import of {len(ids)} sessions: {', '.join(ids)}"
        items = [dict(body, intent="jarvis1-import", id=i) for i in ids]
        print(json.dumps(call("POST", "/setup/requests/batch", {"summary": summary, "items": items}), indent=1))
    else:
        raise SystemExit(jarvis1.__doc__)


if __name__ == "__main__":
    main()
