#!/usr/bin/env python3
"""CI stand-ins for the app's tests (app.yml): throwaway box + setup keys, and the backup bucket on a local
S3 stand-in (rclone serve s3), seeded in exactly infra/setup.py's format by infra/setup.py's own code.

  standin.py keys DIR   DIR/keys/{box,setup}.pub (served to the CI build as its key source),
                        DIR/box-key.pem (the core's BOX_KEY_FILE), DIR/setup-key.pem (signs the backups)
  standin.py seed DIR   buckets on $HETZNER_S3_ENDPOINT, the backups encrypted to the public TEST master key
                        (e2e/testdata/master-test.pub), as a Recover with the test kit expects them:
                          jarvis2-backup-ci       core, default, gmail (sensitive), claude-login (the claude
                                                  harness's store), marked (backup says not sensitive, a
                                                  sensitive/ marker says it is)
                          jarvis2-backup-tampered default signed by another key → Recover must refuse
                          jarvis2-backup-nocore   no core store → Recover still works (the token comes later)
                          jarvis2-backup-keys     key backups only (keys/<store>/<key>.json, router/storedocs.go's
                                                  format), laid over jarvis2-backup-ci's stores at a Recover: default's
                                                  OTHER rewritten (setup), GITHUB_TOKEN deleted, OLD older than the
                                                  store's backup (ignored), SESSION_KEY written by a session's machine (a
                                                  stand-in core identity signed by the box key, a cert it signed, the
                                                  machine's signature), RESTORED put back by a
                                                  phone-approved restore (a receipt that core signed), and keyed-only's API_KEY (a store no whole-store
                                                  backup names)
                        and DIR/backups.json: every bucket's objects as the router serves them ({bucket: [{key, body}]})
Nothing secret: every key here is made for one run, and the master key is the public test pair.
"""
import base64, hashlib, importlib.util, json, os, sys, time

from cryptography.hazmat.primitives import hashes, serialization as s
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def pub(k):
    return base64.b64encode(k.public_key().public_bytes(s.Encoding.X962, s.PublicFormat.UncompressedPoint)).decode()


def pem(k):
    return k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption())


def keys(d):
    os.makedirs(os.path.join(d, "keys"), exist_ok=True)
    for name in ("box", "setup"):
        k = ec.generate_private_key(ec.SECP256R1())
        with open(os.path.join(d, f"{name}-key.pem"), "wb") as f:
            f.write(pem(k))
        with open(os.path.join(d, "keys", f"{name}.pub"), "w") as f:
            f.write(pub(k) + "\n")


def load_setup(d):
    """infra/setup.py itself, its keys/ being the stand-ins"""
    os.environ["JARVIS_KEYS_DIR"] = os.path.join(d, "keys")
    spec = importlib.util.spec_from_file_location("setup", os.path.join(ROOT, "infra", "setup.py"))
    setup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup)
    return setup


def seed(d):
    setup = load_setup(d)
    master = open(os.path.join(ROOT, "e2e", "testdata", "master-test.pub")).read().strip()
    good = open(os.path.join(d, "setup-key.pem")).read()
    other = pem(ec.generate_private_key(ec.SECP256R1())).decode()
    s3 = setup.s3()
    dump = {}

    def bucket(name, stores, markers=(), bad=()):
        try:
            s3.create_bucket(Bucket=name)
        except Exception as e:
            if "BucketAlready" not in str(e):
                raise
        setup.BUCKET = name
        for n, vals, sens in stores:
            os.environ["JARVIS2_SETUP_KEY"] = other if n in bad else good
            setup.backup(n, vals, sens, master)
        os.environ["JARVIS2_SETUP_KEY"] = good
        for n in markers:
            setup.mark_sensitive_backup(n)
        objs = []
        for prefix in ("stores/", "sensitive/", "keys/"):
            for o in s3.list_objects_v2(Bucket=name, Prefix=prefix).get("Contents", []):
                objs.append({"key": o["Key"], "body": s3.get_object(Bucket=name, Key=o["Key"])["Body"].read().decode()})
        dump[name] = objs
        print(f"seeded {name}: {[n for n, _, _ in stores]} markers {list(markers)}")

    core = ("core", {"FLY_API_TOKEN": "ci-dummy"}, True)
    default = ("default", {"GITHUB_TOKEN": "ci-dummy", "OTHER": "x"}, False)
    bucket("jarvis2-backup-ci", [core, default, ("gmail", {"GMAIL_TOKEN": "ci-dummy"}, True),
                                 ("claude-login", {"CLAUDE_CODE_OAUTH_TOKEN": "ci-dummy"}, False),
                                 ("marked", {"M": "1"}, False),
                                 ("github-deploy-keys", {"GITHUB_DEPLOY_KEYS_TOKEN": "ci-dummy"}, True)], markers=["marked"])
    bucket("jarvis2-backup-tampered", [core, default], bad=["default"])
    bucket("jarvis2-backup-nocore", [default])
    key_backups(d, setup, s3, master, good, dump)
    with open(os.path.join(d, "backups.json"), "w") as f:
        json.dump(dump, f)


def sign(key, text):
    return base64.b64encode(key.sign(text.encode(), ec.ECDSA(hashes.SHA256()))).decode()


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def key_backups(d, setup, s3, master, setup_pem, dump):
    """jarvis2-backup-keys: key backups as router/storedocs.go writes them (the router puts them; here written directly)"""
    name = "jarvis2-backup-keys"
    try:
        s3.create_bucket(Bucket=name)
    except Exception as e:
        if "BucketAlready" not in str(e):
            raise
    setup_key = s.load_pem_private_key(setup_pem.encode(), None)
    box = s.load_pem_private_key(open(os.path.join(d, "box-key.pem"), "rb").read(), None)
    # a stand-in core (its identity signed by the box key) and a machine it certified: what a session's write carries
    core_sig, core_agr, machine = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    sk, ak = pub(core_sig), pub(core_agr)
    state = json.dumps({"kind": "core-state", "master": master, "phone": None})
    identity = {"signingKey": sk, "agreementKey": ak, "boxSig": sign(box, f"jarvis2-core-identity {sk} {ak}"),
                "state": {"payload": state, "sig": sign(core_sig, state)}, "bundle": "keys"}
    cert = json.dumps({"kind": "succession-cert", "nonce": "c" * 64, "line": "fake000042",
                       "machine": {"id": "fake000042", "image": "ci", "encryptionKey": pub(machine), "signingKey": pub(machine)}})
    cert_doc = {"payload": cert, "sig": sign(core_sig, cert)}
    now = time.time()

    def put(store, key, value, at, writer="setup"):
        e = data = bsha = ""
        sealed = None
        if value is not None:
            aad = f"{store}\n{key}".encode()
            sealed = setup.seal_to(master, value.encode(), "jarvis2/backup", aad)
            bsha = hashlib.sha256((sealed["e"] + "\n" + sealed["data"]).encode()).hexdigest()
            e = pub(ec.generate_private_key(ec.SECP256R1()))  # the key's E on the core (only its text is signed here)
            data = base64.b64encode(os.urandom(48)).decode()
        dsha = hashlib.sha256(data.encode()).hexdigest() if data else ""
        text = f"jarvis2-store-key\n{store}\n{key}\n{e}\n{dsha}\n{bsha}"
        w = {"by": "setup", "sig": sign(setup_key, text), "cert": None}
        if writer == "machine":
            w = {"by": "machine", "sig": sign(machine, text), "cert": cert_doc}
        if writer == "restore":  # a phone-approved restore: the core's signed receipt (router/storerestore.go)
            rc = json.dumps({"kind": "store-restore-approved", "pending": "p", "store": store, "to": 3, "remove": [],
                             "put": [{"key": key, "e": e, "dataSha256": dsha, "backupSha256": bsha}]})
            w = {"by": "restore", "receipt": {"payload": rc, "sig": sign(core_sig, rc)}}
        obj = {"kind": "key-backup", "store": store, "key": key, "deleted": value is None, "sealed": sealed, "backupSha256": bsha,
               "e": e, "dataSha256": dsha, "writer": w, "core": identity, "explanation": f"what {key} is for", "at": iso(at)}
        s3.put_object(Bucket=name, Key=f"keys/{store}/{key}.json", Body=json.dumps(obj).encode())

    put("default", "OTHER", "y", now + 60)
    put("default", "GITHUB_TOKEN", None, now + 60)
    put("default", "OLD", "stale", now - 3600)
    put("default", "SESSION_KEY", "from-a-session", now + 120, writer="machine")
    put("default", "RESTORED", "r1", now + 90, writer="restore")
    put("keyed-only", "API_KEY", "k1", now + 60)
    dump[name] = [{"key": o["Key"], "body": s3.get_object(Bucket=name, Key=o["Key"])["Body"].read().decode()}
                  for o in s3.list_objects_v2(Bucket=name, Prefix="keys/").get("Contents", [])]
    print(f"seeded {name}: {[o['key'] for o in dump[name]]}")


if __name__ == "__main__":
    {"keys": keys, "seed": seed}[sys.argv[1]](sys.argv[2])
