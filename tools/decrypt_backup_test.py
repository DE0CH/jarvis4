#!/usr/bin/env python3
"""tools/decrypt-backup.py against backups sealed and signed by infra/setup.py's own code (backup, mark_sensitive_backup,
key_write for the per-key backups, laid out as router/storedocs.go WriteKey puts them) with the public TEST master key (e2e/testdata/master-test.pem) and a throwaway setup key, plus the committed vector
tools/testdata/backup-export-v1.json. Offline: python3 tools/decrypt_backup_test.py (needs `cryptography`).
The production master key is never used (no session has it)."""
import base64, datetime, hashlib, importlib.util, io, json, os, stat, subprocess, sys, tempfile, unittest
from contextlib import redirect_stderr, redirect_stdout

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "decrypt-backup.py")
VECTOR = os.path.join(ROOT, "tools", "testdata", "backup-export-v1.json")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def put(path, text):
    with open(path, "w") as f:
        f.write(text)


def pem(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def pub(k):
    return base64.b64encode(k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()


with open(os.path.join(ROOT, "e2e", "testdata", "master-test.pem")) as _f:
    MASTER_PEM = _f.read()
MASTER = serialization.load_pem_private_key(MASTER_PEM.encode(), None)
KIT = "jarvis2-kit:2:" + base64.b64encode(MASTER.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                               serialization.NoEncryption())).decode()
SETUP = ec.generate_private_key(ec.SECP256R1())
OTHER = ec.generate_private_key(ec.SECP256R1())
os.environ["JARVIS2_SETUP_KEY"] = pem(SETUP)
S = load("jarvis2_setup", os.path.join(ROOT, "infra", "setup.py"))
D = load("decrypt_backup", TOOL)

STORES = {"default": ({"GITHUB_TOKEN": "t-1", "OTHER": "x y\nz"}, False), "core": ({"FLY_API_TOKEN": "fly-1"}, True),
          "marked": ({"M": "1"}, False), "empty": ({}, False)}


def seed(signer=None, only=None):
    """{key: body} as infra/setup.py writes them to the bucket"""
    bucket = {}

    class FakeS3:
        def put_object(self, Bucket, Key, Body):
            bucket[Key] = Body.decode() if isinstance(Body, bytes) else Body
    S.s3 = lambda: FakeS3()
    for n, (vals, sens) in STORES.items():
        if only and n not in only:
            continue
        os.environ["JARVIS2_SETUP_KEY"] = pem((signer or {}).get(n, SETUP))
        S.backup(n, vals, sens, pub(MASTER))
    os.environ["JARVIS2_SETUP_KEY"] = pem(SETUP)
    S.mark_sensitive_backup("marked")
    return bucket


# ---- per-key backups (keys/<store>/<key>.json, as router/storedocs.go WriteKey puts them) ---------------------------

BOX = ec.generate_private_key(ec.SECP256R1())
CORE_SIG = ec.generate_private_key(ec.SECP256R1())
CORE_AGR = ec.generate_private_key(ec.SECP256R1())
PHONE_AGR = ec.generate_private_key(ec.SECP256R1())
MACHINE = ec.generate_private_key(ec.SECP256R1())
ME = {"phone": {"agreementKey": pub(PHONE_AGR)}, "agreementKey": pub(CORE_AGR), "master": pub(MASTER)}


def sign(k, text):
    return base64.b64encode(k.sign(text.encode() if isinstance(text, str) else text, ec.ECDSA(hashes.SHA256()))).decode()


def core_identity(box=None):
    """core.Identity as GET /identity answers it (the box key's signature over the core's keys)"""
    state = json.dumps({"kind": "core-state", "master": pub(MASTER), "phone": None})
    return {"signingKey": pub(CORE_SIG), "agreementKey": pub(CORE_AGR),
            "boxSig": sign(box or BOX, f"jarvis2-core-identity {pub(CORE_SIG)} {pub(CORE_AGR)}"),
            "state": {"payload": state, "sig": sign(CORE_SIG, state)}, "bundle": "keys"}


def machine_cert(core=None, machine=None):
    payload = json.dumps({"kind": "succession-cert", "machine": {"id": "m-1", "signingKey": pub(machine or MACHINE)}, "stores": ["default"]})
    return {"payload": payload, "sig": sign(core or CORE_SIG, payload)}


def at(unix):
    return datetime.datetime.fromtimestamp(unix, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def key_backup(store, key, value, when, by="setup", explanation="", signer=None, cert=None, identity=None):
    """keys/<store>/<key>.json: infra/setup.py key_write's request (value None = a delete), then the router's object.
    by "machine": the same sealing, signed by the machine key with its core-signed cert (rust/machine/src/putkey.rs)"""
    os.environ["JARVIS2_SETUP_KEY"] = pem(signer if by == "setup" and signer else SETUP)
    req = S.key_write(store, key, value, ME, explanation)
    os.environ["JARVIS2_SETUP_KEY"] = pem(SETUP)
    e = (req.get("wrapped") or {}).get("e", "")
    data = req.get("data", "")
    bsha = req.get("backupSha256", "")
    if by == "machine":
        req["sig"] = sign(signer or MACHINE, S.writer_text(store, key, e, data, bsha))
    return {"kind": "key-backup", "store": store, "key": key, "deleted": value is None, "sealed": req.get("backup"),
            "backupSha256": bsha, "e": e, "dataSha256": hashlib.sha256(data.encode()).hexdigest() if data else "",
            "writer": {"by": by, "sig": req["sig"], "cert": (cert or machine_cert()) if by == "machine" else None},
            "core": identity or core_identity(), "explanation": explanation, "at": at(when)}


PHONE_SIG = ec.generate_private_key(ec.SECP256R1())


def restore_backups(store, put, remove, when, phone=None, core=None, tamper=None):
    """keys/<store>/<key>.json as router/storerestore.go writes them after a phone-approved restore: the core's backups
    (sealed to the master key, core/history.go sealBackup) and its signed receipt carrying the phone-signed begin"""
    state = json.dumps({"kind": "core-state", "master": pub(MASTER), "phone": {"signingKey": pub(PHONE_SIG), "agreementKey": pub(PHONE_AGR)}})
    ident = dict(core_identity(), state={"payload": state, "sig": sign(CORE_SIG, state)})
    begin = json.dumps({"kind": "store-restore-begin", "pending": "p1", "store": store})
    rows, sealed = [], {}
    for k, v in put.items():
        b = S.seal_to(pub(MASTER), v.encode(), "jarvis2/backup", f"{store}\n{k}".encode())
        sealed[k] = b
        rows.append({"key": k, "e": "E-" + k, "dataSha256": "d" * 64, "backupSha256": hashlib.sha256((b["e"] + "\n" + b["data"]).encode()).hexdigest()})
    r = {"kind": "store-restore-approved", "pending": "p1", "store": store, "from": 4, "to": 2, "put": rows, "remove": remove,
         "begin": begin, "phoneSig": sign(phone or PHONE_SIG, begin)}
    if tamper:  # the receipt only: the objects stay as the router wrote them
        r = json.loads(json.dumps(r))
        tamper(r)
    rp = json.dumps(r)
    receipt = {"payload": rp, "sig": sign(core or CORE_SIG, rp)}
    out = []
    for x in rows:
        out.append({"kind": "key-backup", "store": store, "key": x["key"], "deleted": False, "sealed": sealed[x["key"]],
                    "backupSha256": x["backupSha256"], "e": x["e"], "dataSha256": x["dataSha256"],
                    "writer": {"by": "restore", "receipt": receipt}, "core": ident, "explanation": "", "at": at(when)})
    for k in remove:
        out.append({"kind": "key-backup", "store": store, "key": k, "deleted": True, "sealed": None, "backupSha256": "", "e": "",
                    "dataSha256": "", "writer": {"by": "restore", "receipt": receipt}, "core": ident, "explanation": "", "at": at(when)})
    return out


def add_keys(bucket, *objs):
    b = dict(bucket)
    for o in objs:
        b[f"keys/{o['store']}/{o['key']}.json"] = json.dumps(o)
    return b


def export(bucket, setup_key=None):
    """the app's file (CoreSetup.exportFile): the objects as served plus bucket, fetch time and setup key"""
    return {"format": "jarvis2-backup-export", "version": 1, "bucket": "jarvis2-backup-test", "fetchedAt": "2026-10-13T10:00:00Z",
            "setupKey": setup_key or pub(SETUP), "setupKeySource": "test",
            "objects": [{"key": k, "body": v} for k, v in sorted(bucket.items())]}


class T(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def file(self, obj, name="in.json"):
        p = os.path.join(self.dir, name)
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    def kitfile(self, text=KIT):
        p = os.path.join(self.dir, "kit")
        with open(p, "w") as f:
            f.write(text)
        return p

    def run_tool(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = D.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_decrypts_every_store(self):
        f, out = self.file(export(seed())), os.path.join(self.dir, "plain.json")
        code, stdout, err = self.run_tool(f, "--kit-file", self.kitfile(), "--out", out)
        self.assertEqual(code, 0, err)
        self.assertEqual(stdout, "", "nothing on stdout without --stdout")
        self.assertNotIn("t-1", err, "no value on the terminal")
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        d = json.load(open(out))
        self.assertEqual(d["format"], "jarvis2-stores")
        self.assertEqual({n: s["values"] for n, s in d["stores"].items()}, {n: v for n, (v, _) in STORES.items()})
        self.assertEqual({n: s["sensitive"] for n, s in d["stores"].items()}, {"default": False, "core": True, "marked": True, "empty": False},
                         "a sensitive/ marker wins over the backup's flag")
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(), "--out", out)
        self.assertEqual(code, 2, "never over an existing file")
        self.assertIn("--force", err)
        self.assertEqual(self.run_tool(f, "--kit-file", self.kitfile(), "--out", out, "--force")[0], 0)

    def test_dir_and_stdout(self):
        f = self.file(export(seed()))
        dout = os.path.join(self.dir, "stores") + "/"
        self.assertEqual(self.run_tool(f, "--kit-file", self.kitfile(), "--out", dout)[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(dout).st_mode), 0o700)
        self.assertEqual(sorted(os.listdir(dout)), ["core.json", "default.json", "empty.json", "marked.json"])
        self.assertEqual(json.load(open(dout + "default.json"))["values"]["OTHER"], "x y\nz")
        self.assertEqual(stat.S_IMODE(os.stat(dout + "core.json").st_mode), 0o600)
        code, stdout, _ = self.run_tool(f, "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["stores"]["core"]["values"], {"FLY_API_TOKEN": "fly-1"})

    def test_kit_forms_and_stdin(self):
        f = self.file(export(seed()))
        body = KIT[len("jarvis2-kit:2:"):]
        wrapped = "  " + "\n".join(KIT[i:i + 64] for i in range(0, len(KIT), 64)) + "\n"
        for kit in (wrapped, f"jarvis2-kit:1:{body}:AK:SK", MASTER_PEM):
            self.assertEqual(self.run_tool(f, "--kit-file", self.kitfile(kit), "--stdout")[0], 0, kit[:20])
        for kit, want in (("jarvis2-kit:3:" + body, "unknown"), ("jarvis2-kit:2:AAAA", "doesn't parse"), (body, "isn't a recovery kit")):
            code, _, err = self.run_tool(f, "--kit-file", self.kitfile(kit), "--stdout")
            self.assertEqual(code, 2, kit[:20])
            self.assertIn(want, err)
        # the kit on stdin (a separate process, as Deyao runs it)
        p = subprocess.run([sys.executable, TOOL, f, "--kit-file", "-", "--out", os.path.join(self.dir, "s.json")],
                           input=KIT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        p = subprocess.run([sys.executable, TOOL, f, "--out", os.path.join(self.dir, "s2.json")], input=KIT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, "a piped kit without --kit-file: " + p.stderr)

    def test_wrong_kit(self):
        f = self.file(export(seed()))
        other = "jarvis2-kit:2:" + base64.b64encode(OTHER.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                                         serialization.NoEncryption())).decode()
        out = os.path.join(self.dir, "plain.json")
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(other), "--out", out)
        self.assertEqual(code, 1)
        self.assertIn("doesn't open with this recovery kit", err)
        self.assertFalse(os.path.exists(out), "nothing written")

    def test_bad_signature(self):
        f = self.file(export(seed(signer={"default": OTHER})))
        out = os.path.join(self.dir, "plain.json")
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(), "--out", out)
        self.assertEqual(code, 1)
        self.assertIn("stores/default.json: isn't signed by the file's setup key", err)
        self.assertFalse(os.path.exists(out))
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(), "--out", out, "--skip-bad")
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(json.load(open(out))["stores"]), ["core", "empty", "marked"])

    def test_setup_pub(self):
        b = seed()
        good, other = os.path.join(self.dir, "setup.pub"), os.path.join(self.dir, "other.pub")
        put(good, pub(SETUP) + "\n")
        put(other, pub(OTHER))
        f = self.file(export(b))
        self.assertEqual(self.run_tool(f, "--kit-file", self.kitfile(), "--setup-pub", good, "--stdout")[0], 0)
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(), "--setup-pub", other, "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("isn't " + other, err)
        # a file whose own key was swapped (with its signatures) fails against the real setup.pub
        b2 = seed(signer={n: OTHER for n in STORES})
        os.environ["JARVIS2_SETUP_KEY"] = pem(OTHER)
        S.mark_sensitive_backup("marked")
        os.environ["JARVIS2_SETUP_KEY"] = pem(SETUP)
        swapped = self.file(export(b2, setup_key=pub(OTHER)), "swapped.json")
        self.assertEqual(self.run_tool(swapped, "--kit-file", self.kitfile(), "--stdout")[0], 0, "self-consistent on its own")
        self.assertEqual(self.run_tool(swapped, "--kit-file", self.kitfile(), "--setup-pub", good, "--stdout")[0], 1,
                         "…but not against keys/setup.pub")
        # the raw router answer and a single bucket object carry no setup key: --setup-pub is required
        raw = self.file({"bucket": "b", "objects": export(b)["objects"]}, "raw.json")
        self.assertEqual(self.run_tool(raw, "--kit-file", self.kitfile(), "--stdout")[0], 2)
        self.assertEqual(self.run_tool(raw, "--kit-file", self.kitfile(), "--setup-pub", good, "--stdout")[0], 0)
        one = os.path.join(self.dir, "default.json")
        put(one, b["stores/default.json"])
        code, stdout, _ = self.run_tool(one, "--kit-file", self.kitfile(), "--setup-pub", good, "--stdout")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["stores"]["default"]["values"]["GITHUB_TOKEN"], "t-1")

    def test_store_name_binding(self):
        b = seed()
        # a store's backup served under another store's key
        moved = dict(b)
        moved["stores/marked.json"] = b["stores/core.json"]
        code, _, err = self.run_tool(self.file(export(moved)), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("stores/marked.json: names another store", err)
        # re-signed under another name (a setup key holder): the name is the associated data, so it doesn't open
        d = json.loads(json.loads(b["stores/core.json"])["doc"])
        d["name"] = "marked"
        os.environ["JARVIS2_SETUP_KEY"] = pem(SETUP)
        moved["stores/marked.json"] = json.dumps(S.signed(json.dumps(d)))
        code, _, err = self.run_tool(self.file(export(moved)), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("stores/marked.json: doesn't open with this recovery kit", err)
        # served twice
        e = export(b)
        e["objects"].append(next(o for o in e["objects"] if o["key"].startswith("stores/")))
        self.assertEqual(self.run_tool(self.file(e), "--kit-file", self.kitfile(), "--stdout")[0], 1)

    def test_versions(self):
        e = export(seed())
        e["version"] = 2
        code, _, err = self.run_tool(self.file(e), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 2)
        self.assertIn("newer export", err)

    def test_committed_vector(self):
        """a file made once with the format as shipped: later changes must keep reading it"""
        code, stdout, err = self.run_tool(VECTOR, "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 0, err)
        d = json.loads(stdout)
        self.assertEqual(d["stores"]["default"]["values"], {"GITHUB_TOKEN": "vector-token", "NOTE": "ünïcode ✓"})
        self.assertEqual(d["stores"]["core"]["values"], {"FLY_API_TOKEN": "vector-fly"})
        self.assertEqual(d["stores"]["marked"]["sensitive"], True)
        self.assertEqual(d["bucket"], "jarvis2-backup-vector")

    # ---- per-key backups ----

    def base_at(self, bucket, name):
        return json.loads(json.loads(bucket[f"stores/{name}.json"])["doc"])["at"]

    def box_pub(self, k=None):
        p = os.path.join(self.dir, "box.pub")
        put(p, pub(k or BOX) + "\n")
        return p

    def opened(self, bucket, *extra):
        code, stdout, err = self.run_tool(self.file(export(bucket)), "--kit-file", self.kitfile(), "--stdout", *extra)
        self.assertEqual(code, 0, err)
        return json.loads(stdout)["stores"]

    def test_setup_key_over_base(self):
        b = seed()
        t = self.base_at(b, "default")
        b = add_keys(b, key_backup("default", "GITHUB_TOKEN", "t-2 ✓", t + 5, explanation="GitHub's token"),
                     key_backup("default", "NEW_KEY", "n\n1", t + 6, explanation="A new key"),
                     key_backup("fresh", "ONLY", "o", t + 7, explanation="Only key of a store with no whole-store backup"))
        st = self.opened(b)
        self.assertEqual(st["default"]["values"], {"GITHUB_TOKEN": "t-2 ✓", "OTHER": "x y\nz", "NEW_KEY": "n\n1"})
        self.assertEqual(st["default"]["explanations"], {"GITHUB_TOKEN": "GitHub's token", "NEW_KEY": "A new key"})
        self.assertEqual(st["default"]["at"], t, "the whole-store backup's time is kept")
        self.assertEqual(st["fresh"]["values"], {"ONLY": "o"}, "a store with only key backups starts empty")
        self.assertEqual(st["core"]["explanations"], {})
        # a setup-written key signed by another key fails (and --skip-bad leaves only it out)
        bad = add_keys(b, key_backup("default", "OTHER", "evil", t + 9, signer=OTHER))
        code, _, err = self.run_tool(self.file(export(bad)), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("keys/default/OTHER.json: isn't signed by the file's setup key", err)
        code, stdout, err = self.run_tool(self.file(export(bad)), "--kit-file", self.kitfile(), "--stdout", "--skip-bad")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(stdout)["stores"]["default"]["values"]["OTHER"], "x y\nz")
        # one key's object on its own, with --setup-pub
        one = os.path.join(self.dir, "one.json")
        put(one, b["keys/fresh/ONLY.json"])
        setup = os.path.join(self.dir, "setup.pub")
        put(setup, pub(SETUP))
        code, stdout, err = self.run_tool(one, "--kit-file", self.kitfile(), "--setup-pub", setup, "--stdout")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(stdout)["stores"]["fresh"]["values"], {"ONLY": "o"})

    def test_machine_written_key(self):
        b = seed()
        t = self.base_at(b, "default")
        b = add_keys(b, key_backup("default", "SESSION_KEY", "from a session", t + 5, by="machine", explanation="Written by a session"))
        f = self.file(export(b))
        code, _, err = self.run_tool(f, "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1, "no box key: a session-written key can't be checked")
        self.assertIn("pass --box-pub", err)
        code, stdout, err = self.run_tool(f, "--kit-file", self.kitfile(), "--stdout", "--skip-bad")
        self.assertEqual(code, 0, err)
        self.assertNotIn("SESSION_KEY", json.loads(stdout)["stores"]["default"]["values"])
        st = self.opened(b, "--box-pub", self.box_pub())
        self.assertEqual(st["default"]["values"]["SESSION_KEY"], "from a session")
        self.assertEqual(st["default"]["explanations"], {"SESSION_KEY": "Written by a session"})
        # the box key in the file works too, and must match --box-pub
        e = export(b)
        e["boxKey"] = pub(BOX)
        code, stdout, err = self.run_tool(self.file(e, "boxed.json"), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 0, err)
        code, _, err = self.run_tool(self.file(e, "boxed.json"), "--kit-file", self.kitfile(), "--stdout", "--box-pub", self.box_pub(OTHER))
        self.assertEqual(code, 1)
        self.assertIn("box key isn't", err)
        # every link of the chain: another box, a cert from another core, a signature by another machine
        fake_core = ec.generate_private_key(ec.SECP256R1())
        for o, want in ((key_backup("default", "X", "v", t + 6, by="machine", identity=core_identity(box=OTHER)), "its core's identity isn't signed"),
                        (key_backup("default", "X", "v", t + 6, by="machine", cert=machine_cert(core=fake_core)), "the machine's cert isn't signed by its core"),
                        (key_backup("default", "X", "v", t + 6, by="machine", signer=OTHER), "isn't signed by the key in the machine's cert")):
            code, _, err = self.run_tool(self.file(export(add_keys(b, o)), "chain.json"), "--kit-file", self.kitfile(), "--stdout",
                                         "--box-pub", self.box_pub())
            self.assertEqual(code, 1, want)
            self.assertIn("keys/default/X.json: " + want, err)

    def test_restore_written_keys(self):
        """a phone-approved restore (core/history.go): its keys come back at Recover, its removals remove"""
        b = seed()
        t = self.base_at(b, "default")
        wiped = add_keys(b, key_backup("default", "GITHUB_TOKEN", None, t + 5), key_backup("default", "OTHER", None, t + 5),
                         key_backup("default", "STRAY", "written by mistake", t + 5))
        self.assertEqual(self.opened(wiped)["default"]["values"], {"STRAY": "written by mistake"})
        restored = add_keys(wiped, *restore_backups("default", {"GITHUB_TOKEN": "t-1", "OTHER": "x y\nz"}, ["STRAY"], t + 10))
        code, _, err = self.run_tool(self.file(export(restored)), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1, "no box key: a restore can't be checked")
        self.assertIn("pass --box-pub", err)
        st = self.opened(restored, "--box-pub", self.box_pub())
        self.assertEqual(st["default"]["values"], {"GITHUB_TOKEN": "t-1", "OTHER": "x y\nz"})
        fake = ec.generate_private_key(ec.SECP256R1())
        for objs, want in ((restore_backups("default", {"GITHUB_TOKEN": "v"}, [], t + 10, phone=fake), "isn't signed by the phone"),
                           (restore_backups("default", {"GITHUB_TOKEN": "v"}, [], t + 10, core=fake), "receipt isn't signed by its core"),
                           (restore_backups("default", {"GITHUB_TOKEN": "v"}, [], t + 10, tamper=lambda r: r.update(store="other")), "names another store"),
                           (restore_backups("default", {"GITHUB_TOKEN": "v"}, [], t + 10, tamper=lambda r: r["put"][0].update(backupSha256="0" * 64)), "another value")):
            code, _, err = self.run_tool(self.file(export(add_keys(wiped, *objs)), "bad.json"), "--kit-file", self.kitfile(), "--stdout",
                                         "--box-pub", self.box_pub())
            self.assertEqual(code, 1, want)
            self.assertIn(want, err)

    def test_deleted_key(self):
        b = seed()
        t = self.base_at(b, "default")
        b = add_keys(b, key_backup("default", "OTHER", None, t + 5), key_backup("fresh", "GONE", None, t + 5))
        st = self.opened(b)
        self.assertEqual(st["default"]["values"], {"GITHUB_TOKEN": "t-1"})
        self.assertEqual(st["fresh"]["values"], {})
        # a delete then a later write: the write wins (the order is the times', not the file's)
        b2 = add_keys(seed(), key_backup("default", "K", "first", t + 5))
        b2["keys/default/K.json"] = json.dumps(key_backup("default", "K", None, t + 6))
        self.assertNotIn("K", self.opened(b2)["default"]["values"])

    def test_older_key_backup_ignored(self):
        b = seed()
        t = self.base_at(b, "default")
        b = add_keys(b, key_backup("default", "GITHUB_TOKEN", "older", t - 60), key_backup("default", "OTHER", None, t - 60),
                     key_backup("default", "SAME_SECOND", "same", t))
        st = self.opened(b)
        self.assertEqual(st["default"]["values"], {"GITHUB_TOKEN": "t-1", "OTHER": "x y\nz"},
                         "key backups not after the whole-store backup are already in it")

    def test_tampered_backup_sha(self):
        b = seed()
        t = self.base_at(b, "default")
        o = key_backup("default", "GITHUB_TOKEN", "t-2", t + 5)
        other = key_backup("default", "GITHUB_TOKEN", "evil", t + 5)
        o["sealed"] = other["sealed"]  # another sealed value under the signed hash
        code, _, err = self.run_tool(self.file(export(add_keys(b, o))), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("keys/default/GITHUB_TOKEN.json: backupSha256 isn't its sealed value's", err)
        o["backupSha256"] = hashlib.sha256((o["sealed"]["e"] + "\n" + o["sealed"]["data"]).encode()).hexdigest()
        code, _, err = self.run_tool(self.file(export(add_keys(b, o))), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1, "the hash fixed up: the writer's signature no longer covers it")
        self.assertIn("isn't signed by", err)

    def test_key_moved_to_another_name(self):
        b = seed()
        t = self.base_at(b, "default")
        o = key_backup("default", "GITHUB_TOKEN", "t-2", t + 5)
        # served under another key's path
        b1 = dict(b)
        b1["keys/default/OTHER.json"] = json.dumps(o)
        code, _, err = self.run_tool(self.file(export(b1)), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("keys/default/OTHER.json: names another key", err)
        # renamed and re-signed by a setup key holder: "{store}\n{key}" is the associated data, so it doesn't open
        moved = dict(o, key="OTHER")
        moved["writer"] = dict(o["writer"], sig=sign(SETUP, D.writer_text("default", "OTHER", o["e"], o["dataSha256"], o["backupSha256"])))
        code, _, err = self.run_tool(self.file(export(add_keys(b, moved))), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("keys/default/OTHER.json: doesn't open with this recovery kit", err)
        # …and into another store
        moved2 = dict(o, store="core")
        moved2["writer"] = dict(o["writer"], sig=sign(SETUP, D.writer_text("core", "GITHUB_TOKEN", o["e"], o["dataSha256"], o["backupSha256"])))
        code, _, err = self.run_tool(self.file(export(add_keys(b, moved2))), "--kit-file", self.kitfile(), "--stdout")
        self.assertEqual(code, 1)
        self.assertIn("keys/core/GITHUB_TOKEN.json: doesn't open with this recovery kit", err)


def make_vector():
    """python3 tools/decrypt_backup_test.py make-vector: (re)writes tools/testdata/backup-export-v1.json"""
    global STORES
    STORES = {"default": ({"GITHUB_TOKEN": "vector-token", "NOTE": "ünïcode ✓"}, False), "core": ({"FLY_API_TOKEN": "vector-fly"}, True),
              "marked": ({"M": "1"}, False)}
    e = export(seed())
    e.update(bucket="jarvis2-backup-vector", setupKeySource="a throwaway setup key (tools/decrypt_backup_test.py make-vector)")
    os.makedirs(os.path.dirname(VECTOR), exist_ok=True)
    with open(VECTOR, "w") as f:
        json.dump(e, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    print("wrote", VECTOR)


if __name__ == "__main__":
    if sys.argv[1:] == ["make-vector"]:
        make_vector()
    else:
        unittest.main()
