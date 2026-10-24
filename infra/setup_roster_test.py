#!/usr/bin/env python3
"""infra/setup.py's roster: the payload it signs is sig.RosterPayload byte for byte (checked against the Go side,
kernel/cmd/rostervec), and kernel-roster files what it read through kernel-id, signed by the setup key. Offline (the
router and kernel-id stubbed); needs go: python3 infra/setup_roster_test.py"""
import base64, importlib.util, json, os, random, subprocess, sys, tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
keys = tempfile.mkdtemp()
setup_k = ec.generate_private_key(ec.SECP256R1())
os.environ["JARVIS2_SETUP_KEY"] = setup_k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()).decode()
os.environ["JARVIS2_KEYS_DIR"] = keys
os.environ.update(KERNEL_ID_ACCESS_ID="id", KERNEL_ID_ACCESS_SECRET="secret")
spec = importlib.util.spec_from_file_location("setup", os.path.join(ROOT, "infra", "setup.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
pub = lambda k: base64.b64encode(k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()
sign = lambda k, b: base64.b64encode(k.sign(b, ec.ECDSA(hashes.SHA256()))).decode()


def go_payload(copy, members):
    out = subprocess.run(["go", "run", "./cmd/rostervec"], cwd=os.path.join(ROOT, "kernel"), check=True, capture_output=True,
                         input=json.dumps({"copy": copy, "members": members}).encode())
    return out.stdout.decode()


# 1. byte for byte as Go: real keys, and strings with everything Go's encoder treats specially
ks = {r: (ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())) for r in S.KERNEL_ROLES + ["secrets"]}
members = [{"role": r, "signingKey": pub(a), "agreementKey": pub(b)} for r, (a, b) in ks.items()]
random.shuffle(members)
for copy in ("blue", "green"):
    assert S.roster_payload(copy, members) == go_payload(copy, members), copy
odd = [{"role": "z<b>&", "signingKey": "é  /+=", "agreementKey": "q\"\\é中"}, {"role": "a", "signingKey": "1", "agreementKey": "2"},
       {"role": "é", "signingKey": "x", "agreementKey": "y"}]
assert S.roster_payload("blue", odd) == go_payload("blue", odd), (S.roster_payload("blue", odd), go_payload("blue", odd))

# 2. kernel-roster: identities read through kernel-id (self-signed), the payload signed by the setup key and filed
answers = {}
for r, (a, b) in ks.items():
    ident = {"role": r, "signingKey": pub(a), "agreementKey": pub(b)}
    if r == "secrets":
        st = json.dumps({"kind": "secrets-state", "master": "M", "serving": "serving"})
        answers["/secrets-blue/identity"] = dict(ident, state={"payload": st, "sig": sign(a, st.encode())}, bundle="keys")
    else:
        p = json.dumps(ident)
        answers[f"/{r}/identity"] = {"payload": p, "sig": sign(a, p.encode())}
S.kernel_id = lambda path: answers[path]
filed = []
def call(method, path, body=None):
    if path == "/setup/kernel/roster" and method == "GET":
        return {"current": None, "secretsServing": "blue"}
    assert (method, path) == ("POST", "/setup/kernel/roster"), path
    filed.append(body)
    return {"ok": True, "id": "0" * 64}
S.call = call
S.kernel_roster("blue")
f = filed[0]
assert f["copy"] == "blue" and f["payload"] == go_payload("blue", members)
assert sorted(m["role"] for m in json.loads(f["payload"])["members"]) == ["gullible", "identity", "merger", "minter", "mover", "notarizer", "notary", "secrets", "spawner"]
setup_k.public_key().verify(base64.b64decode(f["setupSig"]), f["payload"].encode(), ec.ECDSA(hashes.SHA256()))

# an identity not signed by its own key is refused
bad = dict(answers["/mover/identity"]); bad["sig"] = answers["/merger/identity"]["sig"]; answers["/mover/identity"] = bad
try:
    S.kernel_roster("blue")
    raise AssertionError("a forged identity was filed")
except SystemExit as e:
    assert "mover" in str(e), e

# 3. kernel-root-key writes both copies (the ConfigMap's without a newline)
os.makedirs(os.path.join(keys, "k8s"), exist_ok=True)
S.ROOT = tempfile.mkdtemp(); os.makedirs(os.path.join(S.ROOT, "k8s", "cluster", "kernel"))
S.write_root_key(pub(setup_k))
assert open(os.path.join(keys, "root.pub")).read() == pub(setup_k) + "\n"
assert open(os.path.join(S.ROOT, "k8s", "cluster", "kernel", "root.pub")).read() == pub(setup_k)
print("ok: setup_roster_test")
