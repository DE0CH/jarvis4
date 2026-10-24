#!/usr/bin/env python3
"""infra/setup.py's roster: the payload it signs is sig.Roster.Payload byte for byte (checked against the Go side,
ios/interop/rostervec), and kernel-roster files what it read through kernel-id, signed by the setup key: the serving
copy's (a restarted component's old keys retired), the other copy's (every serving member retired, the retired keys a
line still needs kept, the serving secrets as its secrets and its empty one as secretsBoot); kernel-flipped. Offline
(the router and kernel-id stubbed); needs go: python3 infra/setup_roster_test.py"""
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


def go_payload(copy, members, retired=(), boot=None):
    body = {"copy": copy, "members": members, "retired": list(retired)}
    if boot:
        body["secretsBoot"] = boot
    out = subprocess.run(["go", "run", "."], cwd=os.path.join(ROOT, "ios", "interop", "rostervec"), check=True, capture_output=True,
                         input=json.dumps(body).encode())
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

# retired (sorted by role, then signing key) and secretsBoot, as Go writes them
ret = [{"role": "mover", "signingKey": "z" + pub(ks["mover"][0]), "agreementKey": "a"}, {"role": "merger", "signingKey": "k", "agreementKey": "b"},
       {"role": "mover", "signingKey": "a" + pub(ks["mover"][0]), "agreementKey": "c"}]
boot = {"role": "secrets", "signingKey": "bs", "agreementKey": "ba"}
assert S.roster_payload("green", members, ret, boot) == go_payload("green", members, ret, boot)
assert S.roster_payload("green", members, [], None) == go_payload("green", members)

# 2. kernel-roster: identities read through kernel-id (self-signed), the payload signed by the setup key and filed
def answer(copy, ks, secrets_state):
    out = {}
    for r, (a, b) in ks.items():
        ident = {"role": r, "signingKey": pub(a), "agreementKey": pub(b)}
        if r == "secrets":
            st = json.dumps(dict({"kind": "secrets-state", "serving": "serving"}, **secrets_state))
            out[f"/secrets-{copy}/identity"] = dict(ident, state={"payload": st, "sig": sign(a, st.encode())}, bundle="keys")
        else:
            p = json.dumps(ident)
            out[f"/{r}-{copy}/identity"] = {"payload": p, "sig": sign(a, p.encode())}
    return out
answers = answer("blue", ks, {"master": "M"})
S.kernel_id = lambda path: answers[path]
filed = []
router = {"current": None, "serving": "blue", "retiredInUse": []}
def call(method, path, body=None):
    if path == "/setup/kernel/roster" and method == "GET":
        return router
    assert (method, path) == ("POST", "/setup/kernel/roster"), path
    filed.append(body)
    return {"ok": True, "id": "0" * 64}
S.call = call
S.kernel_roster()
f = filed[0]
assert f["copy"] == "blue" and f["payload"] == go_payload("blue", members), f
assert sorted(m["role"] for m in json.loads(f["payload"])["members"]) == ["gullible", "identity", "merger", "minter", "mover", "notarizer", "notary", "secrets", "spawner"]
setup_k.public_key().verify(base64.b64decode(f["setupSig"]), f["payload"].encode(), ec.ECDSA(hashes.SHA256()))

# an identity not signed by its own key is refused
good = answers["/mover-blue/identity"]
bad = dict(good); bad["sig"] = answers["/merger-blue/identity"]["sig"]; answers["/mover-blue/identity"] = bad
try:
    S.kernel_roster()
    raise AssertionError("a forged identity was filed")
except SystemExit as e:
    assert "mover" in str(e), e
answers["/mover-blue/identity"] = good

# the root key signed blue's roster; blue's mover restarts: blue's next roster names the new mover and retires the old
root_k = ec.generate_private_key(ec.SECP256R1())
open(os.path.join(keys, "root.pub"), "w").write(pub(root_k) + "\n")
blue_doc = {"payload": f["payload"], "sig": sign(root_k, f["payload"].encode())}
router["current"] = blue_doc
old_mover = {"role": "mover", "signingKey": pub(ks["mover"][0]), "agreementKey": pub(ks["mover"][1])}
ks2 = dict(ks, mover=(ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())))
answers.update(answer("blue", ks2, {"master": "M"}))
S.kernel_roster()
r = json.loads(filed[-1]["payload"])
assert r["copy"] == "blue" and r["retired"] == [old_mover] and "secretsBoot" not in r, r
blue2 = [{"role": k, "signingKey": pub(a), "agreementKey": pub(b)} for k, (a, b) in ks2.items()]
assert filed[-1]["payload"] == go_payload("blue", blue2, [old_mover])
router["current"] = {"payload": filed[-1]["payload"], "sig": sign(root_k, filed[-1]["payload"].encode())}

# a release onto green: every blue member but secrets retired, the old mover kept only while a line needs it (and only
# as the root key named it), the serving secrets as green's secrets, green's empty one as secretsBoot
gks = {k: (ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())) for k in ks}
answers.update(answer("green", gks, {"master": ""}))
stranger = {"role": "notary", "signingKey": "S", "agreementKey": "T"}
router["retiredInUse"] = [old_mover, stranger]
S.kernel_roster("green")
r = json.loads(filed[-1]["payload"])
serving_secrets = {"role": "secrets", "signingKey": pub(ks["secrets"][0]), "agreementKey": pub(ks["secrets"][1])}
want_retired = [m for m in blue2 if m["role"] != "secrets"] + [old_mover]
assert r["copy"] == "green" and {m["role"]: m for m in r["members"]}["secrets"] == serving_secrets, r
assert r["secretsBoot"] == {"role": "secrets", "signingKey": pub(gks["secrets"][0]), "agreementKey": pub(gks["secrets"][1])}, r
assert sorted(map(json.dumps, r["retired"])) == sorted(map(json.dumps, want_retired)) and stranger not in r["retired"], r["retired"]
green_members = [m for m in ({"role": k, "signingKey": pub(a), "agreementKey": pub(b)} for k, (a, b) in gks.items()) if m["role"] != "secrets"] + [serving_secrets]
assert filed[-1]["payload"] == go_payload("green", green_members, want_retired, r["secretsBoot"])
router["retiredInUse"] = []
# a green secrets already set up doesn't take over
answers.update(answer("green", gks, {"master": "M"}))
try:
    S.kernel_roster("green")
    raise AssertionError("a set-up secrets named to take over")
except SystemExit as e:
    assert "empty secrets" in str(e), e

# 3. kernel-root-key writes both copies (the ConfigMap's without a newline)
os.makedirs(os.path.join(keys, "k8s"), exist_ok=True)
S.ROOT = tempfile.mkdtemp(); os.makedirs(os.path.join(S.ROOT, "k8s", "cluster", "kernel"))
S.write_root_key(pub(setup_k))
assert open(os.path.join(keys, "root.pub")).read() == pub(setup_k) + "\n"
assert open(os.path.join(S.ROOT, "k8s", "cluster", "kernel", "root.pub")).read() == pub(setup_k)
print("ok: setup_roster_test")
