#!/usr/bin/env python3
"""R1 audit: infra/setup.py writes nothing to a core someone else claimed first, and keeps the writer's sensitivity.
Runs offline (the router, S3 and the keys stubbed): python3 infra/setup_trust_test.py"""
import base64, importlib.util, json, os, sys, tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
keys = tempfile.mkdtemp()
setup_k = ec.generate_private_key(ec.SECP256R1())
os.environ["JARVIS2_SETUP_KEY"] = setup_k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()).decode()
pub = lambda k: base64.b64encode(k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()
sig = lambda k, t: base64.b64encode(k.sign(t.encode(), ec.ECDSA(hashes.SHA256()))).decode()
open(os.path.join(keys, "setup.pub"), "w").write(pub(setup_k))
os.environ["JARVIS_KEYS_DIR"] = keys
spec = importlib.util.spec_from_file_location("setup", os.path.join(ROOT, "infra", "setup.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

bucket = {}
class FakeS3:
    def get_object(self, Bucket, Key):
        if Key not in bucket:
            raise Exception("NoSuchKey")
        return {"Body": type("B", (), {"read": lambda self, v=bucket[Key]: v})()}
    def put_object(self, Bucket, Key, Body):
        bucket[Key] = Body
S.s3 = lambda: FakeS3()

core_k, phone_k, deyao_master, router_master, device, router_device = (ec.generate_private_key(ec.SECP256R1()) for _ in range(6))
state = {}

def claimed_by(master, dev=None, signer=None):
    """a claim by `master` naming device `dev` in the statement; `signer` countersigns it (the router keeps that)"""
    st = {"kind": "claim", "master": pub(master), "core": {"signingKey": pub(core_k), "agreementKey": pub(core_k)},
          "phone": {"signingKey": pub(phone_k), "agreementKey": pub(phone_k)}, "bundleSha256": "0"}
    if dev:
        st["device"] = pub(dev)
    st = json.dumps(st)
    signer = signer or dev
    state.update(me={"signingKey": pub(core_k), "agreementKey": pub(core_k), "master": pub(master),
                     "phone": {"signingKey": pub(phone_k), "agreementKey": pub(phone_k)}},
                 cert={"statement": st, "masterSig": sig(master, st)},
                 devs=[{"statement": st, "deviceKey": pub(signer), "deviceSig": sig(signer, st)}] if signer else [])

S.identity_real = S.identity
S.identity = lambda: state["me"]
S.call = lambda m, p, b=None: {"/setup/core-cert": state.get("cert"), "/setup/claim-device": state.get("devs")}[p]

def refused(what):
    try:
        S.set_up()
    except SystemExit as e:
        assert "REFUSED" in str(e) or "no master" in str(e), e
        return
    raise AssertionError("trusted: " + what)

claimed_by(deyao_master, device)
refused("a core with nothing pinned")
S.save_pins(pub(deyao_master), None)               # pin-master on Deyao's Recovered core
S.set_up()
assert S.load_pins()["device"] == pub(device), "the device key of a claim under the pinned master isn't pinned"

claimed_by(router_master)                            # the router claims an emptied core first
refused("a core claimed by another master")
claimed_by(router_master, router_device)             # …with its own device key
refused("a core claimed by another master with another device key")
claimed_by(router_master, device, signer=router_device)  # names Deyao's device, can't sign as it
refused("a core claimed by another master naming Deyao's device key")
claimed_by(deyao_master, signer=router_device)       # the router attaches its own device signature to Deyao's claim
S.set_up()
assert S.load_pins()["device"] == pub(device), "the router re-pinned the device key"
new = ec.generate_private_key(ec.SECP256R1())
claimed_by(new, device)                              # Deyao's Reset: a new master countersigned by his device
S.set_up()
assert S.load_pins()["master"] == pub(new)
bucket["pins.json"] = json.dumps({"doc": json.dumps({"kind": "setup-pins", "master": pub(router_master)}), "sig": sig(router_master, "x")}).encode()
try:
    S.load_pins(); raise AssertionError("pins not signed by the setup key were read")
except SystemExit:
    pass

# the kernel's secrets (a box with no core): its keys are the root key's roster's, its state its own; only the pinned
# master is trusted (no claim to read, nothing re-pinned)
root_k, secrets_k, other_k = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
open(os.path.join(keys, "root.pub"), "w").write(pub(root_k))
bucket.clear()
S.save_pins(pub(deyao_master), pub(device))
def kernel_box(master, roster_signer=root_k, serving="serving"):
    payload = S.roster_payload("blue", [{"role": "secrets", "signingKey": pub(secrets_k), "agreementKey": pub(secrets_k)}])
    st = json.dumps({"kind": "secrets-state", "master": pub(master), "phone": {"signingKey": pub(phone_k), "agreementKey": pub(phone_k)}, "serving": serving})
    ident = {"role": "secrets", "signingKey": pub(secrets_k), "agreementKey": pub(secrets_k), "state": {"payload": st, "sig": sig(secrets_k, st)}}
    roster = {"current": {"payload": payload, "sig": sig(roster_signer, payload)}}
    S.call = lambda m, p, b=None: {"/setup/identity": ident, "/setup/kernel/roster": roster}[p]
S.identity = S.__dict__["identity_real"]
kernel_box(deyao_master)
me = S.set_up()
assert me["kernel"] and me["master"] == pub(deyao_master)
w = S.key_write("infra", "K", "v4lue", me, "a key")
assert w["live"]["e"] and w["live"]["data"], "a kernel write carries no live copy"
kernel_box(router_master)
refused("a kernel secrets claimed with another master")
for bad in (lambda: kernel_box(deyao_master, roster_signer=other_k), lambda: kernel_box(deyao_master, serving="standby")):
    bad()
    try:
        S.identity(); raise AssertionError("an unvouched or standby secrets was trusted")
    except SystemExit:
        pass
assert json.loads(json.loads(bucket["pins.json"])["doc"])["master"] == pub(deyao_master), "the pins changed"

print("ok: setup.py trusts only the pinned master or a claim countersigned by the pinned device")
