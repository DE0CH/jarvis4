#!/usr/bin/env python3
"""decrypt-backup — open an offline copy of Jarvis 4's store backups with the master key from the recovery kit.

Runs fully offline (Python 3.9+ and the `cryptography` package; nothing else, no network):

  decrypt-backup.py FILE [--kit-file KIT | -] [--setup-pub keys/setup.pub] [--box-pub keys/box.pub]
                    [--out PATH] [--stdout] [--force] [--skip-bad]

FILE is what the Jarvis 4 app's Settings → Encrypted backup → "Download encrypted backup" saves
(`jarvis2-backup-<date>.json`, format "jarvis2-backup-export" version 1: the objects exactly as `GET /api/backups`
served them, the bucket, the fetch time, the setup public key the app checked them with and, when the file has one, the
box public key `boxKey`). Also taken: the router's raw `GET /api/backups` answer ({bucket, objects}), a single
`stores/<name>.json` object ({doc, sig}) as stored in the bucket (e.g. an older version fetched from the versioned
bucket), and a single `keys/<store>/<key>.json` object. Those carry no setup or box key: pass --setup-pub / --box-pub.

The bucket holds three kinds of object (docs/DESIGN.md "Writing stores and their backups"):
  stores/<name>.json     an older whole-store backup, {doc, sig} signed by the setup key; `at` in unix seconds
  sensitive/<name>.json  a sensitivity marker, signed by the setup key
  keys/<store>/<key>.json  one key's backup, written by the router before the key reaches the core:
      {kind "key-backup", store, key, deleted, sealed {e, data} | null, backupSha256, e, dataSha256,
       writer {by "setup"|"machine", sig, cert?} | {by "restore", receipt}, core {signingKey, agreementKey, boxSig, state, bundle},
       explanation, at (RFC3339)}
    Checks: backupSha256 = hex sha256(sealed.e + "\n" + sealed.data) (a delete: no sealed value, empty hashes); the
    writer's signature over WriterText = "jarvis2-store-key\n{store}\n{key}\n{e}\n{dataSha256}\n{backupSha256}":
    writer "setup" = the setup key; writer "machine" = the signing key in writer.cert ({payload, sig}, a succession
    cert signed by core.signingKey), the core's identity "jarvis2-core-identity {signingKey} {agreementKey}" signed by
    the box key (core.boxSig); writer "restore" (a phone-approved restore, core/history.go) = {by, receipt}: the core's
    signed receipt (kind store-restore-approved, the same core identity) names this key's e, dataSha256 and
    backupSha256 (or lists it as removed), and carries the restore's begin document with the phone's signature over it,
    the phone being the one in the core's signed state. Without a box key (--box-pub or the file's boxKey) a key
    written by a session or a restore fails its check.

The kit (`jarvis2-kit:2:<master private key>`; a version-1 kit's master part works too) is read from --kit-file, from
stdin with `--kit-file -`, or asked for without echo when stdin is a terminal. Never pass it as an argument: it would
end up in the shell history.

Every signature is checked against the key in the file AND, when given, the --setup-pub / --box-pub file (each pair
must be the same key); every store and key is decrypted (ECDH with the master key, HKDF-SHA256 info "jarvis2/backup",
AES-256-GCM 12-byte nonce ‖ ciphertext ‖ tag; associated data: the store's name for a whole-store backup,
"{store}\n{key}" for a key, whose value is its raw UTF-8 string). Then, per store, like the app's Recover: the
whole-store backup is the base (none: the store starts empty), every key backup of that store written later (its `at`
after the base's) replaces that key, a deleted one removes it; an older key backup is ignored. Any problem stops it
before anything is written, unless --skip-bad (the bad objects are then left out and listed). The plaintext goes to
--out (default ./jarvis2-stores-<date>.json), created with mode 0600 and never over an existing file unless --force; an
--out ending in "/" (or an existing directory) gets one <store>.json per store in a 0700 directory. Values are printed
only with --stdout.

Output file: {"format": "jarvis2-stores", "version": 1, "source", "bucket", "fetchedAt", "setupKey",
              "stores": {name: {"sensitive", "at", "values": {KEY: value}, "explanations": {KEY: text}}}}
  (`at`: the whole-store backup's, unix seconds, or null; `explanations`: what each key written since is for, not secret)
Exit codes: 0 done, 1 a check or decryption failed, 2 bad usage or input.
"""
import argparse, base64, datetime, getpass, hashlib, json, os, re, sys

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:  # pragma: no cover
    sys.exit("needs the `cryptography` package: python3 -m pip install cryptography (docs/RUNBOOK.md \"Offline copy of the stores\")")

EXPORT_FORMAT, EXPORT_VERSIONS = "jarvis2-backup-export", (1,)
BACKUP_INFO = b"jarvis2/backup"


class Bad(Exception):
    """a check that failed (exit 1)"""


class Usage(Exception):
    """bad input or arguments (exit 2)"""


# ---- keys --------------------------------------------------------------------------------------------------

def parse_kit(raw):
    """the master private key from the recovery kit text (whitespace ignored). Version 2 = jarvis2-kit:2:<base64 PKCS#8
    DER>; version 1 = jarvis2-kit:1:<base64 PKCS#8 DER>:<bucket keys> (only its master part is used); a PEM private
    key is also taken (the public TEST key in e2e/testdata)."""
    text = raw.strip()
    if "-----BEGIN" in text:
        try:
            k = serialization.load_pem_private_key(text.encode(), None)
        except Exception:
            raise Usage("that PEM isn't a private key")
        return check_p256(k), "PEM"
    s = "".join(text.split())
    if s.startswith("jarvis2-kit:2:"):
        body, version = s[len("jarvis2-kit:2:"):], 2
    elif s.startswith("jarvis2-kit:1:"):
        body, version = s[len("jarvis2-kit:1:"):].split(":")[0], 1
    elif s.startswith("jarvis2-kit:"):
        raise Usage("an unknown recovery kit version: " + s[:14])
    else:
        raise Usage("that isn't a recovery kit (it starts with jarvis2-kit:2:)")
    try:
        k = serialization.load_der_private_key(base64.b64decode(body, validate=True), None)
    except Exception:
        raise Usage("the recovery kit's master key doesn't parse")
    return check_p256(k), f"kit version {version}"


def check_p256(k):
    if not isinstance(k, ec.EllipticCurvePrivateKey) or k.curve.name != "secp256r1":
        raise Usage("the master key isn't a P-256 private key")
    return k


def public_b64(k):
    return base64.b64encode(k.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode()


def load_pub(b64, what):
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode("".join(b64.split()), validate=True))
    except Exception:
        raise Usage(f"{what} isn't a P-256 public key (base64 X9.63)")


def valid(pub, payload, sig_b64):
    try:
        pub.verify(base64.b64decode(sig_b64, validate=True), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def open_sealed(sealed, master, aad):
    """{e, data}: ECDH(master, e) → HKDF-SHA256 (no salt, info "jarvis2/backup") → AES-256-GCM nonce‖ciphertext‖tag"""
    try:
        e = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(sealed["e"], validate=True))
        data = base64.b64decode(sealed["data"], validate=True)
    except Exception:
        raise Bad("the sealed value is malformed")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=BACKUP_INFO).derive(master.exchange(ec.ECDH(), e))
    try:
        return AESGCM(key).decrypt(data[:12], data[12:], aad)
    except InvalidTag:
        raise Bad("doesn't open with this recovery kit")


# ---- the file ----------------------------------------------------------------------------------------------

def load_input(path):
    """→ (objects [{key, body}], meta {bucket, fetchedAt, setupKey})"""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError) as e:
        raise Usage(f"can't read {path}: {e}")
    if not isinstance(d, dict):
        raise Usage(f"{path} isn't a backup file")
    if d.get("format") == EXPORT_FORMAT:
        if d.get("version") not in EXPORT_VERSIONS:
            raise Usage(f"{path} is a newer export (version {d.get('version')}); this script reads {list(EXPORT_VERSIONS)}")
        meta = {k: d.get(k) for k in ("bucket", "fetchedAt", "setupKey", "boxKey")}
        objs = d.get("objects")
    elif "objects" in d:  # the router's raw GET /api/backups answer
        meta, objs = {"bucket": d.get("bucket"), "fetchedAt": None, "setupKey": None}, d["objects"]
    elif d.get("kind") == "key-backup":  # one key's backup as stored in the bucket
        if not isinstance(d.get("store"), str) or not isinstance(d.get("key"), str):
            raise Usage(f"{path} is a key backup without its store and key")
        with open(path, encoding="utf-8") as f:
            body = f.read()
        meta, objs = {"bucket": None, "fetchedAt": None, "setupKey": None}, [{"key": f"keys/{d['store']}/{d['key']}.json", "body": body}]
    elif "doc" in d and "sig" in d:  # one object as stored in the bucket
        try:
            name = json.loads(d["doc"])["name"]
            kind = json.loads(d["doc"])["kind"]
        except Exception:
            raise Usage(f"{path} isn't a signed backup object")
        prefix = {"store-backup": "stores/", "store-sensitive": "sensitive/"}.get(kind)
        if not prefix:
            raise Usage(f"{path} is a {kind!r} document, not a store backup")
        with open(path, encoding="utf-8") as f:
            body = f.read()
        meta, objs = {"bucket": None, "fetchedAt": None, "setupKey": None}, [{"key": f"{prefix}{name}.json", "body": body}]
    else:
        raise Usage(f"{path} isn't a Jarvis 4 backup export")
    if not isinstance(objs, list) or not all(isinstance(o, dict) and isinstance(o.get("key"), str) and isinstance(o.get("body"), str) for o in objs):
        raise Usage(f"{path}: objects must be a list of {{key, body}}")
    return objs, meta


def name_of(key, prefix):
    if key.startswith(prefix) and key.endswith(".json") and len(key) > len(prefix) + 5:
        return key[len(prefix):-5]
    return None


KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def key_path(key):
    """keys/<store>/<key>.json → (store, key), else None"""
    m = re.fullmatch(r"keys/([^/]+)/([^/]+)\.json", key)
    return (m.group(1), m.group(2)) if m else None


def writer_text(store, key, e, data_sha, backup_sha):
    """core.WriterText: what a key's writer signs"""
    return f"jarvis2-store-key\n{store}\n{key}\n{e}\n{data_sha}\n{backup_sha}".encode()


def parse_at(at):
    """an RFC3339 time → unix seconds (float)"""
    if not isinstance(at, str):
        raise ValueError
    t = at.strip()
    if t.endswith("Z") or t.endswith("z"):
        t = t[:-1] + "+00:00"
    t = re.sub(r"(\.\d{6})\d+", r"\1", t)  # Go's nanoseconds → microseconds
    dt = datetime.datetime.fromisoformat(t)
    if dt.tzinfo is None:
        raise ValueError
    return dt.timestamp()


def core_of(d, box_keys):
    """(the core's signing key, None) when the object's core identity is signed by the box key, else (None, why)"""
    c = d.get("core")
    if not isinstance(c, dict) or not all(isinstance(c.get(k), str) for k in ("signingKey", "agreementKey", "boxSig")):
        return None, "carries no core identity"
    ident = f"jarvis2-core-identity {c['signingKey']} {c['agreementKey']}".encode()
    bad = [label for label, pub in box_keys if not valid(pub, ident, c["boxSig"])]
    if bad:
        return None, "its core's identity isn't signed by " + " / ".join(bad)
    try:
        return load_pub(c["signingKey"], "the core's signing key"), None
    except Usage:
        return None, "its core's signing key isn't a P-256 key"


def check_restore_writer(d, store, key, w, box_keys):
    """writer "restore": the core's signed receipt of a phone-approved restore (core/history.go) names this key's
    backup, and the phone the core was set up with signed the restore's begin document"""
    if not box_keys:
        return "is written by a restore: pass --box-pub keys/box.pub to check it"
    core_pub, why = core_of(d, box_keys)
    if why:
        return why
    rc = w.get("receipt")
    if not isinstance(rc, dict) or not isinstance(rc.get("payload"), str) or not isinstance(rc.get("sig"), str):
        return "a restore without the core's receipt"
    if not valid(core_pub, rc["payload"].encode(), rc["sig"]):
        return "the restore's receipt isn't signed by its core"
    st = (d.get("core") or {}).get("state")
    try:
        if not valid(core_pub, st["payload"].encode(), st["sig"]):
            return "its core's state isn't signed by the core"
        phone = load_pub(json.loads(st["payload"])["phone"]["signingKey"], "the phone's signing key")
        r = json.loads(rc["payload"])
        begin = json.loads(r["begin"])
    except (ValueError, KeyError, TypeError, Usage):
        return "the restore's receipt or its core's state isn't readable"
    if r.get("kind") != "store-restore-approved" or r.get("store") != store or begin.get("kind") != "store-restore-begin" or \
            begin.get("pending") != r.get("pending") or begin.get("store") != store:
        return "the restore's receipt names another store or restore"
    if not isinstance(r.get("phoneSig"), str) or not valid(phone, r["begin"].encode(), r["phoneSig"]):
        return "the restore isn't signed by the phone its core was set up with"
    if d.get("deleted"):
        return None if key in (r.get("remove") or []) else "the restore's receipt doesn't remove this key"
    for x in r.get("put") or []:
        if isinstance(x, dict) and x.get("key") == key:
            if (x.get("backupSha256"), x.get("e"), x.get("dataSha256")) != (d.get("backupSha256"), d.get("e"), d.get("dataSha256")):
                return "the restore's receipt names another value for this key"
            return None
    return "the restore's receipt doesn't put this key back"


def check_key_writer(d, store, key, setup_keys, box_keys):
    """None when the writer's signature checks, else why not"""
    w = d.get("writer")
    if isinstance(w, dict) and w.get("by") == "restore":
        return check_restore_writer(d, store, key, w, box_keys)
    if not isinstance(w, dict) or not isinstance(w.get("sig"), str):
        return "names no writer"
    text = writer_text(store, key, d.get("e") or "", d.get("dataSha256") or "", d.get("backupSha256") or "")
    if w.get("by") == "setup":
        if not setup_keys:
            return "is written by the setup session: pass --setup-pub keys/setup.pub"
        bad = [label for label, pub in setup_keys if not valid(pub, text, w["sig"])]
        return ("isn't signed by " + " / ".join(bad)) if bad else None
    if w.get("by") != "machine":
        return "names an unknown writer"
    if not box_keys:
        return "is written by a session: pass --box-pub keys/box.pub to check it"
    core_pub, why = core_of(d, box_keys)
    if why:
        return why
    cert = w.get("cert")
    if not isinstance(cert, dict) or not isinstance(cert.get("payload"), str) or not isinstance(cert.get("sig"), str):
        return "a session's write without the machine's cert"
    if not valid(core_pub, cert["payload"].encode(), cert["sig"]):
        return "the machine's cert isn't signed by its core"
    try:
        cp = json.loads(cert["payload"])
        mkey = load_pub(cp["machine"]["signingKey"], "the machine's signing key")
    except (ValueError, KeyError, TypeError, Usage):
        return "the machine's cert names no signing key"
    if cp.get("kind") != "succession-cert":
        return "the machine's cert isn't a succession cert"
    if not valid(mkey, text, w["sig"]):
        return "isn't signed by the key in the machine's cert"
    return None


def open_key(key_obj, d, setup_keys, box_keys, master):
    """one keys/<store>/<key>.json → (store, key, at, value or None for a delete, explanation); raises Bad(why)"""
    store, key = key_obj
    if d.get("kind") != "key-backup" or d.get("store") != store or d.get("key") != key:
        raise Bad("names another key")
    if not KEY_RE.match(key):
        raise Bad("isn't a key name")
    try:
        at = parse_at(d.get("at"))
    except (ValueError, TypeError):
        raise Bad("has no time (at)")
    deleted = d.get("deleted")
    if not isinstance(deleted, bool):
        raise Bad("doesn't say whether it is a delete")
    sealed = d.get("sealed")
    if deleted:
        if sealed is not None or d.get("backupSha256") or d.get("e") or d.get("dataSha256"):
            raise Bad("a delete that carries a value")
    else:
        if not isinstance(sealed, dict) or not isinstance(sealed.get("e"), str) or not isinstance(sealed.get("data"), str):
            raise Bad("carries no sealed value")
        if hashlib.sha256((sealed["e"] + "\n" + sealed["data"]).encode()).hexdigest() != d.get("backupSha256"):
            raise Bad("backupSha256 isn't its sealed value's")
    why = check_key_writer(d, store, key, setup_keys, box_keys)
    if why:
        raise Bad(why)
    value = None
    if not deleted:
        plain = open_sealed(sealed, master, f"{store}\n{key}".encode())
        try:
            value = plain.decode("utf-8")
        except UnicodeDecodeError:
            raise Bad("holds something that isn't text")
    expl = d.get("explanation")
    return store, key, at, value, expl if isinstance(expl, str) else ""


def check_and_open(objs, setup_keys, master, box_keys=()):
    """the same checks as the app's Recover (ios/Jarvis4/Security/CoreSetup.swift readBackups), per object, then the
    merge: each store's whole-store backup, then its key backups written after it.
    → (stores {name: {sensitive, at, values, explanations}}, problems [(key, why)])"""
    problems, docs, keyobjs, seen = [], [], [], set()
    for o in objs:
        key = o["key"]
        if key in seen:
            problems.append((key, "comes twice"))
            continue
        seen.add(key)
        kp = key_path(key)
        if kp is not None:
            try:
                d = json.loads(o["body"])
                if not isinstance(d, dict):
                    raise ValueError
            except ValueError:
                problems.append((key, "isn't JSON"))
                continue
            keyobjs.append((key, kp, d))
            continue
        try:
            s = json.loads(o["body"])
            doc_text, sig = s["doc"], s["sig"]
            if not isinstance(doc_text, str) or not isinstance(sig, str):
                raise ValueError
        except Exception:
            problems.append((key, "isn't a signed document"))
            continue
        if not setup_keys:
            problems.append((key, "is signed by the setup key: pass --setup-pub keys/setup.pub"))
            continue
        bad = [label for label, pub in setup_keys if not valid(pub, doc_text.encode(), sig)]
        if bad:
            problems.append((key, "isn't signed by " + " / ".join(bad)))
            continue
        try:
            docs.append((key, json.loads(doc_text)))
        except ValueError:
            problems.append((key, "isn't JSON inside"))
    marked = set()
    for key, d in docs:
        n = name_of(key, "sensitive/")
        if n is None:
            continue
        if d.get("kind") != "store-sensitive" or d.get("name") != n:
            problems.append((key, "names another store"))
        else:
            marked.add(n)
    stores = {}
    for key, d in docs:
        n = name_of(key, "stores/")
        if n is None:
            if name_of(key, "sensitive/") is None:
                problems.append((key, "isn't under stores/, sensitive/ or keys/"))
            continue
        if n in stores:
            problems.append((key, "comes twice"))
            continue
        if d.get("kind") != "store-backup" or d.get("name") != n or not isinstance(d.get("sealed"), dict):
            problems.append((key, "names another store"))
            continue
        try:
            plain = open_sealed(d["sealed"], master, n.encode())
        except Bad as e:
            problems.append((key, str(e)))
            continue
        try:
            values = json.loads(plain)
            if not isinstance(values, dict) or not all(isinstance(v, str) for v in values.values()):
                raise ValueError
        except ValueError:
            problems.append((key, "holds something that isn't a store"))
            continue
        stores[n] = {"sensitive": bool(d.get("sensitive")) or n in marked, "at": d.get("at"), "values": values, "explanations": {}}
    # key backups, oldest first, onto each store's whole-store backup (a store with only key backups starts empty;
    # the core makes a store sensitive on its first key, so such a store is sensitive)
    opened = []
    for key, kp, d in keyobjs:
        try:
            opened.append(open_key(kp, d, setup_keys, box_keys, master))
        except Bad as e:
            problems.append((key, str(e)))
    for store, k, at, value, expl in sorted(opened, key=lambda x: x[2]):
        s = stores.setdefault(store, {"sensitive": True, "at": None, "values": {}, "explanations": {}})
        base_at = s["at"]
        if isinstance(base_at, (int, float)) and not isinstance(base_at, bool) and at <= base_at:
            continue  # written before the whole-store backup: that backup already has it as it was then
        if value is None:
            s["values"].pop(k, None)
            s["explanations"].pop(k, None)
        else:
            s["values"][k] = value
            if expl:  # a write without one keeps the key's explanation as it was
                s["explanations"][k] = expl
    return stores, problems


# ---- output ------------------------------------------------------------------------------------------------

def write_private(path, data, force):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    if force and os.path.lexists(path):
        os.unlink(path)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise Usage(f"{path} exists: pass --force to replace it")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)
    os.chmod(path, 0o600)


def default_out(meta):
    at = meta.get("fetchedAt") or ""
    day = at[:10] if len(at) >= 10 else datetime.date.today().isoformat()
    return f"jarvis2-stores-{day}.json"


def main(argv=None):
    os.umask(0o077)
    p = argparse.ArgumentParser(prog="decrypt-backup", description="Open an offline copy of Jarvis 4's store backups "
                                "with the recovery kit (offline; docs/RUNBOOK.md \"Offline copy of the stores\").")
    p.add_argument("file", help="the app's jarvis2-backup-<date>.json (or a raw /api/backups answer, or one stores/<name>.json)")
    p.add_argument("--kit-file", metavar="KIT", help="a file holding the recovery kit; - = stdin (default: asked for, no echo)")
    p.add_argument("--setup-pub", metavar="PATH", help="keys/setup.pub from a clone of DE0CH/jarvis2: must be the file's setup key too")
    p.add_argument("--box-pub", metavar="PATH", help="keys/box.pub from a clone of DE0CH/jarvis2: checks keys written by sessions "
                   "(their core's identity); must be the file's box key too, when it names one")
    p.add_argument("--out", metavar="PATH", help="where the plaintext goes (default ./jarvis2-stores-<date>.json; a path ending in / = one file per store)")
    p.add_argument("--stdout", action="store_true", help="print the plaintext stores (JSON) to stdout instead of writing a file")
    p.add_argument("--force", action="store_true", help="replace an existing output file")
    p.add_argument("--skip-bad", action="store_true", help="leave out objects that fail a check instead of stopping")
    a = p.parse_args(argv)
    try:
        objs, meta = load_input(a.file)
        setup_keys = []
        if meta.get("setupKey"):
            setup_keys.append(("the file's setup key", load_pub(meta["setupKey"], "the file's setupKey")))
        if a.setup_pub:
            try:
                given = read_text(a.setup_pub)
            except OSError as e:
                raise Usage(f"can't read {a.setup_pub}: {e}")
            gk = load_pub(given, a.setup_pub)
            if setup_keys and public_bytes(gk) != public_bytes(setup_keys[0][1]):
                raise Bad(f"the file's setup key isn't {a.setup_pub}: the file was checked against another key")
            setup_keys.append((a.setup_pub, gk))
        box_keys = []
        if meta.get("boxKey"):
            box_keys.append(("the file's box key", load_pub(meta["boxKey"], "the file's boxKey")))
        if a.box_pub:
            try:
                bk = load_pub(read_text(a.box_pub), a.box_pub)
            except OSError as e:
                raise Usage(f"can't read {a.box_pub}: {e}")
            if box_keys and public_bytes(bk) != public_bytes(box_keys[0][1]):
                raise Bad(f"the file's box key isn't {a.box_pub}: the file names another key")
            box_keys.append((a.box_pub, bk))
        if not setup_keys and not all(session_written(o) for o in objs):
            raise Usage("this file names no setup key: pass --setup-pub keys/setup.pub")
        if a.kit_file and a.kit_file != "-":
            try:
                kit = read_text(a.kit_file)
            except OSError as e:
                raise Usage(f"can't read {a.kit_file}: {e}")
        elif a.kit_file == "-" or not sys.stdin.isatty():
            kit = sys.stdin.read()
        else:
            kit = getpass.getpass("Recovery kit (jarvis2-kit:2:…, not echoed): ")
        master, kit_kind = parse_kit(kit)
        del kit
        stores, problems = check_and_open(objs, setup_keys, master, box_keys)
        log = lambda *x: print(*x, file=sys.stderr)
        log(f"{len(objs)} objects from {meta.get('bucket') or 'an unknown bucket'}"
            + (f", fetched {meta['fetchedAt']}" if meta.get("fetchedAt") else "") + f"; master key from the {kit_kind}")
        log("setup key checked: " + (", ".join(label for label, _ in setup_keys) or "none given")
            + "; box key: " + (", ".join(label for label, _ in box_keys) or "none given"))
        for key, why in problems:
            log(f"BAD  {key}: {why}")
        if problems and not a.skip_bad:
            raise Bad(f"{len(problems)} object(s) failed; nothing written (--skip-bad leaves them out)")
        for n in sorted(stores):
            s = stores[n]
            log(f"ok   {n}: {len(s['values'])} keys{' (sensitive)' if s['sensitive'] else ''}")
        if not stores:
            raise Bad("no store in the file")
        out = {"format": "jarvis2-stores", "version": 1, "source": os.path.basename(a.file), "bucket": meta.get("bucket"),
               "fetchedAt": meta.get("fetchedAt"), "setupKey": public_b64(setup_keys[-1][1]) if setup_keys else None,
               "stores": {n: stores[n] for n in sorted(stores)}}
        if a.stdout:
            print(json.dumps(out, indent=2, sort_keys=True))
            return 0
        path = a.out or default_out(meta)
        if path.endswith("/") or os.path.isdir(path):
            os.makedirs(path, mode=0o700, exist_ok=True)
            os.chmod(path, 0o700)
            for n, s in out["stores"].items():
                write_private(os.path.join(path, n + ".json"), json.dumps(dict(s, name=n), indent=2, sort_keys=True) + "\n", a.force)
            log(f"wrote {len(stores)} files (mode 0600) in {path}")
        else:
            write_private(path, json.dumps(out, indent=2, sort_keys=True) + "\n", a.force)
            log(f"wrote {path} (mode 0600): {len(stores)} stores")
        return 0
    except Usage as e:
        print(f"decrypt-backup: {e}", file=sys.stderr)
        return 2
    except Bad as e:
        print(f"decrypt-backup: {e}", file=sys.stderr)
        return 1


def session_written(o):
    """a keys/ object whose writer is a session (needs no setup key)"""
    if key_path(o["key"]) is None:
        return False
    try:
        return json.loads(o["body"])["writer"]["by"] in ("machine", "restore")
    except Exception:
        return False


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def public_bytes(pub):
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


if __name__ == "__main__":
    sys.exit(main())
