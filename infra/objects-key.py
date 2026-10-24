#!/usr/bin/env python3
"""Jarvis 4's object-storage credential "jarvis4-objects": the router's key for the bucket jarvis4-snapshots-de0ch
(docs/STATE.md step 4/5: uploads, task-run outputs, restores, imports, then snapshots). Values never print.

S3 credentials exist only in the Hetzner Console (no API), so the Console steps drive a Chrome over CDP
(CDP, default http://127.0.0.1:9333 — e.g. a headed google-chrome on Xvfb with --remote-debugging-port=9333),
logged in as HETZNER_USER / HETZNER_PASSWORD (run it under `session-secret --keys
HETZNER_USER,HETZNER_PASSWORD,HETZNER_S3_ENDPOINT,HETZNER_S3_REGION,HETZNER_S3_ACCESS_KEY,HETZNER_S3_SECRET_KEY --exec`).
The admin key HETZNER_S3_* does the bucket policies and the cleanup. The new keys live in FILE
(~/.jarvis/jarvis4-objects.env, mode 600: ACCESS_KEY=… / SECRET_KEY=…) until `install`; then it is shredded.

A Hetzner S3 credential can do everything in the project unless a bucket policy denies it, so the key is fenced in by
statements of its own: every bucket but jarvis4-snapshots-de0ch gets Sid NoJarvis4ObjectsKey, a Deny of s3:* for it
(a bucket with no policy gets one; a new bucket needs `policies` run again). On its own bucket it may do everything.

  objects-key.py login       log the Console in (project "Cloud Code", 2827255)
  objects-key.py generate    a new credential "jarvis4-objects" → FILE (refuses if FILE exists)
  objects-key.py policies    the Deny statements name the new key (a rotated-out key is kept for delete-old)
  objects-key.py test        what the new key may do (wait ~1 min after `policies`)
  objects-key.py delete-old  delete the rotated-out credential in the Console
  objects-key.py store       the key into the infra store (JARVIS4_OBJECTS_ACCESS_KEY / _SECRET_KEY, scripts/store-put.py
                             of claude-env, CLAUDE_ENV=its checkout)
  objects-key.py install     the router's Secret: infra/router-secrets.py --box cluster --part objects (OBJECTS_ACCESS_KEY,
                             OBJECTS_SECRET_KEY), then shred FILE; commit and push it with k8s/cluster/router/router.yaml
"""
import json, os, re, secrets, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE = os.path.expanduser("~/.jarvis/jarvis4-objects.env")
OLD = os.path.expanduser("~/.jarvis/jarvis4-objects.old")
CDP = os.environ.get("CDP", "http://127.0.0.1:9333")
URL = "https://console.hetzner.com/projects/2827255/security/s3-credentials"
NAME = "jarvis4-objects"
B = "jarvis4-snapshots-de0ch"
SID_OTHER = "NoJarvis4ObjectsKey"


def client(ak, sk):
    import boto3
    from botocore.config import Config
    return boto3.client("s3", endpoint_url=os.environ["HETZNER_S3_ENDPOINT"], region_name=os.environ["HETZNER_S3_REGION"],
                        aws_access_key_id=ak, aws_secret_access_key=sk,
                        config=Config(s3={"addressing_style": "virtual"}, retries={"max_attempts": 2}))


def admin():
    return client(os.environ["HETZNER_S3_ACCESS_KEY"], os.environ["HETZNER_S3_SECRET_KEY"])


def newkey():
    v = dict(l.strip().split("=", 1) for l in open(FILE) if "=" in l)
    return v["ACCESS_KEY"], v["SECRET_KEY"]


def page(pw):
    ctx = pw.chromium.connect_over_cdp(CDP).contexts[0]
    return ctx.pages[0] if ctx.pages else ctx.new_page()


def mclick(pg, loc):
    """a real mouse click (the Console's row menu and its dialog ignore synthetic clicks)"""
    b = loc.bounding_box()
    x, y = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
    pg.mouse.move(x, y); time.sleep(0.3); pg.mouse.click(x, y)


def login():
    from playwright.sync_api import sync_playwright
    u, p = os.environ["HETZNER_USER"], os.environ["HETZNER_PASSWORD"]
    with sync_playwright() as pw:
        pg = page(pw)
        pg.goto(URL, wait_until="commit", timeout=120000)
        for _ in range(6):
            time.sleep(4)
            f = pg.locator("#_username")
            if f.count() and f.is_visible():
                for sel, val in (("#_username", u), ("#_password", p)):
                    pg.locator(sel).click(); pg.keyboard.press("Control+A"); pg.keyboard.press("Delete")
                    pg.locator(sel).type(val, delay=30)
                pg.keyboard.press("Enter"); time.sleep(10); continue
            if "console.hetzner.com/projects/2827255" in pg.url and "Log in to your account" not in pg.locator("body").inner_text()[:300]:
                print("ok: logged in"); return
            if "accounts.hetzner.com" in pg.url:
                pg.goto(URL, wait_until="commit", timeout=120000)
        raise SystemExit("not logged in: " + pg.url.split("?")[0])


def generate():
    from playwright.sync_api import sync_playwright
    if os.path.exists(FILE):
        raise SystemExit(f"{FILE} exists: install or shred it first")
    os.makedirs(os.path.dirname(FILE), mode=0o700, exist_ok=True)
    with sync_playwright() as pw:
        pg = page(pw)
        pg.goto(URL, wait_until="commit", timeout=120000); pg.get_by_role("button", name="Generate credentials").first.wait_for(timeout=120000)
        pg.get_by_role("button", name="Generate credentials").first.click(); time.sleep(2)
        inp = pg.locator('[data-test="create-s3-credentials-description"] [data-test="input"]')
        inp.click(); inp.type(NAME, delay=40); time.sleep(1)
        pg.get_by_role("button", name="Generate credentials").last.click()  # the dialog's own button
        for _ in range(20):
            time.sleep(1)
            if pg.locator("hc-click-to-show").count():
                break
        else:
            raise SystemExit("no credentials dialog")
        ak = next((t.strip() for t in pg.locator(".click-to-copy__content").all_inner_texts()
                   if re.fullmatch(r"[A-Z0-9]{20}", t.strip())), "")
        pg.locator(".click-to-show").first.click()
        sk = ""
        for _ in range(10):
            time.sleep(0.7)
            raw = pg.evaluate("document.querySelector('hc-click-to-show').textContent")
            raw = raw.replace("Click to show", "").replace("Some random text that is long", "").strip()
            if len(raw) == 40 and " " not in raw:
                sk = raw; break
        if not (ak and sk):
            raise SystemExit("couldn't read the new keys off the dialog")
        with os.fdopen(os.open(FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(f"ACCESS_KEY={ak}\nSECRET_KEY={sk}\n")
        pg.keyboard.press("Escape")
        print(f"ok: {NAME} generated (access key {ak[:4]}…) → {FILE}")


def policies():
    """the key's Deny statements on every other bucket name the new key; a key they named before is kept in OLD for
    delete-old (run it right after: a key no Deny names is unrestricted until it is deleted)"""
    from botocore.exceptions import ClientError
    s3, (new, _) = admin(), newkey()
    arn = "arn:aws:iam:::user/p2827255:" + new
    olds = set()
    buckets = [x["Name"] for x in s3.list_buckets()["Buckets"]]
    assert B in buckets, B + " doesn't exist"
    for b in buckets:
        try:
            j = json.loads(s3.get_bucket_policy(Bucket=b)["Policy"])
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise
            j = {"Version": "2012-10-17", "Statement": []}
        rest = []
        for st in j["Statement"]:
            if st.get("Sid") == SID_OTHER:
                olds |= set(re.findall(r"p2827255:([A-Za-z0-9]+)", json.dumps(st["Principal"]))) - {new}
            else:
                rest.append(st)
        if b == B:
            if len(rest) != len(j["Statement"]):
                j["Statement"] = rest
                s3.put_bucket_policy(Bucket=b, Policy=json.dumps(j)) if rest else s3.delete_bucket_policy(Bucket=b)
            print(f"ok: {b}: the key's own bucket, no Deny for it")
            continue
        j["Statement"] = rest + [{"Sid": SID_OTHER, "Effect": "Deny", "Principal": {"AWS": arn}, "Action": "s3:*",
                                  "Resource": [f"arn:aws:s3:::{b}", f"arn:aws:s3:::{b}/*"]}]
        s3.put_bucket_policy(Bucket=b, Policy=json.dumps(j))
        back = json.loads(s3.get_bucket_policy(Bucket=b)["Policy"])["Statement"]
        assert any(st.get("Sid") == SID_OTHER and new in json.dumps(st["Principal"]) for st in back), b
        assert len(back) == len(rest) + 1, b
        print(f"ok: {b} {SID_OTHER}: the new key is denied s3:* ({len(rest)} other statement(s) kept)")
    if olds:
        assert len(olds) == 1, "the statements named more than one other key"
        with os.fdopen(os.open(OLD, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(olds.pop())
        print("the rotated-out key is in", OLD, "(delete-old next)")


def test():
    from botocore.exceptions import ClientError
    s3, adm = client(*newkey()), admin()
    t = f"zz-permission-test/{secrets.token_hex(8)}"
    others = [x["Name"] for x in adm.list_buckets()["Buckets"] if x["Name"] != B]
    for O in others:
        adm.put_object(Bucket=O, Key=t, Body=b"x")
    rows = []

    def check(name, expect, fn):
        try:
            fn()
            res = "allowed"
        except ClientError as e:
            res = "refused (" + e.response["Error"].get("Code", "?") + ")"
        rows.append((name, res, res.startswith(expect)))
    check(f"put on {B}", "allowed", lambda: s3.put_object(Bucket=B, Key=t, Body=b"x"))
    check(f"get on {B}", "allowed", lambda: s3.get_object(Bucket=B, Key=t)["Body"].read())
    check(f"list {B}", "allowed", lambda: s3.list_objects_v2(Bucket=B, Prefix="zz-permission-test/"))
    check(f"delete on {B}", "allowed", lambda: s3.delete_object(Bucket=B, Key=t))
    for O in others:
        check(f"list {O}", "refused", lambda O=O: s3.list_objects_v2(Bucket=O, MaxKeys=1))
        check(f"get on {O}", "refused", lambda O=O: s3.get_object(Bucket=O, Key=t)["Body"].read())
        check(f"put on {O}", "refused", lambda O=O: s3.put_object(Bucket=O, Key=t + "-x", Body=b"x"))
        check(f"delete on {O}", "refused", lambda O=O: s3.delete_object(Bucket=O, Key=t))
        check(f"put the policy of {O}", "refused", lambda O=O: s3.put_bucket_policy(Bucket=O, Policy=adm.get_bucket_policy(Bucket=O)["Policy"]))
    for name, res, ok in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {res}")
    for b in [B] + others:
        r = adm.list_object_versions(Bucket=b, Prefix="zz-permission-test/")
        for x in r.get("Versions", []) + r.get("DeleteMarkers", []):
            adm.delete_object(Bucket=b, Key=x["Key"], VersionId=x["VersionId"])
    if not all(ok for _, _, ok in rows):
        raise SystemExit("some checks failed (a policy write takes up to a minute to reach every gateway: re-run)")
    print(f"ok: everything on {B}, nothing anywhere else")


def delete_old():
    from playwright.sync_api import sync_playwright
    old, (new, _) = open(OLD).read().strip(), newkey()
    with sync_playwright() as pw:
        pg = page(pw)
        pg.goto(URL, wait_until="commit", timeout=120000); time.sleep(8)
        row = pg.locator("hc-data-view-multi-select-row").filter(has_text=old)
        if row.count() == 0:
            print("ok: the old credential is already gone"); return
        assert row.count() == 1 and new not in row.inner_text()
        row.hover(); time.sleep(1)
        mclick(pg, row.locator('[data-test="dropdown-trigger"]')); time.sleep(1.5)
        mclick(pg, row.locator("a.dropdown__link--red")); time.sleep(2)
        mclick(pg, pg.get_by_role("button", name="OK", exact=True).locator("visible=true").last); time.sleep(6)
        pg.goto(URL, wait_until="commit", timeout=120000); time.sleep(8)
        texts = [r.inner_text() for r in pg.locator("hc-data-view-multi-select-row").all()]
        if any(old in t for t in texts) or not any(new in t for t in texts):
            raise SystemExit("the Console still lists the old credential (or not the new one)")
    os.remove(OLD)
    print("ok: the old credential is deleted")


def store():
    ce = os.environ.get("CLAUDE_ENV", os.path.expanduser("~/workspace/claude-env"))
    ak, sk = newkey()
    for k, v in (("JARVIS4_OBJECTS_ACCESS_KEY", ak), ("JARVIS4_OBJECTS_SECRET_KEY", sk)):
        p = os.path.join(os.path.dirname(FILE), k)
        with os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(v)
        try:
            why = ("Jarvis 4 router's Hetzner S3 " + ("access key" if "ACCESS" in k else "secret key") +
                   " (credential jarvis4-objects): bucket jarvis4-snapshots-de0ch only, denied on every other bucket by"
                   " bucket policies (jarvis4 infra/objects-key.py); the router has it as Secret router-secrets-objects")
            subprocess.run([sys.executable, os.path.join(ce, "scripts/store-put.py"), "infra", f"{k}=file:{p}", "--explain",
                            f"{k}={why}"], check=True, cwd=ce)
        finally:
            subprocess.run(["shred", "-u", p], check=True)
    print("ok: JARVIS4_OBJECTS_ACCESS_KEY / _SECRET_KEY in the infra store")


def install():
    ak, sk = newkey()
    env = dict(os.environ, OBJECTS_ACCESS_KEY=ak, OBJECTS_SECRET_KEY=sk)
    subprocess.run([sys.executable, os.path.join(ROOT, "infra/router-secrets.py"), "--box", "cluster",
                    "--part", "objects", "OBJECTS_ACCESS_KEY", "OBJECTS_SECRET_KEY"], check=True, env=env)
    subprocess.run(["shred", "-u", FILE], check=True)
    print(f"ok: in k8s/cluster/secrets/router-objects.enc.yaml (commit and push it with k8s/cluster/router/router.yaml); {FILE} shredded")


if __name__ == "__main__":
    cmds = {"login": login, "generate": generate, "policies": policies, "test": test, "delete-old": delete_old, "store": store, "install": install}
    a = sys.argv[1:]
    if not a or a[0] not in cmds:
        raise SystemExit(__doc__)
    cmds[a[0]]()
