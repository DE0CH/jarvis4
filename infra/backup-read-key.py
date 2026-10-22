#!/usr/bin/env python3
"""Jarvis 4's read credential for the backup bucket jarvis2-backup-de0ch (the stores' backups Jarvis 2 writes; the
Jarvis 4 app's Recover reads them through the router: GET /api/backups). Values never print.

S3 credentials exist only in the Hetzner Console (no API), so the Console steps drive a Chrome over CDP
(CDP, default http://127.0.0.1:9333 — e.g. a headed google-chrome on Xvfb with --remote-debugging-port=9333),
logged in as HETZNER_USER / HETZNER_PASSWORD (when they aren't in the env, run it under `session-secret --keys
HETZNER_USER,HETZNER_PASSWORD,HETZNER_S3_ENDPOINT,HETZNER_S3_REGION,HETZNER_S3_ACCESS_KEY,HETZNER_S3_SECRET_KEY --exec`).
The admin key HETZNER_S3_* does the bucket policies and the cleanup. The new keys live in FILE
(~/.jarvis2/jarvis4-backup-read.env, mode 600: ACCESS_KEY=… / SECRET_KEY=…) until `install` is done; then it is shredded.

A Hetzner S3 credential can do everything in the project unless a bucket policy denies it, so the key is restricted by
statements of its own, next to Jarvis 2's (whose statement and key stay as they are):
  jarvis2-backup-de0ch   Sid Jarvis4ReadKeyOnlyReads: Deny of every changing action, PutObject included (Jarvis 2's
                         latest backup versions must never be Jarvis 4's: the key only READS)
  every other bucket     Sid NoJarvis4BackupReadKey: Deny s3:* (a bucket with no policy gets one; a new bucket needs
                         `policies` run again)

  backup-read-key.py login       log the Console in (project "Cloud Code", 2827255)
  backup-read-key.py generate    a new credential "jarvis4-backup-read" → FILE (refuses if FILE exists)
  backup-read-key.py policies    the statements above name the new key (a rotated-out key is kept in
                                 ~/.jarvis2/jarvis4-backup-read.old for delete-old)
  backup-read-key.py test        what the new key may do (wait ~1 min after `policies`); throwaway names only, cleaned
                                 up by the admin key
  backup-read-key.py delete-old  delete the rotated-out credential in the Console (its row's ⋯ → Delete → OK)
  backup-read-key.py install     the router's secrets: infra/router-secrets.py --box cluster --part backup (SOPS to the
                                 cluster's age key, k8s/cluster/secrets/router-backup.enc.yaml), then shred FILE; commit
                                 and push that file and k8s/cluster/router/router.yaml (the router restarts with it)
"""
import json, os, re, secrets, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE = os.path.expanduser("~/.jarvis2/jarvis4-backup-read.env")
OLD = os.path.expanduser("~/.jarvis2/jarvis4-backup-read.old")
CDP = os.environ.get("CDP", "http://127.0.0.1:9333")
URL = "https://console.hetzner.com/projects/2827255/security/s3-credentials"
NAME = "jarvis4-backup-read"
B = "jarvis2-backup-de0ch"
SID_B, SID_OTHER = "Jarvis4ReadKeyOnlyReads", "NoJarvis4BackupReadKey"
J2_SID = "BackupReadKeyOnlyReads"  # Jarvis 2's own statement on B: its actions, plus PutObject, are the Jarvis 4 key's Deny


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
    """the Jarvis 4 key's own Deny statements name the new key; a key they named before is kept in OLD for delete-old
    (run it right after: a key no Deny names is unrestricted until it is deleted)"""
    from botocore.exceptions import ClientError
    s3, (new, _) = admin(), newkey()
    arn = "arn:aws:iam:::user/p2827255:" + new
    olds = set()
    for b in [x["Name"] for x in s3.list_buckets()["Buckets"]]:
        try:
            j = json.loads(s3.get_bucket_policy(Bucket=b)["Policy"])
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise
            j = {"Version": "2012-10-17", "Statement": []}
        sid = SID_B if b == B else SID_OTHER
        if b == B:
            j2 = next(st for st in j["Statement"] if st.get("Sid") == J2_SID)
            acts = sorted(set(j2["Action"] if isinstance(j2["Action"], list) else [j2["Action"]]) | {"s3:PutObject"})
        else:
            acts = "s3:*"
        mine = {"Sid": sid, "Effect": "Deny", "Principal": {"AWS": arn}, "Action": acts,
                "Resource": [f"arn:aws:s3:::{b}", f"arn:aws:s3:::{b}/*"]}
        rest = []
        for st in j["Statement"]:
            if st.get("Sid") == sid:
                olds |= set(re.findall(r"p2827255:([A-Za-z0-9]+)", json.dumps(st["Principal"]))) - {new}
            else:
                rest.append(st)
        j["Statement"] = rest + [mine]
        s3.put_bucket_policy(Bucket=b, Policy=json.dumps(j))
        back = json.loads(s3.get_bucket_policy(Bucket=b)["Policy"])["Statement"]
        assert any(st.get("Sid") == sid and new in json.dumps(st["Principal"]) for st in back), b
        assert len(back) == len(rest) + 1, b
        print(f"ok: {b} {sid}: the new key is denied {'every change' if b == B else 's3:*'} ({len(rest)} other statement(s) kept)")
    if olds:
        assert len(olds) == 1, "the statements named more than one other key"
        with os.fdopen(os.open(OLD, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(olds.pop())
        print("the rotated-out key is in", OLD, "(delete-old next)")


def test():
    from botocore.exceptions import ClientError
    s3, adm = client(*newkey()), admin()
    t = f"zz-permission-test/{secrets.token_hex(8)}"
    vid = adm.put_object(Bucket=B, Key=t + "-real", Body=b"x")["VersionId"]
    o2 = f"zz-permission-test/{secrets.token_hex(8)}"
    others = [x["Name"] for x in adm.list_buckets()["Buckets"] if x["Name"] != B]
    for O in others:
        adm.put_object(Bucket=O, Key=o2, Body=b"x")
    rows = []

    def check(name, expect, fn):
        try:
            r = fn()
            res = "refused (" + r["Errors"][0]["Code"] + ")" if isinstance(r, dict) and r.get("Errors") else "allowed"
        except ClientError as e:
            res = "refused (" + e.response["Error"].get("Code", "?") + ")"
        rows.append((name, res, res.startswith(expect)))
    check("list the backup bucket", "allowed", lambda: s3.list_objects_v2(Bucket=B, MaxKeys=5))
    check("get stores/default.json", "allowed", lambda: s3.get_object(Bucket=B, Key="stores/default.json")["Body"].read())
    check("list versions", "allowed", lambda: s3.list_object_versions(Bucket=B, MaxKeys=5))
    check("get the bucket policy", "allowed", lambda: s3.get_bucket_policy(Bucket=B))
    check("put (Jarvis 2's backups are never Jarvis 4's to write)", "refused", lambda: s3.put_object(Bucket=B, Key=t, Body=b"x"))
    check("plain delete", "refused", lambda: s3.delete_object(Bucket=B, Key=t + "-real"))
    check("delete a version", "refused", lambda: s3.delete_object(Bucket=B, Key=t + "-real", VersionId=vid))
    check("multi delete", "refused", lambda: s3.delete_objects(Bucket=B, Delete={"Objects": [{"Key": t + "-real"}]}))
    check("multi delete a version", "refused", lambda: s3.delete_objects(Bucket=B, Delete={"Objects": [{"Key": t + "-real", "VersionId": vid}]}))
    check("multi delete a missing name", "refused", lambda: s3.delete_objects(Bucket=B, Delete={"Objects": [{"Key": t + "-multi"}]}))
    check("delete the bucket policy", "refused", lambda: s3.delete_bucket_policy(Bucket=B))
    check("put the bucket policy", "refused", lambda: s3.put_bucket_policy(Bucket=B, Policy=adm.get_bucket_policy(Bucket=B)["Policy"]))
    check("suspend versioning", "refused", lambda: s3.put_bucket_versioning(Bucket=B, VersioningConfiguration={"Status": "Suspended"}))
    check("put a lifecycle", "refused", lambda: s3.put_bucket_lifecycle_configuration(Bucket=B, LifecycleConfiguration={"Rules": [
        {"ID": "x", "Status": "Enabled", "Filter": {"Prefix": "zz-permission-test/"}, "Expiration": {"Days": 1}}]}))
    check("put the bucket ACL", "refused", lambda: s3.put_bucket_acl(Bucket=B, ACL="private"))
    for O in others:
        check(f"list {O}", "refused", lambda O=O: s3.list_objects_v2(Bucket=O, MaxKeys=1))
        check(f"get on {O}", "refused", lambda O=O: s3.get_object(Bucket=O, Key=o2)["Body"].read())
        check(f"put on {O}", "refused", lambda O=O: s3.put_object(Bucket=O, Key=t, Body=b"x"))
        check(f"delete on {O}", "refused", lambda O=O: s3.delete_object(Bucket=O, Key=o2))
    for name, res, ok in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {res}")
    if adm.get_bucket_versioning(Bucket=B).get("Status") != "Enabled":
        adm.put_bucket_versioning(Bucket=B, VersioningConfiguration={"Status": "Enabled"})
        print("FAIL  versioning was changed (re-enabled)")
    for b in [B] + others:
        r = adm.list_object_versions(Bucket=b, Prefix="zz-permission-test/")
        for x in r.get("Versions", []) + r.get("DeleteMarkers", []):
            adm.delete_object(Bucket=b, Key=x["Key"], VersionId=x["VersionId"])
    if not all(ok for _, _, ok in rows):
        raise SystemExit("some checks failed (a policy write takes up to a minute to reach every gateway: re-run)")
    print("ok: reads only, on the backup bucket only")


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


def install():
    ak, sk = newkey()
    env = dict(os.environ, BACKUP_READ_ACCESS_KEY=ak, BACKUP_READ_SECRET_KEY=sk)
    subprocess.run([sys.executable, os.path.join(ROOT, "infra/router-secrets.py"), "--box", "cluster",
                    "--part", "backup", "BACKUP_READ_ACCESS_KEY", "BACKUP_READ_SECRET_KEY"], check=True, env=env)
    subprocess.run(["shred", "-u", FILE], check=True)
    print(f"ok: in k8s/cluster/secrets/router-backup.enc.yaml (commit and push it with k8s/cluster/router/router.yaml); {FILE} shredded")


if __name__ == "__main__":
    cmds = {"login": login, "generate": generate, "policies": policies, "test": test, "delete-old": delete_old, "install": install}
    a = sys.argv[1:]
    if not a or a[0] not in cmds:
        raise SystemExit(__doc__)
    cmds[a[0]]()
