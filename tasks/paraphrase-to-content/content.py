# Content stores from a Jarvis 4 task (router/content.go): through the machine's local API ($JARVIS_URL), which signs
# each call with the machine's key; the router reads and writes only the content stores the task line's cert names
# (its content fields), and the proxy takes a downloaded file only with the core's attestation. (Identical copy in
# each template that uses it.)
import os, sys
from urllib.parse import quote
import requests

J = os.environ.get("JARVIS_URL", "http://127.0.0.1:7171").rstrip("/")
SID = os.environ.get("SESSION_ID", "")


def _url(store, path):
    return f"{J}/api/sessions/{quote(SID, safe='')}/content/{quote(store, safe='')}/file?path={quote(path, safe='')}"


def get(store, path):
    r = requests.get(_url(store, path), timeout=120)
    if not r.ok:
        sys.exit(f"{store}/{path}: HTTP {r.status_code} {r.text[:200]}")
    return r.content


def put(store, path, data):
    r = requests.put(_url(store, path), data=data, headers={"Content-Type": "application/octet-stream"}, timeout=120)
    if not r.ok:
        sys.exit(f"{store}/{path}: HTTP {r.status_code} {r.text[:200]}")
