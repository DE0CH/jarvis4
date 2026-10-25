#!/usr/bin/env python3
"""Deliver a prompt (stdin) into this session's MAIN DeepSeek Harness conversation (harness-send's `dsh` route).

dsh web (harness-dsh.sh) listens on 127.0.0.1:$DSH_PORT; its launch token is in ~/.dsh-run/token. This client
connects as an API peer (GET /connect?token=…, interactions=none: it never answers approvals), creates the main
conversation in the working dir on first use (its id kept in ~/.claude/.dsh-session) and sends the prompt with mode
"queue", so a prompt that arrives during a turn runs after it. Remote unary calls are POST /api/<ns>/<method> with
{"type":"client-request","rpcId","method","payload":{"args":{"request":{…}}}} (dsh's api-gateway).

  dsh-send.py WORKDIR [IMAGE…] < prompt.txt     exit 0 delivered, 1 failed (stderr says why)
"""
import http.cookiejar, json, os, sys, urllib.error, urllib.request, uuid

HOME = os.path.expanduser("~")
PORT = os.environ.get("DSH_PORT", "3080")
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = os.path.join(HOME, ".dsh-run", "token")
MAIN = os.path.join(HOME, ".claude", ".dsh-session")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def client():
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect)
    try:
        op.open(f"{BASE}/connect?token={open(TOKEN).read().strip()}&interactions=none", timeout=15)
    except urllib.error.HTTPError as e:
        if e.code != 302:
            raise SystemExit(f"dsh-send: /connect answered {e.code}")
    return op


def call(op, method, request):
    body = {"type": "client-request", "rpcId": str(uuid.uuid4()), "method": method, "payload": {"args": {"request": request}}}
    req = urllib.request.Request(f"{BASE}/api/{method}", json.dumps(body).encode(), {"content-type": "application/json"})
    res = json.loads(op.open(req, timeout=30).read() or b"{}").get("result") or {}
    if not res.get("ok"):
        raise SystemExit(f"dsh-send: {method}: {json.dumps(res.get('error'))[:300]}")
    return res.get("value") or {}


def main():
    wd, images = sys.argv[1], sys.argv[2:]
    text = sys.stdin.read()
    if images:
        text += "\n\nAttached images (read them with read_image): " + " ".join(images)
    if not text.strip():
        raise SystemExit("dsh-send: empty prompt")
    op = client()
    sid = open(MAIN).read().strip() if os.path.exists(MAIN) else ""
    if not sid:
        sid = call(op, "session/create", {"cwd": wd})["sessionId"]
        with open(MAIN + ".tmp", "w") as f:
            f.write(sid)
        os.replace(MAIN + ".tmp", MAIN)
    call(op, "session/prompt", {"requestId": str(uuid.uuid4()), "sessionId": sid, "mode": "queue",
                                "content": [{"type": "text", "text": text}]})
    print(json.dumps({"ok": True, "session": sid}))


if __name__ == "__main__":
    main()
