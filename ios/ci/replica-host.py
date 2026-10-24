#!/usr/bin/env python3
"""The phone replica's host helper (ios.yml job `replica`): what a person and the setup session do around the phone,
served to the UI test (ReplicaUITests) on 127.0.0.1:18300.

  GET /faceid/match?for=N   Face ID matches for the next N seconds (each prompt that appears is matched)
  GET /faceid/nomatch       the next prompt fails (a face that isn't enrolled): no match is sent, and a nomatch every
                            1.5 s for 30 s (or until /faceid/match), so the prompt fails whenever it comes up
  GET /relay?msg=M          M to the setup session (HANDLER M, ios/ci/replica-setup.sh, on this runner); its stdout back
  GET /log?msg=M            a line in this helper's log
  GET /memwarn              the simulator's memory warning (Debug → Simulate Memory Warning)
  GET /backup-open?kit=K    the app's saved encrypted backup (its tmp/backups/*.json) opened offline with this run's
                            throwaway kit by tools/decrypt-backup.py (checked against setup.pub in JARVIS_KEYS_DIR, the
                            run's throwaway keys; else keys/): "ok <store>,…"
                            (a sensitive store ends in *; no values), or why not

  (transitions.yml runs it too, with HANDLER "-": no setup session there)

  replica-host.py UDID HANDLER
"""
import glob, http.server, json, os, subprocess, sys, tempfile, threading, time, urllib.parse

UDID, HANDLER = sys.argv[1], sys.argv[2]
state = {"until": 0.0, "fail_until": 0.0}
lock = threading.Lock()


def notify(name):
    subprocess.run(["xcrun", "simctl", "spawn", UDID, "notifyutil", "-p", f"com.apple.BiometricKit_Sim.{name}"], check=False)


def matcher():
    # a nomatch window rather than three blind nomatches: the prompt shows a moment after the tap, and on a slow
    # simulator all three landed before it (replica run 38407156816: the prompt then sat unanswered)
    while True:
        time.sleep(1.5)
        with lock:
            fail_until, until = state["fail_until"], state["until"]
        now = time.time()
        if now < fail_until:
            notify("pearl.nomatch")
        elif now < until:
            notify("pearl.match")


def relay(msg):
    if HANDLER == "-":
        return "no setup session here"
    return subprocess.run([HANDLER, msg], capture_output=True, text=True, timeout=900).stdout.strip()


REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def backup_open(kit):
    data = subprocess.run(["xcrun", "simctl", "get_app_container", UDID, "dev.de0ch.jarvis4", "data"],
                          capture_output=True, text=True).stdout.strip()
    files = sorted(glob.glob(os.path.join(data, "tmp", "backups", "jarvis2-backup-*.json")), key=os.path.getmtime)
    if not files:
        return f"no saved backup in {data}/tmp/backups"
    out = os.path.join(tempfile.mkdtemp(), "plain.json")
    p = subprocess.run([sys.executable, os.path.join(REPO, "tools", "decrypt-backup.py"), files[-1], "--kit-file", "-",
                        "--setup-pub", os.path.join(os.environ.get("JARVIS_KEYS_DIR") or os.path.join(REPO, "keys"), "setup.pub"), "--out", out], input=kit, capture_output=True, text=True)
    if p.returncode != 0:
        return f"decrypt-backup exit {p.returncode}: {p.stderr.strip()[-400:]}"
    with open(out) as f:
        stores = json.load(f)["stores"]
    os.remove(out)
    return "ok " + ",".join(n + ("*" if s["sensitive"] else "") for n, s in sorted(stores.items()))


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        out = "ok"
        if u.path == "/faceid/match":
            with lock:
                state["until"], state["fail_until"] = time.time() + float(q.get("for", "40")), 0.0
        elif u.path == "/faceid/nomatch":
            with lock:
                state["until"], state["fail_until"] = 0, time.time() + 30
        elif u.path == "/relay":
            print(f"relay → {q.get('msg')}", flush=True)
            try:
                out = relay(q.get("msg", ""))
            except Exception as e:
                out = f"relay failed: {e}"
            print(f"relay ← {len(out)} chars", flush=True)
        elif u.path == "/memwarn":
            subprocess.run(["xcrun", "simctl", "spawn", UDID, "notifyutil", "-p", "com.apple.UIKit.SimulatorMemoryWarning"], check=False)
        elif u.path == "/backup-open":
            try:
                out = backup_open(q.get("kit", ""))
            except Exception as e:
                out = f"backup-open failed: {e}"
            print(f"backup-open → {out[:200]}", flush=True)
        elif u.path == "/log":
            print(q.get("msg", ""), flush=True)
        else:
            self.send_response(404); self.end_headers(); return
        b = out.encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def log_message(self, f, *a):
        print(time.strftime("%H:%M:%S"), self.path.split("?")[0], flush=True)


threading.Thread(target=matcher, daemon=True).start()
http.server.ThreadingHTTPServer(("127.0.0.1", 18300), H).serve_forever()
