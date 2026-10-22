#!/usr/bin/env python3
"""run_volumes_test.py — infra/run-volumes.py against a fake Fly Machines API: it deletes only the run's own
unattached jarvis4_state volumes, waits for one still attached, and never touches a volume its records don't name."""
import http.server
import importlib.util
import json
import os
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("run_volumes", os.path.join(HERE, "run-volumes.py"))
rv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rv)


class FakeFly:
    def __init__(self):
        self.volumes = {}
        self.machines = []
        self.deleted = []
        self.lists = 0
        self.lock = threading.Lock()

    def vol(self, vid, state="created", attached="", name="jarvis4_state"):
        self.volumes[vid] = {"id": vid, "name": name, "state": state, "attached_machine_id": attached}


def serve(fake):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, code, body):
            b = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            assert self.headers["Authorization"] == "Bearer tok"
            with fake.lock:
                if self.path == "/v1/apps/jarvis4-sessions/volumes":
                    fake.lists += 1
                    # the attached one's machine finishes going away after the first look
                    if fake.lists == 2 and "vol_attached" in fake.volumes:
                        fake.volumes["vol_attached"]["attached_machine_id"] = ""
                    return self.reply(200, list(fake.volumes.values()))
                if self.path == "/v1/apps/jarvis4-sessions/machines":
                    return self.reply(200, fake.machines)
            self.reply(404, {})

        def do_DELETE(self):
            vid = self.path.rsplit("/", 1)[-1]
            with fake.lock:
                v = fake.volumes.get(vid)
                if v is None or v["attached_machine_id"]:
                    return self.reply(409 if v else 404, {"error": "no"})
                fake.deleted.append(vid)
                v["state"] = "destroyed"
            self.reply(200, {})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    d = tempfile.mkdtemp()
    state = os.path.join(d, "state.json")
    json.dump({
        "started": {"m1": {"id": "m1", "volume": {"id": "vol_leaked", "sizeGb": 10, "path": "/data"}},
                    "m2": {"id": "m2", "volume": {"id": "vol_attached", "sizeGb": 10, "path": "/data"}},
                    "m3": {"id": "m3", "volume": {"id": "vol_gone", "sizeGb": 10, "path": "/data"}},
                    "m4": {"id": "m4", "volume": {"id": "vol_renamed", "sizeGb": 10, "path": "/data"}},
                    "m5": {"id": "m5", "volume": {"id": "vol_mounted", "sizeGb": 10, "path": "/data"}}},
    }, open(state, "w"))
    log = os.path.join(d, "core.log")
    open(log, "w").write("2026/10/22 machine m9: volume vol_fromlog (10 GB)\nunrelated vol_prod line\n")

    fake = FakeFly()
    fake.vol("vol_leaked")                         # the run's, its machine gone: deleted
    fake.vol("vol_fromlog")                        # named only in the core's log: deleted
    fake.vol("vol_attached", attached="m2")        # the run's, its machine still going away: deleted on a later look
    fake.vol("vol_renamed", name="something_else")  # not a session volume: left
    fake.vol("vol_mounted")                        # a machine still mounts it: left (until the rounds run out)
    fake.machines = [{"id": "m5", "state": "stopped", "config": {"mounts": [{"volume": "vol_mounted"}]}},
                     {"id": "mx", "state": "destroyed", "config": {"mounts": [{"volume": "vol_leaked"}]}}]
    fake.vol("vol_prod")                           # production's, unattached: never named by the run, never touched
    fake.vol("vol_prod2", attached="mprod")

    ids = rv.run_ids([state, log, os.path.join(d, "missing.log")])
    assert ids == {"vol_leaked", "vol_attached", "vol_gone", "vol_renamed", "vol_mounted", "vol_fromlog"}, ids

    srv = serve(fake)
    fly = rv.Fly(f"http://127.0.0.1:{srv.server_address[1]}", "jarvis4-sessions", "tok")
    deleted = rv.sweep(fly, ids, rounds=3, wait=0.01)
    assert sorted(fake.deleted) == ["vol_attached", "vol_fromlog", "vol_leaked"], fake.deleted
    assert sorted(deleted) == sorted(fake.deleted)
    for keep in ("vol_prod", "vol_prod2", "vol_renamed", "vol_mounted"):
        assert fake.volumes[keep]["state"] != "destroyed", keep

    # the whole script: no records → nothing listed, nothing deleted
    os.environ.update(FLY_TOKEN="tok", FLY_API=f"http://127.0.0.1:{srv.server_address[1]}")
    before = fake.lists
    assert rv.main([os.path.join(d, "missing.json")]) == 0 and fake.lists == before
    srv.shutdown()
    print("ok: run-volumes deletes only the run's own unattached volumes")


if __name__ == "__main__":
    sys.exit(main())
