#!/usr/bin/env python3
"""run-volumes.py — delete a throwaway run's leftover Fly volumes (ios/ci/replica-stack.sh down, infra/e2e.sh cleanup).

A test run (the phone replica, the e2e) runs its own core, which makes a `jarvis4_state` volume with every session
machine (core/volumes.go). The run's sweep of machines (by the peer their JARVIS2_URL names) deletes the volumes those
machines mount, but a volume whose machine is already gone is never seen that way: Fly names no machine for it, and a
volume carries no label of its own (every core names its volumes jarvis4_state, production's too). So the only safe
way to tell this run's volumes from production's in the same app is the run's own records:

  - its router's state (state.json under DATA_DIR): every machine the run's core started, with its volume
    (`started`);
  - its core's log: the volume ids the core logs (each volume it makes, an extend, a failed delete).

Every id found there and nowhere else is a candidate. One is deleted only when Fly lists it in the app, named
jarvis4_state, in state `created`, attached to nothing and mounted by no machine Fly lists (destroyed ones aside); a
candidate still attached (its machine being destroyed) is looked at again for up to ROUNDS × WAIT seconds. An id that
isn't in these files is never touched, whatever Fly says about it: leftovers of EARLIER runs whose records are gone
can't be told from production's and stay for Deyao (the Machines tab lists them as "not attached"; docs/RUNBOOK.md
"Leftover volumes").

  run-volumes.py [--rounds N] [--wait S] FILE...     FILE: a router state.json or a core log (missing files are skipped)
Env: FLY_TOKEN (a token that can delete volumes in the app), FLY_APP (default jarvis4-sessions),
     FLY_API (default https://api.machines.dev; the test points it at a fake).
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

VOLUME_NAME = "jarvis4_state"  # core/volumes.go volumeName
VOL_ID = re.compile(r"^vol_[a-z0-9]+$")
LOG_ID = re.compile(r"\bvolume (vol_[a-z0-9]+)\b")


def ids_in_state(doc, out):
    """every volume id a router state names: {"volume": {"id": …}} (started, certs)"""
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == "volume":
                if isinstance(v, dict) and isinstance(v.get("id"), str) and VOL_ID.match(v["id"]):
                    out.add(v["id"])
            ids_in_state(v, out)
    elif isinstance(doc, list):
        for v in doc:
            ids_in_state(v, out)


def run_ids(paths):
    out = set()
    for p in paths:
        try:
            text = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if p.endswith(".json"):
            try:
                ids_in_state(json.loads(text), out)
            except ValueError:
                print(f"run-volumes: {p} isn't JSON, skipped", file=sys.stderr)
            continue
        out.update(LOG_ID.findall(text))
    return out


class Fly:
    def __init__(self, base, app, token):
        self.base, self.app = base.rstrip("/"), app
        self.auth = token if token.startswith(("FlyV1 ", "Bearer ")) else "Bearer " + token

    def call(self, method, path):
        req = urllib.request.Request(f"{self.base}/v1/apps/{self.app}{path}", method=method,
                                     headers={"Authorization": self.auth, "User-Agent": "jarvis2-run-volumes"})
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
        return json.loads(body) if body.strip() else None


def deletable(v, mounted):
    """None when the volume may go now, else why not (yet)"""
    if v.get("name") != VOLUME_NAME:
        return "named " + str(v.get("name"))
    if v.get("attached_machine_id"):
        return "attached to " + v["attached_machine_id"]
    if v["id"] in mounted:
        return "mounted by " + mounted[v["id"]]
    if v.get("state") != "created":
        return "state " + str(v.get("state"))
    return None


def sweep(fly, ids, rounds, wait):
    left, deleted = set(ids), []
    for i in range(rounds):
        vols = {v["id"]: v for v in fly.call("GET", "/volumes") or []}
        mounted = {}
        for m in fly.call("GET", "/machines") or []:
            if m.get("state") == "destroyed":
                continue
            for x in ((m.get("config") or {}).get("mounts") or []):
                if x.get("volume"):
                    mounted[x["volume"]] = m["id"]
        waiting = {}
        for vid in sorted(left):
            v = vols.get(vid)
            if v is None or v.get("state") in ("destroyed", "destroying", "pending_destroy"):
                left.discard(vid)  # gone already (the kill or the machine sweep deleted it)
                continue
            why = deletable(v, mounted)
            if why is None:
                try:
                    fly.call("DELETE", "/volumes/" + vid)
                    print(f"run-volumes: deleted {vid} (unattached, this run's)")
                    deleted.append(vid)
                    left.discard(vid)
                    continue
                except urllib.error.HTTPError as e:
                    why = f"delete: HTTP {e.code}"
            if why.startswith(("attached", "mounted", "delete", "state")):
                waiting[vid] = why  # a machine still going away, or Fly busy: look again
            else:
                print(f"run-volumes: {vid} left alone ({why})")
                left.discard(vid)
        if not waiting:
            break
        if i + 1 < rounds:
            time.sleep(wait)
        else:
            for vid, why in sorted(waiting.items()):
                print(f"run-volumes: {vid} not deleted ({why}); it is this run's: docs/RUNBOOK.md \"Leftover volumes\"")
    return deleted


def main(argv):
    rounds, wait, paths = 12, 5.0, []
    it = iter(argv)
    for a in it:
        if a == "--rounds":
            rounds = int(next(it))
        elif a == "--wait":
            wait = float(next(it))
        else:
            paths.append(a)
    token = os.environ.get("FLY_TOKEN", "")
    if not token or not paths:
        print(__doc__.split("\n\n")[-1], file=sys.stderr)
        return 2
    ids = run_ids(paths)
    if not ids:
        print("run-volumes: this run's records name no volume")
        return 0
    fly = Fly(os.environ.get("FLY_API", "https://api.machines.dev"), os.environ.get("FLY_APP", "jarvis4-sessions"), token)
    try:
        sweep(fly, ids, max(1, rounds), wait)
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"run-volumes: Fly: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
