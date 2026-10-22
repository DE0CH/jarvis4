#!/usr/bin/env python3
"""apple-crash.py SINCE_FILE — exit 0 when the app crashed (a Jarvis4-*.ips newer than SINCE_FILE) inside Apple's own
code only: the faulting thread has no frame in the Jarvis4 binary and some in an accessibility framework (seen on the
iOS 27 simulator: AXBinaryMonitor → CFStreamCreateBoundPair, EXC_BAD_ACCESS while XCUITest reads the app). CI retries a
UI test once for that; any crash with our own frames is a real failure (exit 1)."""
import glob, json, os, sys

since = os.path.getmtime(sys.argv[1])
found = False
for p in glob.glob(os.path.expanduser("~/Library/Logs/DiagnosticReports/Jarvis4-*.ips")):
    if os.path.getmtime(p) <= since:
        continue
    try:
        _, body = open(p).read().split("\n", 1)
        d = json.loads(body)
        imgs = d["usedImages"]
        frames = d["threads"][d["faultingThread"]]["frames"]
        names = [imgs[f["imageIndex"]].get("name", "") for f in frames if f.get("imageIndex") is not None and f["imageIndex"] < len(imgs)]
    except Exception as e:
        print(f"{p}: unreadable ({e})"); sys.exit(1)
    if any(n == "Jarvis4" or n.startswith("Jarvis4.") for n in names):
        print(f"{p}: crash in the app's own code"); sys.exit(1)
    if not any(n.startswith("AX") or "Accessibility" in n for n in names):
        print(f"{p}: crash in system code that isn't accessibility: {names[:6]}"); sys.exit(1)
    print(f"{p}: crash inside Apple's accessibility code only: {names[:6]}")
    found = True
sys.exit(0 if found else 1)
