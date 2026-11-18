# jarvis-request blocks until a checked outcome of its request is recorded (rust/machine/src/outcomes.rs record_outcome), prints
# it and exits 0 (approved) or 1; an older outcome of the same id is not this filing's; wait reads any recorded one.
import importlib.machinery, importlib.util, json, os, sys, tempfile, threading, time
loader = importlib.machinery.SourceFileLoader("jr", os.path.join(os.path.dirname(os.path.abspath(__file__)), "jarvis-request"))
spec = importlib.util.spec_from_loader("jr", loader); jr = importlib.util.module_from_spec(spec); loader.exec_module(jr)
# the command itself names the supervisor's outcomes dir (2026-11-17: only this test set it, and every real filing
# failed "NameError: OUTCOMES" while it waited)
assert jr.OUTCOMES == "/run/jarvis/outcomes", "jarvis-request names no outcomes dir"
jr.OUTCOMES = os.path.join(tempfile.mkdtemp(), "out"); os.makedirs(jr.OUTCOMES)
def put(ref, outcome, ns):
    json.dump({"ref": ref, "outcome": outcome, "text": f"{outcome.upper()}: {ref}"}, open(f"{jr.OUTCOMES}/{ref}.{ns}.json", "w"))
put("q1", "denied", 1)                      # an older outcome of the same id: ignored
since = time.time_ns()
threading.Timer(1.0, lambda: (put("q1", "approved", time.time_ns()), put("q2", "approved", time.time_ns()))).start()
assert jr.block(["q1", "q2"], since) == 0
since = time.time_ns()
threading.Timer(1.0, lambda: put("q3", "denied", time.time_ns())).start()
assert jr.block(["q3"], since) == 1
assert jr.block(["q9"], time.time_ns(), timeout=1) == 2
assert jr.block(["q1"], 0, timeout=1) == 0   # wait after a pause: any recorded outcome

# in an aviary sandbox the wait is a person wait on the supervisor's socket while it blocks, ended when it returns
# (Deyao, 2026-11-18: the chat's list shows the conversation as needing him); nothing without the socket
import http.server, socketserver
calls = []
class H(http.server.BaseHTTPRequestHandler):
    def _r(self):
        calls.append((self.command, self.path)); self.send_response(204); self.end_headers()
    do_POST = do_DELETE = _r
    def log_message(self, *a): pass
    def address_string(self): return "sandbox"
class U(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
jr.AGENT_SOCKET = os.path.join(tempfile.mkdtemp(), "agent.sock")
assert jr.block(["q1"], 0, timeout=1) == 0 and calls == []   # no socket: no person wait, no failure
srv = U(jr.AGENT_SOCKET, H); threading.Thread(target=srv.serve_forever, daemon=True).start()
since = time.time_ns()
threading.Timer(1.5, lambda: put("q4", "approved", time.time_ns())).start()
assert jr.block(["q4"], since) == 0
assert ("POST", "/v1/person-waits/inbox-q4?waitMs=20000") in calls, calls
assert calls[-1] == ("DELETE", "/v1/person-waits/inbox-q4"), calls

# a batch of two add-store items (two add-repos) names this session twice; one delivery records one file per id, so
# the wait is for each distinct id (2026-11-18: refs [s, s] against one file never ended, and its person wait kept
# the chat's dot yellow after Deyao approved)
since = time.time_ns()
threading.Timer(1.0, lambda: put("s2", "approved", time.time_ns())).start()
assert jr.block(["s2", "s2"], since, timeout=5) == 0

# the person wait covers only the wait for Deyao's decision: the stores are pulled after it ended, so the mark goes
# when he decides, not when the pull is done (which can take up to an hour)
import subprocess
calls.clear()
jr.subprocess.run = lambda a, **k: calls.append(("RUN", a[-1])) or subprocess.CompletedProcess(a, 0)
since = time.time_ns()
threading.Timer(1.0, lambda: put("s3", "approved", time.time_ns())).start()
assert jr.block(["s3"], since, stores=["gmail"]) == 0
assert calls.index(("DELETE", "/v1/person-waits/inbox-s3")) < calls.index(("RUN", "gmail")), calls
srv.shutdown()

# a single add-store waits on the id its answer names (the session's), never on "" (2026-11-18: the shell had no
# JARVIS2_SESSION_ID, the wait was on "" and never ended after Deyao approved); no id anywhere: it says so at once
import subprocess
ran = []
jr.subprocess.run = lambda a, **k: ran.append(a) or subprocess.CompletedProcess(a, 0)
for v in ("JARVIS2_SESSION_ID", "SESSION_ID"):
    os.environ.pop(v, None)
answer = {"ok": True, "approval": True, "id": "s1"}
jr.call = lambda m, p, b=None: answer
sys.argv = ["jarvis-request", "add-store", "gmail", "--why", "the mail"]
threading.Timer(1.0, lambda: put("s1", "approved", time.time_ns())).start()
try:
    jr.main()
except SystemExit as e:
    assert e.code == 0, e.code
assert ran == [["jarvis-machine", "await-store", "gmail"]], ran
answer = {"ok": True, "approval": True}
try:
    jr.main(); raise AssertionError("an answer with no id waited")
except SystemExit as e:
    assert "names no id" in str(e.code), e.code

# the router's answer is on stdout before the wait starts, also when stdout is a file (block-buffered): the phone
# replica starts jarvis-request detached with its output in a file and answers once the answer's id is there
# (2026-11-18: only stderr's "Waiting for Deyao's decision" reached the file, the JSON sat in the buffer until the
# decision, and every replica run failed "the session filed a grant request")
real_stdout, seen = sys.stdout, []
def on_wait(refs, since, stores=None):
    seen.append(open(outf).read())  # the file still open as stdout, as in the detached request
    return 0
jr.block = on_wait
for argv, ans in ((["grant", "status", "--minutes", "5", "--why", "x"], {"ok": True, "id": "q7"}),
                  (["batch", "--summary", "x", "--item", "grant,holder=archive,minutes=5"], {"id": "b7", "items": [{"id": "q8"}]})):
    outf = os.path.join(tempfile.mkdtemp(), "out")
    jr.call = lambda m, p, b=None, ans=ans: ans
    sys.argv = ["jarvis-request"] + argv
    sys.stdout = f = open(outf, "w")
    try:
        jr.main()
    except SystemExit:
        pass
    sys.stdout = real_stdout
    f.close()
    assert f'"id": "{ans["id"]}"' in seen[-1], (argv[0], seen[-1])
print("ok")
