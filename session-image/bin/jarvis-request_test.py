# jarvis-request blocks until a checked outcome of its request is recorded (machine/outcomes.go recordOutcome), prints
# it and exits 0 (approved) or 1; an older outcome of the same id is not this filing's; wait reads any recorded one.
import importlib.machinery, importlib.util, json, os, sys, tempfile, threading, time
loader = importlib.machinery.SourceFileLoader("jr", os.path.join(os.path.dirname(os.path.abspath(__file__)), "jarvis-request"))
spec = importlib.util.spec_from_loader("jr", loader); jr = importlib.util.module_from_spec(spec); loader.exec_module(jr)
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
print("ok")
