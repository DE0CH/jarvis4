#!/usr/bin/env python3
"""infra/kernel-pin.py on a made-up history over this checkout's kernel/: test, kerneltest and Dockerfile-comment edits
move nothing; a spawner edit moves only the other copy's spawner, and only after a Kernel-Release trailer; an edit after
the release needs another; the serving copy never moves; apply gives the other copy the release's build and the serving
copy's images, replicas 1 and the hold, which refuses the next release until kernel-flipped. Offline; needs git and go:
python3 infra/kernel_pin_test.py"""
import importlib.util, os, re, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIN = os.path.join(ROOT, "infra", "kernel-pin.py")
spec = importlib.util.spec_from_file_location("kernel_pin", PIN)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
d = tempfile.mkdtemp()
env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
git = lambda *a: subprocess.run(["git", *a], cwd=d, env=env, check=True, capture_output=True, text=True).stdout.strip()

arch = subprocess.run(["git", "archive", "HEAD", "kernel"], cwd=ROOT, check=True, capture_output=True).stdout
subprocess.run(["tar", "-x", "-C", d], input=arch, check=True)
git("init", "-q", "-b", "main")
git("add", "-A")
git("commit", "-qm", "base")
yaml_src = open(os.path.join(ROOT, "k8s", "cluster", "kernel", "kernel.yaml")).read()
KF = os.path.join(d, "kernel.yaml")


def pin_all(c):
    s = re.sub(r"ghcr.io/de0ch/jarvis4-kernel:(latest|sha-[0-9a-f]{12}(@sha256:[0-9a-f]{64})?)",
               "ghcr.io/de0ch/jarvis4-kernel:sha-" + c[:12], yaml_src)
    open(KF, "w").write(s)


def edit(path, add, msg):
    with open(os.path.join(d, path), "a") as f:
        f.write(add)
    git("add", "-A")
    git("commit", "-qm", msg)
    return git("rev-parse", "HEAD")


def plan(sha):
    r = subprocess.run([sys.executable, PIN, "plan", KF, "blue", sha], cwd=d, capture_output=True, text=True)
    return r.returncode, r.stdout.split(), r.stderr


base = git("rev-parse", "HEAD")
pin_all(base)

# 1. tests, kerneltest, internal/kt, flowtest and a Dockerfile comment are not inputs
c = edit("kernel/spawner/spawner_test.go", "\n// x\n", "test")
edit("kernel/kerneltest/kerneltest.go", "\n// x\n", "kerneltest")
edit("kernel/internal/kt/kt.go", "\n// x\n", "kt")
edit("kernel/flowtest/" + sorted(os.listdir(os.path.join(d, "kernel/flowtest")))[0], "\n// x\n", "flowtest")
c = edit("kernel/Dockerfile", "\n# a comment\n", "dockerfile comment")
assert plan(c) == (0, [], ""), plan(c)

# 2. a spawner source edit without a release: refused, names the file, moves nothing
c = edit("kernel/spawner/spawner.go", "\n// x\n", "spawner change")
rc, out, err = plan(c)
assert rc == 1 and out == [] and "kernel/spawner/spawner.go" in err and "spawner-blue (spawner" in err and "notary" not in err, (rc, out, err)

# 3. a malformed trailer doesn't count; Deyao's trailer moves the spawner alone
git("commit", "-q", "--allow-empty", "-m", "release\n\nKernel-Release: placement retries")
rc, out, err = plan(git("rev-parse", "HEAD"))
assert rc == 1 and "malformed" in err, (rc, err)
git("commit", "-q", "--allow-empty", "-m", "release\n\nKernel-Release: placement retries (Deyao, 2026-10-24)")
rel = git("rev-parse", "HEAD")
rc, out, err = plan(rel)
assert (rc, out) == (0, ["spawner-green"]), (rc, out, err)

# 4. an edit after the release needs another one; a sig edit touches every component, each moving only in green
c = edit("kernel/sig/sig.go", "\n// x\n", "sig change")
rc, out, err = plan(c)
assert rc == 1 and out == [] and "secrets-blue (secrets" in err, (rc, out, err)
git("commit", "-q", "--allow-empty", "-m", "release 2\n\nKernel-Release: sig fix (Deyao, 2026-10-24)")
rc, out, err = plan(git("rev-parse", "HEAD"))
assert rc == 0 and not [o for o in out if o.endswith("-blue")] and {"spawner-green", "notary-green", "secrets-green"} <= set(out), (rc, out, err)

# 5. go.mod counts; a deleted non-test file counts
pin_all(git("rev-parse", "HEAD"))
os.remove(os.path.join(d, "kernel/sig/identity.go"))
git("add", "-A")
git("commit", "-qm", "delete")
rc, out, err = plan(git("rev-parse", "HEAD"))
assert rc == 1 and "kernel/sig/identity.go" in err and "mover-blue (mover" in err, (rc, err)
pin_all(git("rev-parse", "HEAD"))
c = edit("kernel/go.mod", "\n// x\n", "go.mod")
rc, out, err = plan(c)
assert rc == 1 and "kernel/go.mod" in err and "gullible-blue (gullible" in err, (rc, err)

# 6. apply: the named green Deployment onto the build, every other green one onto blue's image, all of green replicas 1
# and held; blue untouched
pin_all(base)
ds = lambda: {n: (r, cp, pin, i) for n, r, cp, pin, i in M.deployments(open(KF).read())}
parts = lambda: open(KF).read().split("\n---\n")
blue_before = [parts()[i] for n, (_, cp, _, i) in ds().items() if cp == "blue"]
subprocess.run([sys.executable, PIN, "apply", KF, "blue", "ghcr.io/de0ch/jarvis4-kernel:sha-bbbbbbbbbbbb@sha256:" + "2" * 64, "spawner-green"], check=True)
for n, (_, cp, pin, i) in ds().items():
    p = parts()[i]
    if cp == "green":
        assert ("replicas: 1" in p and M.HOLD in p and pin == ("bbbbbbbbbbbb" if n == "spawner-green" else base[:12])), (n, p)
assert [parts()[i] for n, (_, cp, _, i) in ds().items() if cp == "blue"] == blue_before

# 7. the hold refuses the next release (green may serve already); nothing to move passes
git("commit", "-q", "--allow-empty", "-m", "release 3\n\nKernel-Release: more (Deyao, 2026-10-24)")
rc, out, err = plan(git("rev-parse", "HEAD"))
assert rc == 1 and out == [] and "in flight on the green copy" in err, (rc, out, err)

# 8. flipped: green's holds go, blue goes to replicas 0; with green serving, the next release lands on blue
subprocess.run([sys.executable, PIN, "flipped", KF, "green"], check=True)
for n, (_, cp, _, i) in ds().items():
    p = parts()[i]
    assert M.HOLD not in p and ("replicas: 0" in p) == (cp == "blue"), (n, p)
r = subprocess.run([sys.executable, PIN, "plan", KF, "green", git("rev-parse", "HEAD")], cwd=d, capture_output=True, text=True)
assert r.returncode == 0 and r.stdout.split() and all(o.endswith("-blue") for o in r.stdout.split()), (r.returncode, r.stdout, r.stderr)
print("ok: kernel_pin_test")
