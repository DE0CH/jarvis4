#!/usr/bin/env python3
"""infra/kernel-pin.py on a made-up history over this checkout's kernel/: test, kerneltest and Dockerfile-comment edits
move nothing; a spawner edit moves only the spawner, and only after a Kernel-Release trailer; an edit after the release
needs another; the serving secrets colour never moves. Offline; needs git and go: python3 infra/kernel_pin_test.py"""
import os, re, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIN = os.path.join(ROOT, "infra", "kernel-pin.py")
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
assert rc == 1 and out == [] and "kernel/spawner/spawner.go" in err and "spawner (spawner" in err and "notary" not in err, (rc, out, err)

# 3. a malformed trailer doesn't count; Deyao's trailer moves the spawner alone
git("commit", "-q", "--allow-empty", "-m", "release\n\nKernel-Release: placement retries")
rc, out, err = plan(git("rev-parse", "HEAD"))
assert rc == 1 and "malformed" in err, (rc, err)
git("commit", "-q", "--allow-empty", "-m", "release\n\nKernel-Release: placement retries (Deyao, 2026-10-24)")
rel = git("rev-parse", "HEAD")
rc, out, err = plan(rel)
assert (rc, out) == (0, ["spawner"]), (rc, out, err)

# 4. an edit after the release needs another one; a sig edit touches every component but the serving secrets
c = edit("kernel/sig/sig.go", "\n// x\n", "sig change")
rc, out, err = plan(c)
assert rc == 1 and out == [] and "secrets-green" in err and "secrets-blue" not in err, (rc, out, err)
git("commit", "-q", "--allow-empty", "-m", "release 2\n\nKernel-Release: sig fix (Deyao, 2026-10-24)")
rc, out, err = plan(git("rev-parse", "HEAD"))
assert rc == 0 and "secrets-blue" not in out and {"spawner", "notary", "secrets-green"} <= set(out), (rc, out, err)

# 5. go.mod counts; a deleted non-test file counts
pin_all(git("rev-parse", "HEAD"))
os.remove(os.path.join(d, "kernel/sig/identity.go"))
git("add", "-A")
git("commit", "-qm", "delete")
rc, out, err = plan(git("rev-parse", "HEAD"))
assert rc == 1 and "kernel/sig/identity.go" in err and "mover (mover" in err, (rc, err)
pin_all(git("rev-parse", "HEAD"))
c = edit("kernel/go.mod", "\n// x\n", "go.mod")
rc, out, err = plan(c)
assert rc == 1 and "kernel/go.mod" in err and "gullible (gullible" in err, (rc, err)

# 6. apply moves only the named Deployments
subprocess.run([sys.executable, PIN, "apply", KF, "ghcr.io/de0ch/jarvis4-kernel:sha-bbbbbbbbbbbb@sha256:" + "2" * 64, "spawner"], check=True)
s = open(KF).read()
assert s.count("sha-bbbbbbbbbbbb") == 1 and "name: spawner" in s.split("sha-bbbbbbbbbbbb")[0].rsplit("kind: Deployment", 1)[1], s
print("ok: kernel_pin_test")
