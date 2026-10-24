#!/usr/bin/env python3
"""Which kernel Deployments the images pin job moves onto the build of SHA, and the move itself.

Every kernel component makes fresh RAM-only keys at start, so a restart stales the root-signed roster and Jarvis 4
locks until Deyao re-signs it with Face ID. So a component moves only when (1) the files its binary is built from
changed since the build its Deployment pins, and (2) Deyao asked for a kernel release: a commit after that pin carries
the trailer `Kernel-Release: <why> (Deyao, YYYY-MM-DD)` and the component's inputs did not change after it.

A component's inputs: the module's own packages that `go list -deps ./cmd/<role>` reaches (their non-test .go files,
by directory so a deleted file counts, plus embedded files), kernel/go.mod, kernel/go.sum and kernel/Dockerfile's
build (comments, blank lines and `go test` steps dropped). Tests, kerneltest, internal/kt, flowtest and tools are not
inputs. The serving secrets colour (active-secrets.txt) is never moved: a secrets restart empties it.

  kernel-pin.py plan KERNEL_YAML ACTIVE_COLOUR SHA   prints the Deployments to move, one per line; exit 1 (and
                                                     ::error:: lines naming what changed) when inputs changed with no
                                                     Kernel-Release after them: then it prints nothing to move
  kernel-pin.py apply KERNEL_YAML IMAGE NAME...      moves those Deployments' kernel image to IMAGE
Run from the repository root; needs git and go.
"""
import os, re, subprocess, sys, tempfile

MOD = "github.com/DE0CH/jarvis4/kernel"
IMG = re.compile(r"ghcr.io/de0ch/jarvis4-kernel:(latest|sha-[0-9a-f]{12}(@sha256:[0-9a-f]{64})?)")
TRAILER = re.compile(r"^.+ \(Deyao, \d{4}-\d{2}-\d{2}\)$")


def git(*a, check=True):
    return subprocess.run(["git", *a], check=check, capture_output=True, text=True)


def deployments(text):
    """[(name, role, pinned sha12 or None, part index)] for each kernel Deployment in kernel.yaml."""
    out = []
    for i, p in enumerate(text.split("\n---\n")):
        if "kind: Deployment" not in p:
            continue
        name = re.search(r"metadata: \{ name: ([a-z0-9-]+),", p).group(1)
        role = re.search(r'command: \["/kernel/([a-z]+)"\]', p).group(1)
        m = IMG.search(p)
        pin = m.group(1)[4:16] if m and m.group(1) != "latest" else None
        out.append((name, role, pin, i))
    return out


def dockerfile_build(text):
    """kernel/Dockerfile as far as the binaries go: continuation lines joined, comments, blank lines and `go test` steps
    dropped (a test run never changes what is built)."""
    s = re.sub(r"\\\n", " ", text)
    lines = []
    for l in s.splitlines():
        l = l.strip()
        if not l or l.startswith("#"):
            continue
        l = re.sub(r"(\S+=\S+\s+)*go test(\s[^&;|]*)?(&&|;)\s*", "", l)
        lines.append(re.sub(r"\s+", " ", l))
    return "\n".join(lines)


def inputs(sha, roles):
    """{role: [pathspec…]} at SHA: the package directories (non-test .go files) and embedded files of the module's own
    packages each kernel/cmd/<role> is built from, plus kernel/go.mod and kernel/go.sum."""
    with tempfile.TemporaryDirectory() as d:
        arch = subprocess.run(["git", "archive", sha, "kernel"], check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", d], input=arch, check=True)
        src = os.path.join(d, "kernel")
        env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH="amd64", GOFLAGS="-mod=readonly")
        out = {}
        for r in sorted(set(roles)):
            if not os.path.isdir(os.path.join(src, "cmd", r)):
                out[r] = None  # no such binary at SHA: the Deployment can't move onto it
                continue
            lst = subprocess.run(["go", "list", "-e", "-deps", "-f",
                                  '{{if .Module}}{{if eq .Module.Path "' + MOD + '"}}{{.Dir}}|{{join .EmbedFiles ","}}{{end}}{{end}}',
                                  "./cmd/" + r], cwd=src, env=env, check=True, capture_output=True, text=True).stdout
            specs = ["kernel/go.mod", "kernel/go.sum"]
            for line in lst.split():
                dr, emb = line.split("|", 1)
                rel = "kernel/" + os.path.relpath(dr, src) if dr != src else "kernel"
                specs.append(f":(glob){rel}/*.go")
                specs += [f"{rel}/{e}" for e in emb.split(",") if e]
            out[r] = specs + [":(glob,exclude)kernel/**/*_test.go"]
        return out


def changed(a, b, specs):
    """Files of SPECS that differ between commits A and B, and whether the Dockerfile's build differs."""
    files = git("diff", "--name-only", a, b, "--", *specs).stdout.split()
    show = lambda c: git("show", f"{c}:kernel/Dockerfile", check=False).stdout
    if dockerfile_build(show(a)) != dockerfile_build(show(b)):
        files.append("kernel/Dockerfile (its build lines)")
    return files


def releases(sha, pin):
    """[(commit, why)] newest first: the commits after PIN up to SHA with a Kernel-Release trailer, and malformed ones."""
    rng = f"{pin}..{sha}" if pin else sha
    log = git("log", "--format=%H%x1f%(trailers:key=Kernel-Release,valueonly,separator=%x1e)%x1d", rng).stdout
    good, bad = [], []
    for rec in log.split("\x1d"):
        rec = rec.strip("\n")
        if "\x1f" not in rec:
            continue
        c, v = rec.split("\x1f", 1)
        for t in filter(None, (x.strip() for x in v.split("\x1e"))):
            (good if TRAILER.match(t) else bad).append((c, t))
    return good, bad


def plan(kf, active, sha):
    sha = git("rev-parse", "--verify", sha + "^{commit}").stdout.strip()
    ds = [d for d in deployments(open(kf).read()) if d[0] != "secrets-" + active]
    ins = inputs(sha, [d[1] for d in ds])
    move, refused = [], []
    for name, role, pin, _ in ds:
        full = git("rev-parse", "-q", "--verify", f"{pin}^{{commit}}", check=False).stdout.strip() if pin else ""
        if full == sha:
            continue
        if ins[role] is None:
            refused.append(f"{name}: kernel/cmd/{role} does not exist at {sha[:12]}")
            continue
        if full and git("merge-base", "--is-ancestor", full, sha, check=False).returncode != 0:
            full = ""  # pinned to a build that isn't behind SHA: compare as if unpinned
        files = changed(full, sha, ins[role]) if full else ["(no pinned build to compare: " + (pin or "latest") + ")"]
        if not files:
            continue
        good, bad = releases(sha, full)
        for c, t in bad:
            print(f"::warning::{c[:12]} has a malformed trailer 'Kernel-Release: {t}' (needs 'Kernel-Release: <why> (Deyao, YYYY-MM-DD)'): ignored", file=sys.stderr)
        ok = next(((c, t) for c, t in good if not changed(c, sha, ins[role])), None)
        if ok:
            print(f"{name}: kernel release {ok[0][:12]} ({ok[1]}): {', '.join(files)}", file=sys.stderr)
            move.append(name)
        else:
            refused.append(f"{name} ({role}, pinned {pin or 'latest'}): {', '.join(files)}")
    if refused:
        for r in refused:
            print(f"::error::kernel image input changed with no kernel release: {r}", file=sys.stderr)
        print("::error::A kernel release restarts those components: their fresh keys stale the root-signed roster and "
              "Jarvis 4 locks until Deyao re-signs it with Face ID. It needs Deyao's OK, given as a commit trailer "
              "'Kernel-Release: <why> (Deyao, YYYY-MM-DD)' after the change (docs/RUNBOOK.md, 'A kernel release'); "
              "else revert the change. No kernel Deployment was pinned; the router and session pins went ahead.",
              file=sys.stderr)
        return 1
    if move:
        print("\n".join(move))
    return 0


def apply(kf, img, names):
    parts = open(kf).read().split("\n---\n")
    for name, _, _, i in deployments("\n---\n".join(parts)):
        if name in names:
            parts[i] = IMG.sub(img, parts[i])
    open(kf, "w").write("\n---\n".join(parts))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["plan"] and len(a) == 4:
        sys.exit(plan(*a[1:]))
    if a[:1] == ["apply"] and len(a) >= 3:
        sys.exit(apply(a[1], a[2], set(a[3:])))
    sys.exit(__doc__)
