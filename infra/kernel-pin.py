#!/usr/bin/env python3
"""Which kernel Deployments the images pin job moves onto the build of SHA, and the move itself.

The kernel runs as two copies, blue and green (docs/PLAN-cluster.md "Releases: the copy flip"); ACTIVE (active-kernel.txt)
names the one that serves, and a release lands only on the other, which then takes over once Deyao signs its roster
(one Face ID). Every component makes fresh RAM-only keys at start, so a release still needs Deyao's OK: a component of
the other copy moves onto SHA only when (1) the files its binary is built from changed since the build the SERVING
copy's Deployment of it pins, and (2) a commit after that pin carries the trailer `Kernel-Release: <why> (Deyao,
YYYY-MM-DD)` and the component's inputs did not change after it. The move gives the other copy the release's build for
those components and the serving copy's images for the rest (so it runs everything the serving copy does), replicas 1,
and the hold `jarvis2/kernel-release: pending` on each of its Deployments. While that hold is there (the release not yet
flipped and committed: infra/setup.py kernel-flipped deletes it), a second release is refused: the copy it would land
on may be serving already.

A component's inputs: the module's own packages that `go list -deps ./cmd/<role>` reaches (their non-test .go files,
by directory so a deleted file counts, plus embedded files), kernel/go.mod, kernel/go.sum and kernel/Dockerfile's
build (comments, blank lines and `go test` steps dropped). Tests, kerneltest, internal/kt, flowtest and tools are not
inputs. The serving copy is never moved.

  kernel-pin.py plan KERNEL_YAML ACTIVE SHA          prints the other copy's Deployments to move onto SHA, one per line;
                                                     exit 1 (and ::error:: lines naming what changed) when inputs changed
                                                     with no Kernel-Release after them, or a release is in flight: then
                                                     it prints nothing to move
  kernel-pin.py apply KERNEL_YAML ACTIVE IMAGE NAME… the other copy: NAME… onto IMAGE, the rest onto the serving copy's
                                                     images, every one replicas 1 and held
  kernel-pin.py flipped KERNEL_YAML SERVING          after a flip (infra/setup.py kernel-flipped): SERVING's holds go,
                                                     the other copy's replicas go to 0
Run from the repository root; needs git and go.
"""
import os, re, subprocess, sys, tempfile

MOD = "github.com/DE0CH/jarvis4/kernel"
IMG = re.compile(r"ghcr.io/de0ch/jarvis4-kernel:(latest|sha-[0-9a-f]{12}(@sha256:[0-9a-f]{64})?)")
TRAILER = re.compile(r"^.+ \(Deyao, \d{4}-\d{2}-\d{2}\)$")
HOLD = "jarvis2/kernel-release: pending"
COPIES = ("blue", "green")


def git(*a, check=True):
    return subprocess.run(["git", *a], check=check, capture_output=True, text=True)


def other(copy):
    return "green" if copy == "blue" else "blue"


def deployments(text):
    """[(name, role, copy, pinned sha12 or None, part index)] for each kernel Deployment in kernel.yaml."""
    out = []
    for i, p in enumerate(text.split("\n---\n")):
        if "kind: Deployment" not in p:
            continue
        name = re.search(r"metadata: \{ name: ([a-z0-9-]+),", p).group(1)
        role = re.search(r'command: \["/kernel/([a-z]+)"\]', p).group(1)
        copy = name.rsplit("-", 1)[1]
        m = IMG.search(p)
        pin = m.group(1)[4:16] if m and m.group(1) != "latest" else None
        out.append((name, role, copy, pin, i))
    return out


def held(text, copy):
    """the other copy's Deployments that carry the hold (a release pinned there, not yet flipped and committed)"""
    parts = text.split("\n---\n")
    return [name for name, _, c, _, i in deployments(text) if c == copy and HOLD in parts[i]]


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
    if active not in COPIES:
        print(f"::error::active-kernel.txt names no kernel copy ({active!r})", file=sys.stderr)
        return 1
    sha = git("rev-parse", "--verify", sha + "^{commit}").stdout.strip()
    text = open(kf).read()
    standby = {d[1]: d[0] for d in deployments(text) if d[2] == other(active)}
    ds = [d for d in deployments(text) if d[2] == active]
    ins = inputs(sha, [d[1] for d in ds])
    move, refused = [], []
    for name, role, _, pin, _ in ds:
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
            print(f"{standby[role]}: kernel release {ok[0][:12]} ({ok[1]}): {', '.join(files)}", file=sys.stderr)
            move.append(standby[role])
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
    if move and held(text, other(active)):
        print(f"::error::a kernel release is in flight on the {other(active)} copy ({HOLD}): it may serve already, so "
              f"this release waits until that flip is done and committed (infra/setup.py kernel-flipped; docs/RUNBOOK.md "
              f"'A kernel release'). No kernel Deployment was pinned; the router and session pins went ahead.", file=sys.stderr)
        return 1
    if move:
        print("\n".join(move))
    return 0


def apply(kf, active, img, names):
    """the other copy: NAMES onto IMG, the rest onto the serving copy's image of their role; replicas 1 and the hold"""
    parts = open(kf).read().split("\n---\n")
    ds = deployments("\n---\n".join(parts))
    serving = {role: IMG.search(parts[i]).group(0) for _, role, c, _, i in ds if c == active}
    for name, role, c, _, i in ds:
        if c != other(active):
            continue
        p = IMG.sub(img if name in names else serving[role], parts[i])
        p = re.sub(r"(?m)^  replicas: \d+$", "  replicas: 1", p)
        if HOLD not in p:
            p = p.replace(f"metadata: {{ name: {name}, namespace: jarvis4-kernel }}",
                          f"metadata: {{ name: {name}, namespace: jarvis4-kernel, annotations: {{ {HOLD} }} }}")
        parts[i] = p
    open(kf, "w").write("\n---\n".join(parts))


def flipped(kf, serving):
    """after a flip to SERVING: its Deployments' hold goes, the other copy's replicas go to 0"""
    parts = open(kf).read().split("\n---\n")
    for name, _, c, _, i in deployments("\n---\n".join(parts)):
        if c == serving:
            parts[i] = parts[i].replace(f", annotations: {{ {HOLD} }}", "")
        else:
            parts[i] = re.sub(r"(?m)^  replicas: \d+$", "  replicas: 0", parts[i])
    open(kf, "w").write("\n---\n".join(parts))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["plan"] and len(a) == 4:
        sys.exit(plan(*a[1:]))
    if a[:1] == ["apply"] and len(a) >= 4:
        sys.exit(apply(a[1], a[2], a[3], set(a[4:])))
    if a[:1] == ["flipped"] and len(a) == 3 and a[2] in COPIES:
        sys.exit(flipped(a[1], a[2]))
    sys.exit(__doc__)
