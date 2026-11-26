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

The bootstrap: a SERVING-copy Deployment that pins no build (`:latest`, a kernel that has never been released: the
first rollout of the two copies) moves onto SHA itself, in place, with no hold, under the same trailer rule; the other
copy isn't moved for that role. There is nothing to hand over from (the kernel starts empty), so the setup is a
Recover of the kernel's secrets, not a flip.

A component's inputs (role_files): rust/kernel/src/bin/<role>.rs and the kernel's modules it reaches (jarvis_kernel::,
then crate::, by file so a deleted one counts), the sources of the crates rust/kernel builds against by path (rust/sig,
rust/doc, …), every one's Cargo.toml and rust/rust-toolchain.toml; the packages of rust/Cargo.lock the kernel builds
with, the workspace's build profiles and rust/kernel/Dockerfile's build. Full-line comments and #[cfg(test)] modules
are dropped before comparing; tests (tests.rs, tests_*.rs, rust/kernel/tests/) and modules only tests reach (kt,
kerneltest) are not inputs. The serving copy is never moved.

  kernel-pin.py plan KERNEL_YAML ACTIVE SHA          prints the other copy's Deployments to move onto SHA, one per line;
                                                     exit 1 (and ::error:: lines naming what changed) when inputs changed
                                                     with no Kernel-Release after them, or a release is in flight: then
                                                     it prints nothing to move
  kernel-pin.py apply KERNEL_YAML ACTIVE IMAGE NAME… the other copy: NAME… onto IMAGE, the rest onto the serving copy's
                                                     images, every one replicas 1 and held
  kernel-pin.py flipped KERNEL_YAML SERVING          after a flip (infra/setup.py kernel-flipped): SERVING's holds go,
                                                     the other copy's replicas go to 0
Run from the repository root; needs git.
"""
import functools, os, re, subprocess, sys, tomllib

IMG = re.compile(r"ghcr.io/de0ch/jarvis4-kernel:(latest|sha-[0-9a-f]{12}(@sha256:[0-9a-f]{64})?)")
TRAILER = re.compile(r"^.+ \(Deyao, \d{4}-\d{2}-\d{2}\)$")
HOLD = "jarvis2/kernel-release: pending"
COPIES = ("blue", "green")
KERNEL = "rust/kernel"


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
    """rust/kernel/Dockerfile as far as the binaries go: continuation lines joined, comments, blank lines and `cargo
    test` steps dropped (a test run never changes what is built)."""
    s = re.sub(r"\\\n", " ", text)
    lines = []
    for l in s.splitlines():
        l = l.strip()
        if not l or l.startswith("#"):
            continue
        l = re.sub(r"(\S+=\S+\s+)*cargo test(\s[^&;|]*)?(&&|;)\s*", "", l)
        lines.append(re.sub(r"\s+", " ", l))
    return "\n".join(lines)


@functools.lru_cache(maxsize=None)
def show(c, path):
    """the file at commit C, or None"""
    r = git("show", f"{c}:{path}", check=False)
    return r.stdout if r.returncode == 0 else None


@functools.lru_cache(maxsize=None)
def ls(c, path):
    return tuple(git("ls-tree", "-r", "--name-only", c, "--", path).stdout.split())


def normalized(path, text):
    """what of a file reaches the binary: a .rs file without blank lines, full-line comments and its #[cfg(test)] modules (a
    column-0 `mod … {` closed by the next column-0 `}`, as rustfmt lays them out), a .toml without blank lines and
    comments"""
    if text is None:
        return None
    lines = text.splitlines()
    if path.endswith(".rs"):
        out, i = [], 0
        while i < len(lines):
            if lines[i] == "#[cfg(test)]" and i + 1 < len(lines) and lines[i + 1].startswith("mod ") and lines[i + 1].endswith("{"):
                j = i + 2
                while j < len(lines) and lines[j] != "}":
                    j += 1
                i = j + 1
                continue
            if lines[i].strip() and not lines[i].strip().startswith("//"):
                out.append(lines[i])
            i += 1
        return "\n".join(out)
    return "\n".join(l for l in lines if l.strip() and not l.strip().startswith("#"))


def test_file(path):
    """a test-only file: a module's tests (tests.rs, tests_*.rs), the kernel's tests/ and its test harnesses"""
    base = os.path.basename(path)
    return base == "tests.rs" or base.startswith("tests_") or "/tests/" in path


def refs(text, root):
    """the top-level modules TEXT names through ROOT:: (crate or jarvis_kernel), grouped imports included"""
    out = set()
    for m in re.finditer(r"\b" + root + r"::(\{|[a-z_][a-z0-9_]*)", text):
        if m.group(1) != "{":
            out.add(m.group(1))
            continue
        depth, item, i = 1, "", m.end()
        while i < len(text) and depth:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            if depth == 1 and ch == ",":
                item = ""
            elif depth == 1 and ch not in "{}":
                item += ch
                w = re.match(r"\s*([a-z_][a-z0-9_]*)", item)
                if w and (ch in " :" or i + 1 < len(text) and text[i + 1] in ",}:"):
                    out.add(w.group(1))
            i += 1
    return out


def module_files(c, m):
    """a top-level module's files at C: src/M.rs, or every file under src/M/ but its tests"""
    f = f"{KERNEL}/src/{m}.rs"
    if show(c, f) is not None:
        return [f]
    return [p for p in ls(c, f"{KERNEL}/src/{m}") if p.endswith(".rs") and not test_file(p)]


@functools.lru_cache(maxsize=None)
def crates(c):
    """the crate directories rust/kernel builds against at C: itself and its path dependencies, transitively"""
    seen, todo = [], [KERNEL]
    while todo:
        d = todo.pop()
        if d in seen:
            continue
        seen.append(d)
        toml = show(c, f"{d}/Cargo.toml") or ""
        deps = toml.split("[dev-dependencies]")[0]
        for m in re.finditer(r'path\s*=\s*"([^"]+)"', deps):
            todo.append(os.path.normpath(os.path.join(d, m.group(1))))
    return tuple(seen)


@functools.lru_cache(maxsize=None)
def role_files(c, role):
    """{path: what reaches the binary} of ROLE's build at C: rust/kernel/src/bin/ROLE.rs and the kernel's modules it
    reaches (through jarvis_kernel:: and then crate::), the other crates' sources and every Cargo.toml, and the
    toolchain (a module only tests reach, e.g. kt or kerneltest, never counts)"""
    bin_ = f"{KERNEL}/src/bin/{role}.rs"
    out = {}
    text = show(c, bin_)
    if text is not None:
        out[bin_] = text
        mods, todo = set(), set(refs(text, "jarvis_kernel"))
        while todo:
            m = todo.pop()
            if m in mods:
                continue
            mods.add(m)
            for f in module_files(c, m):
                out[f] = show(c, f)
                todo |= refs(out[f], "crate") - mods
    for d in crates(c):
        out[f"{d}/Cargo.toml"] = show(c, f"{d}/Cargo.toml")
        if d != KERNEL:
            for f in ls(c, f"{d}/src"):
                if f.endswith(".rs") and not test_file(f):
                    out[f] = show(c, f)
    out["rust/rust-toolchain.toml"] = show(c, "rust/rust-toolchain.toml")
    return {p: normalized(p, t) for p, t in out.items()}


@functools.lru_cache(maxsize=None)
def lock_closure(c):
    """the packages of rust/Cargo.lock that jarvis-kernel builds with at C (name, version, source, checksum)"""
    text = show(c, "rust/Cargo.lock")
    if not text:
        return ()
    pk = tomllib.loads(text).get("package", [])
    by = {}
    for p in pk:
        by.setdefault(p["name"], []).append(p)
    out, todo = {}, [("jarvis-kernel", None)]
    while todo:
        name, ver = todo.pop()
        for p in by.get(name, []):
            if ver and p["version"] != ver:
                continue
            key = (p["name"], p["version"], p.get("source", ""), p.get("checksum", ""))
            if key in out:
                continue
            out[key] = True
            for dep in p.get("dependencies", []):
                bits = dep.split(" ")
                todo.append((bits[0], bits[1] if len(bits) > 1 else None))
    return tuple(sorted(out))


def profiles(c):
    text = show(c, "rust/Cargo.toml")
    return repr(sorted(tomllib.loads(text).get("profile", {}).items())) if text else ""


def inputs(sha, roles):
    """{role: True, or None when SHA builds no binary of that role}"""
    return {r: (True if show(sha, f"{KERNEL}/src/bin/{r}.rs") is not None else None) for r in set(roles)}


def changed(a, b, role):
    """what of ROLE's build differs between commits A and B (see role_files), and whether the kernel's dependencies in
    Cargo.lock, the workspace's build profiles or the Dockerfile's build differ"""
    fa, fb = role_files(a, role), role_files(b, role)
    files = sorted(p for p in set(fa) | set(fb) if fa.get(p) != fb.get(p))
    if lock_closure(a) != lock_closure(b):
        files.append("rust/Cargo.lock (the kernel's dependencies)")
    if profiles(a) != profiles(b):
        files.append("rust/Cargo.toml (its build profiles)")
    if dockerfile_build(show(a, f"{KERNEL}/Dockerfile") or "") != dockerfile_build(show(b, f"{KERNEL}/Dockerfile") or ""):
        files.append(f"{KERNEL}/Dockerfile (its build lines)")
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
            refused.append(f"{name}: {KERNEL}/src/bin/{role}.rs does not exist at {sha[:12]}")
            continue
        if full and git("merge-base", "--is-ancestor", full, sha, check=False).returncode != 0:
            full = ""  # pinned to a build that isn't behind SHA: compare as if unpinned
        files = changed(full, sha, role) if full else ["(no pinned build to compare: " + (pin or "latest") + ")"]
        if not files:
            continue
        good, bad = releases(sha, full)
        for c, t in bad:
            print(f"::warning::{c[:12]} has a malformed trailer 'Kernel-Release: {t}' (needs 'Kernel-Release: <why> (Deyao, YYYY-MM-DD)'): ignored", file=sys.stderr)
        ok = next(((c, t) for c, t in good if not changed(c, sha, role)), None)
        if ok and not pin:  # the bootstrap: the serving copy has never been released, it is pinned in place
            print(f"{name}: kernel release {ok[0][:12]} ({ok[1]}): the serving copy's first pin, in place", file=sys.stderr)
            move.append(name)
        elif ok:
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
    if held(text, other(active)):
        # the release in flight already gave the held copy this build's inputs (a later build changed nothing it is made
        # from): nothing new to release, so this build passes instead of waiting on the flip
        spin = {d[0]: d[3] for d in deployments(text) if d[2] == other(active)}
        role_of = {v: k for k, v in standby.items()}

        def same(name):
            full = git("rev-parse", "-q", "--verify", f"{spin.get(name)}^{{commit}}", check=False).stdout.strip() if spin.get(name) else ""
            return bool(full) and git("merge-base", "--is-ancestor", full, sha, check=False).returncode == 0 \
                and not changed(full, sha, role_of[name])
        move = [m for m in move if m not in role_of or not same(m)]
    if set(move) & set(standby.values()) and held(text, other(active)):
        print(f"::error::a kernel release is in flight on the {other(active)} copy ({HOLD}): it may serve already, so "
              f"this release waits until that flip is done and committed (infra/setup.py kernel-flipped; docs/RUNBOOK.md "
              f"'A kernel release'). No kernel Deployment was pinned; the router and session pins went ahead.", file=sys.stderr)
        return 1
    if move:
        print("\n".join(move))
    return 0


def apply(kf, active, img, names):
    """the other copy: NAMES onto IMG, the rest onto the serving copy's image of their role; replicas 1 and the hold.
    A serving-copy name (the bootstrap): onto IMG in place, nothing else"""
    parts = open(kf).read().split("\n---\n")
    ds = deployments("\n---\n".join(parts))
    for name, _, c, _, i in ds:
        if c == active and name in names:
            parts[i] = IMG.sub(img, parts[i])
    serving = {role: IMG.search(parts[i]).group(0) for _, role, c, _, i in ds if c == active}
    release = any(c == other(active) and name in names for name, _, c, _, _ in ds)
    for name, role, c, _, i in ds:
        if c != other(active) or not release:
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
