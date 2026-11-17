#!/bin/bash
# aviary-sandbox_test.sh (as root; images.yml): an aviary session's sandbox, on stand-in trees, in a mount namespace
# of its own. A stand-in for aviary's sandbox image (a root filesystem with a shell, its home's links, a config whose
# entrypoint reports what it sees) is fetched through a stand-in `crane`, and aviary-sandbox runs it:
#
#  - Dogfooding (Deyao, 2026-11-14/16): the sandbox IS the image. Its entrypoint runs as PID 1 in the image's working
#    directory with the image's environment and the boot environment, nothing of the machine's; the root is the
#    image's (the machine's files are out of sight); the home has the image's links, so Claude Code finds its home in
#    the supervisor's mount with nothing telling it where. A sandbox whose ~/.claude was a directory of its own had
#    Claude Code write its transcript beside the mount: no tool calls in the chat, a turn that never ended.
#  - The sandbox's home is the machine's home WITH what is mounted in it. ~/workspace and ~/artifacts are mounts from
#    the session's volume; a plain bind left them out, so an aviary session's task record, cloned repos and on-start
#    scripts were gone after its first pause (2026-11-13).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "aviary-sandbox_test: run as root" >&2; exit 1; }
if [ "${AVIARY_SANDBOX_TEST_INNER:-}" != 1 ]; then
  exec env AVIARY_SANDBOX_TEST_INNER=1 unshare --mount --propagation private "$0"
fi
fail() { echo "FAIL: $*" >&2; exit 1; }
t="$(mktemp -d)"; chmod 755 "$t"

# ---- the stand-in image: a root filesystem and its config
src="$t/image-src"
put() { # a program of this machine with the libraries it loads, at the same paths
  local b p l
  for b in "$@"; do
    p="$(command -v "$b")"; install -D "$p" "$src$p"
    for l in $(ldd "$p" | grep -o '/[^ ]*'); do [ -e "$src$l" ] || install -D "$l" "$src$l"; done
  done
}
put bash cat ls id readlink mkdir touch env
sh="$(command -v bash)"
mkdir -p "$src"/{proc,sys,dev,run,mnt,etc,tmp,work,workspace,usr/local/bin,home/sandbox/.harness}
ln -s .harness/claude "$src/home/sandbox/.claude"; ln -s .harness/qwen "$src/home/sandbox/.qwen"
echo "prefix=~/.npm-global" > "$src/home/sandbox/.npmrc"
chown -R 1000:1000 "$src/home/sandbox"; chown -h 1000:1000 "$src/home/sandbox/.claude" "$src/home/sandbox/.qwen"
echo image > "$src/usr/local/bin/supervisor-keeper"
cat > "$src/check.sh" <<'CHECK'
out=/home/sandbox/artifacts/result; : > "$out"
say() { echo "$1" >> "$out"; }
say "pid=$$"; say "cwd=$PWD"; say "image-env=${IMAGE_ENV:-}"; say "boot-env=${BOOT_VAR:-}"; say "machine-env=${MACHINE_VAR:-none}"
say "path=$PATH"
say "workspace=$(cat /home/sandbox/workspace/where 2>&1)"; say "artifacts=$(cat /home/sandbox/artifacts/where 2>&1)"
say "claude-link=$(readlink /home/sandbox/.claude)"
say "harness=$(ls -A /home/sandbox/.harness)"
mkdir /home/sandbox/.harness/claude && echo line > /home/sandbox/.claude/transcript   # what Claude Code does
say "transcript=$(cat /home/sandbox/.harness/claude/transcript 2>&1)"
say "wd=$(cat /workspace/f 2>&1)"
say "keeper=$(cat /usr/local/bin/supervisor-keeper)"
say "machine-root=$([ -e "$MARKER" ] && echo visible || echo gone); mnt=$(ls -A /mnt)"
say "tool=$(cat /usr/local/bin/jarvis-request 2>&1); jarvis=$(readlink /usr/local/bin/jarvis)"
if echo x 2> /dev/null > /usr/local/bin/jarvis-request; then say "tool-writable"; fi
say "secrets=$(cat /run/jarvis/sock 2>&1)"
say "resolv=$(cat /etc/resolv.conf)"
say "installed-before=$(cat /etc/installed 2>/dev/null || echo no)"
echo yes > /etc/installed
echo t > /run/jarvis-transcripts/c.jsonl
exit 7
CHECK
cat > "$t/config.json" <<JSON
{"config": {"Env": ["PATH=/usr/local/bin:/usr/bin:/bin", "IMAGE_ENV=from-the-image"], "WorkingDir": "/work",
            "Entrypoint": ["$sh", "/check.sh"]}}
JSON
digest="$(printf '%064d' 7)"; id="${digest:0:12}"
echo "{\"release\": \"aviary-test\", \"sandbox\": \"ghcr.io/de0ch/hermit-sandbox@sha256:$digest\"}" > "$t/pins.json"
# the stand-in crane: `export REF -` the image's files as a tar, `config REF` its config
mkdir "$t/path"
cat > "$t/path/crane" <<CRANE
#!/bin/bash
echo "\$*" >> "$t/crane.calls"
case "\$1" in export) exec tar -c -C "$src" . ;; config) exec cat "$t/config.json" ;; esac
exit 1
CRANE
chmod 755 "$t/path/crane"

# ---- the machine: its home with the volume's directories mounted in, its own ~/.claude, its session commands
home="$t/claude"
mkdir -p "$home/artifacts" "$home/workspace" "$home/.claude/projects" "$home/.claude/sessions" "$t/bin" "$t/store"
mount -t tmpfs tmpfs "$t/store"   # the session's volume (an overlay's upper cannot sit on a machine's overlay root)
mkdir "$t/store/image-old" "$t/store/upper-old"
echo root-disk > "$home/artifacts/where"
for d in artifacts workspace; do
  mount -t tmpfs tmpfs "$home/$d"
  echo volume > "$home/$d/where"
done
mkdir "$home/workspace/repo"; echo repo-file > "$home/workspace/repo/f"
echo login > "$home/.claude/.credentials.json"
mount -t tmpfs tmpfs "$home/.claude/projects"   # the volume's transcript mirror, mounted inside as the entrypoint does
mkdir "$home/.claude/projects/-home-claude-workspace"
for c in jarvis-machine jarvis-request session-secret; do echo "machine's $c" > "$t/bin/$c"; done
echo "BOOT_VAR=from-the-boot" > "$t/boot.env"
export AVIARY_PINS="$t/pins.json" AVIARY_SANDBOX_STORE="$t/store" AVIARY_SANDBOX_HOME="$home" AVIARY_SANDBOX_BIN="$t/bin"
export PATH="$t/path:$PATH" MACHINE_VAR=from-the-machine MARKER="$t/pins.json"

# ---- the fetch: the image on the volume, another pin's image and overlay gone
img="$(bash "$here/aviary-sandbox" --fetch)"
[ "$img" = "$t/store/image-$id" ] && [ -e "$img/check.sh" ] && [ -s "$img.config" ] || fail "--fetch did not unpack the image ($img)"
[ ! -e "$t/store/image-old" ] && [ ! -e "$t/store/upper-old" ] || fail "another pin's image stays on the volume"
bash "$here/aviary-sandbox" --fetch > /dev/null
[ "$(grep -c '^export' "$t/crane.calls")" = 1 ] || fail "an image already on the volume is fetched again"

# ---- the home gets what the image's home holds; without that the sandbox refuses to start
if bash "$here/aviary-sandbox" "$t/boot.env" "$home/workspace/repo" 2> "$t/err"; then fail "the sandbox started in a home without the image's links"; fi
grep -q "aviary-home" "$t/err" || fail "no word on why the sandbox did not start: $(cat "$t/err")"
"$here/aviary-home" "$home" "$img/home/sandbox"
"$here/aviary-home" "$home" "$img/home/sandbox"   # again: nothing changes
[ "$(readlink "$home/.claude")" = .harness/claude ] && [ "$(readlink "$home/.qwen")" = .harness/qwen ] || fail "the home has not the image's links"
[ "$(cat "$home/.npmrc")" = "prefix=~/.npm-global" ] || fail "the home has not the image's ~/.npmrc"
[ "$(cat "$home/.claude/.credentials.json")" = login ] || fail "the machine's ~/.claude files are not reachable through the link"

# ---- the sandbox
rc=0; bash "$here/aviary-sandbox" "$t/boot.env" "$home/workspace/repo" || rc=$?
[ "$rc" = 7 ] || fail "the sandbox did not end with the image's entrypoint's status (7): $rc"
r="$home/artifacts/result"
[ -s "$r" ] || fail "the sandbox's ~/artifacts is not the volume's: nothing written there"
want() { grep -qxF "$1" "$r" || fail "$2 (wanted: $1) in:"$'\n'"$(cat "$r")"; }
want "pid=1" "the image's entrypoint is not PID 1"
want "cwd=/work" "the entrypoint does not start in the image's working directory"
want "image-env=from-the-image" "the image's environment is not the entrypoint's"
want "boot-env=from-the-boot" "the boot environment is not passed on"
want "machine-env=none" "the machine's environment reaches the sandbox"
want "path=/usr/local/bin:/usr/bin:/bin" "the PATH is not the image's"
want "workspace=volume" "the sandbox's ~/workspace is the machine's root disk, not the volume"
want "artifacts=volume" "the sandbox's ~/artifacts is the machine's root disk, not the volume"
want "claude-link=.harness/claude" "the sandbox's ~/.claude is not the image's link"
want "harness=" "the machine's ~/.harness (its login, the mirror) shows in the sandbox"
want "transcript=line" "a file written to the sandbox's ~/.claude is not in ~/.harness (the supervisor's mount)"
want "wd=repo-file" "/workspace is not the harness's working directory"
want "keeper=image" "the supervisor is not the image's own"
want "machine-root=gone; mnt=" "the machine's root is visible in the sandbox"
want "tool=machine's jarvis-request; jarvis=jarvis-machine" "Jarvis's session commands are not in the sandbox"
want "secrets=cat: /run/jarvis/sock: No such file or directory" "unexpected /run/jarvis"
want "resolv=$(cat /etc/resolv.conf | head -1)" "the sandbox has not the machine's resolv.conf" 2>/dev/null || [ "$(grep -c . /etc/resolv.conf)" != 1 ] || fail "the sandbox has not the machine's resolv.conf"
want "installed-before=no" "the image's root is not clean at the first start"
grep -qx tool-writable "$r" && fail "the sandbox can write Jarvis's session commands"
[ ! -e "$home/.harness/claude/transcript" ] || fail "the sandbox's ~/.claude writes into the machine's own"
[ "$(cat "$home/.claude/projects/-home-claude-workspace/c.jsonl")" = t ] || fail "/run/jarvis-transcripts is not the machine's transcript mirror"
[ ! -e "$img/etc/installed" ] && [ "$(cat "$t/store/upper-$id/up/etc/installed")" = yes ] || fail "what the agent installs is written into the image, not over it"
# again: what was installed is still there (a sandbox's root lives as long as the session)
bash "$here/aviary-sandbox" "$t/boot.env" "$home/workspace/repo" || true
want "installed-before=yes" "what the agent installed is gone at the next start"
# nothing of the sandbox's mounts is left on the machine's side
[ -z "$(findmnt -rn -o TARGET | grep aviary-sandbox-root || true)" ] || fail "the sandbox's root is mounted on the machine's side"
echo "ok: the sandbox is the image: its entrypoint, environment, root and home links; the volume's ~/workspace and ~/artifacts; Jarvis's session commands"

# ---- a fabric machine (docs/PLAN-fabric.md): the image unpacked in the fabric image, its config beside it; nothing is
# fetched, the root is a bind of that directory (gVisor refuses the overlay), what is installed goes into it
fab="$t/fabric"; mkdir -p "$fab"
mount -t tmpfs tmpfs "$fab"   # the fabric's own writable root (sandboxd's overlay over the fabric image)
cp -a "$src" "$fab/aviary-sandbox"; cp "$t/config.json" "$fab/aviary-sandbox.config"
calls_before="$(wc -l < "$t/crane.calls")"
rc=0; AVIARY_SANDBOX_IMAGE_DIR="$fab/aviary-sandbox" bash "$here/aviary-sandbox" "$t/boot.env" "$home/workspace/repo" || rc=$?
[ "$rc" = 7 ] || fail "the fabric sandbox did not end with the image's entrypoint's status (7): $rc"
want "pid=1" "(fabric) the image's entrypoint is not PID 1"
want "boot-env=from-the-boot" "(fabric) the boot environment is not passed on"
want "machine-root=gone; mnt=" "(fabric) the machine's root is visible in the sandbox"
want "workspace=volume" "(fabric) the sandbox's ~/workspace is not the machine's home"
want "installed-before=no" "(fabric) the image's root is not clean at the first start"
[ "$(cat "$fab/aviary-sandbox/etc/installed")" = yes ] || fail "(fabric) what the agent installs is not in the fabric's root"
[ "$(wc -l < "$t/crane.calls")" = "$calls_before" ] || fail "(fabric) the image was fetched"
if AVIARY_SANDBOX_IMAGE_DIR="$t/nowhere" bash "$here/aviary-sandbox" "$t/boot.env" "$home/workspace/repo" 2> "$t/err"; then fail "(fabric) a missing image dir started"; fi
grep -q "no sandbox image at" "$t/err" || fail "(fabric) no word on the missing image: $(cat "$t/err")"
echo "ok: on the fabric the sandbox is the image carried in the fabric image, bound, not fetched or overlaid"

# ---- both ways aviary-home moves the machine's ~/.claude: the atomic exchange, and the copy a new machine's overlay
# root needs (it refuses to rename a directory that comes from several image layers: the first replica run, 2026-11-14)
for way in exchange copy; do
  h="$(mktemp -d)"
  mkdir -p "$h/claude/.claude/projects" "$h/claude/.claude/sessions"
  echo login > "$h/claude/.claude/.credentials.json"
  echo shim > "$h/claude/.claude/sessions/aviary.json"
  mount -t tmpfs tmpfs "$h/claude/.claude/projects"
  echo mirror > "$h/claude/.claude/projects/t.jsonl"
  if [ "$way" = copy ]; then export AVIARY_HOME_TEST_NO_EXCHANGE=1; else unset AVIARY_HOME_TEST_NO_EXCHANGE; fi
  "$here/aviary-home" "$h/claude" "$img/home/sandbox"
  "$here/aviary-home" "$h/claude" "$img/home/sandbox"
  unset AVIARY_HOME_TEST_NO_EXCHANGE
  [ "$(readlink "$h/claude/.claude")" = .harness/claude ] || fail "($way) the home's ~/.claude is not a link to .harness/claude"
  [ "$(readlink "$h/claude/.qwen")" = .harness/qwen ] || fail "($way) the home's ~/.qwen is not a link to .harness/qwen"
  # the machine's side still reaches its own files through the old paths, the volume's mount among them
  [ "$(cat "$h/claude/.claude/.credentials.json")" = login ] && [ "$(cat "$h/claude/.claude/sessions/aviary.json")" = shim ] \
    && [ "$(cat "$h/claude/.claude/projects/t.jsonl")" = mirror ] \
    || fail "($way) the machine's ~/.claude files are not reachable through the link"
  [ "$(findmnt -rn -o TARGET | grep -c "^$h/claude/")" = 1 ] && findmnt -rn -o TARGET | grep -qx "$h/claude/.harness/claude/projects" \
    || fail "($way) the volume's mount is not (only) at ~/.harness/claude/projects: $(findmnt -rn -o TARGET | grep "^$h/claude/")"
done
echo "ok: aviary-home moves the machine's ~/.claude behind the image's link, by exchange and by copy"

# ---- nothing of the image's is written a second time here (the dogfood-aviary check)
grep -q 'CLAUDE_CONFIG_DIR' "$here/aviary-sandbox" "$here/harness-aviary.sh" && fail "the harness tells Claude Code where its home is (an aviary sandbox never does)"
grep -qE 'npm install|claude-code@|\.harness/(claude|qwen)"' "$here/aviary-sandbox" "$here/aviary-home" && fail "the harness installs Claude Code or names the image's links itself"
grep -qE 'releases/download/.*supervisor|/out/supervisor' "$here/../Dockerfile" && fail "the session image carries a supervisor of its own"
echo "ok: the supervisor, Claude Code and the home's links come from the image only"
