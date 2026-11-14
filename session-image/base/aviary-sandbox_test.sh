#!/bin/bash
# aviary-sandbox_test.sh (as root; images.yml): the sandbox's home is the machine's home WITH what is mounted in it.
# ~/workspace and ~/artifacts are mounts from the session's volume (the entrypoint); a plain bind of /home/claude left
# them out, so in the sandbox they were directories of the machine's throwaway root disk: an aviary session's task
# record, cloned repos and on-start scripts were gone after its first pause (2026-11-13). Runs the script's own
# home line on a stand-in tree, in a mount namespace of its own.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "aviary-sandbox_test: run as root" >&2; exit 1; }
if [ "${AVIARY_SANDBOX_TEST_INNER:-}" != 1 ]; then
  exec env AVIARY_SANDBOX_TEST_INNER=1 unshare --mount --propagation private "$0"
fi
t="$(mktemp -d)"
mkdir -p "$t/claude/artifacts" "$t/claude/workspace" "$t/sandbox"
echo root-disk > "$t/claude/artifacts/where"
# the volume's directories, mounted into the machine's home as the entrypoint does
for d in artifacts workspace; do
  mount -t tmpfs tmpfs "$t/claude/$d"
  echo volume > "$t/claude/$d/where"
done
line="$(grep -E '^mount .* /home/claude /home/sandbox$' "$here/aviary-sandbox")"
[ "$(printf '%s\n' "$line" | wc -l)" = 1 ] || { echo "FAIL: no single home line in aviary-sandbox: $line" >&2; exit 1; }
eval "$(printf '%s' "$line" | sed "s#/home/claude#$t/claude#; s#/home/sandbox#$t/sandbox#")"
for d in artifacts workspace; do
  got="$(cat "$t/sandbox/$d/where" 2>/dev/null || echo missing)"
  [ "$got" = volume ] || { echo "FAIL: the sandbox's ~/$d is the machine's root disk, not the volume ($got)" >&2; exit 1; }
done
# what the agent writes there is on the volume
echo kept > "$t/sandbox/artifacts/record.md"
[ "$(cat "$t/claude/artifacts/record.md")" = kept ] || { echo "FAIL: a file written in the sandbox's ~/artifacts is not on the volume" >&2; exit 1; }
echo "ok: the sandbox's ~/workspace and ~/artifacts are the volume's"

# Dogfooding (Deyao, 2026-11-14): the sandbox's home has an aviary sandbox image's links, so Claude Code finds its home
# in the supervisor's mount with nothing telling it where. A sandbox whose ~/.claude was a directory of its own had
# Claude Code write its transcript beside the mount: no tool calls in the chat, a turn that never ended.
# both ways aviary-home moves the machine's ~/.claude: the atomic exchange, and the copy a new machine's overlay root
# needs (it refuses to rename a directory that comes from several image layers: the first replica run, 2026-11-14)
for way in exchange copy; do
  h="$(mktemp -d)"
  mkdir -p "$h/claude/.claude/projects" "$h/claude/.claude/sessions" "$h/sandbox"
  echo login > "$h/claude/.claude/.credentials.json"
  echo shim > "$h/claude/.claude/sessions/aviary.json"
  mount -t tmpfs tmpfs "$h/claude/.claude/projects"   # the volume's transcript mirror, mounted inside as the entrypoint does
  echo mirror > "$h/claude/.claude/projects/t.jsonl"
  if [ "$way" = copy ]; then export AVIARY_HOME_TEST_NO_EXCHANGE=1; else unset AVIARY_HOME_TEST_NO_EXCHANGE; fi
  "$here/aviary-home" "$h/claude"
  "$here/aviary-home" "$h/claude"   # again: nothing changes
  unset AVIARY_HOME_TEST_NO_EXCHANGE
  [ "$(readlink "$h/claude/.claude")" = .harness/claude ] || { echo "FAIL ($way): the home's ~/.claude is not a link to .harness/claude" >&2; exit 1; }
  [ "$(readlink "$h/claude/.qwen")" = .harness/qwen ] || { echo "FAIL ($way): the home's ~/.qwen is not a link to .harness/qwen" >&2; exit 1; }
  # the machine's side still reaches its own files through the old paths, the volume's mount among them
  [ "$(cat "$h/claude/.claude/.credentials.json")" = login ] && [ "$(cat "$h/claude/.claude/sessions/aviary.json")" = shim ] \
    && [ "$(cat "$h/claude/.claude/projects/t.jsonl")" = mirror ] \
    || { echo "FAIL ($way): the machine's ~/.claude files are not reachable through the link" >&2; exit 1; }
  [ "$(findmnt -rn -o TARGET | grep -c "^$h/claude/")" = 1 ] && findmnt -rn -o TARGET | grep -qx "$h/claude/.harness/claude/projects" \
    || { echo "FAIL ($way): the volume's mount is not (only) at ~/.harness/claude/projects: $(findmnt -rn -o TARGET | grep "^$h/claude/")" >&2; exit 1; }
done
# the sandbox: the script's own home and .harness lines, then the supervisor's mount stands in as a tmpfs with claude/
for pat in '^mount .* /home/claude /home/sandbox$' '^mount .* /home/sandbox/\.harness$'; do
  line="$(grep -E "$pat" "$here/aviary-sandbox")"
  [ "$(printf '%s\n' "$line" | wc -l)" = 1 ] && [ -n "$line" ] || { echo "FAIL: no single line $pat in aviary-sandbox" >&2; exit 1; }
  eval "$(printf '%s' "$line" | sed "s#/home/claude#$h/claude#; s#/home/sandbox#$h/sandbox#g")"
done
[ -z "$(ls -A "$h/sandbox/.harness")" ] || { echo "FAIL: the machine's ~/.harness (its login, the mirror) shows in the sandbox: $(ls -A "$h/sandbox/.harness")" >&2; exit 1; }
mount -t tmpfs tmpfs "$h/sandbox/.harness"; mkdir "$h/sandbox/.harness/claude"   # the supervisor's mount
echo line > "$h/sandbox/.claude/transcript"   # what Claude Code does, knowing only its home's name
[ "$(cat "$h/sandbox/.harness/claude/transcript")" = line ] || { echo "FAIL: a file written to the sandbox's ~/.claude is not in the supervisor's mount" >&2; exit 1; }
[ ! -e "$h/claude/.harness/claude/transcript" ] || { echo "FAIL: the sandbox's ~/.claude writes into the machine's own" >&2; exit 1; }
grep -q 'CLAUDE_CONFIG_DIR' "$here/aviary-sandbox" "$here/harness-aviary.sh" && { echo "FAIL: the harness tells Claude Code where its home is (an aviary sandbox never does)" >&2; exit 1; }
echo "ok: the sandbox's ~/.claude is aviary's link into the supervisor's mount"
