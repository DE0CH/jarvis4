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
