#!/bin/bash
# Every shell script of the repo parses (bash -n / sh -n by its shebang). A harness script that does not parse ends
# at once on every start, and nothing else looks at it before a session runs it: harness-aviary.sh went out with an
# apostrophe in a comment inside a single-quoted Python block, and no new aviary session could start (2026-11-13).
set -u
cd "$(dirname "$0")/.."
bad=0; n=0
while IFS= read -r f; do
  case "$(head -n 1 "$f" | tr -d '\0')" in
    '#!'*bash*) sh=bash ;;
    '#!'*/sh|'#!'*' sh') sh=sh ;;
    *) continue ;;
  esac
  n=$((n + 1))
  "$sh" -n "$f" || { echo "FAIL: $f does not parse"; bad=1; }
done < <(git ls-files)
echo "scripts_syntax_test: $n scripts checked"
[ "$n" -gt 0 ] || { echo "FAIL: no script found"; exit 1; }
exit "$bad"
