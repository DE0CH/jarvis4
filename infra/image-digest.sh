#!/bin/bash
# infra/image-digest.sh <ghcr.io/de0ch/jarvis4-session:tag> → ghcr.io/de0ch/jarvis4-session:tag@sha256:<linux/amd64
# manifest>, from GHCR's registry API (anonymous: the package is public). The core starts only images pinned by
# digest and checks that Fly reports that digest (core/vouch.go). Fly reports the PLATFORM manifest's digest
# (linux/amd64), not the multi-arch index's that `docker push` prints, so this resolves the index to that manifest.
set -euo pipefail
ref="${1:?usage: image-digest.sh ghcr.io/owner/name:tag}"
case "$ref" in *@sha256:*) ref="${ref%@*}";; esac
repo="${ref#ghcr.io/}"; tag="${repo##*:}"; repo="${repo%:*}"
[ "$repo" != "$tag" ] || tag=latest
tok="$(curl -fsS "https://ghcr.io/token?scope=repository:$repo:pull" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["token"])')"
accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
hdrs="$(mktemp)"; trap 'rm -f "$hdrs"' EXIT
body="$(curl -fsS -D "$hdrs" -H "Authorization: Bearer $tok" -H "Accept: $accept" "https://ghcr.io/v2/$repo/manifests/$tag")"
top="$(tr -d '\r' < "$hdrs" | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"
digest="$(printf '%s' "$body" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
top = sys.argv[1]
if d.get("manifests"):  # an index: the linux/amd64 image (not the attestation manifest)
    m = [x for x in d["manifests"] if (x.get("platform") or {}).get("os") == "linux" and (x.get("platform") or {}).get("architecture") == "amd64"]
    print(m[0]["digest"] if len(m) == 1 else "")
else:
    print(top)
' "$top")"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "no linux/amd64 digest for $ref" >&2; exit 1; }
echo "ghcr.io/$repo:$tag@$digest"
