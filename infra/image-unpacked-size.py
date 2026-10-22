#!/usr/bin/env python3
"""How big an OCI image is once unpacked onto a filesystem, measured straight from the registry.

Usage: image-unpacked-size.py <repo> <tag-or-digest> [--layers] [--top]
  e.g. image-unpacked-size.py de0ch/jarvis4-session sha-7e19307df2e7

Prints three numbers for the FLATTENED image (later layers' whiteouts and overwrites applied):
  tar_bytes   sum of the gunzipped layer blobs (what the old CI check measured)
  file_bytes  apparent size of the files that survive in the final rootfs
  disk_bytes  what they occupy on ext4 with 4 KiB blocks: every regular file rounded up to whole
              blocks (hard links once), every directory one block, an inode per entry (256 B),
              long symlinks one block. This is the number Fly's "maximum of 8GiB uncompressed" bites on.
Public ghcr.io repos only (anonymous pull token). Streams the layers; nothing is written to disk.
"""
import gzip, json, sys, tarfile, urllib.request

BLOCK, INODE = 4096, 256
A = ("application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, "
     "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json")


def get(url, tok, accept=None):
    h = {"Authorization": f"Bearer {tok}", "User-Agent": "curl/8"}
    if accept:
        h["Accept"] = accept
    return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=600)


def main():
    repo, ref = sys.argv[1], sys.argv[2]
    per_layer = "--layers" in sys.argv
    tok = json.load(urllib.request.urlopen(f"https://ghcr.io/token?scope=repository:{repo}:pull"))["token"]
    base = f"https://ghcr.io/v2/{repo}"
    m = json.load(get(f"{base}/manifests/{ref}", tok, A))
    if "manifests" in m:
        d = next(x["digest"] for x in m["manifests"] if x.get("platform", {}).get("architecture") == "amd64")
        m = json.load(get(f"{base}/manifests/{d}", tok, A))
    files = {}   # path -> (kind, size, linkkey)
    tar_bytes = 0
    for i, layer in enumerate(m["layers"]):
        before = tar_bytes
        with get(f"{base}/blobs/{layer['digest']}", tok) as r:
            cnt = _Count(gzip.GzipFile(fileobj=r))
            with tarfile.open(fileobj=cnt, mode="r|") as t:
                for e in t:
                    p = "/" + e.name.lstrip("./").rstrip("/")
                    d, _, b = p.rpartition("/")
                    if b == ".wh..wh..opq":   # opaque dir: drop everything below it from lower layers
                        pre = d + "/"
                        for k in [k for k in files if k.startswith(pre)]:
                            del files[k]
                        continue
                    if b.startswith(".wh."):
                        gone = d + "/" + b[4:]
                        pre = gone + "/"
                        for k in [k for k in files if k == gone or k.startswith(pre)]:
                            del files[k]
                        continue
                    if e.isdir():
                        files[p] = ("d", 0, None)
                    elif e.issym():
                        files[p] = ("l", len(e.linkname), None)
                    elif e.islnk():
                        tgt = "/" + e.linkname.lstrip("./")
                        files[p] = ("h", 0, tgt)
                    elif e.isreg():
                        files[p] = ("f", e.size, p)
                    else:
                        files[p] = ("o", 0, None)
            tar_bytes += cnt.n
        if per_layer:
            print(f"layer {i:2d} {(tar_bytes - before) / 1e6:9.1f} MB  {layer['digest'][:19]}", file=sys.stderr)
    file_bytes = disk = 0
    seen = set()
    for p, (k, size, key) in files.items():
        disk += INODE
        if k == "d":
            disk += BLOCK
        elif k == "l":
            disk += BLOCK if size >= 60 else 0
        elif k == "f":
            if key in seen:
                continue
            seen.add(key)
            file_bytes += size
            disk += -(-size // BLOCK) * BLOCK
    if "--top" in sys.argv:
        agg = {}
        for p, (k, size, key) in files.items():
            if k == "f":
                top = "/".join(p.split("/")[:5])
                agg[top] = agg.get(top, 0) + -(-size // BLOCK) * BLOCK
        for top, n in sorted(agg.items(), key=lambda x: -x[1])[:60]:
            print(f"{n / 1e6:9.1f} MB  {top}", file=sys.stderr)
    out = {"ref": ref, "entries": len(files), "tar_bytes": tar_bytes, "file_bytes": file_bytes, "disk_bytes": disk}
    print(json.dumps(out))


class _Count:
    def __init__(self, f):
        self.f, self.n = f, 0

    def read(self, n=-1):
        b = self.f.read(n)
        self.n += len(b)
        return b


if __name__ == "__main__":
    main()
