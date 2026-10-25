#!/usr/bin/env python3
"""Export the DeepSeek Harness (dsh) sessions of this machine as Claude-Code-shaped transcripts, so everything
downstream that reads ~/.claude/projects/*/*.jsonl (live transcript sync, the pause snapshot, the Destroy archive, the
search index, the dashboard title/tail) works for a dsh session as it does for a Claude one (as opencode-transcript.py).

  $DSH_HOME/sessions/<cwd key>/<session id>/session.v<N>.jsonl[.zstd]   (dsh's append-only event log; the highest N wins)
      -> ~/.claude/projects/<working dir slug>/<session id>.jsonl

Events read: user/message (the user's turns; source.kind "user"), assistant/message (text, reasoning, tool calls),
tool/result, session/title. One file per session, rewritten whole (atomically) only when its log changed. Entry uuids
are derived from the dsh event ids, so re-exports dedupe in the search index.
Usage: dsh-transcript.py <working dir>   (one pass; the caller loops).
"""
import glob, hashlib, json, os, re, subprocess, sys, uuid
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
DSH_HOME = os.environ.get("DSH_HOME") or os.path.join(HOME, ".dsh")
NS = uuid.UUID("2b0f7a4e-6d8c-4c1e-9f57-3a9c0e1d7b42")


def iso(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def read_log(path):
    if path.endswith(".zstd"):
        raw = subprocess.run(["zstd", "-dcq", path], capture_output=True, timeout=120).stdout.decode("utf-8", "replace")
    else:
        raw = open(path, encoding="utf-8", errors="replace").read()
    for line in raw.splitlines():
        try:
            yield json.loads(line)
        except ValueError:
            continue  # an interrupted tail


def text_of(content):
    out = []
    for c in content or []:
        if c.get("type") == "text":
            out.append({"type": "text", "text": c.get("text") or ""})
        elif c.get("type") == "image":
            out.append({"type": "text", "text": "[image]"})
    return out


def convert(events, sid, cwd, model):
    lines, parent, title = [], None, ""

    def entry(kind, key, ts, message):
        nonlocal parent
        e = {"type": kind, "uuid": str(uuid.uuid5(NS, f"{sid}:{key}")), "parentUuid": parent, "sessionId": sid,
             "timestamp": ts, "cwd": cwd, "harness": "dsh", "message": message}
        parent = e["uuid"]
        lines.append(e)

    for ev in events:
        t, d, ts = ev.get("type"), ev.get("data") or {}, iso(ev.get("time"))
        if t == "user/message" and (d.get("source") or {}).get("kind") == "user":
            content = text_of(d.get("content"))
            if content:
                entry("user", d.get("id") or ev.get("seq"), ts, {"role": "user", "content": content})
        elif t == "assistant/message":
            content = []
            for c in (d.get("message") or {}).get("content") or []:
                if c.get("type") == "text" and c.get("text"):
                    content.append({"type": "text", "text": c["text"]})
                elif c.get("type") == "reasoning" and c.get("text"):
                    content.append({"type": "thinking", "thinking": c["text"]})
                elif c.get("type") == "tool-call":
                    try:
                        args = json.loads(c.get("arguments") or "{}")
                    except ValueError:
                        args = {"arguments": c.get("arguments")}
                    content.append({"type": "tool_use", "id": c.get("id"), "name": c.get("name") or "tool", "input": args})
            if content:
                entry("assistant", f"a{ev.get('seq')}", ts, {"role": "assistant", "model": model, "content": content})
        elif t == "tool/result":
            m = d.get("message") or {}
            body = "\n".join(c.get("text") or "" for c in m.get("content") or [] if c.get("type") == "text")
            entry("user", m.get("id") or f"r{ev.get('seq')}", ts, {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": m.get("toolCallId"), "content": body, "is_error": bool(m.get("isError"))}]})
        elif t == "session/title":
            title = str(d.get("title") or "").strip() or title
    if title:
        lines.append({"type": "ai-title", "aiTitle": title, "sessionId": sid})
    return lines


def newest_logs():
    """{session id: newest log path}; the generation number orders a session's logs (dsh never deletes old ones)."""
    best = {}
    for p in glob.glob(os.path.join(DSH_HOME, "sessions", "*", "*", "session*.jsonl*")):
        sid = os.path.basename(os.path.dirname(p))
        m = re.search(r"session(?:\.v(\d+))?\.jsonl", os.path.basename(p))
        gen = int(m.group(1) or 0) if m else -1
        if sid not in best or gen > best[sid][0]:
            best[sid] = (gen, p)
    return {sid: p for sid, (gen, p) in best.items()}


def main():
    wd = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HOME, "workspace")
    model = os.environ.get("SESSION_MODEL", "")
    outdir = os.path.join(HOME, ".claude", "projects", "".join(c if c.isalnum() else "-" for c in wd))
    os.makedirs(outdir, exist_ok=True)
    for sid, path in newest_logs().items():
        st = os.stat(path)
        mark, stamp = f"{path}|{st.st_size}|{int(st.st_mtime)}", os.path.join(outdir, f".{sid}.stamp")
        dst = os.path.join(outdir, sid + ".jsonl")
        if os.path.exists(dst) and os.path.exists(stamp) and open(stamp).read() == mark:
            continue
        try:
            events = list(read_log(path))
        except Exception as e:
            sys.stderr.write(f"[dsh-transcript] reading {path} failed: {e}\n")
            continue
        cwd = next((e.get("cwd") for e in events if e.get("type") == "session" and e.get("cwd")), wd)
        body = "".join(json.dumps(l, ensure_ascii=False) + "\n" for l in convert(events, sid, cwd, model))
        if not body:
            continue
        if not (os.path.exists(dst) and hashlib.sha256(open(dst, "rb").read()).digest() == hashlib.sha256(body.encode()).digest()):
            tmp = dst + ".tmp"
            with open(tmp, "w", encoding="utf-8") as out:
                out.write(body)
            os.replace(tmp, dst)
        open(stamp, "w").write(mark)


if __name__ == "__main__":
    main()
