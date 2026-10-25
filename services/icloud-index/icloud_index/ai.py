"""OpenRouter calls: reading images (OCR + a description), transcribing audio, embeddings.

Every call returns what it cost (OpenRouter's own `usage.cost`, in USD), so the indexer can keep an
exact running total and stop at the budget. Key: OPENROUTER_API (the default store).
Models are env-configurable: VISION_MODEL, AUDIO_MODEL, EMBED_MODEL, EMBED_DIMS.
"""
import base64, json, os, time, urllib.request, urllib.error

BASE = os.environ.get("OPENROUTER_BASE", "https://openrouter.ai/api/v1")
VISION_MODEL = os.environ.get("VISION_MODEL", "qwen/qwen3.8-omni-flash")
AUDIO_MODEL = os.environ.get("AUDIO_MODEL", "qwen/qwen3.8-omni-flash")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "qwen/qwen3-embedding-8b")
EMBED_DIMS = int(os.environ.get("EMBED_DIMS", "512"))
QUERY_INSTRUCT = "Instruct: Given a search query, retrieve files from a personal cloud drive (documents, scans, photos, videos) whose content or name matches the query\nQuery: "


class Fatal(Exception):
    """Retrying can't help (bad key, out of credit, a request the model rejects)."""
    def __init__(self, msg, billing=False):
        super().__init__(msg); self.billing = billing


def post(path, body, tries=5, timeout=300):
    key = os.environ.get("OPENROUTER_API")
    if not key: raise Fatal("OPENROUTER_API is not set")
    data = json.dumps(body).encode()
    err = None
    for i in range(tries):
        req = urllib.request.Request(BASE + path, data=data, method="POST", headers={
            "Authorization": "Bearer " + key, "Content-Type": "application/json", "User-Agent": "icloud-index/1"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                j = json.loads(r.read())
            if j.get("error"): raise RuntimeError(json.dumps(j["error"])[:300])
            return j
        except urllib.error.HTTPError as e:
            msg = f"{path} -> {e.code} {e.read()[:300]!r}"
            if e.code in (400, 401, 402, 403): raise Fatal(msg, billing=e.code == 402)
            err = RuntimeError(msg)
        except Exception as e:
            err = e
        time.sleep(3 * 2 ** i)
    raise err


def _chat(model, content, max_tokens):
    j = post("/chat/completions", {
        "model": model, "messages": [{"role": "user", "content": content}],
        "max_tokens": max_tokens, "temperature": 0, "usage": {"include": True},
        "response_format": {"type": "json_object"},
        "reasoning": {"effort": "minimal", "exclude": True},
    })
    ch = (j.get("choices") or [{}])[0]
    txt = (ch.get("message") or {}).get("content") or ""
    cost = float((j.get("usage") or {}).get("cost") or 0)
    try:
        out = json.loads(txt[txt.find("{"): txt.rfind("}") + 1]) if "{" in txt else {}
    except ValueError:
        out = {"text": txt}  # a truncated answer: keep what arrived, it is still searchable
    return out, cost, j.get("usage") or {}


IMAGE_PROMPT = """You are indexing a personal file archive for search. Look at this image ({hint}).
Return JSON with exactly these keys:
- "text": every piece of legible text in the image, transcribed verbatim in its original language(s) (Chinese stays Chinese), in reading order, lines separated by \\n. Empty string if there is none.
- "description": 1-3 English sentences saying what this is (e.g. "Scan of a Hong Kong passport data page", "Photo of a comet over a mountain at night", "Screenshot of a train booking confirmation"), naming document types, people's roles, places, events, brands and objects that someone might search for.
- "keywords_zh": 3-10 Chinese search keywords for the same content, space-separated.
No other keys, no markdown."""

FRAMES_PROMPT = """You are indexing a personal video archive for search. These are {n} frames from the video file "{hint}", at the timestamps given before each frame.
Return JSON: {{"summary": "1-3 English sentences on what the video shows overall", "keywords_zh": "3-10 Chinese keywords", "frames": [{{"t": "<timestamp as given>", "text": "legible on-screen text, verbatim, original language, or empty", "description": "one English sentence on what is on screen"}}, ...]}} — one entry per frame, same order. No markdown."""

AUDIO_PROMPT = """Transcribe the speech in this audio (from the file "{hint}", starting at {start} into the file) verbatim, in the language(s) spoken (Chinese stays Chinese). Put a [mm:ss] timestamp (relative to this clip) at the start of each paragraph, at least every 60 seconds. If there is no intelligible speech (music, noise, silence), return an empty transcript.
Return JSON: {{"transcript": "...", "language": "main language code or empty"}}. No markdown."""


def read_image(jpeg_bytes, hint):
    content = [{"type": "text", "text": IMAGE_PROMPT.format(hint=hint)},
               {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + base64.b64encode(jpeg_bytes).decode()}}]
    out, cost, _ = _chat(VISION_MODEL, content, 4096)
    return {"text": str(out.get("text") or ""), "description": str(out.get("description") or ""), "keywords_zh": str(out.get("keywords_zh") or "")}, cost


def read_frames(frames, hint):
    """frames: [(timestamp_str, jpeg_bytes)] -> ({summary, keywords_zh, frames:[{t,text,description}]}, cost)"""
    content = [{"type": "text", "text": FRAMES_PROMPT.format(n=len(frames), hint=hint)}]
    for t, b in frames:
        content.append({"type": "text", "text": f"Frame at {t}:"})
        content.append({"type": "image_url", "image_url": {"url": "data:image/jpeg;base64," + base64.b64encode(b).decode()}})
    out, cost, _ = _chat(VISION_MODEL, content, 8192)
    return out, cost


def transcribe(audio_bytes, fmt, hint, start):
    content = [{"type": "text", "text": AUDIO_PROMPT.format(hint=hint, start=start)},
               {"type": "input_audio", "input_audio": {"data": base64.b64encode(audio_bytes).decode(), "format": fmt}}]
    out, cost, _ = _chat(AUDIO_MODEL, content, 16384)
    return str(out.get("transcript") or ""), cost


def embed(texts, query=False):
    """-> ([list[float] unit length], cost)"""
    inp = [QUERY_INSTRUCT + t for t in texts] if query else texts
    j = post("/embeddings", {"model": EMBED_MODEL, "input": inp, "dimensions": EMBED_DIMS, "usage": {"include": True}},
             tries=3 if query else 5, timeout=30 if query else 300)
    data = sorted(j.get("data") or [], key=lambda d: d["index"])
    if len(data) != len(texts): raise RuntimeError(f"embeddings: asked for {len(texts)}, got {len(data)}")
    out = []
    for d in data:
        v = d["embedding"][:EMBED_DIMS]; n = sum(x * x for x in v) ** 0.5 or 1.0
        out.append([x / n for x in v])
    return out, float((j.get("usage") or {}).get("cost") or 0)
