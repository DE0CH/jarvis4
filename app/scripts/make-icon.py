#!/usr/bin/env python3
"""Draw the Jarvis 4 app icon (the Jarvis arc-reactor ring with a "4" at its centre in place of the triangle and
core) -> assets/icon.png (app.json "icon") and ../ios/Jarvis4/Assets.xcassets/AppIcon.appiconset/icon.png (the native
native build actually uses). The "4" is drawn as strokes (no font file), so it renders the same anywhere.
1024x1024 RGB, no alpha (App Store rejects alpha). Rendered at 2x and downsampled for smooth edges.
The web favicon is the ring (with its 4) alone on a transparent background, no square tile:
assets/favicon.png (app.json web.favicon). Run: python3 app/scripts/make-icon.py"""
import math, os
from PIL import Image, ImageDraw, ImageFilter

S = 2048; C = S / 2
img = Image.new("RGB", (S, S), (8, 14, 26))
bg = Image.new("RGB", (S, S)); d = ImageDraw.Draw(bg)
for r in range(int(S * 0.75), 0, -8):               # radial background glow
    t = r / (S * 0.75)
    d.ellipse([C - r, C - r, C + r, C + r], fill=(int(8 + 22 * (1 - t) ** 2), int(14 + 50 * (1 - t) ** 2), int(26 + 70 * (1 - t) ** 2)))
img = bg

glow = Image.new("RGB", (S, S)); g = ImageDraw.Draw(glow)
CYAN = (110, 225, 255)
def ring(dr, r, w, col):
    dr.ellipse([C - r, C - r, C + r, C + r], outline=col, width=w)
ring(g, 720, 60, CYAN)                                   # outer ring
for i in range(10):                                      # ten coil segments
    a0 = i * 36 + 4; a1 = a0 + 28
    g.arc([C - 600, C - 600, C + 600, C + 600], a0, a1, fill=CYAN, width=120)
ring(g, 430, 40, CYAN)
# the "4": a diagonal from the stem's top down to the left, a crossbar, and the stem — stamped as round discs along the
# path (PIL's wide lines/joints leave spiky gaps), which also gives round caps
W = 110; CORE = (200, 245, 255)
sx, top, bot = C + 85, C - 285, C + 285                  # the stem: x, top, bottom
bx0, by, bx1 = C - 215, C + 115, C + 210                 # the crossbar: left end, height, right end
def seg(p, q):
    n = int(math.dist(p, q) / 2) + 1
    return [(p[0] + (q[0] - p[0]) * k / n, p[1] + (q[1] - p[1]) * k / n) for k in range(n + 1)]
path = seg((sx, top), (bx0, by)) + seg((bx0, by), (bx1, by)) + seg((sx, top), (sx, bot))
for x, y in path:
    g.ellipse([x - W / 2, y - W / 2, x + W / 2, y + W / 2], fill=CORE)
blur = glow.filter(ImageFilter.GaussianBlur(40))
img = Image.blend(img, Image.eval(blur, lambda v: min(255, v)), 0.55)
img.paste(glow, (0, 0), glow.convert("L").point(lambda v: 255 if v > 20 else 0))
img = img.resize((1024, 1024), Image.LANCZOS).convert("RGB")
out = os.path.join(os.path.dirname(__file__), "..", "assets", "icon.png")
img.save(out, optimize=True); print("wrote", os.path.normpath(out))
img.save(os.path.join(os.path.dirname(__file__), "..", "..", "ios", "Jarvis4", "Assets.xcassets", "AppIcon.appiconset", "icon.png"), optimize=True)
# favicons: the ring alone — its shapes plus their soft glow as alpha — cropped to the ring
ringimg = Image.new("RGBA", (S, S), (0, 0, 0, 0))
# the glow in the ring's own cyan (its blurred RGB would show as a grey smudge on a light tab bar)
halo = Image.new("RGBA", (S, S), CYAN + (0,)); halo.putalpha(blur.convert("L").point(lambda v: min(255, int(v * 0.7))))
ringimg.alpha_composite(halo)
ringimg.paste(glow, (0, 0), glow.convert("L").point(lambda v: 255 if v > 20 else 0))
R = 800
ringimg = ringimg.crop((int(C - R), int(C - R), int(C + R), int(C + R)))
ringimg.resize((512, 512), Image.LANCZOS).save(os.path.join(os.path.dirname(__file__), "..", "assets", "favicon.png"), optimize=True)
