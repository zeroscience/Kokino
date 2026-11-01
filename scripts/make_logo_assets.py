"""Builds the GUI logo assets from the master logo (Pillow, numpy).

    python scripts/make_logo_assets.py [kokinoftk-logo.png]

The master (1536 x 1024, transparent background) is made for light
backgrounds: an emblem on a dark navy round badge, "KOKINO" in dark navy
with a cyan stroke on the i, and "FORENSIC TOOLKIT" in slate grey. The GUI
shows it as is on the About page and rebuilds the rest per theme from
masks, so it stays readable on every theme:

  ui/img/logo.png            the full logo as designed (About page)
  ui/img/mark-shape.png      the emblem's silhouette (badge), painted with the theme's disc color
  ui/img/mark-neutral.png    the emblem's silver parts in grey
  ui/img/mark-accent.png     the emblem's cyan details, painted with the theme accent
  ui/img/wordmark-main.png   "KOKINO", painted with the theme text color
  ui/img/wordmark-sub.png    "FORENSIC TOOLKIT" and its rules, painted with the muted text color
  ui/img/wordmark-accent.png the cyan stroke on the i, painted with the theme accent
  ui/img/favicon.png         the emblem in its own colors, 64 px
"""

import os
import sys

import numpy as np
from PIL import Image

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "kokinoftk-logo.png")
OUT = os.path.join(ROOT, "ui", "img")

# Boxes in master coordinates (1536 x 1024).
EMBLEM = (392, 7, 1142, 757)
WORDMARK = (272, 760, 1262, 1003)
SUB_FROM = 935  # first row of "FORENSIC TOOLKIT"


def channels(im):
    a = np.asarray(im).astype(np.float32) / 255.0
    rgb, alpha = a[..., :3], a[..., 3]
    mx, mn = rgb.max(-1), rgb.min(-1)
    sat = np.where(mx > 0, (mx - mn) / np.maximum(mx, 1e-6), 0)
    r, g, b = rgb[..., 0], rgb[..., 1], rgb[..., 2]
    d = np.maximum(mx - mn, 1e-6)
    hue = np.where(mx == r, (g - b) / d % 6, np.where(mx == g, (b - r) / d + 2, (r - g) / d + 4)) * 60
    # Cyan details: saturated, hue 160-220, and bright (the navy is dark).
    cyan = np.clip((sat - 0.3) / 0.35, 0, 1) * ((hue > 160) & (hue < 220)) * np.clip((mx - 0.3) / 0.3, 0, 1)
    grey = rgb @ np.array([0.299, 0.587, 0.114], np.float32)
    return alpha, cyan, grey


def save_mask(a, name):
    white = np.ones_like(a)
    Image.fromarray((np.clip(np.dstack([white, white, white, a]), 0, 1) * 255).astype(np.uint8)).save(os.path.join(OUT, name), optimize=True)


def main():
    im = Image.open(SRC).convert("RGBA")
    if im.size != (1536, 1024):
        im = im.resize((1536, 1024), Image.LANCZOS)
    im.resize((1200, 800), Image.LANCZOS).save(os.path.join(OUT, "logo.png"), optimize=True)

    em = im.crop(EMBLEM).resize((256, 256), Image.LANCZOS)
    alpha, cyan, grey = channels(em)
    save_mask(alpha, "mark-shape.png")
    # The navy badge gives way to the theme disc (the shape layer); silver stays.
    light = np.clip((grey - 0.2) / 0.15, 0, 1)
    neutral = np.dstack([grey, grey, grey, alpha * (1 - cyan) * light])
    Image.fromarray((np.clip(neutral, 0, 1) * 255).astype(np.uint8)).save(os.path.join(OUT, "mark-neutral.png"), optimize=True)
    save_mask(cyan * alpha, "mark-accent.png")
    em.resize((64, 64), Image.LANCZOS).save(os.path.join(OUT, "favicon.png"), optimize=True)

    wm = im.crop(WORDMARK)
    w, h = wm.size
    wm = wm.resize((640, round(h * 640 / w)), Image.LANCZOS)
    alpha, cyan, _ = channels(wm)
    split = round((SUB_FROM - WORDMARK[1]) * 640 / w)
    rows = np.arange(alpha.shape[0])[:, None]
    save_mask(alpha * (1 - cyan) * (rows < split), "wordmark-main.png")
    save_mask(alpha * (1 - cyan) * (rows >= split), "wordmark-sub.png")
    save_mask(alpha * cyan, "wordmark-accent.png")
    print("wordmark", wm.size)
    for f in sorted(os.listdir(OUT)):
        print(f, os.path.getsize(os.path.join(OUT, f)))


if __name__ == "__main__":
    main()
