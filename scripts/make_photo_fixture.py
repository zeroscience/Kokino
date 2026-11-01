"""Builds the photo-forensics test images in tests/fixtures/photo.

Needs Pillow and numpy. Deterministic. Invented content only: a synthetic
"photo" (gradients, shapes, texture, sensor-like noise) saved the way a
camera would (custom quantization tables, EXIF with make, model, dates,
GPS and a matching thumbnail), plus variants with known ground truth:

  camera.jpg        original: no findings
  edited.jpg        a region painted over, saved by "Adobe Photoshop" with the
                    camera EXIF kept (old thumbnail): editor_software,
                    thumbnail_mismatch, modified_after_capture
  resaved.jpg       re-encoded with standard libjpeg tables, EXIF kept:
                    standard_tables_camera
  cropped.jpg       cropped, EXIF kept: thumbnail_mismatch (shape)
  double.jpg        saved at quality 60, then again at 90: double_jpeg
  single.jpg        saved once at quality 90: no double_jpeg
  appended.jpg      camera.jpg with a ZIP appended: trailing_data
  cloned.jpg        a 120x90 region copied within the picture, no EXIF (for
                    the viewer's clone detection; no server finding)
  clean.png         lossless copy: no lsb_embedding
  stego.png         message bits in the LSBs of the first 30%: lsb_embedding
  stego.bmp         the same as BMP

    python scripts/make_photo_fixture.py
"""

import io
import os
import struct
import zipfile

import numpy as np
from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "photo")
W, H = 640, 480

# A camera-like table set: not the IJG tables at any quality (the base is
# close to IJG 94, so every third entry is nudged).
CAM_LUMA_BASE = [2, 1, 1, 2, 3, 5, 6, 7, 1, 1, 2, 2, 3, 7, 7, 7, 2, 2, 2, 3, 5, 7, 8, 7, 2, 2, 3, 3, 6, 10, 10, 7, 2, 3, 4, 7, 8, 13, 12, 9, 3, 4, 7, 8, 10, 12, 14, 11, 6, 8, 9, 10, 12, 15, 14, 12, 9, 11, 11, 12, 13, 12, 12, 12]
CAM_LUMA = [v + (i % 3 == 0) for i, v in enumerate(CAM_LUMA_BASE)]
CAM_CHROMA = [2, 2, 3, 6, 12, 12, 12, 12, 2, 3, 3, 8, 12, 12, 12, 12, 3, 3, 7, 12, 12, 12, 12, 12, 6, 8, 12, 12, 12, 12, 12, 12] + [12] * 32


def scene(seed=11, W=W, H=H):
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:H, 0:W].astype(np.float32)
    img = np.zeros((H, W, 3), np.float32)
    img[..., 0] = 90 + 60 * np.sin(x / 57.0) + 40 * np.cos(y / 41.0)
    img[..., 1] = 110 + 50 * np.cos((x + y) / 73.0)
    img[..., 2] = 140 - 0.15 * y + 30 * np.sin(x / 23.0) * np.cos(y / 31.0)
    pil = Image.fromarray(np.clip(img, 0, 255).astype(np.uint8))
    d = ImageDraw.Draw(pil)
    for _ in range(40):
        x0, y0 = rng.integers(0, W), rng.integers(0, H)
        r = int(rng.integers(8, 60))
        col = tuple(int(c) for c in rng.integers(0, 255, 3))
        (d.ellipse if rng.random() < 0.5 else d.rectangle)((x0, y0, x0 + r, y0 + r * 0.7), fill=col)
    a = np.asarray(pil).astype(np.float32)
    a += rng.normal(0, 6, a.shape)  # sensor noise: gives the DCT histograms real spread
    return Image.fromarray(np.clip(a, 0, 255).astype(np.uint8))


def tiff_exif(make, model, software, dt, original, gps, thumb):
    """Little-endian EXIF: IFD0, Exif IFD, GPS IFD, IFD1 with a JPEG thumbnail."""
    def ascii(s):
        return s.encode() + b"\0"

    # Fixed layout with generous offsets.
    ifd0_off, exif_off, gps_off, ifd1_off, data_off = 8, 200, 300, 460, 560
    blobs = bytearray()

    def put(b):
        off = data_off + len(blobs)
        blobs.extend(b)
        if len(blobs) % 2:
            blobs.append(0)
        return off

    def e_ascii(tag, s):
        b = ascii(s)
        return (tag, 2, len(b), b.ljust(4, b"\0") if len(b) <= 4 else struct.pack("<I", put(b)))

    def e_long(tag, v):
        return (tag, 4, 1, struct.pack("<I", v))

    def e_rat(tag, vals):
        b = b"".join(struct.pack("<II", int(round(v * 1000)), 1000) for v in vals)
        return (tag, 5, len(vals), struct.pack("<I", put(b)))

    def ifd(entries, next_off):
        b = struct.pack("<H", len(entries))
        for tag, typ, count, val in sorted(entries, key=lambda e: e[0]):
            b += struct.pack("<HHI", tag, typ, count) + val
        return b + struct.pack("<I", next_off)

    e0 = [e_ascii(0x010F, make), e_ascii(0x0110, model), e_ascii(0x0132, dt), e_long(0x8769, exif_off), e_long(0x8825, gps_off)]
    if software:
        e0.append(e_ascii(0x0131, software))
    ex = [e_ascii(0x9003, original), e_ascii(0x9004, original)]
    lat, lon = gps
    g = [(1, 2, 2, b"N\0\0\0"), e_rat(2, [int(lat), int(lat * 60) % 60, (lat * 3600) % 60]), (3, 2, 2, b"E\0\0\0"), e_rat(4, [int(lon), int(lon * 60) % 60, (lon * 3600) % 60])]
    t_off = put(thumb)
    e1 = [e_long(0x0201, t_off), e_long(0x0202, len(thumb))]
    out = bytearray(data_off)
    out[0:8] = b"II*\0" + struct.pack("<I", ifd0_off)
    for off, ent, nxt in ((ifd0_off, e0, ifd1_off), (exif_off, ex, 0), (gps_off, g, 0), (ifd1_off, e1, 0)):
        b = ifd(ent, nxt)
        assert off + len(b) <= min(o for o in (exif_off, gps_off, ifd1_off, data_off) if o > off)
        out[off:off + len(b)] = b
    return b"Exif\0\0" + bytes(out) + bytes(blobs)


def thumb_of(img):
    t = img.copy()
    t.thumbnail((160, 120))
    b = io.BytesIO()
    t.save(b, "JPEG", quality=85)
    return b.getvalue()


def save(img, name, **kw):
    img.save(os.path.join(OUT, name), **kw)


def main():
    os.makedirs(OUT, exist_ok=True)
    src = scene()
    cam_q = {"qtables": [CAM_LUMA, CAM_CHROMA], "subsampling": 1}
    exif = tiff_exif("Canon", "Kokino Lab Camera", "", "2026:10:20 09:45:30", "2026:10:20 09:45:30", (41.99, 21.43), thumb_of(src))
    save(src, "camera.jpg", exif=exif, **cam_q)
    cam = Image.open(os.path.join(OUT, "camera.jpg")).convert("RGB")

    ed = cam.copy()
    ImageDraw.Draw(ed).rectangle((200, 150, 330, 260), fill=(30, 140, 60))
    exif_ps = tiff_exif("Canon", "Kokino Lab Camera", "Adobe Photoshop 25.0 (Windows)", "2026:10:22 18:02:11", "2026:10:20 09:45:30", (41.99, 21.43), thumb_of(src))
    save(ed, "edited.jpg", exif=exif_ps, **cam_q)

    save(cam, "resaved.jpg", exif=exif, quality=90)
    save(cam.crop((0, 0, 480, 480)), "cropped.jpg", exif=exif, **cam_q)

    big = scene(12, 1024, 768)
    b = io.BytesIO()
    big.save(b, "JPEG", quality=60)
    Image.open(b).convert("RGB").save(os.path.join(OUT, "double.jpg"), quality=90)
    big.save(os.path.join(OUT, "single.jpg"), quality=90)

    cl = src.copy()
    cl.paste(src.crop((60, 60, 180, 150)), (420, 300))
    save(cl, "cloned.jpg", **cam_q)

    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("plan.txt", "Meet at the north gate at 06:00.\n")
    with open(os.path.join(OUT, "camera.jpg"), "rb") as f:
        open(os.path.join(OUT, "appended.jpg"), "wb").write(f.read() + z.getvalue())

    a = np.asarray(src).copy()
    Image.fromarray(a).save(os.path.join(OUT, "clean.png"))
    rng = np.random.default_rng(5)
    flat = a.reshape(-1)
    n = int(len(flat) * 0.3)
    flat[:n] = (flat[:n] & 0xFE) | rng.integers(0, 2, n, dtype=np.uint8)
    st = Image.fromarray(flat.reshape(a.shape))
    st.save(os.path.join(OUT, "stego.png"))
    st.save(os.path.join(OUT, "stego.bmp"))
    for f in sorted(os.listdir(OUT)):
        print(f, os.path.getsize(os.path.join(OUT, f)))


if __name__ == "__main__":
    main()
