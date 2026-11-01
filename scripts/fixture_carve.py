#!/usr/bin/env python3
"""Carving samples: one small, valid file per format Kokino carves, plus
lookalikes that must NOT be carved. Used by make_win_fixture.py, which puts
them in unallocated space (NTFS free clusters and the unpartitioned tail).

All content is invented. samples() returns [(name, bytes)].
"""

import io
import os
import sqlite3
import struct
import tempfile
import zipfile
import zlib

import fixture_windows


def jpeg(w=64, h=48):
    """Baseline grayscale JPEG, DC-only 8x8 blocks: tiny and decodable."""
    o = bytearray(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    o += b"\xff\xdb\x00\x43\x00" + b"\x01" * 64
    o += b"\xff\xc0\x00\x0b\x08" + struct.pack(">HH", h, w) + b"\x01\x01\x11\x00"
    o += b"\xff\xc4\x00\x1f\x00" + bytes([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]) + bytes(range(12))
    o += b"\xff\xc4\x00\x14\x10" + bytes([1] + [0] * 15) + b"\x00"
    o += b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    lens = [2, 3, 3, 3, 3, 3, 4, 5, 6, 7, 8, 9]
    codes = [0b00, 0b010, 0b011, 0b100, 0b101, 0b110, 0b1110, 0b11110, 0b111110, 0b1111110, 0b11111110, 0b111111110]
    acc, n, out = 0, 0, bytearray()

    def put(v, k):
        nonlocal acc, n
        acc = (acc << k) | v
        n += k
        while n >= 8:
            b = (acc >> (n - 8)) & 0xFF
            out.append(b)
            if b == 0xFF:
                out.append(0)
            n -= 8

    prev = 0
    for by in range(h // 8):
        for bx in range(w // 8):
            level = ((bx * 37 + by * 53) % 200) - 100
            diff = level - prev
            prev = level
            cat = abs(diff).bit_length()
            put(codes[cat], lens[cat])
            if cat:
                put(diff if diff > 0 else (diff - 1) & ((1 << cat) - 1), cat)
            put(0, 1)
    if n:
        put((1 << (8 - n)) - 1, 8 - n)
    return bytes(o + out + b"\xff\xd9")


def png(w=24, h=16):
    raw = b"".join(b"\x00" + b"".join(bytes([x * 10 % 256, y * 15 % 256, 180]) for x in range(w)) for y in range(h))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))

    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def gif():
    # The classic 1x1 GIF89a (white pixel, transparent).
    return bytes.fromhex("47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b")


def bmp(w=8, h=6):
    rows = []
    for y in range(h):
        r = b"".join(bytes([200, (y * 40) % 256, (x * 30) % 256]) for x in range(w))
        rows.append(r + b"\0" * ((4 - len(r) % 4) % 4))
    pix = b"".join(rows)
    dib = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(pix), 2835, 2835, 0, 0)
    return b"BM" + struct.pack("<IHHI", 14 + 40 + len(pix), 0, 0, 54) + dib + pix


def sqlite_db():
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        con = sqlite3.connect(path)
        con.execute("PRAGMA page_size=1024")
        con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT)")
        con.executemany("INSERT INTO messages(sender, body) VALUES (?, ?)", [("marko", "Delete the backups tonight."), ("alice", "Done. Wiped the USB too.")])
        con.commit()
        con.close()
        return open(path, "rb").read()
    finally:
        os.remove(path)


def docx():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Recovered draft: wire instructions for Nightjar</w:t></w:r></w:p></w:body></w:document>")
    return b.getvalue()


def pdf():
    content = b"BT /F1 12 Tf 72 720 Td (Carved PDF: offshore account list) Tj ET"
    c = zlib.compress(content)
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(c) + c + b"\nendstream"]
    out = b"%PDF-1.7\n"
    for i, o in enumerate(objs, 1):
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    return out + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"


def word97():
    word = b"\xec\xa5" + b"\0" * 1022  # FIB magic; the content is not parsed
    return fixture_windows.cfb([("WordDocument", word * 5), ("1Table", b"\0" * 600), ("\x05SummaryInformation", b"\xfe\xff" + b"\0" * 300)])


def pe_exe():
    nt = 0x80
    d = bytearray(0x400)
    d[0:2] = b"MZ"
    struct.pack_into("<I", d, 60, nt)
    d[nt:nt + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", d, nt + 4, 0x8664, 2, 0, 0, 0, 240, 0x0022)
    struct.pack_into("<H", d, nt + 24, 0x20B)
    struct.pack_into("<H", d, nt + 24 + 68, 3)  # console subsystem
    sec = nt + 24 + 240
    d[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", d, sec + 8, 0x200, 0x1000, 0x200, 0x400)
    d[sec + 40:sec + 48] = b".data\0\0\0"
    struct.pack_into("<IIII", d, sec + 48, 0x100, 0x2000, 0x200, 0x600)
    return bytes(d) + b"\xcc" * 0x200 + b"KOKINO-CARVED-EXE".ljust(0x200, b"\0")


def gzip_file():
    import gzip
    return gzip.compress(b"2026-10-20 10:31 wevtutil cl Security\n" * 50, mtime=0)


def sevenzip():
    body = b"\x00" * 64
    nh = b"\x01\x04\x06\x00\x01\x09\x40\x00\x07\x0b\x01\x00\x01\x21\x21\x01\x00\x0c\x40\x00\x00"
    start = struct.pack("<QQI", len(body), len(nh), zlib.crc32(nh))
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(start)) + start + body + nh


def wav():
    data = bytes((i * 7) & 0xFF for i in range(800))
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", len(data)) + data
    return b"RIFF" + struct.pack("<I", len(body)) + body


def mp4():
    def box(t, d):
        return struct.pack(">I", 8 + len(d)) + t + d
    return box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2mp41") + box(b"moov", box(b"mvhd", b"\0" * 100)) + box(b"mdat", b"\x11" * 300)


def evtx_chunk():
    log = fixture_windows.log_security()
    return log[4096:4096 + 65536]


def samples():
    return [
        ("photo.jpg", jpeg()),
        ("chart.png", png()),
        ("dot.gif", gif()),
        ("swatch.bmp", bmp()),
        ("chat.sqlite", sqlite_db()),
        ("draft.docx", docx()),
        ("accounts.pdf", pdf()),
        ("memo.doc", word97()),
        ("tool.exe", pe_exe()),
        ("log.gz", gzip_file()),
        ("archive.7z", sevenzip()),
        ("voice.wav", wav()),
        ("clip.mp4", mp4()),
        ("security.evtx-chunk", evtx_chunk()),
    ]


# Look like headers, must be rejected.
LOOKALIKES = [
    b"MZ" + b" this is a text file that starts with MZ" * 4,
    b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"no end of central directory follows" * 4,
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"then text and no image data" * 4,
]
