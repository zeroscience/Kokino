#!/usr/bin/env python3
"""Write EWF-E01 test images of tests/fixtures/disk-af.img.

An independent writer for the E01 layout documented by the libewf project
(Joachim Metz, "Expert Witness Compression Format specification"), so the
Rust reader is tested against files it did not produce itself. Each output
exercises a different part of the format:

  disk-af.E01                 one segment, zlib for compressible chunks and
                              raw + Adler-32 for the rest, header + header2,
                              hash and digest sections
  disk-af-split.E01 .. .E03   three segments chained by "next"; segments 2+
                              use a non-zero table base offset; a "disk"
                              copy of the volume section in every segment
  disk-af-odd.E01             media size not a multiple of the chunk size
                              (partial last chunk), header v1 only, an error2
                              section listing two unreadable sector ranges

Usage: python scripts/make_e01_fixture.py
"""

import hashlib
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "tests", "fixtures")
SIG = b"EVF\x09\x0d\x0a\xff\x00"
BPS = 512


def adler(b):
    return zlib.adler32(b) & 0xFFFFFFFF


def descriptor(kind, offset, data_len, last=False):
    size = 76 + data_len
    nxt = offset if last else offset + size
    d = kind.encode().ljust(16, b"\0") + struct.pack("<QQ", nxt, size) + b"\0" * 40
    return d + struct.pack("<I", adler(d))


class Segment:
    def __init__(self, number):
        self.buf = bytearray(SIG + b"\x01" + struct.pack("<H", number) + b"\0\0")

    def section(self, kind, data, last=False):
        off = len(self.buf)
        self.buf += descriptor(kind, off, len(data), last) + data
        return off + 76


def header_v1(meta):
    keys = "c\tn\ta\te\tt\tav\tov\tm\tu\tp\tr"
    vals = "\t".join([meta["case"], meta["evidence"], meta["desc"], meta["examiner"], meta["notes"], "baboon-fixture 1", "Python",
                      "2026 10 26 09 30 00", "2026 10 26 09 30 00", "0", "b"])
    return zlib.compress(("1\nmain\n%s\n%s\n\n" % (keys, vals)).encode("ascii"))


def header_v2(meta):
    keys = "a\tc\tn\te\tt\tmd\tsn\tl\tav\tov\tm\tu\tp\tpid\tdc\text"
    vals = "\t".join([meta["desc"], meta["case"], meta["evidence"], meta["examiner"], meta["notes"], "LAB-DISK", "SN-0000-TEST",
                      "", "baboon-fixture 1", "Python", "1793007000", "1793007000", "0", "42", "", "1"])
    text = "3\nmain\n%s\n%s\n\n" % (keys, vals)
    return zlib.compress(b"\xff\xfe" + text.encode("utf-16-le"))


def volume(chunks, spc, sectors):
    v = bytearray(1052)
    v[0] = 0x01  # fixed disk
    struct.pack_into("<IIIQ", v, 4, chunks, spc, BPS, sectors)
    v[52] = 1  # compression level: fast
    v[64:80] = bytes(range(0x10, 0x20))  # set identifier
    struct.pack_into("<I", v, 1048, adler(bytes(v[:1048])))
    return bytes(v)


def table(offsets, base):
    head = struct.pack("<IIQI", len(offsets), 0, base, 0)
    head += struct.pack("<I", adler(head))
    ents = b"".join(struct.pack("<I", o) for o in offsets)
    return head + ents + struct.pack("<I", adler(ents))


def encode_chunk(data, force_raw=False):
    z = zlib.compress(data, 6)
    if len(z) < len(data) and not force_raw:
        return z, True
    return data + struct.pack("<I", adler(data)), False


def write(raw, first, spc=64, per_segment=None, v2=True, errors=(), meta=None):
    cs = spc * BPS
    sectors = len(raw) // BPS
    chunks = [raw[i:i + cs] for i in range(0, len(raw), cs)]
    per_segment = per_segment or len(chunks)
    groups = [chunks[i:i + per_segment] for i in range(0, len(chunks), per_segment)]
    vol = volume(len(chunks), spc, sectors)
    base_name = first[:-4]
    paths = []
    for si, group in enumerate(groups):
        seg = Segment(si + 1)
        if si == 0:
            if v2:
                seg.section("header2", header_v2(meta))
                seg.section("header2", header_v2(meta))
            seg.section("header", header_v1(meta))
            seg.section("volume", vol)
        else:
            seg.section("disk", vol)
        # Every 20th chunk and the final chunk are stored raw, as writers do
        # when compression does not pay off or is switched off.
        n0 = si * per_segment
        encoded = [encode_chunk(c, (n0 + i) % 20 == 2 or n0 + i == len(chunks) - 1) for i, c in enumerate(group)]
        data = b"".join(e[0] for e in encoded)
        sectors_data = seg.section("sectors", data)
        # Segment 1 uses absolute offsets (base 0); later segments use a base.
        base = 0 if si == 0 else sectors_data
        offs, pos = [], sectors_data - base
        for blob, comp in encoded:
            offs.append(pos | (0x80000000 if comp else 0))
            pos += len(blob)
        t = table(offs, base)
        seg.section("table", t)
        seg.section("table2", t)
        last = si == len(groups) - 1
        if last:
            if errors:
                e = struct.pack("<I", len(errors)) + b"\0" * 512
                e += struct.pack("<I", adler(e))
                ents = b"".join(struct.pack("<II", s, n) for s, n in errors)
                seg.section("error2", e + ents + struct.pack("<I", adler(ents)))
            md5 = hashlib.md5(raw).digest()
            sha1 = hashlib.sha1(raw).digest()
            d = md5 + sha1 + b"\0" * 40
            seg.section("digest", d + struct.pack("<I", adler(d)))
            h = md5 + b"\0" * 16
            seg.section("hash", h + struct.pack("<I", adler(h)))
            seg.section("done", b"", last=True)
        else:
            seg.section("next", b"", last=True)
        ext = "E%02d" % (si + 1)
        path = base_name + "." + ext
        with open(path, "wb") as f:
            f.write(seg.buf)
        paths.append(path)
    return paths


def main():
    raw = open(os.path.join(FIX, "disk-af.img"), "rb").read()
    meta = {"case": "LAB-001", "evidence": "1", "desc": "Planted anti-forensics disk", "examiner": "Lab Examiner",
            "notes": "Generated test image, not real evidence"}
    out = []
    out += write(raw, os.path.join(FIX, "disk-af.E01"), meta=meta)
    out += write(raw, os.path.join(FIX, "disk-af-split.E01"), per_segment=60, meta=meta)
    odd = raw[:1954 * BPS]
    out += write(odd, os.path.join(FIX, "disk-af-odd.E01"), spc=64, v2=False, errors=[(100, 8), (1900, 2)], meta=meta)
    for p in out:
        print("wrote", os.path.relpath(p, os.path.join(HERE, "..")), os.path.getsize(p), "bytes")
    print("disk-af.img      sha256", hashlib.sha256(raw).hexdigest())
    print("disk-af-odd media sha256", hashlib.sha256(odd).hexdigest(), len(odd), "bytes")


if __name__ == "__main__":
    main()
