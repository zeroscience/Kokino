"""LZNT1 test vectors made by Windows' own compressor (RtlCompressBuffer,
COMPRESSION_FORMAT_LZNT1), the format NTFS uses for compressed files.

Writes tests/fixtures/win/lznt1-<name>.raw (original) and .lznt (compressed).
Windows only. Invented content.

    python scripts/make_lznt1_fixture.py
"""
import ctypes
import os
import random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "fixtures", "win")
LZNT1 = 2
MAXIMUM = 0x0100

ntdll = ctypes.WinDLL("ntdll")


def compress(data):
    ws_comp = ctypes.c_ulong()
    ws_frag = ctypes.c_ulong()
    st = ntdll.RtlGetCompressionWorkSpaceSize(LZNT1 | MAXIMUM, ctypes.byref(ws_comp), ctypes.byref(ws_frag))
    assert st == 0, hex(st)
    work = ctypes.create_string_buffer(ws_comp.value)
    out = ctypes.create_string_buffer(len(data) * 2 + 4096)
    final = ctypes.c_ulong()
    st = ntdll.RtlCompressBuffer(LZNT1 | MAXIMUM, data, len(data), out, len(out), 4096, ctypes.byref(final), work)
    assert st == 0, hex(st)
    return out.raw[: final.value]


def main():
    rnd = random.Random(7)
    text = ("Kokino lab notes: evidence item E-001 hashed, verified and bookmarked. " * 30).encode()
    words = [b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf", b"hotel"]
    long = b" ".join(rnd.choice(words) for _ in range(30000))  # several 4 KiB chunks
    mixed = bytes(rnd.getrandbits(8) for _ in range(5000)) + b"\x00" * 9000 + text  # stored and compressed chunks
    for name, data in [("text", text), ("long", long), ("mixed", mixed)]:
        with open(os.path.join(OUT, "lznt1-%s.raw" % name), "wb") as f:
            f.write(data)
        c = compress(data)
        with open(os.path.join(OUT, "lznt1-%s.lznt" % name), "wb") as f:
            f.write(c)
        print("%-6s %6d -> %6d bytes" % (name, len(data), len(c)))


if __name__ == "__main__":
    main()
