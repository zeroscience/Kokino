#!/usr/bin/env python3
"""Triage collection fixtures: the synthetic Windows artifacts of
fixture_windows.py (the same files disk-win.img holds) packed the way two
collectors pack them.

  tests/fixtures/collection-velociraptor.zip   uploads/auto/C%3A/<path>, NTFS
                                               times in each entry, log.json
  tests/fixtures/collection-kape.zip           C/<path>, a KAPE copy log

Invented lab data only (LAB-PC, alice, .test domains).
Usage: python scripts/make_collection_fixture.py
"""

import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixture_windows  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures")
FIXED = (2026, 10, 21, 2, 30, 0)


def ntfs_extra(t):
    """The NTFS extra field (0x000a): modified, accessed, created (FILETIME)."""
    body = b"\0" * 4 + struct.pack("<HH", 1, 24) + struct.pack("<QQQ", t, t, t - 864000000000)
    return struct.pack("<HH", 0x000A, len(body)) + body


def escape(part):
    """Velociraptor escapes characters such as ':' and '$' as %XX."""
    return "".join(c if c.isalnum() or c in "._- ()[]{}" else "%%%02X" % ord(c) for c in part)


def build():
    files = fixture_windows.build()
    t = fixture_windows.ft(2026, 10, 20, 9, 0, 0)
    v = os.path.join(OUT, "collection-velociraptor.zip")
    with zipfile.ZipFile(v, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(files):
            zi = zipfile.ZipInfo("uploads/auto/" + escape("C:") + "/" + "/".join(escape(p) for p in path.split("/")), FIXED)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.extra = ntfs_extra(t)
            z.writestr(zi, files[path])
        zi = zipfile.ZipInfo("log.json", FIXED)
        z.writestr(zi, '{"collector": "lab offline collector", "host": "LAB-PC"}\n')
    k = os.path.join(OUT, "collection-kape.zip")
    with zipfile.ZipFile(k, "w", zipfile.ZIP_DEFLATED) as z:
        log = ["CopiedTimestamp,SourceFile,DestinationFile,FileSize"]
        for path in sorted(files):
            zi = zipfile.ZipInfo("C/" + path, FIXED)
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, files[path])
            log.append("2026-10-21 02:30:00,C:\\%s,C\\%s,%d" % (path.replace("/", "\\"), path.replace("/", "\\"), len(files[path])))
        zi = zipfile.ZipInfo("2026-10-21T023000_CopyLog.csv", FIXED)
        z.writestr(zi, "\n".join(log) + "\n")
    for p in (v, k):
        print("wrote", os.path.basename(p), os.path.getsize(p), "bytes")


if __name__ == "__main__":
    build()
