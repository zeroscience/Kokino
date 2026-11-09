#!/usr/bin/env python3
"""Triage collection fixtures: the synthetic Windows artifacts of
fixture_windows.py (the same files disk-win.img holds) packed the way two
collectors pack them.

  tests/fixtures/collection-velociraptor.zip   uploads/auto/C%3A/<path>, NTFS
                                               times in each entry, log.json
  tests/fixtures/collection-kape.zip           C/<path>, a KAPE copy log
  tests/fixtures/collection-uac.tar.gz         the Linux server of
                                               make_ext_fixture.py as UAC packs
                                               it: [root]/<path>, uac.log,
                                               live_response/, bodyfile/

Invented lab data only (LAB-PC, alice, .test domains).
Usage: python scripts/make_collection_fixture.py
"""

import os
import gzip
import io
import struct
import sys
import tarfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixture_windows  # noqa: E402
import make_ext_fixture  # noqa: E402

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
    u = os.path.join(OUT, "collection-uac.tar.gz")
    build_uac(u)
    for p in (v, k, u):
        print("wrote", os.path.basename(p), os.path.getsize(p), "bytes")


def build_uac(path):
    """UAC's tar.gz: collected files under [root]/ with their own times,
    command output under live_response/, a bodyfile and uac.log."""
    tree = make_ext_fixture.server_tree()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as t:
        def add(name, data=b"", mtime=make_ext_fixture.T0, kind=tarfile.REGTYPE, link="", mode=0o644):
            ti = tarfile.TarInfo(name)
            ti.type, ti.mtime, ti.mode, ti.linkname = kind, mtime, mode, link
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            if kind == tarfile.REGTYPE:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
            else:
                t.addfile(ti)
        add("[root]", kind=tarfile.DIRTYPE, mode=0o755)
        for p in sorted(tree):
            if p.endswith(".iso"):
                continue  # keep the fixture small
            v = tree[p]
            mtime = make_ext_fixture.T0
            if isinstance(v, tuple) and v[0] == "link":
                add("[root]" + p, kind=tarfile.SYMTYPE, link=v[1], mode=0o777)
                continue
            if isinstance(v, tuple):
                v, mtime = v
            add("[root]" + p, v.encode() if isinstance(v, str) else v, mtime)
        add("live_response/system/uname_-a.txt", b"Linux lab-srv 6.1.0-lab-amd64 #1 SMP x86_64 GNU/Linux\n")
        add("live_response/network/ss_-tanp.txt", b"State Recv-Q Send-Q Local Address:Port Peer Address:Port\nESTAB 0 0 192.0.2.20:22 192.0.2.10:50122\n")
        add("bodyfile/bodyfile.txt", b"0|/etc/passwd|1234|-rw-r--r--|0|0|204|1792483530|1792483530|1792483530|0\n")
        add("uac.log", b"2026-10-21 02:30:00 INFO UAC (Unix-like Artifacts Collector) lab run on lab-srv\n")
    with open(path, "wb") as f:
        with gzip.GzipFile(fileobj=f, mode="wb", mtime=0, filename="") as g:
            g.write(raw.getvalue())


if __name__ == "__main__":
    build()
