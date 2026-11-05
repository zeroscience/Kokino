#!/usr/bin/env python3
"""Windows-artifact fixture: tests/fixtures/testfs1-af plus the synthetic
artifacts from fixture_windows.py planted at their real Windows paths.

  /Windows/System32/config/{SYSTEM,SOFTWARE,SAM}
  /Windows/AppCompat/Programs/Amcache.hve
  /Windows/System32/winevt/Logs/{Security,System,...}.evtx
  /Windows/Prefetch/{SDELETE64,VERACRYPT,POWERSHELL}.EXE-*.pf  (live, v30 compressed)
  /Users/alice/NTUSER.DAT, /Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat
  /$Extend/$UsnJrnl       change journal ($J after a sparse start, $Max)
  /Users/alice/AppData/Roaming/Microsoft/Windows/Recent/*.lnk, AutomaticDestinations, CustomDestinations

Outputs:
  tests/fixtures/testfs1-win     bare NTFS volume
  tests/fixtures/disk-win.img    MBR disk: 1 MiB gap, NTFS partition

Run make_af_fixture.py first. Usage: python scripts/make_win_fixture.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixture_carve  # noqa: E402
import fixture_windows  # noqa: E402
from make_af_fixture import FIX, Allocator, Volume, add_ads, add_nonresident_data, drop_attrs, name_of, plant_file, ref, set_flags, set_fn  # noqa: E402


def main():
    vol = Volume(open(os.path.join(FIX, "testfs1-af"), "rb").read())
    by_name = {}
    for n, rec in vol.records():
        nm = name_of(rec)
        if nm is not None:
            by_name.setdefault(nm, n)

    def rec_of(name):
        n = by_name[name]
        return n, vol.read(n)

    def ref_of(name):
        n = by_name[name]
        return ref(n, vol.read(n))

    spare = iter(str(i) for i in range(29, 200))

    def mkdir(new, parent_ref):
        n, r = rec_of(next(spare))
        vol.write(n, set_flags(set_fn(r, name=new, parent=parent_ref), in_use=True, is_dir=True))
        return ref(n, vol.read(n))

    alloc = Allocator(vol)
    dirs = {
        "Windows": ref_of("Windows"),
        "Windows/System32": ref_of("System32"),
        "Windows/Prefetch": ref_of("Prefetch"),
        "Windows/System32/winevt/Logs": ref_of("Logs"),
        "Users/alice": ref_of("alice"),
        "Users/alice/AppData/Roaming": ref_of("Roaming"),
    }

    def parent(path):
        d = path.rsplit("/", 1)[0]
        if d not in dirs:
            if "/" in d:
                dirs[d] = mkdir(d.rsplit("/", 1)[1], parent(d))
            else:
                dirs[d] = mkdir(d, ref(5, vol.read(5)))  # a new top-level folder
        return dirs[d]

    files = fixture_windows.build()
    for path in sorted(files, key=lambda p: -len(files[p])):  # big files first: contiguous runs
        plant_file(vol, alloc, next(spare), path.rsplit("/", 1)[1], parent(path), files[path], rec_of)

    # Carving ground truth (see CARVE_TRUTH): files in free clusters that no
    # MFT record describes, one deleted file whose clusters are free again,
    # and more samples in the unpartitioned tail.
    samples = dict(fixture_carve.samples())
    # The deleted file first, so the free-cluster samples do not land on it.
    pic = plant_file(vol, alloc, next(spare), "chart.png", parent("Users/alice/Pictures/x"), samples.pop("chart.png"), rec_of)
    # The change journal takes its clusters before free ones are picked.
    plant_journal(vol, alloc, rec_of(next(spare)), ref_of("$Extend"), parent("Users/alice/x"), parent("Users/alice/Pictures/x"), pic)
    reserved = set()
    for name in ("security.evtx-chunk", "memo.doc", "chat.sqlite", "photo.jpg", "draft.docx"):
        data = samples.pop(name)
        lcn = find_free(alloc, (len(data) + vol.cluster - 1) // vol.cluster, reserved)
        vol.d[lcn * vol.cluster:lcn * vol.cluster + len(data)] = data
    n = pic & 0xFFFFFFFFFFFF
    for lcn, count in vol.runs_of(vol.read(n), 0x80):
        for c in range(lcn, lcn + count):
            set_free(alloc, c)
    vol.write(n, set_flags(vol.read(n), in_use=False))

    out = bytes(vol.d)
    open(os.path.join(FIX, "testfs1-win"), "wb").write(out)
    gap = 1024 * 1024
    mbr = bytearray(512)
    struct.pack_into("<BBBBBBBBII", mbr, 446, 0x00, 0, 0, 0, 0x07, 0, 0, 0, gap // 512, len(out) // 512)
    mbr[510:512] = b"\x55\xaa"
    tail = bytearray(2 * 1024 * 1024)
    p = 4096
    for i, (name, data) in enumerate(samples.items()):
        tail[p:p + len(data)] = data
        p = (p + len(data) + 4096) // 4096 * 4096
        lk = fixture_carve.LOOKALIKES[i % len(fixture_carve.LOOKALIKES)]
        tail[p:p + len(lk)] = lk
        p += 4096
    cut = fixture_carve.jpeg()[:-30]  # starts in the last sector, runs into the end of the disk: incomplete
    tail[len(tail) - 512:len(tail) - 512 + len(cut)] = cut
    open(os.path.join(FIX, "disk-win.img"), "wb").write(bytes(mbr) + b"\0" * (gap - 512) + out + bytes(tail))
    print("wrote testfs1-win and disk-win.img (%d artifacts, %d carving samples)" % (len(files), len(fixture_carve.samples())))


FT = fixture_windows.ft


def usn_v2(usn, file, parent, t, reason, attrs, name):
    enc = name.encode("utf-16-le")
    n = (0x3C + len(enc) + 7) & ~7
    r = bytearray(n)
    struct.pack_into("<IHHQQQQIIIIHH", r, 0, n, 2, 0, file, parent, usn, t, reason, 0, 0, attrs, len(enc), 0x3C)
    r[0x3C:0x3C + len(enc)] = enc
    return bytes(r)


def usn_v3(usn, file, parent, t, reason, attrs, name):
    enc = name.encode("utf-16-le")
    n = (0x4C + len(enc) + 7) & ~7
    r = bytearray(n)
    struct.pack_into("<IHH", r, 0, n, 3, 0)
    struct.pack_into("<QQQQ", r, 8, file, 0, parent, 0)
    struct.pack_into("<QQIIIIHH", r, 40, usn, t, reason, 0, 0, attrs, len(enc), 0x4C)
    r[0x4C:0x4C + len(enc)] = enc
    return bytes(r)


CREATE, DELETE, EXTEND, OLD, NEW, CLOSE = 0x100, 0x200, 0x2, 0x1000, 0x2000, 0x80000000


def journal(alice, pictures, pic, base):
    """Change journal ground truth (tested in kokino-analysis):
    - folder Exfil (MFT 900-2, gone) with dump.7z (901-1), both deleted:
      paths come from the journal alone
    - nightjar-notes.txt (902-3) renamed AAAA...AAA.AAA through
      ZZZZ...ZZZ.ZZZ, then deleted (SDelete's pattern)
    - chart.png, the deleted file on the volume: its deletion time
    - report-v3.docx (903-1): a version 3 record"""
    out = bytearray()
    t = FT(2026, 10, 20, 9, 30)
    s = 10_000_000

    def put(args, v3=False):
        nonlocal out
        make = usn_v3 if v3 else usn_v2
        rec = make(base + len(out), *args)
        if len(out) // 4096 != (len(out) + len(rec) - 1) // 4096:
            out += b"\0" * (4096 - len(out) % 4096)  # records never cross a page
            rec = make(base + len(out), *args)
        out += rec

    exfil, dump, notes = 900 | 2 << 48, 901 | 1 << 48, 902 | 3 << 48
    seq = []
    seq.append((exfil, alice, t, CREATE | CLOSE, 0x10, "Exfil"))
    seq.append((dump, exfil, t + s, CREATE, 0x20, "dump.7z"))
    seq.append((dump, exfil, t + s, CREATE | EXTEND, 0x20, "dump.7z"))
    seq.append((dump, exfil, t + 2 * s, CREATE | EXTEND | CLOSE, 0x20, "dump.7z"))
    name = "nightjar-notes.txt"
    for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        new = c * 18 + "." + c * 3
        at = t + (60 + i) * s
        seq.append((notes, alice, at, OLD, 0x20, name))
        seq.append((notes, alice, at, NEW, 0x20, new))
        seq.append((notes, alice, at, NEW | CLOSE, 0x20, new))
        name = new
    seq.append((notes, alice, t + 90 * s, DELETE | CLOSE, 0x20, name))
    seq.append((dump, exfil, t + 120 * s, DELETE | CLOSE, 0x20, "dump.7z"))
    seq.append((exfil, alice, t + 121 * s, DELETE | CLOSE, 0x10, "Exfil"))
    seq.append((pic, pictures, t + 180 * s, DELETE | CLOSE, 0x20, "chart.png"))
    for args in seq:
        put(args)
    put((903 | 1 << 48, alice, t + 200 * s, CREATE | CLOSE, 0x20, "report-v3.docx"), v3=True)
    return bytes(out)


def plant_journal(vol, alloc, slot, extend, alice, pictures, pic):
    n, r = slot
    sparse = 4
    base = sparse * vol.cluster
    data = journal(alice, pictures, pic, base)
    clusters = (len(data) + vol.cluster - 1) // vol.cluster
    lcn = alloc.take(clusters)
    vol.d[lcn * vol.cluster:lcn * vol.cluster + len(data)] = data
    r = set_fn(r, name="$UsnJrnl", parent=extend)
    r = set_flags(r, in_use=True, is_dir=False)
    r = drop_attrs(r, {0x80, 0x90, 0xA0, 0xB0})
    r = add_nonresident_data(r, lcn, clusters, base + len(data), vol.cluster, name="$J", sparse=sparse)
    # Journal created when Windows was installed (fixture_windows: 2025-03-02).
    jid = FT(2025, 3, 2, 8, 0)
    r = add_ads(r, "$Max", struct.pack("<QQQQ", 32 << 20, 8 << 20, jid, 0))
    vol.write(n, r)


def find_free(alloc, n, reserved):
    """A run of n free clusters, left free in $Bitmap (unlike Allocator.take)."""
    run = 0
    for i in range(alloc.clusters):
        run = run + 1 if not alloc._bit(i) and i not in reserved else 0
        if run == n:
            start = i - n + 1
            reserved.update(range(start, i + 1))
            return start
    raise ValueError("no free run of %d clusters" % n)


def set_free(alloc, i):
    for lcn, count in alloc.runs:
        nbytes = count * alloc.vol.cluster
        if i // 8 < nbytes:
            p = lcn * alloc.vol.cluster + i // 8
            alloc.vol.d[p] &= ~(1 << (i % 8)) & 0xFF
            return
        i -= nbytes * 8


if __name__ == "__main__":
    main()
