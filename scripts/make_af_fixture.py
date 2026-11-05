#!/usr/bin/env python3
"""Build anti-forensics ground-truth fixtures from tests/fixtures/testfs1.

Takes the clean 2 MiB NTFS volume and plants known traces by editing MFT
records directly (with proper update-sequence fixups), so every Kokino
anti-forensics rule has a case with a known answer:

  /file-with-12345              $SI created back-dated to 2009, whole second (timestomp)
  /ZZZZZZZZZZZZZZZ              ex 1000-bytes-file: SDelete-style rename, deleted, clusters zeroed
  /photo01.jpg                  ex sparse-file: content replaced by a PE header (extension mismatch)
  /Users/alice/notes.txt        ex empty-file: carries an ADS "payload" holding a PE
  /Users/alice/sdelete64.exe    wiping tool present
  /Windows/Prefetch/SDELETE64.EXE-1A2B3C4D.pf   deleted prefetch of the tool, Prefetch otherwise empty
  /Windows/System32/ntoskrnl.exe                marks it as a Windows system volume
  /Windows/System32/winevt/Logs                 exists, but Security.evtx is missing
  (no $UsnJrnl: mkntfs never creates one)
  /Users/alice/AppData/Local/Google/Chrome/User Data/Default/History     Chrome history (see fixture_browsers.py)
  /Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/History   Edge history, cleared
  /Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/k3x9w2qe.default-release/places.sqlite (+ -wal)

Outputs:
  tests/fixtures/testfs1-af      bare NTFS volume
  tests/fixtures/disk-af.img     MBR disk: 1 MiB gap, NTFS partition (type 0x07), 2 MiB unallocated tail

Usage: python scripts/make_af_fixture.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixture_browsers  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "tests", "fixtures")


class Volume:
    def __init__(self, data):
        self.d = bytearray(data)
        self.sector = struct.unpack_from("<H", self.d, 0x0B)[0]
        self.cluster = self.sector * self.d[0x0D]
        mft_lcn = struct.unpack_from("<Q", self.d, 0x30)[0]
        rs = struct.unpack_from("<b", self.d, 0x40)[0]
        self.rsize = 2 ** (-rs) if rs < 0 else rs * self.cluster
        self.mft_off = mft_lcn * self.cluster
        rec0 = self.unfix(self.d[self.mft_off:self.mft_off + self.rsize])
        self.mft_runs = self.runs_of(rec0, 0x80)

    # -- update sequence fixups -------------------------------------------
    def unfix(self, rec):
        rec = bytearray(rec)
        usa_off, usa_cnt = struct.unpack_from("<HH", rec, 4)
        for i in range(1, usa_cnt):
            end = i * self.sector - 2
            rec[end:end + 2] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
        return rec

    def fix(self, rec):
        rec = bytearray(rec)
        usa_off, usa_cnt = struct.unpack_from("<HH", rec, 4)
        usn = rec[usa_off:usa_off + 2]
        for i in range(1, usa_cnt):
            end = i * self.sector - 2
            rec[usa_off + 2 * i:usa_off + 2 * i + 2] = rec[end:end + 2]
            rec[end:end + 2] = usn
        return rec

    # -- MFT addressing ---------------------------------------------------
    def runs_of(self, rec, atype):
        for a in attrs(rec):
            if a["type"] == atype and a["nonres"]:
                return decode_runs(rec, a["off"] + struct.unpack_from("<H", rec, a["off"] + 0x20)[0])
        return []

    def record_offset(self, n):
        """Byte offset of record n; None if it straddles two runs."""
        want = n * self.rsize
        vcn_bytes = 0
        for lcn, count in self.mft_runs:
            length = count * self.cluster
            if want < vcn_bytes + length:
                if want + self.rsize > vcn_bytes + length:
                    return None
                return lcn * self.cluster + (want - vcn_bytes)
            vcn_bytes += length
        return None

    def read(self, n):
        off = self.record_offset(n)
        if off is None:
            return None
        return self.unfix(self.d[off:off + self.rsize])

    def write(self, n, rec):
        off = self.record_offset(n)
        self.d[off:off + self.rsize] = self.fix(rec)

    def records(self):
        total = sum(c for _, c in self.mft_runs) * self.cluster // self.rsize
        for n in range(total):
            rec = self.read(n)
            if rec is not None and rec[:4] == b"FILE":
                yield n, rec


def attrs(rec):
    off = struct.unpack_from("<H", rec, 0x14)[0]
    while off + 8 <= len(rec):
        t, ln = struct.unpack_from("<II", rec, off)
        if t == 0xFFFFFFFF or ln == 0:
            break
        yield {"type": t, "off": off, "len": ln, "nonres": rec[off + 8] != 0}
        off += ln


def decode_runs(rec, p):
    runs, lcn = [], 0
    while rec[p] != 0:
        h = rec[p]
        lsz, osz = h & 0xF, h >> 4
        count = int.from_bytes(rec[p + 1:p + 1 + lsz], "little")
        delta = int.from_bytes(rec[p + 1 + lsz:p + 1 + lsz + osz], "little", signed=True) if osz else 0
        lcn += delta
        runs.append((lcn, count))
        p += 1 + lsz + osz
    return runs


def fn_attr(rec):
    best = None
    for a in attrs(rec):
        if a["type"] == 0x30:
            v = a["off"] + struct.unpack_from("<H", rec, a["off"] + 0x14)[0]
            if best is None or rec[v + 0x41] != 2:  # prefer non-DOS namespace
                best = (a, v)
    return best


def name_of(rec):
    f = fn_attr(rec)
    if not f:
        return None
    a, v = f
    n = rec[v + 0x40]
    return rec[v + 0x42:v + 0x42 + 2 * n].decode("utf-16le")


def replace_attr(rec, a, new_attr):
    """Swap an attribute for new bytes, shifting the rest of the record."""
    used = struct.unpack_from("<I", rec, 0x18)[0]
    tail = rec[a["off"] + a["len"]:used]
    body = rec[:a["off"]] + new_attr + tail
    if len(body) > len(rec):
        raise ValueError("record full")
    out = bytearray(rec)
    out[:len(body)] = body
    out[len(body):used] = b"\0" * max(0, used - len(body))
    struct.pack_into("<I", out, 0x18, len(body))
    return out


def set_fn(rec, name=None, parent=None):
    """Rewrite every $FILE_NAME attribute: new name and/or parent reference."""
    for a in list(attrs(rec)):
        if a["type"] != 0x30:
            continue
        hdr_len = struct.unpack_from("<H", rec, a["off"] + 0x14)[0]
        v = a["off"] + hdr_len
        vlen = struct.unpack_from("<I", rec, a["off"] + 0x10)[0]
        value = bytearray(rec[v:v + vlen])
        if parent is not None:
            struct.pack_into("<Q", value, 0, parent)
        if name is not None:
            enc = name.encode("utf-16le")
            value = value[:0x40] + bytes([len(name), 1 if value[0x41] != 2 else 1]) + enc
        hdr = bytearray(rec[a["off"]:a["off"] + hdr_len])
        total = (hdr_len + len(value) + 7) & ~7
        struct.pack_into("<I", hdr, 4, total)
        struct.pack_into("<I", hdr, 0x10, len(value))
        new = bytes(hdr) + bytes(value) + b"\0" * (total - hdr_len - len(value))
        rec = replace_attr(rec, a, new)
        if name is not None:
            # Drop any remaining DOS-only name so only one name survives.
            for b in list(attrs(rec)):
                if b["type"] == 0x30 and b["off"] != a["off"]:
                    bv = b["off"] + struct.unpack_from("<H", rec, b["off"] + 0x14)[0]
                    if rec[bv + 0x41] == 2:
                        rec = replace_attr(rec, b, b"")
            break
    return rec


def set_si_created(rec, ft):
    for a in attrs(rec):
        if a["type"] == 0x10:
            v = a["off"] + struct.unpack_from("<H", rec, a["off"] + 0x14)[0]
            struct.pack_into("<Q", rec, v, ft)
    return rec


def set_flags(rec, in_use=None, is_dir=None):
    f = struct.unpack_from("<H", rec, 0x16)[0]
    if in_use is not None:
        f = (f | 1) if in_use else (f & ~1)
    if is_dir is not None:
        f = (f | 2) if is_dir else (f & ~2)
    struct.pack_into("<H", rec, 0x16, f)
    return rec


def add_ads(rec, name, content):
    used = struct.unpack_from("<I", rec, 0x18)[0]
    end = used - 8  # position of the 0xFFFFFFFF end marker (+ padding)
    for a in attrs(rec):
        end = a["off"] + a["len"]
    enc = name.encode("utf-16le")
    name_off = 0x18
    val_off = (name_off + len(enc) + 7) & ~7
    total = (val_off + len(content) + 7) & ~7
    attr_id = struct.unpack_from("<H", rec, 0x28)[0]
    a = bytearray(total)
    struct.pack_into("<IIBBHHH", a, 0, 0x80, total, 0, len(name), name_off, 0, attr_id)
    struct.pack_into("<IHBB", a, 0x10, len(content), val_off, 0, 0)
    a[name_off:name_off + len(enc)] = enc
    a[val_off:val_off + len(content)] = content
    struct.pack_into("<H", rec, 0x28, attr_id + 1)
    tail = b"\xff\xff\xff\xff" + b"\0" * 4
    body = rec[:end] + a + tail
    out = bytearray(rec)
    out[:len(body)] = body
    struct.pack_into("<I", out, 0x18, len(body))
    return out


def ref(n, rec):
    return n | (struct.unpack_from("<H", rec, 0x10)[0] << 48)


def drop_attrs(rec, types):
    for a in reversed(list(attrs(rec))):
        if a["type"] in types:
            rec = replace_attr(rec, a, b"")
    return rec


def _int_bytes(v, signed):
    n = 1
    while True:
        try:
            return v.to_bytes(n, "little", signed=signed)
        except OverflowError:
            n += 1


def add_nonresident_data(rec, lcn, clusters, size, cluster, name="", sparse=0):
    """Append a non-resident $DATA attribute (unnamed unless `name`) with a
    single run, after `sparse` sparse clusters."""
    runlist = b""
    if sparse:
        sc = _int_bytes(sparse, False)
        runlist += bytes([len(sc)]) + sc
    cnt = _int_bytes(clusters, False)
    off = _int_bytes(lcn, True)
    runlist += bytes([(len(off) << 4) | len(cnt)]) + cnt + off + b"\0"
    enc = name.encode("utf-16le")
    runs_off = (0x40 + len(enc) + 7) & ~7
    total = (runs_off + len(runlist) + 7) & ~7
    attr_id = struct.unpack_from("<H", rec, 0x28)[0]
    a = bytearray(total)
    struct.pack_into("<IIBBHHH", a, 0, 0x80, total, 1, len(name), 0x40, 0x8000 if sparse else 0, attr_id)
    struct.pack_into("<QQHH", a, 0x10, 0, sparse + clusters - 1, runs_off, 0)
    struct.pack_into("<QQQ", a, 0x28, (sparse + clusters) * cluster, size, size)
    a[0x40:0x40 + len(enc)] = enc
    a[runs_off:runs_off + len(runlist)] = runlist
    struct.pack_into("<H", rec, 0x28, attr_id + 1)
    end = struct.unpack_from("<H", rec, 0x14)[0]
    for x in attrs(rec):
        end = x["off"] + x["len"]
    body = rec[:end] + a + b"\xff\xff\xff\xff" + b"\0" * 4
    out = bytearray(rec)
    out[:len(body)] = body
    struct.pack_into("<I", out, 0x18, len(body))
    return out


class Allocator:
    """Hands out free clusters from $Bitmap and marks them used."""

    def __init__(self, vol):
        self.vol = vol
        self.runs = vol.runs_of(vol.read(6), 0x80)
        self.clusters = struct.unpack_from("<Q", vol.d, 0x28)[0] // vol.d[0x0D]

    def _bit(self, i, set_it=False):
        for lcn, count in self.runs:
            nbytes = count * self.vol.cluster
            if i // 8 < nbytes:
                p = lcn * self.vol.cluster + i // 8
                if set_it:
                    self.vol.d[p] |= 1 << (i % 8)
                return (self.vol.d[p] >> (i % 8)) & 1
            i -= nbytes * 8
        return 1

    def take(self, n):
        run = 0
        for i in range(self.clusters):
            run = run + 1 if not self._bit(i) else 0
            if run == n:
                start = i - n + 1
                for j in range(start, i + 1):
                    self._bit(j, set_it=True)
                return start
        raise ValueError("no free run of %d clusters" % n)


def plant_file(vol, alloc, old, new, parent_ref, data, rec_of):
    """Turn record `old` into file `new` under `parent_ref` holding `data`."""
    n, r = rec_of(old)
    clusters = max(1, (len(data) + vol.cluster - 1) // vol.cluster)
    lcn = alloc.take(clusters)
    vol.d[lcn * vol.cluster:lcn * vol.cluster + len(data)] = data
    r = set_fn(r, name=new, parent=parent_ref)
    r = set_flags(r, in_use=True, is_dir=False)
    r = drop_attrs(r, {0x80, 0x90, 0xA0, 0xB0})
    r = add_nonresident_data(r, lcn, clusters, len(data), vol.cluster)
    vol.write(n, r)
    return ref(n, vol.read(n))


PE_STUB = bytearray(0x48)
PE_STUB[0:2] = b"MZ"
struct.pack_into("<I", PE_STUB, 0x3C, 0x40)
PE_STUB[0x40:0x44] = b"PE\0\0"
PE_STUB = bytes(PE_STUB)

FT_2009 = 128_920_032_000_000_000  # 2009-07-14 00:00:00 UTC, whole second


def main():
    src = open(os.path.join(FIX, "testfs1"), "rb").read()
    vol = Volume(src)
    by_name = {}
    for n, rec in vol.records():
        nm = name_of(rec)
        if nm is not None:
            by_name.setdefault(nm, n)

    def rec_of(name):
        n = by_name[name]
        return n, vol.read(n)

    root_ref = ref(5, vol.read(5))

    # Timestomp.
    n, r = rec_of("file-with-12345")
    vol.write(n, set_si_created(r, FT_2009))

    # SDelete pattern: rename, zero content, delete.
    n, r = rec_of("1000-bytes-file")
    for lcn, count in vol.runs_of(r, 0x80):
        vol.d[lcn * vol.cluster:(lcn + count) * vol.cluster] = b"\0" * (count * vol.cluster)
    vol.write(n, set_flags(set_fn(r, name="ZZZZZZZZZZZZZZZ"), in_use=False))

    # Executable disguised as a photo.
    n, r = rec_of("sparse-file")
    lcn = vol.runs_of(r, 0x80)[0][0]
    vol.d[lcn * vol.cluster:lcn * vol.cluster + len(PE_STUB)] = PE_STUB
    vol.write(n, set_fn(r, name="photo01.jpg"))

    # Windows-like tree out of numbered directories.
    def mkdir(old, new, parent_ref, is_dir=True, in_use=True):
        n, r = rec_of(old)
        r = set_fn(r, name=new, parent=parent_ref)
        r = set_flags(r, in_use=in_use, is_dir=is_dir)
        vol.write(n, r)
        return ref(n, vol.read(n))

    n, r = rec_of("many_subdirs")
    vol.write(n, set_fn(r, name="Windows"))
    win = ref(n, vol.read(n))
    sys32 = mkdir("1", "System32", win)
    prefetch = mkdir("2", "Prefetch", win)
    users = mkdir("3", "Users", root_ref)
    alice = mkdir("4", "alice", users)
    mkdir("5", "SDELETE64.EXE-1A2B3C4D.pf", prefetch, is_dir=False, in_use=False)
    mkdir("6", "sdelete64.exe", alice, is_dir=False)
    winevt = mkdir("7", "winevt", sys32)
    mkdir("8", "Logs", winevt)
    mkdir("9", "ntoskrnl.exe", sys32, is_dir=False)

    # ADS payload on a user document.
    n, r = rec_of("empty-file")
    r = set_fn(r, name="notes.txt", parent=alice)
    vol.write(n, add_ads(r, "payload", PE_STUB))

    # Browser profiles with real SQLite history databases.
    dbs = fixture_browsers.build()
    alloc = Allocator(vol)
    appdata = mkdir("10", "AppData", alice)
    local = mkdir("11", "Local", appdata)
    chrome_ud = mkdir("14", "User Data", mkdir("13", "Chrome", mkdir("12", "Google", local)))
    plant_file(vol, alloc, "16", "History", mkdir("15", "Default", chrome_ud), dbs["chrome"], rec_of)
    edge_ud = mkdir("19", "User Data", mkdir("18", "Edge", mkdir("17", "Microsoft", local)))
    plant_file(vol, alloc, "21", "History", mkdir("20", "Default", edge_ud), dbs["edge"], rec_of)
    profiles = mkdir("25", "Profiles", mkdir("24", "Firefox", mkdir("23", "Mozilla", mkdir("22", "Roaming", appdata))))
    ff = mkdir("26", "k3x9w2qe.default-release", profiles)
    plant_file(vol, alloc, "27", "places.sqlite", ff, dbs["firefox"], rec_of)
    plant_file(vol, alloc, "28", "places.sqlite-wal", ff, dbs["firefox_wal"], rec_of)

    out = bytes(vol.d)
    open(os.path.join(FIX, "testfs1-af"), "wb").write(out)

    # MBR disk wrapper.
    gap = 1024 * 1024
    mbr = bytearray(512)
    struct.pack_into("<BBBBBBBBII", mbr, 446, 0x00, 0, 0, 0, 0x07, 0, 0, 0, gap // 512, len(out) // 512)
    mbr[510:512] = b"\x55\xaa"
    disk = bytes(mbr) + b"\0" * (gap - 512) + out + b"\0" * (2 * 1024 * 1024)
    open(os.path.join(FIX, "disk-af.img"), "wb").write(disk)
    print("wrote testfs1-af and disk-af.img")


if __name__ == "__main__":
    main()
