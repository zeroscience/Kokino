"""Builds the FAT12/16/32 and exFAT test volumes in tests/fixtures.

Pure Python (no mkfs tools needed), deterministic, lab content only.
Every volume holds the same story:

  /Projects/Nightjar plan (final).txt   live, fragmented (two cluster runs)
  /Projects/budget.csv                  live, sits between the two runs
  /Projects/Photos/IMG_0001.JPG         live, small JPEG-shaped file
  /Projects/report.txt                  live, reuses the clusters of ...
  /Projects/overwritten draft.txt       deleted, clusters in use again
  /Old keys.txt                         deleted, clusters still free
  /Trip/itinerary.txt                   in a deleted directory

and a disk image (disk-fat.img, MBR) with the FAT32 and exFAT volumes as
two partitions for the end-to-end analysis tests.

    python scripts/make_fat_fixture.py
"""

import os
import struct

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures")
BPS = 512
NOTES = b"Move the archive to the external drive.\n" * 200
KEYS = b"vault: 4242-1717\n"
DRAFT = b"Draft: meet at the north gate at 06:00.\n" * 20
REPORT = b"Quarterly report, final numbers attached.\n" * 24
BUDGET = b"item,amount\nboat,1200\nfuel,310\n" * 30
TRIP = b"Day 1: ferry to the island. Day 2: back by noon.\n"
# A JPEG-shaped blob: SOI, APP0 JFIF, filler, EOI.
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + bytes(range(256)) * 5 + b"\xff\xd9"

# 2026-10-20 09:45:30 local
DATE = ((2026 - 1980) << 9) | (10 << 5) | 20
TIME = (9 << 11) | (45 << 5) | 15


def chain_sum(data, skip=()):
    s = 0
    for i, b in enumerate(data):
        if i in skip:
            continue
        s = (((s & 1) << 15) | (s >> 1)) + b & 0xFFFF
    return s


def lfn_checksum(short):
    s = 0
    for c in short:
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


class Volume:
    """Shared cluster allocator: next-fit, like Windows, so freed clusters
    stay untouched unless a file is placed on them on purpose."""

    def alloc(self, n):
        cs = list(range(self.next, self.next + n))
        self.next += n
        return cs

    def chain(self, cs):
        for a, b in zip(cs, cs[1:]):
            self.fat[a] = b
        self.fat[cs[-1]] = self.eoc

    def free(self, cs):
        for c in cs:
            self.fat[c] = 0

    def put(self, cs, data):
        for i, c in enumerate(cs):
            part = data[i * self.cluster:(i + 1) * self.cluster]
            o = self.coff(c)
            self.img[o:o + len(part)] = part

    def coff(self, c):
        return self.heap + (c - 2) * self.cluster


class Fat(Volume):
    def __init__(self, bits, sectors, label):
        self.bits, self.sectors, self.label = bits, sectors, label
        self.cluster = BPS
        self.rsvd = 32 if bits == 32 else 1
        self.root_ents = 0 if bits == 32 else 512
        root_secs = self.root_ents * 32 // BPS
        fatsz = 1
        while True:
            clusters = sectors - self.rsvd - 2 * fatsz - root_secs
            need = -(-(clusters + 2) * bits // 8 // BPS)
            if need <= fatsz:
                break
            fatsz = need
        self.fatsz, self.clusters = fatsz, clusters
        self.root_off = (self.rsvd + 2 * fatsz) * BPS
        self.heap = self.root_off + root_secs * BPS
        self.img = bytearray(sectors * BPS)
        self.eoc = {12: 0xFFF, 16: 0xFFFF, 32: 0x0FFFFFFF}[bits]
        self.fat = [0] * (clusters + 2)
        self.fat[0] = self.eoc & ~0xFF | 0xF8
        self.fat[1] = self.eoc
        self.next = 2
        self.dirs = {}
        if bits == 32:
            self.root = self.mkdir_storage(4)
        else:
            self.root = ("root", [])
        self.dirs["/"] = self.root
        self.short_ix = 0

    def mkdir_storage(self, n):
        cs = self.alloc(n)
        self.chain(cs)
        return (cs, [])

    def short_for(self, name):
        stem, _, ext = name.rpartition(".") if "." in name else (name, "", "")
        clean = lambda s: "".join(c for c in s.upper() if c.isalnum())
        base, ext = clean(stem), clean(ext)[:3]
        if name == name.upper() and len(base) <= 8 and stem == base and (not ext or name.endswith("." + ext)):
            return (base.ljust(8) + ext.ljust(3)).encode(), False
        self.short_ix += 1
        return ((base[:6] + "~" + str(self.short_ix % 10)).ljust(8) + ext.ljust(3)).encode(), True

    def add(self, dirpath, name, start, size, attr=0x20):
        """Appends LFN entries plus the short entry; returns their indices."""
        d = self.dirs[dirpath][1]
        short, need_lfn = self.short_for(name)
        first = len(d)
        if need_lfn:
            u = name.encode("utf-16-le")
            chars = [u[i:i + 2] for i in range(0, len(u), 2)]
            if len(chars) % 13:
                chars.append(b"\x00\x00")
            while len(chars) % 13:
                chars.append(b"\xff\xff")
            parts = [chars[i:i + 13] for i in range(0, len(chars), 13)]
            sum_ = lfn_checksum(short)
            for k in range(len(parts), 0, -1):
                p = parts[k - 1]
                e = bytearray(32)
                e[0] = k | (0x40 if k == len(parts) else 0)
                e[1:11] = b"".join(p[0:5])
                e[11] = 0x0F
                e[13] = sum_
                e[14:26] = b"".join(p[5:11])
                e[28:32] = b"".join(p[11:13])
                d.append(e)
        e = bytearray(32)
        e[0:11] = short
        e[11] = attr
        e[13] = 50
        struct.pack_into("<HHHHHHHI", e, 14, TIME, DATE, DATE, start >> 16, TIME + 2, DATE, start & 0xFFFF, size)
        if attr == 0x08:
            e[13:32] = bytes(19)
        d.append(e)
        return list(range(first, len(d)))

    def label_entry(self):
        e = bytearray(32)
        e[0:11] = self.label.upper().ljust(11)[:11].encode()
        e[11] = 0x08
        struct.pack_into("<HH", e, 22, TIME, DATE)
        self.dirs["/"][1].append(e)

    def mkdir(self, parent, name, n=2):
        cs, _ = self.mkdir_storage(n)
        self.add(parent, name, cs[0], 0, attr=0x10)
        path = (parent.rstrip("/") + "/" + name)
        self.dirs[path] = (cs, [])
        pc = 0 if parent == "/" else self.dirs[parent][0][0]
        for nm, c in ((b".          ", cs[0]), (b"..         ", pc)):
            e = bytearray(32)
            e[0:11] = nm
            e[11] = 0x10
            struct.pack_into("<HHHHHHHI", e, 14, TIME, DATE, DATE, c >> 16, TIME, DATE, c & 0xFFFF, 0)
            self.dirs[path][1].append(e)
        return path

    def file(self, dirpath, name, data, cs=None):
        n = max(1, -(-len(data) // self.cluster))
        cs = cs or self.alloc(n)
        self.chain(cs)
        self.put(cs, data)
        return cs, self.add(dirpath, name, cs[0], len(data))

    def delete(self, dirpath, idxs, cs):
        for i in idxs:
            self.dirs[dirpath][1][i][0] = 0xE5
        self.free(cs)

    def build(self):
        self.story()
        for path, (where, ents) in self.dirs.items():
            raw = b"".join(bytes(e) for e in ents)
            if where == "root":
                assert len(raw) <= self.root_ents * 32
                self.img[self.root_off:self.root_off + len(raw)] = raw
            else:
                assert len(raw) <= len(where) * self.cluster, path
                self.put(where, raw)
        b = self.img
        b[0:3] = b"\xEB\x3C\x90" if self.bits != 32 else b"\xEB\x58\x90"
        b[3:11] = b"MSDOS5.0"
        tot16 = self.sectors if self.sectors < 0x10000 and self.bits != 32 else 0
        struct.pack_into("<HBHBHHBHHHII", b, 11, BPS, 1, self.rsvd, 2, self.root_ents, tot16, 0xF8,
                         self.fatsz if self.bits != 32 else 0, 63, 255, 0, 0 if tot16 else self.sectors)
        serial = {12: 0x1A2B3C4D, 16: 0x2B3C4D5E, 32: 0x3C4D5E6F}[self.bits]
        lab = self.label.upper().ljust(11)[:11].encode()
        if self.bits == 32:
            struct.pack_into("<IHHIHH", b, 36, self.fatsz, 0, 0, 2, 1, 6)
            struct.pack_into("<BBBI", b, 64, 0x80, 0, 0x29, serial)
            b[71:82] = lab
            b[82:90] = b"FAT32   "
            fsinfo = bytearray(BPS)
            free = sum(1 for c in range(2, self.clusters + 2) if self.fat[c] == 0)
            struct.pack_into("<I", fsinfo, 0, 0x41615252)
            struct.pack_into("<IIII", fsinfo, 484, 0x61417272, free, self.next, 0)
            struct.pack_into("<I", fsinfo, 508, 0xAA550000)
            b[BPS:2 * BPS] = fsinfo
        else:
            struct.pack_into("<BBBI", b, 36, 0x80, 0, 0x29, serial)
            b[43:54] = lab
            b[54:62] = b"FAT12   " if self.bits == 12 else b"FAT16   "
        b[510:512] = b"\x55\xAA"
        if self.bits == 32:
            b[6 * BPS:7 * BPS] = b[0:BPS]
            b[7 * BPS:8 * BPS] = b[BPS:2 * BPS]
        fat = bytearray(self.fatsz * BPS)
        for c, v in enumerate(self.fat):
            if self.bits == 12:
                o = c + c // 2
                w = struct.unpack_from("<H", fat, o)[0]
                w = (w & 0xF000) | v if c % 2 == 0 else (w & 0x000F) | (v << 4)
                struct.pack_into("<H", fat, o, w)
            elif self.bits == 16:
                struct.pack_into("<H", fat, 2 * c, v)
            else:
                struct.pack_into("<I", fat, 4 * c, v)
        for i in range(2):
            o = (self.rsvd + i * self.fatsz) * BPS
            b[o:o + len(fat)] = fat
        return bytes(b)

    def story(self):
        self.label_entry()
        proj = self.mkdir("/", "Projects")
        photos = self.mkdir(proj, "Photos")
        self.file(photos, "IMG_0001.JPG", JPEG)
        # Fragmented: budget.csv sits between the two halves of the notes.
        first = self.alloc(8)
        self.file(proj, "budget.csv", BUDGET)
        notes = first + self.alloc(len(NOTES) // self.cluster + 1 - 8)
        self.file(proj, "Nightjar plan (final).txt", NOTES, cs=notes)
        cs, ix = self.file("/", "Old keys.txt", KEYS)
        self.delete("/", ix, cs)
        cs, ix = self.file(proj, "overwritten draft.txt", DRAFT)
        self.delete(proj, ix, cs)
        self.file(proj, "report.txt", REPORT, cs=cs + self.alloc(len(REPORT) // self.cluster + 1 - len(cs)))
        # A deleted directory whose entries still describe its file.
        root = self.dirs["/"][1]
        start = len(root)
        trip = self.mkdir("/", "Trip", n=1)
        tcs, _ = self.file(trip, "itinerary.txt", TRIP)
        self.free(tcs)
        self.delete("/", list(range(start, len(root))), self.dirs[trip][0])


class ExFat(Volume):
    def __init__(self, sectors, label, part_offset=0):
        self.sectors, self.label, self.part_offset = sectors, label, part_offset
        self.cluster = BPS
        self.fat_off = 24
        clusters = sectors - self.fat_off
        self.fat_len = -(-(clusters + 2) * 4 // BPS)
        self.heap_sec = self.fat_off + self.fat_len
        self.clusters = sectors - self.heap_sec
        self.heap = self.heap_sec * BPS
        self.img = bytearray(sectors * BPS)
        self.eoc = 0xFFFFFFFF
        self.fat = [0] * (self.clusters + 2)
        self.fat[0], self.fat[1] = 0xFFFFFFF8, 0xFFFFFFFF
        self.used = set()
        self.next = 2
        self.dirs = {}

    def take(self, cs, fat_chain):
        self.used.update(cs)
        if fat_chain:
            self.chain(cs)

    def entry_set(self, name, attr, start, size, nofat):
        u = name.encode("utf-16-le")
        names = [u[i:i + 30] for i in range(0, len(u), 30)]
        prim = bytearray(32)
        prim[0] = 0x85
        prim[1] = 1 + len(names)
        struct.pack_into("<H", prim, 4, attr)
        struct.pack_into("<III", prim, 8, DATE << 16 | TIME, DATE << 16 | (TIME + 2), DATE << 16 | TIME)
        prim[20], prim[21], prim[22], prim[23], prim[24] = 50, 0, 0x88, 0x88, 0x88
        st = bytearray(32)
        st[0] = 0xC0
        st[1] = 1 | (2 if nofat else 0)
        st[3] = len(name)
        struct.pack_into("<H", st, 4, chain_sum(name.upper().encode("utf-16-le")))
        struct.pack_into("<Q", st, 8, size)
        struct.pack_into("<IQ", st, 20, start, size)
        ents = [prim, st]
        for n in names:
            e = bytearray(32)
            e[0] = 0xC1
            e[2:2 + len(n)] = n
            ents.append(e)
        raw = b"".join(bytes(e) for e in ents)
        struct.pack_into("<H", ents[0], 2, chain_sum(raw, skip=(2, 3)))
        return ents

    def add(self, dirpath, name, attr, start, size, nofat):
        d = self.dirs[dirpath][1]
        first = len(d)
        d.extend(self.entry_set(name, attr, start, size, nofat))
        return list(range(first, len(d)))

    def mkdir(self, parent, name, n=2):
        cs = self.alloc(n)
        self.take(cs, True)
        self.add(parent, name, 0x10, cs[0], n * self.cluster, False)
        path = parent.rstrip("/") + "/" + name
        self.dirs[path] = (cs, [])
        return path

    def file(self, dirpath, name, data, cs=None, nofat=True):
        cs = cs or self.alloc(max(1, -(-len(data) // self.cluster)))
        self.take(cs, not nofat)
        self.put(cs, data)
        return cs, self.add(dirpath, name, 0x20, cs[0], len(data), nofat)

    def delete(self, dirpath, idxs, cs):
        for i in idxs:
            self.dirs[dirpath][1][i][0] &= 0x7F
        self.used.difference_update(cs)
        self.free(cs)

    def build(self):
        bm_c = self.alloc(1)
        self.take(bm_c, True)
        up = b"".join(struct.pack("<H", ord(chr(i).upper()) if i < 128 else i) for i in range(128))
        up_c = self.alloc(1)
        self.take(up_c, True)
        self.put(up_c, up)
        root = self.alloc(4)
        self.take(root, True)
        self.dirs["/"] = (root, [])
        r = self.dirs["/"][1]
        lab = bytearray(32)
        lab[0] = 0x83
        lab[1] = len(self.label)
        lab[2:2 + 2 * len(self.label)] = self.label.encode("utf-16-le")
        bm = bytearray(32)
        bm[0] = 0x81
        struct.pack_into("<IQ", bm, 20, bm_c[0], (self.clusters + 7) // 8)
        uc = bytearray(32)
        uc[0] = 0x82
        upsum = 0
        for x in up:
            upsum = (((upsum & 1) << 31) | (upsum >> 1)) + x & 0xFFFFFFFF
        struct.pack_into("<I", uc, 4, upsum)
        struct.pack_into("<IQ", uc, 20, up_c[0], len(up))
        r.extend([lab, bm, uc])
        self.story()
        for path, (cs, ents) in self.dirs.items():
            raw = b"".join(bytes(e) for e in ents)
            assert len(raw) <= len(cs) * self.cluster, path
            self.put(cs, raw)
        bitmap = bytearray((self.clusters + 7) // 8)
        for c in self.used:
            bitmap[(c - 2) // 8] |= 1 << ((c - 2) % 8)
        self.put(bm_c, bytes(bitmap))
        b = self.img
        boot = bytearray(BPS)
        boot[0:3] = b"\xEB\x76\x90"
        boot[3:11] = b"EXFAT   "
        struct.pack_into("<QQIIIIIIHHBBBBB", boot, 64, self.part_offset, self.sectors, self.fat_off, self.fat_len,
                         self.heap_sec, self.clusters, root[0], 0x4D5E6F70, 0x0100, 0, 9, 0, 1, 0x80,
                         len(self.used) * 100 // self.clusters)
        boot[510:512] = b"\x55\xAA"
        region = bytearray(12 * BPS)
        region[0:BPS] = boot
        for s in range(1, 9):
            region[s * BPS + 510:s * BPS + 512] = b"\x55\xAA"
        s = 0
        for i, x in enumerate(region[:11 * BPS]):
            if i in (106, 107, 112):
                continue
            s = (((s & 1) << 31) | (s >> 1)) + x & 0xFFFFFFFF
        region[11 * BPS:12 * BPS] = struct.pack("<I", s) * (BPS // 4)
        b[0:12 * BPS] = region
        b[12 * BPS:24 * BPS] = region
        fat = b"".join(struct.pack("<I", v) for v in self.fat)
        b[self.fat_off * BPS:self.fat_off * BPS + len(fat)] = fat
        return bytes(b)

    def story(self):
        proj = self.mkdir("/", "Projects")
        photos = self.mkdir(proj, "Photos")
        self.file(photos, "IMG_0001.JPG", JPEG)
        first = self.alloc(8)
        self.file(proj, "budget.csv", BUDGET)
        notes = first + self.alloc(len(NOTES) // self.cluster + 1 - 8)
        self.file(proj, "Nightjar plan (final).txt", NOTES, cs=notes, nofat=False)
        cs, ix = self.file("/", "Old keys.txt", KEYS)
        self.delete("/", ix, cs)
        cs, ix = self.file(proj, "overwritten draft.txt", DRAFT)
        self.delete(proj, ix, cs)
        self.file(proj, "report.txt", REPORT, cs=cs + self.alloc(len(REPORT) // self.cluster + 1 - len(cs)))
        root = self.dirs["/"][1]
        start = len(root)
        trip = self.mkdir("/", "Trip", n=1)
        tcs, _ = self.file(trip, "itinerary.txt", TRIP)
        self.delete("/", list(range(start, len(root))), self.dirs[trip][0])
        self.used.difference_update(tcs)


def mbr(parts, total):
    b = bytearray(BPS)
    struct.pack_into("<I", b, 440, 0x4B4F4B49)
    for i, (typ, start, n) in enumerate(parts):
        o = 446 + 16 * i
        b[o:o + 16] = struct.pack("<B3sB3sII", 0, b"\xFE\xFF\xFF", typ, b"\xFE\xFF\xFF", start, n)
    b[510:512] = b"\x55\xAA"
    return bytes(b) + bytes(total * BPS - BPS)


def main():
    vols = {
        "fat12.img": Fat(12, 2048, "KOKINO FAT1").build(),
        "fat16.img": Fat(16, 5120, "KOKINO FAT2").build(),
        "fat32.img": Fat(32, 5120, "KOKINO FAT3").build(),
        "exfat.img": ExFat(2048, "KokinoExFAT").build(),
    }
    for name, data in vols.items():
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)
        print(name, len(data))
    # Disk: FAT32 (type 0x0C) at sector 128, exFAT (type 0x07) after it.
    s1 = 128
    s2 = s1 + 5120
    disk = bytearray(mbr([(0x0C, s1, 5120), (0x07, s2, 2048)], s2 + 2048 + 64))
    disk[s1 * BPS:(s1 + 5120) * BPS] = vols["fat32.img"]
    disk[s2 * BPS:(s2 + 2048) * BPS] = ExFat(2048, "KokinoExFAT", part_offset=s2).build()
    with open(os.path.join(OUT, "disk-fat.img"), "wb") as f:
        f.write(disk)
    print("disk-fat.img", len(disk))


if __name__ == "__main__":
    main()
