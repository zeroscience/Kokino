"""UDF test images with sparable and virtual partitions, for Kokino's tests.

mkisofs writes only plain UDF; these two layouts come from rewritable and
write-once discs written in packets, so they are built here directly from
ECMA-167 and the OSTA UDF 2.01 specification (pure Python, descriptor tags
with their checksums and CRCs).

    tests/fixtures/udf-sparable.img   DVD-RW style: one sparable partition
                                      map, packets of 32 blocks, one sparing
                                      table. The packet holding moved.txt
                                      was moved to the spare area; its
                                      original place holds other text
                                      ("STALE COPY..."), so a reader that
                                      ignores the sparing table shows the
                                      wrong content.
    tests/fixtures/udf-vat.img        CD-R style: a physical and a virtual
                                      partition map. The file set, every
                                      file entry and directory are in the
                                      virtual partition; the VAT (UDF 2.00
                                      layout, file type 248) in the last
                                      sector maps them to physical blocks,
                                      which are not in order. File data is
                                      in the physical partition (long_ad).

The tree on both (invented data):

    README.TXT                  "Kokino UDF test disc. Invented data.\\n"
    docs/report.txt             5,000 bytes over three blocks
    moved.txt                   (sparable) in the moved packet
    session.txt                 (VAT)

Every time is 2026-10-20 08:05:30 UTC.

    python scripts/make_udf_fixture.py
"""
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "fixtures")
BS = 2048


def crc_itu(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def tag(ident, location, body, version=2, serial=1):
    """A descriptor: 16-byte tag, then `body` (the rest of the descriptor)."""
    crc = crc_itu(body)
    t = bytearray(struct.pack("<HHBBHHHI", ident, version, 0, 0, serial, crc, len(body), location))
    t[4] = sum(t[i] for i in range(16) if i != 4) & 0xFF
    return bytes(t) + body


def ts():
    # Type 1 (local time) with offset 0: 2026-10-20 08:05:30.
    return struct.pack("<HHBBBBBBBB", (1 << 12) | 0, 2026, 10, 20, 8, 5, 30, 0, 0, 0)


def entity(ident, suffix=b""):
    return bytes([0]) + ident.ljust(23, b"\0")[:23] + suffix.ljust(8, b"\0")[:8]


def udf_suffix(rev=0x0201):
    return struct.pack("<HB", rev, 0)


def dstring(s, n):
    b = b"\x08" + s.encode("latin-1")
    return b.ljust(n - 1, b"\0") + bytes([len(b)])


def charspec():
    return bytes([0]) + b"OSTA Compressed Unicode".ljust(63, b"\0")


def long_ad(length, lbn, part):
    return struct.pack("<IIH", length, lbn, part) + bytes(6)


def pad(b):
    return b.ljust(BS, b"\0")


class Disc:
    def __init__(self, sectors):
        self.d = bytearray(sectors * BS)

    def put(self, sector, data):
        assert len(data) <= BS * ((len(data) + BS - 1) // BS)
        self.d[sector * BS:sector * BS + len(data)] = data

    def recognition(self):
        for i, ident in enumerate((b"BEA01", b"NSR03", b"TEA01")):
            self.put(16 + i, b"\x00" + ident + b"\x01")


def avdp(vds, length):
    body = struct.pack("<II", length * BS, vds) + struct.pack("<II", length * BS, vds) + bytes(480)
    return tag(2, 256, body)


def pvd(loc, label):
    body = bytearray(512 - 16)
    struct.pack_into("<II", body, 0, 1, 0)                                # VDS number, PVD number
    body[24 - 16:24 - 16 + 32] = dstring(label, 32)
    struct.pack_into("<HHHI", body, 56 - 16, 1, 1, 2, 1)                 # vol seq, max, interchange, charset list
    body[376 - 16:376 - 16 + 12] = ts()
    return tag(1, loc, bytes(body))


def partition_desc(loc, number, start, length, access):
    body = bytearray(512 - 16)
    struct.pack_into("<IHH", body, 0, 2, 1, number)                      # VDS number, flags (allocated), number
    body[24 - 16:24 - 16 + 32] = entity(b"+NSR03")
    struct.pack_into("<III", body, 184 - 16, access, start, length)
    return tag(5, loc, bytes(body))


def lvd(loc, label, fsd_lbn, fsd_part, maps):
    table = b"".join(maps)
    body = bytearray(440 - 16)
    struct.pack_into("<I", body, 0, 3)
    body[20 - 16:20 - 16 + 64] = charspec()
    body[84 - 16:84 - 16 + 128] = dstring(label, 128)
    struct.pack_into("<I", body, 212 - 16, BS)
    body[216 - 16:216 - 16 + 32] = entity(b"*OSTA UDF Compliant", udf_suffix())
    body[248 - 16:248 - 16 + 16] = long_ad(BS, fsd_lbn, fsd_part)
    struct.pack_into("<II", body, 264 - 16, len(table), len(maps))
    return tag(6, loc, bytes(body) + table)


def term(loc):
    return tag(8, loc, bytes(512 - 16))


def map_physical(number):
    return struct.pack("<BBHH", 1, 6, 1, number)


def map_sparable(number, packet, tables, table_size):
    m = bytearray(64)
    m[0], m[1] = 2, 64
    m[4:36] = entity(b"*UDF Sparable Partition", udf_suffix())
    struct.pack_into("<HHHBBI", m, 36, 1, number, packet, len(tables), 0, table_size)
    for i, t in enumerate(tables):
        struct.pack_into("<I", m, 48 + 4 * i, t)
    return bytes(m)


def map_virtual(number):
    m = bytearray(64)
    m[0], m[1] = 2, 64
    m[4:36] = entity(b"*UDF Virtual Partition", udf_suffix())
    struct.pack_into("<HH", m, 36, 1, number)
    return bytes(m)


def fsd(loc, root_lbn, root_part):
    body = bytearray(512 - 16)
    body[16 - 16:16 - 16 + 12] = ts()
    struct.pack_into("<HHII", body, 28 - 16, 3, 3, 1, 1)
    body[48 - 16:48 - 16 + 64] = charspec()
    body[112 - 16:112 - 16 + 128] = dstring("KOKINO_UDF", 128)
    body[240 - 16:240 - 16 + 64] = charspec()
    body[304 - 16:304 - 16 + 32] = dstring("KOKINO_UDF", 32)
    body[400 - 16:400 - 16 + 16] = long_ad(BS, root_lbn, root_part)
    body[416 - 16:416 - 16 + 32] = entity(b"*OSTA UDF Compliant", udf_suffix())
    return tag(256, loc, bytes(body))


def file_entry(loc, ftype, size, ads, ad_kind, unique, links=1):
    """`ads`: allocation descriptors (bytes); `ad_kind` 0 short, 1 long, 3 embedded."""
    body = bytearray(176 - 16)
    struct.pack_into("<IHHHBB", body, 0, 0, 4, 0, 1, 0, ftype)           # ICB tag: strategy 4, file type
    struct.pack_into("<H", body, 34 - 16, ad_kind)
    struct.pack_into("<IIIH", body, 36 - 16, 1000, 1000, 0x1CE7, links)  # uid, gid, permissions, links
    struct.pack_into("<QQ", body, 56 - 16, size, (size + BS - 1) // BS if ad_kind != 3 else 0)
    for off in (72, 84, 96):
        body[off - 16:off - 16 + 12] = ts()
    struct.pack_into("<I", body, 108 - 16, 1)
    body[128 - 16:128 - 16 + 32] = entity(b"*Kokino test")
    struct.pack_into("<QII", body, 160 - 16, unique, 0, len(ads))
    return tag(261, loc, bytes(body) + ads)


def fid(name, lbn, part, is_dir=False, parent=False, deleted=False):
    ch = (2 if is_dir else 0) | (8 if parent else 0) | (4 if deleted else 0)
    ident = b"" if parent else b"\x08" + name.encode("latin-1")
    body = struct.pack("<HBB", 1, ch, len(ident)) + long_ad(BS, lbn, part) + struct.pack("<H", 0) + ident
    total = (38 + len(ident) + 3) & ~3
    body = body.ljust(total - 16, b"\0")
    return tag(257, 0, body)


README = b"Kokino UDF test disc. Invented data.\n"
REPORT = (b"Quarterly report line, lab.test internal.\n" * 120)[:5000]
MOVED = b"This block was moved to the spare area (test data).\n"
STALE = b"STALE COPY left where the packet used to be (test data).\n"
SESSION = b"Written in the last session of a CD-R (test data).\n"


def common_vds(disc, label, part_start, part_len, access, maps, fsd_lbn, fsd_part):
    disc.recognition()
    disc.put(256, avdp(32, 4))
    disc.put(32, pvd(32, label))
    disc.put(33, partition_desc(33, 0, part_start, part_len, access))
    disc.put(34, lvd(34, label, fsd_lbn, fsd_part, maps))
    disc.put(35, term(35))


def sparable():
    """Partition 0 at sector 400, 256 blocks, packets of 32. Packet 64..95
    (moved.txt's data at block 70) was moved to the spare packet at sector
    320; the sparing table at sector 300 says so."""
    PSTART, PLEN, PACKET = 400, 256, 32
    disc = Disc(PSTART + PLEN + 64)
    common_vds(disc, "KOKINO_DVDRW", PSTART, PLEN, 4, [map_sparable(0, PACKET, [300], 56 + 8 * 4)], 0, 0)
    blk = lambda lbn, data: disc.put(PSTART + lbn, data)
    # Sparing table: one moved packet, three free spare packets.
    entries = struct.pack("<II", 64, 320) + struct.pack("<II", 0xFFFFFFFF, 352) * 3
    st = bytearray(entity(b"*UDF Sparing Table", udf_suffix())) + struct.pack("<HHI", 4, 0, 1) + entries
    disc.put(300, tag(0, 300, bytes(st)))
    root, docs, readme, report, moved = 1, 2, 3, 4, 5
    blk(0, fsd(0, root, 0))
    rootdir = fid("", root, 0, is_dir=True, parent=True) + fid("README.TXT", readme, 0) + fid("docs", docs, 0, is_dir=True) + fid("moved.txt", moved, 0)
    docsdir = fid("", root, 0, is_dir=True, parent=True) + fid("report.txt", report, 0)
    blk(root, file_entry(root, 4, len(rootdir), rootdir, 3, 16, links=2))
    blk(docs, file_entry(docs, 4, len(docsdir), docsdir, 3, 17))
    blk(readme, file_entry(readme, 5, len(README), README, 3, 18))
    blk(report, file_entry(report, 5, len(REPORT), struct.pack("<II", len(REPORT), 10), 0, 19))
    for i in range(3):
        blk(10 + i, pad(REPORT[i * BS:(i + 1) * BS]))
    blk(moved, file_entry(moved, 5, len(MOVED), struct.pack("<II", len(MOVED), 70), 0, 20))
    blk(70, pad(STALE))                         # where the packet was
    disc.put(320 + (70 - 64), pad(MOVED))       # where it is now
    return bytes(disc.d)


def vat():
    """Partition 0 at sector 300. Virtual blocks: 0 FSD, 1 root, 2 docs,
    3 README FE, 4 report FE, 5 session FE, recorded at physical blocks
    (relative to the partition) 40, 41, 50, 42, 51, 60 - not in order. File
    data at physical blocks 20.. (long_ad, partition reference 0). The VAT
    file entry is the last sector of the image, its data the sector
    before."""
    PSTART = 300
    total = PSTART + 80
    disc = Disc(total)
    common_vds(disc, "KOKINO_CDR", PSTART, total - PSTART, 2, [map_physical(0), map_virtual(0)], 0, 1)
    phys = lambda lbn, data: disc.put(PSTART + lbn, data)
    where = {0: 40, 1: 41, 2: 50, 3: 42, 4: 51, 5: 60}
    v = lambda vlbn, data: phys(where[vlbn], data)
    v(0, fsd(0, 1, 1))
    rootdir = fid("", 1, 1, is_dir=True, parent=True) + fid("README.TXT", 3, 1) + fid("docs", 2, 1, is_dir=True) + fid("session.txt", 5, 1)
    docsdir = fid("", 1, 1, is_dir=True, parent=True) + fid("report.txt", 4, 1)
    v(1, file_entry(1, 4, len(rootdir), rootdir, 3, 16, links=2))
    v(2, file_entry(2, 4, len(docsdir), docsdir, 3, 17))
    v(3, file_entry(3, 5, len(README), README, 3, 18))
    v(4, file_entry(4, 5, len(REPORT), long_ad(len(REPORT), 20, 0), 1, 19))
    for i in range(3):
        phys(20 + i, pad(REPORT[i * BS:(i + 1) * BS]))
    v(5, file_entry(5, 5, len(SESSION), long_ad(len(SESSION), 30, 0), 1, 20))
    phys(30, pad(SESSION))
    # VAT (UDF 2.00): header, then one entry per virtual block.
    hdr = struct.pack("<HH", 152, 0) + dstring("KOKINO_CDR", 128) + struct.pack("<IIIHHHH", 0xFFFFFFFF, 3, 2, 0x0201, 0x0201, 0x0201, 0)
    assert len(hdr) == 152
    table = hdr + b"".join(struct.pack("<I", where[i]) for i in range(6))
    last = total - 1
    phys(last - 1 - PSTART, pad(table))
    disc.put(last, file_entry(last - PSTART, 248, len(table), struct.pack("<II", len(table), last - 1 - PSTART), 0, 21))
    return bytes(disc.d)


def main():
    for name, data in (("udf-sparable.img", sparable()), ("udf-vat.img", vat())):
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)
        print(name, len(data), "bytes")


if __name__ == "__main__":
    main()
