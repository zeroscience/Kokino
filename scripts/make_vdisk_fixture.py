"""Virtual disk test images for Kokino, made from tests/fixtures/disk-fat.img.

Pure Python. Every image holds the same disk (an MBR with a FAT32 and an
exFAT partition); the differencing and snapshot images add a known patch on
top of their parent, so a reader must give back:

    base     = disk-fat.img
    patched  = base with PATCH written at PATCH_AT (see below)

    vd-dynamic.vhd          VHD dynamic                      -> base
    vd-diff.vhd             VHD differencing, parent above   -> patched
    vd-dynamic.vhdx         VHDX dynamic (1 MiB blocks)      -> base
    vd-diff.vhdx            VHDX differencing, partially
                            present block + sector bitmap    -> patched
    vd-sparse.vmdk          VMDK monolithicSparse            -> base
    vd-stream.vmdk          VMDK streamOptimized (deflate)   -> base
    vd-flat.vmdk            VMDK monolithicFlat descriptor
      + vd-flat-flat.vmdk   and its flat extent              -> base
    vd-split.vmdk           VMDK twoGbMaxExtentSparse
      + vd-split-s001.vmdk, -s002.vmdk (two sparse extents)  -> base
    vd-snap.vmdk            VMDK snapshot of vd-sparse.vmdk   -> patched

ESXi snapshot formats (python scripts/make_vdisk_fixture.py esx writes
only these), snapshots of vd-flat.vmdk:

    vd-esx-vmfssparse.vmdk  descriptor, createType vmfsSparse
      + vd-esx-vmfssparse-delta.vmdk  "COWD" sparse extent, 1-sector
                            grains, 4096-entry grain tables      -> patched
    vd-esx-sesparse.vmdk    descriptor, createType seSparse
      + vd-esx-sesparse-sesparse.vmdk  SE sparse extent, 4 KiB grains,
                            64-bit grain directory and tables; the
                            patched grain is allocated, and one grain
                            that is zeros in the base is marked "zero"   -> patched

The layouts follow QEMU's vmdk driver (block/vmdk.c), which reads both.

    python scripts/make_vdisk_fixture.py
"""
import os
import struct
import uuid
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
BASE = open(os.path.join(FIX, "disk-fat.img"), "rb").read()
SIZE = len(BASE)
SECTOR = 512
# Patch: 3 sectors starting mid-way through a 64 KiB grain and a VHD block,
# so differencing readers must mix parent and child within one block.
PATCH_AT = 0x21200
PATCH = bytes((i * 7 + 3) & 0xFF for i in range(3 * SECTOR))
PATCHED = BASE[:PATCH_AT] + PATCH + BASE[PATCH_AT + len(PATCH):]
TS = 1792483530  # 2026-10-20 08:05:30 UTC


def out(name, data):
    with open(os.path.join(FIX, name), "wb") as f:
        f.write(data)
    print(name, len(data))


def pad(b, n=SECTOR):
    return b + b"\0" * (-len(b) % n)


# ---------------------------------------------------------------- VHD

def vhd_footer(size, disk_type, uid):
    cyl, heads, spt = 1024, 16, 63
    f = bytearray(512)
    struct.pack_into(">8sIIQI4sI4sQQHBBII16sB", f, 0, b"conectix", 2, 0x00010000,
                     0xFFFFFFFFFFFFFFFF if disk_type == 2 else 512, TS - 946684800, b"kkno",
                     0x00010000, b"Wi2k", size, size, cyl, heads, spt, disk_type, 0, uid, 0)
    struct.pack_into(">I", f, 64, (~sum(f)) & 0xFFFFFFFF)
    return bytes(f)


def vhd(data, block, parent=None, only=None):
    """Dynamic VHD (or differencing when `parent` = (name, uid)). `only`:
    byte ranges this file holds; other blocks stay unallocated."""
    nblocks = (SIZE + block - 1) // block
    uid = uuid.uuid5(uuid.NAMESPACE_URL, "kokino-vhd-%s" % (parent is not None)).bytes
    disk_type = 4 if parent else 3
    footer = vhd_footer(SIZE, disk_type, uid)
    bat_off = 512 + 1024
    bat_len = pad(b"\0" * 4 * nblocks)
    pos = bat_off + len(bat_len)
    loc_data = b""
    locators = bytearray(8 * 24)
    if parent:
        rel = (".\\" + parent[0]).encode("utf-16-le")
        loc_data = pad(rel)
        struct.pack_into(">4sIIIQ", locators, 0, b"W2ru", len(loc_data) // 512, len(rel), 0, pos)
        pos += len(loc_data)
    hdr = bytearray(1024)
    struct.pack_into(">8sQQIIII16sI", hdr, 0, b"cxsparse", 0xFFFFFFFFFFFFFFFF, bat_off, 0x00010000,
                     nblocks, block, 0, parent[1] if parent else bytes(16), TS - 946684800 if parent else 0)
    if parent:
        hdr[64:64 + 512] = parent[0].encode("utf-16-be").ljust(512, b"\0")
        hdr[576:576 + len(locators)] = locators
    struct.pack_into(">I", hdr, 36, (~sum(hdr)) & 0xFFFFFFFF)
    bat = []
    blocks = b""
    bitmap_len = pad(b"\0" * ((block // 512 + 7) // 8))
    for i in range(nblocks):
        lo, hi = i * block, min(SIZE, (i + 1) * block)
        chunk = data[lo:hi].ljust(block, b"\0")
        if only is not None:
            ranges = [(max(a, lo), min(b, hi)) for a, b in only if a < hi and b > lo]
            if not ranges:
                bat.append(0xFFFFFFFF)
                continue
            bm = bytearray(len(bitmap_len))
            for a, b in ranges:
                for s in range((a - lo) // 512, (b - lo + 511) // 512):
                    bm[s // 8] |= 0x80 >> (s % 8)  # big-endian bit order
        else:
            if not any(chunk):
                bat.append(0xFFFFFFFF)
                continue
            bm = bytearray(b"\xff" * len(bitmap_len))
        bat.append((pos + len(blocks)) // 512)
        blocks += bytes(bm) + chunk
    bat_bytes = pad(b"".join(struct.pack(">I", x) for x in bat))
    return footer + bytes(hdr) + bat_bytes + loc_data + blocks + footer, uid


# ---------------------------------------------------------------- VHDX

def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def guid(s):
    return uuid.UUID(s).bytes_le


BAT_GUID = guid("2DC27766-F623-4200-9D64-115E9BFD4A08")
META_GUID = guid("8B7CA206-4790-4B9A-B8FE-575F050F886E")
FILE_PARAMS = guid("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
VDISK_SIZE = guid("2FA54224-CD1B-4876-B211-5DBED83BF4B8")
LOGICAL_SECTOR = guid("8141BF1D-A96F-4709-BA47-F233A8FAAB5F")
PHYSICAL_SECTOR = guid("CDA348C7-445D-4471-9CC9-E9885251C556")
PAGE83 = guid("BECA12AB-B2E6-4523-93EF-C309E000C746")
PARENT_LOCATOR = guid("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C")
VHDX_LOCATOR_TYPE = guid("B04AEFB7-D19E-4A81-B789-25B8E9445913")
MiB = 1 << 20


def vhdx(data, parent=None, only=None):
    """Dynamic VHDX with 1 MiB blocks, or differencing when `parent` =
    (relative path, parent's data write GUID string)."""
    block = MiB
    nblocks = (SIZE + block - 1) // block
    chunk_ratio = (1 << 23) * SECTOR // block
    data_write = str(uuid.uuid5(uuid.NAMESPACE_URL, "kokino-vhdx-%s" % (parent is not None))).upper()
    f = bytearray(4 * MiB)
    f[0:8] = b"vhdxfile"
    creator = "Kokino test".encode("utf-16-le")
    f[8:8 + len(creator)] = creator
    for i, seq in ((0, 1), (1, 2)):
        h = bytearray(4096)
        struct.pack_into("<4sIQ16s16s16sHHIQ", h, 0, b"head", 0, seq, guid(str(uuid.uuid4())), guid(data_write), bytes(16), 0, 1, MiB, MiB)
        struct.pack_into("<I", h, 4, crc32c(h))
        f[(1 + i) * 64 * 1024:(1 + i) * 64 * 1024 + 4096] = h
    # Region table: BAT at 3 MiB, metadata at 2 MiB.
    bat_entries = nblocks + (nblocks - 1) // chunk_ratio if not parent else (nblocks + chunk_ratio - 1) // chunk_ratio * (chunk_ratio + 1)
    bat_len = (bat_entries * 8 + MiB - 1) // MiB * MiB
    rt = bytearray(64 * 1024)
    struct.pack_into("<4sIII", rt, 0, b"regi", 0, 2, 0)
    struct.pack_into("<16sQII", rt, 16, BAT_GUID, 3 * MiB, bat_len, 1)
    struct.pack_into("<16sQII", rt, 48, META_GUID, 2 * MiB, MiB, 1)
    struct.pack_into("<I", rt, 4, crc32c(rt))
    f[192 * 1024:256 * 1024] = rt
    f[256 * 1024:320 * 1024] = rt
    # Metadata.
    md = bytearray(MiB)
    items = [(FILE_PARAMS, struct.pack("<II", block, 2 if parent else 0), 4),
             (VDISK_SIZE, struct.pack("<Q", SIZE), 6),
             (LOGICAL_SECTOR, struct.pack("<I", SECTOR), 6),
             (PHYSICAL_SECTOR, struct.pack("<I", 4096), 6),
             (PAGE83, guid(str(uuid.uuid5(uuid.NAMESPACE_URL, "kokino-page83"))), 6)]
    if parent:
        kv = [("parent_linkage", "{%s}" % parent[1]), ("relative_path", ".\\" + parent[0])]
        loc = bytearray(20 + 12 * len(kv))
        struct.pack_into("<16sHH", loc, 0, VHDX_LOCATOR_TYPE, 0, len(kv))
        strings = b""
        for i, (k, v) in enumerate(kv):
            kb, vb = k.encode("utf-16-le"), v.encode("utf-16-le")
            ko = len(loc) + len(strings)
            strings += kb
            vo = len(loc) + len(strings)
            strings += vb
            struct.pack_into("<IIHH", loc, 20 + 12 * i, ko, vo, len(kb), len(vb))
        items.append((PARENT_LOCATOR, bytes(loc) + strings, 4))
    struct.pack_into("<8sHH", md, 0, b"metadata", 0, len(items))
    off = 64 * 1024
    for i, (g, payload, flags) in enumerate(items):
        struct.pack_into("<16sIII", md, 32 + 32 * i, g, off, len(payload), flags)
        md[off:off + len(payload)] = payload
        off += (len(payload) + 4095) // 4096 * 4096
    f[2 * MiB:3 * MiB] = md
    # Payload and BAT.
    bat = bytearray(bat_len)
    payload = bytearray()
    first = len(f) + bat_len - MiB if bat_len > MiB else len(f)
    first = 4 * MiB if bat_len <= MiB else 3 * MiB + bat_len
    bitmap = bytearray(MiB) if parent else None
    for i in range(nblocks):
        lo, hi = i * block, min(SIZE, (i + 1) * block)
        chunk = bytes(data[lo:hi]).ljust(block, b"\0")
        idx = i + i // chunk_ratio
        if only is not None:
            ranges = [(max(a, lo), min(b, hi)) for a, b in only if a < hi and b > lo]
            if not ranges:
                continue  # NOT_PRESENT (0): read from the parent
            state = 7  # PARTIALLY_PRESENT
            for a, b in ranges:
                for s in range(a // SECTOR, (b + SECTOR - 1) // SECTOR):
                    bitmap[(s // 8) % MiB] |= 1 << (s % 8)
        else:
            if not any(chunk):
                continue
            state = 6  # FULLY_PRESENT
        at = first + len(payload)
        payload += chunk
        struct.pack_into("<Q", bat, idx * 8, state | (at // MiB) << 20)
    if parent:
        at = first + len(payload)
        payload += bitmap
        struct.pack_into("<Q", bat, chunk_ratio * 8, 6 | (at // MiB) << 20)
    if bat_len > MiB:
        f += bytes(bat_len - MiB)
    f[3 * MiB:3 * MiB + bat_len] = bat
    return bytes(f) + bytes(payload), data_write


# ---------------------------------------------------------------- VMDK

GRAIN = 128  # sectors (64 KiB)
GTE = 512


def descriptor(create_type, extents, cid, parent_cid=0xFFFFFFFF, parent_hint=None):
    lines = ["# Disk DescriptorFile", "version=1", "CID=%08x" % cid, "parentCID=%08x" % parent_cid, 'createType="%s"' % create_type]
    if parent_hint:
        lines.append('parentFileNameHint="%s"' % parent_hint)
    lines += ["", "# Extent description"] + extents + ["", "# The Disk Data Base", "#DDB", 'ddb.virtualHWVersion = "4"', 'ddb.adapterType = "ide"', ""]
    return "\n".join(lines).encode()


def sparse_header(capacity, desc_off, desc_size, gd_off, overhead, flags=3, version=1, compress=0):
    h = bytearray(512)
    struct.pack_into("<4sIIQQQQIQQQB4sH", h, 0, b"KDMV", version, flags, capacity, GRAIN, desc_off, desc_size,
                     GTE, 0, gd_off, overhead, 0, b"\n \r\n", compress)
    return bytes(h)


def vmdk_sparse(data, desc=b"", only=None):
    """Hosted sparse extent (monolithicSparse when `desc` is given)."""
    cap = len(data) // SECTOR
    grains = (cap + GRAIN - 1) // GRAIN
    ngt = (grains + GTE - 1) // GTE
    desc_sec = 1
    desc_size = 20 if desc else 0
    gd_off = desc_sec + desc_size if desc else 1
    gt_off = gd_off + 1
    overhead = (gt_off + ngt * 4 + GRAIN - 1) // GRAIN * GRAIN
    gt = [0] * (ngt * GTE)
    body = b""
    for g in range(grains):
        chunk = data[g * GRAIN * SECTOR:(g + 1) * GRAIN * SECTOR].ljust(GRAIN * SECTOR, b"\0")
        lo, hi = g * GRAIN * SECTOR, (g + 1) * GRAIN * SECTOR
        if only is not None:
            if not any(a < hi and b > lo for a, b in only):
                continue
        elif not any(chunk):
            continue
        gt[g] = overhead + len(body) // SECTOR
        body += chunk
    head = bytearray(overhead * SECTOR)
    head[:512] = sparse_header(cap, desc_sec if desc else 0, desc_size, gd_off, overhead, flags=1)
    if desc:
        head[512:512 + len(desc)] = desc
    gd = b"".join(struct.pack("<I", gt_off + 4 * i) for i in range(ngt))
    head[gd_off * SECTOR:gd_off * SECTOR + len(gd)] = gd
    gtb = b"".join(struct.pack("<I", x) for x in gt)
    head[gt_off * SECTOR:gt_off * SECTOR + len(gtb)] = gtb
    return bytes(head) + body


def vmdk_stream(data, desc):
    cap = len(data) // SECTOR
    grains = (cap + GRAIN - 1) // GRAIN
    ngt = (grains + GTE - 1) // GTE
    marker = lambda val, size, ty: pad(struct.pack("<QII", val, size, ty))
    f = bytearray(sparse_header(cap, 1, 20, 0xFFFFFFFFFFFFFFFF, 128, flags=0x30001, version=3, compress=1))
    f += pad(desc).ljust(20 * SECTOR, b"\0")
    f = f.ljust(128 * SECTOR, b"\0")
    gt = [0] * (ngt * GTE)
    for g in range(grains):
        chunk = data[g * GRAIN * SECTOR:(g + 1) * GRAIN * SECTOR].ljust(GRAIN * SECTOR, b"\0")
        if not any(chunk):
            continue
        gt[g] = len(f) // SECTOR
        z = zlib.compress(chunk)
        f += pad(struct.pack("<QI", g * GRAIN, len(z)) + z)
    gt_secs = []
    for t in range(ngt):
        f += marker(4, 0, 1)  # grain table, 4 sectors
        gt_secs.append(len(f) // SECTOR)
        f += b"".join(struct.pack("<I", x) for x in gt[t * GTE:(t + 1) * GTE])
    f += marker(1, 0, 2)  # grain directory
    gd = len(f) // SECTOR
    f += pad(b"".join(struct.pack("<I", x) for x in gt_secs))
    f += marker(1, 0, 3)  # footer
    f += sparse_header(cap, 1, 20, gd, 128, flags=0x30001, version=3, compress=1)
    f += marker(0, 0, 0)  # end of stream
    return bytes(f)


def cowd(data, only):
    """VMFSSPARSE extent ("COWD", ESX 3 and later snapshot deltas): header
    in sectors 0-3, grain directory at sector 4, grain tables of 4096
    32-bit entries (absolute sector numbers, 0 = in the parent), 1-sector
    grains."""
    cap = len(data) // SECTOR
    gtes = 4096
    ngt = (cap + gtes - 1) // gtes
    gd_sec = 4
    gt_sec = gd_sec + (ngt * 4 + SECTOR - 1) // SECTOR
    gt_secs = (gtes * 4) // SECTOR
    first_grain = gt_sec + ngt * gt_secs
    gt = [0] * (ngt * gtes)
    body = b""
    for s in range(cap):
        lo, hi = s * SECTOR, (s + 1) * SECTOR
        if any(a < hi and b > lo for a, b in only):
            gt[s] = first_grain + len(body) // SECTOR
            body += data[lo:hi]
    head = bytearray(first_grain * SECTOR)
    # magic, version 1, flags 3, sectors, granularity 1, GD sector, GD entries, next free sector
    struct.pack_into("<4sIIIIIII", head, 0, b"COWD", 1, 3, cap, 1, gd_sec, ngt, first_grain + len(body) // SECTOR)
    for t in range(ngt):
        struct.pack_into("<I", head, gd_sec * SECTOR + 4 * t, gt_sec + t * gt_secs)
        for i in range(gtes):
            struct.pack_into("<I", head, (gt_sec + t * gt_secs) * SECTOR + 4 * i, gt[t * gtes + i])
    return bytes(head) + body


def sesparse(data, only, zero_grains):
    """SESPARSE extent (ESXi 6.5 and later): a 512-byte constant header,
    every offset and size in sectors; 4 KiB grains; grain tables of 4096
    64-bit entries (64 sectors); grain directory entries 0x1 << 60 | table
    index; grain table entries: state in the top 4 bits (0 parent, 1
    unmapped, 2 zero, 3 allocated) and the grain index split 12/48."""
    cap = len(data) // SECTOR
    grain = 8
    gtes = 4096
    grains = (cap + grain - 1) // grain
    ngt = (grains + gtes - 1) // gtes
    gd_off, gd_size = 4, 1
    gt_off, gt_size = gd_off + gd_size, ngt * 64
    grains_off = gt_off + gt_size
    gt = [0] * (ngt * gtes)
    body = b""
    for g in range(grains):
        lo, hi = g * grain * SECTOR, (g + 1) * grain * SECTOR
        if any(a < hi and b > lo for a, b in only):
            idx = len(body) // (grain * SECTOR)
            gt[g] = (3 << 60) | ((idx & 0xFFF) << 48) | (idx >> 12)
            body += data[lo:hi].ljust(grain * SECTOR, b"\0")
        elif g in zero_grains:
            gt[g] = 2 << 60
    head = bytearray(grains_off * SECTOR)
    fields = [0x00000000CAFEBABE, 0x0000000200000001, cap, grain, 64, 0, 0, 0, 0, 0,
              1, 1, 2, 1, 3, 1, gd_off, gd_size, gt_off, gt_size, 0, 0, 0, 0, grains_off, len(body) // SECTOR]
    struct.pack_into("<26Q", head, 0, *fields)
    struct.pack_into("<Q", head, SECTOR, 0x00000000CAFECAFE)  # volatile header
    for t in range(ngt):
        struct.pack_into("<Q", head, gd_off * SECTOR + 8 * t, (1 << 60) | t)
        for i in range(gtes):
            struct.pack_into("<Q", head, (gt_off + t * 64) * SECTOR + 8 * i, gt[t * gtes + i])
    return bytes(head) + body


def esx():
    cap = SIZE // SECTOR
    patch = [(PATCH_AT, PATCH_AT + len(PATCH))]
    out("vd-esx-vmfssparse.vmdk", descriptor("vmfsSparse", ['RW %d VMFSSPARSE "vd-esx-vmfssparse-delta.vmdk"' % cap], 0x66666666, 0x33333333, "vd-flat.vmdk"))
    out("vd-esx-vmfssparse-delta.vmdk", cowd(PATCHED, patch))
    # A 4 KiB grain that is all zeros in the base, marked "zero" in the snapshot.
    zero = next(g for g in range(SIZE // 4096) if not any(BASE[g * 4096:(g + 1) * 4096]) and g > 100)
    out("vd-esx-sesparse.vmdk", descriptor("seSparse", ['RW %d SESPARSE "vd-esx-sesparse-sesparse.vmdk"' % cap], 0x77777777, 0x33333333, "vd-flat.vmdk"))
    out("vd-esx-sesparse-sesparse.vmdk", sesparse(PATCHED, patch, {zero}))


def main():
    cap = SIZE // SECTOR
    patch = [(PATCH_AT, PATCH_AT + len(PATCH))]

    d, uid = vhd(BASE, 512 * 1024)
    out("vd-dynamic.vhd", d)
    out("vd-diff.vhd", vhd(PATCHED, 512 * 1024, parent=("vd-dynamic.vhd", uid), only=patch)[0])

    d, write_guid = vhdx(BASE)
    out("vd-dynamic.vhdx", d)
    out("vd-diff.vhdx", vhdx(PATCHED, parent=("vd-dynamic.vhdx", write_guid), only=patch)[0])

    out("vd-sparse.vmdk", vmdk_sparse(BASE, descriptor("monolithicSparse", ['RW %d SPARSE "vd-sparse.vmdk"' % cap], 0x11111111)))
    out("vd-stream.vmdk", vmdk_stream(BASE, descriptor("streamOptimized", ['RW %d SPARSE "vd-stream.vmdk"' % cap], 0x22222222)))
    out("vd-flat.vmdk", descriptor("monolithicFlat", ['RW %d FLAT "vd-flat-flat.vmdk" 0' % cap], 0x33333333))
    out("vd-flat-flat.vmdk", BASE)
    half = (cap // 2 + GRAIN - 1) // GRAIN * GRAIN
    out("vd-split.vmdk", descriptor("twoGbMaxExtentSparse", ['RW %d SPARSE "vd-split-s001.vmdk"' % half, 'RW %d SPARSE "vd-split-s002.vmdk"' % (cap - half)], 0x44444444))
    out("vd-split-s001.vmdk", vmdk_sparse(BASE[:half * SECTOR]))
    out("vd-split-s002.vmdk", vmdk_sparse(BASE[half * SECTOR:]))
    out("vd-snap.vmdk", vmdk_sparse(PATCHED, descriptor("monolithicSparse", ['RW %d SPARSE "vd-snap.vmdk"' % cap], 0x55555555, 0x11111111, "vd-sparse.vmdk"), only=patch))


if __name__ == "__main__":
    import sys
    esx() if sys.argv[1:] == ["esx"] else main()
