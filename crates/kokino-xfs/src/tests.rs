use super::*;
use kokino_core::time::filetime_to_iso;
use std::collections::HashMap;

const BS: usize = 4096;
const AGB: u64 = 1024;
const ISZ: usize = 512;
const T_MOD: i64 = 1_792_483_540; // 20-10-2026 08:05:40 UTC
const T_CR: i64 = 1_792_479_940; // 20-10-2026 07:05:40 UTC
const T_DEL: i64 = 1_792_490_000; // 20-10-2026 09:53:20 UTC

fn put16(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 2].copy_from_slice(&(v as u16).to_be_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 4].copy_from_slice(&(v as u32).to_be_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_be_bytes());
}
fn pack(off: u64, fsb: u64, n: u64) -> [u8; 16] {
    let mut r = [0u8; 16];
    put64(&mut r, 0, (off << 9) | (fsb >> 43));
    put64(&mut r, 8, ((fsb & ((1 << 43) - 1)) << 21) | n);
    r
}
/// A file-system block number: AG in the high bits.
fn fsb(ag: u64, b: u64) -> u64 {
    (ag << 10) | b
}

struct Img(Vec<u8>);

impl Img {
    fn blk(&mut self, ag: u64, b: u64) -> &mut [u8] {
        let at = ((ag * AGB + b) as usize) * BS;
        &mut self.0[at..at + BS]
    }
    /// Inode `n` (AG 0 chunk at block 8, AG 1 chunk at block 8).
    fn inode(&mut self, n: u64) -> &mut [u8] {
        let ag = n >> 13;
        let agino = n & ((1 << 13) - 1);
        let at = ((ag * AGB + (agino >> 3)) as usize) * BS + (agino as usize & 7) * ISZ;
        &mut self.0[at..at + ISZ]
    }
    #[allow(clippy::too_many_arguments)]
    fn mk_inode(&mut self, n: u64, mode: u64, format: u8, size: u64, nblocks: u64, nextents: u64, bigtime: bool, ctime: i64) {
        let i = self.inode(n);
        i.fill(0);
        i[0..2].copy_from_slice(b"IN");
        put16(i, 2, mode);
        i[4] = 3;
        i[5] = format;
        put32(i, 8, 1000);
        put32(i, 12, 1000);
        put32(i, 16, if mode == 0 { 0 } else { 1 });
        let ts = |i: &mut [u8], o: usize, s: i64, ns: u64| {
            if bigtime {
                put64(i, o, ((s + (1 << 31)) as u64) * 1_000_000_000 + ns);
            } else {
                put32(i, o, s as u64);
                put32(i, o + 4, ns);
            }
        };
        ts(i, 32, T_MOD + 60, 0);
        ts(i, 40, T_MOD, 123_456_789);
        ts(i, 48, ctime, 0);
        ts(i, 144, T_CR, 0);
        put64(i, 56, size);
        put64(i, 64, nblocks);
        put32(i, 76, nextents);
        i[83] = 2;
        put32(i, 92, 7);
        put32(i, 96, 0xFFFF_FFFF);
        put64(i, 120, if bigtime { 0x8 } else { 0 });
        put64(i, 152, n);
    }
    fn extents(&mut self, n: u64, recs: &[[u8; 16]]) {
        let i = self.inode(n);
        for (k, r) in recs.iter().enumerate() {
            i[176 + k * 16..176 + k * 16 + 16].copy_from_slice(r);
        }
    }
    fn data(&mut self, ag: u64, b: u64, d: &[u8]) {
        let at = ((ag * AGB + b) as usize) * BS;
        self.0[at..at + d.len()].copy_from_slice(d);
    }
}

/// A directory entry at `p`; returns its size.
fn dent(b: &mut [u8], p: usize, ino: u64, name: &str, ft: u8) -> usize {
    let size = (8 + 1 + name.len() + 1 + 2).next_multiple_of(8);
    put64(b, p, ino);
    b[p + 8] = name.len() as u8;
    b[p + 9..p + 9 + name.len()].copy_from_slice(name.as_bytes());
    b[p + 9 + name.len()] = ft;
    put16(b, p + size - 2, p as u64);
    size
}
/// Marks `p..p+len` free, as the kernel does: the first four bytes and the tag.
fn free(b: &mut [u8], p: usize, len: usize) {
    put16(b, p, 0xFFFF);
    put16(b, p + 2, len as u64);
    put16(b, p + len - 2, p as u64);
}

fn build() -> Vec<u8> {
    let mut m = Img(vec![0u8; 2 * AGB as usize * BS]);
    // Superblock.
    {
        let sb = m.blk(0, 0);
        sb[0..4].copy_from_slice(b"XFSB");
        put32(sb, 4, BS as u64);
        put64(sb, 8, 2 * AGB);
        sb[32..48].copy_from_slice(&[0x11; 16]);
        put64(sb, 56, 64);
        put32(sb, 84, AGB);
        put32(sb, 88, 2);
        put16(sb, 100, 0xB4B5);
        put16(sb, 102, 512);
        put16(sb, 104, ISZ as u64);
        put16(sb, 106, 8);
        sb[108..118].copy_from_slice(b"kokino-xfs");
        sb[120] = 12;
        sb[121] = 9;
        sb[122] = 9;
        sb[123] = 3;
        sb[124] = 10;
        put64(sb, 128, 128);
        put32(sb, 200, 0x18a);
        put32(sb, 216, 0x1 | 0x8);
        // Internal log: 4 blocks at AG 0 block 44.
        put64(sb, 48, fsb(0, 44));
        put32(sb, 96, 4);
    }
    // AGF, AGI, free-space and inode B+tree leaves for both AGs.
    let free_ag: [Vec<(u64, u64)>; 2] = [vec![(31, 2), (40, 2), (100, 924)], vec![(200, 824)]];
    for ag in 0..2u64 {
        let h = m.blk(ag, 0);
        let agf = &mut h[512..1024];
        agf[0..4].copy_from_slice(b"XAGF");
        put32(agf, 4, 1);
        put32(agf, 8, ag);
        put32(agf, 12, AGB);
        put32(agf, 16, 1);
        put32(agf, 20, 3);
        put32(agf, 28, 1);
        put32(agf, 32, 1);
        let agi = &mut h[1024..1536];
        agi[0..4].copy_from_slice(b"XAGI");
        put32(agi, 4, 1);
        put32(agi, 8, ag);
        put32(agi, 12, AGB);
        put32(agi, 16, 64);
        put32(agi, 20, 2);
        put32(agi, 24, 1);
        let b = m.blk(ag, 1);
        b[0..4].copy_from_slice(b"AB3B");
        put16(b, 6, free_ag[ag as usize].len() as u64);
        for (k, &(s, c)) in free_ag[ag as usize].iter().enumerate() {
            put32(b, 56 + k * 8, s);
            put32(b, 60 + k * 8, c);
        }
        let b = m.blk(ag, 2);
        b[0..4].copy_from_slice(b"IAB3");
        put16(b, 6, 1);
        put32(b, 56, 64);
        // AG 0: inodes 69, 70, 73, 74 freed, 75 and up never used. AG 1: one file.
        let used: u64 = if ag == 0 { 0b1_0001_1111 } else { 1 };
        put64(b, 64, !used);
        // Every inode of both chunks starts as never used.
        for k in 0..64 {
            let n = (ag << 13) | (64 + k);
            let i = m.inode(n);
            i[0..2].copy_from_slice(b"IN");
            i[4] = 3;
            i[5] = 2;
            put64(i, 152, n);
        }
    }

    // Root (64): a block folder.
    m.mk_inode(64, 0o040755, FMT_EXTENTS, BS as u64, 1, 1, true, T_MOD);
    m.extents(64, &[pack(0, fsb(0, 20), 1)]);
    {
        let b = m.blk(0, 20);
        b[0..4].copy_from_slice(b"XDB3");
        put64(b, 40, 64);
        let mut p = 64;
        p += dent(b, p, 64, ".", 2);
        p += dent(b, p, 64, "..", 2);
        p += dent(b, p, 65, "hello.txt", 1);
        p += dent(b, p, 66, "docs", 2);
        // Removed alone: the high half of its inode number is overwritten.
        let s = dent(b, p, 69, "secret.txt", 1);
        free(b, p, s);
        p += s;
        // Removed one after the other: one free region over both.
        let a = dent(b, p, 76, "x.tmp", 1);
        let g = dent(b, p + a, 70, "gone2.txt", 1);
        free(b, p, a + g);
        p += a + g;
        p += dent(b, p, 67, "big.bin", 1);
        p += dent(b, p, 68, "link", 7);
        p += dent(b, p, 8256, "far.txt", 1);
        let count = 9;
        let end = BS - 8 - count * 8;
        // Removed: its inode is cleared, only the log still has it.
        dent(b, p, 75, "logged.txt", 1);
        free(b, p, end - p);
        put32(b, BS - 8, count as u64);
    }
    // hello.txt (65), bigtime with nanoseconds.
    m.mk_inode(65, 0o100644, FMT_EXTENTS, 37, 1, 1, true, T_MOD);
    m.extents(65, &[pack(0, fsb(0, 30), 1)]);
    m.data(0, 30, b"Hello from Kokino's XFS test volume.\n");
    // docs (66): short form, one entry, a removed one left past the end.
    m.mk_inode(66, 0o040755, FMT_LOCAL, 19, 0, 0, false, T_MOD);
    {
        let i = m.inode(66);
        let f = &mut i[176..];
        f[0] = 1;
        put32(f, 2, 64);
        f[6] = 5;
        put16(f, 7, 0x60);
        f[9..14].copy_from_slice(b"a.txt");
        f[14] = 1;
        put32(f, 15, 72);
        f[19] = 7;
        put16(f, 20, 0x70);
        f[22..29].copy_from_slice(b"old.txt");
        f[29] = 1;
        put32(f, 30, 73);
    }
    // big.bin (67): extent B+tree, root in the inode, one leaf; the second
    // extent in AG 1.
    let big: Vec<u8> = (0..3 * BS as u32 - 100).map(|i| (i * 37 + 11) as u8).collect();
    m.mk_inode(67, 0o100600, FMT_BTREE, big.len() as u64, 4, 2, false, T_MOD);
    {
        let i = m.inode(67);
        put16(i, 176, 1);
        put16(i, 178, 1);
        put64(i, 176 + 4 + 20 * 8, fsb(0, 50));
        let b = m.blk(0, 50);
        b[0..4].copy_from_slice(b"BMA3");
        put16(b, 6, 2);
        b[72..88].copy_from_slice(&pack(0, fsb(0, 60), 2));
        b[88..104].copy_from_slice(&pack(2, fsb(1, 100), 1));
    }
    m.data(0, 60, &big[..2 * BS]);
    m.data(1, 100, &big[2 * BS..]);
    // link (68): target in the inode.
    m.mk_inode(68, 0o120777, FMT_LOCAL, 10, 0, 0, false, T_MOD);
    m.inode(68)[176..186].copy_from_slice(b"docs/a.txt");
    // Freed inodes: mode, size and count cleared, extent records kept.
    for (n, b, text) in [(69u64, 31u64, &b"SECRET: wire 1,200 EUR to LAB-0001 (test data)\n"[..]), (70, 32, b"second deleted file\n"), (73, 40, b"old plan, removed from docs\n"), (74, 41, b"orphaned inode, name long gone\n")] {
        m.mk_inode(n, 0, FMT_EXTENTS, 0, 0, 0, false, T_DEL);
        m.extents(n, &[pack(0, fsb(0, b), 1)]);
        m.data(0, b, text);
    }
    // a.txt (72), plain (not bigtime) times.
    m.mk_inode(72, 0o100640, FMT_EXTENTS, 6, 1, 1, false, T_MOD);
    m.extents(72, &[pack(0, fsb(0, 33), 1)]);
    m.data(0, 33, b"a.txt\n");
    // far.txt (8256): inode and content in AG 1.
    m.mk_inode(8256, 0o100644, FMT_EXTENTS, 12, 1, 1, false, T_MOD);
    m.extents(8256, &[pack(0, fsb(1, 20), 1)]);
    m.data(1, 20, b"far away AG\n");
    // The cleared inode 75 and one log record holding an older copy of it,
    // as a little-endian machine writes it.
    {
        let i = m.inode(75);
        i[2..4].fill(0);
        let text = b"logged, then deleted: from the log\n";
        m.data(0, 42, text);
        let log = log_record(75, text.len() as u64, fsb(0, 42));
        let at = 44 * BS;
        m.0[at..at + log.len()].copy_from_slice(&log);
    }
    m.0
}

/// One log record: a transaction with an inode item (format, core in
/// little-endian, one extent), sector-stamped as the kernel writes it.
fn log_record(ino: u64, size: u64, block: u64) -> Vec<u8> {
    let mut ops: Vec<u8> = vec![];
    let mut nops = 0;
    let mut op = |ops: &mut Vec<u8>, flags: u8, body: &[u8]| {
        ops.extend_from_slice(&7u32.to_be_bytes());
        ops.extend_from_slice(&(body.len() as u32).to_be_bytes());
        ops.extend_from_slice(&[0x69, flags, 0, 0]);
        ops.extend_from_slice(body);
        nops += 1;
    };
    op(&mut ops, 0x01, &[]);
    let mut th = vec![];
    for v in [0x5452_414Eu32, 1, 7, 1] {
        th.extend_from_slice(&v.to_le_bytes());
    }
    op(&mut ops, 0, &th);
    let mut ilf = vec![0u8; 56];
    ilf[0..2].copy_from_slice(&0x123bu16.to_le_bytes());
    ilf[2..4].copy_from_slice(&3u16.to_le_bytes());
    ilf[4..8].copy_from_slice(&5u32.to_le_bytes());
    ilf[10..12].copy_from_slice(&16u16.to_le_bytes());
    ilf[16..24].copy_from_slice(&ino.to_le_bytes());
    op(&mut ops, 0, &ilf);
    let mut d = vec![0u8; 176];
    d[0..2].copy_from_slice(&0x494eu16.to_le_bytes());
    d[2..4].copy_from_slice(&0o100644u16.to_le_bytes());
    d[4] = 3;
    d[5] = 2;
    d[8..12].copy_from_slice(&1000u32.to_le_bytes());
    d[12..16].copy_from_slice(&1000u32.to_le_bytes());
    d[16..20].copy_from_slice(&1u32.to_le_bytes());
    for o in [32, 40, 48, 144] {
        d[o..o + 4].copy_from_slice(&(T_MOD as u32).to_le_bytes());
    }
    d[56..64].copy_from_slice(&size.to_le_bytes());
    d[64..72].copy_from_slice(&1u64.to_le_bytes());
    d[76..80].copy_from_slice(&1u32.to_le_bytes());
    d[83] = 2;
    d[152..160].copy_from_slice(&ino.to_le_bytes());
    op(&mut ops, 0, &d);
    op(&mut ops, 0, &pack(0, block, 1));
    op(&mut ops, 0x02, &[]);
    // Header sector, then the data with each sector's first word stamped
    // with the cycle (1) and kept in the header.
    let sectors = ops.len().div_ceil(512);
    ops.resize(sectors * 512, 0);
    let mut h = vec![0u8; 512];
    put32(&mut h, 0, 0xFEED_BABE);
    put32(&mut h, 4, 1);
    put32(&mut h, 8, 2);
    put32(&mut h, 12, ops.len() as u64);
    put64(&mut h, 16, 1 << 32);
    put32(&mut h, 40, nops);
    for k in 0..sectors {
        h[44 + 4 * k..48 + 4 * k].copy_from_slice(&ops[k * 512..k * 512 + 4]);
        put32(&mut ops, k * 512, 1);
    }
    put32(&mut h, 300, 1);
    put32(&mut h, 320, 32768);
    [h, ops].concat()
}

fn check_synth(img: Vec<u8>) {
    let size = img.len() as u64;
    let mut f = std::io::Cursor::new(img);
    let v = open(&mut f, size).unwrap();
    assert_eq!((v.version, v.label.as_str(), v.agcount), (5, "kokino-xfs", 2));
    let s = scan(&v, &mut f, |_, _| true).unwrap();
    let paths: Vec<&str> = s.entries.iter().map(|e| e.path.as_str()).collect();
    let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} not in {:?}", p, paths));
    let read = |f: &mut std::io::Cursor<Vec<u8>>, e: &FsEntry| v.read(f, e, 0, e.size as usize).unwrap();

    let hello = by("/hello.txt");
    assert_eq!(read(&mut f, hello), b"Hello from Kokino's XFS test volume.\n");
    let t = hello.si.unwrap();
    assert_eq!(filetime_to_iso(t.modified), "2026-10-20T08:05:40.1234567Z");
    assert_eq!(filetime_to_iso(t.created), "2026-10-20T07:05:40.0000000Z");
    let u = hello.unix.as_ref().unwrap();
    assert_eq!((u.inode, u.uid, u.mode_string().as_str()), (65, 1000, "-rw-r--r--"));
    assert_eq!(filetime_to_iso(by("/docs/a.txt").si.unwrap().modified), "2026-10-20T08:05:40.1234567Z");
    assert_eq!(read(&mut f, by("/docs/a.txt")), b"a.txt\n");
    let big = by("/big.bin");
    let want: Vec<u8> = (0..3 * BS as u32 - 100).map(|i| (i * 37 + 11) as u8).collect();
    assert_eq!(read(&mut f, big), want);
    assert_eq!(v.read(&mut f, big, 8000, 1000).unwrap(), want[8000..9000].to_vec());
    assert_eq!(v.extents(&mut f, big).unwrap().len(), 2);
    assert_eq!(by("/link").unix.as_ref().unwrap().link_target.as_deref(), Some("docs/a.txt"));
    assert_eq!(read(&mut f, by("/far.txt")), b"far away AG\n");
    assert_eq!(by("/far.txt").unix.as_ref().unwrap().inode, 8256);

    // Removed at the start of a free region: low half of the number.
    let secret = by("/secret.txt");
    assert!(secret.deleted && !secret.orphan);
    let d = read(&mut f, secret);
    assert_eq!(d.len(), BS);
    assert!(d.starts_with(b"SECRET: wire 1,200 EUR to LAB-0001 (test data)\n"));
    assert!(secret.error.as_deref().unwrap().starts_with("size not kept"), "{:?}", secret.error);
    assert_eq!(secret.unix.as_ref().unwrap().deleted_time, unix_ft(T_DEL, 0));
    // Inside a free region: the whole number.
    assert!(read(&mut f, by("/gone2.txt")).starts_with(b"second deleted file\n"));
    // A name whose inode was never used: listed, no content.
    let x = by("/x.tmp");
    assert!(x.deleted && x.size == 0 && x.unix.as_ref().is_none_or(|u| u.journal_seq.is_none()));
    // Short form: the removed entry left past the end.
    let old = by("/docs/old.txt");
    assert!(old.deleted);
    assert!(read(&mut f, old).starts_with(b"old plan, removed from docs\n"));
    // A freed inode no name leads to.
    let orphan = by("$OrphanFiles/inode-74");
    assert!(orphan.deleted && orphan.orphan);
    assert!(read(&mut f, orphan).starts_with(b"orphaned inode, name long gone\n"));
    assert_eq!(s.entries.iter().filter(|e| e.orphan).count(), 1, "{:?}", paths);
    assert_eq!(s.entries.iter().filter(|e| !e.deleted && !e.is_dir).count(), 5, "{:?}", paths);
    assert!(s.notes.iter().any(|n| n.starts_with("4 deleted file(s) were recovered")), "{:?}", s.notes);
    // Cleared inode, older copy in the log: content with its real size.
    let logged = by("/logged.txt");
    assert!(logged.deleted && logged.unix.as_ref().unwrap().journal_seq.is_some(), "{:?}", logged);
    assert_eq!(read(&mut f, logged), b"logged, then deleted: from the log\n");
    assert!(s.notes.iter().any(|n| n.starts_with("1 deleted file(s) were recovered through older copies")), "{:?}", s.notes);

    // Free space from both AGs' trees; the deleted files' blocks are in it.
    let free = v.free_runs(&mut f);
    assert!(free.iter().any(|r| r.0 == 31 * BS as u64 && r.1 == 2 * BS as u64), "{:?}", free);
    assert!(free.iter().any(|r| r.0 == (AGB + 200) * BS as u64));
    assert!(!v.allocated(&mut f, 31) && v.allocated(&mut f, 30));
}

#[test]
fn synthetic_volume() {
    check_synth(build());
}

#[test]
fn rejects_garbage() {
    let mut c = std::io::Cursor::new(vec![0u8; 8192]);
    assert!(open(&mut c, 8192).is_err());
    let mut img = build();
    img[120] = 20;
    assert!(open(&mut std::io::Cursor::new(img), 8192).is_err());
    // A damaged tree or folder must not panic.
    let mut img = build();
    for o in [20 * BS + 64, 50 * BS + 6, 2 * BS + 6, BS + 6] {
        img[o..o + 2].copy_from_slice(&[0xFF, 0xF0]);
    }
    let size = img.len() as u64;
    let mut c = std::io::Cursor::new(img);
    let v = open(&mut c, size).unwrap();
    let _ = scan(&v, &mut c, |_, _| true);
}

/// dfvfs's test images (made with mkfs.xfs on Linux), when downloaded to
/// target/validation/xfs.
fn dfvfs(name: &str) -> Option<std::fs::File> {
    std::fs::File::open(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/validation/xfs").join(name)).ok()
}

#[test]
fn dfvfs_images() {
    for (name, dir, file, other, link, bigtime) in [("xfs.raw", 11075, 11076, 11078, 11079, false), ("xfs-bigtime.raw", 16131, 16132, 16134, 16135, true)] {
        let Some(mut f) = dfvfs(name) else { return };
        let size = f.metadata().unwrap().len();
        let v = open(&mut f, size).unwrap();
        assert_eq!((v.version, v.label.as_str()), (5, "xfs_test"));
        let s = scan(&v, &mut f, |_, _| true).unwrap();
        let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} not in {:?}", p, s.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        assert_eq!(by("/a_directory").unix.as_ref().unwrap().inode, dir);
        assert!(by("/a_directory").is_dir);
        let a = by("/a_directory/a_file");
        assert_eq!(a.unix.as_ref().unwrap().inode, file);
        assert_eq!(by("/a_directory/another_file").unix.as_ref().unwrap().inode, other);
        let l = by("/a_link");
        assert_eq!(l.unix.as_ref().unwrap().inode, link);
        assert_eq!(l.unix.as_ref().unwrap().link_target.as_deref(), Some("a_directory/another_file"));
        let d = v.read(&mut f, a, 0, a.size as usize).unwrap();
        assert_eq!(d, b"This is a text file.\n\nWe should be able to parse it.\n");
        assert_eq!(v.read(&mut f, by("/a_directory/another_file"), 0, 100).unwrap(), b"This is another file.\n");
        assert!(s.entries.iter().any(|e| e.path == "/passwords.txt"));
        assert!(s.entries.iter().all(|e| !e.deleted), "{:?}", s.entries.iter().filter(|e| e.deleted).map(|e| &e.path).collect::<Vec<_>>());
        assert!(!v.free_runs(&mut f).is_empty());
        assert_eq!(v.features.contains(&"bigtime (dates to 2486)"), bigtime);
    }
}

/// Writes the fuzzing seed: the synthetic volume's first 64 blocks (every
/// structure but the second AG). Run with --ignored after changing build().
#[test]
#[ignore]
fn write_fuzz_seed() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kokino-fuzz/seeds/xfs");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("synthetic-v5.xfs"), &build()[..64 * BS]).unwrap();
    // The whole volume, for trying it in the GUI, where validation data lives.
    let val = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/validation/xfs");
    if val.is_dir() {
        std::fs::write(val.join("synthetic-v5.xfs"), build()).unwrap();
    }
}

/// Images made by the kernel with scripts/make-xfs-samples.sh, compared
/// with the kernel's own listing of every file (inode, mode, size, times,
/// SHA-256, link target), and the deleted files with the listing taken
/// before they were deleted. Runs when the images are in
/// target/validation/xfs-samples.
#[test]
fn kernel_made_images() {
    use sha2::{Digest, Sha256};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/validation/xfs-samples");
    if !dir.is_dir() {
        return;
    }
    let sha = |d: &[u8]| -> String { Sha256::digest(d).iter().map(|b| format!("{:02x}", b)).collect() };
    // path -> (inode, mode, size, [mtime, ctime, atime, birth] as FILETIME, sha, link)
    type Row = (u64, u32, u64, [u64; 4], String, Option<String>);
    let parse = |p: &std::path::Path| -> HashMap<String, Row> {
        let mut m = HashMap::new();
        for line in std::fs::read_to_string(p).unwrap().lines() {
            let (main, link) = match line.split_once(" -> ") {
                Some((a, b)) => (a, Some(b.to_string())),
                None => (line, None),
            };
            let f: Vec<&str> = main.rsplitn(12, ' ').collect();
            let ft = |s: &str| {
                let (a, b) = s.split_once('.').unwrap();
                unix_ft(a.parse().unwrap(), b.parse().unwrap())
            };
            let path = f[11].trim_start_matches('.').to_string();
            m.insert(path, (f[10].parse().unwrap(), u32::from_str_radix(f[9], 16).unwrap(), f[5].parse().unwrap(), [ft(f[4]), ft(f[3]), ft(f[2]), ft(f[1])], f[0].to_string(), link));
        }
        m
    };
    let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".img")).collect();
    names.sort();
    let mut problems = vec![];
    for name in names {
        let base = name.trim_end_matches(".img");
        let after = parse(&dir.join(format!("{}.after.txt", base)));
        let before = parse(&dir.join(format!("{}.before.txt", base)));
        let mut f = std::fs::File::open(dir.join(&name)).unwrap();
        let size = f.metadata().unwrap().len();
        let v = open(&mut f, size).unwrap();
        let s = scan(&v, &mut f, |_, _| true).unwrap();
        let live: HashMap<&str, &FsEntry> = s.entries.iter().filter(|e| !e.deleted).map(|e| (e.path.as_str(), e)).collect();
        let (mut ok, mut bad) = (0, 0);
        for (path, (ino, mode, sz, times, want_sha, link)) in &after {
            let Some(e) = live.get(path.as_str()) else {
                problems.push(format!("{}: {} missing", base, path));
                bad += 1;
                continue;
            };
            let u = e.unix.as_ref().unwrap();
            let t = e.si.unwrap();
            let mut why = vec![];
            if u.inode != *ino {
                why.push(format!("inode {} not {}", u.inode, ino));
            }
            if u.mode != *mode {
                why.push(format!("mode {:o} not {:o}", u.mode, mode));
            }
            if [t.modified, t.mft_modified, t.accessed, t.created] != *times {
                why.push(format!("times {:?} not {:?}", [t.modified, t.mft_modified, t.accessed, t.created], times));
            }
            if mode & 0o170000 == 0o100000 {
                if e.size != *sz {
                    why.push(format!("size {} not {}", e.size, sz));
                }
                let d = v.read(&mut f, e, 0, e.size as usize).unwrap();
                if sha(&d) != *want_sha {
                    why.push("content differs".into());
                }
            }
            if link.is_some() && u.link_target != *link {
                why.push(format!("link {:?} not {:?}", u.link_target, link));
            }
            if why.is_empty() {
                ok += 1;
            } else {
                bad += 1;
                problems.push(format!("{}: {}: {}", base, path, why.join("; ")));
            }
        }
        let extra: Vec<_> = live.keys().filter(|p| **p != "/" && !after.contains_key(**p) && !p.starts_with("$Orphan")).collect();
        for p in &extra {
            problems.push(format!("{}: {} listed but not in the image", base, p));
        }
        // Deleted: name found, and for files, content as it was.
        let mut report = vec![];
        let mut gone: Vec<_> = before.keys().filter(|p| !after.contains_key(*p)).collect();
        gone.sort();
        for p in gone {
            let (_, mode, sz, _, want_sha, _) = &before[p];
            let e = s.entries.iter().find(|e| e.deleted && &e.path == p);
            let state = match e {
                None => "name not found".to_string(),
                Some(_) if mode & 0o170000 != 0o100000 => "folder found".to_string(),
                Some(e) => {
                    let d = v.read(&mut f, e, 0, (*sz as usize).min(e.size as usize)).unwrap();
                    if d.len() as u64 == *sz && sha(&d) == *want_sha {
                        "content matches".to_string()
                    } else {
                        format!("content differs ({} of {} bytes read, {:?})", d.len(), sz, e.error)
                    }
                }
            };
            if state != "content matches" && state != "folder found" {
                problems.push(format!("{}: deleted {}: {}", base, p, state));
            }
            report.push(format!("    {} -> {}", p, state));
        }
        let orphans: Vec<_> = s.entries.iter().filter(|e| e.orphan).map(|e| e.path.as_str()).collect();
        eprintln!("{}: {} of {} live entries match, {} wrong, {} extra; orphans {:?}\n{}\n  notes: {:?}", base, ok, after.len(), bad, extra.len(), orphans, report.join("\n"), s.notes);
    }
    assert!(problems.is_empty(), "{}", problems.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}

