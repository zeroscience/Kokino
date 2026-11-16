//! $LogFile, the NTFS transaction log: the restart area and every log
//! record still in the file, with the NTFS operations they carry (redo: the
//! change, undo: what was there before).
//!
//! Layout (Microsoft's NTFS log file service as documented by libfsntfs and
//! the Linux ntfs-3g sources): two restart pages ("RSTR") give the log page
//! size and how a log sequence number (LSN) maps to a file offset; record
//! pages ("RCRD", with update sequence fixups) hold log records of a 0x30
//! byte header and client data, a record running on into the next page.
//! Every record's LSN names the place it was written, so a record is taken
//! only where its LSN says it is: old copies in the spare (ping-pong) pages
//! and leftovers of earlier rounds through the log fall out by themselves.
//!
//! The client data is an NTFS log record: redo and undo operation, where
//! their data is, the target (attribute, VCN, offset in the MFT record or
//! index buffer) and the data itself.

/// One NTFS operation in the log.
#[derive(Debug, Clone, PartialEq)]
pub struct LogRecord {
    pub lsn: u64,
    pub prev_lsn: u64,
    pub undo_next_lsn: u64,
    pub transaction: u32,
    /// 1: a client record (an NTFS operation), 2: a client restart.
    pub kind: u32,
    pub redo_op: u16,
    pub undo_op: u16,
    pub target_attribute: u16,
    pub record_offset: u16,
    pub attribute_offset: u16,
    /// In 512-byte units inside the cluster.
    pub cluster_block_offset: u16,
    pub target_vcn: u64,
    pub lcns: Vec<u64>,
    pub redo: Vec<u8>,
    pub undo: Vec<u8>,
}

impl LogRecord {
    /// The MFT record an operation on a file record segment changes.
    pub fn mft_record(&self, cluster_size: u64, record_size: u64) -> Option<u64> {
        if !op_targets_mft(self.redo_op) && !op_targets_mft(self.undo_op) || record_size == 0 {
            return None;
        }
        Some(self.target_vcn.checked_mul(cluster_size)?.checked_add(self.cluster_block_offset as u64 * 512)? / record_size)
    }
}

/// Operations whose target is a file record segment (an MFT record).
pub fn op_targets_mft(op: u16) -> bool {
    matches!(op, 0x02..=0x07 | 0x09 | 0x0B | 0x0C | 0x0D | 0x11 | 0x13 | 0x21)
}

/// The operation's name, as the NTFS sources call it.
pub fn op_name(op: u16) -> &'static str {
    match op {
        0x00 => "Noop",
        0x01 => "CompensationLogRecord",
        0x02 => "InitializeFileRecordSegment",
        0x03 => "DeallocateFileRecordSegment",
        0x04 => "WriteEndOfFileRecordSegment",
        0x05 => "CreateAttribute",
        0x06 => "DeleteAttribute",
        0x07 => "UpdateResidentValue",
        0x08 => "UpdateNonresidentValue",
        0x09 => "UpdateMappingPairs",
        0x0A => "DeleteDirtyClusters",
        0x0B => "SetNewAttributeSizes",
        0x0C => "AddIndexEntryRoot",
        0x0D => "DeleteIndexEntryRoot",
        0x0E => "AddIndexEntryAllocation",
        0x0F => "DeleteIndexEntryAllocation",
        0x10 => "WriteEndOfIndexBuffer",
        0x11 => "SetIndexEntryVcnRoot",
        0x12 => "SetIndexEntryVcnAllocation",
        0x13 => "UpdateFileNameRoot",
        0x14 => "UpdateFileNameAllocation",
        0x15 => "SetBitsInNonresidentBitMap",
        0x16 => "ClearBitsInNonresidentBitMap",
        0x17 => "HotFix",
        0x18 => "EndTopLevelAction",
        0x19 => "PrepareTransaction",
        0x1A => "CommitTransaction",
        0x1B => "ForgetTransaction",
        0x1C => "OpenNonresidentAttribute",
        0x1D => "OpenAttributeTableDump",
        0x1E => "AttributeNamesDump",
        0x1F => "DirtyPageTableDump",
        0x20 => "TransactionTableDump",
        0x21 => "UpdateRecordDataRoot",
        0x22 => "UpdateRecordDataAllocation",
        0x25 => "UpdateRelativeDataInIndex",
        0x26 => "UpdateRelativeDataInIndex2",
        0x27 => "ZeroEndOfFileRecord",
        _ => "Unknown",
    }
}

/// What the restart area says, and the records found.
#[derive(Debug, Clone, Default)]
pub struct Log {
    pub version: (i16, i16),
    pub page_size: u64,
    pub file_size: u64,
    pub seq_bits: u32,
    /// The LSN of the last checkpoint Windows wrote.
    pub current_lsn: u64,
    /// The volume was not closed cleanly: the restart area is not marked
    /// clean, so the newest changes may be only in the log.
    pub dirty: bool,
    /// Records in LSN order.
    pub records: Vec<LogRecord>,
    /// Record pages read and how many were damaged (fixups did not match).
    pub pages: u64,
    pub damaged_pages: u64,
}

const MAX_RECORDS: usize = 2_000_000;
const MAX_CLIENT_DATA: u64 = 1 << 20;

fn u16_at(d: &[u8], o: usize) -> u16 {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0)
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}

/// Undoes the update sequence fixups of one page (or MFT record) in place;
/// false when a sector's last two bytes do not match the sequence number
/// (a torn write).
pub fn fixup(page: &mut [u8]) -> bool {
    let (ofs, count) = (u16_at(page, 4) as usize, u16_at(page, 6) as usize);
    if count < 2 || ofs + count * 2 > page.len() || (count - 1) * 512 > page.len() {
        return false;
    }
    let usn = [page[ofs], page[ofs + 1]];
    for i in 1..count {
        let end = i * 512;
        if page[end - 2..end] != usn {
            return false;
        }
        let (a, b) = (page[ofs + i * 2], page[ofs + i * 2 + 1]);
        page[end - 2] = a;
        page[end - 1] = b;
    }
    true
}

/// Reads $LogFile's bytes (the whole file).
pub fn parse(data: &[u8]) -> Option<Log> {
    // The newer of the two restart pages.
    let mut best: Option<(u64, Vec<u8>, usize)> = None;
    for at in [0usize, 4096] {
        let Some(p) = data.get(at..at + 4096) else { continue };
        if &p[..4] != b"RSTR" {
            continue;
        }
        let page_size = u32_at(p, 0x10) as usize;
        let Some(pg) = data.get(at..at + page_size.clamp(512, 65_536)) else { continue };
        let mut pg = pg.to_vec();
        if !fixup(&mut pg) {
            continue;
        }
        let ra = u16_at(&pg, 0x18) as usize;
        let lsn = u64_at(&pg, ra);
        if best.as_ref().is_none_or(|b| lsn > b.0) {
            best = Some((lsn, pg, ra));
        }
    }
    let (current_lsn, rp, ra) = best?;
    let log_page = u32_at(&rp, 0x14) as u64;
    if !(512..=65_536).contains(&log_page) || !log_page.is_power_of_two() {
        return None;
    }
    let version = (u16_at(&rp, 0x1C) as i16, u16_at(&rp, 0x1A) as i16);
    let seq_bits = u32_at(&rp, ra + 0x10);
    let flags = u16_at(&rp, ra + 0x0E);
    let file_size = u64_at(&rp, ra + 0x18).min(data.len() as u64);
    let data_off = match u16_at(&rp, ra + 0x26) as u64 {
        0 => 0x40,
        x => x,
    };
    if !(3..=60).contains(&seq_bits) || data_off >= log_page {
        return None;
    }
    let mut log = Log { version, page_size: log_page, file_size, seq_bits, current_lsn, dirty: flags & 2 == 0, ..Default::default() };
    let lsn_off = |lsn: u64| (lsn << seq_bits) >> (seq_bits - 3).min(63);
    // Every record page with its fixups undone; None when damaged.
    let npages = (file_size / log_page) as usize;
    let mut pages: Vec<Option<Vec<u8>>> = vec![None; npages];
    for (i, slot) in pages.iter_mut().enumerate().skip(2) {
        let at = i * log_page as usize;
        let Some(p) = data.get(at..at + log_page as usize) else { break };
        if &p[..4] != b"RCRD" {
            continue;
        }
        log.pages += 1;
        let mut p = p.to_vec();
        if fixup(&mut p) {
            *slot = Some(p);
        } else {
            log.damaged_pages += 1;
        }
    }
    let area = (log_page - data_off) as usize;
    // Bytes of the log from file offset `at`, across page data areas.
    let take = |at: u64, n: usize| -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        let (mut page, mut within) = ((at / log_page) as usize, (at % log_page) as usize);
        if within < data_off as usize {
            return None;
        }
        while out.len() < n {
            let p = pages.get(page)?.as_ref()?;
            let k = (n - out.len()).min(log_page as usize - within);
            out.extend_from_slice(&p[within..within + k]);
            page += 1;
            within = data_off as usize;
            if out.len() < n && page >= npages {
                return None;
            }
        }
        Some(out)
    };
    let mut seen = std::collections::HashSet::new();
    for (i, p) in pages.iter().enumerate() {
        let Some(p) = p else { continue };
        let base = (i as u64) * log_page;
        let mut o = data_off as usize;
        while o + 0x30 <= log_page as usize && log.records.len() < MAX_RECORDS {
            let lsn = u64_at(p, o);
            let ok = lsn != 0 && lsn_off(lsn) == base + o as u64 && matches!(u32_at(p, o + 0x20), 1 | 2) && (u32_at(p, o + 0x18) as u64) <= MAX_CLIENT_DATA;
            if !ok {
                o += 8;
                continue;
            }
            let len = u32_at(p, o + 0x18) as usize;
            let Some(rec) = take(base + o as u64, 0x30 + len) else {
                o += 8;
                continue;
            };
            if seen.insert(lsn) {
                if let Some(r) = decode(&rec) {
                    log.records.push(r);
                }
            }
            // The next record starts 8-aligned after this one (on this page,
            // or the walk finds it on the next).
            let used = (0x30 + len).div_ceil(8) * 8;
            if o + used >= log_page as usize {
                break;
            }
            o += used;
        }
        let _ = area;
    }
    log.records.sort_by_key(|r| r.lsn);
    Some(log)
}

fn decode(rec: &[u8]) -> Option<LogRecord> {
    let kind = u32_at(rec, 0x20);
    let mut r = LogRecord {
        lsn: u64_at(rec, 0),
        prev_lsn: u64_at(rec, 0x08),
        undo_next_lsn: u64_at(rec, 0x10),
        transaction: u32_at(rec, 0x24),
        kind,
        redo_op: 0,
        undo_op: 0,
        target_attribute: 0,
        record_offset: 0,
        attribute_offset: 0,
        cluster_block_offset: 0,
        target_vcn: 0,
        lcns: vec![],
        redo: vec![],
        undo: vec![],
    };
    if kind != 1 {
        return Some(r);
    }
    let c = rec.get(0x30..)?;
    if c.len() < 0x20 {
        return Some(r);
    }
    r.redo_op = u16_at(c, 0);
    r.undo_op = u16_at(c, 2);
    let (ro, rl, uo, ul) = (u16_at(c, 4) as usize, u16_at(c, 6) as usize, u16_at(c, 8) as usize, u16_at(c, 0x0A) as usize);
    r.target_attribute = u16_at(c, 0x0C);
    let nlcn = u16_at(c, 0x0E) as usize;
    r.record_offset = u16_at(c, 0x10);
    r.attribute_offset = u16_at(c, 0x12);
    r.cluster_block_offset = u16_at(c, 0x14);
    r.target_vcn = u64_at(c, 0x18);
    r.lcns = (0..nlcn.min(256)).filter_map(|i| c.get(0x20 + i * 8..0x28 + i * 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))).collect();
    r.redo = c.get(ro..ro + rl).map(|x| x.to_vec()).unwrap_or_default();
    r.undo = c.get(uo..uo + ul).map(|x| x.to_vec()).unwrap_or_default();
    Some(r)
}

/// A file name from an index entry ($I30): the file's MFT reference, its
/// folder's, the name and the four times the entry carries.
#[derive(Debug, Clone, PartialEq)]
pub struct EntryName {
    pub file: (u64, u16),
    pub parent: (u64, u16),
    pub name: String,
    /// created, modified, MFT modified, accessed (FILETIME).
    pub times: [u64; 4],
    pub size: u64,
    pub dir: bool,
    /// 0 POSIX, 1 Win32, 2 DOS (8.3), 3 Win32 and DOS.
    pub namespace: u8,
}

fn mft_ref(v: u64) -> (u64, u16) {
    (v & 0x0000_FFFF_FFFF_FFFF, (v >> 48) as u16)
}

/// The $FILE_NAME of an index entry (as AddIndexEntry and DeleteIndexEntry
/// carry it).
pub fn index_entry_name(d: &[u8]) -> Option<EntryName> {
    let (len, key) = (u16_at(d, 8) as usize, u16_at(d, 10) as usize);
    if len < 0x10 + 0x42 || key < 0x42 || d.len() < 0x10 + 0x42 {
        return None;
    }
    let f = &d[0x10..];
    let n = *f.get(0x40)? as usize;
    let raw = f.get(0x42..0x42 + n * 2)?;
    let u: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let name = String::from_utf16(&u).ok()?;
    if name.is_empty() || name.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(EntryName {
        file: mft_ref(u64_at(d, 0)),
        parent: mft_ref(u64_at(f, 0)),
        name,
        times: [u64_at(f, 8), u64_at(f, 16), u64_at(f, 24), u64_at(f, 32)],
        size: u64_at(f, 48),
        dir: u32_at(f, 0x38) & 0x1000_0000 != 0,
        namespace: f[0x41],
    })
}

/// Attributes in an MFT record image (as InitializeFileRecordSegment's redo
/// data holds it): (type, name, resident value).
pub fn record_attributes(d: &[u8]) -> Vec<(u32, String, Vec<u8>)> {
    let mut out = vec![];
    if d.len() < 0x18 || &d[..4] != b"FILE" {
        return out;
    }
    let mut o = u16_at(d, 0x14) as usize;
    while o + 0x10 <= d.len() && out.len() < 64 {
        let t = u32_at(d, o);
        if t == 0xFFFF_FFFF || t == 0 {
            break;
        }
        let len = u32_at(d, o + 4) as usize;
        if len < 0x10 || o + len > d.len() {
            break;
        }
        let a = &d[o..o + len];
        let (nlen, noff) = (a[9] as usize, u16_at(a, 10) as usize);
        let name = a.get(noff..noff + nlen * 2).map(|b| String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())).unwrap_or_default();
        let value = if a[8] == 0 {
            let (vl, vo) = (u32_at(a, 0x10) as usize, u16_at(a, 0x14) as usize);
            a.get(vo..vo + vl).map(|v| v.to_vec()).unwrap_or_default()
        } else {
            vec![]
        };
        out.push((t, name, value));
        o += len;
    }
    out
}

/// One attribute as CreateAttribute and DeleteAttribute carry it (header
/// and value): (type, name, resident value).
pub fn attribute(d: &[u8]) -> Option<(u32, String, Vec<u8>)> {
    let t = u32_at(d, 0);
    if d.len() < 0x10 || t == 0 || t == 0xFFFF_FFFF || t > 0x1000 {
        return None;
    }
    let (nlen, noff) = (d[9] as usize, u16_at(d, 10) as usize);
    let name = d.get(noff..noff + nlen * 2).map(|b| String::from_utf16_lossy(&b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>())).unwrap_or_default();
    let value = if d[8] == 0 {
        let (vl, vo) = (u32_at(d, 0x10) as usize, u16_at(d, 0x14) as usize);
        d.get(vo..vo + vl).map(|v| v.to_vec()).unwrap_or_default()
    } else {
        vec![]
    };
    Some((t, name, value))
}

/// The name and folder in a $FILE_NAME value.
pub fn file_name_value(v: &[u8]) -> Option<((u64, u16), String)> {
    let n = *v.get(0x40)? as usize;
    let raw = v.get(0x42..0x42 + n * 2)?;
    let name = String::from_utf16(&raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()).ok()?;
    Some((mft_ref(u64_at(v, 0)), name))
}

/// Fuzzing: a $LogFile from anywhere, every record decoded.
pub fn fuzz(d: &[u8]) {
    if let Some(l) = parse(d) {
        for r in l.records.iter().take(4096) {
            let _ = r.mft_record(4096, 1024);
            let _ = index_entry_name(&r.redo);
            let _ = index_entry_name(&r.undo);
            let _ = record_attributes(&r.redo);
            let _ = attribute(&r.redo);
            let _ = attribute(&r.undo);
        }
    }
}

/// Builds $LogFile images for tests (here and in the analysis crate).
#[doc(hidden)]
pub mod synth {

    /// A $LogFile as Windows lays one out: two restart pages, then record
    /// pages with fixups. `recs` are (redo op, undo op, target VCN, cluster
    /// block offset, record offset, attribute offset, redo, undo); the
    /// third runs on into the next page.
    pub fn build(recs: &[(u16, u16, u64, u16, u16, u16, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        const PAGE: usize = 4096;
        const SEQ_BITS: u32 = 44;
        let mut d = vec![0u8; PAGE * 8];
        let usa = |pg: &mut [u8], seq: u16| {
            let (ofs, count) = (u16::from_le_bytes([pg[4], pg[5]]) as usize, u16::from_le_bytes([pg[6], pg[7]]) as usize);
            pg[ofs..ofs + 2].copy_from_slice(&seq.to_le_bytes());
            for i in 1..count {
                let end = i * 512;
                let (a, b) = (pg[end - 2], pg[end - 1]);
                pg[ofs + i * 2] = a;
                pg[ofs + i * 2 + 1] = b;
                pg[end - 2..end].copy_from_slice(&seq.to_le_bytes());
            }
        };
        let lsn_of = |off: u64| off >> 3;
        // Records in the data area of pages 4.. (data starts at 0x40).
        let mut stream: Vec<(u64, Vec<u8>)> = vec![];
        let mut at = (4 * PAGE + 0x40) as u64;
        let mut last = 0u64;
        for (i, (redo_op, undo_op, vcn, cbo, ro, ao, redo, undo)) in recs.iter().enumerate() {
            let mut c = vec![0u8; 0x20];
            c[0..2].copy_from_slice(&redo_op.to_le_bytes());
            c[2..4].copy_from_slice(&undo_op.to_le_bytes());
            c[4..6].copy_from_slice(&0x20u16.to_le_bytes());
            c[6..8].copy_from_slice(&(redo.len() as u16).to_le_bytes());
            let uo = 0x20 + redo.len().div_ceil(8) * 8;
            c[8..10].copy_from_slice(&(uo as u16).to_le_bytes());
            c[10..12].copy_from_slice(&(undo.len() as u16).to_le_bytes());
            c[0x10..0x12].copy_from_slice(&ro.to_le_bytes());
            c[0x12..0x14].copy_from_slice(&ao.to_le_bytes());
            c[0x14..0x16].copy_from_slice(&cbo.to_le_bytes());
            c[0x18..0x20].copy_from_slice(&vcn.to_le_bytes());
            c.extend(redo);
            c.resize(uo, 0);
            c.extend(undo);
            let mut h = vec![0u8; 0x30];
            // The third record starts near the end of its page.
            if i == 2 {
                at = ((at / PAGE as u64) + 1) * PAGE as u64 - 0x30 - 16;
            }
            h[0..8].copy_from_slice(&lsn_of(at).to_le_bytes());
            h[8..16].copy_from_slice(&last.to_le_bytes());
            h[0x18..0x1C].copy_from_slice(&(c.len() as u32).to_le_bytes());
            h[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
            h[0x24..0x28].copy_from_slice(&(0x18u32 + i as u32).to_le_bytes());
            last = lsn_of(at);
            let rec = [h, c].concat();
            stream.push((at, rec.clone()));
            // Advance across page data areas.
            let mut left = rec.len().div_ceil(8) * 8;
            while left > 0 {
                let room = PAGE - (at as usize % PAGE);
                if left < room {
                    at += left as u64;
                    break;
                }
                left -= room;
                at = ((at / PAGE as u64) + 1) * PAGE as u64 + 0x40;
            }
        }
        for (at, rec) in stream {
            let mut at = at as usize;
            let mut k = 0;
            while k < rec.len() {
                let room = PAGE - at % PAGE;
                let n = room.min(rec.len() - k);
                d[at..at + n].copy_from_slice(&rec[k..k + n]);
                k += n;
                at = (at / PAGE + 1) * PAGE + 0x40;
            }
        }
        for p in 4..8 {
            let pg = &mut d[p * PAGE..(p + 1) * PAGE];
            pg[0..4].copy_from_slice(b"RCRD");
            pg[4..6].copy_from_slice(&0x28u16.to_le_bytes());
            pg[6..8].copy_from_slice(&9u16.to_le_bytes());
            usa(pg, 3);
        }
        for p in 0..2 {
            let pg = &mut d[p * PAGE..(p + 1) * PAGE];
            pg[0..4].copy_from_slice(b"RSTR");
            pg[4..6].copy_from_slice(&0x1Eu16.to_le_bytes());
            pg[6..8].copy_from_slice(&9u16.to_le_bytes());
            pg[0x10..0x14].copy_from_slice(&(PAGE as u32).to_le_bytes());
            pg[0x14..0x18].copy_from_slice(&(PAGE as u32).to_le_bytes());
            pg[0x18..0x1A].copy_from_slice(&0x30u16.to_le_bytes());
            pg[0x1A..0x1C].copy_from_slice(&1u16.to_le_bytes());
            pg[0x1C..0x1E].copy_from_slice(&1u16.to_le_bytes());
            let ra = 0x30;
            pg[ra..ra + 8].copy_from_slice(&last.to_le_bytes());
            pg[ra + 0x0E..ra + 0x10].copy_from_slice(&2u16.to_le_bytes());
            pg[ra + 0x10..ra + 0x14].copy_from_slice(&SEQ_BITS.to_le_bytes());
            pg[ra + 0x18..ra + 0x20].copy_from_slice(&((PAGE * 8) as u64).to_le_bytes());
            pg[ra + 0x24..ra + 0x26].copy_from_slice(&0x30u16.to_le_bytes());
            pg[ra + 0x26..ra + 0x28].copy_from_slice(&0x40u16.to_le_bytes());
            usa(pg, 1);
        }
        d
    }

    /// An index entry for `name` in folder 5 (the root).
    pub fn entry(record: u64, name: &str, created: u64) -> Vec<u8> {
        let u: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let key = 0x42 + u.len();
        let len = (0x10 + key).div_ceil(8) * 8;
        let mut e = vec![0u8; len];
        e[0..8].copy_from_slice(&(record | (1 << 48)).to_le_bytes());
        e[8..10].copy_from_slice(&(len as u16).to_le_bytes());
        e[10..12].copy_from_slice(&(key as u16).to_le_bytes());
        let f = 0x10;
        e[f..f + 8].copy_from_slice(&(5u64 | (5 << 48)).to_le_bytes());
        for k in 0..4 {
            e[f + 8 + k * 8..f + 16 + k * 8].copy_from_slice(&created.to_le_bytes());
        }
        e[f + 0x40] = name.encode_utf16().count() as u8;
        e[f + 0x41] = 1;
        e[f + 0x42..f + 0x42 + u.len()].copy_from_slice(&u);
        e
    }

}

#[cfg(test)]
mod tests {
    use super::synth::*;
    use super::*;

    #[test]
    fn reads_records_and_their_operations() {
        let t = 134_000_000_000_000_000u64;
        let big = vec![0x41u8; 5000];
        let log = build(&[
            (0x0E, 0x0F, 2, 0, 0x18, 0, entry(70, "plan.docx", t), vec![]),
            (0x07, 0x07, 17, 4, 0x38, 0x18, (t + 1).to_le_bytes().to_vec(), t.to_le_bytes().to_vec()),
            (0x07, 0x07, 17, 6, 0x98, 0x18, big.clone(), vec![1, 2, 3]),
            (0x00, 0x0F, 2, 0, 0x18, 0, vec![], entry(71, "old.txt", t)),
        ]);
        let l = parse(&log).expect("parsed");
        assert_eq!(l.page_size, 4096);
        assert_eq!(l.records.len(), 4, "{:?}", l.records.iter().map(|r| r.lsn).collect::<Vec<_>>());
        let r = &l.records;
        assert_eq!((r[0].redo_op, r[0].undo_op), (0x0E, 0x0F));
        let n = index_entry_name(&r[0].redo).unwrap();
        assert_eq!((n.name.as_str(), n.file, n.parent, n.times[0]), ("plan.docx", (70, 1), (5, 5), t));
        assert_eq!(r[1].mft_record(4096, 1024), Some(17 * 4 + 2));
        assert_eq!((r[1].record_offset, r[1].attribute_offset), (0x38, 0x18));
        assert_eq!(r[1].undo, t.to_le_bytes());
        assert_eq!(r[2].redo, big, "a record running on into the next page");
        assert_eq!(index_entry_name(&r[3].undo).unwrap().name, "old.txt");
        assert!(r.windows(2).all(|w| w[0].lsn < w[1].lsn));
        // A torn page is counted, not read.
        let mut torn = log.clone();
        torn[5 * 4096 + 1022] ^= 0xFF;
        let l2 = parse(&torn).unwrap();
        assert_eq!(l2.damaged_pages, 1);
        // Not a log.
        assert!(parse(&vec![0u8; 65_536]).is_none());
    }
}
