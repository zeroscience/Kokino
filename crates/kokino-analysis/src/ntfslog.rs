//! What $LogFile, the NTFS transaction log, says happened: files created,
//! deleted and renamed, timestamps changed (and to what, from what), sizes,
//! named streams added and removed, and the content of small (resident)
//! files before and after a change. NTFS logs every change to its metadata
//! with what was there before (to undo it), so the log shows earlier states
//! the MFT no longer has, for the last minutes to hours of activity (the
//! log is circular, usually 64 MiB).
//!
//! Log records carry no time of their own: events are in log order (LSN),
//! with the times found inside them (a name's times, the new timestamps).

use crate::fs::Fs;
use crate::FileRow;
use kokino_ntfs::logfile::{self, EntryName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

/// Events kept (the newest), and the largest log read.
pub const MAX_EVENTS: usize = 300_000;
const MAX_LOG: u64 = 512 << 20;
/// How far apart (in operations) the parts of one change may be.
const WINDOW: usize = 64;
const MINUTE: u64 = 60 * 10_000_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogHistory {
    /// The $LogFile entry (index into the volume's files).
    pub file: u32,
    pub size: u64,
    pub version: String,
    pub page_size: u64,
    pub records: u64,
    pub pages: u64,
    pub damaged_pages: u64,
    pub first_lsn: u64,
    pub last_lsn: u64,
    /// Not closed cleanly: the newest changes may be only in the log.
    pub dirty: bool,
    /// Events not kept (the oldest), beyond the limit.
    pub dropped: u64,
    pub events: Vec<LogEvent>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogEvent {
    pub lsn: u64,
    pub transaction: u32,
    /// created, deleted, renamed, name added, name removed, record set up,
    /// record freed, times changed, size changed, stream added, stream
    /// removed, content changed
    pub what: String,
    /// The MFT record, when known.
    pub record: Option<u64>,
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub old_path: String,
    /// What changed, as people read it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// A time found in the record (FILETIME, UTC); 0 when none.
    pub time: u64,
    /// Small content or values before and after (text, or hex).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub before: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub after: String,
    /// The file on this volume, when the record and name still match.
    pub file: Option<u32>,
    /// $STANDARD_INFORMATION created or modified set back in time.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub backdated: bool,
}

/// One decoded change before pairing.
#[derive(Debug, Clone)]
enum Fact {
    NameAdded(EntryName),
    NameRemoved(EntryName),
    Init(u64, Option<((u64, u16), String)>),
    Freed(u64),
    /// record, (field, old, new) for created, modified, MFT modified, accessed
    Times(u64, Vec<(usize, u64, u64)>),
    Size(u64, u64, u64),
    Stream(u64, bool, String),
    Content(u64, Vec<u8>, Vec<u8>),
}

fn u16_at(d: &[u8], o: usize) -> usize {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize).unwrap_or(0)
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}

/// Where each attribute of an MFT record image starts: start -> (type,
/// value offset, resident, named).
fn layout(rec: &[u8]) -> Layout {
    let mut out = HashMap::new();
    if rec.len() < 0x18 || &rec[..4] != b"FILE" {
        return out;
    }
    let mut o = u16_at(rec, 0x14);
    while o + 0x18 <= rec.len() && out.len() < 64 {
        let t = u32_at(rec, o);
        let len = u32_at(rec, o + 4) as usize;
        if t == 0xFFFF_FFFF || t == 0 || len < 0x10 || o + len > rec.len() {
            break;
        }
        let resident = rec[o + 8] == 0;
        out.insert(o, (t, if resident { u16_at(rec, o + 0x14) } else { 0 }, resident, rec[o + 9] != 0));
        o += len;
    }
    out
}

fn plausible(ft: u64) -> bool {
    // 1990 to 2100.
    (126_227_808_000_000_000..=159_725_088_000_000_000).contains(&ft)
}

/// $STANDARD_INFORMATION times changed by an update at `value_off` within
/// the value: (field, old, new) for each whole time covered.
fn si_times(rel: usize, redo: &[u8], undo: &[u8]) -> Vec<(usize, u64, u64)> {
    let mut out = vec![];
    for field in 0..4 {
        let at = field * 8;
        if at < rel || at + 8 > rel + redo.len().min(undo.len()) {
            continue;
        }
        let (new, old) = (u64_at(redo, at - rel), u64_at(undo, at - rel));
        if new != old && plausible(new) && plausible(old) {
            out.push((field, old, new));
        }
    }
    out
}

/// Bytes as people read them: text when it is text, else hex.
fn preview(d: &[u8]) -> String {
    let d = &d[..d.len().min(512)];
    match std::str::from_utf8(d) {
        Ok(t) if t.chars().all(|c| !c.is_control() || c.is_whitespace()) => t.to_string(),
        _ => d.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
    }
}

fn utc(ft: u64) -> String {
    kokino_core::time::utc_text(ft)
}

/// Reads $LogFile of an NTFS volume and says what it holds.
pub fn build<R: Read + Seek>(fs: &Fs, r: &mut R, files: &[FileRow], progress: crate::Progress) -> Option<LogHistory> {
    let Fs::Ntfs(n) = fs else { return None };
    let (li, lf) = files.iter().enumerate().find(|(_, f)| f.e.record == 2 && f.e.name_only.is_none() && !f.e.deleted && f.e.name == "$LogFile")?;
    let mut h = LogHistory { file: li as u32, size: lf.e.size, ..Default::default() };
    if lf.e.size > MAX_LOG {
        h.error = Some(format!("$LogFile is {} bytes; only logs up to {} bytes are read", lf.e.size, MAX_LOG));
        return Some(h);
    }
    progress("Transaction log ($LogFile)", 0, 1);
    let data = match fs.read(r, &lf.e, "", 0, lf.e.size as usize) {
        Ok(d) => d,
        Err(e) => {
            h.error = Some(format!("{:#}", e));
            return Some(h);
        }
    };
    let Some(log) = logfile::parse(&data) else {
        h.error = Some("no valid restart page: the log is empty or overwritten (a freshly formatted volume, or one never mounted by Windows)".into());
        return Some(h);
    };
    h.version = format!("{}.{}", log.version.0, log.version.1);
    h.page_size = log.page_size;
    h.records = log.records.len() as u64;
    h.pages = log.pages;
    h.damaged_pages = log.damaged_pages;
    h.first_lsn = log.records.first().map(|r| r.lsn).unwrap_or(0);
    h.last_lsn = log.records.last().map(|r| r.lsn).unwrap_or(0);
    h.dirty = log.dirty;
    let (cluster, rsize) = (n.cluster_size() as u64, n.file_record_size() as u64);
    let by_rec: HashMap<u64, usize> = files.iter().enumerate().filter(|(_, f)| f.e.name_only.is_none()).map(|(i, f)| (f.e.record, i)).collect();
    // Current MFT record images, read once each.
    let mut image = |rec: u64| -> Layout {
        let mut l = HashMap::new();
        if let Some(&i) = by_rec.get(&rec) {
            let off = files[i].e.record_offset;
            let mut b = vec![0u8; rsize as usize];
            if off > 0 && r.seek(SeekFrom::Start(off)).is_ok() && r.read_exact(&mut b).is_ok() && logfile::fixup(&mut b) {
                l = layout(&b);
            }
        }
        l
    };
    let (events, dropped) = interpret(&log, cluster, rsize, files, &mut image, progress);
    h.events = events;
    h.dropped = dropped;
    Some(h)
}

/// Where each attribute of an MFT record starts: start -> (type, value
/// offset, resident, named).
pub type Layout = HashMap<usize, (u32, usize, bool, bool)>;

/// The events of a parsed log. `image(record)` gives the current layout of
/// an MFT record (to tell which attribute an update changed).
pub fn interpret(log: &logfile::Log, cluster: u64, rsize: u64, files: &[FileRow], image: &mut dyn FnMut(u64) -> Layout, progress: crate::Progress) -> (Vec<LogEvent>, u64) {
    let by_rec: HashMap<u64, usize> = files.iter().enumerate().filter(|(_, f)| f.e.name_only.is_none()).map(|(i, f)| (f.e.record, i)).collect();
    let mut images: HashMap<u64, Layout> = HashMap::new();
    let mut image = |rec: u64| -> Layout { images.entry(rec).or_insert_with(|| image(rec)).clone() };
    let mut facts: Vec<(usize, Fact)> = vec![];
    for (k, rec) in log.records.iter().enumerate() {
        if rec.kind != 1 {
            continue;
        }
        let mft = rec.mft_record(cluster, rsize);
        match (rec.redo_op, rec.undo_op) {
            (0x0C | 0x0E, _) => {
                if let Some(e) = logfile::index_entry_name(&rec.redo).filter(|e| e.namespace != 2) {
                    facts.push((k, Fact::NameAdded(e)));
                }
            }
            (_, 0x0C | 0x0E) if matches!(rec.redo_op, 0x0D | 0x0F) => {
                if let Some(e) = logfile::index_entry_name(&rec.undo).filter(|e| e.namespace != 2) {
                    facts.push((k, Fact::NameRemoved(e)));
                }
            }
            (0x02, _) => {
                if let Some(m) = mft {
                    let name = logfile::record_attributes(&rec.redo).into_iter().filter(|a| a.0 == 0x30).filter_map(|a| logfile::file_name_value(&a.2)).max_by_key(|x| x.1.len());
                    facts.push((k, Fact::Init(m, name)));
                }
            }
            (0x03, _) => {
                if let Some(m) = mft {
                    facts.push((k, Fact::Freed(m)));
                }
            }
            (0x05, 0x06) | (0x06, 0x05) => {
                let added = rec.redo_op == 0x05;
                if let (Some(m), Some((t, name, _))) = (mft, logfile::attribute(if added { &rec.redo } else { &rec.undo })) {
                    if t == 0x80 && !name.is_empty() {
                        facts.push((k, Fact::Stream(m, added, name)));
                    }
                }
            }
            (0x0B, 0x0B) => {
                if let Some(m) = mft {
                    let (old, new) = (u64_at(&rec.undo, 8), u64_at(&rec.redo, 8));
                    if rec.redo.len() >= 16 && rec.undo.len() >= 16 && old != new {
                        facts.push((k, Fact::Size(m, old, new)));
                    }
                }
            }
            (0x07, 0x07) => {
                let Some(m) = mft else { continue };
                let ro = rec.record_offset as usize;
                let ao = rec.attribute_offset as usize;
                let l = image(m);
                match l.get(&ro) {
                    Some(&(0x10, vo, true, _)) if ao >= vo => {
                        let t = si_times(ao - vo, &rec.redo, &rec.undo);
                        if !t.is_empty() {
                            facts.push((k, Fact::Times(m, t)));
                        }
                    }
                    Some(&(0x80, vo, true, false)) if ao >= vo => facts.push((k, Fact::Content(m, rec.undo.clone(), rec.redo.clone()))),
                    Some(_) => {}
                    // The record is gone or changed: $STANDARD_INFORMATION
                    // is the first attribute, its value 0x18 bytes in.
                    None if matches!(ro, 0x30 | 0x38) && ao >= 0x18 => {
                        let t = si_times(ao - 0x18, &rec.redo, &rec.undo);
                        if !t.is_empty() {
                            facts.push((k, Fact::Times(m, t)));
                        }
                    }
                    None => {}
                }
            }
            _ => {}
        }
        if k % 4096 == 0 && !progress("Transaction log ($LogFile)", k as u64, log.records.len() as u64) {
            break;
        }
    }

    // Folders the log names, for paths of what is gone.
    let mut folders: HashMap<u64, (String, u64)> = HashMap::new();
    for (_, f) in &facts {
        if let Fact::NameAdded(e) | Fact::NameRemoved(e) = f {
            if e.dir {
                folders.insert(e.file.0, (e.name.clone(), e.parent.0));
            }
        }
    }
    let folder = |rec: u64| -> String {
        let mut parts = vec![];
        let mut cur = rec;
        for _ in 0..64 {
            if cur == kokino_ntfs::ROOT_RECORD {
                break;
            }
            if let Some(&i) = by_rec.get(&cur).filter(|&&i| files[i].e.is_dir && !files[i].e.deleted) {
                let p = files[i].e.path.trim_end_matches('/').to_string();
                return if parts.is_empty() { p } else { format!("{}/{}", p, parts.into_iter().rev().collect::<Vec<_>>().join("/")) };
            }
            match folders.get(&cur) {
                Some((name, parent)) if *parent != cur => {
                    parts.push(name.clone());
                    cur = *parent;
                }
                _ => {
                    parts.push(format!("[folder {}]", cur));
                    break;
                }
            }
        }
        format!("/{}", parts.into_iter().rev().collect::<Vec<_>>().join("/"))
    };
    let path_of = |e: &EntryName| format!("{}/{}", folder(e.parent.0).trim_end_matches('/'), e.name);
    let record_path = |rec: u64| by_rec.get(&rec).map(|&i| files[i].e.path.clone()).unwrap_or_else(|| format!("[record {}]", rec));
    let file_of = |rec: u64, name: Option<&str>| by_rec.get(&rec).filter(|&&i| name.is_none_or(|n| files[i].e.name.eq_ignore_ascii_case(n))).map(|&i| i as u32);

    let mut used = vec![false; facts.len()];
    let mut events: Vec<LogEvent> = vec![];
    let near = |i: usize, j: usize| facts[i].0.abs_diff(facts[j].0) <= WINDOW;
    for i in 0..facts.len() {
        if used[i] {
            continue;
        }
        let k = facts[i].0;
        let rec = &log.records[k];
        let mut ev = LogEvent { lsn: rec.lsn, transaction: rec.transaction, ..Default::default() };
        match facts[i].1.clone() {
            Fact::NameAdded(e) => {
                let rn = e.file.0;
                let init = (i.saturating_sub(WINDOW)..(i + WINDOW + 1).min(facts.len())).find(|&j| !used[j] && j != i && near(i, j) && matches!(&facts[j].1, Fact::Init(r, _) if *r == rn));
                let removed = (i.saturating_sub(WINDOW)..(i + WINDOW + 1).min(facts.len())).find(|&j| !used[j] && j != i && near(i, j) && matches!(&facts[j].1, Fact::NameRemoved(o) if o.file.0 == rn && (o.name != e.name || o.parent != e.parent)));
                ev.record = Some(rn);
                ev.path = path_of(&e);
                ev.file = file_of(rn, Some(&e.name));
                if let Some(j) = removed {
                    used[j] = true;
                    if let Fact::NameRemoved(o) = &facts[j].1 {
                        ev.old_path = path_of(o);
                    }
                    ev.what = "renamed".into();
                    ev.time = e.times[2];
                } else if let Some(j) = init {
                    used[j] = true;
                    ev.what = "created".into();
                    ev.time = e.times[0];
                    ev.detail = format!("created {}", utc(e.times[0]));
                } else {
                    ev.what = "name added".into();
                    ev.time = e.times[2];
                }
                if e.dir {
                    ev.detail = if ev.detail.is_empty() { "folder".into() } else { format!("folder, {}", ev.detail) };
                }
            }
            Fact::NameRemoved(e) => {
                let rn = e.file.0;
                let added = (i.saturating_sub(WINDOW)..(i + WINDOW + 1).min(facts.len())).find(|&j| !used[j] && j != i && near(i, j) && matches!(&facts[j].1, Fact::NameAdded(o) if o.file.0 == rn && (o.name != e.name || o.parent != e.parent)));
                let freed = (i.saturating_sub(WINDOW)..(i + WINDOW + 1).min(facts.len())).find(|&j| !used[j] && j != i && near(i, j) && matches!(&facts[j].1, Fact::Freed(r) if *r == rn));
                ev.record = Some(rn);
                ev.old_path = String::new();
                if let Some(j) = added {
                    used[j] = true;
                    if let Fact::NameAdded(o) = &facts[j].1 {
                        ev.path = path_of(o);
                        ev.file = file_of(rn, Some(&o.name));
                        ev.time = o.times[2];
                    }
                    ev.old_path = path_of(&e);
                    ev.what = "renamed".into();
                } else {
                    ev.path = path_of(&e);
                    ev.time = e.times[2];
                    if let Some(j) = freed {
                        used[j] = true;
                        ev.what = "deleted".into();
                    } else {
                        ev.what = "name removed".into();
                    }
                    ev.detail = format!("it was created {}, last modified {}", utc(e.times[0]), utc(e.times[1]));
                }
            }
            Fact::Init(rn, name) => {
                // Part of a creation already listed (a record is often set up
                // twice while a file is made).
                let lo = i.saturating_sub(WINDOW);
                if (lo..(i + WINDOW + 1).min(facts.len())).any(|j| j != i && near(i, j) && matches!(&facts[j].1, Fact::NameAdded(e) if e.file.0 == rn)) {
                    used[i] = true;
                    continue;
                }
                ev.record = Some(rn);
                ev.what = "record set up".into();
                ev.path = match &name {
                    Some((parent, n)) => format!("{}/{}", folder(parent.0).trim_end_matches('/'), n),
                    None => record_path(rn),
                };
                ev.file = file_of(rn, name.as_ref().map(|x| x.1.as_str()));
                // Records set up one after another without names (as
                // formatting does): one line.
                if name.is_none() {
                    let mut last = rn;
                    for j in i + 1..facts.len() {
                        match &facts[j].1 {
                            Fact::Init(r2, None) if *r2 == last + 1 && !used[j] => {
                                used[j] = true;
                                last = *r2;
                            }
                            Fact::Init(..) | Fact::Freed(_) | Fact::Size(..) | Fact::Times(..) => {}
                            _ => break,
                        }
                    }
                    if last > rn {
                        ev.path = format!("[records {} to {}]", rn, last);
                        ev.file = None;
                        ev.detail = format!("{} MFT records set up one after another, as formatting or a large copy does", last - rn + 1);
                    }
                }
            }
            Fact::Freed(rn) => {
                let lo = i.saturating_sub(WINDOW);
                if (lo..(i + WINDOW + 1).min(facts.len())).any(|j| j != i && near(i, j) && matches!(&facts[j].1, Fact::NameRemoved(e) if e.file.0 == rn)) {
                    used[i] = true;
                    continue;
                }
                ev.record = Some(rn);
                ev.what = "record freed".into();
                ev.path = record_path(rn);
            }
            Fact::Times(rn, t) => {
                const NAMES: [&str; 4] = ["created", "modified", "MFT modified", "accessed"];
                // Successive updates of one file's times: first to last, per
                // time (a file being written updates them every second).
                let mut merged: Vec<(usize, u64, u64)> = t;
                for j in i + 1..facts.len() {
                    if !near(i, j) {
                        break;
                    }
                    if let Fact::Times(r2, t2) = &facts[j].1 {
                        if *r2 == rn && !used[j] {
                            used[j] = true;
                            for &(f, o, n) in t2 {
                                match merged.iter_mut().find(|x| x.0 == f) {
                                    Some(x) => x.2 = n,
                                    None => merged.push((f, o, n)),
                                }
                            }
                        }
                    }
                }
                // Only changes people look for: created and modified, by a
                // second or more.
                let mut t: Vec<_> = merged.into_iter().filter(|x| x.0 < 2 && x.1.abs_diff(x.2) >= 10_000_000).collect();
                t.sort_by_key(|x| x.0);
                if t.is_empty() {
                    continue;
                }
                ev.record = Some(rn);
                ev.what = "times changed".into();
                ev.path = record_path(rn);
                ev.file = file_of(rn, None);
                ev.detail = t.iter().map(|&(f, o, n)| format!("{} {} -> {}", NAMES[f], utc(o), utc(n))).collect::<Vec<_>>().join("; ");
                ev.time = t.iter().map(|x| x.2).max().unwrap_or(0);
                // Created set back: copying keeps a file's modified time, but
                // gives the copy a new creation time.
                ev.backdated = t.iter().any(|&(f, o, n)| f == 0 && n + MINUTE < o);
            }
            Fact::Size(rn, old, mut new) => {
                // Successive size changes of one file: first to last.
                for j in i + 1..facts.len() {
                    if !near(i, j) {
                        break;
                    }
                    if let Fact::Size(r2, _, n2) = facts[j].1 {
                        if r2 == rn && !used[j] {
                            used[j] = true;
                            new = n2;
                        }
                    }
                }
                if old == new {
                    continue;
                }
                ev.record = Some(rn);
                ev.what = "size changed".into();
                ev.path = record_path(rn);
                ev.file = file_of(rn, None);
                ev.detail = format!("{} -> {} bytes", old, new);
            }
            Fact::Stream(rn, added, name) => {
                ev.record = Some(rn);
                ev.what = if added { "stream added" } else { "stream removed" }.into();
                ev.path = format!("{}:{}", record_path(rn), name);
                ev.file = file_of(rn, None);
            }
            Fact::Content(rn, before, after) => {
                ev.record = Some(rn);
                ev.what = "content changed".into();
                ev.path = record_path(rn);
                ev.file = file_of(rn, None);
                ev.before = preview(&before);
                ev.after = preview(&after);
                ev.detail = format!("{} bytes of a small (resident) file rewritten", after.len());
            }
        }
        used[i] = true;
        events.push(ev);
    }
    let mut dropped = 0;
    if events.len() > MAX_EVENTS {
        dropped = (events.len() - MAX_EVENTS) as u64;
        events.drain(..events.len() - MAX_EVENTS);
    }
    (events, dropped)
}

/// Fuzzing: a $LogFile from anywhere, read and explained.
pub fn fuzz(d: &[u8]) {
    kokino_ntfs::logfile::fuzz(d);
    if let Some(log) = logfile::parse(d) {
        let mut image = |_: u64| -> Layout { HashMap::from([(0x38, (0x10, 0x18, true, false)), (0x98, (0x80, 0x18, true, false))]) };
        let _ = interpret(&log, 4096, 1024, &[], &mut image, &mut |_, _, _| true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_what_happened() {
        use kokino_ntfs::logfile::synth::{build, entry};
        let t = 134_000_000_000_000_000u64;
        let year = 365 * 86_400 * 10_000_000u64;
        let mut stomp_new = (t - 2 * year).to_le_bytes().to_vec();
        stomp_new.extend((t - 2 * year).to_le_bytes());
        let mut stomp_old = t.to_le_bytes().to_vec();
        stomp_old.extend(t.to_le_bytes());
        // A named $DATA attribute ("Zone.Identifier"), resident.
        let name: Vec<u8> = "Zone.Identifier".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut ads = vec![0u8; 0x18];
        ads[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        ads[9] = 15;
        ads[10..12].copy_from_slice(&0x18u16.to_le_bytes());
        ads.extend(&name);
        ads.resize(0x38, 0);
        ads[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes());
        ads[0x10..0x14].copy_from_slice(&26u32.to_le_bytes());
        ads.extend(b"[ZoneTransfer]\r\nZoneId=3\r\n");
        let len = ads.len() as u32;
        ads[4..8].copy_from_slice(&len.to_le_bytes());
        let data = build(&[
            (0x0E, 0x0F, 2, 0, 0x18, 0, entry(70, "report.docx", t), vec![]),
            (0x02, 0x00, 17, 4, 0, 0, vec![], vec![]),
            (0x07, 0x07, 17, 4, 0x38, 0x18, stomp_new, stomp_old),
            (0x0F, 0x0E, 2, 0, 0x18, 0, vec![], entry(70, "report.docx", t)),
            (0x0E, 0x0F, 2, 0, 0x18, 0, entry(70, "q3.docx", t), vec![]),
            (0x0F, 0x0E, 2, 0, 0x18, 0, vec![], entry(71, "old.txt", t)),
            (0x03, 0x02, 17, 6, 0, 0, vec![], vec![]),
            (0x05, 0x06, 17, 4, 0x100, 0, ads, vec![]),
            (0x07, 0x07, 18, 0, 0x98, 0x18, b"wire 9,000 to the new account".to_vec(), b"wire 1,000 to the old account".to_vec()),
        ]);
        if std::env::var_os("KOKINO_WRITE_SEEDS").is_some() {
            let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kokino-fuzz/seeds/logfile");
            std::fs::create_dir_all(&seeds).unwrap();
            std::fs::write(seeds.join("lab.log"), &data).unwrap();
        }
        let log = logfile::parse(&data).unwrap();
        assert_eq!(log.records.len(), 9);
        let mut image = |rec: u64| -> Layout {
            match rec {
                70 => HashMap::from([(0x38, (0x10, 0x18, true, false))]),
                72 => HashMap::from([(0x98, (0x80, 0x18, true, false))]),
                _ => HashMap::new(),
            }
        };
        let (ev, dropped) = interpret(&log, 4096, 1024, &[], &mut image, &mut |_, _, _| true);
        assert_eq!(dropped, 0);
        let what: Vec<(&str, &str, &str)> = ev.iter().map(|e| (e.what.as_str(), e.path.as_str(), e.old_path.as_str())).collect();
        assert_eq!(what, [
            ("created", "/report.docx", ""),
            ("times changed", "[record 70]", ""),
            ("renamed", "/q3.docx", "/report.docx"),
            ("deleted", "/old.txt", ""),
            ("stream added", "[record 70]:Zone.Identifier", ""),
            ("content changed", "[record 72]", ""),
        ]);
        let stomp = &ev[1];
        assert!(stomp.backdated, "created set back two years");
        assert!(stomp.detail.starts_with("created ") && stomp.detail.contains(" -> "), "{}", stomp.detail);
        assert_eq!((ev[5].before.as_str(), ev[5].after.as_str()), ("wire 1,000 to the old account", "wire 9,000 to the new account"));
        assert_eq!(ev[0].time, t);
    }

    #[test]
    fn times_and_previews() {
        let t = 134_000_000_000_000_000u64;
        let mut redo = vec![];
        let mut undo = vec![];
        for k in 0..4u64 {
            redo.extend((t - 400 * MINUTE + k).to_le_bytes());
            undo.extend((t + k).to_le_bytes());
        }
        let x = si_times(0, &redo, &undo);
        assert_eq!(x.len(), 4);
        assert_eq!(x[0], (0, t, t - 400 * MINUTE));
        // An update of the modified time alone (8 bytes at value offset 8).
        let x = si_times(8, &(t + 5).to_le_bytes(), &t.to_le_bytes());
        assert_eq!(x, vec![(1, t, t + 5)]);
        assert!(si_times(8, &[1, 2, 3], &[4, 5, 6]).is_empty());
        assert_eq!(preview(b"meet at noon"), "meet at noon");
        assert_eq!(preview(&[0, 1, 0xFF]), "00 01 ff");
    }
}
