//! Legacy Windows event logs (.evt): Windows NT, 2000, XP and Server 2003
//! (`Windows\System32\config\SecEvent.Evt`, `SysEvent.Evt`, `AppEvent.Evt`).
//!
//! The file is a circular buffer of `LfLe` records after a 48-byte header.
//! Every 4-byte boundary is checked for a record (length, signature, and
//! the same length repeated at its end), so records in the unused part of
//! the buffer, left from before the log wrapped or was cleared, are read
//! too; a record that runs past the end of the file continues after the
//! header, as the buffer wraps.
//!
//! Records give the same [`Event`] as the EVTX reader. The message text
//! lives in DLLs on the original system, so a record only holds its
//! insertion strings; for the Security events that matter most they are
//! given the names Windows Vista and later use (TargetUserName, LogonType,
//! IpAddress, NewProcessName, ...), so the rest of Kokino reads both alike.

use crate::bin::*;
use crate::evtx::{Event, LogInfo};

const HEADER: usize = 0x30;
const MAX_RECORD: usize = 0x10_0000;

/// Channel name for a legacy log file name.
pub fn channel_of(file_name: &str) -> String {
    let stem = file_name.rsplit_once('.').map(|(s, _)| s).unwrap_or(file_name);
    match stem.to_ascii_lowercase().as_str() {
        "secevent" => "Security".into(),
        "sysevent" => "System".into(),
        "appevent" => "Application".into(),
        _ => stem.to_string(),
    }
}

fn unix_ft(t: u32) -> u64 {
    if t == 0 { 0 } else { unix_to_filetime(t as i64).unwrap_or(0) }
}

/// Names for the insertion strings of Security events (Windows XP and 2003
/// layouts), so they read like their Vista and later counterparts.
fn names(channel: &str, id: u32) -> &'static [(usize, &'static str)] {
    if !channel.eq_ignore_ascii_case("Security") {
        return &[];
    }
    match id {
        517 => &[(0, "PrimaryUserName"), (1, "PrimaryDomainName"), (3, "SubjectUserName"), (4, "SubjectDomainName")],
        528 | 540 => &[(0, "TargetUserName"), (1, "TargetDomainName"), (2, "TargetLogonId"), (3, "LogonType"), (4, "LogonProcessName"), (5, "AuthenticationPackageName"), (6, "WorkstationName"), (8, "SubjectUserName"), (13, "IpAddress"), (14, "IpPort")],
        529..=537 | 539 => &[(0, "TargetUserName"), (1, "TargetDomainName"), (2, "LogonType"), (3, "LogonProcessName"), (4, "AuthenticationPackageName"), (5, "WorkstationName"), (6, "SubjectUserName"), (11, "IpAddress"), (12, "IpPort")],
        538 => &[(0, "TargetUserName"), (1, "TargetDomainName"), (3, "LogonType")],
        552 => &[(0, "SubjectUserName"), (1, "SubjectDomainName"), (3, "LogonGuid"), (4, "TargetUserName"), (5, "TargetDomainName"), (7, "TargetServerName"), (9, "IpAddress")],
        592 => &[(0, "NewProcessId"), (1, "NewProcessName"), (2, "ProcessId"), (3, "SubjectUserName"), (4, "SubjectDomainName")],
        601 => &[(0, "ServiceName"), (1, "ImagePath"), (2, "ServiceType"), (3, "StartType"), (4, "AccountName")],
        624 => &[(0, "TargetUserName"), (1, "TargetDomainName"), (2, "TargetSid"), (3, "SubjectUserName"), (4, "SubjectDomainName")],
        626 | 627 | 628 | 629 | 630 | 642 | 644 => &[(0, "TargetUserName"), (1, "TargetDomainName"), (2, "TargetSid"), (3, "SubjectUserName"), (4, "SubjectDomainName")],
        632 | 636 | 660 => &[(0, "MemberName"), (1, "MemberSid"), (2, "TargetUserName"), (3, "TargetDomainName"), (4, "TargetSid"), (5, "SubjectUserName"), (6, "SubjectDomainName")],
        _ => &[],
    }
}

/// Reads a .evt file; `channel` comes from the file name ([`channel_of`]).
pub fn parse(data: &[u8], channel: &str, f: &mut dyn FnMut(Event)) -> anyhow::Result<LogInfo> {
    if data.len() < HEADER || slice(data, 4, 4) != Some(b"LfLe") || u32_at(data, 0) != Some(0x30) {
        anyhow::bail!("not a legacy event log (no LfLe header)");
    }
    let flags = u32_at(data, 36).unwrap_or(0);
    let mut info = LogInfo { dirty: flags & 1 != 0, full: flags & 4 != 0, ..Default::default() };
    // Bytes at a buffer position, wrapping after the end to just after the header.
    let ring = data.len() - HEADER;
    let rd = |pos: usize, n: usize| -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let mut p = pos;
        while out.len() < n {
            if p >= data.len() {
                p = HEADER;
            }
            let k = (n - out.len()).min(data.len() - p);
            out.extend_from_slice(&data[p..p + k]);
            p += k;
        }
        out
    };
    let mut seen = std::collections::HashSet::new();
    let mut p = HEADER;
    while p + 8 <= data.len() {
        if slice(data, p + 4, 4) != Some(b"LfLe") {
            p += 4;
            continue;
        }
        let len = u32_at(data, p).unwrap_or(0) as usize;
        if len < 0x38 || len > MAX_RECORD.min(ring) || len % 4 != 0 {
            p += 4;
            continue;
        }
        let r = rd(p, len);
        if u32_at(&r, len - 4) != Some(len as u32) {
            p += 4;
            continue;
        }
        let rn = u32_at(&r, 8).unwrap_or(0);
        if !seen.insert((rn, u32_at(&r, 16).unwrap_or(0))) {
            p += 4;
            continue;
        }
        match record(&r, channel) {
            Some(e) => {
                info.records += 1;
                if info.first_record == 0 || e.record_id < info.first_record {
                    info.first_record = e.record_id;
                }
                info.last_record = info.last_record.max(e.record_id);
                if e.time != 0 {
                    info.oldest = if info.oldest == 0 { e.time } else { info.oldest.min(e.time) };
                    info.newest = info.newest.max(e.time);
                }
                f(e);
            }
            None => info.errors += 1,
        }
        // Records are 4-aligned; one that wrapped ends past the file.
        p += if p + len <= data.len() { len } else { 4 };
    }
    Ok(info)
}

fn record(r: &[u8], channel: &str) -> Option<Event> {
    let len = r.len();
    let rn = u32_at(r, 8)? as u64;
    let generated = u32_at(r, 12)?;
    let id = u32_at(r, 20)? & 0xFFFF;
    let etype = u16_at(r, 24)?;
    let nstr = u16_at(r, 26)? as usize;
    let str_off = u32_at(r, 36)? as usize;
    let (sid_len, sid_off) = (u32_at(r, 40)? as usize, u32_at(r, 44)? as usize);
    let (data_len, data_off) = (u32_at(r, 48)? as usize, u32_at(r, 52)? as usize);
    let source = utf16z(r, 56, 256);
    let computer = utf16z(r, 56 + (source.encode_utf16().count() + 1) * 2, 256);
    let mut strings = vec![];
    let mut p = str_off;
    for _ in 0..nstr.min(256) {
        if p >= len {
            break;
        }
        let s = utf16z(r, p, 32_768);
        p += (s.encode_utf16().count() + 1) * 2;
        strings.push(s);
    }
    let user_sid = if sid_len >= 8 && sid_off + sid_len <= len { sid(&r[sid_off..sid_off + sid_len]) } else { None };
    let mut data: Vec<(String, String)> = vec![];
    let named = names(channel, id);
    for (i, s) in strings.iter().enumerate() {
        let key = named.iter().find(|(n, _)| *n == i).map(|(_, k)| k.to_string()).unwrap_or_else(|| format!("param{}", i + 1));
        data.push((key, s.trim().to_string()));
    }
    if data_len > 0 && data_off + data_len <= len {
        let b = &r[data_off..data_off + data_len.min(256)];
        data.push(("Data".into(), b.iter().map(|x| format!("{:02x}", x)).collect::<String>()));
    }
    // Event type to an EVTX-like level: 1 error, 2 warning, 4 information,
    // 8 and 16 audit success and failure.
    let level = match etype {
        1 => 2,
        2 => 3,
        4 => 4,
        _ => 0,
    };
    let keywords_failure = etype == 0x10;
    if keywords_failure {
        data.push(("Audit".into(), "failure".into()));
    } else if etype == 0x08 {
        data.push(("Audit".into(), "success".into()));
    }
    Some(Event { record_id: rn, time: unix_ft(generated), event_id: id, level, provider: source, channel: channel.to_string(), computer, user_sid, data, ..Default::default() })
}

/// Test helpers (a record and header writer), public so other crates can
/// build fixtures with them.
#[doc(hidden)]
pub mod tests {
    use super::*;

    fn u16z(s: &str) -> Vec<u8> {
        s.encode_utf16().chain([0]).flat_map(|u| u.to_le_bytes()).collect()
    }

    /// One record as Windows XP writes it.
    pub fn record_bytes(rn: u32, t: u32, id: u32, etype: u16, source: &str, computer: &str, strings: &[&str]) -> Vec<u8> {
        let mut r = vec![0u8; 56];
        r.extend(u16z(source));
        r.extend(u16z(computer));
        while r.len() % 4 != 0 {
            r.push(0);
        }
        let sid_off = r.len();
        let sid_b = [1u8, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xe9, 3, 0, 0];
        r.extend_from_slice(&sid_b);
        let str_off = r.len();
        for s in strings {
            r.extend(u16z(s));
        }
        while r.len() % 4 != 0 {
            r.push(0);
        }
        let len = r.len() as u32 + 4;
        r[0..4].copy_from_slice(&len.to_le_bytes());
        r[4..8].copy_from_slice(b"LfLe");
        r[8..12].copy_from_slice(&rn.to_le_bytes());
        r[12..16].copy_from_slice(&t.to_le_bytes());
        r[16..20].copy_from_slice(&t.to_le_bytes());
        r[20..24].copy_from_slice(&id.to_le_bytes());
        r[24..26].copy_from_slice(&etype.to_le_bytes());
        r[26..28].copy_from_slice(&(strings.len() as u16).to_le_bytes());
        r[36..40].copy_from_slice(&(str_off as u32).to_le_bytes());
        r[40..44].copy_from_slice(&(sid_b.len() as u32).to_le_bytes());
        r[44..48].copy_from_slice(&(sid_off as u32).to_le_bytes());
        r[52..56].copy_from_slice(&(len - 4).to_le_bytes());
        r.extend_from_slice(&len.to_le_bytes());
        r
    }

    pub fn header(size: u32, flags: u32) -> Vec<u8> {
        let mut h = vec![0u8; HEADER];
        h[0..4].copy_from_slice(&0x30u32.to_le_bytes());
        h[4..8].copy_from_slice(b"LfLe");
        h[8..12].copy_from_slice(&1u32.to_le_bytes());
        h[12..16].copy_from_slice(&1u32.to_le_bytes());
        h[32..36].copy_from_slice(&size.to_le_bytes());
        h[36..40].copy_from_slice(&flags.to_le_bytes());
        h[44..48].copy_from_slice(&0x30u32.to_le_bytes());
        h
    }

    #[test]
    fn reads_records_names_strings_and_wraps() {
        let t = 1_160_000_000u32; // 2006-10-04
        let logon = record_bytes(10, t, 528, 8, "Security", "XP-LAB", &["bob", "XP-LAB", "(0x0,0x3E7)", "10", "User32", "Negotiate", "XP-LAB", "-", "XP-LAB$", "WORKGROUP", "(0x0,0x3E7)", "640", "-", "192.0.2.7", "1025"]);
        let cleared = record_bytes(11, t + 60, 517, 8, "Security", "XP-LAB", &["SYSTEM", "NT AUTHORITY", "(0x0,0x3E7)", "bob", "XP-LAB", "(0x0,0x2A4F)"]);
        let mut d = header(0x10000, 1);
        d.extend(&logon);
        d.extend(&cleared);
        // An old record left in the unused part of the buffer, and one that
        // wraps: its first half at the end of the file, the rest after the header.
        let old = record_bytes(3, t - 3600, 592, 8, "Security", "XP-LAB", &["1234", "C:\\tools\\sdelete.exe", "640", "bob", "XP-LAB", "(0x0,0x2A4F)"]);
        d.extend(vec![0u8; 64]);
        d.extend(&old);
        let wrap = record_bytes(12, t + 120, 6005, 4, "EventLog", "XP-LAB", &[]);
        let half = wrap.len() / 2 / 4 * 4;
        d.resize(0x1000 - half, 0);
        d.extend(&wrap[..half]);
        // The wrapped tail overwrites the start of the buffer (after the header).
        let mut ring = d.clone();
        ring[HEADER..HEADER + wrap.len() - half].copy_from_slice(&wrap[half..]);
        let mut ev = vec![];
        let info = parse(&ring, "System", &mut |e| ev.push(e)).unwrap();
        assert!(ev.iter().any(|e| e.record_id == 12 && e.event_id == 6005), "{:?}", ev.iter().map(|e| e.record_id).collect::<Vec<_>>());
        let mut ev = vec![];
        let info2 = parse(&d, "Security", &mut |e| ev.push(e)).unwrap();
        assert!(info2.dirty && info2.records >= 3);
        let l = ev.iter().find(|e| e.record_id == 10).unwrap();
        assert_eq!((l.event_id, l.get("TargetUserName"), l.get("LogonType"), l.get("IpAddress"), l.computer.as_str(), l.provider.as_str()), (528, Some("bob"), Some("10"), Some("192.0.2.7"), "XP-LAB", "Security"));
        assert_eq!(l.user_sid.as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(l.time, unix_ft(t));
        assert_eq!(ev.iter().find(|e| e.record_id == 11).unwrap().get("SubjectUserName"), Some("bob"));
        assert_eq!(ev.iter().find(|e| e.record_id == 3).unwrap().get("NewProcessName"), Some("C:\\tools\\sdelete.exe"));
        assert!(info.records >= 1);
        assert_eq!(channel_of("SecEvent.Evt"), "Security");
        assert_eq!(channel_of("ODiag.evt"), "ODiag");
        assert!(parse(b"ElfFile\0 not this one", "x", &mut |_| {}).is_err());
    }
}
