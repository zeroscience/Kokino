//! Scheduled tasks: the task files under `Windows\System32\Tasks` and what
//! the Task Scheduler keeps about each task in the registry.
//!
//! A task file is XML (UTF-16 with a byte-order mark, as Windows writes it,
//! or UTF-8): who registered it and when, the account it runs as, its
//! triggers and its actions. The registry (SOFTWARE\Microsoft\Windows
//! NT\CurrentVersion\Schedule\TaskCache) holds a copy of each task's
//! actions in a binary form and, in `DynamicInfo`, when the task was
//! created and when it last ran, which the file does not record.
//!
//! The XML reader here handles the machine-written task format only:
//! elements, attributes it does not need, character entities. It is not a
//! general XML parser and never resolves anything outside the text.

use crate::bin::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Action {
    /// "Exec", "COM handler", "Email" or "Message"
    pub kind: String,
    pub command: String,
    pub arguments: String,
    pub working_dir: String,
    /// COM handler class id
    pub clsid: String,
}

impl Action {
    /// What runs, in one line.
    pub fn summary(&self) -> String {
        match self.kind.as_str() {
            "Exec" if self.arguments.is_empty() => self.command.clone(),
            "Exec" => format!("{} {}", self.command, self.arguments),
            "COM handler" if self.arguments.is_empty() => format!("COM handler {}", self.clsid),
            "COM handler" => format!("COM handler {} ({})", self.clsid, self.arguments),
            k => k.to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Task {
    pub uri: String,
    pub author: String,
    pub description: String,
    /// RegistrationInfo/Date as written (local time, usually without a zone)
    pub date: String,
    /// Principal UserId or GroupId (a name or a SID)
    pub user: String,
    pub logon_type: String,
    /// "HighestAvailable" or "LeastPrivilege"
    pub run_level: String,
    /// Settings/Hidden: not shown in Task Scheduler unless "Show hidden tasks" is on
    pub hidden: bool,
    pub enabled: bool,
    /// One line per trigger, for example "at logon" or "daily from 2026-10-21T02:00:00"
    pub triggers: Vec<String>,
    pub actions: Vec<Action>,
}

/// Most bytes of task XML read.
const MAX_XML: usize = 1 << 20;

/// Parses a task file.
pub fn parse_xml(d: &[u8]) -> anyhow::Result<Task> {
    let s = decode(&d[..d.len().min(MAX_XML)]);
    let Some(root) = element(&s, "Task") else { anyhow::bail!("not a task file (no <Task> element)") };
    let reg = element(root, "RegistrationInfo").unwrap_or("");
    let settings = element(root, "Settings").unwrap_or("");
    let principal = element(root, "Principals").and_then(|p| element(p, "Principal")).unwrap_or("");
    let mut t = Task {
        uri: text(reg, "URI"),
        author: text(reg, "Author"),
        description: text(reg, "Description"),
        date: text(reg, "Date"),
        user: Some(text(principal, "UserId")).filter(|u| !u.is_empty()).unwrap_or_else(|| text(principal, "GroupId")),
        logon_type: text(principal, "LogonType"),
        run_level: text(principal, "RunLevel"),
        hidden: text(settings, "Hidden").eq_ignore_ascii_case("true"),
        enabled: !text(settings, "Enabled").eq_ignore_ascii_case("false"),
        ..Default::default()
    };
    if let Some(trs) = element(root, "Triggers") {
        for (name, body) in children(trs) {
            if let Some(line) = trigger(name, body) {
                t.triggers.push(line);
            }
        }
    }
    if let Some(acts) = element(root, "Actions") {
        for (name, body) in children(acts) {
            let a = match name {
                "Exec" => Action { kind: "Exec".into(), command: text(body, "Command"), arguments: text(body, "Arguments"), working_dir: text(body, "WorkingDirectory"), ..Default::default() },
                "ComHandler" => Action { kind: "COM handler".into(), clsid: text(body, "ClassId"), arguments: text(body, "Data"), ..Default::default() },
                "SendEmail" => Action { kind: "Email".into(), ..Default::default() },
                "ShowMessage" => Action { kind: "Message".into(), ..Default::default() },
                _ => continue,
            };
            t.actions.push(a);
        }
    }
    Ok(t)
}

fn trigger(name: &str, body: &str) -> Option<String> {
    let start = text(body, "StartBoundary");
    let from = if start.is_empty() { String::new() } else { format!(" from {}", start) };
    let mut line = match name {
        "BootTrigger" => "at startup".to_string(),
        "LogonTrigger" => match text(body, "UserId") {
            u if u.is_empty() => "at logon of any user".into(),
            u => format!("at logon of {}", u),
        },
        "TimeTrigger" if start.is_empty() => "once".into(),
        "TimeTrigger" => format!("once at {}", start),
        "CalendarTrigger" => {
            let how = if element(body, "ScheduleByDay").is_some() {
                match text(element(body, "ScheduleByDay").unwrap_or(""), "DaysInterval").as_str() {
                    "" | "1" => "daily".to_string(),
                    n => format!("every {} days", n),
                }
            } else if element(body, "ScheduleByWeek").is_some() {
                "weekly".into()
            } else {
                "monthly".into()
            };
            format!("{}{}", how, from)
        }
        "IdleTrigger" => "when the computer is idle".into(),
        "RegistrationTrigger" => "when registered".into(),
        "SessionStateChangeTrigger" => format!("on session change ({})", text(body, "StateChange")),
        "EventTrigger" => {
            let q = text(body, "Subscription");
            let q: String = q.chars().take(160).collect();
            format!("on event {}", q)
        }
        "WnfStateChangeTrigger" => "on a WNF state change".into(),
        _ => return None,
    };
    if let Some(rep) = element(body, "Repetition") {
        let iv = text(rep, "Interval");
        if !iv.is_empty() {
            line.push_str(&format!(", repeated every {}", duration(&iv)));
        }
    }
    let delay = text(body, "Delay");
    if !delay.is_empty() {
        line.push_str(&format!(", after {}", duration(&delay)));
    }
    if text(body, "Enabled").eq_ignore_ascii_case("false") {
        line.push_str(" (disabled)");
    }
    Some(line)
}

/// "PT5M" -> "5 min", "P1D" -> "1 day"; anything else as written.
fn duration(iso: &str) -> String {
    let Some(rest) = iso.strip_prefix('P') else { return iso.to_string() };
    let mut out = vec![];
    let mut num = String::new();
    let mut time = false;
    for c in rest.chars() {
        match c {
            'T' => time = true,
            '0'..='9' | '.' => num.push(c),
            u => {
                let unit = match (u, time) {
                    ('D', false) => "day",
                    ('W', false) => "week",
                    ('M', false) => "month",
                    ('Y', false) => "year",
                    ('H', true) => "h",
                    ('M', true) => "min",
                    ('S', true) => "s",
                    _ => return iso.to_string(),
                };
                let plural = if unit.len() > 3 && num != "1" { "s" } else { "" };
                out.push(format!("{} {}{}", num, unit, plural));
                num.clear();
            }
        }
    }
    if out.is_empty() { iso.to_string() } else { out.join(" ") }
}

fn decode(d: &[u8]) -> String {
    if let Some(b) = d.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(b);
    }
    // UTF-16 without a byte-order mark: '<' then a zero byte.
    if d.len() >= 2 && d[0] == b'<' && d[1] == 0 {
        return utf16(d);
    }
    let d = d.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(d);
    String::from_utf8_lossy(d).into_owned()
}

/// The content of the first `<tag ...>...</tag>` element (empty for `<tag/>`).
fn element<'s>(s: &'s str, tag: &str) -> Option<&'s str> {
    let mut from = 0;
    while let Some(i) = s[from..].find('<').map(|i| i + from) {
        let rest = &s[i + 1..];
        if let Some(after) = rest.strip_prefix(tag) {
            match after.chars().next() {
                Some('>') | Some(' ') | Some('\t') | Some('\r') | Some('\n') | Some('/') => {
                    let close = after.find('>')?;
                    if after[..close].ends_with('/') {
                        return Some("");
                    }
                    let start = i + 1 + tag.len() + close + 1;
                    let end = s[start..].find(&format!("</{}>", tag))?;
                    return Some(&s[start..start + end]);
                }
                _ => {}
            }
        }
        from = i + 1;
    }
    None
}

/// The direct child elements of a fragment: (name, content).
fn children(s: &str) -> Vec<(&str, &str)> {
    let mut out = vec![];
    let mut at = 0;
    while let Some(i) = s[at..].find('<').map(|i| i + at) {
        let rest = &s[i + 1..];
        if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
            at = i + 1;
            continue;
        }
        let name_len = rest.find(|c: char| c == '>' || c == '/' || c.is_whitespace()).unwrap_or(rest.len());
        let name = &rest[..name_len];
        let Some(close) = rest.find('>') else { break };
        if rest[..close].ends_with('/') {
            out.push((name, ""));
            at = i + 1 + close + 1;
            continue;
        }
        let start = i + 1 + close + 1;
        let end_tag = format!("</{}>", name);
        let Some(end) = s[start..].find(&end_tag) else { break };
        out.push((name, &s[start..start + end]));
        at = start + end + end_tag.len();
        if out.len() >= 64 {
            break;
        }
    }
    out
}

/// Text of the first `<tag>` element, entities decoded and trimmed.
fn text(s: &str, tag: &str) -> String {
    element(s, tag).map(|t| unescape(t.trim())).unwrap_or_default()
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|&e| e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let c = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => ent
                .strip_prefix("#x")
                .or_else(|| ent.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| ent.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match c {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// TaskCache\Tasks\{id}\DynamicInfo: when the task was created and last ran.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicInfo {
    pub created: u64,
    pub last_run: u64,
    /// Windows 10 and later only
    pub last_success: u64,
    pub state: u32,
    /// Result of the last run (0 = success, or an HRESULT)
    pub last_error: u32,
}

/// Version (u32), created, last run (FILETIMEs), state, last error (u32);
/// 36-byte records (Windows 10 and later) add the last successful run.
pub fn dynamic_info(b: &[u8]) -> Option<DynamicInfo> {
    if b.len() < 28 {
        return None;
    }
    Some(DynamicInfo {
        created: plausible(u64_at(b, 4)?),
        last_run: plausible(u64_at(b, 12)?),
        state: u32_at(b, 20)?,
        last_error: u32_at(b, 24)?,
        last_success: if b.len() >= 36 { plausible(u64_at(b, 28)?) } else { 0 },
    })
}

/// TaskCache\Tasks\{id}\Actions: a version (u16; 3 on Windows 8 and
/// later, which adds the context the actions run in), then the actions,
/// each led by a u16 signature (0x6666 run a program, 0x7777 COM handler,
/// 0x8888 email, 0x9999 message box) with length-prefixed UTF-16 strings.
/// Returns the context (an account or principal id, empty before version 3)
/// and the actions read before anything unexpected.
pub fn actions_blob(b: &[u8]) -> (String, Vec<Action>) {
    let mut out = vec![];
    let Some(version) = u16_at(b, 0) else { return (String::new(), out) };
    let mut p = 2usize;
    let mut context = String::new();
    if version >= 2 {
        match string(b, &mut p) {
            Some(s) => context = s,
            None => return (context, out),
        }
    }
    while out.len() < 32 {
        let Some(sig) = u16_at(b, p) else { break };
        p += 2;
        let a = match sig {
            0x6666 => (|| {
                let _id = string(b, &mut p)?;
                let command = string(b, &mut p)?;
                let arguments = string(b, &mut p)?;
                let working_dir = string(b, &mut p)?;
                if version >= 3 {
                    p += 2; // flags
                }
                Some(Action { kind: "Exec".into(), command, arguments, working_dir, ..Default::default() })
            })(),
            0x7777 => (|| {
                let _id = string(b, &mut p)?;
                let clsid = guid(slice(b, p, 16)?);
                p += 16;
                let data = string(b, &mut p)?;
                Some(Action { kind: "COM handler".into(), clsid, arguments: data, ..Default::default() })
            })(),
            // Email and message box actions are deprecated and rare; their
            // layout is not decoded, so nothing after them is read.
            0x8888 => {
                out.push(Action { kind: "Email".into(), ..Default::default() });
                break;
            }
            0x9999 => {
                out.push(Action { kind: "Message".into(), ..Default::default() });
                break;
            }
            _ => None,
        };
        match a {
            Some(a) => out.push(a),
            None => break,
        }
    }
    (context, out)
}

/// A u32 byte count, then that many bytes of UTF-16.
fn string(b: &[u8], p: &mut usize) -> Option<String> {
    let n = u32_at(b, *p)? as usize;
    if n > 0x10000 || !n.is_multiple_of(2) {
        return None;
    }
    let s = slice(b, *p + 4, n)?;
    *p += 4 + n;
    Some(utf16(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_bom(s: &str) -> Vec<u8> {
        let mut v = vec![0xFF, 0xFE];
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-10-21T02:16:40</Date>
    <Author>LAB-PC\alice</Author>
    <Description>Keeps the &quot;updater&quot; &amp; friends running</Description>
    <URI>\Updater\Check</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>LAB-PC\alice</UserId></LogonTrigger>
    <CalendarTrigger>
      <Repetition><Interval>PT5M</Interval></Repetition>
      <StartBoundary>2026-10-21T02:20:00</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
    <BootTrigger><Enabled>false</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings><Hidden>true</Hidden><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec><Command>C:\Users\Public\updsvc.exe</Command><Arguments>-silent &gt; nul</Arguments></Exec>
    <ComHandler><ClassId>{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}</ClassId></ComHandler>
  </Actions>
</Task>"#;

    #[test]
    fn task_xml() {
        let t = parse_xml(&utf16_bom(XML)).unwrap();
        assert_eq!(t.uri, r"\Updater\Check");
        assert_eq!(t.author, r"LAB-PC\alice");
        assert_eq!(t.description, "Keeps the \"updater\" & friends running");
        assert_eq!(t.date, "2026-10-21T02:16:40");
        assert_eq!(t.user, "S-1-5-18");
        assert_eq!(t.run_level, "HighestAvailable");
        assert!(t.hidden && t.enabled);
        assert_eq!(t.triggers, vec![r"at logon of LAB-PC\alice".to_string(), "daily from 2026-10-21T02:20:00, repeated every 5 min".into(), "at startup (disabled)".into()]);
        assert_eq!(t.actions.len(), 2);
        assert_eq!(t.actions[0].summary(), r"C:\Users\Public\updsvc.exe -silent > nul");
        assert_eq!(t.actions[1].clsid, "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}");
        // The same file in UTF-8.
        assert_eq!(parse_xml(XML.as_bytes()).unwrap(), t);
        assert!(parse_xml(b"<html></html>").is_err());
        assert_eq!(duration("P1DT2H"), "1 day 2 h");
        assert_eq!(duration("bogus"), "bogus");
    }

    fn s16(s: &str) -> Vec<u8> {
        let b: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut v = (b.len() as u32).to_le_bytes().to_vec();
        v.extend(b);
        v
    }

    #[test]
    fn cache_blobs() {
        let mut b = 3u16.to_le_bytes().to_vec();
        b.extend(s16("Author"));
        b.extend(0x6666u16.to_le_bytes());
        b.extend(s16(""));
        b.extend(s16(r"C:\Users\Public\updsvc.exe"));
        b.extend(s16("-silent"));
        b.extend(s16(""));
        b.extend(0u16.to_le_bytes());
        b.extend(0x7777u16.to_le_bytes());
        b.extend(s16(""));
        b.extend([0x9F, 0x36, 0x87, 0x0F, 0xE5, 0xA4, 0xFC, 0x4C, 0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD]);
        b.extend(s16("data"));
        let (ctx, a) = actions_blob(&b);
        assert_eq!(ctx, "Author");
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].summary(), r"C:\Users\Public\updsvc.exe -silent");
        assert_eq!(a[1].clsid, "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}");
        // Cut short: what was read stays.
        assert_eq!(actions_blob(&b[..b.len() - 3]).1.len(), 1);
        assert!(actions_blob(&[]).1.is_empty());

        let mut d = vec![0u8; 36];
        d[0] = 3;
        let t = 133_740_000_000_000_000u64;
        d[4..12].copy_from_slice(&t.to_le_bytes());
        d[12..20].copy_from_slice(&(t + 1).to_le_bytes());
        d[24..28].copy_from_slice(&0x8007_0002u32.to_le_bytes());
        d[28..36].copy_from_slice(&(t + 2).to_le_bytes());
        let i = dynamic_info(&d).unwrap();
        assert_eq!((i.created, i.last_run, i.last_success, i.last_error), (t, t + 1, t + 2, 0x8007_0002));
        assert_eq!(dynamic_info(&d[..28]).unwrap().last_success, 0);
        assert!(dynamic_info(&d[..20]).is_none());
    }
}
