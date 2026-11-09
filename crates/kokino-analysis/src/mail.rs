//! Email in mbox mailboxes and single .eml files: Thunderbird and other
//! Mozilla mail profiles, `/var/mail` and `/var/spool/mail` on Linux, and
//! any `.mbox`, `.mbx` or `.eml` file.
//!
//! An mbox file is messages one after another, each starting with a line
//! that begins `From `. Every message is listed with its date, sender,
//! recipients, subject and attachments; its text (plain, or HTML without
//! the markup) is decoded from quoted-printable or base64 and its charset
//! for full-text search, and so are its attachments when they are
//! documents. Thunderbird marks a message it deleted with the
//! `X-Mozilla-Status` flag 0x0008 and keeps it in the file until the folder
//! is compacted; such messages are listed and marked.
//!
//! Outlook PST and OST files (see `pst`) are mailboxes too: each message
//! is listed with its folder, and read on demand as an RFC 822 message.
//!
//! Apple Mail keeps one message per .emlx file (a byte count, the message,
//! then a property list of flags) in .mbox folders; each folder is listed
//! as one mailbox. Flag bit 1 marks a message deleted in Apple Mail.

use crate::FileRow;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek};

const MAX_MAILBOX: u64 = 512 << 20;
const MAX_MESSAGES: usize = 200_000;
const MAX_PARTS: usize = 256;
const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Attachment {
    pub name: String,
    pub content_type: String,
    /// Decoded size in bytes.
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Message {
    /// The mailbox file (index into the file list).
    pub file: u32,
    /// Where the message starts in that file, and its length.
    pub offset: u64,
    pub len: u64,
    pub date: u64,
    pub from: String,
    pub to: String,
    pub cc: String,
    pub subject: String,
    pub message_id: String,
    pub attachments: Vec<Attachment>,
    /// The first words of the text.
    pub snippet: String,
    /// Marked deleted by the mail program but still in the file (Thunderbird:
    /// not yet compacted; Apple Mail: the deleted flag).
    pub expunged: bool,
    /// The mailbox file itself is deleted.
    pub deleted: bool,
    /// The folder in a PST or OST ("Top of Personal Folders/Inbox").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub folder: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Mailbox {
    pub file: u32,
    pub path: String,
    /// "mbox", "eml", "pst", "ost" or "emlx" (an Apple Mail folder)
    pub kind: String,
    /// "Thunderbird", "Linux mail spool" or "".
    pub client: String,
    pub messages: u64,
    pub deleted: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Mail {
    pub mailboxes: Vec<Mailbox>,
    pub messages: Vec<Message>,
}

impl Mail {
    pub fn is_empty(&self) -> bool {
        self.mailboxes.is_empty()
    }
}

/// A parsed message: headers, text and attachments (with their bytes).
#[derive(Debug, Default)]
pub struct Parsed {
    pub headers: Vec<(String, String)>,
    pub text: String,
    pub attachments: Vec<(Attachment, Vec<u8>)>,
}

impl Parsed {
    pub fn header(&self, name: &str) -> String {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).unwrap_or_default()
    }
}

/// Which files are mailboxes, by path; the content is checked too.
pub fn classify(path: &str) -> Option<(&'static str, &'static str)> {
    let p = path.to_ascii_lowercase();
    let name = p.rsplit('/').next().unwrap_or("");
    if name.ends_with(".eml") {
        return Some(("eml", ""));
    }
    if name.ends_with(".pst") || name.ends_with(".ost") {
        return Some(("pst", "Outlook"));
    }
    if name.ends_with(".emlx") {
        return Some(("emlx", "Apple Mail"));
    }
    if name.ends_with(".mbox") || name.ends_with(".mbx") {
        return Some(("mbox", if p.contains("/thunderbird/") { "Thunderbird" } else { "" }));
    }
    if (p.starts_with("/var/mail/") || p.starts_with("/var/spool/mail/")) && !name.contains('.') {
        return Some(("mbox", "Linux mail spool"));
    }
    // Thunderbird (and SeaMonkey) folders: files without an extension under
    // Mail/ or ImapMail/ in a profile; .msf files are their indexes.
    let mozilla = p.contains("/thunderbird/") || p.contains("/seamonkey/") || p.contains("/.thunderbird/");
    if mozilla && (p.contains("/mail/") || p.contains("/imapmail/")) && !name.contains('.') {
        return Some(("mbox", "Thunderbird"));
    }
    None
}

fn looks_like_headers(d: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&d[..d.len().min(2048)]);
    let first = head.lines().next().unwrap_or("");
    let known = ["received:", "return-path:", "delivered-to:", "mime-version:", "date:", "from:", "to:", "subject:", "message-id:", "x-", "dkim-signature:", "reply-to:", "content-type:"];
    let lower = first.to_ascii_lowercase();
    known.iter().any(|k| lower.starts_with(k)) && head.to_ascii_lowercase().contains("\nsubject:") || lower.starts_with("subject:")
}

/// Whether the bytes are an mbox (`From ` then a header) or a single message.
pub fn detect(d: &[u8]) -> Option<&'static str> {
    if d.starts_with(b"From ") {
        let second = d.iter().position(|&c| c == b'\n').map(|i| &d[i + 1..]).unwrap_or(&[]);
        if looks_like_headers(second) {
            return Some("mbox");
        }
        return None;
    }
    looks_like_headers(d).then_some("eml")
}

/// Messages in an mbox: (offset, length), each starting at a `From ` line
/// that begins the file or follows an empty line.
pub fn split_mbox(d: &[u8]) -> Vec<(usize, usize)> {
    let mut starts = vec![];
    let mut p = 0usize;
    while p < d.len() && starts.len() < MAX_MESSAGES {
        let at_start = p == 0 || (p >= 2 && d[p - 1] == b'\n' && (d[p - 2] == b'\n' || (p >= 3 && d[p - 2] == b'\r' && d[p - 3] == b'\n')));
        if at_start && d[p..].starts_with(b"From ") {
            starts.push(p);
        }
        match d[p..].iter().position(|&c| c == b'\n') {
            Some(i) => p += i + 1,
            None => break,
        }
    }
    let mut out = vec![];
    for (k, &s) in starts.iter().enumerate() {
        let e = starts.get(k + 1).copied().unwrap_or(d.len());
        out.push((s, e - s));
    }
    out
}

fn split_head(d: &[u8]) -> (&[u8], &[u8]) {
    for (i, w) in d.windows(2).enumerate() {
        if w == b"\n\n" {
            return (&d[..i], &d[i + 2..]);
        }
        if i + 3 < d.len() && &d[i..i + 4] == b"\r\n\r\n" {
            return (&d[..i], &d[i + 4..]);
        }
    }
    (d, &[])
}

fn headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let mut out: Vec<(String, String)> = vec![];
    for line in text.lines() {
        if line.starts_with("From ") && out.is_empty() {
            continue; // the mbox separator
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = out.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if !k.is_empty() && !k.contains(' ') && out.len() < 512 {
                out.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    out
}

/// A header parameter, e.g. `boundary` or `filename` (RFC 2231 `name*=` too).
fn param(v: &str, name: &str) -> Option<String> {
    for part in v.split(';').skip(1) {
        let (k, val) = part.split_once('=')?;
        let k = k.trim().to_ascii_lowercase();
        let val = val.trim().trim_matches('"');
        if k == name {
            return Some(decode_words(val));
        }
        if k == format!("{}*", name) {
            // charset''percent-encoded
            let enc = val.splitn(3, '\'').last().unwrap_or(val);
            return Some(percent(enc));
        }
    }
    None
}

fn percent(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn charset_text(b: &[u8], charset: &str) -> String {
    let cs = charset.to_ascii_lowercase();
    if cs.contains("utf-8") || cs.contains("utf8") || cs.is_empty() || cs == "us-ascii" {
        return String::from_utf8_lossy(b).into_owned();
    }
    if cs.contains("utf-16") {
        let w: Vec<u16> = b.chunks_exact(2).map(|c| if cs.contains("be") { u16::from_be_bytes([c[0], c[1]]) } else { u16::from_le_bytes([c[0], c[1]]) }).collect();
        return String::from_utf16_lossy(&w);
    }
    // ISO-8859-1 and Windows-1252 (and, as an approximation, other 8-bit sets).
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b.iter().map(|&c| crate::oletext::cp1252(c)).collect(),
    }
}

/// RFC 2047 encoded words: =?charset?B?...?= and =?charset?Q?...?=.
pub fn decode_words(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    let mut last_was_word = false;
    while let Some(i) = rest.find("=?") {
        let before = &rest[..i];
        let after = &rest[i + 2..];
        let parts: Vec<&str> = after.splitn(3, '?').collect();
        if parts.len() == 3 {
            if let Some(end) = parts[2].find("?=") {
                let (cs, enc, data) = (parts[0], parts[1], &parts[2][..end]);
                let bytes = match enc.to_ascii_uppercase().as_str() {
                    "B" => base64(data.as_bytes()),
                    "Q" => qp(data.replace('_', " ").as_bytes()),
                    _ => None.unwrap_or_default(),
                };
                if !(last_was_word && before.trim().is_empty()) {
                    out.push_str(before);
                }
                out.push_str(&charset_text(&bytes, cs.split('*').next().unwrap_or(cs)));
                rest = &parts[2][end + 2..];
                last_was_word = true;
                continue;
            }
        }
        out.push_str(&rest[..i + 2]);
        rest = &rest[i + 2..];
        last_was_word = false;
    }
    out.push_str(rest);
    out
}

pub fn base64(d: &[u8]) -> Vec<u8> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::with_capacity(d.len() * 3 / 4);
    let (mut acc, mut n) = (0u32, 0u32);
    for &c in d {
        if c == b'=' {
            break;
        }
        let Some(v) = val(c) else { continue };
        acc = acc << 6 | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
            acc &= (1 << n) - 1;
        }
    }
    out
}

pub fn qp(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(d.len());
    let mut i = 0;
    while i < d.len() {
        if d[i] == b'=' {
            if d.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if d.get(i + 1) == Some(&b'\r') && d.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
            if let Some(v) = d.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(d[i]);
        i += 1;
    }
    out
}

fn body_bytes(body: &[u8], cte: &str) -> Vec<u8> {
    match cte.to_ascii_lowercase().as_str() {
        "base64" => base64(body),
        "quoted-printable" => qp(body),
        _ => body.to_vec(),
    }
}

/// Headers, text and attachments of one message (an mbox `From ` line
/// before it is ignored).
pub fn parse(raw: &[u8]) -> Parsed {
    let mut p = Parsed::default();
    let (head, body) = split_head(raw);
    p.headers = headers(head);
    let mut parts = 0usize;
    walk(&p.headers.clone(), body, &mut p, 0, &mut parts);
    p
}

fn walk(h: &[(String, String)], body: &[u8], out: &mut Parsed, depth: usize, parts: &mut usize) {
    *parts += 1;
    if depth > MAX_DEPTH || *parts > MAX_PARTS {
        return;
    }
    let get = |n: &str| h.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str()).unwrap_or("");
    let ct = get("Content-Type");
    let ctl = ct.to_ascii_lowercase();
    let mime = ctl.split(';').next().unwrap_or("").trim().to_string();
    let cte = get("Content-Transfer-Encoding").trim().to_string();
    let cd = get("Content-Disposition");
    if mime.starts_with("multipart/") {
        let Some(b) = param(ct, "boundary") else { return };
        let delim = format!("--{}", b);
        let text = body;
        let mut pieces = vec![];
        let mut i = 0usize;
        while let Some(f) = find(text, delim.as_bytes(), i) {
            pieces.push(f);
            i = f + delim.len();
            if pieces.len() > MAX_PARTS {
                break;
            }
        }
        for w in pieces.windows(2) {
            let mut s = w[0] + delim.len();
            // Skip the rest of the boundary line.
            while s < w[1] && text[s] != b'\n' {
                s += 1;
            }
            let part = &text[(s + 1).min(w[1])..w[1]];
            let (ph, pb) = split_head(part);
            walk(&headers(ph), pb, out, depth + 1, parts);
        }
        return;
    }
    if mime == "message/rfc822" {
        let inner = body_bytes(body, &cte);
        let (ih, ib) = split_head(&inner);
        let hh = headers(ih);
        let subj = hh.iter().find(|(k, _)| k.eq_ignore_ascii_case("Subject")).map(|(_, v)| decode_words(v)).unwrap_or_default();
        out.text.push_str(&format!("\n[attached message: {}]\n", subj));
        if cd.to_ascii_lowercase().starts_with("attachment") {
            // An attached message is an attachment of its own (exported as
            // .eml); its text is searched with the message.
            let mut sub = Parsed::default();
            walk(&hh, ib, &mut sub, depth + 1, parts);
            out.text.push_str(sub.text.trim());
            let name = param(cd, "filename").or_else(|| param(ct, "name")).unwrap_or_else(|| format!("{}.eml", if subj.is_empty() { "message" } else { &subj }));
            out.attachments.push((Attachment { name, content_type: mime, size: inner.len() as u64 }, inner));
            return;
        }
        walk(&hh, ib, out, depth + 1, parts);
        return;
    }
    let filename = param(cd, "filename").or_else(|| param(ct, "name"));
    let attachment = cd.to_ascii_lowercase().starts_with("attachment") || filename.is_some() && !mime.starts_with("text/");
    let data = body_bytes(body, &cte);
    if attachment || !(mime.is_empty() || mime.starts_with("text/")) {
        let name = filename.unwrap_or_else(|| format!("(unnamed {})", if mime.is_empty() { "part" } else { &mime }));
        out.attachments.push((Attachment { name, content_type: mime, size: data.len() as u64 }, data));
        return;
    }
    let charset = param(ct, "charset").unwrap_or_default();
    let text = charset_text(&data, &charset);
    let text = if mime == "text/html" { crate::doctext::xml_text(&text) } else { text };
    if out.text.len() < 8 << 20 {
        if !out.text.is_empty() {
            out.text.push('\n');
        }
        out.text.push_str(text.trim());
    }
}

fn find(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if n.is_empty() || from >= h.len() {
        return None;
    }
    h[from..].windows(n.len()).position(|w| w == n).map(|i| i + from)
}

fn date(s: &str) -> u64 {
    let s = s.trim();
    // Drop a trailing "(CEST)" comment, which the parser does not take.
    let s = s.split(" (").next().unwrap_or(s);
    chrono::DateTime::parse_from_rfc2822(s).map(|d| kokino_core::time::datetime_to_filetime(d.with_timezone(&chrono::Utc))).unwrap_or(0)
}

/// The message summary Kokino lists.
pub fn summary(raw: &[u8], file: u32, offset: u64, deleted: bool) -> Message {
    let p = parse(raw);
    let mozilla = u32::from_str_radix(p.header("X-Mozilla-Status").trim(), 16).unwrap_or(0);
    let snippet: String = p.text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(240).collect();
    Message {
        file,
        offset,
        len: raw.len() as u64,
        date: date(&p.header("Date")),
        from: decode_words(&p.header("From")),
        to: decode_words(&p.header("To")),
        cc: decode_words(&p.header("Cc")),
        subject: decode_words(&p.header("Subject")),
        message_id: p.header("Message-ID"),
        attachments: p.attachments.iter().map(|(a, _)| a.clone()).collect(),
        snippet,
        expunged: mozilla & 0x0008 != 0,
        deleted,
        folder: String::new(),
    }
}

/// Every message in a mailbox file (an mbox, or one message).
pub fn messages(d: &[u8], kind: &str, file: u32, deleted: bool) -> Vec<Message> {
    if kind == "eml" || !d.starts_with(b"From ") {
        return vec![summary(d, file, 0, deleted)];
    }
    split_mbox(d).into_iter().map(|(o, n)| summary(&d[o..o + n], file, o as u64, deleted)).collect()
}

pub fn collect<R: Read + Seek>(fs: &crate::fs::Fs, r: &mut R, files: &[FileRow], progress: crate::Progress) -> Mail {
    let mut out = Mail::default();
    let cand: Vec<(usize, &str, &str)> = files.iter().enumerate().filter(|(_, f)| !f.e.is_dir && f.e.size > 0).filter_map(|(i, f)| classify(&f.e.path).map(|(k, c)| (i, k, c))).collect();
    let total = cand.len() as u64;
    for (n, (i, kind, client)) in cand.into_iter().enumerate() {
        progress("Email", n as u64, total);
        let f = &files[i];
        let mut mb = Mailbox { file: i as u32, path: f.e.path.clone(), kind: kind.into(), client: client.into(), deleted: f.e.deleted, ..Default::default() };
        if kind == "emlx" {
            // One message per file; the folder (INBOX.mbox) is the mailbox.
            let Ok(d) = fs.read(r, &f.e, "", 0, f.e.size.min(MAX_MAILBOX) as usize) else { continue };
            let Some((offset, len, flags)) = emlx(&d) else { continue };
            let folder = emlx_folder(&f.e.path);
            let mut m = summary(&d[offset..offset + len], i as u32, offset as u64, f.e.deleted);
            m.expunged = flags & 2 != 0;
            m.folder = folder.clone();
            match out.mailboxes.iter_mut().find(|b| b.kind == "emlx" && b.path == folder) {
                Some(b) => b.messages += 1,
                None => out.mailboxes.push(Mailbox { file: i as u32, path: folder, kind: "emlx".into(), client: "Apple Mail".into(), messages: 1, deleted: false, error: None }),
            }
            if out.messages.len() < MAX_MESSAGES {
                out.messages.push(m);
            }
            continue;
        }
        if kind == "pst" {
            // Read in place, block by block: PST files are often large.
            let left = MAX_MESSAGES.saturating_sub(out.messages.len());
            match pst_messages(fs, r, f, i as u32, left) {
                Ok((k, msgs)) => {
                    mb.kind = k.into();
                    mb.messages = msgs.len() as u64;
                    out.messages.extend(msgs);
                }
                Err(e) => {
                    if !crate::pst::is_pst(&fs.read(r, &f.e, "", 0, 16).unwrap_or_default()) {
                        continue;
                    }
                    mb.error = Some(format!("{:#}", e));
                }
            }
            out.mailboxes.push(mb);
            continue;
        }
        if f.e.size > MAX_MAILBOX {
            mb.error = Some(format!("{} bytes; larger than the {} byte limit", f.e.size, MAX_MAILBOX));
            out.mailboxes.push(mb);
            continue;
        }
        let d = match fs.read(r, &f.e, "", 0, f.e.size as usize) {
            Ok(d) => d,
            Err(e) => {
                mb.error = Some(format!("{:#}", e));
                out.mailboxes.push(mb);
                continue;
            }
        };
        let Some(found) = detect(&d) else { continue };
        let kind = if kind == "eml" { "eml" } else { found };
        mb.kind = kind.into();
        let msgs = messages(&d, kind, i as u32, f.e.deleted);
        mb.messages = msgs.len() as u64;
        if out.messages.len() < MAX_MESSAGES {
            out.messages.extend(msgs);
        }
        out.mailboxes.push(mb);
    }
    progress("Email", total, total);
    out.messages.sort_by_key(|m| m.date);
    out
}

/// An Apple Mail .emlx file: (message offset, length, flags).
pub fn emlx(d: &[u8]) -> Option<(usize, usize, u64)> {
    let nl = d.iter().take(16).position(|&c| c == b'\n')?;
    let len: usize = std::str::from_utf8(&d[..nl]).ok()?.trim().parse().ok()?;
    let start = nl + 1;
    let end = start.checked_add(len)?.min(d.len());
    let flags = kokino_artifacts::plist::parse(&d[end..]).and_then(|v| v.get("flags").and_then(|x| x.int())).unwrap_or(0) as u64;
    Some((start, end - start, flags))
}

/// The Apple Mail folder an .emlx file belongs to: the path up to its
/// ".mbox" folder (the Messages folders below it are Mail's own).
fn emlx_folder(path: &str) -> String {
    match path.find(".mbox/") {
        Some(i) => path[..i + 5].to_string(),
        None => path.rsplit_once('/').map(|x| x.0.to_string()).unwrap_or_default(),
    }
}

/// The messages of a PST or OST file, read through the file system.
fn pst_messages<R: Read + Seek>(fs: &crate::fs::Fs, r: &mut R, f: &FileRow, file: u32, max: usize) -> anyhow::Result<(&'static str, Vec<Message>)> {
    let mut p = crate::pst::Pst::open(crate::fs::stream(fs, r, &f.e), f.e.size)?;
    let folders: std::collections::HashMap<u32, String> = p.folders().into_iter().map(|x| (x.nid, x.path)).collect();
    let mut out = vec![];
    for nid in p.message_ids().into_iter().take(max) {
        let parent = p.nodes.get(&nid).map(|n| n.parent).unwrap_or(0);
        let Ok((m, _)) = p.message(nid) else { continue };
        let snippet: String = m.text().split_whitespace().collect::<Vec<_>>().join(" ").chars().take(240).collect();
        out.push(Message {
            file,
            offset: nid as u64,
            len: 0,
            date: m.date,
            from: m.from,
            to: m.to,
            cc: m.cc,
            subject: m.subject,
            message_id: m.message_id,
            attachments: m.attachments.iter().map(|a| Attachment { name: if a.embedded && !a.name.to_ascii_lowercase().ends_with(".eml") { format!("{}.eml", a.name) } else { a.name.clone() }, content_type: if a.embedded { "message/rfc822".into() } else { a.mime.clone() }, size: a.size }).collect(),
            snippet,
            expunged: false,
            deleted: f.e.deleted,
            folder: folders.get(&parent).cloned().unwrap_or_else(|| "(folder not found)".into()),
        });
    }
    Ok((if p.ost { "ost" } else { "pst" }, out))
}

/// Timeline events (kind MAIL): one per dated message.
pub fn timeline(m: &Mail) -> Vec<crate::windows::WinTime> {
    m.messages
        .iter()
        .filter(|x| x.date > 0)
        .map(|x| crate::windows::WinTime {
            t: x.date,
            kind: "MAIL".into(),
            what: if x.subject.is_empty() { "(no subject)".into() } else { x.subject.clone() },
            detail: format!("email from {} to {}{}{}", x.from, x.to, if x.attachments.is_empty() { String::new() } else { format!(", {} attachment(s)", x.attachments.len()) }, if x.expunged { ", marked deleted in the mail program" } else { "" }),
        })
        .collect()
}

pub fn impact(m: &Mail) -> Vec<String> {
    if m.messages.is_empty() {
        return vec![];
    }
    let att: usize = m.messages.iter().map(|x| x.attachments.len()).sum();
    let exp = m.messages.iter().filter(|x| x.expunged).count();
    let dates: Vec<u64> = m.messages.iter().map(|x| x.date).filter(|&t| t > 0).collect();
    let day = |t: u64| kokino_core::time::filetime_to_iso(t).chars().take(10).collect::<String>();
    let mut s = format!(
        "{} email message(s) in {} mailbox(es){}, with {} attachment(s)",
        m.messages.len(),
        m.mailboxes.iter().filter(|b| b.messages > 0).count(),
        match (dates.iter().min(), dates.iter().max()) {
            (Some(a), Some(b)) => format!(", from {} to {}", day(*a), day(*b)),
            _ => String::new(),
        },
        att
    );
    if exp > 0 {
        s.push_str(&format!("; {} marked deleted by the mail program (Thunderbird, Apple Mail) but still in the mailbox", exp));
    }
    vec![s + "."]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn mbox() -> Vec<u8> {
        let a = "From alice@lab.test Tue Oct 20 10:05:30 2026\r\n\
Return-Path: <alice@lab.test>\r\n\
Date: Tue, 20 Oct 2026 10:05:30 +0200\r\n\
From: Alice <alice@lab.test>\r\n\
To: bob@lab.test\r\n\
Subject: =?UTF-8?B?UTMgcGxhbiDigJMgY29uZmlkZW50aWFs?=\r\n\
Message-ID: <1@lab.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"XYZ\"\r\n\
\r\n\
--XYZ\r\n\
Content-Type: text/plain; charset=iso-8859-1\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Move the funds to the caf=E9 account to=\r\n\
night.\r\n\
--XYZ\r\n\
Content-Type: application/pdf; name=\"ledger.pdf\"\r\n\
Content-Disposition: attachment; filename=\"ledger.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQKJcOkw7w=\r\n\
--XYZ--\r\n\
\r\n";
        let b = "From bob@lab.test Wed Oct 21 09:00:00 2026\n\
X-Mozilla-Status: 0009\n\
Date: Wed, 21 Oct 2026 09:00:00 +0000\n\
From: bob@lab.test\n\
To: Alice <alice@lab.test>\n\
Subject: Re: wipe the laptop\n\
Content-Type: text/html; charset=utf-8\n\
\n\
<p>Done. Used <b>sdelete</b> on everything.</p>\n\
>From the desk of bob\n";
        format!("{}{}", a, b).into_bytes()
    }

    #[test]
    fn mbox_messages_mime_and_flags() {
        let d = mbox();
        assert_eq!(detect(&d), Some("mbox"));
        let m = messages(&d, "mbox", 3, false);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].subject, "Q3 plan \u{2013} confidential");
        assert_eq!((m[0].from.as_str(), m[0].to.as_str()), ("Alice <alice@lab.test>", "bob@lab.test"));
        assert_eq!(kokino_core::time::filetime_to_iso(m[0].date), "2026-10-20T08:05:30.0000000Z");
        assert_eq!(m[0].attachments, vec![Attachment { name: "ledger.pdf".into(), content_type: "application/pdf".into(), size: 14 }]);
        assert_eq!(m[0].snippet, "Move the funds to the caf\u{e9} account tonight.");
        assert!(!m[0].expunged);
        assert_eq!(m[1].snippet, "Done. Used sdelete on everything. >From the desk of bob");
        assert!(m[1].expunged);
        assert_eq!(m[1].offset as usize, d.windows(9).position(|w| w == b"From bob@").unwrap());
        let p = parse(&d[..m[0].len as usize]);
        assert_eq!(p.attachments[0].1, b"%PDF-1.4\n%\xc3\xa4\xc3\xbc");
        // A single message file.
        let eml = &d[m[1].offset as usize + m[1].len as usize - (m[1].len as usize)..];
        let eml = &eml[eml.iter().position(|&c| c == b'\n').unwrap() + 1..];
        assert_eq!(detect(eml), Some("eml"));
        assert_eq!(messages(eml, "eml", 1, true)[0].subject, "Re: wipe the laptop");
        assert_eq!(classify("/Users/alice/AppData/Roaming/Thunderbird/Profiles/x.default/Mail/Local Folders/Inbox"), Some(("mbox", "Thunderbird")));
        assert!(classify("/Users/alice/AppData/Roaming/Thunderbird/Profiles/x.default/Mail/Local Folders/Inbox.msf").is_none());
        assert_eq!(classify("/var/mail/alice"), Some(("mbox", "Linux mail spool")));
        assert!(detect(b"From here on, this is a text file.\nNot mail.").is_none());
        assert_eq!(decode_words("=?iso-8859-1?Q?caf=E9?= =?utf-8?B?4oKs?="), "caf\u{e9}\u{20ac}");
    }
}
