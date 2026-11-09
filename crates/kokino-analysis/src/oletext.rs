//! Text of legacy Office files and RTF, for the full-text index.
//!
//! - Word 97-2003 (.doc): the document text through the piece table (the
//!   FIB points at it in the 0Table or 1Table stream), each piece either
//!   8-bit (Windows-1252) or UTF-16, with field codes dropped and field
//!   results kept.
//! - Excel 97-2003 (.xls): the shared string table (with strings split over
//!   CONTINUE records), older LABEL cells and the sheet names.
//! - PowerPoint 97-2003 (.ppt): every text atom (slides, notes, outlines).
//! - Outlook .msg: every text property (subject, body, sender, recipients,
//!   attachment names).
//! - Any OLE file: the document properties (title, subject, author,
//!   keywords, comments, last saved by).
//! - RTF: the text, with \\'hh and \\u escapes decoded and font tables,
//!   pictures and other non-text groups skipped.
//!
//! Encrypted Word and Excel files are reported, not guessed. Every read is
//! bounded by the input; nothing here allocates more than a small multiple
//! of the stream it reads.

use kokino_artifacts::bin::{u16_at, u32_at, utf16};
use kokino_artifacts::cfb;

/// Most bytes kept from one OLE stream.
const MAX_STREAM: usize = 64 << 20;
const MAX_TEXT: usize = 32 << 20;

pub struct Out {
    pub parts: Vec<(String, String)>,
    pub notes: Vec<String>,
}

/// Windows-1252 byte to char.
pub fn cp1252(b: u8) -> char {
    const HI: [u16; 32] = [
        0x20AC, 0x81, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8D, 0x017D, 0x8F, 0x90, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x9D, 0x017E, 0x0178,
    ];
    if (0x80..0xA0).contains(&b) {
        char::from_u32(HI[(b - 0x80) as usize] as u32).unwrap_or(' ')
    } else {
        b as char
    }
}

fn utf16_n(b: &[u8]) -> String {
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&w)
}

pub fn ole(data: &[u8]) -> Out {
    let mut out = Out { parts: vec![], notes: vec![] };
    let streams = match cfb::streams(data, MAX_STREAM) {
        Ok(s) => s,
        Err(e) => {
            out.notes.push(format!("OLE file could not be read: {}", e));
            return out;
        }
    };
    // Top-level streams only (embedded objects have their own).
    let get = |name: &str| streams.iter().find(|s| s.name.eq_ignore_ascii_case(name)).map(|s| &s.data[..]);
    if let Some(wd) = get("WordDocument") {
        match word(wd, get("0Table"), get("1Table")) {
            Ok(t) => out.parts.push(("document".into(), t)),
            Err(e) => out.notes.push(format!("Word document: {}", e)),
        }
    }
    if let Some(wb) = get("Workbook").or_else(|| get("Book")) {
        match excel(wb) {
            Ok(t) => out.parts.push(("workbook".into(), t)),
            Err(e) => out.notes.push(format!("Excel workbook: {}", e)),
        }
    }
    if let Some(pp) = get("PowerPoint Document") {
        out.parts.push(("presentation".into(), powerpoint(pp)));
    }
    // Outlook .msg: text properties (type 001F UTF-16, 001E 8-bit).
    let mut msg = vec![];
    for s in streams.iter().filter(|s| s.name.rsplit('/').next().is_some_and(|n| n.starts_with("__substg1.0_"))) {
        let n = s.name.rsplit('/').next().unwrap_or("");
        let text = match n.get(n.len().saturating_sub(4)..) {
            Some("001F") => utf16(&s.data),
            Some("001E") => s.data.iter().take_while(|&&b| b != 0).map(|&b| cp1252(b)).collect(),
            _ => continue,
        };
        if !text.trim().is_empty() {
            msg.push(text);
        }
    }
    if !msg.is_empty() {
        out.parts.push(("message".into(), msg.join("\n")));
    }
    for (name, label) in [("\u{5}SummaryInformation", "properties"), ("\u{5}DocumentSummaryInformation", "more properties")] {
        if let Some(p) = streams.iter().find(|s| s.name == name || s.name.ends_with(&format!("/{}", name))) {
            let t = property_text(&p.data);
            if !t.is_empty() {
                out.parts.push((label.into(), t));
            }
        }
    }
    out.parts.retain(|p| !p.1.trim().is_empty());
    out
}

/// Word: text through the piece table.
fn word(wd: &[u8], t0: Option<&[u8]>, t1: Option<&[u8]>) -> anyhow::Result<String> {
    if u16_at(wd, 0) != Some(0xA5EC) {
        anyhow::bail!("not a Word 97-2003 document (FIB signature)");
    }
    let flags = u16_at(wd, 0x0A).unwrap_or(0);
    if flags & 0x0100 != 0 {
        anyhow::bail!("encrypted; its text is not readable without the password");
    }
    let table = if flags & 0x0200 != 0 { t1 } else { t0 }.ok_or_else(|| anyhow::anyhow!("table stream missing"))?;
    let fc_clx = u32_at(wd, 0x01A2).unwrap_or(0) as usize;
    let lcb_clx = u32_at(wd, 0x01A6).unwrap_or(0) as usize;
    let clx = table.get(fc_clx..fc_clx.saturating_add(lcb_clx)).ok_or_else(|| anyhow::anyhow!("piece table outside the table stream"))?;
    // Skip Prc entries (0x01), then the Pcdt (0x02).
    let mut p = 0usize;
    while clx.get(p) == Some(&0x01) {
        p += 3 + u16_at(clx, p + 1).unwrap_or(0) as usize;
    }
    if clx.get(p) != Some(&0x02) {
        anyhow::bail!("piece table not found");
    }
    let lcb = u32_at(clx, p + 1).unwrap_or(0) as usize;
    let plc = clx.get(p + 5..(p + 5).saturating_add(lcb)).ok_or_else(|| anyhow::anyhow!("piece table cut off"))?;
    if plc.len() < 16 || (plc.len() - 4) % 12 != 0 {
        anyhow::bail!("piece table has an odd size");
    }
    let n = (plc.len() - 4) / 12;
    let mut text = String::new();
    for i in 0..n {
        let (a, b) = (u32_at(plc, 4 * i).unwrap_or(0), u32_at(plc, 4 * i + 4).unwrap_or(0));
        let count = b.saturating_sub(a) as usize;
        let fc = u32_at(plc, 4 * (n + 1) + 8 * i + 2).unwrap_or(0);
        if fc & 0x4000_0000 != 0 {
            let off = ((fc & !0x4000_0000) / 2) as usize;
            if let Some(b) = wd.get(off..off.saturating_add(count)) {
                text.extend(b.iter().map(|&c| cp1252(c)));
            }
        } else {
            let off = fc as usize;
            if let Some(b) = wd.get(off..off.saturating_add(count * 2)) {
                text.push_str(&utf16_n(b));
            }
        }
        if text.len() > MAX_TEXT {
            break;
        }
    }
    Ok(word_clean(&text))
}

/// Paragraph and cell marks to line breaks and tabs; field codes dropped
/// (field results kept); object anchors and other control marks removed.
fn word_clean(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    // Depth of field codes being skipped (0x13 begins, 0x14 separates, 0x15 ends).
    let mut stack: Vec<bool> = vec![];
    for c in t.chars() {
        match c {
            '\u{13}' => stack.push(true),
            '\u{14}' => {
                if let Some(s) = stack.last_mut() {
                    *s = false;
                }
            }
            '\u{15}' => {
                stack.pop();
            }
            _ if stack.iter().any(|&code| code) => {}
            '\r' | '\u{b}' | '\u{c}' => out.push('\n'),
            '\u{7}' => out.push('\t'),
            '\t' | '\n' => out.push(c),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

/// BIFF8 records, with CONTINUE records kept apart so strings that cross
/// them can be read.
fn biff_records(d: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = vec![];
    let mut p = 0usize;
    while p + 4 <= d.len() {
        let ty = u16_at(d, p).unwrap_or(0);
        let len = u16_at(d, p + 2).unwrap_or(0) as usize;
        let Some(body) = d.get(p + 4..p + 4 + len) else { break };
        out.push((ty, body));
        p += 4 + len;
    }
    out
}

/// Reads characters across a record and its CONTINUE records. At each
/// CONTINUE boundary inside a string's characters a new option byte says
/// whether the rest is 8-bit or 16-bit.
struct Biff<'a> {
    segs: Vec<&'a [u8]>,
    seg: usize,
    pos: usize,
}

impl<'a> Biff<'a> {
    fn left(&self) -> usize {
        self.segs.get(self.seg).map(|s| s.len().saturating_sub(self.pos)).unwrap_or(0)
    }
    fn next_seg(&mut self) -> bool {
        if self.seg + 1 < self.segs.len() {
            self.seg += 1;
            self.pos = 0;
            true
        } else {
            false
        }
    }
    fn bytes(&mut self, mut n: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(n.min(1 << 16));
        while n > 0 {
            if self.left() == 0 && !self.next_seg() {
                return None;
            }
            let k = n.min(self.left());
            out.extend_from_slice(&self.segs[self.seg][self.pos..self.pos + k]);
            self.pos += k;
            n -= k;
        }
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.bytes(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.bytes(n).map(|_| ())
    }
    /// An XLUnicodeRichExtendedString.
    fn string(&mut self) -> Option<String> {
        let cch = self.u16()? as usize;
        let flags = self.u8()?;
        let runs = if flags & 0x08 != 0 { self.u16()? as usize } else { 0 };
        let ext = if flags & 0x04 != 0 { self.u32()? as usize } else { 0 };
        let mut wide = flags & 0x01 != 0;
        let mut s = String::new();
        let mut left = cch;
        while left > 0 {
            if self.left() == 0 {
                if !self.next_seg() {
                    return None;
                }
                wide = self.u8()? & 0x01 != 0;
            }
            let fit = if wide { self.left() / 2 } else { self.left() };
            let k = left.min(fit.max(1));
            if wide {
                s.push_str(&utf16_n(&self.bytes(k * 2)?));
            } else {
                s.extend(self.bytes(k)?.iter().map(|&c| cp1252(c)));
            }
            left -= k;
        }
        self.skip(runs * 4)?;
        self.skip(ext)?;
        Some(s)
    }
}

fn excel(wb: &[u8]) -> anyhow::Result<String> {
    let recs = biff_records(wb);
    if recs.first().map(|r| r.0) != Some(0x0809) {
        anyhow::bail!("not a BIFF8 workbook (no BOF record)");
    }
    let mut out: Vec<String> = vec![];
    let mut sheets = vec![];
    let mut i = 0;
    while i < recs.len() {
        let (ty, body) = recs[i];
        match ty {
            0x002F => anyhow::bail!("encrypted; its text is not readable without the password"),
            0x0085 => {
                // BoundSheet8: name as ShortXLUnicodeString at 6.
                let cch = body.get(6).copied().unwrap_or(0) as usize;
                let wide = body.get(7).is_some_and(|f| f & 1 != 0);
                let name = if wide { utf16_n(body.get(8..8 + cch * 2).unwrap_or(&[])) } else { body.get(8..8 + cch).unwrap_or(&[]).iter().map(|&c| cp1252(c)).collect() };
                sheets.push(name);
            }
            0x00FC => {
                let mut segs = vec![body];
                let mut j = i + 1;
                while j < recs.len() && recs[j].0 == 0x003C {
                    segs.push(recs[j].1);
                    j += 1;
                }
                let mut r = Biff { segs, seg: 0, pos: 8 };
                let unique = u32_at(body, 4).unwrap_or(0) as usize;
                for _ in 0..unique.min(10_000_000) {
                    match r.string() {
                        Some(s) => out.push(s),
                        None => break,
                    }
                    if out.iter().map(|s| s.len()).sum::<usize>() > MAX_TEXT {
                        break;
                    }
                }
                i = j;
                continue;
            }
            0x0204 => {
                // LABEL (older writers): row, col, xf, then an XLUnicodeString.
                let cch = u16_at(body, 6).unwrap_or(0) as usize;
                let wide = body.get(8).is_some_and(|f| f & 1 != 0);
                let s = if wide { utf16_n(body.get(9..9 + cch * 2).unwrap_or(&[])) } else { body.get(9..9 + cch).unwrap_or(&[]).iter().map(|&c| cp1252(c)).collect() };
                out.push(s);
            }
            _ => {}
        }
        i += 1;
    }
    let mut text = String::new();
    if !sheets.is_empty() {
        text.push_str(&format!("Sheets: {}\n", sheets.join(", ")));
    }
    text.push_str(&out.join("\n"));
    Ok(text)
}

fn powerpoint(d: &[u8]) -> String {
    fn walk(d: &[u8], out: &mut Vec<String>, depth: u32) {
        let mut p = 0usize;
        while p + 8 <= d.len() && out.len() < 1_000_000 {
            let ver = u16_at(d, p).unwrap_or(0) & 0x0F;
            let ty = u16_at(d, p + 2).unwrap_or(0);
            let len = u32_at(d, p + 4).unwrap_or(0) as usize;
            let Some(body) = d.get(p + 8..(p + 8).saturating_add(len)) else { break };
            match ty {
                0x0FA0 => out.push(utf16_n(body)),
                0x0FA8 => out.push(body.iter().map(|&c| cp1252(c)).collect()),
                _ if ver == 0x0F && depth < 16 => walk(body, out, depth + 1),
                _ => {}
            }
            p += 8 + len;
        }
    }
    let mut out = vec![];
    walk(d, &mut out, 0);
    out.iter().map(|s| s.replace(['\r', '\u{b}'], "\n")).collect::<Vec<_>>().join("\n")
}

/// Document properties (title, subject, author, keywords, comments, last
/// saved by, company, manager...) from a property set stream.
fn property_text(d: &[u8]) -> String {
    let mut out = vec![];
    let sections = u32_at(d, 24).unwrap_or(0).min(4) as usize;
    for s in 0..sections {
        let Some(so) = u32_at(d, 28 + 20 * s + 16).map(|v| v as usize) else { break };
        let count = u32_at(d, so + 4).unwrap_or(0).min(256) as usize;
        // Codepage (property 1), for 8-bit strings.
        let mut utf8 = false;
        for i in 0..count {
            if u32_at(d, so + 8 + 8 * i) == Some(1) {
                let po = so + u32_at(d, so + 12 + 8 * i).unwrap_or(0) as usize;
                utf8 = u16_at(d, po + 4) == Some(65001);
            }
        }
        for i in 0..count {
            let id = u32_at(d, so + 8 + 8 * i).unwrap_or(0);
            if id < 2 {
                continue;
            }
            let po = so + u32_at(d, so + 12 + 8 * i).unwrap_or(0) as usize;
            let ty = u32_at(d, po).unwrap_or(0);
            let n = u32_at(d, po + 4).unwrap_or(0) as usize;
            let s = match ty {
                0x1E => d.get(po + 8..(po + 8).saturating_add(n.min(1 << 16))).map(|b| {
                    let b: Vec<u8> = b.iter().copied().take_while(|&c| c != 0).collect();
                    if utf8 { String::from_utf8_lossy(&b).into_owned() } else { b.iter().map(|&c| cp1252(c)).collect() }
                }),
                0x1F => d.get(po + 8..(po + 8).saturating_add(n.min(1 << 15) * 2)).map(utf16),
                _ => None,
            };
            if let Some(s) = s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
                out.push(s);
            }
        }
    }
    out.join("\n")
}

/// RTF text.
pub fn rtf(d: &[u8]) -> String {
    const SKIP: &[&str] = &[
        "fonttbl", "colortbl", "stylesheet", "listtable", "listoverridetable", "rsidtbl", "generator", "pict", "objdata", "themedata", "colorschememapping", "datastore", "latentstyles", "xmlnstbl", "mmathPr", "fldinst", "filetbl", "revtbl", "pgdsctbl", "bkmkstart", "bkmkend", "xmlopen", "blipuid", "protusertbl", "wgrffmtfilter", "defchp", "defpap", "panose", "falt", "nonshppict",
    ];
    let mut out = String::new();
    // Per group: skipping, chars to skip after \u (\uc).
    let mut stack: Vec<(bool, usize)> = vec![(false, 1)];
    let mut skip_after_u = 0usize;
    let mut p = 0usize;
    let mut pending: Vec<u8> = vec![];
    let flush = |pending: &mut Vec<u8>, out: &mut String| {
        out.extend(pending.iter().map(|&c| cp1252(c)));
        pending.clear();
    };
    while p < d.len() && out.len() < MAX_TEXT {
        let c = d[p];
        let (skipping, uc) = *stack.last().unwrap_or(&(false, 1));
        match c {
            b'{' => {
                flush(&mut pending, &mut out);
                // {\* destination} is skipped when not understood.
                let star = d.get(p + 1..p + 3) == Some(b"\\*");
                stack.push((skipping || star, uc));
                if stack.len() > 512 {
                    break;
                }
                p += 1;
            }
            b'}' => {
                flush(&mut pending, &mut out);
                if stack.len() > 1 {
                    stack.pop();
                }
                p += 1;
            }
            b'\\' => {
                let next = d.get(p + 1).copied().unwrap_or(0);
                if next == b'\'' {
                    if let Some(h) = d.get(p + 2..p + 4).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                        if skip_after_u > 0 {
                            skip_after_u -= 1;
                        } else if !skipping {
                            pending.push(h);
                        }
                    }
                    p += 4;
                    continue;
                }
                if !next.is_ascii_alphabetic() {
                    // Control symbol.
                    if !skipping {
                        match next {
                            b'\\' | b'{' | b'}' => {
                                flush(&mut pending, &mut out);
                                out.push(next as char);
                            }
                            b'~' => out.push(' '),
                            b'_' => out.push('-'),
                            b'\n' | b'\r' => out.push('\n'),
                            _ => {}
                        }
                    }
                    p += 2;
                    continue;
                }
                let mut q = p + 1;
                while q < d.len() && d[q].is_ascii_alphabetic() && q - p < 40 {
                    q += 1;
                }
                let word = std::str::from_utf8(&d[p + 1..q]).unwrap_or("");
                let ns = q;
                if q < d.len() && (d[q] == b'-' || d[q].is_ascii_digit()) {
                    q += 1;
                    while q < d.len() && d[q].is_ascii_digit() && q - ns < 12 {
                        q += 1;
                    }
                }
                let num: Option<i64> = std::str::from_utf8(&d[ns..q]).ok().and_then(|s| s.parse().ok());
                if q < d.len() && d[q] == b' ' {
                    q += 1;
                }
                flush(&mut pending, &mut out);
                if SKIP.contains(&word) {
                    if let Some(t) = stack.last_mut() {
                        t.0 = true;
                    }
                } else if word == "bin" {
                    // Binary data follows: skip it whole.
                    q = q.saturating_add(num.unwrap_or(0).max(0) as usize);
                } else if word == "uc" {
                    if let Some(t) = stack.last_mut() {
                        t.1 = num.unwrap_or(1).clamp(0, 8) as usize;
                    }
                } else if !skipping {
                    match word {
                        "par" | "line" | "sect" | "page" | "row" => out.push('\n'),
                        "tab" | "cell" => out.push('\t'),
                        "u" => {
                            let v = num.unwrap_or(0);
                            let v = if v < 0 { v + 65536 } else { v } as u32;
                            out.push(char::from_u32(v).unwrap_or('?'));
                            skip_after_u = uc;
                        }
                        "emdash" => out.push('-'),
                        "endash" => out.push('-'),
                        "lquote" | "rquote" => out.push('\''),
                        "ldblquote" | "rdblquote" => out.push('"'),
                        "bullet" => out.push('*'),
                        _ => {}
                    }
                } else if word == "u" {
                    skip_after_u = uc;
                }
                p = q;
            }
            b'\r' | b'\n' => p += 1,
            _ => {
                if skip_after_u > 0 {
                    skip_after_u -= 1;
                } else if !skipping {
                    pending.push(c);
                }
                p += 1;
            }
        }
    }
    flush(&mut pending, &mut out);
    out.lines().map(|l| l.trim_end()).collect::<Vec<_>>().join("\n").trim().to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal Word 97 document: FIB, a piece table with one 8-bit piece
    /// and one UTF-16 piece, and a field whose code is dropped.
    pub fn doc(text8: &str, text16: &str) -> Vec<u8> {
        let mut wd = vec![0u8; 0x600];
        wd[0..2].copy_from_slice(&0xA5ECu16.to_le_bytes());
        wd[0x0A..0x0C].copy_from_slice(&0x0200u16.to_le_bytes()); // 1Table
        let off8 = 0x400usize;
        wd[off8..off8 + text8.len()].copy_from_slice(text8.as_bytes());
        let off16 = 0x500usize;
        let w: Vec<u8> = text16.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        wd[off16..off16 + w.len()].copy_from_slice(&w);
        let n8 = text8.len() as u32;
        let n16 = text16.encode_utf16().count() as u32;
        let mut plc = vec![];
        for cp in [0, n8, n8 + n16] {
            plc.extend_from_slice(&cp.to_le_bytes());
        }
        for fc in [((off8 * 2) as u32) | 0x4000_0000, off16 as u32] {
            plc.extend_from_slice(&[0, 0]);
            plc.extend_from_slice(&fc.to_le_bytes());
            plc.extend_from_slice(&[0, 0]);
        }
        let mut clx = vec![0x02];
        clx.extend_from_slice(&(plc.len() as u32).to_le_bytes());
        clx.extend_from_slice(&plc);
        let mut table = vec![0u8; 16];
        let fc_clx = table.len() as u32;
        table.extend_from_slice(&clx);
        wd[0x01A2..0x01A6].copy_from_slice(&fc_clx.to_le_bytes());
        wd[0x01A6..0x01AA].copy_from_slice(&(clx.len() as u32).to_le_bytes());
        cfb::tests::write(&[("WordDocument", &wd), ("1Table", &table)])
    }

    /// A BIFF8 workbook: a sheet name and a shared string table whose second
    /// string is split over a CONTINUE record, the rest 16-bit.
    pub fn xls() -> Vec<u8> {
        let rec = |ty: u16, body: &[u8]| -> Vec<u8> { [ty.to_le_bytes().to_vec(), (body.len() as u16).to_le_bytes().to_vec(), body.to_vec()].concat() };
        let mut bs = vec![0u8; 6];
        bs.extend_from_slice(&[7, 0]);
        bs.extend_from_slice(b"Ledger1");
        let mut sst = vec![];
        sst.extend_from_slice(&2u32.to_le_bytes());
        sst.extend_from_slice(&2u32.to_le_bytes());
        sst.extend_from_slice(&6u16.to_le_bytes());
        sst.push(0);
        sst.extend_from_slice(b"Amount");
        sst.extend_from_slice(&14u16.to_le_bytes());
        sst.push(0);
        sst.extend_from_slice(b"offshore");
        let mut cont = vec![1u8];
        cont.extend(" acct".encode_utf16().flat_map(|u| u.to_le_bytes()));
        cont.extend("!".encode_utf16().flat_map(|u| u.to_le_bytes()));
        let wb = [rec(0x0809, &[0; 16]), rec(0x0085, &bs), rec(0x00FC, &sst), rec(0x003C, &cont), rec(0x000A, &[])].concat();
        cfb::tests::write(&[("Workbook", &wb)])
    }

    #[test]
    fn word_excel_powerpoint_and_properties() {
        let d = doc("Wire the funds \u{13} HYPERLINK x \u{14}today\u{15}\r", "to the caf\u{e9} account\r");
        let o = ole(&d);
        assert_eq!(o.parts[0].0, "document");
        assert_eq!(o.parts[0].1, "Wire the funds today\nto the caf\u{e9} account\n");
        let o = ole(&xls());
        assert_eq!(o.parts[0].1, "Sheets: Ledger1\nAmount\noffshore acct!");
        // PowerPoint: a container holding a UTF-16 and an 8-bit text atom.
        let atom = |ty: u16, b: &[u8]| [0u16.to_le_bytes().to_vec(), ty.to_le_bytes().to_vec(), (b.len() as u32).to_le_bytes().to_vec(), b.to_vec()].concat();
        let inner = [atom(0x0FA0, &"Q3 plan".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>()), atom(0x0FA8, b"move servers\rtonight")].concat();
        let cont = [0x000Fu16.to_le_bytes().to_vec(), 0x03E8u16.to_le_bytes().to_vec(), (inner.len() as u32).to_le_bytes().to_vec(), inner].concat();
        let o = ole(&cfb::tests::write(&[("PowerPoint Document", &cont)]));
        assert_eq!(o.parts[0].1, "Q3 plan\nmove servers\ntonight");
        // Encrypted Word is reported.
        let mut enc = doc("x", "y");
        let wd_pos = enc.windows(2).position(|w| w == [0xEC, 0xA5]).unwrap();
        enc[wd_pos + 0x0B] |= 0x01; // fEncrypted (0x0100)
        let o = ole(&enc);
        assert!(o.parts.is_empty() && o.notes[0].contains("encrypted"), "{:?}", o.notes);
        // Outlook message text properties.
        let subj: Vec<u8> = "Invoice 4471".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let o = ole(&cfb::tests::write(&[("__substg1.0_0037001F", &subj), ("__substg1.0_1000001E", b"Pay today.\0")]));
        assert_eq!(o.parts[0], ("message".to_string(), "Invoice 4471\nPay today.".to_string()));
    }

    #[test]
    fn rtf_text() {
        let r = br"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0 Times;}}{\colortbl;\red0\green0\blue0;}{\*\generator Riched20;}
\pard Transfer to the caf\'e9\par Na\u239?ve \u8364? total\tab 500\par{\*\bkmkstart x}{\field{\*\fldinst HYPERLINK http://x.test}{\fldrslt link text}}\par{\pict\wmetafile8 0123abcd}}";
        assert_eq!(rtf(r), "Transfer to the caf\u{e9}\nNa\u{ef}ve \u{20ac} total\t500\nlink text");
        assert_eq!(rtf(br"{\rtf1 a\bin4 \{\}\} b}"), "a} b"); // bin4 swallows the next four bytes
    }
}
