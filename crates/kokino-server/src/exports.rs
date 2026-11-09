//! Lists as CSV or JSON: every table Kokino shows (files, timeline, web
//! activity, Windows and Linux artifacts, indicators, carved files), with
//! times as ISO 8601 UTC and the same columns in both formats.
//!
//! CSV is RFC 4180 (comma, CRLF, quotes doubled) with a UTF-8 byte-order
//! mark so spreadsheets read it as UTF-8. A cell that starts with = + - @
//! or a tab is prefixed with an apostrophe, so a spreadsheet does not run
//! text from the evidence as a formula; the JSON file keeps every value
//! exactly as it is.

use crate::state::{AppState, HashStatus, Loaded};
use kokino_analysis::carve::CarveResult;
use kokino_core::time::filetime_to_iso;
use serde_json::{json, Value};

pub struct Table {
    pub headers: Vec<&'static str>,
    pub rows: Vec<Vec<Value>>,
}

/// (id, label, needs a carving result)
pub const LISTS: &[(&str, &str)] = &[
    ("files", "Files (live and deleted)"),
    ("timeline", "Timeline"),
    ("indicators", "Anti-forensics indicators"),
    ("visits", "Web: page visits"),
    ("downloads", "Web: downloads"),
    ("searches", "Web: searches"),
    ("iecache", "Web: Internet Explorer cache"),
    ("cookies", "Web: Internet Explorer cookies"),
    ("mail", "Email messages"),
    ("execution", "Windows: programs run"),
    ("access", "Windows: files and folders opened"),
    ("shellbags", "Windows: folders opened (ShellBags)"),
    ("journal", "Windows: change journal"),
    ("autoruns", "Windows: autostart entries"),
    ("tasks", "Windows: scheduled tasks"),
    ("programs", "Windows: installed programs"),
    ("usb", "Windows: USB devices"),
    ("networks", "Windows: networks"),
    ("accounts", "Windows: accounts"),
    ("events", "Windows: notable events"),
    ("regkeys", "Windows: deleted registry keys"),
    ("regvalues", "Windows: deleted registry values"),
    ("srum", "Windows: network use per program (SRUM)"),
    ("linux-commands", "Linux: shell history"),
    ("linux-logons", "Linux: logons"),
    ("linux-events", "Linux: events"),
    ("linux-packages", "Linux: installed packages"),
    ("linux-persistence", "Linux: persistence"),
    ("carved", "Carved files"),
    ("ie-records", "Carved Internet Explorer records"),
];

fn t(ft: u64) -> Value {
    if ft == 0 { Value::String(String::new()) } else { Value::String(filetime_to_iso(ft)) }
}

fn s(v: impl Into<String>) -> Value {
    Value::String(v.into())
}

fn opt<T: Into<Value>>(v: Option<T>) -> Value {
    v.map(Into::into).unwrap_or(Value::Null)
}

/// The rows of one list. `None` when the list does not exist.
pub fn table(l: &Loaded, fi: usize, hs: Option<&HashStatus>, carved: Option<&CarveResult>, what: &str) -> anyhow::Result<Table> {
    let fsa = || l.analysis.filesystems.get(fi).ok_or_else(|| anyhow::anyhow!("no such file system"));
    let tb = |headers: Vec<&'static str>, rows: Vec<Vec<Value>>| Ok(Table { headers, rows });
    match what {
        "files" => {
            let f = fsa()?;
            let mut rows = vec![];
            for r in &f.files {
                let si = r.e.si.unwrap_or_default();
                let fname = r.e.fname.unwrap_or_default();
                let h = hs.and_then(|h| h.by_file.get(&(fi, r.e.record)).map(|&i| &h.fh.files[i].hashes));
                rows.push(vec![
                    json!(r.e.record),
                    json!(r.e.seq),
                    s(&r.e.path),
                    json!(r.e.is_dir),
                    json!(r.e.deleted),
                    s(r.e.name_only.as_ref().map(|n| n.source.as_str()).unwrap_or("")),
                    json!(r.e.size),
                    t(si.created),
                    t(si.modified),
                    t(si.accessed),
                    t(si.mft_modified),
                    t(fname.created),
                    t(fname.modified),
                    t(fname.accessed),
                    t(fname.mft_modified),
                    s(r.sig_label.clone().unwrap_or_default()),
                    json!(r.mismatch),
                    opt(r.entropy.map(|e| (e as f64 * 1000.0).round() / 1000.0)),
                    s(r.flags.join(" ")),
                    s(h.map(|h| h.md5.clone()).unwrap_or_default()),
                    s(h.map(|h| h.sha1.clone()).unwrap_or_default()),
                    s(h.map(|h| h.sha256.clone()).unwrap_or_default()),
                ]);
            }
            tb(
                vec!["record", "seq", "path", "is_dir", "deleted", "name_only_from", "size", "si_created", "si_modified", "si_accessed", "si_changed", "fn_created", "fn_modified", "fn_accessed", "fn_changed", "signature", "extension_mismatch", "entropy", "flags", "md5", "sha1", "sha256"],
                rows,
            )
        }
        "timeline" => {
            let f = fsa()?;
            let idx = l.fs.get(fi).ok_or_else(|| anyhow::anyhow!("no such file system"))?;
            let mut rows = vec![];
            for e in &idx.timeline {
                let (what, detail, deleted) = if kokino_analysis::timeline::is_web(e.src) {
                    let (a, b, _) = crate::api::web_text(f, e.src, e.idx as usize);
                    (a, b, false)
                } else if kokino_analysis::timeline::is_windows(e.src) {
                    match kokino_analysis::timeline::system_event(&f.windows, &f.linux.timeline, e.idx as usize) {
                        Some(w) => (w.what.clone(), w.detail.clone(), false),
                        None => continue,
                    }
                } else {
                    let r = &f.files[e.idx as usize];
                    (r.e.path.clone(), String::new(), r.e.deleted)
                };
                rows.push(vec![t(e.t), s(e.src), s(&e.macb), s(what), s(detail), json!(deleted)]);
            }
            tb(vec!["time_utc", "source", "macb", "what", "detail", "deleted"], rows)
        }
        "indicators" => {
            let f = fsa()?;
            tb(
                vec!["id", "title", "category", "count", "strength", "weight", "explanation", "caveat", "mft_records"],
                f.indicators.iter().map(|i| vec![s(&i.id), s(&i.title), s(&i.category), json!(i.count), json!((i.strength as f64 * 1000.0).round() / 1000.0), json!(i.weight), s(&i.explanation), s(&i.caveat), s(i.records.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(" "))]).collect(),
            )
        }
        "visits" | "downloads" | "searches" | "iecache" | "cookies" => {
            let w = &fsa()?.web;
            let src = |i: u32| w.sources.get(i as usize).map(|x| format!("{} / {} / {}", x.browser, x.user, x.profile)).unwrap_or_default();
            match what {
                "visits" => tb(
                    vec!["time_utc", "browser", "url", "title", "how", "typed", "visit_count", "duration_ms", "url_table_only", "recovered_deleted_entry"],
                    w.visits.iter().map(|v| vec![t(v.t), s(src(v.src)), s(&v.url), s(&v.title), s(&v.how), json!(v.typed), json!(v.visit_count), json!(v.duration_ms), json!(v.url_only), json!(v.recovered)]).collect(),
                ),
                "downloads" => tb(
                    vec!["started_utc", "ended_utc", "browser", "url", "referrer", "saved_to", "received", "total", "state", "danger", "mime", "opened"],
                    w.downloads.iter().map(|d| vec![t(d.start), t(d.end), s(src(d.src)), s(&d.url), s(&d.referrer), s(&d.target), json!(d.received), json!(d.total), s(&d.state), s(&d.danger), s(&d.mime), json!(d.opened)]).collect(),
                ),
                "searches" => tb(
                    vec!["time_utc", "browser", "engine", "term", "recorded_in", "url"],
                    w.searches.iter().map(|q| vec![t(q.t), s(src(q.src)), s(&q.engine), s(&q.term), s(&q.how), s(&q.url)]).collect(),
                ),
                "cookies" => tb(
                    vec!["created_utc", "expires_utc", "last_access_utc", "browser", "site", "name", "value", "flags", "cookie_file", "recovered_index_entry", "note"],
                    w.cookies.iter().map(|c| vec![t(c.created), t(c.expires), t(c.last_access), s(src(c.src)), s(&c.site), s(&c.name), s(&c.value), json!(c.flags), s(&c.file), json!(c.recovered), s(&c.note)]).collect(),
                ),
                _ => tb(
                    vec!["last_access_utc", "server_modified_utc", "browser", "url", "cached_as", "content_type", "hits", "recovered_deleted_entry", "leak"],
                    w.cache.iter().map(|c| vec![t(c.t), t(c.modified), s(src(c.src)), s(&c.url), s(&c.file), s(&c.content_type), json!(c.hits), json!(c.recovered), json!(c.leak)]).collect(),
                ),
            }
        }
        "execution" | "access" | "shellbags" | "journal" | "autoruns" | "tasks" | "programs" | "usb" | "networks" | "accounts" | "events" | "regkeys" | "regvalues" | "srum" => {
            let f = fsa()?;
            let w = &f.windows;
            let file = |i: Option<u32>| i.and_then(|i| f.files.get(i as usize)).map(|r| r.e.path.clone()).unwrap_or_default();
            match what {
                "execution" => tb(
                    vec!["source", "program", "user", "run_count", "times_utc", "sha1", "detail", "artifact_file", "wiping_tool"],
                    w.execution.iter().map(|x| vec![s(&x.source), s(&x.program), s(&x.user), opt(x.count), s(x.times.iter().map(|&v| filetime_to_iso(v)).collect::<Vec<_>>().join(" ")), s(&x.sha1), s(&x.detail), s(file(x.file)), json!(x.tool)]).collect(),
                ),
                "access" => tb(
                    vec!["time_utc", "first_utc", "source", "user", "path", "count", "drive_type", "volume_label", "volume_serial", "machine", "mac", "app_id", "pinned", "artifact_file"],
                    w.access.iter().map(|x| vec![t(x.time), t(x.first), s(&x.source), s(&x.user), s(&x.path), opt(x.count), s(&x.drive_type), s(&x.volume_label), s(&x.volume_serial), s(&x.machine), s(&x.mac), s(&x.app_id), json!(x.pinned), s(file(x.file))]).collect(),
                ),
                "shellbags" => tb(
                    vec!["opened_utc", "path", "kind", "user", "folder_created_local", "folder_modified_local", "folder_accessed_local", "mft_record", "mft_seq", "source", "key", "artifact_file"],
                    w.shellbags.iter().map(|b| vec![t(b.bag.opened), s(&b.bag.path), s(&b.bag.kind), s(&b.user), t(b.bag.created), t(b.bag.modified), t(b.bag.accessed), opt(b.bag.mft.map(|m| m.0)), opt(b.bag.mft.map(|m| m.1)), s(&b.source), s(&b.bag.key), s(file(Some(b.file)))]).collect(),
                ),
                "journal" => tb(
                    vec!["time_utc", "first_utc", "what", "path", "old_path", "usn", "mft_record", "mft_seq", "reasons", "is_dir"],
                    w.journal.as_ref().map(|j| j.changes.iter().map(|c| vec![t(c.c.t), t(c.c.first), s(&c.what), s(&c.path), s(&c.old_path), json!(c.c.usn), json!(c.c.record), json!(c.c.seq), s(format!("0x{:08x}", c.c.reasons)), json!(c.dir)]).collect()).unwrap_or_default(),
                ),
                "autoruns" => tb(
                    vec!["kind", "location", "name", "command", "user", "written_utc", "start", "unusual"],
                    w.autoruns.iter().map(|a| vec![s(&a.kind), s(&a.location), s(&a.name), s(&a.command), s(&a.user), t(a.written), s(&a.start), json!(a.unusual)]).collect(),
                ),
                "tasks" => tb(
                    vec!["path", "runs", "triggers", "user", "author", "created_utc", "last_run_utc", "last_success_utc", "last_result", "enabled", "hidden_flag", "sd_removed", "windows_own", "unusual", "notes", "task_file"],
                    w.tasks.iter().map(|k| vec![s(&k.path), s(k.command()), s(k.triggers.join("; ")), s(&k.user), s(&k.author), t(k.created), t(k.last_run), t(k.last_success), s(format!("0x{:08x}", k.last_result)), json!(k.enabled), json!(k.hidden), json!(k.sd_removed), json!(k.microsoft), json!(k.unusual), s(k.notes.join("; ")), s(file(k.file))]).collect(),
                ),
                "programs" => tb(
                    vec!["name", "version", "publisher", "install_date_utc", "location", "key_written_utc", "wow64"],
                    w.programs.iter().map(|p| vec![s(&p.name), s(&p.version), s(&p.publisher), t(p.install_date), s(&p.location), t(p.key_written), json!(p.wow64)]).collect(),
                ),
                "usb" => tb(
                    vec!["name", "vendor", "product", "revision", "serial", "drive_letter", "first_connected_utc", "last_connected_utc", "last_removed_utc", "key_written_utc"],
                    w.usb.iter().map(|u| vec![s(&u.name), s(&u.vendor), s(&u.product), s(&u.revision), s(&u.serial), s(&u.drive_letter), t(u.first_connected), t(u.last_connected), t(u.last_removed), t(u.key_written)]).collect(),
                ),
                "networks" => tb(
                    vec!["name", "description", "kind", "category", "created_utc", "last_connected_utc", "gateway_mac", "dns_suffix"],
                    w.networks.iter().map(|n| vec![s(&n.name), s(&n.description), s(&n.kind), s(&n.category), t(n.created), t(n.last_connected), s(&n.gateway_mac), s(&n.dns_suffix)]).collect(),
                ),
                "accounts" => tb(
                    vec!["name", "rid", "sid", "profile", "created_utc", "last_logon_utc", "password_set_utc", "last_failed_utc", "logon_count", "failed_count", "disabled", "source"],
                    w.users.iter().map(|u| vec![s(&u.name), opt(u.rid), s(&u.sid), s(&u.profile), t(u.created), t(u.last_logon), t(u.password_set), t(u.last_failed), json!(u.logon_count), json!(u.failed_count), json!(u.disabled), s(&u.source)]).collect(),
                ),
                "events" => tb(
                    vec!["time_utc", "channel", "event_id", "record_id", "category", "title", "summary", "user", "ip", "computer", "data", "log_file"],
                    w.events.iter().map(|e| vec![t(e.time), s(&e.channel), json!(e.event_id), json!(e.record_id), s(&e.category), s(&e.title), s(&e.summary), s(&e.user), s(&e.ip), s(&e.computer), s(e.data.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("; ")), s(file(Some(e.file)))]).collect(),
                ),
                "regkeys" => tb(
                    vec!["hive", "key", "last_changed_utc", "complete_path", "subkeys", "values", "records", "hive_file"],
                    w.reg_deleted_keys.iter().map(|k| vec![s(&k.hive), s(&k.path), t(k.last_written), json!(k.complete_path), json!(k.subkeys), s(k.values.iter().map(|v| format!("{} ({}) = {}", v.name, v.kind, v.text)).collect::<Vec<_>>().join("; ")), s(&k.notable), s(file(Some(k.file)))]).collect(),
                ),
                "regvalues" => tb(
                    vec!["hive", "key", "name", "type", "data", "size", "data_cell_reused", "records", "hive_file"],
                    w.reg_deleted_values.iter().map(|v| vec![s(&v.hive), s(&v.key), s(&v.name), s(&v.kind), s(&v.text), json!(v.size), json!(v.data_reused), s(&v.notable), s(file(Some(v.file)))]).collect(),
                ),
                _ => tb(
                    vec!["program", "user", "first_utc", "last_utc", "bytes_sent", "bytes_received", "disk_read", "disk_written"],
                    w.srum.as_ref().map(|r| r.apps.iter().map(|a| vec![s(&a.app), s(&a.user), t(a.first), t(a.last), json!(a.sent), json!(a.received), json!(a.read), json!(a.written)]).collect()).unwrap_or_default(),
                ),
            }
        }
        "mail" => {
            let f = fsa()?;
            tb(
                vec!["date_utc", "from", "to", "cc", "subject", "attachments", "deleted_in_thunderbird", "mailbox_deleted", "message_id", "mailbox", "folder", "offset", "length"],
                f.mail.messages.iter().map(|m| vec![t(m.date), s(&m.from), s(&m.to), s(&m.cc), s(&m.subject), s(m.attachments.iter().map(|a| format!("{} ({} bytes)", a.name, a.size)).collect::<Vec<_>>().join("; ")), json!(m.expunged), json!(m.deleted), s(&m.message_id), s(f.files.get(m.file as usize).map(|r| r.e.path.clone()).unwrap_or_default()), s(&m.folder), json!(m.offset), json!(m.len)]).collect(),
            )
        }
        "linux-commands" | "linux-logons" | "linux-events" | "linux-packages" | "linux-persistence" => {
            let f = fsa()?;
            let x = &f.linux;
            let file = |i: u32| f.files.get(i as usize).map(|r| r.e.path.clone()).unwrap_or_default();
            match what {
                "linux-commands" => tb(
                    vec!["time_utc", "user", "shell", "command", "flag", "line", "history_file", "deleted"],
                    x.commands.iter().map(|c| vec![t(c.time), s(&c.user), s(&c.shell), s(&c.command), s(&c.flag), json!(c.line), s(file(c.file)), json!(c.deleted)]).collect(),
                ),
                "linux-logons" => tb(
                    vec!["time_utc", "end_utc", "user", "kind", "how", "from", "tty", "source", "log_file"],
                    x.logons.iter().map(|g| vec![t(g.time), t(g.end), s(&g.user), s(&g.kind), s(&g.how), s(&g.from), s(&g.tty), s(&g.source), s(file(g.file))]).collect(),
                ),
                "linux-events" => tb(
                    vec!["time_utc", "year_guessed", "category", "summary", "program", "host", "user", "ip", "message", "source", "log_file"],
                    x.events.iter().map(|e| vec![t(e.time), json!(e.year_guessed), s(&e.category), s(&e.summary), s(&e.program), s(&e.host), s(&e.user), s(&e.ip), s(&e.message), s(&e.source), s(file(e.file))]).collect(),
                ),
                "linux-packages" => tb(
                    vec!["name", "version", "arch", "manager", "installed_utc", "installed_by", "description"],
                    x.packages.iter().map(|p| vec![s(&p.name), s(&p.version), s(&p.arch), s(&p.manager), t(p.installed), s(&p.by), s(&p.description)]).collect(),
                ),
                _ => tb(
                    vec!["kind", "location", "name", "command", "user", "written_utc", "unusual", "reason", "file", "deleted"],
                    x.persistence.iter().map(|p| vec![s(&p.kind), s(&p.location), s(&p.name), s(&p.command), s(&p.user), t(p.written), json!(p.unusual), s(&p.reason), s(file(p.file)), json!(p.deleted)]).collect(),
                ),
            }
        }
        "carved" => {
            let c = carved.ok_or_else(|| anyhow::anyhow!("this evidence has not been carved"))?;
            tb(
                vec!["id", "offset", "length", "kind", "label", "complete", "detail", "region", "note", "beyond_region", "md5", "sha256", "decrypted_volume"],
                c.files.iter().map(|f| vec![json!(f.id), json!(f.offset), json!(f.len), s(&f.kind), s(&f.label), json!(f.complete), s(&f.detail), s(&f.region), s(&f.note), json!(f.beyond_region), s(&f.md5), s(&f.sha256), opt(f.space)]).collect(),
            )
        }
        "ie-records" => {
            let c = carved.ok_or_else(|| anyhow::anyhow!("this evidence has not been carved"))?;
            tb(
                vec!["offset", "length", "record", "what", "time_utc", "user", "url", "title", "file", "hits", "region", "inside_carved_file", "decrypted_volume"],
                c.records.iter().map(|r| vec![json!(r.offset), json!(r.len), s(&r.tag), s(&r.what), t(r.t), s(&r.user), s(&r.url), s(&r.title), s(&r.file), json!(r.hits), s(&r.region), opt(r.in_file), opt(r.space)]).collect(),
            )
        }
        _ => anyhow::bail!("no such list: {}", what),
    }
}

/// Builds one list, saves it in the case's exports folder, records its
/// SHA-256 in the case audit log and returns (file name, bytes). `fi` is
/// ignored for the carving lists, which belong to the whole evidence.
pub fn export_list(st: &AppState, cid: &str, eid: &str, fi: usize, what: &str, json_out: bool, actor: &str, skip_empty: bool) -> anyhow::Result<Option<(String, Vec<u8>)>> {
    if !LISTS.iter().any(|x| x.0 == what) {
        anyhow::bail!("no such list: {} (one of: {})", what, LISTS.iter().map(|x| x.0).collect::<Vec<_>>().join(", "));
    }
    let l = st.loaded(cid, eid)?;
    let case = st.case(cid)?;
    let hs = st.hash_status(cid, eid);
    let carving = matches!(what, "carved" | "ie-records");
    let carved = if carving { crate::jobs::load_carved(&case, eid) } else { None };
    let t = table(&l, fi, hs.as_deref(), carved.as_ref(), what)?;
    if skip_empty && t.rows.is_empty() {
        return Ok(None);
    }
    let data = if json_out { json_rows(&t) } else { csv(&t) };
    let (hashes, _) = kokino_core::hashing::hash_reader(&data[..], |_| true)?;
    let stamp: String = kokino_core::time::now_iso().chars().filter(|c| c.is_ascii_digit()).take(14).collect();
    let scope = if carving { String::new() } else { format!("_fs{}", fi) };
    let name = format!("{}{}_{}_{}.{}", eid, scope, what, stamp, if json_out { "json" } else { "csv" });
    std::fs::write(case.dir.join("exports").join(&name), &data)?;
    case.audit.append(actor, "list.export", json!({"evidence": eid, "fs": if carving { Value::Null } else { json!(fi) }, "list": what, "format": if json_out { "json" } else { "csv" }, "rows": t.rows.len(), "bytes": data.len(), "hashes": hashes, "saved_as": name}))?;
    Ok(Some((name, data)))
}

fn cell_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

pub fn csv(t: &Table) -> Vec<u8> {
    let field = |raw: &str| -> String {
        let mut s = raw.to_string();
        if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
            s.insert(0, '\'');
        }
        if s.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    };
    let mut out = String::from("\u{feff}");
    out.push_str(&t.headers.iter().map(|h| field(h)).collect::<Vec<_>>().join(","));
    out.push_str("\r\n");
    for r in &t.rows {
        out.push_str(&r.iter().map(|v| field(&cell_text(v))).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out.into_bytes()
}

/// An array of objects, keys in column order.
pub fn json_rows(t: &Table) -> Vec<u8> {
    let mut out = String::from("[\n");
    for (n, r) in t.rows.iter().enumerate() {
        out.push_str("  {");
        let parts: Vec<String> = t.headers.iter().zip(r).map(|(h, v)| format!("{}: {}", Value::String(h.to_string()), v)).collect();
        out.push_str(&parts.join(", "));
        out.push('}');
        if n + 1 < t.rows.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("]\n");
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_and_guards_formulas() {
        let t = Table { headers: vec!["a", "b", "c"], rows: vec![vec![s("x,y"), s("say \"hi\""), s("=HYPERLINK(\"http://evil.test\")")], vec![json!(5), Value::Null, json!(true)]] };
        let c = String::from_utf8(csv(&t)).unwrap();
        assert_eq!(c, "\u{feff}a,b,c\r\n\"x,y\",\"say \"\"hi\"\"\",\"'=HYPERLINK(\"\"http://evil.test\"\")\"\r\n5,,true\r\n");
        let j: Value = serde_json::from_slice(&json_rows(&t)).unwrap();
        assert_eq!(j[0]["c"], "=HYPERLINK(\"http://evil.test\")");
        assert_eq!(j[1]["a"], 5);
        assert!(j[1]["b"].is_null());
        // Column order is kept.
        let raw = String::from_utf8(json_rows(&t)).unwrap();
        assert!(raw.find("\"a\"").unwrap() < raw.find("\"b\"").unwrap());
    }

    /// Lists of the Windows test image, saved and audited.
    #[test]
    fn exports_fixture_lists() {
        let img = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/disk-win.img");
        if !img.exists() {
            return;
        }
        let root = std::env::temp_dir().join(format!("kokino-exports-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let st = AppState::new(root.clone(), 7311, false, vec![]).unwrap();
        let case = kokino_core::case::Case::create(&root, "Exports", "tester", "").unwrap();
        let cid = case.info.id.clone();
        let ev = kokino_image::Evidence::open(&img).unwrap();
        let a = kokino_analysis::analyze(&ev, &mut |_, _, _| true).unwrap();
        st.put(&cid, "ev1", a, ev);
        // Every list builds; the Windows ones have rows.
        let l = st.loaded(&cid, "ev1").unwrap();
        for (id, _) in LISTS.iter().filter(|x| !matches!(x.0, "carved" | "ie-records")) {
            let t = table(&l, 0, None, None, id).unwrap();
            assert!(t.rows.iter().all(|r| r.len() == t.headers.len()), "{id}");
        }
        for id in ["files", "timeline", "visits", "iecache", "tasks", "regkeys", "events", "journal"] {
            assert!(!table(&l, 0, None, None, id).unwrap().rows.is_empty(), "{id}");
        }
        assert!(table(&l, 0, None, None, "nope").is_err());
        assert!(table(&l, 0, None, None, "carved").is_err()); // not carved yet
        let (name, data) = export_list(&st, &cid, "ev1", 0, "regkeys", false, "tester", false).unwrap().unwrap();
        let text = String::from_utf8(data.clone()).unwrap();
        assert!(text.contains("Software\\Microsoft\\Internet Explorer\\TypedURLs,2026-10-21T02:11:00.0000000Z,true"), "{text}");
        assert!(name.starts_with("ev1_fs0_regkeys_") && name.ends_with(".csv"));
        assert_eq!(std::fs::read(case.dir.join("exports").join(&name)).unwrap(), data);
        let (jname, jdata) = export_list(&st, &cid, "ev1", 0, "visits", true, "tester", false).unwrap().unwrap();
        let v: Value = serde_json::from_slice(&jdata).unwrap();
        assert!(v.as_array().unwrap().iter().any(|r| r["url"] == "http://drop.test/upload.html" && r["recovered_deleted_entry"] == true));
        assert!(jname.ends_with(".json"));
        // Empty lists are skipped when asked; unknown lists are refused.
        assert!(export_list(&st, &cid, "ev1", 0, "linux-commands", false, "tester", true).unwrap().is_none());
        assert!(export_list(&st, &cid, "ev1", 0, "../x", false, "tester", false).is_err());
        // Both exports are in the audit log with their hashes.
        let log = std::fs::read_to_string(case.dir.join("audit.jsonl")).unwrap();
        assert_eq!(log.matches("\"list.export\"").count(), 2);
        let (h, _) = kokino_core::hashing::hash_reader(&data[..], |_| true).unwrap();
        assert!(log.contains(&h.sha256));
        std::fs::remove_dir_all(&root).ok();
    }
}
