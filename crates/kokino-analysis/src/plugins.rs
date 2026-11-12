//! Plugins: parsers for artifacts Kokino does not read itself, as separate
//! programs.
//!
//! A plugin is a folder holding `plugin.json`:
//!
//! ```json
//! {
//!   "name": "Example parser",
//!   "version": "1.0",
//!   "description": "What it reads",
//!   "match": ["*.example", "Users/*/AppData/Roaming/Example/**"],
//!   "command": ["python", "parse.py", "{file}"],
//!   "timeout": 60,
//!   "max_file_size": 104857600
//! }
//! ```
//!
//! `match` patterns are compared with each file's path on the volume (any
//! case, / as separator, no leading /): `*` is any run of characters but /,
//! `**` any run including /, `?` one character; a pattern without / is
//! compared with the file name only. Every matching file with content,
//! live or deleted, is copied to a temporary folder (the evidence itself
//! is never handed to the plugin), and `command` runs with `{file}`
//! replaced by the copy's path, `{name}` by the file's name and `{path}`
//! by its path on the volume, in the plugin's folder, with no input, a
//! reduced environment and a time limit.
//!
//! The program writes JSON to standard output:
//!
//! ```json
//! {"rows": [{"time": "2026-10-20T08:05:30Z", "what": "...", "detail": "...",
//!            "fields": {"any": "value"}}],
//!  "notes": ["..."]}
//! ```
//!
//! or one row object per line. `time` (ISO 8601, UTC) and `fields` are
//! optional. Output beyond the limits is cut and said so; a plugin that
//! fails, times out or writes something else is reported with its error
//! output.
//!
//! Plugins are programs: they run with the rights of the Kokino server.
//! Only the folder an administrator gives Kokino is used, and nothing runs
//! until an examiner starts it.

use crate::{volume_reader, Analysis, Progress};
use kokino_image::Evidence;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const PLUGIN_SCHEMA: u32 = 1;
const MAX_OUTPUT: usize = 64 << 20;
const MAX_ROWS: usize = 200_000;
const MAX_FILES_PER_PLUGIN: usize = 10_000;
const DEFAULT_TIMEOUT: u64 = 60;
const DEFAULT_MAX_FILE: u64 = 256 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plugin {
    /// The folder's name: how the plugin is referred to.
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "match")]
    pub patterns: Vec<String>,
    pub command: Vec<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub max_file_size: Option<u64>,
    #[serde(skip)]
    pub dir: PathBuf,
}

/// The plugins in `dir` (one folder each), and the ones that could not be
/// loaded with why.
pub fn load(dir: &Path) -> (Vec<Plugin>, Vec<String>) {
    let mut out = vec![];
    let mut bad = vec![];
    let Ok(rd) = std::fs::read_dir(dir) else {
        return (out, vec![format!("plugin folder {} cannot be read", dir.display())]);
    };
    let mut entries: Vec<_> = rd.flatten().filter(|e| e.path().is_dir()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let id = e.file_name().to_string_lossy().to_string();
        let p = e.path().join("plugin.json");
        if !p.is_file() {
            continue;
        }
        match std::fs::read_to_string(&p).map_err(anyhow::Error::from).and_then(|t| Ok(serde_json::from_str::<Plugin>(&t)?)) {
            Ok(mut pl) => {
                if pl.command.is_empty() || pl.patterns.is_empty() {
                    bad.push(format!("{}: plugin.json needs \"match\" and \"command\"", id));
                    continue;
                }
                pl.id = id;
                pl.dir = e.path();
                out.push(pl);
            }
            Err(err) => bad.push(format!("{}: {}", id, err)),
        }
    }
    (out, bad)
}

/// One plugin from its own folder (for testing it).
pub fn load_one(dir: &Path) -> anyhow::Result<Plugin> {
    let p = dir.join("plugin.json");
    let text = std::fs::read_to_string(&p).map_err(|e| anyhow::anyhow!("{}: {}", p.display(), e))?;
    let mut pl: Plugin = serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {}", p.display(), e))?;
    if pl.command.is_empty() || pl.patterns.is_empty() {
        anyhow::bail!("{}: needs \"match\" and \"command\"", p.display());
    }
    pl.id = dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    pl.dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    Ok(pl)
}

/// What a test run of a plugin on one file shows its author.
#[derive(Debug, Default, Serialize)]
pub struct TestRun {
    /// Whether `path` matches the plugin's patterns (the plugin would be
    /// given this file in a real run).
    pub matches: bool,
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
    /// Things to fix: rows without a readable time or without "what".
    pub warnings: Vec<String>,
    pub millis: u128,
}

/// Runs a plugin on one local file the way a real run does (on a copy,
/// with its time limit and the reduced environment). `path` is where the
/// file would be on a volume ("/Users/alice/x.url"); it decides the match.
pub fn test_file(pl: &Plugin, file: &Path, path: &str) -> anyhow::Result<TestRun> {
    let mut t = TestRun { matches: pl.patterns.iter().any(|p| glob(p, path)), ..Default::default() };
    let size = std::fs::metadata(file)?.len();
    if size > pl.max_file_size.unwrap_or(DEFAULT_MAX_FILE) {
        t.warnings.push(format!("{} bytes: larger than max_file_size, a real run would skip this file", size));
    }
    let work = std::env::temp_dir().join(format!("kokino-plugin-test-{}", uuid_like()));
    std::fs::create_dir_all(&work)?;
    let name = path.rsplit('/').next().unwrap_or("file");
    let copy = work.join(safe_name(name));
    std::fs::copy(file, &copy)?;
    let start = Instant::now();
    let res = exec(pl, &copy, name, path);
    t.millis = start.elapsed().as_millis();
    let _ = std::fs::remove_dir_all(&work);
    let (rows, notes) = res?;
    for (i, r) in rows.iter().enumerate() {
        if !r.time.is_empty() && row_time(&r.time).is_none() {
            t.warnings.push(format!("row {}: time \"{}\" is not ISO 8601; the row will not be on the timelines", i + 1, r.time));
        }
        if r.what.is_empty() {
            t.warnings.push(format!("row {}: no \"what\"", i + 1));
        }
    }
    t.rows = rows;
    t.notes = notes;
    Ok(t)
}

/// Glob match: `*` any run but /, `**` any run, `?` one character.
pub fn glob(pattern: &str, text: &str) -> bool {
    // Tokens: literal byte, ? (one character but /), * (a run without /),
    // ** (any run). Matched by dynamic programming over (token, position).
    fn go(p: &[u8], t: &[u8]) -> bool {
        #[derive(Clone, Copy, PartialEq)]
        enum Tok {
            Byte(u8),
            One,
            Star,
            Deep,
        }
        let mut toks = vec![];
        let mut i = 0;
        while i < p.len() {
            if p[i] == b'*' && p.get(i + 1) == Some(&b'*') {
                // "**/" also matches no folder at all (see Byte below).
                toks.push(Tok::Deep);
                i += 2;
            } else if p[i] == b'*' {
                toks.push(Tok::Star);
                i += 1;
            } else if p[i] == b'?' {
                toks.push(Tok::One);
                i += 1;
            } else {
                toks.push(Tok::Byte(p[i]));
                i += 1;
            }
        }
        if t.len() > 1 << 16 || toks.len() > 256 {
            return false;
        }
        // ok[j]: tokens matched so far can end at text position j.
        let mut ok = vec![false; t.len() + 1];
        ok[0] = true;
        for (k, tok) in toks.iter().enumerate() {
            let mut next = vec![false; t.len() + 1];
            match tok {
                Tok::Byte(b) => {
                    for j in 0..t.len() {
                        if ok[j] && t[j] == *b {
                            next[j + 1] = true;
                        }
                    }
                    // "**/" may match nothing: a Deep followed by "/" can skip the slash.
                    if *b == b'/' && k > 0 && toks[k - 1] == Tok::Deep {
                        for j in 0..=t.len() {
                            if ok[j] && (j == 0 || t[j - 1] == b'/') {
                                next[j] = true;
                            }
                        }
                    }
                }
                Tok::One => {
                    for j in 0..t.len() {
                        if ok[j] && t[j] != b'/' {
                            next[j + 1] = true;
                        }
                    }
                }
                Tok::Star => {
                    let mut on = false;
                    for j in 0..=t.len() {
                        on = ok[j] || (on && j > 0 && t[j - 1] != b'/');
                        next[j] = on;
                    }
                }
                Tok::Deep => {
                    let mut on = false;
                    for j in 0..=t.len() {
                        on = on || ok[j];
                        next[j] = on;
                    }
                }
            }
            ok = next;
        }
        ok[t.len()]
    }
    let p = pattern.trim_start_matches('/').replace('\\', "/").to_lowercase();
    let t = text.trim_start_matches('/').to_lowercase();
    if !p.contains('/') {
        let name = t.rsplit('/').next().unwrap_or("");
        return go(p.as_bytes(), name.as_bytes());
    }
    go(p.as_bytes(), t.as_bytes())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Row {
    /// Which file it came from.
    pub fi: usize,
    pub file: usize,
    pub path: String,
    #[serde(default)]
    pub time: String,
    #[serde(default)]
    pub what: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub fields: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginRun {
    pub plugin: String,
    pub name: String,
    pub version: String,
    pub files: usize,
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
    /// Files the plugin failed on: (path, error).
    pub errors: Vec<(String, String)>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginResults {
    pub schema: u32,
    pub tool_version: String,
    pub ran_at: String,
    pub runs: Vec<PluginRun>,
}

/// A row's time as a FILETIME: ISO 8601 with a zone or Z, or without one
/// (taken as UTC), or a date alone (midnight UTC).
pub fn row_time(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.len() < 10 {
        return None;
    }
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(kokino_core::time::datetime_to_filetime(t.with_timezone(&chrono::Utc)));
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(s, f) {
            return Some(kokino_core::time::datetime_to_filetime(t.and_utc()));
        }
    }
    chrono::NaiveDate::parse_from_str(s.get(..10)?, "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0)).map(|t| kokino_core::time::datetime_to_filetime(t.and_utc()))
}

/// The dated rows of a plugin run, in time order, for the timelines:
/// (time, run, row).
#[derive(Debug, Default)]
pub struct Dated {
    pub results: PluginResults,
    pub events: Vec<(u64, u32, u32)>,
}

impl Dated {
    pub fn new(results: PluginResults) -> Dated {
        let mut events = vec![];
        for (ri, run) in results.runs.iter().enumerate() {
            for (k, row) in run.rows.iter().enumerate() {
                if let Some(t) = row_time(&row.time).filter(|&t| t > 0) {
                    events.push((t, ri as u32, k as u32));
                }
            }
        }
        events.sort_unstable();
        Dated { results, events }
    }

    pub fn row(&self, run: u32, row: u32) -> Option<(&PluginRun, &Row)> {
        let r = self.results.runs.get(run as usize)?;
        Some((r, r.rows.get(row as usize)?))
    }
}

/// Runs `plugins` over every matching file of the analyzed evidence.
pub fn run(ev: &Evidence, analysis: &Analysis, plugins: &[Plugin], progress: Progress) -> anyhow::Result<PluginResults> {
    let mut res = PluginResults { schema: PLUGIN_SCHEMA, tool_version: kokino_core::TOOL_VERSION.into(), ran_at: kokino_core::time::now_iso(), runs: vec![] };
    let work = std::env::temp_dir().join(format!("kokino-plugins-{}", uuid_like()));
    std::fs::create_dir_all(&work)?;
    // Each plugin's matching files: (filesystem, file index).
    let todo: Vec<Vec<(usize, usize)>> = plugins
        .iter()
        .map(|pl| {
            let mut v = vec![];
            for (fi, f) in analysis.filesystems.iter().enumerate().filter(|(_, f)| f.volume.shadow.is_none()) {
                for (i, r) in f.files.iter().enumerate() {
                    if !r.e.is_dir && r.e.size > 0 && pl.patterns.iter().any(|p| glob(p, &r.e.path)) {
                        v.push((fi, i));
                    }
                }
            }
            v
        })
        .collect();
    let total: u64 = todo.iter().map(|v| v.len().min(MAX_FILES_PER_PLUGIN) as u64).sum();
    let mut done = 0u64;
    for (pl, files) in plugins.iter().zip(todo) {
        let mut run = PluginRun { plugin: pl.id.clone(), name: pl.name.clone(), version: pl.version.clone(), files: files.len(), ..Default::default() };
        if files.len() > MAX_FILES_PER_PLUGIN {
            run.notes.push(format!("{} files match; the first {} were given to the plugin", files.len(), MAX_FILES_PER_PLUGIN));
            run.truncated = true;
        }
        let mut handles: std::collections::HashMap<usize, (crate::fs::Fs, kokino_image::BlockCache<kokino_image::VolReader>)> = Default::default();
        for (fi, i) in files.into_iter().take(MAX_FILES_PER_PLUGIN) {
            done += 1;
            if !progress(&format!("Plugin {}", pl.name), done, total) {
                let _ = std::fs::remove_dir_all(&work);
                anyhow::bail!("plugins cancelled");
            }
            let fsa = &analysis.filesystems[fi];
            let e = &fsa.files[i].e;
            if e.size > pl.max_file_size.unwrap_or(DEFAULT_MAX_FILE) {
                run.errors.push((e.path.clone(), format!("{} bytes: larger than the plugin's limit", e.size)));
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(v) = handles.entry(fi) {
                let mut r = volume_reader(ev, &fsa.volume)?;
                let fs = crate::fs::Fs::open(&mut r, &fsa.volume)?;
                v.insert((fs, r));
            }
            let (fs, r) = handles.get_mut(&fi).unwrap();
            let copy = work.join(format!("{}-{}-{}", fi, i, safe_name(&e.name)));
            let copied = (|| -> anyhow::Result<()> {
                let mut src = crate::fs::stream(fs, r, e);
                let mut out = std::fs::File::create(&copy)?;
                std::io::copy(&mut src, &mut out)?;
                out.flush()?;
                Ok(())
            })();
            if let Err(err) = copied {
                run.errors.push((e.path.clone(), format!("cannot be read: {:#}", err)));
                continue;
            }
            match exec(pl, &copy, &e.name, &e.path) {
                Ok((rows, notes)) => {
                    for mut row in rows {
                        if run.rows.len() >= MAX_ROWS {
                            run.truncated = true;
                            break;
                        }
                        row.fi = fi;
                        row.file = i;
                        row.path = e.path.clone();
                        run.rows.push(row);
                    }
                    run.notes.extend(notes.into_iter().take(20).map(|n| format!("{}: {}", e.path, n)));
                }
                Err(err) => run.errors.push((e.path.clone(), format!("{:#}", err))),
            }
            let _ = std::fs::remove_file(&copy);
        }
        if run.truncated && !run.notes.iter().any(|n| n.contains("rows")) && run.rows.len() >= MAX_ROWS {
            run.notes.push(format!("cut at {} rows", MAX_ROWS));
        }
        res.runs.push(run);
    }
    let _ = std::fs::remove_dir_all(&work);
    Ok(res)
}

fn uuid_like() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{}-{:x}", std::process::id(), t)
}

/// A file name safe on every system, keeping the extension.
fn safe_name(n: &str) -> String {
    let s: String = n.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
    let s = s.trim_start_matches('.').to_string();
    let s = if s.len() > 100 { s[s.len() - 100..].to_string() } else { s };
    if s.is_empty() { "file".into() } else { s }
}

/// Runs the plugin on one copied file and reads its output.
fn exec(pl: &Plugin, copy: &Path, name: &str, path: &str) -> anyhow::Result<(Vec<Row>, Vec<String>)> {
    let fill = |a: &str| a.replace("{file}", &copy.to_string_lossy()).replace("{name}", name).replace("{path}", path);
    let args: Vec<String> = pl.command.iter().map(|a| fill(a)).collect();
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]).current_dir(&pl.dir).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).env_clear();
    // Only what a program needs to start.
    for k in ["PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP", "HOME", "LANG", "PATHEXT", "COMSPEC"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    // Its own process group, so a time-out stops whatever it started too.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().map_err(|err| anyhow::anyhow!("cannot start {}: {}", args[0], err))?;
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut b = vec![];
        let _ = (&mut so).take(MAX_OUTPUT as u64 + 1).read_to_end(&mut b);
        // Keep draining so the program is not blocked on a full pipe.
        let _ = std::io::copy(&mut so, &mut std::io::sink());
        b
    });
    let err_t = std::thread::spawn(move || {
        let mut b = vec![];
        let _ = (&mut se).take(64 << 10).read_to_end(&mut b);
        let _ = std::io::copy(&mut se, &mut std::io::sink());
        b
    });
    let limit = Duration::from_secs(pl.timeout.unwrap_or(DEFAULT_TIMEOUT).clamp(1, 3600));
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break Some(s);
        }
        if start.elapsed() > limit {
            kill_tree(child.id());
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let Some(status) = status else {
        // Not waiting for the output: a program it started may hold it open.
        anyhow::bail!("stopped after {} s (the plugin's time limit)", limit.as_secs());
    };
    let out = out_t.join().unwrap_or_default();
    let err = err_t.join().unwrap_or_default();
    let err_text = String::from_utf8_lossy(&err).trim().chars().take(500).collect::<String>();
    if !status.success() {
        anyhow::bail!("exited with {}{}", status, if err_text.is_empty() { String::new() } else { format!(": {}", err_text) });
    }
    let mut notes = vec![];
    if out.len() > MAX_OUTPUT {
        notes.push(format!("output cut at {} MB", MAX_OUTPUT >> 20));
    }
    let text = String::from_utf8_lossy(&out[..out.len().min(MAX_OUTPUT)]);
    let (rows, more) = parse_output(&text)?;
    notes.extend(more);
    Ok((rows, notes))
}

/// Stops a process and everything it started.
fn kill_tree(pid: u32) {
    if cfg!(windows) {
        let _ = Command::new("taskkill").args(["/T", "/F", "/PID", &pid.to_string()]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    } else {
        let _ = Command::new("kill").args(["-KILL", "--", &format!("-{}", pid)]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

/// The plugin's output: one JSON object with "rows" (and "notes"), or one
/// row object per line.
pub fn parse_output(text: &str) -> anyhow::Result<(Vec<Row>, Vec<String>)> {
    let t = text.trim();
    if t.is_empty() {
        return Ok((vec![], vec![]));
    }
    let row = |v: &Value| -> Option<Row> {
        let o = v.as_object()?;
        let s = |k: &str| o.get(k).map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).unwrap_or_default().chars().take(4000).collect::<String>();
        let fields = o.get("fields").and_then(Value::as_object).cloned().unwrap_or_default();
        Some(Row { time: s("time"), what: s("what"), detail: s("detail"), fields, ..Default::default() })
    };
    if let Ok(v) = serde_json::from_str::<Value>(t) {
        if let Some(rows) = v.get("rows").and_then(Value::as_array) {
            let notes = v.get("notes").and_then(Value::as_array).map(|n| n.iter().filter_map(|x| x.as_str().map(|s| s.chars().take(500).collect())).collect()).unwrap_or_default();
            return Ok((rows.iter().take(MAX_ROWS).filter_map(row).collect(), notes));
        }
        if let Some(arr) = v.as_array() {
            return Ok((arr.iter().take(MAX_ROWS).filter_map(row).collect(), vec![]));
        }
        if v.is_object() {
            return Ok((row(&v).into_iter().collect(), vec![]));
        }
    }
    let mut rows = vec![];
    for (n, line) in t.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let v: Value = serde_json::from_str(line.trim()).map_err(|e| anyhow::anyhow!("output line {} is not JSON: {}", n + 1, e))?;
        if let Some(r) = row(&v) {
            rows.push(r);
        }
        if rows.len() >= MAX_ROWS {
            break;
        }
    }
    Ok((rows, vec![]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("*.pf", "/Windows/Prefetch/CMD.EXE-4A81B364.pf"));
        assert!(glob("*.PF", "/x/y.pf"));
        assert!(!glob("*.pf", "/x/y.pfx"));
        assert!(glob("Windows/Prefetch/*", "/Windows/Prefetch/A.pf"));
        assert!(!glob("Windows/*", "/Windows/Prefetch/A.pf"));
        assert!(glob("Windows/**", "/Windows/Prefetch/A.pf"));
        assert!(glob("Users/*/AppData/**/*.db", "/Users/alice/AppData/Local/x/y/z.db"));
        assert!(!glob("Users/*/AppData/**/*.db", "/Users/alice/bob/AppData/z.db"));
        assert!(glob("etc/ld.so.preload", "/etc/ld.so.preload"));
        assert!(glob("?.txt", "/a.txt") && !glob("?.txt", "/ab.txt"));
        assert!(glob("**", "/anything/at/all"));
        assert!(glob("Users/**/*.db", "/Users/z.db"), "**/ matches no folder too");
        assert!(glob("a*b*c", "/axxbyyc") && !glob("a*b*c", "/axx/byyc"));
    }

    /// A plugin command: a script written to `dir`, run with the file's
    /// copy as its argument (a .cmd on Windows, a shell script elsewhere).
    fn script(dir: &Path, name: &str, windows: &str, unix: &str) -> Vec<String> {
        if cfg!(windows) {
            let p = dir.join(format!("{}.cmd", name));
            std::fs::write(&p, format!("@echo off\r\n{}\r\n", windows)).unwrap();
            vec!["cmd".into(), "/C".into(), p.to_string_lossy().into(), "{file}".into()]
        } else {
            let p = dir.join(format!("{}.sh", name));
            std::fs::write(&p, format!("#!/bin/sh\n{}\n", unix)).unwrap();
            vec!["sh".into(), p.to_string_lossy().into(), "{file}".into()]
        }
    }

    fn plugin(dir: &Path, command: Vec<String>, patterns: &[&str], timeout: Option<u64>) -> Plugin {
        Plugin { id: "test".into(), name: "Test".into(), version: "1".into(), description: String::new(), patterns: patterns.iter().map(|x| x.to_string()).collect(), command, timeout, max_file_size: None, dir: dir.to_path_buf() }
    }

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kokino-plugin-test-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The copy of the file is what the plugin reads: here it prints it.
    #[test]
    fn runs_a_program_on_a_copy() {
        let dir = scratch();
        let f = dir.join("in.json");
        std::fs::write(&f, "{\"what\": \"from the file\", \"detail\": \"d\"}\n").unwrap();
        let cat = script(&dir, "cat", "type \"%~1\"", "cat \"$1\"");
        let (rows, _) = exec(&plugin(&dir, cat, &["*"], None), &f, "in.json", "/x/in.json").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].what, "from the file");
        // A program that fails is reported with its error output.
        let fail = script(&dir, "fail", "echo broken 1>&2\r\nexit /b 3", "echo broken 1>&2; exit 3");
        let err = exec(&plugin(&dir, fail, &["*"], None), &f, "in.json", "/x/in.json").unwrap_err().to_string();
        assert!(err.contains("broken"), "{}", err);
        // One that runs too long is stopped.
        let slow = script(&dir, "slow", "ping -n 6 127.0.0.1 >NUL", "sleep 5");
        let t = Instant::now();
        let err = exec(&plugin(&dir, slow, &["*"], Some(1)), &f, "in.json", "/x/in.json").unwrap_err().to_string();
        assert!(err.contains("time limit") && t.elapsed() < Duration::from_secs(4), "{}", err);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Testing one plugin on one file, as its author would.
    #[test]
    fn tests_a_plugin_on_one_file() {
        let dir = scratch();
        let cmd = script(&dir, "rows", "echo {\"what\": \"a\", \"time\": \"2026-10-20T08:05:30Z\"}\r\necho {\"what\": \"\", \"time\": \"last tuesday\"}", "echo '{\"what\": \"a\", \"time\": \"2026-10-20T08:05:30Z\"}'; echo '{\"what\": \"\", \"time\": \"last tuesday\"}'");
        std::fs::write(dir.join("plugin.json"), serde_json::to_string(&serde_json::json!({"name": "Rows", "match": ["*.url"], "command": cmd})).unwrap()).unwrap();
        let pl = load_one(&dir).unwrap();
        let f = dir.join("x.bin");
        std::fs::write(&f, b"anything").unwrap();
        let t = test_file(&pl, &f, "/Users/alice/Lab.url").unwrap();
        assert!(t.matches);
        assert_eq!(t.rows.len(), 2);
        assert_eq!(t.warnings.len(), 2, "{:?}", t.warnings);
        assert!(!test_file(&pl, &f, "/Users/alice/Lab.txt").unwrap().matches);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Over a whole image: the files that match, each row tied to its file.
    #[test]
    fn runs_over_an_image() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ext4.img");
        let Ok(ev) = kokino_image::Evidence::open(&p) else { return };
        let a = crate::analyze(&ev, &mut |_, _, _| true).unwrap();
        let dir = scratch();
        let echo = script(&dir, "echo", "echo {\"what\": \"seen\", \"time\": \"2026-10-20T08:05:30Z\"}", "echo '{\"what\": \"seen\", \"time\": \"2026-10-20T08:05:30Z\"}'");
        let res = run(&ev, &a, &[plugin(&dir, echo, &["hello.txt", "docs/**/*.txt"], None)], &mut |_, _, _| true).unwrap();
        let r = &res.runs[0];
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let mut paths: Vec<&str> = r.rows.iter().map(|x| x.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, ["/docs/hello-link.txt", "/docs/notes/deep.txt", "/docs/report.txt", "/hello.txt"]);
        assert!(r.rows.iter().all(|x| x.what == "seen" && x.time == "2026-10-20T08:05:30Z"));
        assert_eq!(r.files, 4);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn row_times() {
        let iso = kokino_core::time::filetime_to_iso;
        assert_eq!(iso(row_time("2026-10-20T08:05:30Z").unwrap()), "2026-10-20T08:05:30.0000000Z");
        assert_eq!(iso(row_time("2026-10-20T10:05:30+02:00").unwrap()), "2026-10-20T08:05:30.0000000Z");
        assert_eq!(iso(row_time("2026-10-20 08:05:30").unwrap()), "2026-10-20T08:05:30.0000000Z");
        assert_eq!(iso(row_time("2026-10-20").unwrap()), "2026-10-20T00:00:00.0000000Z");
        assert!(row_time("").is_none() && row_time("yesterday").is_none());
        let res = PluginResults { runs: vec![PluginRun { rows: vec![Row { time: "2026-10-21".into(), ..Default::default() }, Row::default(), Row { time: "2026-10-20".into(), ..Default::default() }], ..Default::default() }], ..Default::default() };
        let d = Dated::new(res);
        assert_eq!(d.events.iter().map(|e| e.2).collect::<Vec<_>>(), [2, 0]);
    }

    #[test]
    fn output_forms() {
        let (r, n) = parse_output(r#"{"rows": [{"time": "2026-10-20T08:05:30Z", "what": "run", "detail": "x", "fields": {"n": 3}}, {"what": 5}], "notes": ["ok"]}"#).unwrap();
        assert_eq!((r.len(), r[0].what.as_str(), r[1].what.as_str(), n), (2, "run", "5", vec!["ok".to_string()]));
        assert_eq!(r[0].fields["n"], 3);
        let (r, _) = parse_output("{\"what\": \"a\"}\n\n{\"what\": \"b\"}\n").unwrap();
        assert_eq!(r.len(), 2);
        assert!(parse_output("not json\n").is_err());
        assert!(parse_output("").unwrap().0.is_empty());
    }
}
