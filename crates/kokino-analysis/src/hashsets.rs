//! Hash sets and hash analysis.
//!
//! A hash set is a list of file hashes of one kind: `Known` (known-good
//! files such as the NIST NSRL, hidden to cut noise) or `Notable`
//! (known-bad files the lab wants flagged). Sets are imported once into
//! `<cases>/.kokino/hashsets/<id>.sqlite`, one table per algorithm with the
//! binary hash as primary key, and are shared by every case.
//!
//! Sources: NSRL RDS v3 (SQLite, table FILE), NSRL RDS 2.x `NSRLFile.txt`
//! and other CSV files with a header naming the hash columns, and plain
//! lists (one hash per line, md5sum / sha256sum output, hashes mixed with
//! names): every token of 32, 40 or 64 hex digits is taken as MD5, SHA-1 or
//! SHA-256.
//!
//! Hash analysis computes MD5, SHA-1 and SHA-256 of every file of an
//! evidence item (live and deleted, where content is readable) and looks
//! them up in the enabled sets. Hashes are kept, so a changed set list only
//! needs a new lookup, not a new read of the evidence.

use crate::{volume_reader, Analysis, Progress};
use kokino_core::hashing::{sha256_hex, Hashes, MultiHasher};
use kokino_image::Evidence;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const FILEHASH_SCHEMA: u32 = 1;
const ALGOS: [&str; 3] = ["md5", "sha1", "sha256"];
/// NTFS records below this are file-system metadata ($MFT, $Bitmap...).
const FIRST_USER_RECORD: u64 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SetKind {
    /// Known-good: matching files can be hidden.
    Known,
    /// Known-bad: matching files are flagged.
    Notable,
}

impl SetKind {
    pub fn label(self) -> &'static str {
        match self {
            SetKind::Known => "known good",
            SetKind::Notable => "known bad",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSetInfo {
    pub id: String,
    pub name: String,
    pub kind: SetKind,
    #[serde(default)]
    pub description: String,
    pub enabled: bool,
    /// File name the set was imported from.
    pub source: String,
    pub source_sha256: String,
    pub source_bytes: u64,
    pub format: String,
    /// Distinct hashes per algorithm.
    pub md5: u64,
    pub sha1: u64,
    pub sha256: u64,
    /// Lines or rows read, and those without a usable hash.
    pub rows: u64,
    pub skipped: u64,
    pub imported_at: String,
    pub imported_by: String,
    /// How the source file was checked against its publisher's hash, e.g.
    /// "SHA-256 matches signatures.txt"; empty when nothing was published next to it.
    #[serde(default)]
    pub source_verified: String,
}

impl HashSetInfo {
    pub fn hashes(&self) -> u64 {
        self.md5 + self.sha1 + self.sha256
    }
}

/// Serializes changes to the set list within this process.
static LIST_LOCK: Mutex<()> = Mutex::new(());
/// Ids of imports in progress, whose files cleanup must leave alone.
static IMPORTING: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// `dir` is `<cases>/.kokino/hashsets`; it is created on first import.
    pub fn open(dir: impl Into<PathBuf>) -> Self {
        Store { dir: dir.into() }
    }

    fn list_path(&self) -> PathBuf {
        self.dir.join("sets.json")
    }

    fn db_path(&self, id: &str) -> anyhow::Result<PathBuf> {
        Ok(self.dir.join(format!("{}.sqlite", kokino_core::case::safe_id(id)?)))
    }

    pub fn list(&self) -> anyhow::Result<Vec<HashSetInfo>> {
        let p = self.list_path();
        if !p.exists() {
            return Ok(vec![]);
        }
        Ok(serde_json::from_slice(&std::fs::read(p)?)?)
    }

    fn update<T>(&self, f: impl FnOnce(&mut Vec<HashSetInfo>) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let _g = LIST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::fs::create_dir_all(&self.dir)?;
        let mut list = self.list()?;
        let out = f(&mut list)?;
        kokino_core::case::write_json(&self.list_path(), &list)?;
        Ok(out)
    }

    pub fn get(&self, id: &str) -> anyhow::Result<HashSetInfo> {
        self.list()?.into_iter().find(|s| s.id == id).ok_or_else(|| anyhow::anyhow!("no such hash set"))
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> anyhow::Result<HashSetInfo> {
        self.update(|l| {
            let s = l.iter_mut().find(|s| s.id == id).ok_or_else(|| anyhow::anyhow!("no such hash set"))?;
            s.enabled = enabled;
            Ok(s.clone())
        })
    }

    pub fn delete(&self, id: &str) -> anyhow::Result<HashSetInfo> {
        let s = self.update(|l| {
            let i = l.iter().position(|s| s.id == id).ok_or_else(|| anyhow::anyhow!("no such hash set"))?;
            Ok(l.remove(i))
        })?;
        self.cleanup();
        Ok(s)
    }

    /// Removes databases of deleted sets and unfinished imports. A file
    /// still open (a lookup running on Windows) is left for the next time.
    fn cleanup(&self) {
        let Ok(list) = self.list() else { return };
        let busy = IMPORTING.lock().unwrap_or_else(|e| e.into_inner()).clone();
        for e in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let id = name.split('.').next().unwrap_or("");
            let ours = name.ends_with(".sqlite") || name.ends_with(".sqlite.part");
            if ours && !list.iter().any(|s| s.id == id) && !busy.iter().any(|b| b == id) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    /// Imports `src` as a new, enabled set.
    pub fn import(&self, src: &Path, name: &str, kind: SetKind, description: &str, user: &str, progress: Progress) -> anyhow::Result<HashSetInfo> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
            anyhow::bail!("a hash set name is 1 to 80 printable characters");
        }
        if self.list()?.iter().any(|s| s.name.eq_ignore_ascii_case(name)) {
            anyhow::bail!("a hash set named \"{}\" exists already", name);
        }
        let meta = std::fs::metadata(src).map_err(|e| anyhow::anyhow!("{}: {}", src.display(), e))?;
        if !meta.is_file() {
            anyhow::bail!("{} is not a file", src.display());
        }
        std::fs::create_dir_all(&self.dir)?;
        let now = kokino_core::time::now_iso();
        let id = sha256_hex(format!("{}|{}|{}", name, now, src.display()).as_bytes())[..12].to_string();
        let part = self.dir.join(format!("{}.sqlite.part", id));
        self.cleanup();
        IMPORTING.lock().unwrap_or_else(|e| e.into_inner()).push(id.clone());
        let res = (|| {
            let (source_sha256, _) = kokino_core::hashing::hash_reader(std::fs::File::open(src)?, |d| progress("Hashing the source file", d, meta.len()))?;
            let source_verified = check_signatures(src, &source_sha256.sha256)?;
            let mut w = Writer::create(&part)?;
            let format = if is_sqlite(src)? {
                import_sqlite(src, &mut w, progress)?
            } else if is_sql_dump(src)? {
                import_sql_dump(src, meta.len(), &mut w, progress)?
            } else {
                import_text(src, meta.len(), &mut w, progress)?
            };
            progress("Finishing", 0, 1);
            let (rows, skipped, counts) = w.finish()?;
            if counts.iter().sum::<u64>() == 0 {
                anyhow::bail!("no MD5, SHA-1 or SHA-256 hashes found in {}", src.display());
            }
            Ok(HashSetInfo {
                id: id.clone(),
                name: name.to_string(),
                kind,
                description: description.trim().chars().take(500).collect(),
                enabled: true,
                source: src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                source_sha256: source_sha256.sha256,
                source_bytes: meta.len(),
                format,
                md5: counts[0],
                sha1: counts[1],
                sha256: counts[2],
                rows,
                skipped,
                imported_at: now.clone(),
                imported_by: user.to_string(),
                source_verified,
            })
        })();
        let res = res.and_then(|info| {
            std::fs::rename(&part, self.db_path(&id)?)?;
            self.update(|l| {
                l.push(info.clone());
                Ok(())
            })?;
            Ok(info)
        });
        IMPORTING.lock().unwrap_or_else(|e| e.into_inner()).retain(|x| *x != id);
        let res = res.map_err(|e| {
            let full = e.chain().any(|c| {
                c.downcast_ref::<rusqlite::Error>().is_some_and(|x| x.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull))
                    || c.downcast_ref::<std::io::Error>().is_some_and(|x| x.raw_os_error() == Some(112) || x.raw_os_error() == Some(28))
            });
            if full {
                anyhow::anyhow!("the disk holding {} is full: free some space and import again (nothing was imported)", self.dir.display())
            } else {
                e
            }
        });
        if res.is_err() {
            let _ = std::fs::remove_file(&part);
        }
        res
    }

    /// The enabled sets, opened for lookups.
    pub fn matcher(&self) -> anyhow::Result<Matcher> {
        let mut sets = vec![];
        for s in self.list()?.into_iter().filter(|s| s.enabled) {
            let db = Connection::open_with_flags(self.db_path(&s.id)?, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
                .map_err(|e| anyhow::anyhow!("hash set \"{}\": {}", s.name, e))?;
            sets.push((s, db));
        }
        Ok(Matcher { sets })
    }
}

/// Builds a set database: one table per algorithm, duplicates ignored.
struct Writer {
    db: Connection,
    rows: u64,
    skipped: u64,
    pending: u64,
}

impl Writer {
    fn create(p: &Path) -> anyhow::Result<Self> {
        let db = Connection::open(p)?;
        db.execute_batch(
            "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-262144;
             CREATE TABLE md5(h BLOB PRIMARY KEY) WITHOUT ROWID;
             CREATE TABLE sha1(h BLOB PRIMARY KEY) WITHOUT ROWID;
             CREATE TABLE sha256(h BLOB PRIMARY KEY) WITHOUT ROWID;
             BEGIN;",
        )?;
        Ok(Writer { db, rows: 0, skipped: 0, pending: 0 })
    }

    /// One row or line: whatever hashes it holds.
    fn row(&mut self, hashes: &[Vec<u8>]) -> anyhow::Result<()> {
        self.rows += 1;
        if hashes.is_empty() {
            self.skipped += 1;
            return Ok(());
        }
        for h in hashes {
            let t = match h.len() {
                16 => "INSERT OR IGNORE INTO md5 VALUES (?1)",
                20 => "INSERT OR IGNORE INTO sha1 VALUES (?1)",
                32 => "INSERT OR IGNORE INTO sha256 VALUES (?1)",
                _ => continue,
            };
            self.db.prepare_cached(t)?.execute([h])?;
        }
        self.pending += 1;
        if self.pending >= 500_000 {
            self.db.execute_batch("COMMIT; BEGIN;")?;
            self.pending = 0;
        }
        Ok(())
    }

    fn finish(self) -> anyhow::Result<(u64, u64, [u64; 3])> {
        self.db.execute_batch("COMMIT;")?;
        let mut counts = [0u64; 3];
        for (i, t) in ALGOS.iter().enumerate() {
            counts[i] = self.db.query_row(&format!("SELECT count(*) FROM {}", t), [], |r| r.get::<_, i64>(0))? as u64;
        }
        // No VACUUM: the file was just written and has little free space to
        // reclaim, while VACUUM needs as much disk again to rebuild it.
        self.db.execute_batch("PRAGMA journal_mode=DELETE;")?;
        Ok((self.rows, self.skipped, counts))
    }
}

/// A hex hash (MD5, SHA-1 or SHA-256 length) as bytes.
fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_matches('"');
    if !matches!(s.len(), 32 | 40 | 64) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn is_sqlite(p: &Path) -> anyhow::Result<bool> {
    let mut b = [0u8; 16];
    let n = std::fs::File::open(p)?.read(&mut b)?;
    Ok(n == 16 && &b == b"SQLite format 3\0")
}

/// NSRL RDS v3 and other SQLite files: the table FILE, or else the first
/// table with md5 / sha1 / sha256 columns.
fn import_sqlite(src: &Path, w: &mut Writer, progress: Progress) -> anyhow::Result<String> {
    let db = Connection::open_with_flags(src, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    // A downloaded hash set is outside data too. The full NSRL takes a while,
    // so the time limit is generous.
    kokino_artifacts::sqlite::harden(&db, std::time::Duration::from_secs(4 * 3600))?;
    let tables: Vec<String> = db.prepare("SELECT name FROM sqlite_master WHERE type='table'")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut best: Option<(String, Vec<Option<String>>)> = None;
    for t in &tables {
        let cols: Vec<String> = db.prepare(&format!("PRAGMA table_info(\"{}\")", t.replace('"', "\"\"")))?.query_map([], |r| r.get(1))?.collect::<Result<_, _>>()?;
        let find = |names: &[&str]| cols.iter().find(|c| names.iter().any(|n| c.eq_ignore_ascii_case(n))).cloned();
        let found = vec![find(&["md5"]), find(&["sha1", "sha-1"]), find(&["sha256", "sha-256"])];
        if found.iter().any(Option::is_some) && (best.is_none() || t.eq_ignore_ascii_case("file")) {
            best = Some((t.clone(), found));
        }
    }
    let (table, cols) = best.ok_or_else(|| anyhow::anyhow!("no table with md5, sha1 or sha256 columns in this SQLite file"))?;
    let q = |c: &Option<String>| c.as_ref().map(|c| format!("\"{}\"", c.replace('"', "\"\""))).unwrap_or_else(|| "NULL".into());
    let tq = format!("\"{}\"", table.replace('"', "\"\""));
    let total = db.query_row(&format!("SELECT max(rowid) FROM {}", tq), [], |r| r.get::<_, Option<i64>>(0)).ok().flatten().unwrap_or(0) as u64;
    let mut st = db.prepare(&format!("SELECT {}, {}, {} FROM {}", q(&cols[0]), q(&cols[1]), q(&cols[2]), tq))?;
    let mut rows = st.query([])?;
    let mut n = 0u64;
    while let Some(r) = rows.next()? {
        let mut hs = vec![];
        for i in 0..3 {
            let v: rusqlite::types::Value = r.get(i)?;
            let h = match v {
                rusqlite::types::Value::Text(s) => unhex(&s),
                rusqlite::types::Value::Blob(b) if matches!(b.len(), 16 | 20 | 32) => Some(b),
                _ => None,
            };
            hs.extend(h);
        }
        w.row(&hs)?;
        n += 1;
        if n % 65536 == 0 && !progress("Importing hashes", n.min(total), total.max(n)) {
            anyhow::bail!("import cancelled");
        }
    }
    Ok(if table.eq_ignore_ascii_case("file") { "NSRL RDS v3 (SQLite)".into() } else { format!("SQLite table {}", table) })
}

/// NIST ships `signatures.txt` ("SHA256(name)= hex" per file) with each
/// RDS release. When it lists the source, the SHA-256 must match: a file cut
/// short by a full disk or a broken download is refused. Returns how the
/// source was verified, or "" when no signature is published for it.
fn check_signatures(src: &Path, sha256: &str) -> anyhow::Result<String> {
    let (Some(dir), Some(name)) = (src.parent(), src.file_name().and_then(|n| n.to_str())) else { return Ok(String::new()) };
    let Ok(text) = std::fs::read_to_string(dir.join("signatures.txt")) else { return Ok(String::new()) };
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("SHA256(") else { continue };
        let Some((file, hex)) = rest.split_once(")=") else { continue };
        if file.trim() != name {
            continue;
        }
        let want = hex.trim().to_ascii_lowercase();
        if want != sha256.to_ascii_lowercase() {
            anyhow::bail!(
                "{} does not match the SHA-256 in signatures.txt next to it (published {}, file {}): the file is incomplete or altered, for example an unzip or download that stopped early. Extract it again and import once more; nothing was imported.",
                name, want, sha256
            );
        }
        return Ok("SHA-256 matches signatures.txt".into());
    }
    Ok(String::new())
}

/// A text file of SQL statements (NSRL publishes RDS deltas this way): starts
/// with BEGIN, CREATE, INSERT or PRAGMA.
fn is_sql_dump(p: &Path) -> anyhow::Result<bool> {
    let mut b = [0u8; 256];
    let n = std::fs::File::open(p)?.read(&mut b)?;
    let head = String::from_utf8_lossy(&b[..n]);
    let head = head.trim_start_matches('\u{feff}').trim_start().to_ascii_uppercase();
    Ok(["BEGIN TRANSACTION", "BEGIN;", "CREATE TABLE", "INSERT INTO", "PRAGMA "].iter().any(|k| head.starts_with(k)))
}

/// The values of one `VALUES(...)` list: SQL strings ('' is a quote), NULL,
/// numbers, X'..' blobs. None if it is not a well-formed list.
fn sql_values(s: &str) -> Option<Vec<Option<String>>> {
    let b = s.as_bytes();
    let mut i = s.find('(')? + 1;
    let mut out = vec![];
    loop {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        if b[i] == b'\'' {
            let mut v = Vec::new();
            i += 1;
            loop {
                match b.get(i)? {
                    b'\'' if b.get(i + 1) == Some(&b'\'') => {
                        v.push(b'\'');
                        i += 2;
                    }
                    b'\'' => {
                        i += 1;
                        break;
                    }
                    c => {
                        v.push(*c);
                        i += 1;
                    }
                }
            }
            out.push(Some(String::from_utf8_lossy(&v).into_owned()));
        } else {
            let start = i;
            while i < b.len() && b[i] != b',' && b[i] != b')' {
                i += 1;
            }
            let t = s[start..i].trim();
            out.push(if t.eq_ignore_ascii_case("NULL") { None } else { Some(t.to_string()) });
        }
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        match b.get(i)? {
            b',' => i += 1,
            b')' => return Some(out),
            _ => return None,
        }
    }
}

/// A SQL dump: every `INSERT INTO table(columns) VALUES(...)` whose columns
/// include md5, sha1 or sha256 adds those values, and only those (NSRL rows
/// also carry key_hash and other hex columns that are not file hashes).
/// Other statements are ignored.
fn import_sql_dump(src: &Path, size: u64, w: &mut Writer, progress: Progress) -> anyhow::Result<String> {
    let mut r = BufReader::with_capacity(1 << 20, std::fs::File::open(src)?);
    let mut buf = vec![];
    let mut stmt = String::new();
    let mut read = 0u64;
    // Per column list: the indexes of md5, sha1 and sha256.
    let mut layouts: std::collections::HashMap<String, [Option<usize>; 3]> = Default::default();
    let mut tables: std::collections::BTreeSet<String> = Default::default();
    loop {
        buf.clear();
        let n = r.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        read += n as u64;
        stmt.push_str(&String::from_utf8_lossy(&buf));
        // A statement ends at a line ending in ';' outside quotes (an even number of ').
        if !(stmt.trim_end().ends_with(';') && stmt.bytes().filter(|&c| c == b'\'').count() % 2 == 0) {
            if stmt.len() > 64 << 20 {
                anyhow::bail!("a statement longer than 64 MiB: not a SQL dump Kokino can read");
            }
            continue;
        }
        let line = std::mem::take(&mut stmt);
        let t = line.trim_start();
        if t.len() < 12 || !t[..12].eq_ignore_ascii_case("INSERT INTO ") {
            continue;
        }
        let Some(open) = t.find('(') else { continue };
        let Some(vpos) = t.find(") VALUES(").or_else(|| t.find(") VALUES (")).or_else(|| t.to_ascii_uppercase().find(") VALUES")) else { continue };
        if vpos < open {
            continue;
        }
        let cols = &t[open + 1..vpos];
        let layout = *layouts.entry(cols.to_string()).or_insert_with(|| {
            let names: Vec<String> = cols.split(',').map(|c| c.trim().trim_matches(|x| x == '"' || x == '`' || x == '[' || x == ']').to_ascii_lowercase()).collect();
            let at = |n: &[&str]| names.iter().position(|c| n.contains(&c.as_str()));
            [at(&["md5"]), at(&["sha1", "sha-1"]), at(&["sha256", "sha-256"])]
        });
        if layout.iter().all(Option::is_none) {
            continue;
        }
        tables.insert(t[12..open].trim().trim_matches('"').to_string());
        let vals = sql_values(&t[vpos + 1..]).unwrap_or_default();
        let hs: Vec<Vec<u8>> = layout.iter().flatten().filter_map(|&i| vals.get(i).cloned().flatten().and_then(|v| unhex(&v))).collect();
        w.row(&hs)?;
        if w.rows % 65536 == 0 && !progress("Importing hashes", read.min(size), size) {
            anyhow::bail!("import cancelled");
        }
    }
    if !stmt.trim().is_empty() {
        anyhow::bail!("the SQL file ends in the middle of a statement: it is cut short (an unzip or download that stopped early?). Nothing was imported.");
    }
    if tables.is_empty() {
        anyhow::bail!("no INSERT statements with md5, sha1 or sha256 columns in this SQL file");
    }
    let nsrl = tables.iter().any(|t| t.eq_ignore_ascii_case("metadata") || t.eq_ignore_ascii_case("file"));
    Ok(if nsrl { "NSRL RDS v3 (SQL)".into() } else { format!("SQL dump ({})", tables.iter().cloned().collect::<Vec<_>>().join(", ")) })
}

/// Splits one CSV line, honouring double quotes.
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn import_text(src: &Path, size: u64, w: &mut Writer, progress: Progress) -> anyhow::Result<String> {
    let mut r = BufReader::with_capacity(1 << 20, std::fs::File::open(src)?);
    let mut buf = vec![];
    let mut read = 0u64;
    // Column indexes of md5, sha1, sha256 when the file has a CSV header.
    let mut header: Option<[Option<usize>; 3]> = None;
    let mut first = true;
    let mut format = "Hash list".to_string();
    loop {
        buf.clear();
        let n = r.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        read += n as u64;
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if first {
            first = false;
            let fields: Vec<String> = csv_fields(line).into_iter().map(|f| f.trim().to_ascii_lowercase()).collect();
            let col = |names: &[&str]| fields.iter().position(|f| names.contains(&f.as_str()));
            let h = [col(&["md5"]), col(&["sha-1", "sha1"]), col(&["sha-256", "sha256"])];
            if h.iter().any(Option::is_some) && fields.iter().all(|f| unhex(f).is_none()) {
                format = if fields.first().map(|f| f == "sha-1").unwrap_or(false) && fields.iter().any(|f| f == "productcode") { "NSRL RDS 2.x (CSV)".into() } else { "CSV with a header".into() };
                header = Some(h);
                continue;
            }
        }
        let hs: Vec<Vec<u8>> = match &header {
            Some(cols) => {
                let f = csv_fields(line);
                cols.iter().flatten().filter_map(|&i| f.get(i).and_then(|v| unhex(v))).collect()
            }
            None => line.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '|' | '"' | '\'' | '*' | ':')).filter_map(unhex).collect(),
        };
        w.row(&hs)?;
        if w.rows % 65536 == 0 && !progress("Importing hashes", read.min(size), size) {
            anyhow::bail!("import cancelled");
        }
    }
    Ok(format)
}

/// The enabled sets, opened read-only.
pub struct Matcher {
    sets: Vec<(HashSetInfo, Connection)>,
}

impl Matcher {
    pub fn sets(&self) -> Vec<HashSetInfo> {
        self.sets.iter().map(|s| s.0.clone()).collect()
    }

    /// Sets containing one of these hashes: (set index, algorithm), the
    /// strongest algorithm first.
    pub fn lookup(&self, h: &Hashes) -> anyhow::Result<Vec<(usize, &'static str)>> {
        let mut out = vec![];
        for (i, (_, db)) in self.sets.iter().enumerate() {
            for (algo, hex) in [("sha256", &h.sha256), ("sha1", &h.sha1), ("md5", &h.md5)] {
                let Some(b) = unhex(hex) else { continue };
                let hit: Option<i64> = db.prepare_cached(&format!("SELECT 1 FROM {} WHERE h=?1", algo))?.query_row([b], |r| r.get(0)).ok();
                if hit.is_some() {
                    out.push((i, algo));
                    break;
                }
            }
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    pub fi: usize,
    pub record: u64,
    pub size: u64,
    #[serde(flatten)]
    pub hashes: Hashes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    /// Index into `files`.
    pub file: usize,
    /// Index into `sets`.
    pub set: usize,
    pub algo: String,
}

/// Hash analysis of one evidence item: every file's hashes and the set
/// matches, kept in `<case>/hashes/<eid>.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileHashes {
    pub schema: u32,
    pub tool_version: String,
    pub hashed_at: String,
    pub bytes: u64,
    pub files: Vec<FileHash>,
    pub matched_at: String,
    /// The sets used for `hits`, as they were then.
    pub sets: Vec<HashSetInfo>,
    pub hits: Vec<Hit>,
}

impl FileHashes {
    pub fn errors(&self) -> usize {
        self.files.iter().filter(|f| f.error.is_some()).count()
    }

    /// Files matching at least one set of this kind.
    pub fn count(&self, kind: SetKind) -> usize {
        let mut v: Vec<usize> = self.hits.iter().filter(|h| self.sets.get(h.set).map(|s| s.kind == kind).unwrap_or(false)).map(|h| h.file).collect();
        v.sort_unstable();
        v.dedup();
        v.len()
    }

    /// True when the enabled sets differ from the ones last matched.
    pub fn outdated(&self, current: &[HashSetInfo]) -> bool {
        let key = |l: &[HashSetInfo]| {
            let mut v: Vec<(String, SetKind)> = l.iter().map(|s| (s.id.clone(), s.kind)).collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            v
        };
        key(&self.sets) != key(&current.iter().filter(|s| s.enabled).cloned().collect::<Vec<_>>())
    }
}

/// MD5, SHA-1 and SHA-256 of every file with content (live and deleted
/// where readable; NTFS metadata files left out).
pub fn hash_files(ev: &Evidence, analysis: &Analysis, progress: Progress) -> anyhow::Result<FileHashes> {
    let mut out = FileHashes { schema: FILEHASH_SCHEMA, tool_version: kokino_core::TOOL_VERSION.into(), hashed_at: kokino_core::time::now_iso(), ..Default::default() };
    let total: u64 = analysis.filesystems.iter().flat_map(|f| &f.files).filter(|f| !f.e.is_dir).map(|f| f.e.size).sum();
    let mut done = 0u64;
    for (fi, fsa) in analysis.filesystems.iter().enumerate() {
        let mut r = volume_reader(ev, &fsa.volume)?;
        let Ok(fs) = crate::fs::Fs::open(&mut r, &fsa.volume) else { continue };
        for f in &fsa.files {
            if f.e.is_dir || f.e.size == 0 || f.e.name_only.is_some() || (fs.is_ntfs() && (f.e.record < FIRST_USER_RECORD || f.e.path.starts_with("/$Extend"))) {
                continue;
            }
            let mut h = MultiHasher::default();
            let mut off = 0u64;
            let mut error = None;
            while off < f.e.size {
                let want = (f.e.size - off).min(4 << 20) as usize;
                match fs.read(&mut r, &f.e, "", off, want) {
                    Ok(d) if !d.is_empty() => {
                        h.update(&d);
                        off += d.len() as u64;
                        done += d.len() as u64;
                    }
                    Ok(_) => {
                        error = Some(format!("content ends after {} of {} bytes", off, f.e.size));
                        break;
                    }
                    Err(e) => {
                        error = Some(format!("{:#}", e));
                        break;
                    }
                }
                if !progress("Hashing files", done.min(total), total) {
                    anyhow::bail!("hash analysis cancelled");
                }
            }
            out.bytes += off;
            let hashes = if error.is_none() { h.finish() } else { Hashes::default() };
            out.files.push(FileHash { fi, record: f.e.record, size: f.e.size, hashes, error });
        }
    }
    Ok(out)
}

/// Looks every hashed file up in the matcher's sets.
pub fn match_sets(fh: &mut FileHashes, m: &Matcher, progress: Progress) -> anyhow::Result<()> {
    fh.sets = m.sets();
    fh.hits.clear();
    let n = fh.files.len() as u64;
    for (i, f) in fh.files.iter().enumerate() {
        if f.error.is_some() {
            continue;
        }
        for (set, algo) in m.lookup(&f.hashes)? {
            fh.hits.push(Hit { file: i, set, algo: algo.into() });
        }
        if i % 4096 == 0 && !progress("Looking up hash sets", i as u64, n) {
            anyhow::bail!("hash analysis cancelled");
        }
    }
    fh.matched_at = kokino_core::time::now_iso();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kokino-hs-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn hashes(data: &[u8]) -> Hashes {
        kokino_core::hashing::hash_reader(data, |_| true).unwrap().0
    }

    #[test]
    fn imports_lists_csv_and_sqlite_and_matches() {
        let d = tmp("import");
        let store = Store::open(d.join("sets"));
        let (a, b, c) = (hashes(b"alpha"), hashes(b"bravo"), hashes(b"charlie"));
        // md5sum / sha256sum style, comments, junk and a hex-looking file name.
        let list = d.join("bad.txt");
        std::fs::write(&list, format!("# lab list\n{}  alpha.bin\n{} *bravo.exe\nnot a hash\n{}\n{}.txt\n", a.md5, b.sha256, a.md5, c.md5)).unwrap();
        let bad = store.import(&list, "Lab known bad", SetKind::Notable, "", "tester", &mut |_, _, _| true).unwrap();
        assert_eq!((bad.md5, bad.sha1, bad.sha256), (1, 0, 1));
        assert_eq!((bad.rows, bad.skipped), (5, 2));
        assert_eq!(bad.format, "Hash list");
        // NSRL RDS 2.x CSV, with a comma inside a quoted file name.
        let csv = d.join("NSRLFile.txt");
        std::fs::write(&csv, format!("\"SHA-1\",\"MD5\",\"CRC32\",\"FileName\",\"FileSize\",\"ProductCode\",\"OpSystemCode\",\"SpecialCode\"\n\"{}\",\"{}\",\"0\",\"c, d.dll\",5,1,\"WIN\",\"\"\n", c.sha1.to_uppercase(), c.md5)).unwrap();
        let nsrl2 = store.import(&csv, "NSRL 2", SetKind::Known, "", "tester", &mut |_, _, _| true).unwrap();
        assert_eq!(nsrl2.format, "NSRL RDS 2.x (CSV)");
        assert_eq!((nsrl2.md5, nsrl2.sha1), (1, 1));
        // NSRL RDS v3 layout.
        let rds = d.join("rds.db");
        let db = Connection::open(&rds).unwrap();
        db.execute_batch("CREATE TABLE PKG(package_id INTEGER); CREATE TABLE FILE(sha256 TEXT, sha1 TEXT, md5 TEXT, file_name TEXT);").unwrap();
        db.execute("INSERT INTO FILE VALUES (?1, ?2, ?3, 'b')", [&b.sha256, &b.sha1, &b.md5]).unwrap();
        drop(db);
        let v3 = store.import(&rds, "NSRL 3", SetKind::Known, "", "tester", &mut |_, _, _| true).unwrap();
        assert_eq!(v3.format, "NSRL RDS v3 (SQLite)");
        assert_eq!((v3.md5, v3.sha1, v3.sha256), (1, 1, 1));
        assert!(store.import(&list, "lab KNOWN bad", SetKind::Notable, "", "t", &mut |_, _, _| true).is_err());
        let empty = d.join("empty.txt");
        std::fs::write(&empty, "nothing here\n").unwrap();
        assert!(store.import(&empty, "Empty", SetKind::Known, "", "t", &mut |_, _, _| true).is_err());
        assert_eq!(std::fs::read_dir(d.join("sets")).unwrap().count(), 4, "three databases and sets.json, no leftovers");

        let m = store.matcher().unwrap();
        let names = |h: &Hashes| m.lookup(h).unwrap().into_iter().map(|(i, algo)| format!("{}:{}", m.sets()[i].name, algo)).collect::<Vec<_>>();
        assert_eq!(names(&a), vec!["Lab known bad:md5"]);
        assert_eq!(names(&b), vec!["Lab known bad:sha256", "NSRL 3:sha256"]);
        assert_eq!(names(&c), vec!["NSRL 2:sha1"]);
        assert!(names(&hashes(b"delta")).is_empty());

        let mut fh = FileHashes { files: [&a, &b, &c].iter().enumerate().map(|(i, h)| FileHash { fi: 0, record: i as u64, size: 5, hashes: (*h).clone(), error: None }).collect(), ..Default::default() };
        match_sets(&mut fh, &m, &mut |_, _, _| true).unwrap();
        assert_eq!((fh.count(SetKind::Notable), fh.count(SetKind::Known)), (2, 2));
        assert!(!fh.outdated(&store.list().unwrap()));
        store.set_enabled(&v3.id, false).unwrap();
        assert!(fh.outdated(&store.list().unwrap()));
        drop(m);
        store.delete(&nsrl2.id).unwrap();
        assert_eq!(store.list().unwrap().len(), 2);
        assert!(!d.join("sets").join(format!("{}.sqlite", nsrl2.id)).exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn imports_nsrl_sql_dumps_by_column_name() {
        let d = tmp("sql");
        let (a, b) = (hashes(b"alpha"), hashes(b"bravo"));
        let key = "1".repeat(64); // a 64-hex value that is not a file hash
        let dump = format!(
            "BEGIN TRANSACTION;\nINSERT INTO APPLICATION(application_id,name) VALUES(1,'Vim');\nINSERT INTO METADATA(metadata_id,key_hash,path,file_name,md5,sha1,sha256) VALUES(7,'{key}','C:\\it''s, here\nnext line','a.exe','{}','{}','{}');\nINSERT INTO METADATA(metadata_id,key_hash,path,file_name,md5,sha1,sha256) VALUES(8,'{key}','x',NULL,'{}',NULL,NULL);\nCOMMIT;\n",
            a.md5, a.sha1, a.sha256, b.md5
        );
        let src = d.join("RDS_delta.sql");
        std::fs::write(&src, dump).unwrap();
        let store = Store::open(d.join("sets"));
        let info = store.import(&src, "NSRL delta", SetKind::Known, "", "t", &mut |_, _, _| true).unwrap();
        assert_eq!(info.format, "NSRL RDS v3 (SQL)");
        assert_eq!((info.md5, info.sha1, info.sha256), (2, 1, 1), "{:?}", info);
        let m = store.matcher().unwrap();
        assert!(!m.lookup(&a).unwrap().is_empty());
        let mut fake = Hashes::default();
        fake.sha256 = key;
        assert!(m.lookup(&fake).unwrap().is_empty(), "key_hash must not be taken for a SHA-256");
        // Cut short, or not matching NIST's signatures.txt: refused.
        let cut = d.join("cut.sql");
        std::fs::write(&cut, format!("BEGIN TRANSACTION;\nINSERT INTO METADATA(md5) VALUES('{}');\nINSERT INTO METADATA(md5) VALUES('{}", a.md5, b.md5)).unwrap();
        let e = store.import(&cut, "Cut", SetKind::Known, "", "t", &mut |_, _, _| true).unwrap_err();
        assert!(e.to_string().contains("cut short"), "{}", e);
        std::fs::write(d.join("signatures.txt"), "SHA256(RDS_delta.sql)= 00ff\n").unwrap();
        let e = store.import(&src, "Signed", SetKind::Known, "", "t", &mut |_, _, _| true).unwrap_err();
        assert!(e.to_string().contains("signatures.txt"), "{}", e);
        let sha = kokino_core::hashing::hash_reader(std::fs::File::open(&src).unwrap(), |_| true).unwrap().0.sha256;
        std::fs::write(d.join("signatures.txt"), format!("SHA256(RDS_delta.sql)= {}\n", sha.to_uppercase())).unwrap();
        let ok = store.import(&src, "Signed", SetKind::Known, "", "t", &mut |_, _, _| true).unwrap();
        assert_eq!(ok.source_verified, "SHA-256 matches signatures.txt");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn hashes_fixture_files() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/disk-fat.img");
        if !p.exists() {
            return;
        }
        let ev = Evidence::open(&p).unwrap();
        let a = crate::analyze(&ev, &mut |_, _, _| true).unwrap();
        let fh = hash_files(&ev, &a, &mut |_, _, _| true).unwrap();
        let expected = a.filesystems.iter().flat_map(|f| &f.files).filter(|f| !f.e.is_dir && f.e.size > 0).count();
        assert_eq!(fh.files.len(), expected);
        assert!(fh.files.iter().filter(|f| f.error.is_none()).all(|f| f.hashes.sha256.len() == 64));
        // A file's hash equals the hash of its bytes read directly.
        let (fi, f) = a.filesystems.iter().enumerate().flat_map(|(i, x)| x.files.iter().map(move |f| (i, f))).find(|(_, f)| !f.e.is_dir && f.e.size > 0 && !f.e.deleted).unwrap();
        let mut r = volume_reader(&ev, &a.filesystems[fi].volume).unwrap();
        let fs = crate::fs::Fs::open(&mut r, &a.filesystems[fi].volume).unwrap();
        let data = fs.read(&mut r, &f.e, "", 0, f.e.size as usize).unwrap();
        let got = fh.files.iter().find(|x| x.fi == fi && x.record == f.e.record).unwrap();
        assert_eq!(got.hashes, hashes(&data));
    }
}
