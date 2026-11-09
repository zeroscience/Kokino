//! Windows system artifacts found on an NTFS volume.
//!
//! Locates the registry hives (SYSTEM, SOFTWARE, SAM, every NTUSER.DAT and
//! UsrClass.dat, Amcache.hve), event logs, Prefetch files, Recent-folder
//! shortcuts, Jump Lists and the NTFS change journal by their Windows paths,
//! deleted copies included, reads them through the NTFS layer and turns
//! them into what an examiner asks first: which computer and accounts,
//! which USB devices and networks, what was installed and set to start
//! automatically, what ran (BAM included), which files and folders were
//! opened (ShellBags included), what happened to files (the change journal),
//! how much each program used the network and the disk (SRUM), and the
//! notable events (logons, log clearing, service and account creation,
//! remote desktop, PowerShell).

use crate::FileRow;
use kokino_artifacts::registry::{Hive, Key};
use kokino_artifacts::{ese, evtx, jumplist, lnk, prefetch, reglog, registry, shellbags, task, usn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek};

/// Files larger than this are listed with an error instead of parsed.
const MAX_HIVE: u64 = 1 << 30;
const MAX_LOG: u64 = 2 << 30;
/// Task files are a few KB; anything this large is not one.
const MAX_TASK: u64 = 4 << 20;
/// Most TaskCache entries read.
const MAX_TASKS: usize = 20_000;
/// Notable events kept per log (counts are always complete).
const MAX_EVENTS_PER_LOG: usize = 50_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WindowsArtifacts {
    pub computer: Computer,
    pub users: Vec<UserAccount>,
    pub usb: Vec<UsbDevice>,
    pub networks: Vec<NetworkProfile>,
    pub interfaces: Vec<NetInterface>,
    pub programs: Vec<InstalledProgram>,
    pub autoruns: Vec<Autorun>,
    pub execution: Vec<Execution>,
    pub access: Vec<FileAccess>,
    pub events: Vec<WinEvent>,
    /// (channel, event id, count) over every record of every log.
    pub event_counts: Vec<(String, u32, u64)>,
    pub logs: Vec<LogSummary>,
    /// Every artifact file that was read, with what happened.
    pub sources: Vec<Source>,
    pub timeline: Vec<WinTime>,
    /// Folders users opened in Explorer.
    #[serde(default)]
    pub shellbags: Vec<ShellBag>,
    /// The NTFS change journal ($UsnJrnl) of this volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal: Option<Journal>,
    /// System Resource Usage Monitor (SRUDB.dat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srum: Option<Srum>,
    /// Scheduled tasks: task files and the registry's TaskCache.
    #[serde(default)]
    pub tasks: Vec<ScheduledTask>,
    /// Registry keys recovered from free space in the hives.
    #[serde(default)]
    pub reg_deleted_keys: Vec<RegDeletedKey>,
    /// Deleted values: of live keys (from older copies of the key) and
    /// values whose key is not known.
    #[serde(default)]
    pub reg_deleted_values: Vec<RegDeletedValue>,
}

/// A deleted registry key, recovered from a free cell of a hive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegDeletedKey {
    /// The hive file (index into the file list).
    pub file: u32,
    /// HKLM\SOFTWARE, HKU\alice (NTUSER.DAT), ...
    pub hive: String,
    pub path: String,
    /// When the key last changed before it was deleted.
    pub last_written: u64,
    /// False: a parent key is gone too and was not found.
    pub complete_path: bool,
    pub subkeys: u32,
    pub values: Vec<RegDeletedValue>,
    /// What the key records, when it is a known trace of user activity.
    pub notable: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegDeletedValue {
    pub file: u32,
    pub hive: String,
    /// Empty when the value was found on its own.
    pub key: String,
    pub name: String,
    pub kind: String,
    pub text: String,
    pub size: u64,
    /// The data's cell is in use again; the data may be newer than the value.
    pub data_reused: bool,
    pub notable: String,
}

/// What SRUM holds: per program and user, hour by hour, how much it sent
/// and received over which network, and how much it used the processor
/// and the disk; and when the computer was connected to which network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Srum {
    pub file: u32,
    /// Not cleanly closed: the newest hours may be only in its logs.
    pub dirty: bool,
    pub first: u64,
    pub last: u64,
    /// Totals per program and user, most data sent first.
    pub apps: Vec<SrumApp>,
    pub network: Vec<SrumNet>,
    pub usage: Vec<SrumUsage>,
    pub connections: Vec<SrumConn>,
    /// Rows not kept (the oldest), beyond the limit.
    pub dropped: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SrumApp {
    pub app: String,
    pub user: String,
    pub first: u64,
    pub last: u64,
    pub sent: u64,
    pub received: u64,
    pub read: u64,
    pub written: u64,
    /// Processor cycles in the foreground and background.
    pub foreground: u64,
    pub background: u64,
    pub records: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SrumNet {
    pub t: u64,
    pub app: String,
    pub user: String,
    pub interface: String,
    pub profile: String,
    pub sent: u64,
    pub received: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SrumUsage {
    pub t: u64,
    pub app: String,
    pub user: String,
    pub foreground: u64,
    pub background: u64,
    pub read: u64,
    pub written: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SrumConn {
    pub start: u64,
    pub seconds: u64,
    pub interface: String,
    pub profile: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShellBag {
    #[serde(flatten)]
    pub bag: shellbags::Bag,
    pub user: String,
    /// "UsrClass.dat" or "NTUSER.DAT"
    pub source: String,
    pub file: u32,
    pub deleted: bool,
    /// The folder on this volume, when the MFT reference and name match.
    pub on_volume: Option<u32>,
}

/// What the change journal holds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Journal {
    /// The $UsnJrnl file (index into the volume's files).
    pub file: u32,
    /// Size of the $J stream and how much of it is stored (the rest is
    /// sparse: records that aged out).
    pub size: u64,
    pub stored: u64,
    pub max: Option<usn::JournalMax>,
    /// When this journal was created (its ID).
    pub created: u64,
    pub first: u64,
    pub last: u64,
    pub records: u64,
    /// Changes not kept (the oldest), beyond the limit.
    pub dropped: u64,
    pub changes: Vec<JournalChange>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JournalChange {
    #[serde(flatten)]
    pub c: usn::Change,
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub old_path: String,
    pub what: String,
    pub dir: bool,
    /// The file on this volume, when its MFT reference and name match.
    pub file: Option<u32>,
}

impl WindowsArtifacts {
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty() && self.journal.is_none()
    }

    /// The hourly SRUM rows, which `without_journal` leaves out.
    pub fn srum_rows(&self) -> Option<(&[SrumNet], &[SrumUsage])> {
        self.srum.as_ref().map(|s| (s.network.as_slice(), s.usage.as_slice()))
    }

    /// A copy without the change journal, which can hold hundreds of
    /// thousands of changes and is served page by page instead.
    pub fn without_journal(&self) -> WindowsArtifacts {
        WindowsArtifacts {
            computer: self.computer.clone(),
            users: self.users.clone(),
            usb: self.usb.clone(),
            networks: self.networks.clone(),
            interfaces: self.interfaces.clone(),
            programs: self.programs.clone(),
            autoruns: self.autoruns.clone(),
            execution: self.execution.clone(),
            access: self.access.clone(),
            events: self.events.clone(),
            event_counts: self.event_counts.clone(),
            logs: self.logs.clone(),
            sources: self.sources.clone(),
            timeline: vec![],
            shellbags: self.shellbags.clone(),
            journal: None,
            // Hourly rows are served page by page too.
            srum: self.srum.as_ref().map(|s| Srum { network: vec![], usage: vec![], ..s.clone() }),
            tasks: self.tasks.clone(),
            reg_deleted_keys: self.reg_deleted_keys.clone(),
            reg_deleted_values: self.reg_deleted_values.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Computer {
    pub name: String,
    pub os: String,
    pub edition: String,
    pub version: String,
    pub build: String,
    pub install_time: u64,
    pub owner: String,
    pub organization: String,
    pub time_zone: String,
    /// Minutes to add to local time to get UTC (Windows' ActiveTimeBias).
    pub active_bias_minutes: Option<i32>,
    pub last_shutdown: u64,
    pub control_set: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserAccount {
    pub name: String,
    pub rid: Option<u32>,
    pub sid: String,
    pub profile: String,
    pub created: u64,
    pub last_logon: u64,
    pub password_set: u64,
    pub last_failed: u64,
    pub logon_count: u32,
    pub failed_count: u32,
    pub disabled: bool,
    /// "SAM", "profile" or both.
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsbDevice {
    pub vendor: String,
    pub product: String,
    pub revision: String,
    pub serial: String,
    pub name: String,
    pub drive_letter: String,
    pub first_connected: u64,
    pub last_connected: u64,
    pub last_removed: u64,
    pub key_written: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkProfile {
    pub name: String,
    pub description: String,
    pub kind: String,
    pub category: String,
    pub created: u64,
    pub last_connected: u64,
    pub gateway_mac: String,
    pub dns_suffix: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetInterface {
    pub guid: String,
    pub ip: String,
    pub dhcp_server: String,
    pub domain: String,
    pub gateway: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstalledProgram {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: u64,
    pub location: String,
    pub key_written: u64,
    pub wow64: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Autorun {
    /// "Run key" or "Service"
    pub kind: String,
    pub location: String,
    pub name: String,
    pub command: String,
    pub user: String,
    pub written: u64,
    pub start: String,
    /// Runs from a user-writable or otherwise unusual location.
    pub unusual: bool,
}

/// A scheduled task, from its task file (Windows\System32\Tasks) and the
/// registry's TaskCache (SOFTWARE), joined on the task's path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScheduledTask {
    /// For example \Microsoft\Windows\Defrag\ScheduledDefrag
    pub path: String,
    /// The task file (index into the volume's files), when there is one.
    pub file: Option<u32>,
    pub file_deleted: bool,
    pub author: String,
    pub description: String,
    /// When it was registered, as the task file writes it (local time).
    pub date: String,
    /// The account it runs as (a name or a SID).
    pub user: String,
    pub run_level: String,
    /// Marked hidden in its definition.
    pub hidden: bool,
    pub enabled: bool,
    pub triggers: Vec<String>,
    pub actions: Vec<task::Action>,
    /// TaskCache DynamicInfo (UTC): created, last run, last successful run.
    pub created: u64,
    pub last_run: u64,
    pub last_success: u64,
    /// Result of the last run (0 = success).
    pub last_result: u32,
    /// Listed in TaskCache.
    pub registered: bool,
    /// Its TaskCache\Tree key lost the SD value: schtasks and the Task
    /// Scheduler do not show it, but it still runs (the Tarrask technique).
    pub sd_removed: bool,
    pub tree_written: u64,
    /// One of Windows' own tasks (under \Microsoft\).
    pub microsoft: bool,
    /// Runs a program from a user-writable or otherwise unusual location.
    pub unusual: bool,
    pub notes: Vec<String>,
}

impl ScheduledTask {
    /// The actions in one line.
    pub fn command(&self) -> String {
        self.actions.iter().map(|a| a.summary()).collect::<Vec<_>>().join(" ; ")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Execution {
    /// Prefetch, UserAssist, ShimCache, Amcache, BAM, DAM or "Event 4688"
    pub source: String,
    pub program: String,
    pub user: String,
    pub count: Option<u32>,
    /// Newest first.
    pub times: Vec<u64>,
    pub sha1: String,
    pub detail: String,
    /// Artifact file (index into the volume's files).
    pub file: Option<u32>,
    pub deleted: bool,
    /// Matches a known wiping / anti-forensic tool.
    pub tool: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileAccess {
    /// LNK, Jump List, RecentDocs, TypedPaths, RunMRU or "Explorer search"
    pub source: String,
    pub user: String,
    pub path: String,
    /// Last opened / used.
    pub time: u64,
    /// First opened, when known.
    pub first: u64,
    pub count: Option<u32>,
    pub drive_type: String,
    pub volume_label: String,
    pub volume_serial: String,
    pub machine: String,
    pub mac: String,
    pub app_id: String,
    pub pinned: bool,
    pub file: Option<u32>,
    pub deleted: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WinEvent {
    pub time: u64,
    pub channel: String,
    pub event_id: u32,
    pub record_id: u64,
    pub category: String,
    pub title: String,
    pub summary: String,
    pub user: String,
    pub ip: String,
    pub computer: String,
    pub data: Vec<(String, String)>,
    pub file: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogSummary {
    pub file: u32,
    pub path: String,
    pub channel: String,
    pub info: evtx::LogInfo,
    pub notable: u64,
    pub deleted: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Source {
    pub file: u32,
    pub path: String,
    pub kind: String,
    pub deleted: bool,
    pub error: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WinTime {
    pub t: u64,
    /// EXEC, OPEN, USB, INST, NET, EVT or FILE (change journal)
    pub kind: String,
    pub what: String,
    pub detail: String,
}

// ------------------------------------------------------------------ collect

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    System,
    Software,
    Sam,
    NtUser,
    UsrClass,
    Amcache,
    Srum,
    WlanProfile,
    Task,
    Evtx,
    /// Windows NT to Server 2003 event log.
    Evt,
    Prefetch,
    Lnk,
    JumpList,
}

fn classify(path: &str) -> Option<Kind> {
    let p = path.to_ascii_lowercase();
    // Windows 2000 installs to \WINNT.
    let p = match p.strip_prefix("/winnt/") {
        Some(rest) => format!("/windows/{}", rest),
        None => p,
    };
    let parts: Vec<&str> = p.split('/').collect();
    // Windows XP and 2003: profiles under Documents and Settings.
    if parts.len() >= 4 && parts[1] == "documents and settings" {
        let rest = parts[3..].join("/");
        if rest == "ntuser.dat" {
            return Some(Kind::NtUser);
        }
        if rest == "local settings/application data/microsoft/windows/usrclass.dat" {
            return Some(Kind::UsrClass);
        }
        if p.ends_with(".lnk") && (rest.starts_with("recent/") || rest.starts_with("application data/microsoft/office/recent/")) {
            return Some(Kind::Lnk);
        }
    }
    if p.starts_with("/windows/system32/config/") && p.ends_with(".evt") {
        return Some(Kind::Evt);
    }
    match p.as_str() {
        "/windows/system32/config/system" => return Some(Kind::System),
        "/windows/system32/config/software" => return Some(Kind::Software),
        "/windows/system32/config/sam" => return Some(Kind::Sam),
        "/windows/appcompat/programs/amcache.hve" => return Some(Kind::Amcache),
        _ => {}
    }
    if parts.len() == 4 && parts[1] == "users" && parts[3] == "ntuser.dat" {
        return Some(Kind::NtUser);
    }
    if parts.len() == 8 && parts[1] == "users" && parts[3..].join("/") == "appdata/local/microsoft/windows/usrclass.dat" {
        return Some(Kind::UsrClass);
    }
    if p == "/windows/system32/sru/srudb.dat" {
        return Some(Kind::Srum);
    }
    if p.starts_with("/programdata/microsoft/wlansvc/profiles/interfaces/") && p.ends_with(".xml") {
        return Some(Kind::WlanProfile);
    }
    if p.starts_with("/windows/system32/tasks/") {
        return Some(Kind::Task);
    }
    if p.starts_with("/windows/system32/winevt/logs/") && p.ends_with(".evtx") {
        return Some(Kind::Evtx);
    }
    if p.starts_with("/windows/prefetch/") && p.ends_with(".pf") {
        return Some(Kind::Prefetch);
    }
    if parts.len() >= 4 && parts[1] == "users" {
        let rest = parts[3..].join("/");
        if rest.starts_with("appdata/roaming/microsoft/windows/recent/automaticdestinations/") || rest.starts_with("appdata/roaming/microsoft/windows/recent/customdestinations/") {
            return Some(Kind::JumpList);
        }
        if p.ends_with(".lnk") && (rest.starts_with("appdata/roaming/microsoft/windows/recent/") || rest.starts_with("appdata/roaming/microsoft/office/recent/")) {
            return Some(Kind::Lnk);
        }
    }
    None
}

fn user_of(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 2 && (parts[1].eq_ignore_ascii_case("users") || parts[1].eq_ignore_ascii_case("documents and settings")) { parts[2].to_string() } else { String::new() }
}

pub fn collect<R: Read + Seek>(fs: &crate::fs::Fs, r: &mut R, files: &[FileRow], progress: crate::Progress) -> WindowsArtifacts {
    let mut w = WindowsArtifacts::default();
    // Live copies first, so deleted ones never shadow them.
    // Live files by (parent, lowercase name): transaction logs next to hives.
    let log_files: HashMap<(u64, String), usize> = files
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.e.is_dir && !f.e.deleted && f.e.name.to_ascii_lowercase().contains(".log"))
        .map(|(i, f)| ((f.e.parent, f.e.name.to_ascii_lowercase()), i))
        .collect();
    let mut found: Vec<(usize, Kind)> = files.iter().enumerate().filter(|(_, f)| !f.e.is_dir && f.e.size > 0).filter_map(|(i, f)| classify(&f.e.path).map(|k| (i, k))).collect();
    found.sort_by_key(|(i, _)| (files[*i].e.deleted, *i));
    let total = found.len() as u64;
    let mut hives: Vec<(Kind, usize, Hive)> = vec![];
    let mut srum_db: Option<(usize, Vec<u8>)> = None;
    // Wi-Fi profile GUID (as in the file name) -> network name.
    let mut wlan: HashMap<String, String> = HashMap::new();
    let mut task_files: Vec<(usize, task::Task)> = vec![];
    for (n, (i, kind)) in found.into_iter().enumerate() {
        if !progress("Windows artifacts", n as u64, total) {
            break;
        }
        let f = &files[i];
        let limit = match kind {
            Kind::Evtx | Kind::Evt => MAX_LOG,
            Kind::Task => MAX_TASK,
            _ => MAX_HIVE,
        };
        let mut src = Source { file: i as u32, path: f.e.path.clone(), deleted: f.e.deleted, kind: kind_name(kind).into(), ..Default::default() };
        let data = if f.e.size > limit {
            Err(anyhow::anyhow!("{} bytes; larger than the {} byte limit", f.e.size, limit))
        } else {
            fs.read(r, &f.e, "", 0, f.e.size as usize)
        };
        // A hive that was not cleanly saved: its transaction logs, from the
        // same folder (.LOG1 and .LOG2; .LOG on Windows XP).
        let hive_kind = matches!(kind, Kind::System | Kind::Software | Kind::Sam | Kind::NtUser | Kind::UsrClass | Kind::Amcache);
        let mut logs: [Option<Vec<u8>>; 2] = [None, None];
        if hive_kind && data.as_ref().is_ok_and(|d| reglog::dirty(d)) {
            let lname = f.e.name.to_ascii_lowercase();
            for (slot, exts) in [(0usize, ["log1", "log"]), (1, ["log2", "log2"])] {
                let j = exts.iter().find_map(|x| log_files.get(&(f.e.parent, format!("{}.{}", lname, x))).copied());
                if let Some(j) = j {
                    let e = &files[j].e;
                    if e.size > 0 && e.size <= MAX_HIVE {
                        logs[slot] = fs.read(r, e, "", 0, e.size as usize).ok();
                    }
                }
            }
        }
        let res = data.and_then(|d| match kind {
            Kind::System | Kind::Software | Kind::Sam | Kind::NtUser | Kind::UsrClass | Kind::Amcache => {
                // A deleted hive is reported but not used when a live one exists.
                let per_user = matches!(kind, Kind::NtUser | Kind::UsrClass);
                if f.e.deleted && hives.iter().any(|(k, j, _)| *k == kind && (!per_user || user_of(&files[*j].e.path).eq_ignore_ascii_case(&user_of(&f.e.path)))) {
                    src.note = Some("older deleted copy; the live hive is used".into());
                    return Ok(());
                }
                let mut d = d;
                if reglog::dirty(&d) {
                    match reglog::recover(&d, logs[0].as_deref(), logs[1].as_deref()) {
                        Ok(Some((fixed, rec))) => {
                            d = fixed;
                            let mut note = format!(
                                "hive was not cleanly saved; recent changes were applied from {} ({} {}, {} pages) as Windows would on its next start",
                                rec.from.join(" and "),
                                rec.applied,
                                if rec.format == "new" { if rec.applied == 1 { "log entry" } else { "log entries" } } else { "log" },
                                rec.pages
                            );
                            if let Some(s) = rec.stopped {
                                note.push_str(&format!("; the replay stopped early: {}", s));
                            }
                            src.note = Some(note);
                        }
                        Ok(None) => {}
                        Err(e) => src.note = Some(format!("hive was not cleanly saved; recent changes may be missing: {:#}", e)),
                    }
                }
                let h = Hive::parse(d)?;
                hives.push((kind, i, h));
                Ok(())
            }
            Kind::Evtx => {
                events(&mut w, &d, i, f, false);
                Ok(())
            }
            Kind::Evt => {
                events(&mut w, &d, i, f, true);
                Ok(())
            }
            Kind::Prefetch => {
                let pf = prefetch::parse(&d)?;
                prefetch_exec(&mut w, pf, i, f);
                Ok(())
            }
            Kind::Lnk => {
                let l = lnk::parse(&d)?;
                lnk_access(&mut w, l, i, f);
                Ok(())
            }
            Kind::JumpList => {
                let jl = jumplist::parse(&f.e.name, &d)?;
                jump_access(&mut w, jl, i, f);
                Ok(())
            }
            Kind::Srum => {
                if srum_db.is_some() {
                    src.note = Some("older deleted copy; the live database is used".into());
                } else {
                    ese::Db::open(&d)?;
                    srum_db = Some((i, d));
                }
                Ok(())
            }
            Kind::WlanProfile => {
                let name = xml_text(&d, "name").ok_or_else(|| anyhow::anyhow!("no <name> in the profile"))?;
                wlan.insert(f.e.name.trim_end_matches(".xml").trim_end_matches(".XML").to_ascii_uppercase(), name);
                Ok(())
            }
            Kind::Task => {
                task_files.push((i, task::parse_xml(&d)?));
                Ok(())
            }
        });
        if let Err(e) = res {
            src.error = Some(format!("{:#}", e));
        }
        w.sources.push(src);
    }

    // Hives in a fixed order: SYSTEM decides the control set, SOFTWARE gives
    // profile SIDs that SAM accounts are matched against.
    hives.sort_by_key(|(k, _, _)| match k {
        Kind::System => 0,
        Kind::Software => 1,
        Kind::Sam => 2,
        Kind::Amcache => 3,
        _ => 4,
    });
    for (kind, i, h) in &hives {
        let f = &files[*i];
        match kind {
            Kind::System => system_hive(&mut w, h),
            Kind::Software => software_hive(&mut w, h),
            Kind::Sam => sam_hive(&mut w, h),
            Kind::Amcache => amcache_hive(&mut w, h, *i),
            Kind::NtUser => {
                ntuser_hive(&mut w, h, &user_of(&f.e.path), *i);
                for key in ["Software\\Microsoft\\Windows\\Shell\\BagMRU", "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU"] {
                    bags(&mut w, h, key, "NTUSER.DAT", f, *i);
                }
            }
            Kind::UsrClass => bags(&mut w, h, "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", "UsrClass.dat", f, *i),
            _ => {}
        }
    }
    link_bags(&mut w, files);
    for (kind, i, h) in &hives {
        deleted_registry(&mut w, h, *kind, *i, &files[*i]);
    }
    let software = hives.iter().find(|(k, _, _)| *k == Kind::Software).map(|(_, _, h)| h);
    if software.is_some() || !task_files.is_empty() {
        scheduled_tasks(&mut w, software, task_files, files);
    }
    if let Some((i, d)) = srum_db {
        let mut profiles: HashMap<u32, String> = HashMap::new();
        for (_, _, h) in hives.iter().filter(|(k, _, _)| *k == Kind::Software) {
            wlan_profiles(h, &wlan, &mut profiles);
        }
        srum(&mut w, &d, i, files[i].e.deleted, &profiles);
    }
    if fs.is_ntfs() {
        journal(&mut w, fs, r, files, &mut *progress);
    }
    finish(&mut w);
    w
}

const MAX_REG_DELETED: usize = 20_000;

/// Keys that record what a user did; a cleaner deletes these.
const REG_TRACES: &[(&str, &str)] = &[
    ("\\explorer\\recentdocs", "recent documents"),
    ("\\explorer\\typedpaths", "paths typed in Explorer"),
    ("\\explorer\\runmru", "Run box history"),
    ("\\explorer\\userassist", "programs run (UserAssist)"),
    ("\\explorer\\comdlg32", "files opened and saved in dialogs"),
    ("\\explorer\\wordwheelquery", "Explorer searches"),
    ("\\explorer\\mountpoints2", "drives and shares mounted"),
    ("\\shell\\bagmru", "folders opened (ShellBags)"),
    ("\\shell\\bags", "folders opened (ShellBags)"),
    ("\\internet explorer\\typedurls", "addresses typed in Internet Explorer"),
    ("\\file mru", "Office recent files"),
    ("\\place mru", "Office recent folders"),
    ("\\recent file list", "recent files of a program"),
    ("\\currentversion\\run", "autostart (Run)"),
    ("\\enum\\usbstor", "USB storage devices"),
    ("\\enum\\usb\\", "USB devices"),
    ("\\windows portable devices\\devices", "portable devices"),
    ("\\networklist\\profiles", "networks connected to"),
    ("\\terminal server client", "remote desktop connections made"),
    ("\\bam\\state\\usersettings", "programs run (BAM)"),
    ("\\appcompatflags\\compatibility assistant", "programs run (Compatibility Assistant)"),
];

/// Traces a user's own activity leaves (not autostart or device keys,
/// which installers and Windows remove themselves).
pub fn user_activity_trace(notable: &str) -> bool {
    !notable.is_empty() && !matches!(notable, "autostart (Run)" | "USB storage devices" | "USB devices" | "portable devices" | "networks connected to")
}

fn reg_trace(path: &str) -> String {
    let p = format!("\\{}\\", path.to_lowercase());
    REG_TRACES.iter().find(|(k, _)| p.contains(k)).map(|(_, v)| v.to_string()).unwrap_or_default()
}

fn reg_kind(k: u32) -> String {
    match k {
        0 => "REG_NONE".into(),
        1 => "REG_SZ".into(),
        2 => "REG_EXPAND_SZ".into(),
        3 => "REG_BINARY".into(),
        4 => "REG_DWORD".into(),
        5 => "REG_DWORD_BIG_ENDIAN".into(),
        6 => "REG_LINK".into(),
        7 => "REG_MULTI_SZ".into(),
        11 => "REG_QWORD".into(),
        k => format!("type {}", k),
    }
}

fn reg_value(d: &registry::DeletedValue, file: u32, hive: &str) -> RegDeletedValue {
    let v = &d.value;
    let key = d.key.clone().unwrap_or_default();
    let text = match v.kind {
        registry::REG_SZ | registry::REG_EXPAND_SZ | registry::REG_DWORD | registry::REG_QWORD | registry::REG_MULTI_SZ => v.string(),
        _ => {
            // Binary: a UTF-16 file name when it starts like one (MRU lists), else hex.
            let s = kokino_artifacts::bin::utf16(&v.data);
            if s.chars().count() >= 3 && s.chars().all(|c| !c.is_control()) {
                s
            } else {
                v.data.iter().take(48).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ") + if v.data.len() > 48 { " ..." } else { "" }
            }
        }
    };
    // UserAssist names are ROT13.
    let name = if key.to_lowercase().contains("\\userassist\\") { rot13(&v.name) } else { v.name.clone() };
    RegDeletedValue { file, hive: hive.to_string(), notable: if key.is_empty() { String::new() } else { reg_trace(&key) }, key, name, kind: reg_kind(v.kind), text, size: v.data.len() as u64, data_reused: d.data_reused }
}

/// Deleted keys and values in one hive.
fn deleted_registry(w: &mut WindowsArtifacts, h: &Hive, kind: Kind, i: usize, f: &FileRow) {
    let hive = match kind {
        Kind::System => "HKLM\\SYSTEM".to_string(),
        Kind::Software => "HKLM\\SOFTWARE".to_string(),
        Kind::Sam => "HKLM\\SAM".to_string(),
        Kind::NtUser => format!("HKU\\{} (NTUSER.DAT)", user_of(&f.e.path)),
        Kind::UsrClass => format!("HKU\\{} (UsrClass.dat)", user_of(&f.e.path)),
        Kind::Amcache => "Amcache.hve".to_string(),
        _ => return,
    };
    let d = h.deleted();
    let file = i as u32;
    for k in d.keys {
        if w.reg_deleted_keys.len() >= MAX_REG_DELETED {
            break;
        }
        let values = k.values.iter().map(|v| reg_value(v, file, &hive)).collect();
        let notable = reg_trace(&k.path);
        w.reg_deleted_keys.push(RegDeletedKey { file, hive: hive.clone(), notable, path: k.path, last_written: k.last_written, complete_path: k.complete_path, subkeys: k.subkey_count, values });
    }
    for v in d.values.iter().chain(&d.orphans) {
        if w.reg_deleted_values.len() >= MAX_REG_DELETED {
            break;
        }
        w.reg_deleted_values.push(reg_value(v, file, &hive));
    }
}

/// Text of the first <tag> element in an XML file (UTF-8 or UTF-16).
fn xml_text(d: &[u8], tag: &str) -> Option<String> {
    let s = if d.starts_with(&[0xFF, 0xFE]) { kokino_artifacts::bin::utf16(&d[2..]) } else { String::from_utf8_lossy(d).into_owned() };
    let open = format!("<{}>", tag);
    let a = s.find(&open)? + open.len();
    let b = a + s[a..].find('<')?;
    let t = s[a..b].trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// SRUM's L2ProfileId is the ProfileIndex of a Wi-Fi profile in
/// SOFTWARE\Microsoft\WlanSvc\Interfaces\{interface}\Profiles\{profile};
/// the profile's name is in its XML file, named after the same GUID.
fn wlan_profiles(h: &Hive, names: &HashMap<String, String>, out: &mut HashMap<u32, String>) {
    let Some(ifs) = h.open("Microsoft\\WlanSvc\\Interfaces") else { return };
    for i in ifs.subkeys() {
        let Some(ps) = i.subkey("Profiles") else { continue };
        for p in ps.subkeys() {
            if let Some(idx) = p.u32("ProfileIndex") {
                let g = p.name().to_ascii_uppercase();
                out.insert(idx, names.get(&g).cloned().unwrap_or(g));
            }
        }
    }
}

const SRUM_NETWORK: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";
const SRUM_USAGE: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";
const SRUM_CONNECTIVITY: &str = "{DD6636C4-8929-4683-974E-22C046A43763}";
/// Most hourly rows kept per table (the newest).
const MAX_SRUM_ROWS: usize = 250_000;

/// SRUM times: OLE Automation dates (days since 1899-12-30) or FILETIMEs.
fn srum_time(v: Option<&ese::Value>) -> u64 {
    const OLE_EPOCH: f64 = 94_353_120_000_000_000.0;
    match v {
        Some(ese::Value::Float(d)) if d.is_finite() && *d > 0.0 => kokino_artifacts::bin::plausible((OLE_EPOCH + d * 864_000_000_000.0) as u64),
        Some(v) => kokino_artifacts::bin::plausible(v.i64().unwrap_or(0).max(0) as u64),
        None => 0,
    }
}

/// The interface type from the top 16 bits of an interface LUID.
fn if_type(luid: i64) -> String {
    match (luid as u64) >> 48 {
        0 => String::new(),
        6 => "Ethernet".into(),
        71 => "Wi-Fi".into(),
        23 => "PPP".into(),
        24 => "loopback".into(),
        131 => "tunnel".into(),
        243 | 244 => "mobile broadband".into(),
        t => format!("interface type {}", t),
    }
}

fn srum(w: &mut WindowsArtifacts, d: &[u8], file: usize, deleted: bool, profiles: &HashMap<u32, String>) {
    let mut s = Srum { file: file as u32, ..Default::default() };
    let db = match ese::Db::open(d) {
        Ok(db) => db,
        Err(e) => {
            s.error = Some(format!("{:#}", e));
            w.srum = Some(s);
            return;
        }
    };
    s.dirty = db.dirty();
    let sids: HashMap<String, String> = w.users.iter().filter(|u| !u.sid.is_empty()).map(|u| (u.sid.clone(), u.name.clone())).collect();
    // Id map: apps (paths), services and user SIDs, by index.
    let mut ids: HashMap<i64, String> = HashMap::new();
    if let Some(t) = db.table("SruDbIdMapTable") {
        for r in db.rows(t, 1 << 20) {
            let (Some(ty), Some(idx)) = (r.get("IdType").and_then(|v| v.i64()), r.get("IdIndex").and_then(|v| v.i64())) else { continue };
            let blob = r.get("IdBlob").and_then(|v| v.bytes()).unwrap_or(&[]);
            let text = match ty {
                3 => kokino_artifacts::bin::sid(blob).map(|sid| sids.get(&sid).cloned().unwrap_or(sid)).unwrap_or_default(),
                _ => {
                    let t = kokino_artifacts::bin::utf16(blob);
                    let (p, _) = device_path(&t);
                    if ty == 1 { format!("{} (service)", p) } else { p }
                }
            };
            ids.insert(idx, text);
        }
    } else {
        s.error = Some("no SruDbIdMapTable: program and user names cannot be resolved".into());
    }
    let name = |r: &HashMap<String, ese::Value>, col: &str| -> String {
        let i = r.get(col).and_then(|v| v.i64()).unwrap_or(0);
        ids.get(&i).cloned().unwrap_or_else(|| if i == 0 { String::new() } else { format!("[id {}]", i) })
    };
    let num = |r: &HashMap<String, ese::Value>, col: &str| r.get(col).and_then(|v| v.i64()).unwrap_or(0).max(0) as u64;
    let profile = |r: &HashMap<String, ese::Value>| {
        let p = num(r, "L2ProfileId") as u32;
        if p == 0 { String::new() } else { profiles.get(&p).cloned().unwrap_or_else(|| format!("profile {}", p)) }
    };
    if let Some(t) = db.table(SRUM_NETWORK) {
        for r in db.rows(t, usize::MAX) {
            s.network.push(SrumNet {
                t: srum_time(r.get("TimeStamp")),
                app: name(&r, "AppId"),
                user: name(&r, "UserId"),
                interface: if_type(r.get("InterfaceLuid").and_then(|v| v.i64()).unwrap_or(0)),
                profile: profile(&r),
                sent: num(&r, "BytesSent"),
                received: num(&r, "BytesRecvd"),
            });
        }
    }
    if let Some(t) = db.table(SRUM_USAGE) {
        for r in db.rows(t, usize::MAX) {
            s.usage.push(SrumUsage {
                t: srum_time(r.get("TimeStamp")),
                app: name(&r, "AppId"),
                user: name(&r, "UserId"),
                foreground: num(&r, "ForegroundCycleTime"),
                background: num(&r, "BackgroundCycleTime"),
                read: num(&r, "ForegroundBytesRead") + num(&r, "BackgroundBytesRead"),
                written: num(&r, "ForegroundBytesWritten") + num(&r, "BackgroundBytesWritten"),
            });
        }
    }
    if let Some(t) = db.table(SRUM_CONNECTIVITY) {
        for r in db.rows(t, 1 << 20) {
            let start = srum_time(r.get("ConnectStartTime"));
            s.connections.push(SrumConn { start: if start > 0 { start } else { srum_time(r.get("TimeStamp")) }, seconds: num(&r, "ConnectedTime"), interface: if_type(r.get("InterfaceLuid").and_then(|v| v.i64()).unwrap_or(0)), profile: profile(&r) });
        }
    }
    // Totals per program and user.
    let mut apps: BTreeMap<(String, String), SrumApp> = BTreeMap::new();
    let span = |t: u64, a: &mut SrumApp| {
        if t > 0 {
            a.first = if a.first == 0 { t } else { a.first.min(t) };
            a.last = a.last.max(t);
        }
        a.records += 1;
    };
    for n in &s.network {
        let a = apps.entry((n.app.clone(), n.user.clone())).or_insert_with(|| SrumApp { app: n.app.clone(), user: n.user.clone(), ..Default::default() });
        a.sent += n.sent;
        a.received += n.received;
        span(n.t, a);
    }
    for u in &s.usage {
        let a = apps.entry((u.app.clone(), u.user.clone())).or_insert_with(|| SrumApp { app: u.app.clone(), user: u.user.clone(), ..Default::default() });
        a.read += u.read;
        a.written += u.written;
        a.foreground += u.foreground;
        a.background += u.background;
        span(u.t, a);
    }
    s.apps = apps.into_values().collect();
    s.apps.sort_by(|a, b| b.sent.cmp(&a.sent).then(b.written.cmp(&a.written)));
    let times = s.network.iter().map(|n| n.t).chain(s.usage.iter().map(|u| u.t)).filter(|&t| t > 0);
    s.first = times.clone().min().unwrap_or(0);
    s.last = times.max().unwrap_or(0);
    s.dropped = keep_newest(&mut s.network, MAX_SRUM_ROWS, |x| x.t) + keep_newest(&mut s.usage, MAX_SRUM_ROWS, |x| x.t);
    s.connections.sort_by_key(|c| c.start);
    if deleted {
        s.error.get_or_insert_with(|| "read from a deleted copy of SRUDB.dat".into());
    }
    w.srum = Some(s);
}

/// The TaskCache reader on a raw hive, for the fuzzer.
pub fn fuzz_tasks(d: &[u8]) {
    if let Ok(h) = Hive::parse(d.to_vec()) {
        let mut w = WindowsArtifacts::default();
        scheduled_tasks(&mut w, Some(&h), vec![], &[]);
    }
}

/// The SRUM reader on raw bytes, for the fuzzer.
pub fn fuzz_srum(d: &[u8]) {
    let mut w = WindowsArtifacts::default();
    srum(&mut w, d, 0, false, &HashMap::new());
}

/// Sorts rows by time and keeps the newest `n`; returns how many were
/// dropped.
fn keep_newest<T>(v: &mut Vec<T>, n: usize, t: fn(&T) -> u64) -> u64 {
    v.sort_by_key(t);
    let drop = v.len().saturating_sub(n);
    v.drain(..drop);
    drop as u64
}

fn bags(w: &mut WindowsArtifacts, h: &Hive, key: &str, source: &str, f: &FileRow, i: usize) {
    let Some(k) = h.open(key) else { return };
    let user = user_of(&f.e.path);
    for bag in shellbags::walk(&k) {
        w.shellbags.push(ShellBag { bag, user: user.clone(), source: source.into(), file: i as u32, deleted: f.e.deleted, on_volume: None });
    }
}

/// Folders whose MFT reference and name match a folder on this volume. The
/// drive letter is not checked (a USB stick can hold the same record
/// numbers), so the name must match too.
fn link_bags(w: &mut WindowsArtifacts, files: &[FileRow]) {
    if w.shellbags.is_empty() {
        return;
    }
    let by_rec: HashMap<u64, usize> = files.iter().enumerate().filter(|(_, f)| f.e.is_dir && f.e.name_only.is_none()).map(|(i, f)| (f.e.record, i)).collect();
    for b in &mut w.shellbags {
        let Some((rec, seq)) = b.bag.mft else { continue };
        let Some(&i) = by_rec.get(&rec) else { continue };
        let e = &files[i].e;
        let name = b.bag.path.rsplit('\\').next().unwrap_or("");
        let seq_ok = e.seq == seq || (e.deleted && e.seq == seq.wrapping_add(1));
        if seq_ok && e.name.eq_ignore_ascii_case(name) {
            b.on_volume = Some(i as u32);
        }
    }
}

/// Most of $J read, and changes kept (the newest).
const MAX_JOURNAL: u64 = 1 << 30;
const MAX_CHANGES: usize = 250_000;

fn journal<R: Read + Seek>(w: &mut WindowsArtifacts, fs: &crate::fs::Fs, r: &mut R, files: &[FileRow], progress: crate::Progress) {
    let Some((ji, jf)) = files.iter().enumerate().find(|(_, f)| !f.e.deleted && f.e.path.eq_ignore_ascii_case("/$Extend/$UsnJrnl")) else { return };
    let Some(size) = jf.e.streams.iter().find(|s| s.name == "$J").map(|s| s.size) else { return };
    let mut j = Journal { file: ji as u32, size, ..Default::default() };
    j.max = fs.read(r, &jf.e, "$Max", 0, 32).ok().and_then(|d| usn::parse_max(&d));
    j.created = j.max.map(|m| kokino_artifacts::bin::plausible(m.journal_id)).unwrap_or(0);
    let mut ext = match fs.extents(r, &jf.e, "$J") {
        Ok(x) => x,
        Err(e) => {
            j.error = Some(format!("{:#}", e));
            w.journal = Some(j);
            return;
        }
    };
    ext.sort_by_key(|x| x.offset);
    let stored: u64 = ext.iter().filter(|x| x.vol.is_some() && x.offset < size).map(|x| x.len.min(size - x.offset)).sum();
    j.stored = stored;
    let mut g = usn::Grouper::default();
    let (mut done, mut carry, mut next) = (0u64, Vec::<u8>::new(), None);
    const CHUNK: u64 = 4 << 20;
    'outer: for x in ext.iter().filter(|x| x.offset < size) {
        let len = x.len.min(size - x.offset);
        let Some(v) = x.vol else {
            carry.clear();
            continue;
        };
        if next != Some(x.offset) {
            carry.clear();
        }
        let mut at = 0;
        while at < len {
            if done >= MAX_JOURNAL {
                j.error = Some(format!("only the first {} bytes of the journal were read", MAX_JOURNAL));
                break 'outer;
            }
            if !progress("Change journal", done, stored.min(MAX_JOURNAL)) {
                break 'outer;
            }
            let n = (len - at).min(CHUNK) as usize;
            let mut buf = std::mem::take(&mut carry);
            let base = buf.len();
            buf.resize(base + n, 0);
            if r.seek(std::io::SeekFrom::Start(v + at)).is_err() || r.read_exact(&mut buf[base..]).is_err() {
                j.error = Some(format!("could not read the journal at volume offset {}", v + at));
                break 'outer;
            }
            let used = usn::parse(&buf, &mut |rec| g.push(rec));
            if buf.len() - used <= 0x1_0000 {
                carry = buf[used..].to_vec();
            }
            at += n as u64;
            done += n as u64;
        }
        next = Some(x.offset + len);
    }
    j.records = g.records;
    j.first = g.first;
    j.last = g.last;
    let (mut changes, folders) = g.finish();
    if changes.len() > MAX_CHANGES {
        j.dropped = (changes.len() - MAX_CHANGES) as u64;
        changes.drain(..changes.len() - MAX_CHANGES);
    }
    // Paths: folders as they are now when the reference still matches, else
    // as the journal last named them.
    let by_rec: HashMap<u64, usize> = files.iter().enumerate().filter(|(_, f)| f.e.name_only.is_none()).map(|(i, f)| (f.e.record, i)).collect();
    let mut cache: HashMap<(u64, u16), String> = HashMap::new();
    fn folder(rf: (u64, u16), files: &[FileRow], by_rec: &HashMap<u64, usize>, folders: &HashMap<(u64, u16), (String, (u64, u16))>, cache: &mut HashMap<(u64, u16), String>, depth: u32) -> String {
        if rf.0 == kokino_ntfs::ROOT_RECORD {
            return String::new();
        }
        if let Some(p) = cache.get(&rf) {
            return p.clone();
        }
        let p = match by_rec.get(&rf.0).map(|&i| &files[i].e) {
            Some(e) if e.is_dir && e.seq == rf.1 && !e.deleted => e.path.clone(),
            _ => match folders.get(&rf) {
                Some((name, parent)) if depth < 64 && *parent != rf => format!("{}/{}", folder(*parent, files, by_rec, folders, cache, depth + 1), name),
                _ => format!("/[folder {}-{}]", rf.0, rf.1),
            },
        };
        cache.insert(rf, p.clone());
        p
    }
    let mut by_ref: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        let rec = match &f.e.name_only {
            Some(n) => n.mft_record,
            None => Some(f.e.record),
        };
        if let Some(rec) = rec {
            by_ref.entry(rec).or_default().push(i);
        }
    }
    for c in changes {
        let path = format!("{}/{}", folder((c.parent, c.parent_seq), files, &by_rec, &folders, &mut cache, 0), c.name);
        let old_path = c.old.as_ref().map(|(n, p, s)| format!("{}/{}", folder((*p, *s), files, &by_rec, &folders, &mut cache, 0), n)).unwrap_or_default();
        let file = by_ref.get(&c.record).and_then(|v| {
            v.iter().copied().find(|&i| {
                let e = &files[i].e;
                let seq = e.name_only.as_ref().map(|n| n.mft_seq).unwrap_or(e.seq);
                (seq == c.seq || (e.deleted && seq == c.seq.wrapping_add(1))) && (e.name.eq_ignore_ascii_case(&c.name) || c.old.as_ref().is_some_and(|o| e.name.eq_ignore_ascii_case(&o.0)))
            })
        });
        j.changes.push(JournalChange { what: usn::describe(c.reasons), dir: c.attributes & 0x10 != 0, path, old_path, file: file.map(|i| i as u32), c });
    }
    w.journal = Some(j);
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::System => "SYSTEM hive",
        Kind::Software => "SOFTWARE hive",
        Kind::Sam => "SAM hive",
        Kind::NtUser => "NTUSER.DAT",
        Kind::UsrClass => "UsrClass.dat",
        Kind::Srum => "SRUM database",
        Kind::WlanProfile => "Wi-Fi profile",
        Kind::Task => "Scheduled task",
        Kind::Amcache => "Amcache.hve",
        Kind::Evtx => "Event log",
        Kind::Evt => "Event log (legacy .evt)",
        Kind::Prefetch => "Prefetch",
        Kind::Lnk => "Shortcut (LNK)",
        Kind::JumpList => "Jump List",
    }
}

fn base_name(p: &str) -> &str {
    // SRUM names many programs "!!<file>!<date>!<hex>!..." instead of a path.
    if let Some(r) = p.strip_prefix("!!") {
        return r.split('!').next().unwrap_or(r);
    }
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

fn is_tool(program: &str) -> bool {
    crate::antiforensics::tool_name(base_name(program)).is_some()
}

// ------------------------------------------------------------------ registry

fn system_hive(w: &mut WindowsArtifacts, h: &Hive) {
    let current = h.open("Select").and_then(|k| k.u32("Current")).unwrap_or(1);
    let cs_name = format!("ControlSet{:03}", current);
    let Some(cs) = h.open(&cs_name) else { return };
    w.computer.control_set = cs_name;
    if let Some(n) = cs.open("Control\\ComputerName\\ComputerName").and_then(|k| k.string("ComputerName")) {
        w.computer.name = n;
    }
    if let Some(tz) = cs.open("Control\\TimeZoneInformation") {
        w.computer.time_zone = tz.string("TimeZoneKeyName").or_else(|| tz.string("StandardName")).unwrap_or_default();
        w.computer.active_bias_minutes = tz.u32("ActiveTimeBias").map(|v| v as i32);
    }
    if let Some(t) = cs.open("Control\\Windows").and_then(|k| k.u64("ShutdownTime")) {
        w.computer.last_shutdown = kokino_artifacts::bin::plausible(t);
    }
    // Drive letters from MountedDevices: "\DosDevices\E:" -> device path with the serial.
    let mut letters: Vec<(String, String)> = vec![];
    if let Some(md) = h.open("MountedDevices") {
        for v in md.values() {
            if let Some(l) = v.name.strip_prefix("\\DosDevices\\") {
                letters.push((l.to_string(), kokino_artifacts::bin::utf16(&v.data).to_ascii_lowercase()));
            }
        }
    }
    if let Some(usbstor) = cs.open("Enum\\USBSTOR") {
        for class in usbstor.subkeys() {
            let cname = class.name();
            let field = |tag: &str| cname.split('&').find_map(|p| p.strip_prefix(tag)).unwrap_or("").replace('_', " ");
            for inst in class.subkeys() {
                let serial_key = inst.name();
                let prop = |id: &str| {
                    inst.open(&format!("Properties\\{{83da6326-97a6-4088-9453-a1923f573b29}}\\{}", id))
                        .and_then(|k| k.values().into_iter().next())
                        .and_then(|v| kokino_artifacts::bin::u64_at(&v.data, 0))
                        .map(kokino_artifacts::bin::plausible)
                        .unwrap_or(0)
                };
                let serial = serial_key.strip_suffix("&0").unwrap_or(&serial_key).to_string();
                let lc = serial_key.to_ascii_lowercase();
                w.usb.push(UsbDevice {
                    vendor: field("Ven_"),
                    product: field("Prod_"),
                    revision: field("Rev_"),
                    name: inst.string("FriendlyName").unwrap_or_default(),
                    drive_letter: letters.iter().find(|(_, dev)| dev.contains(&format!("#{}#", lc))).map(|(l, _)| l.clone()).unwrap_or_default(),
                    first_connected: prop("0064"),
                    last_connected: prop("0066"),
                    last_removed: prop("0067"),
                    key_written: inst.last_written(),
                    serial,
                });
            }
        }
    }
    if let Some(ifs) = cs.open("Services\\Tcpip\\Parameters\\Interfaces") {
        for i in ifs.subkeys() {
            let first = |names: &[&str]| names.iter().find_map(|n| i.value(n).map(|v| if v.kind == registry::REG_MULTI_SZ { v.multi().join(", ") } else { v.string() }).filter(|s| !s.is_empty() && s != "0.0.0.0")).unwrap_or_default();
            let ip = first(&["DhcpIPAddress", "IPAddress"]);
            if ip.is_empty() {
                continue;
            }
            w.interfaces.push(NetInterface { guid: i.name(), ip, dhcp_server: first(&["DhcpServer"]), domain: first(&["DhcpDomain", "Domain"]), gateway: first(&["DhcpDefaultGateway", "DefaultGateway"]) });
        }
    }
    if let Some(svcs) = cs.open("Services") {
        for s in svcs.subkeys() {
            let (Some(img), Some(start), Some(ty)) = (s.string("ImagePath"), s.u32("Start"), s.u32("Type")) else { continue };
            // Auto-start user-mode services from unusual places; the rest is noise here.
            if start > 2 || ty & 0x30 == 0 || !unusual_path(&img) {
                continue;
            }
            w.autoruns.push(Autorun {
                kind: "Service".into(),
                location: format!("SYSTEM\\{}\\Services\\{}", w.computer.control_set, s.name()),
                name: s.string("DisplayName").unwrap_or_else(|| s.name()),
                command: img,
                written: s.last_written(),
                start: ["boot", "system", "automatic"].get(start as usize).unwrap_or(&"").to_string(),
                unusual: true,
                ..Default::default()
            });
        }
    }
    if let Some(v) = cs.open("Control\\Session Manager\\AppCompatCache").and_then(|k| k.value("AppCompatCache")) {
        for (path, modified) in shimcache(&v.data) {
            w.execution.push(Execution {
                source: "ShimCache".into(),
                tool: is_tool(&path),
                program: path,
                detail: format!("file last modified {}; on Windows 10+ an entry is not proof that it ran", iso(modified)),
                ..Default::default()
            });
        }
    }
    bam(w, &cs);
}

/// Background and Desktop Activity Moderator (Windows 10 1709 and later):
/// per user SID, the last time each program ran, in the first 8 bytes of a
/// value named after it. 1709 to 1803 keep it under Services\bam\UserSettings,
/// later versions under Services\bam\State\UserSettings. Entries are
/// removed about a week after the program last ran, and at some reboots.
fn bam(w: &mut WindowsArtifacts, cs: &Key) {
    for (svc, label) in [("bam", "BAM"), ("dam", "DAM")] {
        for sub in ["State\\UserSettings", "UserSettings"] {
            let Some(us) = cs.open(&format!("Services\\{}\\{}", svc, sub)) else { continue };
            for k in us.subkeys() {
                let sid = k.name();
                for v in k.values() {
                    let t = kokino_artifacts::bin::plausible(kokino_artifacts::bin::u64_at(&v.data, 0).unwrap_or(0));
                    if v.data.len() < 8 || t == 0 || v.name == "Version" || v.name == "SequenceNumber" {
                        continue;
                    }
                    let (program, volume) = device_path(&v.name);
                    w.execution.push(Execution {
                        source: label.into(),
                        tool: is_tool(&program),
                        program,
                        user: sid.clone(),
                        times: vec![t],
                        detail: if volume.is_empty() { "last run".into() } else { format!("last run, from {}", volume) },
                        ..Default::default()
                    });
                }
            }
        }
    }
}

/// "\Device\HarddiskVolume3\Windows\x.exe" -> ("\Windows\x.exe", "HarddiskVolume3").
fn device_path(p: &str) -> (String, String) {
    if let Some(rest) = p.strip_prefix("\\Device\\") {
        if let Some(i) = rest.find('\\') {
            return (rest[i..].to_string(), rest[..i].to_string());
        }
    }
    (p.to_string(), String::new())
}

/// Executables run from places normal software does not live.
fn unusual_path(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase().replace('/', "\\");
    let normal = [
        "\\windows\\",
        "%systemroot%",
        "%windir%",
        "system32\\",
        "\\program files",
        "\\programdata\\microsoft\\windows defender",
        // Microsoft's own per-user installs
        "\\appdata\\local\\microsoft\\onedrive\\",
        "\\appdata\\local\\microsoft\\teams\\",
    ];
    !normal.iter().any(|n| c.contains(n)) || c.contains("\\users\\public") || c.contains("\\temp\\") || c.contains("\\appdata\\local\\temp")
}

/// Windows 8.1 / 10 / 11 AppCompatCache entries: (path, file modified time).
fn shimcache(d: &[u8]) -> Vec<(String, u64)> {
    use kokino_artifacts::bin::*;
    let header = u32_at(d, 0).unwrap_or(0) as usize;
    let win81 = header == 0x80;
    if !(header == 0x30 || header == 0x34 || win81) {
        return vec![];
    }
    let mut out = vec![];
    let mut p = header;
    while out.len() < 10_000 && (slice(d, p, 4) == Some(b"10ts") || slice(d, p, 4) == Some(b"00ts")) {
        let size = u32_at(d, p + 8).unwrap_or(0) as usize;
        let b = p + 12;
        let plen = u16_at(d, b).unwrap_or(0) as usize;
        let path = utf16(slice(d, b + 2, plen).unwrap_or(&[]));
        let mut q = b + 2 + plen;
        if win81 {
            q += 2 + u16_at(d, q).unwrap_or(0) as usize + 8; // package name, flags + unknown
        }
        out.push((path, plausible(u64_at(d, q).unwrap_or(0))));
        if size == 0 {
            break;
        }
        p = b + size;
    }
    out
}

fn software_hive(w: &mut WindowsArtifacts, h: &Hive) {
    if let Some(cv) = h.open("Microsoft\\Windows NT\\CurrentVersion") {
        let build = cv.string("CurrentBuild").or_else(|| cv.string("CurrentBuildNumber")).unwrap_or_default();
        let mut os = cv.string("ProductName").unwrap_or_default();
        // Windows 11 still reports "Windows 10" in ProductName.
        if build.parse::<u32>().map(|b| b >= 22_000).unwrap_or(false) && os.contains("Windows 10") {
            os = os.replace("Windows 10", "Windows 11");
        }
        w.computer.os = os;
        w.computer.edition = cv.string("EditionID").unwrap_or_default();
        w.computer.version = cv.string("DisplayVersion").or_else(|| cv.string("ReleaseId")).unwrap_or_default();
        w.computer.build = match cv.u32("UBR") {
            Some(u) if !build.is_empty() => format!("{}.{}", build, u),
            _ => build,
        };
        w.computer.install_time = cv
            .u64("InstallTime")
            .map(kokino_artifacts::bin::plausible)
            .filter(|t| *t > 0)
            .or_else(|| cv.u32("InstallDate").and_then(|s| kokino_artifacts::bin::unix_to_filetime(s as i64)))
            .unwrap_or(0);
        w.computer.owner = cv.string("RegisteredOwner").unwrap_or_default();
        w.computer.organization = cv.string("RegisteredOrganization").unwrap_or_default();
        if let Some(pl) = cv.subkey("ProfileList") {
            for p in pl.subkeys() {
                let sid = p.name();
                if !sid.starts_with("S-1-5-21-") {
                    continue;
                }
                let profile = p.string("ProfileImagePath").unwrap_or_default();
                w.users.push(UserAccount {
                    name: profile.rsplit('\\').next().unwrap_or("").to_string(),
                    rid: sid.rsplit('-').next().and_then(|r| r.parse().ok()),
                    sid,
                    profile,
                    created: p.last_written(),
                    source: "profile".into(),
                    ..Default::default()
                });
            }
        }
        if let Some(nl) = cv.subkey("NetworkList") {
            let mut macs: HashMap<String, (String, String)> = HashMap::new();
            for kind in ["Signatures\\Unmanaged", "Signatures\\Managed"] {
                if let Some(s) = nl.open(kind) {
                    for sig in s.subkeys() {
                        let mac = sig.value("DefaultGatewayMac").map(|v| v.data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")).unwrap_or_default();
                        if let Some(g) = sig.string("ProfileGuid") {
                            macs.insert(g.to_ascii_lowercase(), (mac, sig.string("DnsSuffix").unwrap_or_default()));
                        }
                    }
                }
            }
            if let Some(profiles) = nl.subkey("Profiles") {
                for p in profiles.subkeys() {
                    let st = |n: &str| p.value(n).and_then(|v| kokino_artifacts::bin::systemtime(&v.data)).unwrap_or(0);
                    let (gateway_mac, dns_suffix) = macs.get(&p.name().to_ascii_lowercase()).cloned().unwrap_or_default();
                    w.networks.push(NetworkProfile {
                        name: p.string("ProfileName").unwrap_or_default(),
                        description: p.string("Description").unwrap_or_default(),
                        kind: match p.u32("NameType") {
                            Some(0x47) => "wireless",
                            Some(0x06) => "wired",
                            Some(0x17) => "mobile broadband",
                            _ => "other",
                        }
                        .into(),
                        category: match p.u32("Category") {
                            Some(0) => "public",
                            Some(1) => "private",
                            Some(2) => "domain",
                            _ => "",
                        }
                        .into(),
                        created: st("DateCreated"),
                        last_connected: st("DateLastConnected"),
                        gateway_mac,
                        dns_suffix,
                    });
                }
            }
        }
    }
    for (path, wow64) in [("Microsoft\\Windows\\CurrentVersion\\Uninstall", false), ("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", true)] {
        let Some(u) = h.open(path) else { continue };
        for p in u.subkeys() {
            let Some(name) = p.string("DisplayName") else { continue };
            if p.u32("SystemComponent") == Some(1) {
                continue;
            }
            w.programs.push(InstalledProgram {
                name,
                version: p.string("DisplayVersion").unwrap_or_default(),
                publisher: p.string("Publisher").unwrap_or_default(),
                install_date: p.string("InstallDate").and_then(|s| yyyymmdd(&s)).unwrap_or(0),
                location: p.string("InstallLocation").unwrap_or_default(),
                key_written: p.last_written(),
                wow64,
            });
        }
    }
    for path in ["Microsoft\\Windows\\CurrentVersion\\Run", "Microsoft\\Windows\\CurrentVersion\\RunOnce", "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"] {
        run_key(w, h.open(path), &format!("SOFTWARE\\{}", path), "");
    }
}

const TASK_CACHE: &str = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";

/// Joins task files with TaskCache. A task the Task Scheduler knows has a
/// key under TaskCache\Tree (folders as subkeys) with its id, and the
/// same id under TaskCache\Tasks holds its path, a binary copy of its
/// actions and DynamicInfo (created, last run).
fn scheduled_tasks(w: &mut WindowsArtifacts, sw: Option<&Hive>, defs: Vec<(usize, task::Task)>, files: &[FileRow]) {
    // Task files by path; live copies came first.
    let mut by_path: Vec<(String, usize, task::Task)> = vec![];
    for (i, t) in defs {
        let p = &files[i].e.path;
        let rel = p.get("/Windows/System32/Tasks".len()..).unwrap_or("").replace('/', "\\");
        if rel.is_empty() || by_path.iter().any(|(q, _, _)| q.eq_ignore_ascii_case(&rel)) {
            continue;
        }
        by_path.push((rel, i, t));
    }
    let mut out: Vec<ScheduledTask> = vec![];
    if let Some(cache) = sw.and_then(|h| h.open(TASK_CACHE)) {
        let tasks = cache.subkey("Tasks");
        // (path, id, SD present, Tree key last written)
        let mut tree: Vec<(String, String, bool, u64)> = vec![];
        if let Some(t) = cache.subkey("Tree") {
            tree_walk(&t, "", 0, &mut tree);
        }
        // Windows 7 writes no SD values at all; only where the others have
        // one does a missing SD mean a hidden task.
        let uses_sd = tree.iter().any(|t| t.2);
        for t in &mut tree {
            t.2 = t.2 || !uses_sd;
        }
        let mut seen: Vec<String> = vec![];
        let add = |path: String, id: &str, sd: Option<bool>, written: u64, out: &mut Vec<ScheduledTask>| {
            let k = tasks.as_ref().and_then(|t| t.subkey(id));
            let mut x = ScheduledTask { path, registered: true, sd_removed: sd == Some(false), tree_written: written, enabled: true, ..Default::default() };
            if let Some(k) = &k {
                x.author = k.string("Author").unwrap_or_default();
                x.description = k.string("Description").unwrap_or_default();
                x.date = k.string("Date").unwrap_or_default();
                if let Some(d) = k.value("DynamicInfo").and_then(|v| task::dynamic_info(&v.data)) {
                    x.created = d.created;
                    x.last_run = d.last_run;
                    x.last_success = d.last_success;
                    x.last_result = d.last_error;
                }
                if let Some(v) = k.value("Actions") {
                    let (ctx, acts) = task::actions_blob(&v.data);
                    x.actions = acts;
                    if ctx.starts_with("S-1-") || ctx.contains('\\') {
                        x.user = ctx;
                    }
                }
            }
            if sd.is_none() {
                x.notes.push("in TaskCache\\Tasks but not in the task tree".into());
            }
            out.push(x);
        };
        for (path, id, sd, written) in tree {
            seen.push(id.to_ascii_lowercase());
            add(path, &id, Some(sd), written, &mut out);
        }
        if let Some(t) = &tasks {
            for k in t.subkeys().into_iter().take(MAX_TASKS) {
                if seen.contains(&k.name().to_ascii_lowercase()) {
                    continue;
                }
                let Some(path) = k.string("Path") else { continue };
                add(path, &k.name(), None, 0, &mut out);
            }
        }
    }
    let have_cache = !out.is_empty();
    for x in &mut out {
        let Some(at) = by_path.iter().position(|(p, _, _)| p.eq_ignore_ascii_case(&x.path)) else {
            x.notes.push("no task file: it is registered, but Windows\\System32\\Tasks has no file for it".into());
            continue;
        };
        let (_, i, t) = by_path.swap_remove(at);
        merge_task(x, i, t, files);
    }
    for (path, i, t) in by_path {
        let mut x = ScheduledTask { path, ..Default::default() };
        merge_task(&mut x, i, t, files);
        if have_cache {
            x.notes.push(if x.file_deleted { "deleted task file; the task is not registered any more" } else { "not registered in TaskCache: the file may have been copied in, or the SOFTWARE hive is older than the file" }.into());
        }
        out.push(x);
    }
    for x in &mut out {
        x.microsoft = x.path.to_ascii_lowercase().starts_with("\\microsoft\\");
        x.unusual = x.actions.iter().any(|a| a.kind == "Exec" && unusual_path(&a.command) || unusual_path(&a.arguments) && a.arguments.contains('\\'));
        if x.sd_removed {
            x.notes.insert(0, "hidden: its TaskCache\\Tree key has no SD value, so schtasks and the Task Scheduler do not list it, yet it still runs (the Tarrask technique)".into());
        }
        if x.file_deleted {
            x.notes.push("task file deleted".into());
        }
        if !x.microsoft || x.unusual || x.sd_removed {
            w.autoruns.push(Autorun {
                kind: "Scheduled task".into(),
                location: format!("Task {}", x.path),
                name: x.path.rsplit('\\').next().unwrap_or("").to_string(),
                command: x.command(),
                user: x.user.clone(),
                written: if x.created > 0 { x.created } else { x.tree_written },
                start: if x.triggers.is_empty() { "on demand or as registered".into() } else { x.triggers.join("; ") },
                unusual: x.unusual || x.sd_removed,
            });
        }
    }
    // Hidden first, then unusual ones, then the rest; Windows' own last.
    out.sort_by(|a, b| b.sd_removed.cmp(&a.sd_removed).then(b.unusual.cmp(&a.unusual)).then(a.microsoft.cmp(&b.microsoft)).then(b.created.cmp(&a.created)).then(a.path.cmp(&b.path)));
    w.tasks = out;
}

fn merge_task(x: &mut ScheduledTask, i: usize, t: task::Task, files: &[FileRow]) {
    x.file = Some(i as u32);
    x.file_deleted = files[i].e.deleted;
    let or = |a: &mut String, b: String| {
        if !b.is_empty() {
            *a = b;
        }
    };
    or(&mut x.author, t.author);
    or(&mut x.description, t.description);
    or(&mut x.date, t.date);
    or(&mut x.user, t.user);
    x.run_level = t.run_level;
    x.hidden = t.hidden;
    x.enabled = t.enabled;
    x.triggers = t.triggers;
    if !t.actions.is_empty() {
        x.actions = t.actions;
    }
}

fn tree_walk(k: &Key<'_>, prefix: &str, depth: usize, out: &mut Vec<(String, String, bool, u64)>) {
    if depth > 16 || out.len() >= MAX_TASKS {
        return;
    }
    for s in k.subkeys() {
        let path = format!("{}\\{}", prefix, s.name());
        if let Some(id) = s.string("Id") {
            out.push((path.clone(), id, s.value("SD").is_some(), s.last_written()));
        }
        tree_walk(&s, &path, depth + 1, out);
    }
}

/// Names of the service accounts tasks usually run as.
fn well_known_sid(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-5-18" => Some("SYSTEM"),
        "S-1-5-19" => Some("LOCAL SERVICE"),
        "S-1-5-20" => Some("NETWORK SERVICE"),
        "S-1-5-32-544" => Some("Administrators"),
        "S-1-5-32-545" => Some("Users"),
        "S-1-5-4" => Some("INTERACTIVE"),
        _ => None,
    }
}

fn run_key(w: &mut WindowsArtifacts, k: Option<Key<'_>>, location: &str, user: &str) {
    let Some(k) = k else { return };
    for v in k.values() {
        let command = v.string();
        if command.is_empty() {
            continue;
        }
        w.autoruns.push(Autorun {
            kind: "Run key".into(),
            location: location.into(),
            name: v.name.clone(),
            unusual: unusual_path(&command),
            command,
            user: user.into(),
            written: k.last_written(),
            start: "at logon".into(),
        });
    }
}

fn yyyymmdd(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.len() != 8 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let (y, m, d): (u16, u16, u16) = (s[0..4].parse().ok()?, s[4..6].parse().ok()?, s[6..8].parse().ok()?);
    let st: Vec<u8> = [y, m, 0u16, d, 0, 0, 0, 0].iter().flat_map(|v| v.to_le_bytes()).collect();
    kokino_artifacts::bin::systemtime(&st)
}

fn sam_hive(w: &mut WindowsArtifacts, h: &Hive) {
    use kokino_artifacts::bin::*;
    let Some(users) = h.open("SAM\\Domains\\Account\\Users") else { return };
    let Some(names) = users.subkey("Names") else { return };
    for n in names.subkeys() {
        let name = n.name();
        // The default value's type field holds the RID.
        let Some(rid) = n.values().first().map(|v| v.kind) else { continue };
        let f = users.subkey(&format!("{:08X}", rid)).and_then(|k| k.value("F")).map(|v| v.data).unwrap_or_default();
        let acb = u16_at(&f, 56).unwrap_or(0);
        let mut acct = UserAccount {
            name: name.clone(),
            rid: Some(rid),
            created: n.last_written(),
            last_logon: plausible(u64_at(&f, 8).unwrap_or(0)),
            password_set: plausible(u64_at(&f, 24).unwrap_or(0)),
            last_failed: plausible(u64_at(&f, 40).unwrap_or(0)),
            failed_count: u16_at(&f, 64).unwrap_or(0) as u32,
            logon_count: u16_at(&f, 66).unwrap_or(0) as u32,
            disabled: acb & 0x0001 != 0,
            source: "SAM".into(),
            ..Default::default()
        };
        if let Some(p) = w.users.iter().position(|u| u.source == "profile" && u.rid == Some(rid)) {
            let prof = w.users.remove(p);
            acct.sid = prof.sid;
            acct.profile = prof.profile;
            acct.source = "SAM, profile".into();
        }
        w.users.push(acct);
    }
}

fn amcache_hive(w: &mut WindowsArtifacts, h: &Hive, file: usize) {
    let Some(inv) = h.open("Root\\InventoryApplicationFile") else { return };
    for k in inv.subkeys() {
        let path = k.string("LowerCaseLongPath").unwrap_or_default();
        if path.is_empty() {
            continue;
        }
        let sha1 = k.string("FileId").map(|s| s.trim_start_matches("0000").to_string()).unwrap_or_default();
        let detail = [
            k.string("Publisher").map(|p| format!("publisher {}", p)),
            k.string("Version").map(|v| format!("version {}", v)),
            k.string("LinkDate").map(|v| format!("compiled {}", v)),
            k.u64("Size").map(|s| format!("{} bytes", s)),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        w.execution.push(Execution {
            source: "Amcache".into(),
            tool: is_tool(&path),
            program: path,
            times: vec![k.last_written()],
            sha1,
            detail,
            file: Some(file as u32),
            ..Default::default()
        });
    }
}

/// Well-known folder GUIDs used in UserAssist value names.
const KNOWN_FOLDERS: &[(&str, &str)] = &[
    ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "C:\\Windows\\System32"),
    ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "C:\\Windows\\SysWOW64"),
    ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "C:\\Windows"),
    ("{6D809377-6AF0-444B-8957-A3773F02200E}", "C:\\Program Files"),
    ("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "C:\\Program Files (x86)"),
    ("{905E63B6-C1BF-494E-B29C-65B732D3D21A}", "C:\\Program Files"),
];

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

fn mru_order(k: &Key<'_>) -> Vec<String> {
    if let Some(v) = k.value("MRUListEx") {
        return v.data.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).take_while(|&i| i != u32::MAX).map(|i| i.to_string()).collect();
    }
    if let Some(s) = k.string("MRUList") {
        return s.chars().map(|c| c.to_string()).collect();
    }
    let mut v: Vec<String> = k.values().into_iter().map(|v| v.name).collect();
    v.sort();
    v
}

fn ntuser_hive(w: &mut WindowsArtifacts, h: &Hive, user: &str, file: usize) {
    use kokino_artifacts::bin::*;
    let exp = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";
    if let Some(ua) = h.open(&format!("{}\\UserAssist", exp)) {
        for g in ua.subkeys() {
            let Some(count) = g.subkey("Count") else { continue };
            for v in count.values() {
                let mut name = rot13(&v.name);
                if name.starts_with("UEME_") || v.data.len() < 16 {
                    continue;
                }
                for (guid, path) in KNOWN_FOLDERS {
                    if name.len() >= guid.len() && name[..guid.len()].eq_ignore_ascii_case(guid) {
                        name = format!("{}{}", path, &name[guid.len()..]);
                    }
                }
                let (runs, last) = if v.data.len() >= 68 {
                    (u32_at(&v.data, 4).unwrap_or(0), plausible(u64_at(&v.data, 60).unwrap_or(0)))
                } else {
                    (u32_at(&v.data, 4).unwrap_or(0).saturating_sub(5), plausible(u64_at(&v.data, 8).unwrap_or(0)))
                };
                let focus = u32_at(&v.data, 12).unwrap_or(0);
                w.execution.push(Execution {
                    source: "UserAssist".into(),
                    tool: is_tool(&name),
                    program: name,
                    user: user.into(),
                    count: Some(runs),
                    times: if last > 0 { vec![last] } else { vec![] },
                    detail: if v.data.len() >= 68 { format!("in focus {} s", focus / 1000) } else { String::new() },
                    file: Some(file as u32),
                    ..Default::default()
                });
            }
        }
    }
    let mru = |w: &mut WindowsArtifacts, key: &str, source: &str, decode: &dyn Fn(&registry::Value) -> String| {
        let Some(k) = h.open(key) else { return };
        let vals = k.values();
        for (pos, name) in mru_order(&k).iter().enumerate() {
            let Some(v) = vals.iter().find(|v| &v.name == name) else { continue };
            let text = decode(v);
            if text.is_empty() {
                continue;
            }
            w.access.push(FileAccess {
                source: source.into(),
                user: user.into(),
                path: text,
                // Only the most recent entry's time is known: the key's last write.
                time: if pos == 0 { k.last_written() } else { 0 },
                file: Some(file as u32),
                ..Default::default()
            });
        }
    };
    mru(w, &format!("{}\\RecentDocs", exp), "RecentDocs", &|v| utf16(&v.data));
    mru(w, &format!("{}\\TypedPaths", exp), "TypedPaths", &|v| v.string());
    mru(w, &format!("{}\\RunMRU", exp), "RunMRU", &|v| v.string().trim_end_matches("\\1").to_string());
    mru(w, &format!("{}\\WordWheelQuery", exp), "Explorer search", &|v| utf16(&v.data));
    for path in ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"] {
        run_key(w, h.open(path), &format!("NTUSER.DAT ({})\\{}", user, path), user);
    }
}

// ------------------------------------------------------------------ files

fn prefetch_exec(w: &mut WindowsArtifacts, pf: prefetch::Prefetch, i: usize, f: &FileRow) {
    let program = pf.path.clone().map(|p| strip_volume(&p)).unwrap_or_else(|| pf.executable.clone());
    let vols: Vec<String> = pf.volumes.iter().map(|v| format!("{} (serial {})", v.device, v.serial)).collect();
    w.execution.push(Execution {
        source: "Prefetch".into(),
        tool: is_tool(&pf.executable),
        program,
        count: Some(pf.run_count),
        times: pf.last_runs.clone(),
        detail: format!("version {}{}, {} files referenced, volume {}", pf.version, if pf.compressed { " (compressed)" } else { "" }, pf.files.len(), vols.join("; ")),
        file: Some(i as u32),
        deleted: f.e.deleted,
        ..Default::default()
    });
}

/// "\VOLUME{...}\USERS\ALICE\X.EXE" -> "\USERS\ALICE\X.EXE"
fn strip_volume(p: &str) -> String {
    if p.starts_with("\\VOLUME{") || p.starts_with("\\DEVICE\\") {
        if let Some(i) = p[1..].find('\\') {
            return p[i + 1..].to_string();
        }
    }
    p.to_string()
}

fn lnk_access(w: &mut WindowsArtifacts, l: lnk::Lnk, i: usize, f: &FileRow) {
    // The shortcut is created the first time the target is opened and
    // updated each time after: its own $SI times give first and last open.
    let si = f.e.si.unwrap_or_default();
    w.access.push(FileAccess {
        source: "LNK".into(),
        user: user_of(&f.e.path),
        path: l.target.clone(),
        time: si.modified,
        first: si.created,
        drive_type: l.drive_type,
        volume_label: l.volume_label,
        volume_serial: l.volume_serial,
        machine: l.machine_id,
        mac: l.mac,
        file: Some(i as u32),
        deleted: f.e.deleted,
        ..Default::default()
    });
}

fn jump_access(w: &mut WindowsArtifacts, jl: jumplist::JumpList, i: usize, f: &FileRow) {
    for e in jl.entries {
        let l = e.lnk.clone().unwrap_or_default();
        w.access.push(FileAccess {
            source: "Jump List".into(),
            user: user_of(&f.e.path),
            path: e.path,
            time: e.last_access,
            count: (!jl.custom).then_some(e.access_count),
            pinned: e.pinned,
            app_id: jl.app_id.clone(),
            drive_type: l.drive_type,
            volume_label: l.volume_label,
            volume_serial: l.volume_serial,
            machine: if e.hostname.is_empty() { l.machine_id } else { e.hostname },
            mac: l.mac,
            file: Some(i as u32),
            deleted: f.e.deleted,
            ..Default::default()
        });
    }
}

// ------------------------------------------------------------------ events

struct Notable {
    channel: &'static str,
    id: u32,
    category: &'static str,
    title: &'static str,
}

const TS_LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

const NOTABLE: &[Notable] = &[
    Notable { channel: "Security", id: 1102, category: "Log cleared", title: "Security log cleared" },
    Notable { channel: "System", id: 104, category: "Log cleared", title: "Event log cleared" },
    Notable { channel: "Security", id: 4624, category: "Logon", title: "Logon" },
    Notable { channel: "Security", id: 4625, category: "Failed logon", title: "Failed logon" },
    Notable { channel: "Security", id: 4647, category: "Logon", title: "User logged off" },
    Notable { channel: "Security", id: 4648, category: "Logon", title: "Logon with explicit credentials" },
    Notable { channel: "Security", id: 4672, category: "Logon", title: "Administrator-level logon" },
    Notable { channel: "Security", id: 4688, category: "Process", title: "Process created" },
    Notable { channel: "Security", id: 4697, category: "Service", title: "Service installed" },
    Notable { channel: "Security", id: 4698, category: "Task", title: "Scheduled task created" },
    Notable { channel: "Security", id: 4699, category: "Task", title: "Scheduled task deleted" },
    Notable { channel: "Security", id: 4616, category: "Time change", title: "System time changed" },
    Notable { channel: "Security", id: 4719, category: "Account", title: "Audit policy changed" },
    Notable { channel: "Security", id: 4720, category: "Account", title: "User account created" },
    Notable { channel: "Security", id: 4722, category: "Account", title: "User account enabled" },
    Notable { channel: "Security", id: 4724, category: "Account", title: "Password reset" },
    Notable { channel: "Security", id: 4725, category: "Account", title: "User account disabled" },
    Notable { channel: "Security", id: 4726, category: "Account", title: "User account deleted" },
    Notable { channel: "Security", id: 4728, category: "Account", title: "Member added to global group" },
    Notable { channel: "Security", id: 4732, category: "Account", title: "Member added to local group" },
    Notable { channel: "Security", id: 4756, category: "Account", title: "Member added to universal group" },
    Notable { channel: "Security", id: 4740, category: "Account", title: "Account locked out" },
    Notable { channel: "Security", id: 4778, category: "Remote desktop", title: "Session reconnected" },
    Notable { channel: "Security", id: 4779, category: "Remote desktop", title: "Session disconnected" },
    // Windows NT, 2000, XP and Server 2003 (legacy .evt logs).
    Notable { channel: "Security", id: 517, category: "Log cleared", title: "Security log cleared" },
    Notable { channel: "Security", id: 528, category: "Logon", title: "Logon" },
    Notable { channel: "Security", id: 540, category: "Logon", title: "Network logon" },
    Notable { channel: "Security", id: 529, category: "Failed logon", title: "Failed logon (bad user name or password)" },
    Notable { channel: "Security", id: 530, category: "Failed logon", title: "Failed logon (time restriction)" },
    Notable { channel: "Security", id: 531, category: "Failed logon", title: "Failed logon (account disabled)" },
    Notable { channel: "Security", id: 532, category: "Failed logon", title: "Failed logon (account expired)" },
    Notable { channel: "Security", id: 533, category: "Failed logon", title: "Failed logon (not allowed on this computer)" },
    Notable { channel: "Security", id: 534, category: "Failed logon", title: "Failed logon (logon type not granted)" },
    Notable { channel: "Security", id: 535, category: "Failed logon", title: "Failed logon (password expired)" },
    Notable { channel: "Security", id: 539, category: "Failed logon", title: "Failed logon (account locked out)" },
    Notable { channel: "Security", id: 552, category: "Logon", title: "Logon with explicit credentials" },
    Notable { channel: "Security", id: 592, category: "Process", title: "Process created" },
    Notable { channel: "Security", id: 601, category: "Service", title: "Service installed" },
    Notable { channel: "Security", id: 612, category: "Account", title: "Audit policy changed" },
    Notable { channel: "Security", id: 520, category: "Time change", title: "System time changed" },
    Notable { channel: "Security", id: 624, category: "Account", title: "User account created" },
    Notable { channel: "Security", id: 626, category: "Account", title: "User account enabled" },
    Notable { channel: "Security", id: 628, category: "Account", title: "Password reset" },
    Notable { channel: "Security", id: 629, category: "Account", title: "User account disabled" },
    Notable { channel: "Security", id: 630, category: "Account", title: "User account deleted" },
    Notable { channel: "Security", id: 632, category: "Account", title: "Member added to global group" },
    Notable { channel: "Security", id: 636, category: "Account", title: "Member added to local group" },
    Notable { channel: "Security", id: 660, category: "Account", title: "Member added to universal group" },
    Notable { channel: "Security", id: 644, category: "Account", title: "Account locked out" },
    Notable { channel: "System", id: 6005, category: "System", title: "Event log service started (boot)" },
    Notable { channel: "System", id: 6006, category: "System", title: "Event log service stopped (shutdown)" },
    Notable { channel: "System", id: 6008, category: "System", title: "Unexpected shutdown" },
    Notable { channel: "System", id: 1074, category: "System", title: "Shutdown or restart initiated" },
    Notable { channel: "System", id: 41, category: "System", title: "Rebooted without clean shutdown" },
    Notable { channel: "System", id: 7045, category: "Service", title: "Service installed" },
    Notable { channel: TS_LSM, id: 21, category: "Remote desktop", title: "Remote desktop logon" },
    Notable { channel: TS_LSM, id: 23, category: "Remote desktop", title: "Remote desktop logoff" },
    Notable { channel: TS_LSM, id: 24, category: "Remote desktop", title: "Remote desktop disconnected" },
    Notable { channel: TS_LSM, id: 25, category: "Remote desktop", title: "Remote desktop reconnected" },
    Notable { channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", id: 1149, category: "Remote desktop", title: "Remote desktop authentication succeeded" },
    Notable { channel: "Microsoft-Windows-PowerShell/Operational", id: 4104, category: "PowerShell", title: "PowerShell script block" },
    Notable { channel: "Microsoft-Windows-Windows Defender/Operational", id: 1116, category: "Defender", title: "Malware detected" },
    Notable { channel: "Microsoft-Windows-Windows Defender/Operational", id: 1117, category: "Defender", title: "Malware action taken" },
    Notable { channel: "Microsoft-Windows-Windows Defender/Operational", id: 5001, category: "Defender", title: "Real-time protection disabled" },
    Notable { channel: "Microsoft-Windows-TaskScheduler/Operational", id: 106, category: "Task", title: "Scheduled task registered" },
    Notable { channel: "Microsoft-Windows-TaskScheduler/Operational", id: 141, category: "Task", title: "Scheduled task deleted" },
    Notable { channel: "Microsoft-Windows-WLAN-AutoConfig/Operational", id: 8001, category: "Network", title: "Connected to wireless network" },
];

fn logon_type(t: &str) -> &'static str {
    match t {
        "2" => "interactive",
        "3" => "network",
        "4" => "batch",
        "5" => "service",
        "7" => "unlock",
        "8" => "network cleartext",
        "9" => "new credentials",
        "10" => "remote desktop",
        "11" => "cached",
        _ => "",
    }
}

/// System and service accounts whose logons are routine noise.
fn machine_account(e: &evtx::Event) -> bool {
    let sid = e.get("TargetUserSid").unwrap_or("");
    let name = e.get("TargetUserName").or(e.get("SubjectUserName")).unwrap_or("");
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-7")
        || name.ends_with('$')
        || name.starts_with("DWM-")
        || name.starts_with("UMFD-")
        || name.eq_ignore_ascii_case("SYSTEM")
        || name.eq_ignore_ascii_case("LOCAL SERVICE")
        || name.eq_ignore_ascii_case("NETWORK SERVICE")
        || name.eq_ignore_ascii_case("ANONYMOUS LOGON")
}

fn summarize(e: &evtx::Event) -> (String, String, String) {
    let g = |k: &str| e.get(k).unwrap_or("").to_string();
    let who = |u: &str, d: &str| if d.is_empty() || d == "-" { u.to_string() } else { format!("{}\\{}", d, u) };
    let target = who(&g("TargetUserName"), &g("TargetDomainName"));
    let subject = g("SubjectUserName");
    let ip = g("IpAddress");
    let from = |ip: &str, ws: &str| match (ip, ws) {
        ("", "") => String::new(),
        (ip, "") => format!(" from {}", ip),
        ("", ws) => format!(" from {}", ws),
        (ip, ws) => format!(" from {} ({})", ip, ws),
    };
    let s = match (e.channel.as_str(), e.event_id) {
        ("Security", 1102) | ("Security", 517) => format!("Security log cleared by {}", if subject.is_empty() { "unknown" } else { &subject }),
        ("System", 104) => format!("{} log cleared by {}", g("Channel"), subject),
        ("Security", 4624 | 4625 | 528 | 540 | 529..=537 | 539) => {
            let lt = g("LogonType");
            let ip = if ip == "127.0.0.1" || ip == "::1" { String::new() } else { ip.clone() };
            let kind = if logon_type(&lt).is_empty() { format!("(type {})", lt) } else { format!("({})", logon_type(&lt)) };
            format!("{} {} {}{}", target, if matches!(e.event_id, 4624 | 528 | 540) { "logged on" } else { "failed to log on" }, kind, from(&ip, &g("WorkstationName")))
        }
        ("Security", 4672) => format!("{} received administrator privileges", subject),
        ("Security", 4688 | 592) => format!("{} ran {}", subject, if g("CommandLine").is_empty() { g("NewProcessName") } else { g("CommandLine") }),
        ("Security", 4720 | 624) => format!("{} created account {}", subject, target),
        ("Security", 4732 | 4728 | 4756 | 632 | 636 | 660) => {
            let member = if g("MemberName").is_empty() { g("MemberSid") } else { g("MemberName") };
            format!("{} added {} to {}", subject, member, g("TargetUserName"))
        }
        ("Security", 4616) => format!("{} changed the time from {} to {}", subject, g("PreviousTime"), g("NewTime")),
        ("System", 7045) | ("Security", 601) => format!("{} ({}, {})", g("ServiceName"), g("ImagePath"), g("StartType")),
        ("System", 1074) => format!("{} by {}: {}", g("param5"), g("param7"), g("param3")),
        (_, 21) | (_, 23) | (_, 24) | (_, 25) => format!("{}{}", g("User"), from(&g("Address"), "")),
        (_, 1149) => format!("{}{}", g("Param1"), from(&g("Param3"), "")),
        (_, 4104) => g("ScriptBlockText").chars().take(400).collect(),
        (_, 1116) | (_, 1117) => format!("{} in {}", g("Threat Name"), g("Path")),
        (_, 8001) => format!("SSID {}", g("SSID")),
        _ => e.data.iter().filter(|(_, v)| !v.is_empty()).take(4).map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(", "),
    };
    let rdp_auth = e.event_id == 1149;
    let user = [g("TargetUserName"), g("User"), if rdp_auth { g("Param1") } else { String::new() }, subject].into_iter().find(|u| !u.is_empty()).unwrap_or_default();
    let ip = [ip, g("Address"), if rdp_auth { g("Param3") } else { String::new() }].into_iter().find(|v| !v.is_empty() && v != "-" && v != "127.0.0.1" && v != "::1").unwrap_or_default();
    (s, user, ip)
}

fn events(w: &mut WindowsArtifacts, d: &[u8], i: usize, f: &FileRow, legacy: bool) {
    let mut counts: BTreeMap<(String, u32), u64> = BTreeMap::new();
    let mut kept = 0usize;
    let mut notable = 0u64;
    let mut channel = String::new();
    let mut new_events = vec![];
    let mut execs = vec![];
    let legacy_channel = kokino_artifacts::evt::channel_of(&f.e.name);
    let mut each = |e: evtx::Event| {
        if channel.is_empty() {
            channel = e.channel.clone();
        }
        *counts.entry((e.channel.clone(), e.event_id)).or_default() += 1;
        let Some(n) = NOTABLE.iter().find(|n| n.id == e.event_id && n.channel.eq_ignore_ascii_case(&e.channel)) else { return };
        if e.channel == "Security" && matches!(e.event_id, 4624 | 4625 | 4672 | 4647 | 4648 | 528 | 529..=537 | 538 | 539 | 540 | 552 | 576) && machine_account(&e) {
            return;
        }
        if matches!(e.event_id, 4624 | 528) && e.get("LogonType") == Some("5") {
            return;
        }
        if e.event_id == 4616 && matches!(e.user_sid.as_deref(), Some("S-1-5-19")) {
            return;
        }
        notable += 1;
        if kept >= MAX_EVENTS_PER_LOG {
            return;
        }
        kept += 1;
        if matches!(e.event_id, 4688 | 592) && e.channel == "Security" {
            let program = e.get("NewProcessName").unwrap_or("").to_string();
            execs.push(Execution {
                source: format!("Event {}", e.event_id),
                tool: is_tool(&program),
                program,
                user: e.get("SubjectUserName").unwrap_or("").into(),
                times: vec![e.time],
                detail: e.get("CommandLine").unwrap_or("").into(),
                file: Some(i as u32),
                deleted: f.e.deleted,
                ..Default::default()
            });
        }
        let (summary, user, ip) = summarize(&e);
        new_events.push(WinEvent {
            time: e.time,
            channel: e.channel.clone(),
            event_id: e.event_id,
            record_id: e.record_id,
            category: n.category.into(),
            title: n.title.into(),
            summary,
            user,
            ip,
            computer: e.computer.clone(),
            data: e.data.iter().filter(|(_, v)| !v.is_empty()).take(24).map(|(k, v)| (k.clone(), v.chars().take(2000).collect())).collect(),
            file: i as u32,
        });
    };
    let res = if legacy { kokino_artifacts::evt::parse(d, &legacy_channel, &mut each) } else { evtx::parse(d, &mut each) };
    let (info, error) = match res {
        Ok(info) => (info, None),
        Err(e) => (evtx::LogInfo::default(), Some(format!("{:#}", e))),
    };
    if channel.is_empty() {
        channel = if legacy { legacy_channel.clone() } else { f.e.name.trim_end_matches(".evtx").replace("%4", "/") };
    }
    w.events.extend(new_events);
    w.execution.extend(execs);
    for ((c, id), n) in counts {
        match w.event_counts.iter_mut().find(|x| x.0 == c && x.1 == id) {
            Some(x) => x.2 += n,
            None => w.event_counts.push((c, id, n)),
        }
    }
    w.logs.push(LogSummary { file: i as u32, path: f.e.path.clone(), channel, info, notable, deleted: f.e.deleted, error });
}

// ------------------------------------------------------------------ finish

fn iso(ft: u64) -> String {
    if ft == 0 { "unknown".into() } else { kokino_core::time::filetime_to_iso(ft) }
}

fn finish(w: &mut WindowsArtifacts) {
    // Name accounts that events only identify by SID.
    let names: Vec<(String, String)> = w.users.iter().filter(|u| !u.sid.is_empty()).map(|u| (u.sid.clone(), u.name.clone())).collect();
    for x in w.execution.iter_mut().filter(|x| x.user.starts_with("S-1-")) {
        if let Some((_, n)) = names.iter().find(|(s, _)| *s == x.user) {
            x.user = n.clone();
        }
    }
    for x in w.tasks.iter_mut().filter(|x| x.user.starts_with("S-1-")) {
        x.user = match (names.iter().find(|(s, _)| *s == x.user), well_known_sid(&x.user)) {
            (Some((_, n)), _) => n.clone(),
            (None, Some(n)) => n.to_string(),
            _ => continue,
        };
    }
    for a in w.autoruns.iter_mut().filter(|a| a.user.starts_with("S-1-")) {
        a.user = match (names.iter().find(|(s, _)| *s == a.user), well_known_sid(&a.user)) {
            (Some((_, n)), _) => n.clone(),
            (None, Some(n)) => n.to_string(),
            _ => continue,
        };
    }
    for e in &mut w.events {
        for (sid, name) in &names {
            if e.summary.contains(sid.as_str()) {
                e.summary = e.summary.replace(sid.as_str(), &format!("{} ({})", name, sid));
            }
        }
    }
    w.events.sort_by(|a, b| a.time.cmp(&b.time).then(a.record_id.cmp(&b.record_id)));
    w.execution.sort_by(|a, b| b.times.first().cmp(&a.times.first()).then(a.program.cmp(&b.program)));
    w.access.sort_by(|a, b| b.time.cmp(&a.time));
    w.usb.sort_by(|a, b| b.last_connected.max(b.key_written).cmp(&a.last_connected.max(a.key_written)));
    w.programs.sort_by(|a, b| b.install_date.max(b.key_written).cmp(&a.install_date.max(a.key_written)));
    w.event_counts.sort_by(|a, b| b.2.cmp(&a.2));
    let mut t = vec![];
    for x in &w.execution {
        if x.source == "ShimCache" || x.source == "Event 4688" {
            continue;
        }
        for &ts in &x.times {
            let label = if x.source == "Amcache" { "first seen (Amcache)" } else { x.source.as_str() };
            t.push(WinTime { t: ts, kind: "EXEC".into(), what: x.program.clone(), detail: format!("{}{}", label, if x.user.is_empty() { String::new() } else { format!(", user {}", x.user) }) });
        }
    }
    for a in &w.access {
        if a.time > 0 {
            t.push(WinTime { t: a.time, kind: "OPEN".into(), what: a.path.clone(), detail: format!("{}{}", a.source, if a.user.is_empty() { String::new() } else { format!(", user {}", a.user) }) });
        }
        if a.first > 0 && a.first != a.time {
            t.push(WinTime { t: a.first, kind: "OPEN".into(), what: a.path.clone(), detail: format!("first opened ({})", a.source) });
        }
    }
    for u in &w.usb {
        let name = if u.name.is_empty() { format!("{} {}", u.vendor, u.product) } else { u.name.clone() };
        for (ts, what) in [(u.first_connected, "first connected"), (u.last_connected, "last connected"), (u.last_removed, "removed")] {
            if ts > 0 {
                t.push(WinTime { t: ts, kind: "USB".into(), what: name.clone(), detail: format!("{}, serial {}", what, u.serial) });
            }
        }
    }
    for p in &w.programs {
        let ts = if p.install_date > 0 { p.install_date } else { p.key_written };
        if ts > 0 {
            t.push(WinTime { t: ts, kind: "INST".into(), what: p.name.clone(), detail: format!("installed{}", if p.publisher.is_empty() { String::new() } else { format!(", {}", p.publisher) }) });
        }
    }
    for n in &w.networks {
        for (ts, what) in [(n.created, "first connected"), (n.last_connected, "last connected")] {
            if ts > 0 {
                t.push(WinTime { t: ts, kind: "NET".into(), what: n.name.clone(), detail: what.into() });
            }
        }
    }
    for e in &w.events {
        t.push(WinTime { t: e.time, kind: "EVT".into(), what: e.title.clone(), detail: e.summary.chars().take(300).collect() });
    }
    for b in &w.shellbags {
        if b.bag.opened > 0 {
            t.push(WinTime { t: b.bag.opened, kind: "OPEN".into(), what: b.bag.path.clone(), detail: format!("folder opened (ShellBags){}", if b.user.is_empty() { String::new() } else { format!(", user {}", b.user) }) });
        }
    }
    if let Some(s) = &w.srum {
        // Hours in which a program sent a lot (100 MiB or more), and
        // network connections.
        for n in s.network.iter().filter(|n| n.sent >= 100 << 20) {
            t.push(WinTime { t: n.t, kind: "NET".into(), what: n.app.clone(), detail: format!("sent {} bytes, received {} in the hour before (SRUM){}{}", n.sent, n.received, if n.profile.is_empty() { String::new() } else { format!(", network {}", n.profile) }, if n.user.is_empty() { String::new() } else { format!(", user {}", n.user) }) });
        }
        for c in &s.connections {
            t.push(WinTime { t: c.start, kind: "NET".into(), what: if c.profile.is_empty() { c.interface.clone() } else { c.profile.clone() }, detail: format!("connected for {} min ({}, SRUM)", c.seconds / 60, c.interface) });
        }
    }
    for k in &w.tasks {
        // Windows' own tasks run all the time; only the others' runs are events.
        if k.created > 0 {
            t.push(WinTime { t: k.created, kind: "INST".into(), what: k.path.clone(), detail: format!("scheduled task registered: {}", k.command()) });
        }
        if k.last_run > 0 && !k.microsoft {
            t.push(WinTime { t: k.last_run, kind: "EXEC".into(), what: k.path.clone(), detail: format!("scheduled task last ran: {}", k.command()) });
        }
    }
    if let Some(j) = &w.journal {
        // Created, deleted and renamed files; plain writes stay in the
        // journal table.
        let notable = usn::FILE_CREATE | usn::FILE_DELETE | usn::RENAME_NEW_NAME;
        for c in j.changes.iter().filter(|c| c.c.reasons & notable != 0) {
            let detail = if c.old_path.is_empty() { format!("{} (change journal)", c.what) } else { format!("{} from {} (change journal)", c.what, c.old_path) };
            t.push(WinTime { t: c.c.t, kind: "FILE".into(), what: c.path.clone(), detail });
        }
    }
    for k in w.reg_deleted_keys.iter().filter(|k| k.complete_path) {
        t.push(WinTime {
            t: k.last_written,
            kind: "REG".into(),
            what: format!("{}\\{}", k.hive, k.path),
            detail: format!("deleted registry key, last changed{}", if k.notable.is_empty() { String::new() } else { format!("; it recorded {}", k.notable) }),
        });
    }
    t.retain(|x| x.t > 0);
    t.sort_by(|a, b| a.t.cmp(&b.t));
    w.timeline = t;
}

/// Lines for the impact summary.
pub fn impact(w: &WindowsArtifacts) -> Vec<String> {
    let mut out = vec![];
    let traces: Vec<&RegDeletedKey> = w.reg_deleted_keys.iter().filter(|k| user_activity_trace(&k.notable)).collect();
    let c = &w.computer;
    if !c.name.is_empty() || !c.os.is_empty() {
        out.push(format!("Computer {} running {} {} (build {}), installed {}.", or(&c.name, "unnamed"), c.os, c.version, or(&c.build, "unknown"), iso(c.install_time)));
    }
    for e in w.events.iter().filter(|e| e.category == "Log cleared") {
        out.push(format!("{} at {} ({}).", e.summary, iso(e.time), e.channel));
    }
    let mut tools: Vec<String> = w.execution.iter().filter(|x| x.tool && x.source != "ShimCache").map(|x| format!("{} ({})", base_name(&x.program).to_ascii_lowercase(), x.source)).collect();
    tools.sort();
    tools.dedup();
    if !tools.is_empty() {
        out.push(format!("Execution records show anti-forensic tools ran: {}.", tools.join(", ")));
    }
    if !w.usb.is_empty() {
        out.push(format!("{} USB storage device(s) connected: {}.", w.usb.len(), w.usb.iter().map(|u| if u.name.is_empty() { u.product.clone() } else { u.name.clone() }).collect::<Vec<_>>().join(", ")));
    }
    let rdp: Vec<&WinEvent> = w.events.iter().filter(|e| e.category == "Remote desktop" || (e.event_id == 4624 && e.data.iter().any(|(k, v)| k == "LogonType" && v == "10"))).collect();
    if !rdp.is_empty() {
        let ips: std::collections::BTreeSet<&str> = rdp.iter().map(|e| e.ip.as_str()).filter(|i| !i.is_empty()).collect();
        out.push(format!("{} remote desktop event(s){}.", rdp.len(), if ips.is_empty() { String::new() } else { format!(" from {}", ips.into_iter().collect::<Vec<_>>().join(", ")) }));
    }
    let hidden: Vec<&ScheduledTask> = w.tasks.iter().filter(|k| k.sd_removed).collect();
    if !hidden.is_empty() {
        out.push(format!("{} scheduled task(s) hidden by removing their security descriptor (Tarrask technique): {}.", hidden.len(), hidden.iter().map(|k| format!("{} ({})", k.path, k.command())).collect::<Vec<_>>().join(", ")));
    }
    let odd: Vec<&ScheduledTask> = w.tasks.iter().filter(|k| k.unusual && !k.sd_removed).collect();
    if !odd.is_empty() {
        out.push(format!("{} scheduled task(s) run programs from unusual places: {}.", odd.len(), odd.iter().take(5).map(|k| format!("{} ({})", k.path, k.command())).collect::<Vec<_>>().join(", ")));
    }
    let failed = w.events.iter().filter(|e| e.event_id == 4625).count();
    if failed > 0 {
        out.push(format!("{} failed logon(s) recorded.", failed));
    }
    let field = |e: &WinEvent, k: &str| e.data.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_else(|| "?".into());
    let created: Vec<String> = w.events.iter().filter(|e| e.event_id == 4720).map(|e| field(e, "TargetUserName")).collect();
    if !created.is_empty() {
        out.push(format!("User account(s) created: {}.", created.join(", ")));
    }
    let services: Vec<String> = w.events.iter().filter(|e| e.event_id == 7045 || e.event_id == 4697).map(|e| field(e, "ServiceName")).collect();
    if !services.is_empty() {
        out.push(format!("Service(s) installed: {}.", services.join(", ")));
    }
    let odd = w.autoruns.iter().filter(|a| a.unusual).count();
    if odd > 0 {
        out.push(format!("{} autostart entr{} run from unusual locations.", odd, if odd == 1 { "y" } else { "ies" }));
    }
    if let Some(j) = &w.journal {
        if j.records > 0 {
            let del = j.changes.iter().filter(|c| c.c.reasons & usn::FILE_DELETE != 0).count();
            out.push(format!(
                "The change journal covers {} to {}: {} records, {} file changes ({} deletions){}.",
                iso(j.first),
                iso(j.last),
                j.records,
                j.changes.len() as u64 + j.dropped,
                del,
                if j.dropped > 0 { format!("; the oldest {} are not kept", j.dropped) } else { String::new() }
            ));
        }
        if let Some(e) = &j.error {
            out.push(format!("Change journal: {}.", e));
        }
    }
    if let Some(s) = &w.srum {
        if s.first > 0 {
            let top: Vec<String> = s.apps.iter().filter(|a| a.sent >= 1 << 20).take(3).map(|a| format!("{} ({} MiB)", base_name(&a.app), a.sent >> 20)).collect();
            out.push(format!(
                "SRUM covers {} to {}: {} program(s){}.{}",
                iso(s.first),
                iso(s.last),
                s.apps.len(),
                if top.is_empty() { String::new() } else { format!("; most data sent by {}", top.join(", ")) },
                if s.dirty { " The database was not cleanly closed: the newest hours may be only in its transaction logs (SRU*.log), which are not read." } else { "" }
            ));
        }
        if let Some(e) = &s.error {
            out.push(format!("SRUM: {}.", e));
        }
    }
    if !w.shellbags.is_empty() {
        let away = w.shellbags.iter().filter(|b| matches!(b.bag.kind.as_str(), "drive" | "network") || b.bag.path.starts_with("\\\\")).count();
        out.push(format!("ShellBags record {} folder(s) users opened in Explorer{}.", w.shellbags.len(), if away > 0 { format!(", including {} drive or network location(s)", away) } else { String::new() }));
    }
    if !w.reg_deleted_keys.is_empty() || !w.reg_deleted_values.is_empty() {
        let mut line = format!("{} deleted registry key(s) and {} deleted value(s) recovered from free space in the hives", w.reg_deleted_keys.len(), w.reg_deleted_values.len());
        if !traces.is_empty() {
            let mut what: Vec<String> = traces.iter().map(|k| format!("{} ({})", k.path, k.notable)).collect();
            what.sort();
            what.dedup();
            let n = what.len();
            what.truncate(5);
            line.push_str(&format!("; {} of the keys recorded user activity: {}{}", traces.len(), what.join(", "), if n > 5 { ", ..." } else { "" }));
        }
        out.push(line + ".");
    }
    out
}

fn or<'a>(s: &'a str, d: &'a str) -> &'a str {
    if s.is_empty() { d } else { s }
}

// ------------------------------------------------------------------ inspect

/// What a single artifact file holds, for `kokino artifact`: detected by
/// content, summarized (or dumped in full with `full`).
pub fn inspect(name: &str, data: &[u8], full: bool) -> anyhow::Result<Value> {
    if data.get(4..8) == Some(b"LfLe") {
        let channel = kokino_artifacts::evt::channel_of(name);
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut events = vec![];
        let info = kokino_artifacts::evt::parse(data, &channel, &mut |e| {
            *counts.entry(format!("{} {}", e.provider, e.event_id)).or_default() += 1;
            if full {
                events.push(e);
            }
        })?;
        let mut top: Vec<(String, u64)> = counts.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        let mut v = json!({"kind": "evt", "file": name, "channel": channel, "log": info, "event_ids": top.iter().take(40).map(|(k, n)| json!([k, n])).collect::<Vec<_>>()});
        if full {
            v["events"] = json!(events);
        }
        return Ok(v);
    }
    if data.starts_with(kokino_artifacts::iecache::SIGNATURE) {
        use kokino_artifacts::iecache::{self, Location};
        let ix = iecache::parse(data)?;
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for r in &ix.records {
            let what = match iecache::location(&r.location) {
                Location::History { period: None, .. } => "history",
                Location::History { .. } => "daily or weekly history",
                Location::Host => "host summary",
                Location::Cookie { .. } => "cookie",
                Location::Download => "download",
                Location::Url(_) => "url",
                Location::Other => "other",
            };
            *counts.entry(format!("{} {}{}", r.kind.tag(), what, if r.listed { "" } else { " (not listed)" })).or_default() += 1;
        }
        let mut v = json!({"kind": "index.dat", "file": name, "version": ix.version, "cache_dirs": ix.dirs, "records": ix.records.len(), "deleted_records": ix.unlisted, "by_type": counts, "truncated": ix.truncated});
        if full {
            v["entries"] = json!(ix.records);
        }
        return Ok(v);
    }
    if data.starts_with(b"ElfFile\0") {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut events = vec![];
        let info = evtx::parse(data, &mut |e| {
            *counts.entry(format!("{} {}", e.channel, e.event_id)).or_default() += 1;
            if full {
                events.push(e);
            }
        })?;
        let mut top: Vec<(String, u64)> = counts.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        let mut v = json!({"kind": "evtx", "file": name, "log": info, "event_ids": top.iter().take(40).map(|(k, n)| json!([k, n])).collect::<Vec<_>>()});
        if full {
            v["events"] = json!(events);
        }
        return Ok(v);
    }
    if data.starts_with(b"regf") {
        let h = registry::Hive::parse(data.to_vec())?;
        let (mut keys, mut values, mut max_depth) = (0u64, 0u64, 0usize);
        let mut dump = vec![];
        h.root().walk(&mut |k, depth| {
            keys += 1;
            max_depth = max_depth.max(depth);
            let vs = k.values();
            values += vs.len() as u64;
            if full && dump.len() < 200_000 {
                dump.push(json!({"depth": depth, "key": k.name(), "last_written": k.last_written(), "values": vs.iter().map(|v| json!({"name": v.name, "type": v.kind, "text": v.string(), "size": v.data.len()})).collect::<Vec<_>>()}));
            }
        });
        let mut v = json!({"kind": "registry", "file": name, "root": h.root().name(), "dirty": h.dirty, "version": [h.version.0, h.version.1], "embedded_name": h.embedded_name, "keys": keys, "values": values, "max_depth": max_depth});
        let del = h.deleted();
        let text = |d: &registry::DeletedValue| json!({"key": d.key, "name": d.value.name, "type": d.value.kind, "text": d.value.string(), "size": d.value.data.len(), "data_reused": d.data_reused});
        v["deleted"] = json!({"keys": del.keys.len(), "values_of_live_keys": del.values.len(), "values_without_key": del.orphans.len(), "old_copies_of_live_keys": del.old_copies});
        if full {
            v["deleted_keys"] = json!(del.keys.iter().map(|k| json!({"path": k.path, "complete_path": k.complete_path, "last_written": kokino_core::time::filetime_to_iso(k.last_written), "subkeys": k.subkey_count, "values": k.values.iter().map(text).collect::<Vec<_>>()})).collect::<Vec<_>>());
            v["deleted_values"] = json!(del.values.iter().map(text).collect::<Vec<_>>());
            v["values_without_key"] = json!(del.orphans.iter().map(text).collect::<Vec<_>>());
        }
        if full {
            v["tree"] = json!(dump);
        }
        return Ok(v);
    }
    if lnk::is_lnk(data) {
        return Ok(json!({"kind": "lnk", "file": name, "lnk": lnk::parse(data)?}));
    }
    if data.starts_with(b"MAM") || data.get(4..8) == Some(b"SCCA") {
        let pf = prefetch::parse(data)?;
        let mut v = json!({"kind": "prefetch", "file": name, "prefetch": pf});
        if !full {
            v["prefetch"]["files"] = json!(pf.files.len());
        }
        return Ok(v);
    }
    let lower = name.to_ascii_lowercase();
    if lower.contains("destinations-ms") || kokino_artifacts::cfb::is_cfb(data) {
        return Ok(json!({"kind": "jumplist", "file": name, "jumplist": jumplist::parse(name, data)?}));
    }
    anyhow::bail!("not a supported artifact (registry hive, EVTX, Prefetch, LNK, Jump List)")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Windows XP Security log: logons, a log clearing, a process start,
    /// an account created, read like the EVTX events of later Windows.
    #[test]
    fn legacy_evt_events() {
        use kokino_artifacts::evt::tests::{header, record_bytes};
        let t = 1_160_000_000u32;
        let mut d = header(0x10000, 0);
        d.extend(record_bytes(1, t, 528, 8, "Security", "XP-LAB", &["bob", "XP-LAB", "(0x0,0x1)", "10", "User32", "Negotiate", "XP-LAB", "-", "XP-LAB$", "WORKGROUP", "-", "640", "-", "192.0.2.7", "1025"]));
        d.extend(record_bytes(2, t + 5, 528, 8, "Security", "XP-LAB", &["XP-LAB$", "WORKGROUP", "(0x0,0x2)", "5", "Advapi", "Negotiate", "XP-LAB"]));
        d.extend(record_bytes(3, t + 10, 592, 8, "Security", "XP-LAB", &["1234", "C:\\tools\\sdelete.exe", "640", "bob", "XP-LAB", "(0x0,0x1)"]));
        d.extend(record_bytes(4, t + 20, 624, 8, "Security", "XP-LAB", &["helpdesk", "XP-LAB", "S-1-5-21-1-2-3-1005", "bob", "XP-LAB", "(0x0,0x1)"]));
        d.extend(record_bytes(5, t + 30, 517, 8, "Security", "XP-LAB", &["SYSTEM", "NT AUTHORITY", "(0x0,0x3E7)", "bob", "XP-LAB", "(0x0,0x1)"]));
        d.extend(record_bytes(6, t + 40, 6005, 4, "EventLog", "XP-LAB", &[]));
        let f = crate::antiforensics::tests::row(50, "/WINDOWS/system32/config/SecEvent.Evt", false, 0, None);
        assert!(matches!(classify(&f.e.path), Some(Kind::Evt)));
        assert!(matches!(classify("/WINNT/system32/config/SysEvent.Evt"), Some(Kind::Evt)));
        assert!(matches!(classify("/Documents and Settings/bob/NTUSER.DAT"), Some(Kind::NtUser)));
        assert!(matches!(classify("/Documents and Settings/bob/Recent/plan.doc.lnk"), Some(Kind::Lnk)));
        assert_eq!(user_of("/Documents and Settings/bob/NTUSER.DAT"), "bob");
        let mut w = WindowsArtifacts::default();
        events(&mut w, &d, 7, &f, true);
        let s: Vec<(u32, &str, &str)> = w.events.iter().map(|e| (e.event_id, e.category.as_str(), e.summary.as_str())).collect();
        assert_eq!(s, [
            (528, "Logon", "XP-LAB\\bob logged on (remote desktop) from 192.0.2.7 (XP-LAB)"),
            (592, "Process", "bob ran C:\\tools\\sdelete.exe"),
            (624, "Account", "bob created account XP-LAB\\helpdesk"),
            (517, "Log cleared", "Security log cleared by bob"),
        ], "{:?}", w.events);
        assert_eq!(w.events[0].ip, "192.0.2.7");
        assert!(w.execution.iter().any(|x| x.source == "Event 592" && x.tool));
        assert_eq!((w.logs[0].channel.as_str(), w.logs[0].info.records), ("Security", 6));
        assert!(w.event_counts.iter().any(|c| c.0 == "Security" && c.1 == 6005));
    }

    #[test]
    fn helpers() {
        assert_eq!(rot13("P:\\Hfref"), "C:\\Users");
        assert!(unusual_path("C:\\Users\\Public\\updsvc.exe -k netsvc"));
        assert!(unusual_path("C:\\Users\\alice\\AppData\\Roaming\\x.exe"));
        assert!(!unusual_path("%SystemRoot%\\System32\\spoolsv.exe"));
        assert!(!unusual_path("\"C:\\Program Files\\App\\app.exe\""));
        assert!(!unusual_path("\"C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"));
        assert_eq!(strip_volume("\\VOLUME{01d4-5a6b}\\USERS\\ALICE\\X.EXE"), "\\USERS\\ALICE\\X.EXE");
        assert_eq!(classify("/Users/alice/NTUSER.DAT").map(kind_name), Some("NTUSER.DAT"));
        assert_eq!(classify("/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/x.temp").map(kind_name), Some("Jump List"));
        assert!(classify("/Users/alice/Documents/NTUSER.DAT").is_none());
        assert_eq!(yyyymmdd("20261019"), kokino_artifacts::bin::unix_to_filetime(1_792_368_000));
        assert_eq!(base_name("\\Device\\HarddiskVolume3\\Tools\\rclone.exe"), "rclone.exe");
        assert_eq!(base_name("!!rclone.exe!2026/10/20:09:00:00!1a2b!"), "rclone.exe");
    }
}
