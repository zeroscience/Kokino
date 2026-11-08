//! Anti-forensics indicators and the combined likelihood score.
//!
//! Every indicator is a transparent rule with a weight, a saturation constant
//! and a written caveat. The score is a triage aid: it says where to look,
//! never what happened. See docs/ANTI-FORENSICS.md for the method.

use crate::FileRow;
use crate::linux::LinuxArtifacts;
use crate::windows::WindowsArtifacts;
use kokino_artifacts::browser::WebActivity;
use kokino_core::time::is_whole_second;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Max records kept per indicator (the count is always exact).
const MAX_REFS: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub id: String,
    pub title: String,
    pub category: String,
    /// Stand-alone strength of one strong occurrence, 0..1.
    pub weight: f32,
    /// Saturation: how many occurrences reach ~63% of `weight`.
    pub k: f32,
    pub count: u64,
    /// weight * (1 - exp(-count / k))
    pub strength: f32,
    pub explanation: String,
    pub caveat: String,
    /// MFT record numbers that triggered this indicator.
    pub records: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Score {
    pub likelihood: f32,
    pub band: String,
    pub drivers: Vec<String>,
}

struct Rule {
    id: &'static str,
    title: &'static str,
    category: &'static str,
    weight: f32,
    k: f32,
    explanation: &'static str,
    caveat: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        id: "linux_antiforensic_command",
        title: "Shell history or sudo log shows evidence being destroyed",
        category: "Tool presence",
        weight: 0.6,
        k: 2.0,
        explanation: "A user's shell history, apt history or the sudo log contains commands that wipe files (shred, wipe, srm), clear or disable the shell history, remove log files, vacuum the journal, set file times by hand, change the system clock, open a reverse shell or load a kernel module.",
        caveat: "Administrators run some of these routinely (log rotation clean-up, touch in build scripts). Read the command and its context on the System page.",
    },
    Rule {
        id: "shell_history_cleared",
        title: "Shell history emptied or sent to /dev/null",
        category: "Log tampering",
        weight: 0.45,
        k: 1.0,
        explanation: "A user's .bash_history is empty or is a symbolic link to /dev/null, so the shell keeps no record of the commands typed.",
        caveat: "A new or rarely used account also has an empty history, and some hardened systems disable history on purpose.",
    },
    Rule {
        id: "linux_log_emptied",
        title: "Linux log file emptied",
        category: "Log tampering",
        weight: 0.5,
        k: 1.0,
        explanation: "wtmp is empty, or auth.log / secure is empty while older rotations still hold entries: the usual result of truncating a log to hide logons.",
        caveat: "Log rotation leaves a fresh, empty file until the next entry is written; check the file's modification time against the last rotation.",
    },
    Rule {
        id: "task_hidden_sd",
        title: "Scheduled task hidden from the Task Scheduler",
        category: "Persistence",
        weight: 0.7,
        k: 1.0,
        explanation: "The task's key under TaskCache\\Tree has no SD (security descriptor) value. Windows still runs the task, but schtasks, PowerShell and the Task Scheduler window no longer list it. Removing the value takes SYSTEM rights and has no legitimate use; the Tarrask malware (HAFNIUM, 2022) hid its persistence this way.",
        caveat: "A damaged or partly restored SOFTWARE hive can also lose values. Check the task's command, its task file and when the Tree key was last written.",
    },
    Rule {
        id: "registry_traces_deleted",
        title: "Registry keys that record user activity were deleted",
        category: "Trace removal",
        weight: 0.5,
        k: 2.0,
        explanation: "Whole keys that Windows uses to record what a user did (recent documents, the Run box, typed paths and addresses, files opened in dialogs, Explorer searches, UserAssist, ShellBags, mounted drives, Office recent files) were found deleted in a hive's free space. Windows trims these lists itself by dropping single entries; removing the key is what cleaners such as CCleaner and privacy tools do.",
        caveat: "Uninstalling a program removes its own keys, and Windows can rebuild some lists (ShellBags) after a profile repair. Check what the deleted key held, when it last changed, and whether a cleaner ran around that time.",
    },
    Rule {
        id: "ld_preload",
        title: "/etc/ld.so.preload loads a library into every program",
        category: "Persistence",
        weight: 0.6,
        k: 1.0,
        explanation: "Every program started on the system loads the libraries listed in /etc/ld.so.preload. User-mode rootkits (Azazel, Jynx, libprocesshider) use it to hide files, processes and network connections.",
        caveat: "A few legitimate tools (some security agents, memory allocators) use it too. Check the listed library's path, hashes and package ownership.",
    },
    Rule {
        id: "log_cleared_event",
        title: "Windows recorded that an event log was cleared",
        category: "Log tampering",
        weight: 0.6,
        k: 1.0,
        explanation: "Event 1102 (Security) or 104 (System) is written when someone clears an event log; it names the account and the time. Clearing logs destroys the record of logons, process starts and other activity.",
        caveat: "Administrators sometimes clear logs during maintenance or imaging. Check who cleared it and what else happened around that time.",
    },
    Rule {
        id: "tool_execution_record",
        title: "Execution records show an anti-forensic tool ran",
        category: "Tool presence",
        weight: 0.5,
        k: 1.0,
        explanation: "UserAssist, Amcache or process-creation events (4688) record that a known wiping, cleaning or timestamp-altering tool was started, independently of Prefetch.",
        caveat: "Amcache also lists programs that were only installed or scanned. Confirm with run counts and times on the System page.",
    },
    Rule {
        id: "browser_history_cleared",
        title: "Browser history cleared or its database deleted",
        category: "Log tampering",
        weight: 0.45,
        k: 1.0,
        explanation: "A browser history database holds no visits and no URLs, or the database file itself is deleted. Clearing history removes the record of what was browsed and when.",
        caveat: "A new, rarely used or 'clear history on exit' profile is also empty. Compare with the profile's other files (Cookies, Web Data, Favicons) and their timestamps.",
    },
    Rule {
        id: "antiforensic_web",
        title: "Anti-forensic tools downloaded or researched",
        category: "Tool presence",
        weight: 0.4,
        k: 2.0,
        explanation: "Browser history shows a download of a known wiping, cleaning or timestamp tool, or searches about wiping, shredding, permanently deleting files, clearing traces or hidden encrypted volumes.",
        caveat: "Researching a tool is not using it. Administrators and privacy-minded users search for these topics routinely; look for matching execution artifacts.",
    },
    Rule {
        id: "si_before_fn",
        title: "$SI creation earlier than $FN creation",
        category: "Timestamp manipulation",
        weight: 0.55,
        k: 3.0,
        explanation: "The $STANDARD_INFORMATION creation time is more than one second before the $FILE_NAME creation time. User-mode tools (SetFileTime, timestomp, PowerShell) can rewrite $SI but not $FN, so back-dated $SI is the classic timestomping signature.",
        caveat: "Installers, archive extractors and copy tools that preserve times can also set $SI creation in the past. Corroborate with $UsnJrnl, $LogFile and execution artifacts.",
    },
    Rule {
        id: "si_whole_second",
        title: "$SI creation on an exact second while $FN is not",
        category: "Timestamp manipulation",
        weight: 0.45,
        k: 5.0,
        explanation: "NTFS records time in 100ns ticks; naturally created files almost never land on .0000000. Many timestomping tools only accept whole seconds, leaving $SI exact while $FN keeps full precision.",
        caveat: "Files restored from FAT/ZIP (2-second resolution) or created by some sync tools also have whole-second times.",
    },
    Rule {
        id: "implausible_time",
        title: "Timestamps in the future or before NTFS existed",
        category: "Timestamp manipulation",
        weight: 0.35,
        k: 3.0,
        explanation: "A $SI timestamp lies after the analysis date or before 1993-01-01 (NTFS predates neither). On FAT and exFAT only future times count, since their dates start in 1980.",
        caveat: "A wrong system clock at the time of activity produces the same pattern.",
    },
    Rule {
        id: "wipe_tool",
        title: "Secure-deletion or anti-forensic tool present",
        category: "Tool presence",
        weight: 0.5,
        k: 1.5,
        explanation: "A file name matches a known wiping, cleaning or timestamp-altering tool (SDelete, CCleaner, BleachBit, Eraser, PrivaZer, timestomp, SetMACE, ...).",
        caveat: "Presence is not use. Check Prefetch, Amcache and UserAssist for execution.",
    },
    Rule {
        id: "wipe_tool_executed",
        title: "Prefetch shows an anti-forensic tool was executed",
        category: "Tool presence",
        weight: 0.75,
        k: 1.0,
        explanation: "A Prefetch file exists for a known wiping, cleaning or timestamp-altering tool, which means it was run on this system.",
        caveat: "The tool is matched by name. Its run count and last run times are on the System page (Program execution).",
    },
    Rule {
        id: "sdelete_rename",
        title: "Deleted entries with single-character repeated names",
        category: "Secure deletion",
        weight: 0.8,
        k: 2.0,
        explanation: "SDelete and similar tools rename a file repeatedly (AAAA.AAA, BBBB.BBB, ... ZZZZ.ZZZ) before deleting it to destroy the original name in the MFT.",
        caveat: "Rarely produced by anything else.",
    },
    Rule {
        id: "wiped_content",
        title: "Deleted file content is uniformly overwritten",
        category: "Secure deletion",
        weight: 0.35,
        k: 10.0,
        explanation: "Every sampled byte of a deleted file's former clusters has the same value (usually 0x00), consistent with overwriting before deletion.",
        caveat: "On SSDs, TRIM makes freed clusters read as zero without any user action. Check the media type before weighting this.",
    },
    Rule {
        id: "ext_mismatch",
        title: "File content contradicts its extension",
        category: "Data hiding",
        weight: 0.4,
        k: 3.0,
        explanation: "The file signature belongs to a different type than the extension claims, for example an executable named .jpg or an archive named .mp3.",
        caveat: "Some applications cache data under misleading names; review the list.",
    },
    Rule {
        id: "ads_payload",
        title: "Executable or archive hidden in an alternate data stream",
        category: "Data hiding",
        weight: 0.75,
        k: 1.0,
        explanation: "A named NTFS stream (ADS) contains an executable or a container format. ADS are invisible in Explorer and in a plain directory listing.",
        caveat: "A few security and backup products store binary data in ADS.",
    },
    Rule {
        id: "ads_unusual",
        title: "Unusual alternate data streams",
        category: "Data hiding",
        weight: 0.3,
        k: 5.0,
        explanation: "Named streams other than the well-known ones (Zone.Identifier, SmartScreen, Dropbox, macOS AFP_AfpInfo, ...).",
        caveat: "Many applications use ADS legitimately; review names and content.",
    },
    Rule {
        id: "encrypted_container",
        title: "Large high-entropy files without a known format",
        category: "Data hiding",
        weight: 0.4,
        k: 2.0,
        explanation: "Files of 1 MiB or more with near-maximum entropy (>= 7.97 bits/byte across samples) and no recognised signature, consistent with VeraCrypt/TrueCrypt containers or other encrypted blobs.",
        caveat: "Compressed or encrypted application data (game assets, backups) look the same.",
    },
    Rule {
        id: "usnjrnl_missing",
        title: "$UsnJrnl missing on a Windows system volume",
        category: "Log tampering",
        weight: 0.5,
        k: 1.0,
        explanation: "Windows enables the NTFS change journal on system volumes by default. Its absence suggests it was deleted (fsutil usn deletejournal).",
        caveat: "Some imaging or hardening workflows disable it; confirm with system configuration.",
    },
    Rule {
        id: "usn_wipe_rename",
        title: "Change journal shows files renamed to AAAA.AAA-style names",
        category: "Secure deletion",
        weight: 0.85,
        k: 2.0,
        explanation: "The NTFS change journal recorded files renamed to a single repeated letter (AAAA.AAA ... ZZZZ.ZZZ), the pattern SDelete and similar wipers leave when they destroy a file's name before deleting it. The journal keeps the original names and folders of those files.",
        caveat: "Rarely produced by anything else. Each count is one file.",
    },
    Rule {
        id: "usn_journal_recreated",
        title: "Change journal created long after the volume",
        category: "Log tampering",
        weight: 0.35,
        k: 1.0,
        explanation: "On a Windows system volume the change journal is created when Windows is installed. This journal's ID (its creation time) is much later than the volume, which happens when it is deleted (fsutil usn deletejournal) and Windows creates a new one: all earlier records are gone.",
        caveat: "Windows also recreates a damaged journal (for example after chkdsk), and some disk and backup tools reset it. Compare the creation time with the system's event logs.",
    },
    Rule {
        id: "evtx_cleared",
        title: "Security event log missing or reset",
        category: "Log tampering",
        weight: 0.55,
        k: 1.0,
        explanation: "Security.evtx is missing or no larger than a freshly initialised log (68 KiB), consistent with clearing (wevtutil cl, Clear-EventLog).",
        caveat: "A brand-new installation has a small log too. Parse EVTX for event 1102 to confirm.",
    },
    Rule {
        id: "prefetch_empty",
        title: "Prefetch folder present but empty",
        category: "Log tampering",
        weight: 0.3,
        k: 1.0,
        explanation: "C:\\Windows\\Prefetch exists but holds no .pf files, which suggests it was cleaned.",
        caveat: "Prefetch is disabled by default on Windows Server and on some SSD configurations.",
    },
];

const TOOLS: &[&str] = &[
    "sdelete", "sdelete64", "sdelete64a", "ccleaner", "ccleaner64", "bleachbit", "bleachbit_console", "eraser", "eraserl", "privazer",
    "timestomp", "setmace", "ntimestomp", "ntimestomp_v1.2_x64", "filetouch", "newfiletime", "hardwipe", "fileshredder", "file shredder",
    "wipefile", "killdisk", "dban", "secure-delete", "blancco", "evidence-eliminator", "evidencenuker", "wevtutil-clear",
];

pub fn benign_ads(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "zone.identifier" | "smartscreen" | "encryptable" | "favicon" | "afp_afpinfo" | "afp_resource" | "com.dropbox.attrs" | "com.dropbox.attributes"
            | "ms-properties" | "oecustomproperty" | "win32app_1" | "$config_digest" | "$bad" | "$j" | "$max" | "$sds" | "$sdh" | "$sii" | "$srat" | "$tops"
            | "$o" | "$q" | "$r" | "$taddr" | "$repair" | "$verify" | "$corrupt" | "$dsc" | "$wof" | "wofcompresseddata"
            | "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}" | "kernel.apppurgeablestorage" | "msdtcapp" | "summaryinformation" | "docsummaryinformation"
    ) || n.starts_with('\u{5}')
        || n.starts_with("com.apple.")
        || n.starts_with("{")
}

pub(crate) fn tool_name(file_name: &str) -> Option<&'static str> {
    let lower = file_name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    TOOLS.iter().copied().find(|t| stem == *t)
}

/// Downloads arrive as archives and versioned installers
/// (SDelete.zip, BleachBit-4.6.0-setup.exe), so match by prefix after
/// dropping the extension. Short names stay exact to avoid false hits.
pub fn downloaded_tool(file_name: &str) -> Option<&'static str> {
    let lower = file_name.to_ascii_lowercase();
    let stem = [".tar.gz", ".exe", ".zip", ".msi", ".7z", ".rar", ".dmg", ".tgz"].iter().find_map(|e| lower.strip_suffix(e)).unwrap_or(&lower);
    TOOLS.iter().copied().find(|t| stem == *t || (t.len() >= 5 && stem.starts_with(t)))
}

/// Prefetch names look like SDELETE64.EXE-1A2B3C4D.pf
fn prefetch_tool(file_name: &str) -> Option<&'static str> {
    let lower = file_name.to_ascii_lowercase();
    let exe = lower.strip_suffix(".pf")?.rsplit_once('-')?.0;
    tool_name(exe)
}

/// A name made of one repeated letter (AAAA.AAA), as SDelete leaves.
pub fn sdelete_like(name: &str) -> bool {
    let chars: Vec<char> = name.chars().filter(|c| *c != '.').collect();
    chars.len() >= 3 && chars.iter().all(|c| *c == chars[0] && c.is_ascii_alphabetic())
}

/// Runs every rule, tags matching files and returns indicators with count > 0.
/// `fat`: FAT/exFAT volume, whose dates start in 1980, so only future times
/// count as implausible there.
/// `any_epoch`: the file system is not NTFS, so only future times are implausible.
pub fn evaluate(files: &mut [FileRow], now: u64, web: &WebActivity, win: &WindowsArtifacts, linux: &LinuxArtifacts, any_epoch: bool) -> Vec<Indicator> {
    let mut hits: HashMap<&'static str, Vec<usize>> = HashMap::new();
    const SECOND: u64 = 10_000_000;
    const NTFS_EPOCH_1993: u64 = 124_604_352_000_000_000;
    let future = now + 86_400 * SECOND;
    let oldest = if any_epoch { 0 } else { NTFS_EPOCH_1993 };

    let by_path: HashMap<String, usize> = files.iter().enumerate().filter(|(_, f)| !f.e.deleted).map(|(i, f)| (f.e.path.to_ascii_lowercase(), i)).collect();
    let windows_volume = by_path.contains_key("/windows/system32");

    for (i, f) in files.iter().enumerate() {
        let e = &f.e;
        if let (Some(si), Some(fname)) = (e.si, e.fname) {
            if e.record >= 24 {
                if si.created + SECOND < fname.created {
                    hits.entry("si_before_fn").or_default().push(i);
                }
                if is_whole_second(si.created) && !is_whole_second(fname.created) && fname.created != 0 {
                    hits.entry("si_whole_second").or_default().push(i);
                }
            }
        }
        if let Some(si) = e.si {
            let ts = [si.created, si.modified, si.accessed, si.mft_modified];
            if ts.iter().any(|t| *t != 0 && (*t > future || *t < oldest)) {
                hits.entry("implausible_time").or_default().push(i);
            }
        }
        if !e.is_dir && tool_name(&e.name).is_some() {
            hits.entry("wipe_tool").or_default().push(i);
        }
        if !e.is_dir && f.ext == "pf" && prefetch_tool(&e.name).is_some() {
            hits.entry("wipe_tool_executed").or_default().push(i);
        }
        if e.deleted && sdelete_like(&e.name) {
            hits.entry("sdelete_rename").or_default().push(i);
        }
        if e.deleted && !e.resident && f.uniform.is_some() {
            hits.entry("wiped_content").or_default().push(i);
        }
        if f.mismatch {
            hits.entry("ext_mismatch").or_default().push(i);
        }
        if let Some(sig) = &f.ads_sig {
            let payload = matches!(sig.as_str(), "pe" | "elf" | "macho64" | "zip" | "rar" | "7z" | "cab" | "dex" | "class");
            hits.entry(if payload { "ads_payload" } else { "ads_unusual" }).or_default().push(i);
        } else if e.ads().any(|s| !benign_ads(&s.name)) && !e.path.starts_with("/$") {
            hits.entry("ads_unusual").or_default().push(i);
        }
        if !e.deleted && e.size >= 1024 * 1024 && f.sig.is_none() && f.entropy.unwrap_or(0.0) >= 7.97 {
            hits.entry("encrypted_container").or_default().push(i);
        }
    }

    if windows_volume {
        let usn = by_path.get("/$extend/$usnjrnl").map(|i| files[*i].e.streams.iter().any(|s| s.name == "$J")).unwrap_or(false);
        if !usn {
            hits.entry("usnjrnl_missing").or_default().push(by_path.get("/$extend").copied().unwrap_or(0));
        }
        if let (Some(j), Some(mft)) = (&win.journal, files.iter().find(|f| f.e.record == 0 && f.e.name == "$MFT").and_then(|f| f.e.si)) {
            const DAY: u64 = 86_400 * SECOND;
            if j.created > 0 && mft.created > 0 && j.created > mft.created + 2 * DAY {
                hits.entry("usn_journal_recreated").or_default().push(j.file as usize);
            }
        }
        match by_path.get("/windows/system32/winevt/logs/security.evtx") {
            None => {
                if let Some(i) = by_path.get("/windows/system32/winevt/logs") {
                    hits.entry("evtx_cleared").or_default().push(*i);
                }
            }
            Some(i) if files[*i].e.size <= 69_632 => hits.entry("evtx_cleared").or_default().push(*i),
            _ => {}
        }
        if let Some(pi) = by_path.get("/windows/prefetch") {
            let pf = files.iter().filter(|f| !f.e.deleted && f.e.path.to_ascii_lowercase().starts_with("/windows/prefetch/") && f.ext == "pf").count();
            if pf == 0 {
                hits.entry("prefetch_empty").or_default().push(*pi);
            }
        }
    }
    for t in win.tasks.iter().filter(|t| t.sd_removed) {
        // The task file when there is one, else the SOFTWARE hive.
        let at = t.file.map(|f| f as usize).or_else(|| by_path.get("/windows/system32/config/software").copied());
        if let Some(i) = at {
            hits.entry("task_hidden_sd").or_default().push(i);
        }
    }
    // Whole user-activity keys deleted; one hit per key, on its hive file.
    for k in win.reg_deleted_keys.iter().filter(|k| crate::windows::user_activity_trace(&k.notable)) {
        hits.entry("registry_traces_deleted").or_default().push(k.file as usize);
    }
    if let Some(j) = &win.journal {
        let mut wiped: Vec<u64> = j.changes.iter().filter(|c| c.c.reasons & kokino_artifacts::usn::RENAME_NEW_NAME != 0 && sdelete_like(&c.c.name)).map(|c| c.c.record).collect();
        wiped.sort();
        wiped.dedup();
        for _ in wiped {
            hits.entry("usn_wipe_rename").or_default().push(j.file as usize);
        }
    }

    let by_record: HashMap<u64, usize> = files.iter().enumerate().map(|(i, f)| (f.e.record, i)).collect();
    for (si, s) in web.sources.iter().enumerate() {
        let Some(&i) = by_record.get(&s.record) else { continue };
        // Internet Explorer: only the main history file counts. Cache and
        // download lists hold no visits, and Windows deletes daily and weekly
        // files itself as they age.
        let ie = s.engine == Some(kokino_artifacts::browser::Engine::Ie);
        let history = !ie || s.profile == "History" || s.profile == "History (protected mode)";
        if history && (s.deleted || (s.error.is_none() && s.visits == 0 && s.urls == 0)) {
            hits.entry("browser_history_cleared").or_default().push(i);
        }
        let si = si as u32;
        let downloads = web.downloads.iter().filter(|d| d.src == si && downloaded_tool(d.target.rsplit(['\\', '/']).next().unwrap_or("")).is_some()).count();
        let searches = web.searches.iter().filter(|q| q.src == si && antiforensic_query(&q.term)).count();
        for _ in 0..downloads + searches {
            hits.entry("antiforensic_web").or_default().push(i);
        }
    }

    // Windows' own records: a log clearing event names who and when, which is
    // stronger than a small Security.evtx alone.
    for e in win.events.iter().filter(|e| e.category == "Log cleared") {
        hits.entry("log_cleared_event").or_default().push(e.file as usize);
    }
    for x in win.execution.iter().filter(|x| x.tool && !matches!(x.source.as_str(), "Prefetch" | "ShimCache")) {
        if let Some(f) = x.file {
            hits.entry("tool_execution_record").or_default().push(f as usize);
        }
    }

    for (id, file) in &linux.hits {
        if let Some(rule) = RULES.iter().find(|r| r.id == id) {
            if (*file as usize) < files.len() {
                hits.entry(rule.id).or_default().push(*file as usize);
            }
        }
    }

    let mut out = vec![];
    for rule in RULES {
        let Some(idx) = hits.get(rule.id) else { continue };
        for &i in idx {
            if !files[i].flags.iter().any(|f| f == rule.id) {
                files[i].flags.push(rule.id.to_string());
            }
        }
        let count = idx.len() as u64;
        out.push(Indicator {
            id: rule.id.into(),
            title: rule.title.into(),
            category: rule.category.into(),
            weight: rule.weight,
            k: rule.k,
            count,
            strength: strength(rule.weight, rule.k, count),
            explanation: rule.explanation.into(),
            caveat: rule.caveat.into(),
            records: {
                let mut r: Vec<u64> = idx.iter().map(|i| files[*i].e.record).collect();
                r.dedup();
                r.truncate(MAX_REFS);
                r
            },
        });
    }
    out.sort_by(|a, b| b.strength.partial_cmp(&a.strength).unwrap());
    out
}

/// Search terms about destroying or hiding evidence.
pub fn antiforensic_query(term: &str) -> bool {
    let t = term.to_ascii_lowercase();
    const PHRASES: &[&str] = &[
        "wipe", "shred", "secure erase", "secure delete", "permanently delete", "delete permanently", "erase hard drive", "erase disk",
        "anti forensic", "anti-forensic", "antiforensic", "timestomp", "clear event log", "delete event log", "clear browser history",
        "delete browser history", "remove traces", "cover tracks", "hidden volume", "sdelete", "bleachbit", "ccleaner", "eraser",
        "how to delete history", "clear ie history", "clear internet history", "delete internet history", "recover deleted", "undeletable",
    ];
    PHRASES.iter().any(|p| t.contains(p))
}

pub fn strength(weight: f32, k: f32, count: u64) -> f32 {
    weight * (1.0 - (-(count as f32) / k).exp())
}

/// Noisy-OR over indicator strengths.
pub fn score(indicators: &[Indicator]) -> Score {
    let not = indicators.iter().fold(1.0f32, |acc, i| acc * (1.0 - i.strength));
    let likelihood = ((1.0 - not) * 1000.0).round() / 1000.0;
    let band = match likelihood {
        l if l < 0.15 => "Low",
        l if l < 0.4 => "Moderate",
        l if l < 0.7 => "High",
        _ => "Very high",
    };
    Score {
        likelihood,
        band: band.into(),
        drivers: indicators.iter().filter(|i| i.strength >= 0.1).take(3).map(|i| i.title.clone()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert!(sdelete_like("ZZZZZZZZ.ZZZ"));
        assert!(!sdelete_like("report.doc"));
        assert_eq!(prefetch_tool("SDELETE64.EXE-1A2B3C4D.pf"), Some("sdelete64"));
        assert_eq!(tool_name("CCleaner64.exe"), Some("ccleaner64"));
        assert!(benign_ads("Zone.Identifier"));
        assert!(!benign_ads("hidden.exe"));
        assert!(antiforensic_query("How to PERMANENTLY delete files"));
        assert!(antiforensic_query("veracrypt hidden volume"));
        assert!(!antiforensic_query("quarterly results"));
        assert_eq!(downloaded_tool("SDelete.zip"), Some("sdelete"));
        assert_eq!(downloaded_tool("BleachBit-4.6.0-setup.exe"), Some("bleachbit"));
        assert_eq!(downloaded_tool("dbanner.png"), None);
        assert_eq!(downloaded_tool("report.zip"), None);
        let s = strength(0.5, 1.0, 100);
        assert!((s - 0.5).abs() < 1e-3);
        assert_eq!(strength(0.5, 1.0, 0), 0.0);
    }

    fn row(record: u64, path: &str, is_dir: bool, created: u64, stream: Option<&str>) -> FileRow {
        let e = kokino_ntfs::FsEntry {
            record,
            seq: 1,
            parent: 5,
            parent_seq: 5,
            name: path.rsplit('/').next().unwrap_or("").into(),
            dos_name: None,
            path: path.into(),
            is_dir,
            deleted: false,
            orphan: false,
            size: 0,
            alloc_size: 0,
            resident: true,
            attributes: 0,
            hard_links: 1,
            usn: None,
            si: Some(kokino_ntfs::Times { created, modified: created, accessed: created, mft_modified: created }),
            fname: None,
            streams: stream.map(|n| vec![kokino_ntfs::Stream { name: n.into(), size: 1 << 20, resident: false, first_offset: None }]).unwrap_or_default(),
            has_reparse: false,
            record_offset: 0,
            error: None,
            unix: None,
            name_only: None,
        };
        FileRow { e, ext: String::new(), sig: None, sig_label: None, category: None, mismatch: false, entropy: None, uniform: None, ads_sig: None, flags: vec![] }
    }

    /// The change journal rules (the SDelete pattern is planted in
    /// disk-win.img; a recreated journal is built here).
    #[test]
    fn journal_rules() {
        const DAY: u64 = 864_000_000_000;
        let installed = 133_800_000_000_000_000;
        let mut files = vec![row(0, "/$MFT", false, installed, None), row(30, "/Windows/System32", true, installed, None), row(40, "/$Extend/$UsnJrnl", false, installed, Some("$J"))];
        let mut win = WindowsArtifacts::default();
        let mut j = crate::windows::Journal { file: 2, created: installed + DAY / 24, ..Default::default() };
        win.journal = Some(j.clone());
        let none = evaluate(&mut files, installed + 400 * DAY, &WebActivity::default(), &win, &LinuxArtifacts::default(), false);
        assert!(!none.iter().any(|i| i.id.starts_with("usn")), "{:?}", none);
        j.created = installed + 300 * DAY;
        for n in ["AAAA.AAA", "BBBB.BBB"] {
            let mut c = crate::windows::JournalChange::default();
            c.c.record = 77;
            c.c.name = n.into();
            c.c.reasons = kokino_artifacts::usn::RENAME_NEW_NAME;
            j.changes.push(c);
        }
        win.journal = Some(j);
        let hit = evaluate(&mut files, installed + 400 * DAY, &WebActivity::default(), &win, &LinuxArtifacts::default(), false);
        let ids: Vec<(&str, u64)> = hit.iter().map(|i| (i.id.as_str(), i.count)).collect();
        assert!(ids.contains(&("usn_journal_recreated", 1)) && ids.contains(&("usn_wipe_rename", 1)), "{:?}", ids);
        assert!(files[2].flags.iter().any(|f| f == "usn_journal_recreated"));
    }

    #[test]
    fn hidden_task_rule() {
        let mut files = vec![row(0, "/$MFT", false, 0, None), row(40, "/Windows/System32/config/SOFTWARE", false, 0, None)];
        let mut win = WindowsArtifacts::default();
        win.tasks.push(crate::windows::ScheduledTask { path: "\\Sync".into(), sd_removed: false, ..Default::default() });
        let none = evaluate(&mut files, 0, &WebActivity::default(), &win, &LinuxArtifacts::default(), false);
        assert!(!none.iter().any(|i| i.id == "task_hidden_sd"));
        win.tasks[0].sd_removed = true;
        let hit = evaluate(&mut files, 0, &WebActivity::default(), &win, &LinuxArtifacts::default(), false);
        assert!(hit.iter().any(|i| i.id == "task_hidden_sd" && i.count == 1), "{:?}", hit.iter().map(|i| &i.id).collect::<Vec<_>>());
        assert!(files[1].flags.iter().any(|f| f == "task_hidden_sd"));
    }

    #[test]
    fn deleted_trace_keys_rule() {
        let mut files = vec![row(0, "/$MFT", false, 0, None), row(41, "/Users/alice/NTUSER.DAT", false, 0, None)];
        let mut win = WindowsArtifacts::default();
        // An autostart entry removed by an uninstaller does not count.
        win.reg_deleted_keys.push(crate::windows::RegDeletedKey { file: 1, notable: "autostart (Run)".into(), ..Default::default() });
        let none = evaluate(&mut files, 0, &WebActivity::default(), &win, &LinuxArtifacts::default(), false);
        assert!(!none.iter().any(|i| i.id == "registry_traces_deleted"));
        win.reg_deleted_keys.push(crate::windows::RegDeletedKey { file: 1, notable: "Run box history".into(), ..Default::default() });
        let hit = evaluate(&mut files, 0, &WebActivity::default(), &win, &LinuxArtifacts::default(), false);
        assert!(hit.iter().any(|i| i.id == "registry_traces_deleted" && i.count == 1));
        assert!(files[1].flags.iter().any(|f| f == "registry_traces_deleted"));
    }
}
