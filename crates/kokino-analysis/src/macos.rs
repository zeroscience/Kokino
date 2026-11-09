//! macOS system artifacts, added to the Unix summary (`linux`):
//!
//! - the system: SystemVersion.plist (version and build), the computer's
//!   names (SystemConfiguration preferences.plist), when the Mac was set up
//!   (.AppleSetupDone);
//! - local accounts (dslocal user records: name, uid, real name, home,
//!   shell; admins from the admin group);
//! - persistence: launchd agents and daemons outside /System, with the
//!   program they run;
//! - downloads from the quarantine database (QuarantineEventsV2: when, by
//!   which program, from where);
//! - application use from KnowledgeC (which app was in front, when, how
//!   long).
//!
//! Shell histories, SSH keys, /etc files and the time zone are read by the
//! Unix code itself (/Users homes, /private/etc). Apple's times are seconds
//! since 2001-01-01.

use crate::linux::{LinuxArtifacts, LinuxEvent, LinuxUser, Persistence};
use crate::windows::Source;
use crate::FileRow;
use kokino_artifacts::plist::{self, mac_time};
use std::io::{Read, Seek};

const MAX_DB: u64 = 512 << 20;
const MAX_PLIST: u64 = 16 << 20;
const MAX_EVENTS: usize = 200_000;

/// Whether these files hold a macOS system (or a Mac user's data).
pub fn is_mac(files: &[FileRow]) -> bool {
    files.iter().any(|f| {
        let p = f.e.path.as_str();
        p == "/System/Library/CoreServices/SystemVersion.plist" || p.starts_with("/private/var/db/dslocal/") || (p.starts_with("/Users/") && p.contains("/Library/Preferences/"))
    })
}

fn read<R: Read + Seek>(fs: &crate::fs::Fs, r: &mut R, f: &FileRow, cap: u64) -> anyhow::Result<Vec<u8>> {
    if f.e.size > cap {
        anyhow::bail!("{} bytes; larger than the {} byte limit", f.e.size, cap);
    }
    fs.read(r, &f.e, "", 0, f.e.size as usize)
}

/// The user whose home a path is in ("/Users/alice/..." gives alice).
fn owner(path: &str) -> String {
    path.strip_prefix("/Users/").and_then(|r| r.split('/').next()).unwrap_or("").to_string()
}

pub fn collect<R: Read + Seek>(fs: &crate::fs::Fs, r: &mut R, files: &[FileRow], a: &mut LinuxArtifacts) {
    let live = |p: &str| files.iter().position(|f| !f.e.deleted && !f.e.is_dir && f.e.path == p);
    let src = |a: &mut LinuxArtifacts, i: usize, kind: &str, err: Option<String>| {
        a.sources.push(Source { file: i as u32, path: files[i].e.path.clone(), kind: kind.into(), deleted: files[i].e.deleted, error: err, note: None });
    };
    a.computer.os_id = "macos".into();
    // The zone note about classic syslog lines does not apply to a Mac.
    if let Some(i) = a.computer.time_zone.find(" (zone data not found") {
        a.computer.time_zone.truncate(i);
    }

    // The system.
    if let Some(i) = live("/System/Library/CoreServices/SystemVersion.plist") {
        match read(fs, r, &files[i], MAX_PLIST).ok().and_then(|d| plist::parse(&d)) {
            Some(v) => {
                let g = |k: &str| v.get(k).and_then(|x| x.str()).unwrap_or("").to_string();
                a.computer.version = g("ProductVersion");
                a.computer.os = format!("{} {}{}", if g("ProductName").is_empty() { "macOS".into() } else { g("ProductName") }, g("ProductVersion"), if g("ProductBuildVersion").is_empty() { String::new() } else { format!(" ({})", g("ProductBuildVersion")) });
                src(a, i, "macOS version", None);
            }
            None => src(a, i, "macOS version", Some("not a property list".into())),
        }
    }
    if let Some(i) = live("/Library/Preferences/SystemConfiguration/preferences.plist") {
        if let Some(v) = read(fs, r, &files[i], MAX_PLIST).ok().and_then(|d| plist::parse(&d)) {
            let name = ["System/System/ComputerName", "System/System/HostName", "System/Network/HostNames/LocalHostName"].iter().find_map(|k| v.path(k).and_then(|x| x.str()).filter(|s| !s.is_empty())).unwrap_or("");
            if !name.is_empty() {
                a.computer.hostname = name.to_string();
            }
            src(a, i, "computer name", None);
        }
    }
    if let Some(i) = files.iter().position(|f| f.e.path == "/private/var/db/.AppleSetupDone") {
        // Written when Setup Assistant finished: the Mac's setup.
        a.computer.fs_created = files[i].e.si.map(|t| t.modified).unwrap_or(0);
        src(a, i, "setup done", None);
    }

    // Accounts.
    let admins: Vec<String> = live("/private/var/db/dslocal/nodes/Default/groups/admin.plist")
        .and_then(|i| read(fs, r, &files[i], MAX_PLIST).ok())
        .and_then(|d| plist::parse(&d))
        .map(|v| v.get("users").map(|u| u.array().iter().filter_map(|x| x.str().map(String::from)).collect()).unwrap_or_default())
        .unwrap_or_default();
    for (i, f) in files.iter().enumerate().filter(|(_, f)| !f.e.is_dir && f.e.path.starts_with("/private/var/db/dslocal/nodes/Default/users/") && f.e.name.ends_with(".plist")) {
        let Some(v) = read(fs, r, f, MAX_PLIST).ok().and_then(|d| plist::parse(&d)) else { continue };
        let g = |k: &str| v.get(k).and_then(|x| x.str()).unwrap_or("").to_string();
        let name = g("name");
        // Apple's own service accounts start with "_".
        if name.is_empty() || name.starts_with('_') && name != "_mbsetupuser" {
            continue;
        }
        let shell = g("shell");
        let login_shell = !shell.is_empty() && !shell.ends_with("/false") && !shell.ends_with("/nologin");
        let uid = v.get("uid").and_then(|x| x.int()).unwrap_or(-1) as u32;
        // /private/etc/passwd lists root too: one entry per account.
        if let Some(u) = a.users.iter_mut().find(|u| u.name == name) {
            u.admin |= admins.contains(&name);
            if u.gecos.is_empty() {
                u.gecos = g("realname");
            }
            src(a, i, "account", None);
            continue;
        }
        a.users.push(LinuxUser {
            name: name.clone(),
            uid,
            gid: v.get("gid").and_then(|x| x.int()).unwrap_or(0) as u32,
            gecos: g("realname"),
            home: g("home"),
            shell,
            login_shell,
            password: if v.get("ShadowHashData").is_some() { "set".into() } else { "none".into() },
            admin: admins.contains(&name),
            note: if uid == 0 && name != "root" { "uid 0: a second root account".into() } else { String::new() },
            ..Default::default()
        });
        src(a, i, "account", None);
    }

    // Persistence: launchd jobs outside /System (Apple's own).
    for (i, f) in files.iter().enumerate().filter(|(_, f)| !f.e.is_dir && f.e.name.ends_with(".plist")) {
        let p = f.e.path.as_str();
        let dir = p.rsplit_once('/').map(|x| x.0).unwrap_or("");
        let kind = match dir {
            "/Library/LaunchDaemons" => "launchd daemon",
            "/Library/LaunchAgents" => "launchd agent",
            d if d.starts_with("/Users/") && d.ends_with("/Library/LaunchAgents") => "launchd agent (user)",
            _ => continue,
        };
        let v = read(fs, r, f, MAX_PLIST).ok().and_then(|d| plist::parse(&d));
        let (label, command, at_load) = match &v {
            Some(v) => {
                let args: Vec<String> = v.get("ProgramArguments").map(|x| x.array().iter().filter_map(|a| a.str().map(String::from)).collect()).unwrap_or_default();
                let program = v.get("Program").and_then(|x| x.str()).map(String::from).unwrap_or_else(|| args.first().cloned().unwrap_or_default());
                let cmd = if args.len() > 1 { args.join(" ") } else { program };
                (v.get("Label").and_then(|x| x.str()).unwrap_or("").to_string(), cmd, v.get("RunAtLoad").and_then(|x| x.bool()).unwrap_or(false) || v.get("KeepAlive").is_some())
            }
            None => (String::new(), String::new(), false),
        };
        let lower = command.to_ascii_lowercase();
        let first = lower.split_whitespace().next().unwrap_or("").to_string();
        let reason = if first.starts_with("/tmp/") || first.starts_with("/private/tmp/") || first.starts_with("/var/tmp/") || first.starts_with("/users/shared/") {
            "runs a program from a temporary or shared folder"
        } else if first.split('/').any(|c| c.starts_with('.') && c.len() > 1) {
            "runs a program from a hidden folder"
        } else if matches!(first.rsplit('/').next(), Some("bash" | "sh" | "zsh" | "python" | "python3" | "osascript" | "curl")) && (lower.contains(" -c ") || lower.contains("http")) {
            "runs a script or a download through a shell or interpreter"
        } else if v.is_none() {
            "not a readable property list"
        } else {
            ""
        };
        a.persistence.push(Persistence {
            kind: kind.into(),
            location: p.to_string(),
            name: if label.is_empty() { f.e.name.clone() } else { label },
            command: format!("{}{}", command, if at_load { " (at load)" } else { "" }),
            user: owner(p),
            written: f.e.si.map(|t| t.modified).unwrap_or(0),
            unusual: !reason.is_empty(),
            reason: reason.into(),
            file: i as u32,
            deleted: f.e.deleted,
        });
    }

    // Downloads: the quarantine database of each user.
    for (i, f) in files.iter().enumerate().filter(|(_, f)| !f.e.is_dir && f.e.name == "com.apple.LaunchServices.QuarantineEventsV2" && f.e.path.contains("/Library/Preferences/")) {
        let user = owner(&f.e.path);
        let res = read(fs, r, f, MAX_DB).and_then(|d| {
            kokino_artifacts::sqlite::with_db(&d, None, &["LSQuarantineEvent"], |c| {
                let mut st = c.prepare("SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderName, LSQuarantineSenderAddress FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp")?;
                let rows = st.query_map([], |x| {
                    Ok((x.get::<_, Option<f64>>(0)?, x.get::<_, Option<String>>(1)?, x.get::<_, Option<String>>(2)?, x.get::<_, Option<String>>(3)?, x.get::<_, Option<String>>(4)?, x.get::<_, Option<String>>(5)?, x.get::<_, Option<String>>(6)?))
                })?;
                Ok(rows.flatten().take(MAX_EVENTS).collect::<Vec<_>>())
            })
        });
        match res {
            Ok(rows) => {
                for (t, agent, bundle, url, origin, sender, addr) in rows {
                    let agent = agent.or(bundle).unwrap_or_default();
                    let url = url.unwrap_or_default();
                    a.events.push(LinuxEvent {
                        time: t.map(mac_time).unwrap_or(0),
                        category: "Download".into(),
                        summary: format!("{} downloaded {}{}", if agent.is_empty() { "a program" } else { &agent }, if url.is_empty() { "a file" } else { &url }, origin.filter(|o| !o.is_empty() && *o != url).map(|o| format!(" (from {})", o)).unwrap_or_default()),
                        program: agent,
                        user: user.clone(),
                        message: [sender, addr].into_iter().flatten().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" "),
                        source: "quarantine events".into(),
                        file: i as u32,
                        ..Default::default()
                    });
                }
                src(a, i, "quarantine events", None);
            }
            Err(e) => src(a, i, "quarantine events", Some(format!("{:#}", e))),
        }
    }

    // Application use: KnowledgeC.
    for (i, f) in files.iter().enumerate().filter(|(_, f)| !f.e.is_dir && f.e.name == "knowledgeC.db") {
        let user = owner(&f.e.path);
        let wal = files.iter().find(|w| w.e.path == format!("{}-wal", f.e.path) && !w.e.deleted).and_then(|w| read(fs, r, w, MAX_DB).ok());
        let res = read(fs, r, f, MAX_DB).and_then(|d| {
            kokino_artifacts::sqlite::with_db(&d, wal.as_deref(), &["ZOBJECT"], |c| {
                let mut st = c.prepare("SELECT ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE FROM ZOBJECT WHERE ZSTREAMNAME IN ('/app/inFocus', '/app/usage', '/app/webUsage') ORDER BY ZSTARTDATE")?;
                let rows = st.query_map([], |x| Ok((x.get::<_, Option<String>>(0)?, x.get::<_, Option<String>>(1)?, x.get::<_, Option<f64>>(2)?, x.get::<_, Option<f64>>(3)?)))?;
                Ok(rows.flatten().take(MAX_EVENTS).collect::<Vec<_>>())
            })
        });
        match res {
            Ok(rows) => {
                for (stream, app, start, end) in rows {
                    let app = app.unwrap_or_default();
                    let secs = match (start, end) {
                        (Some(s), Some(e)) if e >= s => (e - s) as u64,
                        _ => 0,
                    };
                    let stream = stream.unwrap_or_default();
                    a.events.push(LinuxEvent {
                        time: start.map(mac_time).unwrap_or(0),
                        category: "App use".into(),
                        summary: format!("{} {} for {}", app, if stream == "/app/inFocus" { "in front" } else { "used" }, human_secs(secs)),
                        program: app,
                        user: user.clone(),
                        message: stream,
                        source: "KnowledgeC".into(),
                        file: i as u32,
                        ..Default::default()
                    });
                    if a.events.len() > MAX_EVENTS {
                        break;
                    }
                }
                src(a, i, "KnowledgeC", None);
            }
            Err(e) => src(a, i, "KnowledgeC", Some(format!("{:#}", e))),
        }
    }
}

fn human_secs(s: u64) -> String {
    if s >= 3600 {
        format!("{} h {} min", s / 3600, s % 3600 / 60)
    } else if s >= 60 {
        format!("{} min {} s", s / 60, s % 60)
    } else {
        format!("{} s", s)
    }
}

/// Plain-language lines for the summary.
pub fn impact(a: &LinuxArtifacts) -> Vec<String> {
    let mut out = vec![];
    let dl = a.events.iter().filter(|e| e.category == "Download").count();
    if dl > 0 {
        let agents: std::collections::BTreeSet<&str> = a.events.iter().filter(|e| e.category == "Download").map(|e| e.program.as_str()).filter(|s| !s.is_empty()).collect();
        out.push(format!("{} download(s) recorded in quarantine events{}.", dl, if agents.is_empty() { String::new() } else { format!(" (by {})", agents.into_iter().collect::<Vec<_>>().join(", ")) }));
    }
    let use_ = a.events.iter().filter(|e| e.category == "App use").count();
    if use_ > 0 {
        let apps: std::collections::BTreeSet<&str> = a.events.iter().filter(|e| e.category == "App use").map(|e| e.program.as_str()).collect();
        out.push(format!("{} application use record(s) in KnowledgeC, {} application(s).", use_, apps.len()));
    }
    out
}
