#![forbid(unsafe_code)]
use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kokino", version, about = "Kokino Forensic Toolkit by Zero Science Lab")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the browser GUI (127.0.0.1 unless --listen is given)
    Serve {
        /// Directory that holds cases (default: ~/KokinoCases)
        #[arg(long)]
        cases: Option<PathBuf>,
        /// Port (0 picks a free one)
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Address to listen on. Anything other than loopback serves HTTPS only,
        /// e.g. 0.0.0.0 for every interface
        #[arg(long, default_value = "127.0.0.1")]
        listen: std::net::IpAddr,
        /// DNS name examiners use to reach this server (repeatable); added to
        /// the self-signed certificate and to the accepted Host headers
        #[arg(long = "hostname")]
        hostnames: Vec<String>,
        /// TLS certificate (PEM). Without it LAN mode uses a self-signed one
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// TLS private key (PEM)
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// Serve HTTPS even on loopback
        #[arg(long)]
        tls: bool,
        /// Do not open a browser window
        #[arg(long)]
        no_browser: bool,
    },
    /// Manage examiner accounts (works while the server runs; use it to
    /// recover from a lost admin password)
    User {
        /// Directory that holds cases (default: ~/KokinoCases)
        #[arg(long, global = true)]
        cases: Option<PathBuf>,
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Remove everything Kokino stored on this machine: every case (analysis,
    /// bookmarks, reports, audit logs), accounts, the system audit log, hash
    /// sets, the TLS key and deleted cases. Evidence image files are never
    /// touched. Asks you to type DELETE ALL; stop the server first.
    Purge {
        /// Directory that holds cases (default: ~/KokinoCases)
        #[arg(long)]
        cases: Option<PathBuf>,
        /// Skip the prompt (for scripts): must be exactly "DELETE ALL"
        #[arg(long)]
        confirm: Option<String>,
    },
    /// Manage hash sets: known-good lists (e.g. NIST NSRL) to hide, known-bad
    /// lists to flag. Shared by every case; works while the server runs
    Hashset {
        /// Directory that holds cases (default: ~/KokinoCases)
        #[arg(long, global = true)]
        cases: Option<PathBuf>,
        #[command(subcommand)]
        cmd: HashsetCmd,
    },
    /// Analyze an image headless and print the summary (same engine as the GUI)
    Analyze {
        image: PathBuf,
        /// Write the full analysis as JSON
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// Compute MD5, SHA-1 and SHA-256 of an image's logical stream
    Hash { image: PathBuf },
    /// Carve files from unallocated space and unpartitioned areas, and list
    /// each with its image offset, length and hashes
    Carve {
        image: PathBuf,
        /// One JSON object per line instead of tab-separated text
        #[arg(long)]
        json: bool,
    },
    /// List every file with content (live and deleted) with its MD5, SHA-1
    /// and SHA-256, read from the image
    Files {
        image: PathBuf,
        /// One JSON object per line instead of tab-separated text
        #[arg(long)]
        json: bool,
        /// Also write each file's content to DIR/fs<n>/<record>-<name>
        #[arg(long, value_name = "DIR")]
        extract: Option<PathBuf>,
    },
    /// Verify the hash chain of a case's audit log
    VerifyAudit { case_dir: PathBuf },
    /// Print the version; with --check, ask GitHub whether a newer release exists (the only command that uses the network, and only when asked)
    Version {
        #[arg(long)]
        check: bool,
    },
    /// Write the case report (bookmarks as exhibits, evidence, chain of
    /// custody, methods, limitations) as HTML and Word into the case's
    /// exports folder, and record both files' SHA-256 in its audit log
    Report {
        case_dir: PathBuf,
        /// Report title (default: Forensic examination report)
        #[arg(long)]
        title: Option<String>,
        /// Your reference or lab number
        #[arg(long)]
        reference: Option<String>,
        /// Who asked for the examination
        #[arg(long)]
        requested_by: Option<String>,
        /// Text file with the summary of findings
        #[arg(long)]
        summary: Option<PathBuf>,
        /// Only bookmarks with this tag
        #[arg(long)]
        tag: Option<String>,
        /// Append the full audit log
        #[arg(long)]
        full_audit: bool,
        /// Times in UTC instead of this computer's local time
        #[arg(long)]
        utc: bool,
    },
    /// Parse one exported artifact file (registry hive, EVTX, Prefetch, LNK,
    /// Jump List, Internet Explorer index.dat) and print what it holds as JSON
    Artifact {
        file: PathBuf,
        /// Every record instead of a summary
        #[arg(long)]
        full: bool,
    },
    /// Analyze one picture (JPEG, PNG, BMP): EXIF, compression tables and
    /// history, thumbnail, software traces, hidden data, LSB test; prints JSON
    Image { file: PathBuf },
}

#[derive(Subcommand)]
enum HashsetCmd {
    /// List hash sets
    List,
    /// Import a hash set: NSRL RDS v3 (.db, or .sql full and delta releases), NSRL RDS 2.x NSRLFile.txt, CSV
    /// with a header, or a plain list (md5sum / sha256sum output works)
    Import {
        file: PathBuf,
        #[arg(long)]
        name: String,
        /// known (known good, hidden) or notable (known bad, flagged)
        #[arg(long)]
        kind: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Use a set in hash analysis again
    Enable { id: String },
    /// Stop using a set (kept, can be enabled again)
    Disable { id: String },
    /// Remove a set and its database
    Delete { id: String },
}

/// Console log times day first, like everything else people read.
struct DayFirst;

impl tracing_subscriber::fmt::time::FormatTime for DayFirst {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", kokino_core::time::human_full(&kokino_core::time::now_iso()))
    }
}

fn hashset_cmd(root: PathBuf, cmd: HashsetCmd) -> anyhow::Result<()> {
    use kokino_analysis::hashsets::{SetKind, Store};
    let users = kokino_core::users::UserStore::open(&root)?;
    let store = Store::open(root.join(".kokino").join("hashsets"));
    let actor = format!("cli:{}", std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_default());
    let list_only = matches!(cmd, HashsetCmd::List);
    match cmd {
        HashsetCmd::List => {
            let list = store.list()?;
            if list.is_empty() {
                println!("No hash sets. Import one with: kokino hashset import <file> --name NSRL --kind known");
            }
            for s in list {
                println!(
                    "{}  {:<30} {:<10} {:>12} hashes  {}  from {} (SHA-256 {}){}",
                    s.id,
                    s.name,
                    s.kind.label(),
                    s.hashes(),
                    if s.enabled { "enabled " } else { "disabled" },
                    s.source,
                    &s.source_sha256[..16],
                    if s.description.is_empty() { String::new() } else { format!("\n      {}", s.description) }
                );
            }
        }
        HashsetCmd::Import { file, name, kind, description } => {
            let kind = match kind.to_ascii_lowercase().as_str() {
                "known" | "good" | "known-good" => SetKind::Known,
                "notable" | "bad" | "known-bad" => SetKind::Notable,
                _ => anyhow::bail!("--kind is known (known good) or notable (known bad)"),
            };
            let mut last = String::new();
            let mut shown = 0u64;
            let info = store.import(&file, &name, kind, &description, &actor, &mut |stage, d, t| {
                let pct = if t > 0 { d * 100 / t } else { 0 };
                if stage != last || pct >= shown + 10 {
                    eprintln!("  {} {}%", stage, pct);
                    last = stage.to_string();
                    shown = pct;
                }
                true
            })?;
            users.audit.append(&actor, "hashset.import", serde_json::json!({"set": info, "path": file.to_string_lossy()}))?;
            println!("Imported {} ({}, {}): {} MD5, {} SHA-1, {} SHA-256 hashes from {} rows ({} without a hash). Id {}.", info.name, info.kind.label(), info.format, info.md5, info.sha1, info.sha256, info.rows, info.skipped, info.id);
        }
        HashsetCmd::Enable { id } => {
            let s = store.set_enabled(&id, true)?;
            users.audit.append(&actor, "hashset.update", serde_json::json!({"id": s.id, "name": s.name, "enabled": true}))?;
            println!("{} enabled", s.name);
        }
        HashsetCmd::Disable { id } => {
            let s = store.set_enabled(&id, false)?;
            users.audit.append(&actor, "hashset.update", serde_json::json!({"id": s.id, "name": s.name, "enabled": false}))?;
            println!("{} disabled", s.name);
        }
        HashsetCmd::Delete { id } => {
            let s = store.delete(&id)?;
            users.audit.append(&actor, "hashset.delete", serde_json::json!({"id": s.id, "name": s.name, "kind": s.kind, "source_sha256": s.source_sha256}))?;
            println!("{} deleted", s.name);
        }
    }
    if !list_only {
        println!("Evidence analyzed before is compared with the changed sets by Hash analysis > Check again in the GUI.");
    }
    Ok(())
}

#[derive(Subcommand)]
enum UserCmd {
    /// List accounts
    List,
    /// Create an account (prompts for the password)
    Add {
        username: String,
        /// admin, examiner or reviewer
        #[arg(long, default_value = "examiner")]
        role: String,
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Set a new password (prompts) and re-enable the account
    Reset { username: String },
    /// Change an account's role
    Role { username: String, role: String },
    /// Disable an account
    Disable { username: String },
    /// Delete an account. Never-used accounts are removed completely; used
    /// ones keep only a record reserving the username (audit logs name it)
    Delete {
        username: String,
        /// Skip the typed confirmation
        #[arg(long)]
        yes: bool,
    },
}

fn prompt_password() -> anyhow::Result<String> {
    let p = rpassword::prompt_password("New password: ")?;
    kokino_core::users::check_password(&p)?;
    if rpassword::prompt_password("Repeat password: ")? != p {
        anyhow::bail!("passwords do not match");
    }
    Ok(p)
}

fn user_cmd(root: PathBuf, cmd: UserCmd) -> anyhow::Result<()> {
    use kokino_core::users::{hash_password, Role, UserStore};
    let store = UserStore::open(&root)?;
    let actor = format!("cli:{}", std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_default());
    match cmd {
        UserCmd::List => {
            for u in store.list()? {
                println!(
                    "{:<20} {:<9} {:<28} {}{}",
                    u.username,
                    format!("{:?}", u.role).to_lowercase(),
                    u.display_name,
                    if u.disabled { "disabled " } else { "" },
                    u.last_login.map(|t| format!("last login {}", kokino_core::time::human(&t))).unwrap_or_default()
                );
            }
        }
        UserCmd::Add { username, role, display_name } => {
            let role = Role::parse(&role)?;
            let p = prompt_password()?;
            let u = store.create(&username, display_name.as_deref().unwrap_or(""), role, &p)?;
            store.audit.append(&actor, "user.create", serde_json::json!({"username": u.username, "role": u.role}))?;
            println!("created {}", u.username);
        }
        UserCmd::Reset { username } => {
            let p = prompt_password()?;
            let h = hash_password(&p)?;
            let name = username.to_ascii_lowercase();
            store.update(|all| {
                let u = all.iter_mut().find(|u| u.username == name).ok_or_else(|| anyhow::anyhow!("no such user"))?;
                u.password = h;
                u.disabled = false;
                u.must_change_password = false;
                Ok(())
            })?;
            store.audit.append(&actor, "user.update", serde_json::json!({"username": name, "changes": {"password_reset": true, "disabled": false}}))?;
            println!("password reset for {}", name);
        }
        UserCmd::Role { username, role } => {
            let role = Role::parse(&role)?;
            let name = username.to_ascii_lowercase();
            store.update(|all| {
                all.iter_mut().find(|u| u.username == name).ok_or_else(|| anyhow::anyhow!("no such user"))?.role = role;
                Ok(())
            })?;
            store.audit.append(&actor, "user.update", serde_json::json!({"username": name, "changes": {"role": role}}))?;
            println!("{} is now {:?}", name, role);
        }
        UserCmd::Disable { username } => {
            let name = username.to_ascii_lowercase();
            store.update(|all| {
                all.iter_mut().find(|u| u.username == name).ok_or_else(|| anyhow::anyhow!("no such user"))?.disabled = true;
                Ok(())
            })?;
            store.audit.append(&actor, "user.update", serde_json::json!({"username": name, "changes": {"disabled": true}}))?;
            println!("{} disabled", name);
        }
        UserCmd::Delete { username, yes } => {
            let name = username.to_ascii_lowercase();
            store.get(&name)?.ok_or_else(|| anyhow::anyhow!("no such user"))?;
            let usage = store.usage(&root, &name)?;
            if usage.is_empty() {
                println!("{} was never used: the account will be removed completely.", name);
            } else {
                println!("{} was used:", name);
                for u in &usage {
                    println!("  - {}", u);
                }
                println!("Its password and display name will be removed; the username stays reserved so those records keep naming one person.");
            }
            if !yes {
                print!("Type the username to confirm: ");
                std::io::Write::flush(&mut std::io::stdout())?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                if line.trim().to_ascii_lowercase() != name {
                    anyhow::bail!("not confirmed; nothing deleted");
                }
            }
            let d = store.delete(&root, &name, &actor)?;
            println!("{} deleted{}{}", name, if d.purged { " (removed completely)" } else { " (username reserved)" }, if d.cases.is_empty() { String::new() } else { format!("; removed from {} case(s)", d.cases.len()) });
            println!("A running server signs the account out on its next request.");
        }
    }
    Ok(())
}

/// Bytes in a folder, recursively (symbolic links not followed).
fn folder_size(p: &std::path::Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => folder_size(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

/// `kokino purge`: deletes what Kokino created in the cases folder (case
/// folders, recognized by their case.json, and .kokino) and nothing else.
fn purge(root: PathBuf, confirm: Option<String>) -> anyhow::Result<()> {
    if !root.is_dir() {
        println!("Nothing to remove: {} does not exist.", root.display());
        return Ok(());
    }
    let cases: Vec<PathBuf> = std::fs::read_dir(&root)?.flatten().map(|e| e.path()).filter(|p| p.is_dir() && p.join("case.json").is_file()).collect();
    let state = kokino_core::state_dir(&root);
    let names: Vec<String> = cases
        .iter()
        .map(|p| kokino_core::case::read_json::<kokino_core::case::CaseInfo>(&p.join("case.json")).map(|i| i.name).unwrap_or_else(|_| p.file_name().unwrap_or_default().to_string_lossy().into_owned()))
        .collect();
    let mb = |b: u64| format!("{:.1} MB", b as f64 / 1_048_576.0);
    println!("This removes everything Kokino stored in {}:", root.display());
    println!("  {} case(s): {}", cases.len(), if names.is_empty() { "none".to_string() } else { names.join(", ") });
    println!("    analysis, search indexes, carved files, bookmarks, reports, exports and audit logs ({})", mb(cases.iter().map(|p| folder_size(p)).sum()));
    if state.is_dir() {
        println!("  {}: accounts, system audit log, hash sets, TLS key and deleted cases ({})", state.display(), mb(folder_size(&state)));
    }
    println!("Evidence image files are not touched. Other files in the folder are left alone.");
    println!("Stop the Kokino server first. This cannot be undone.");
    let answer = match confirm {
        Some(c) => c,
        None => {
            print!("Type DELETE ALL to continue: ");
            std::io::Write::flush(&mut std::io::stdout())?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        }
    };
    if answer.trim() != "DELETE ALL" {
        println!("Nothing was removed.");
        return Ok(());
    }
    let mut failed = vec![];
    for p in cases.iter().chain(state.is_dir().then_some(&state)) {
        if let Err(e) = std::fs::remove_dir_all(p) {
            failed.push(format!("{}: {}", p.display(), e));
        }
    }
    // The folder itself goes too when nothing else is left in it.
    let _ = std::fs::remove_dir(&root);
    if failed.is_empty() {
        println!("Removed. Kokino keeps nothing else on this machine; browsers keep only your display settings (theme, time zone, error list) for the Kokino page.");
        Ok(())
    } else {
        anyhow::bail!("could not remove everything (is the server still running, or a file open?):\n  {}", failed.join("\n  "))
    }
}

fn default_cases() -> PathBuf {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    // A cases folder from before the rename moves to ~/KokinoCases once.
    let (root, note) = kokino_core::case::Case::migrate_root(&home.join("BaboonCases"), &home.join("KokinoCases"));
    if let Some(n) = note {
        eprintln!("{}", n);
        if let Ok(users) = kokino_core::users::UserStore::open(&root) {
            let _ = users.audit.append("kokino", "system.cases_folder", serde_json::json!({"event": n}));
        }
    }
    root
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_timer(DayFirst).with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    match Cli::parse().cmd {
        Cmd::Serve { cases, port, listen, hostnames, tls_cert, tls_key, tls, no_browser } => {
            let cases = cases.unwrap_or_else(default_cases);
            let tls = match (tls_cert, tls_key) {
                (Some(cert), Some(key)) => kokino_server::Tls::Files { cert, key },
                _ if tls || !listen.is_loopback() => kokino_server::Tls::SelfSigned,
                _ => kokino_server::Tls::Off,
            };
            let running = kokino_server::start(kokino_server::ServerConfig { cases_root: cases.clone(), listen, port, tls, hostnames }).await?;
            println!("Kokino Forensic Toolkit {} by Zero Science Lab", kokino_core::TOOL_VERSION);
            println!("Cases: {}", cases.display());
            println!("Open:  {}   (on this machine)", running.url);
            for u in &running.lan_urls {
                println!("       {}   (from other machines)", u);
            }
            for u in &running.name_urls {
                println!("       {}   (needs DNS or a hosts entry for this name)", u);
            }
            if let Some(fp) = &running.fingerprint {
                println!("TLS:   self-signed certificate, SHA-256 fingerprint");
                println!("       {}", fp);
                println!("       Compare it with what the browser shows before accepting the warning.");
            }
            if !listen.is_loopback() {
                println!("LAN:   listening on {}; examiners need an account to sign in.", listen);
            }
            if let Some(setup) = &running.setup_url {
                println!();
                println!("No accounts yet. Create the first admin with this one-time link:");
                println!("       {}", setup);
                println!("(or run: kokino user add <name> --role admin)");
            }
            println!("Press Ctrl+C to stop.");
            if !no_browser && listen.is_loopback() {
                let _ = open::that(running.setup_url.as_ref().unwrap_or(&running.url));
            }
            running.handle.await??;
        }
        Cmd::User { cases, cmd } => user_cmd(cases.unwrap_or_else(default_cases), cmd)?,
        Cmd::Hashset { cases, cmd } => hashset_cmd(cases.unwrap_or_else(default_cases), cmd)?,
        Cmd::Purge { cases, confirm } => purge(cases.unwrap_or_else(default_cases), confirm)?,
        Cmd::Carve { image, json } => {
            use std::io::{Read, Seek, SeekFrom};
            let ev = kokino_image::Evidence::open(&image)?;
            eprintln!("{} ({}, {} bytes)", image.display(), ev.format_label(), ev.size);
            let a = kokino_analysis::analyze(&ev, &mut |_, _, _| true)?;
            let c = kokino_analysis::carve::carve(&ev, &a, &mut |_, _, _| true)?;
            let mut r = ev.reader()?;
            if !json {
                println!("id\toffset\tlength\tkind\tcomplete\tmd5\tsha1\tsha256\tdetail");
            }
            for f in &c.files {
                r.seek(SeekFrom::Start(f.offset))?;
                let (h, _) = kokino_core::hashing::hash_reader((&mut r).take(f.len), |_| true)?;
                if json {
                    println!("{}", serde_json::json!({"id": f.id, "offset": f.offset, "len": f.len, "kind": f.kind, "complete": f.complete, "md5": h.md5, "sha1": h.sha1, "sha256": h.sha256, "detail": f.detail, "region": f.region}));
                } else {
                    println!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", f.id, f.offset, f.len, f.kind, f.complete, h.md5, h.sha1, h.sha256, f.detail);
                }
            }
            if !c.records.is_empty() {
                if !json {
                    println!("\noffset\trecord\twhat\ttime_utc\tuser\turl\tfile\tin_carved_file");
                }
                let iso = |t: u64| if t == 0 { String::new() } else { kokino_core::time::filetime_to_iso(t) };
                for x in &c.records {
                    if json {
                        println!("{}", serde_json::json!({"ie_record": x.tag, "offset": x.offset, "len": x.len, "what": x.what, "t": iso(x.t), "user": x.user, "url": x.url, "title": x.title, "file": x.file, "hits": x.hits, "region": x.region, "in_file": x.in_file}));
                    } else {
                        println!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", x.offset, x.tag, x.what, iso(x.t), x.user, x.url, x.file, x.in_file.map(|i| i.to_string()).unwrap_or_default());
                    }
                }
            }
            eprintln!("{} files carved from {} bytes in {} regions{}", c.files.len(), c.scanned_bytes, c.regions, if c.truncated { " (stopped at the limit)" } else { "" });
            if !c.records.is_empty() {
                eprintln!("{} Internet Explorer records recovered{}", c.records.len(), if c.records_truncated { " (stopped at the limit)" } else { "" });
            }
        }
        Cmd::Files { image, json, extract } => {
            let ev = kokino_image::Evidence::open(&image)?;
            eprintln!("{} ({}, {} bytes)", image.display(), ev.format_label(), ev.size);
            let a = kokino_analysis::analyze(&ev, &mut |_, _, _| true)?;
            let fh = kokino_analysis::hashsets::hash_files(&ev, &a, &mut |_, _, _| true)?;
            if !json {
                println!("fs\trecord\tdeleted\tsize\tmd5\tsha1\tsha256\tpath\tnote");
            }
            // Readers for --extract, one per file system, opened on first use.
            let mut readers: std::collections::HashMap<usize, (kokino_analysis::fs::Fs, _)> = Default::default();
            for h in &fh.files {
                let Some(fsa) = a.filesystems.get(h.fi) else { continue };
                let Some(f) = fsa.files.iter().find(|f| f.e.record == h.record) else { continue };
                let note = h.error.clone().or_else(|| f.e.error.clone()).unwrap_or_else(|| {
                    // NTFS FILE_ATTRIBUTE_ENCRYPTED: what was hashed is ciphertext.
                    if !fsa.volume.fs_label.contains("FAT") && f.e.attributes & 0x4000 != 0 { "EFS-encrypted: hashes are of the ciphertext".into() } else { String::new() }
                });
                if let Some(dir) = &extract {
                    if !readers.contains_key(&h.fi) {
                        let mut r = kokino_analysis::volume_reader(&ev, &fsa.volume)?;
                        let fs = kokino_analysis::fs::Fs::open(&mut r, &fsa.volume)?;
                        readers.insert(h.fi, (fs, r));
                    }
                    let (fs, r) = readers.get_mut(&h.fi).unwrap();
                    let safe: String = f.e.name.chars().map(|c| if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' }).collect();
                    let out = dir.join(format!("fs{}", h.fi)).join(format!("{}-{}", h.record, safe));
                    std::fs::create_dir_all(out.parent().unwrap())?;
                    match fs.read(r, &f.e, "", 0, f.e.size as usize) {
                        Ok(d) => std::fs::write(&out, d)?,
                        Err(e) => eprintln!("{}: {}", f.e.path, e),
                    }
                }
                if json {
                    println!("{}", serde_json::json!({"fs": h.fi, "record": h.record, "deleted": f.e.deleted, "size": h.size, "md5": h.hashes.md5, "sha1": h.hashes.sha1, "sha256": h.hashes.sha256, "path": f.e.path, "note": note}));
                } else {
                    println!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", h.fi, h.record, if f.e.deleted { "deleted" } else { "live" }, h.size, h.hashes.md5, h.hashes.sha1, h.hashes.sha256, f.e.path, note);
                }
            }
            eprintln!("{} files hashed", fh.files.len());
        }
        Cmd::Analyze { image, json } => {
            let ev = kokino_image::Evidence::open(&image)?;
            eprintln!("{} ({}, {} bytes)", image.display(), ev.format_label(), ev.size);
            let mut last = String::new();
            let a = kokino_analysis::analyze(&ev, &mut |stage, d, t| {
                if stage != last {
                    eprintln!("  {}", stage);
                    last = stage.to_string();
                }
                let _ = (d, t);
                true
            })?;
            for v in &a.volumes {
                println!("volume {}  start {:>12}  len {:>12}  {:<22} {}", v.index, v.start, v.length, v.fs_label, v.description);
            }
            for f in &a.filesystems {
                let deleted = f.files.iter().filter(|r| r.e.deleted).count();
                println!("\n{} volume {} \"{}\" serial {} ({} entries, {} deleted)", f.volume.fs_label, f.volume.index, f.info.label, f.info.serial, f.files.len(), deleted);
                for line in &f.stats.impact {
                    println!("  - {}", line);
                }
                println!("  Anti-forensics likelihood: {} ({:.0}%)", f.score.band, f.score.likelihood * 100.0);
                for i in &f.indicators {
                    println!("    [{:.2}] {} x{}", i.strength, i.title, i.count);
                }
                if f.stats.time_max > 0 {
                    println!("  Activity: {} .. {}", kokino_core::time::filetime_human(f.stats.time_min), kokino_core::time::filetime_human(f.stats.time_max));
                }
            }
            for e in &a.errors {
                println!("note: {}", e);
            }
            if let Some(p) = json {
                std::fs::write(&p, serde_json::to_vec_pretty(&a)?).with_context(|| format!("writing {}", p.display()))?;
                eprintln!("wrote {}", p.display());
            }
        }
        Cmd::Hash { image } => {
            let ev = kokino_image::Evidence::open(&image)?;
            let (h, n) = kokino_core::hashing::hash_reader(ev.reader()?, |_| true)?;
            println!("format  {}\nbytes   {}\nmd5     {}\nsha1    {}\nsha256  {}", ev.format_label(), n, h.md5, h.sha1, h.sha256);
            // EWF images carry the hash the imaging tool computed; check it.
            if let Some(info) = ev.ewf_info() {
                println!();
                for (k, v) in &info.acquisition {
                    let v = if k == "acquired" || k == "system_date" { kokino_core::time::human(v) } else { v.clone() };
                    println!("{:<22}{}", k.replace('_', " "), v);
                }
                println!("{:<22}{} ({} chunks, {} compressed)", "segments", info.segments.len(), info.chunk_count, info.compressed_chunks);
                for (s, c) in &info.read_errors {
                    println!("{:<22}sectors {}-{} ({})", "UNREADABLE", s, s + c.saturating_sub(1), c);
                }
                let mut bad = false;
                for (name, stored, ours) in [("md5", &info.md5, &h.md5), ("sha1", &info.sha1, &h.sha1)] {
                    if let Some(s) = stored {
                        let ok = s.eq_ignore_ascii_case(ours);
                        bad |= !ok;
                        println!("{:<22}{} {}", format!("stored {}", name), s, if ok { "MATCH" } else { "MISMATCH" });
                    }
                }
                if info.md5.is_none() && info.sha1.is_none() {
                    println!("stored hash           none in this image");
                }
                if bad {
                    std::process::exit(3);
                }
            }
        }
        Cmd::Artifact { file, full } => {
            let data = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let v = kokino_analysis::windows::inspect(&name, &data, full)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Cmd::Image { file } => {
            let data = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let mut r = kokino_analysis::photo::analyze(&data, &file.to_string_lossy().replace('\\', "/"));
            r.thumbnail_data = None;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Cmd::Report { case_dir, title, reference, requested_by, summary, tag, full_audit, utc } => {
            if !case_dir.join("case.json").is_file() {
                anyhow::bail!("{} is not a case folder (no case.json)", case_dir.display());
            }
            let case_dir = std::path::absolute(&case_dir)?;
            let (Some(root), Some(cid)) = (case_dir.parent(), case_dir.file_name().and_then(|n| n.to_str())) else { anyhow::bail!("give the case folder, e.g. KokinoCases/my-case-1a2b3c4d") };
            let summary = match summary {
                Some(p) => std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?,
                None => String::new(),
            };
            let o = kokino_server::casereport::ReportOptions {
                title: title.unwrap_or_default(),
                reference: reference.unwrap_or_default(),
                requested_by: requested_by.unwrap_or_default(),
                summary,
                tag: tag.unwrap_or_default(),
                full_audit,
                utc,
            };
            let st = kokino_server::AppState::new(root.to_path_buf(), 0, false, vec![])?;
            let actor = format!("cli:{}", std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_default());
            let g = kokino_server::casereport::generate(&st, cid, &actor, &actor, &o)?;
            println!("Report {} with {} exhibit(s):", g.report, g.exhibits);
            for f in &g.files {
                println!("  {}", case_dir.join("exports").join(&f.name).display());
                println!("    SHA-256 {}", f.sha256);
            }
        }
        Cmd::Version { check } => {
            println!("{} {}", kokino_core::TOOL_NAME, kokino_core::TOOL_VERSION);
            if check {
                println!("asking {} ...", kokino_server::update::RELEASES_API);
                let u = kokino_server::update::check()?;
                if u.newer {
                    println!("newer release: {} (published {})\n{}", u.latest, u.published, u.url);
                    if let Some(c) = &u.checksums {
                        println!("\nSHA256SUMS.txt of that release:\n{}", c.trim_end());
                    }
                } else {
                    println!("this is the latest release ({})", u.latest);
                }
            }
        }
        Cmd::VerifyAudit { case_dir } => {
            let r = kokino_core::audit::verify(&case_dir.join("audit.jsonl"))?;
            println!("{}", serde_json::to_string_pretty(&r)?);
            if !r.ok {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}
