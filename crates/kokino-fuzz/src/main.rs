//! Mutation fuzzer for Kokino's parsers, on stable Rust.
//!
//!   kokino-fuzz run <target>|all [--secs N] [--seed S]
//!   kokino-fuzz repro <target> <file>
//!   kokino-fuzz list
//!
//! `run` starts a child process that feeds the target mutated seeds. The
//! child reports each input's number before running it, so when it panics,
//! aborts, overflows its stack, runs out of its memory budget or stops
//! making progress, the parent regenerates that exact input (the mutations
//! are a pure function of seed and number) and saves it under
//! `target/fuzz-findings/<target>/`. Panics are caught in the child, which keeps going.
//!
//! Limits, chosen so that real parsing never hits them: 2 MiB of stack (the
//! default for the server's worker threads), 256 MiB for one allocation and
//! 1 GiB in all, 20 seconds per input.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const MAX_ONE: usize = 256 << 20;
const MAX_LIVE: usize = 1 << 30;
const STACK: usize = 2 << 20;
const HANG: Duration = Duration::from_secs(20);

/// Allocator with a budget: an input that makes a parser ask for more is a
/// finding (memory exhaustion from a small file), reported and aborted.
struct Capped;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static ENFORCE: AtomicBool = AtomicBool::new(false);

fn over(size: usize) {
    // Stop enforcing so the report itself can allocate.
    ENFORCE.store(false, Ordering::Relaxed);
    eprintln!("\nKOKINO-FUZZ: memory budget exceeded: {} bytes requested, {} live\n{}", size, LIVE.load(Ordering::Relaxed), std::backtrace::Backtrace::force_capture());
    std::process::abort();
}

unsafe impl GlobalAlloc for Capped {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ENFORCE.load(Ordering::Relaxed) && (l.size() > MAX_ONE || LIVE.load(Ordering::Relaxed) + l.size() > MAX_LIVE) {
            over(l.size());
        }
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        if ENFORCE.load(Ordering::Relaxed) && (l.size() > MAX_ONE || LIVE.load(Ordering::Relaxed) + l.size() > MAX_LIVE) {
            over(l.size());
        }
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if ENFORCE.load(Ordering::Relaxed) && new > l.size() && (new > MAX_ONE || LIVE.load(Ordering::Relaxed) + new - l.size() > MAX_LIVE) {
            over(new);
        }
        let q = System.realloc(p, l, new);
        if !q.is_null() {
            LIVE.fetch_sub(l.size(), Ordering::Relaxed);
            LIVE.fetch_add(new, Ordering::Relaxed);
        }
        q
    }
}

#[global_allocator]
static A: Capped = Capped;

fn usage() -> ! {
    eprintln!("usage: kokino-fuzz run <target>|all [--secs N] [--seed S] | repro <target> <file> | list");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("list") => {
            for t in kokino_fuzz::TARGETS {
                println!("{:9} {} seed file(s)", t.name, kokino_fuzz::load_seeds(t).len());
            }
        }
        Some("child") => child(&args[2], args[3].parse().unwrap(), args[4].parse().unwrap()),
        Some("repro") => {
            let t = kokino_fuzz::target(args.get(2).unwrap_or_else(|| usage())).unwrap_or_else(|| usage());
            let d = std::fs::read(args.get(3).unwrap_or_else(|| usage())).expect("read input");
            ENFORCE.store(true, Ordering::Relaxed);
            let t0 = Instant::now();
            let ok = std::thread::Builder::new().stack_size(STACK).spawn(move || (t.run)(&d)).unwrap().join().is_ok();
            println!("{} in {:?}", if ok { "ok" } else { "PANIC" }, t0.elapsed());
            std::process::exit(if ok { 0 } else { 1 });
        }
        Some("run") => {
            let which = args.get(2).unwrap_or_else(|| usage()).clone();
            let opt = |k: &str, def: u64| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok()).unwrap_or(def);
            let (secs, seed) = (opt("--secs", 60), opt("--seed", 1));
            let names: Vec<&str> = if which == "all" { kokino_fuzz::TARGETS.iter().map(|t| t.name).collect() } else { vec![which.as_str()] };
            if names.len() == 1 {
                std::process::exit(parent(names[0], secs, seed));
            }
            // All targets at once, one process each.
            let me = std::env::current_exe().unwrap();
            let kids: Vec<_> = names.iter().map(|n| (n, Command::new(&me).args(["run", n, "--secs", &secs.to_string(), "--seed", &seed.to_string()]).spawn().unwrap())).collect();
            let mut bad = 0;
            for (n, mut k) in kids {
                if !k.wait().map(|s| s.success()).unwrap_or(false) {
                    eprintln!("{}: findings", n);
                    bad += 1;
                }
            }
            std::process::exit(if bad > 0 { 1 } else { 0 });
        }
        _ => usage(),
    }
}

/// Child: runs inputs `start..` forever, announcing each one first.
fn child(name: &str, seed: u64, start: u64) {
    let t = kokino_fuzz::target(name).unwrap();
    let seeds = kokino_fuzz::prepare(kokino_fuzz::load_seeds(t));
    let last_panic = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let lp = last_panic.clone();
    std::panic::set_hook(Box::new(move |info| {
        let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let msg = info.payload().downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| info.payload().downcast_ref::<String>().cloned()).unwrap_or_default();
        *lp.lock().unwrap() = format!("{} | {}", loc, msg.replace('\n', " "));
    }));
    let worker = std::thread::Builder::new().stack_size(STACK).spawn(move || {
        let mut out = std::io::stdout().lock();
        let mut n = start;
        loop {
            let d = kokino_fuzz::generate(&seeds, seed, n);
            writeln!(out, "I {}", n).unwrap();
            out.flush().unwrap();
            ENFORCE.store(true, Ordering::Relaxed);
            let ok = std::panic::catch_unwind(|| (t.run)(&d)).is_ok();
            ENFORCE.store(false, Ordering::Relaxed);
            if !ok {
                let p = last_panic.lock().unwrap().clone();
                writeln!(out, "P {} {}", n, p).unwrap();
            }
            n += 1;
        }
    });
    worker.unwrap().join().ok();
}

/// Parent: runs the child for `secs`, restarting it after each crash.
fn parent(name: &str, secs: u64, seed: u64) -> i32 {
    let t = kokino_fuzz::target(name).unwrap_or_else(|| usage());
    let seeds = kokino_fuzz::prepare(kokino_fuzz::load_seeds(t));
    if seeds.is_empty() {
        eprintln!("{}: no seed files found", name);
        return 2;
    }
    let dir = kokino_fuzz::workspace_root().join("target").join("fuzz-findings").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let me = std::env::current_exe().unwrap();
    let end = Instant::now() + Duration::from_secs(secs);
    let mut start = 0u64;
    let mut done = 0u64;
    let mut seen: std::collections::HashMap<String, u32> = Default::default();
    let mut findings = 0;
    let mut save = |kind: &str, key: String, n: u64, detail: &str| {
        let c = seen.entry(format!("{} {}", kind, key)).or_insert(0);
        *c += 1;
        if *c > 3 {
            return;
        }
        let d = kokino_fuzz::generate(&seeds, seed, n);
        let f = dir.join(format!("{}-{}-{}.bin", kind, seed, n));
        std::fs::write(&f, &d).unwrap();
        println!("[{}] {} at input {} ({} bytes): {}  -> {}", name, kind.to_uppercase(), n, d.len(), detail, f.display());
    };
    while Instant::now() < end {
        let mut kid = Command::new(&me)
            .args(["child", name, &seed.to_string(), &start.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let out = kid.stdout.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let err = kid.stderr.take().unwrap();
        let err_tail = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let et = err_tail.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(err).lines().map_while(Result::ok) {
                let mut s = et.lock().unwrap();
                s.push_str(&l);
                s.push('\n');
                if s.len() > 4000 {
                    let cut = s.len() - 2000;
                    *s = s[cut..].to_string();
                }
            }
        });
        let mut cur = start;
        let mut last = Instant::now();
        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(l) => {
                    last = Instant::now();
                    if let Some(n) = l.strip_prefix("I ") {
                        cur = n.parse().unwrap_or(cur);
                        done += 1;
                    } else if let Some(rest) = l.strip_prefix("P ") {
                        let (n, info) = rest.split_once(' ').unwrap_or((rest, ""));
                        let key = info.split(" | ").next().unwrap_or("").to_string();
                        findings += 1;
                        save("panic", key, n.parse().unwrap_or(0), info);
                    }
                    if Instant::now() >= end {
                        let _ = kid.kill();
                        let _ = kid.wait();
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if last.elapsed() > HANG {
                        let _ = kid.kill();
                        let _ = kid.wait();
                        findings += 1;
                        save("hang", "hang".into(), cur, &format!("no progress for {:?}", HANG));
                        start = cur + 1;
                        break;
                    }
                    if Instant::now() >= end {
                        let _ = kid.kill();
                        let _ = kid.wait();
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let status = kid.wait().ok();
                    std::thread::sleep(Duration::from_millis(100));
                    let tail = err_tail.lock().unwrap().clone();
                    let kind = if tail.contains("memory budget") {
                        "oom"
                    } else if tail.contains("overflowed its stack") {
                        "stack"
                    } else {
                        "crash"
                    };
                    findings += 1;
                    let detail = format!("{:?} {}", status.and_then(|s| s.code()), tail.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or(""));
                    save(kind, kind.into(), cur, &detail);
                    start = cur + 1;
                    break;
                }
            }
        }
        if Instant::now() >= end {
            break;
        }
    }
    println!("[{}] {} inputs in {}s, {} finding(s), {} distinct", name, done, secs, findings, seen.len());
    if findings > 0 { 1 } else { 0 }
}
