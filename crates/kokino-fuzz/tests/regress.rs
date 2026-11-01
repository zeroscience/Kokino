//! Replays every input listed in regress.txt: each must now finish within
//! the time limit, on a 2 MiB stack, without panicking.

use std::sync::mpsc;
use std::time::Duration;

#[test]
fn saved_inputs_no_longer_break_parsers() {
    let list = std::fs::read_to_string(kokino_fuzz::workspace_root().join("crates/kokino-fuzz/regress.txt")).unwrap();
    let mut failures = vec![];
    let mut n_cases = 0;
    for line in list.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let t = kokino_fuzz::target(f[0]).unwrap_or_else(|| panic!("unknown target in {:?}", line));
        let seeds = kokino_fuzz::prepare(kokino_fuzz::load_seeds(t));
        let input = kokino_fuzz::generate(&seeds, f[1].parse().unwrap(), f[2].parse().unwrap());
        let (tx, rx) = mpsc::channel();
        let run = t.run;
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || {
                let ok = std::panic::catch_unwind(|| run(&input)).is_ok();
                let _ = tx.send(ok);
            })
            .unwrap();
        n_cases += 1;
        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(true) => {}
            Ok(false) => failures.push(format!("{}: panicked", line)),
            Err(_) => failures.push(format!("{}: still running after 60 s", line)),
        }
    }
    assert!(n_cases > 0);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
