//! Opening SQLite databases that come from evidence or from outside the lab.
//!
//! Such a database is untrusted input: its schema can define views and
//! triggers that run SQL when Kokino reads it, its pages can be corrupt on
//! purpose, and a query over it can be made to run for ever (a recursive
//! view standing in for a table, for example). `harden` applies SQLite's own
//! advice for untrusted databases and puts a time limit on every statement.

use rusqlite::config::DbConfig;
use rusqlite::Connection;
use std::time::{Duration, Instant};

/// Longest a database may keep Kokino busy, all its statements together.
pub const BUDGET: Duration = Duration::from_secs(120);

/// Defensive mode (no writable schema, no shadow-table tampering), schema
/// SQL not trusted to call functions with side effects, cell sizes checked,
/// no memory mapping, and statements interrupted once `budget` has passed.
pub fn harden(c: &Connection, budget: Duration) -> rusqlite::Result<()> {
    c.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    c.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA cell_size_check = ON; PRAGMA mmap_size = 0;")?;
    let deadline = Instant::now() + budget;
    c.progress_handler(10_000, Some(move || Instant::now() > deadline));
    Ok(())
}

/// Names among `names` that the schema defines as views rather than tables:
/// a sign the database was altered, since the browsers never do this.
pub fn views_named(c: &Connection, names: &[&str]) -> Vec<String> {
    let Ok(mut st) = c.prepare("SELECT name FROM sqlite_master WHERE type = 'view'") else { return vec![] };
    let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) else { return vec![] };
    rows.flatten().filter(|v| names.iter().any(|n| n.eq_ignore_ascii_case(v))).collect()
}

/// Turns SQLite's "interrupted" into a message that says why.
pub fn explain(e: anyhow::Error) -> anyhow::Error {
    if e.chain().any(|c| c.downcast_ref::<rusqlite::Error>().is_some_and(|x| x.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted))) {
        anyhow::anyhow!("reading the database took longer than {} s and was stopped (the database may be crafted to stall analysis)", BUDGET.as_secs())
    } else {
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_never_ending_view_is_stopped() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE VIEW urls AS WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n) SELECT x AS id FROM n;").unwrap();
        harden(&c, Duration::from_millis(300)).unwrap();
        let t = Instant::now();
        let r = c.query_row("SELECT count(*) FROM urls", [], |r| r.get::<_, i64>(0));
        assert!(r.is_err());
        assert!(t.elapsed() < Duration::from_secs(5));
        assert_eq!(views_named(&c, &["urls", "visits"]), vec!["urls".to_string()]);
        let msg = explain(anyhow::Error::from(r.unwrap_err())).to_string();
        assert!(msg.contains("stopped"), "{}", msg);
    }
}
