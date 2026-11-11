//! Windows FILETIME helpers.
//!
//! FILETIME counts 100-nanosecond intervals since 1601-01-01 UTC. We keep the
//! raw value everywhere (lossless, needed for sub-second anomaly checks) and
//! convert to ISO 8601 only for display.

use chrono::{DateTime, Utc};

/// 100ns ticks between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF_TICKS: u64 = 116_444_736_000_000_000;

/// Converts a FILETIME to a UTC datetime. Returns None for 0 or out of range.
pub fn filetime_to_datetime(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }
    let unix_ticks = ft as i128 - EPOCH_DIFF_TICKS as i128;
    let secs = unix_ticks.div_euclid(10_000_000) as i64;
    let nanos = (unix_ticks.rem_euclid(10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// ISO 8601 with 7 fractional digits (full FILETIME precision), or empty.
pub fn filetime_to_iso(ft: u64) -> String {
    match filetime_to_datetime(ft) {
        Some(dt) => {
            let frac = ft % 10_000_000;
            format!("{}.{:07}Z", dt.format("%Y-%m-%dT%H:%M:%S"), frac)
        }
        None => String::new(),
    }
}

/// FILETIME for a UTC datetime.
pub fn datetime_to_filetime(dt: DateTime<Utc>) -> u64 {
    let ticks = dt.timestamp() as i128 * 10_000_000 + (dt.timestamp_subsec_nanos() / 100) as i128;
    (ticks + EPOCH_DIFF_TICKS as i128).max(0) as u64
}

/// True when the sub-second part is exactly zero. Natural NTFS timestamps
/// almost never land on a whole second; many timestomping tools write whole
/// seconds only.
pub fn is_whole_second(ft: u64) -> bool {
    ft != 0 && ft % 10_000_000 == 0
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

thread_local! {
    /// Show times in UTC on this thread instead of the computer's zone (a
    /// report generated "in UTC").
    static IN_UTC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` with times shown in UTC (true) or this computer's zone (false).
pub fn with_utc<T>(utc: bool, f: impl FnOnce() -> T) -> T {
    let before = IN_UTC.with(|c| c.replace(utc));
    let out = f();
    IN_UTC.with(|c| c.set(before));
    out
}

/// "UTC+1", "UTC-3:30", or "UTC".
fn offset_label(secs: i32) -> String {
    if secs == 0 {
        return "UTC".into();
    }
    let a = secs.unsigned_abs() / 60;
    format!("UTC{}{}{}", if secs > 0 { "+" } else { "-" }, a / 60, if a % 60 > 0 { format!(":{:02}", a % 60) } else { String::new() })
}

/// A stored time for people, day first, to the second. Times marked UTC
/// ("Z" or an offset) are converted to this computer's zone, with summer
/// time applied for that date, and carry their offset:
/// "2026-10-30T14:32:05.123Z" -> "30-10-2026 15:32:05 UTC+1" in Amsterdam.
/// Times without a zone (a device's local clock) are shown as stored,
/// without a label. A date alone becomes "30-10-2026"; anything else is
/// returned as it is. Stored data (audit logs, case files, JSON) stays ISO.
pub fn human(iso: &str) -> String {
    format_time(iso, false)
}

/// Like `human`, keeping the fraction of a second as stored (FILETIME has
/// 100 ns): "02-01-2021 13:37:00.1234567 UTC+1".
pub fn human_full(iso: &str) -> String {
    format_time(iso, true)
}

/// Like `human_full`, but never converted: for a device's local clock (FAT)
/// carried as if it were UTC.
pub fn human_as_stored(iso: &str) -> String {
    let plain = iso.trim_end_matches('Z');
    format_time(plain, true)
}

fn format_time(iso: &str, full: bool) -> String {
    let b = iso.as_bytes();
    let digits = |r: std::ops::Range<usize>| b.get(r).is_some_and(|x| x.iter().all(u8::is_ascii_digit));
    if !(digits(0..4) && b.get(4) == Some(&b'-') && digits(5..7) && b.get(7) == Some(&b'-') && digits(8..10)) {
        return iso.to_string();
    }
    let date = |y: &str, m: &str, d: &str| format!("{}-{}-{}", d, m, y);
    if !(iso.len() >= 19 && matches!(b[10], b'T' | b' ') && digits(11..13) && digits(14..16) && digits(17..19)) {
        return date(&iso[0..4], &iso[5..7], &iso[8..10]);
    }
    let rest = &iso[19..];
    let frac: String = if rest.starts_with('.') { rest.chars().take_while(|c| *c == '.' || c.is_ascii_digit()).collect() } else { String::new() };
    let zone = &rest[frac.len()..];
    let frac = if full && frac.len() > 1 { frac } else { String::new() };
    if zone.is_empty() {
        // No zone stored: as it is.
        return format!("{} {}{}", date(&iso[0..4], &iso[5..7], &iso[8..10]), &iso[11..19], frac);
    }
    let instant = chrono::DateTime::parse_from_rfc3339(&format!("{}{}", &iso[..19], if zone == "Z" { "+00:00" } else { zone }));
    let Ok(t) = instant else { return iso.to_string() };
    let t = t.with_timezone(&Utc);
    if IN_UTC.with(|c| c.get()) {
        return format!("{}{} UTC", t.format("%d-%m-%Y %H:%M:%S"), frac);
    }
    let local = t.with_timezone(&chrono::Local);
    format!("{}{} {}", local.format("%d-%m-%Y %H:%M:%S"), frac, offset_label(local.offset().local_minus_utc()))
}

/// A FILETIME for text that is stored with the analysis (summaries, notes):
/// always UTC, whatever the computer's zone, so the analysis of an image is
/// the same everywhere. "20-10-2026 10:30:02 UTC"; empty for 0.
pub fn utc_text(ft: u64) -> String {
    if ft == 0 {
        return String::new();
    }
    with_utc(true, || human(&filetime_to_iso(ft)))
}

/// A FILETIME for people (see `human`), or empty.
pub fn filetime_human(ft: u64) -> String {
    human(&filetime_to_iso(ft))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_roundtrip() {
        assert_eq!(filetime_to_iso(EPOCH_DIFF_TICKS + 1), "1970-01-01T00:00:00.0000001Z");
        let dt = filetime_to_datetime(132_539_328_000_000_000).unwrap();
        assert_eq!(dt.to_rfc3339(), "2021-01-01T00:00:00+00:00");
        assert_eq!(datetime_to_filetime(dt), 132_539_328_000_000_000);
        assert!(is_whole_second(132_539_328_000_000_000));
        assert!(!is_whole_second(132_539_328_000_000_001));
    }

    #[test]
    fn human_dates_are_day_first() {
        with_utc(true, || {
            assert_eq!(human("2021-01-02T12:37:00.1234567Z"), "02-01-2021 12:37:00 UTC");
            assert_eq!(human("2026-10-30T16:05:09.123+02:00"), "30-10-2026 14:05:09 UTC");
            assert_eq!(human_full("2021-01-02T12:37:00.1234567Z"), "02-01-2021 12:37:00.1234567 UTC");
            assert_eq!(filetime_human(132_539_328_000_000_000), "01-01-2021 00:00:00 UTC");
        });
        // No zone stored, or a device's clock: shown as stored.
        assert_eq!(human("2010-08-06 00:06:08"), "06-08-2010 00:06:08");
        assert_eq!(human_as_stored("2026-10-20T09:45:30.5000000Z"), "20-10-2026 09:45:30.5000000");
        assert_eq!(human("2026-10-30"), "30-10-2026");
        assert_eq!(human("not a time"), "not a time");
        assert_eq!(human(""), "");
        // This computer's zone: the label matches the conversion.
        let l = human("2026-01-15T12:00:00Z");
        assert!(l.starts_with("15-01-2026 ") && l.contains("UTC"), "{}", l);
        assert_eq!(offset_label(3600), "UTC+1");
        assert_eq!(offset_label(-12600), "UTC-3:30");
        assert_eq!(offset_label(0), "UTC");
    }
}
