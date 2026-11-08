# Anti-forensics likelihood: method

The score answers one question for the examiner: *where should I look first
for signs that someone tried to hide or destroy evidence?* It is a triage
aid. It is never a finding on its own, and the report says so.

## Indicators

Every indicator is a fixed, documented rule in
`crates/kokino-analysis/src/antiforensics.rs`. Each has:

- `weight` (0..1): how suspicious a single strong occurrence is.
- `k`: saturation. `count = k` reaches about 63% of `weight`.
- `explanation` and `caveat`: shown in the GUI and in the report.
- `records`: the exact MFT records that triggered it (up to 2000; the count is always exact).

| Id | Category | Weight | k | Rule |
|---|---|---|---|---|
| `si_before_fn` | Timestamp manipulation | 0.55 | 3 | $SI creation more than 1 s before $FN creation |
| `si_whole_second` | Timestamp manipulation | 0.45 | 5 | $SI creation exactly on a second while $FN is not |
| `implausible_time` | Timestamp manipulation | 0.35 | 3 | any $SI time after analysis date + 1 day or before 1993 |
| `wipe_tool` | Tool presence | 0.50 | 1.5 | file name of a known wiping / cleaning / timestomping tool |
| `wipe_tool_executed` | Tool presence | 0.75 | 1 | Prefetch file for such a tool |
| `sdelete_rename` | Secure deletion | 0.80 | 2 | deleted entry named with one repeated letter (AAAA.AAA) |
| `wiped_content` | Secure deletion | 0.35 | 10 | deleted non-resident file whose sampled bytes are all identical |
| `ext_mismatch` | Data hiding | 0.40 | 3 | signature contradicts a passive-content extension |
| `ads_payload` | Data hiding | 0.75 | 1 | named stream holds an executable or archive |
| `ads_unusual` | Data hiding | 0.30 | 5 | named stream other than well-known benign ones |
| `encrypted_container` | Data hiding | 0.40 | 2 | >= 1 MiB, entropy >= 7.97, no known signature |
| `usnjrnl_missing` | Log tampering | 0.50 | 1 | Windows system volume without $Extend/$UsnJrnl:$J |
| `usn_journal_recreated` | Log tampering | 0.35 | 1 | on a Windows system volume, the change journal's ID (its creation time) is more than 2 days after $MFT was created |
| `usn_wipe_rename` | Secure deletion | 0.85 | 2 | the change journal shows a file renamed to one repeated letter (AAAA.AAA); counted once per file |
| `evtx_cleared` | Log tampering | 0.55 | 1 | Security.evtx missing or <= 68 KiB |
| `prefetch_empty` | Log tampering | 0.30 | 1 | Windows\Prefetch exists with no live .pf files |
| `browser_history_cleared` | Log tampering | 0.45 | 1 | a browser history database with no visits and no URLs, or a deleted history database (for Internet Explorer, only the main history index.dat counts: cache and download lists hold no visits, and Windows deletes daily and weekly files itself) |
| `antiforensic_web` | Tool presence | 0.40 | 2 | a download of a known wiping/cleaning tool, or a search about wiping, shredding, permanent deletion, clearing traces or hidden volumes |
| `log_cleared_event` | Log tampering | 0.60 | 1 | event 1102 (Security log cleared) or 104 (another log cleared), which names the account and time |
| `linux_antiforensic_command` | Tool presence | 0.60 | 2 | shell, apt or sudo history shows shred / wipe / srm, history -c or HISTFILE disabled, log or history files removed, journal vacuumed, touch -d, clock changes, reverse shells or kernel modules loaded |
| `shell_history_cleared` | Log tampering | 0.45 | 1 | a user's .bash_history is empty or a symbolic link to /dev/null |
| `linux_log_emptied` | Log tampering | 0.50 | 1 | wtmp empty, or auth.log / secure empty while older rotations hold entries |
| `ld_preload` | Persistence | 0.60 | 1 | /etc/ld.so.preload lists a library (user-mode rootkit technique) |
| `registry_traces_deleted` | Trace removal | 0.50 | 2 | a whole registry key that records user activity (recent documents, Run box, typed paths and addresses, dialog history, Explorer searches, UserAssist, ShellBags, mounted drives, Office recent files) found deleted in a hive's free space; one count per key |
| `task_hidden_sd` | Persistence | 0.70 | 1 | a scheduled task's TaskCache\Tree key has no SD value while the hive's other tasks have one (hidden from schtasks and the Task Scheduler; the Tarrask technique) |
| `tool_execution_record` | Tool presence | 0.50 | 1 | UserAssist, Amcache or a 4688 process-creation event shows a known wiping / cleaning tool started (independent of Prefetch) |

## Combination

```
strength_i  = weight_i * (1 - exp(-count_i / k_i))
likelihood  = 1 - PRODUCT_i (1 - strength_i)
```

Bands: Low < 0.15 <= Moderate < 0.40 <= High < 0.70 <= Very high.

Why noisy-OR: independent weak signals should add up, a single strong
signal should dominate, and the result must stay in 0..1. Why saturation:
500 files extracted from a ZIP with whole-second times are one behaviour,
not 500 pieces of evidence.

## Ground truth

`scripts/make_af_fixture.py` plants one instance of every rule into a clean
NTFS volume and wraps it in an MBR disk. The test
`finds_planted_antiforensics` asserts that each rule fires on exactly the
planted file. New rules must add a planted case there. The Windows artifact
rules are planted in `scripts/make_win_fixture.py` (an SDelete rename chain
in the change journal, a hidden scheduled task and a deleted TypedURLs key in
alice's NTUSER.DAT, tested by `finds_windows_artifacts`), and the journal,
task and registry rules are also tested on built-up data (`journal_rules`,
`hidden_task_rule`, `deleted_trace_keys_rule`).

## Known limits

- The change journal is checked for SDelete-style renames and for being
  recreated; gaps inside the journal and its oldest record being much newer
  than expected are not scored yet.
- `wiped_content` cannot tell deliberate wiping from SSD TRIM.
- Weights are expert-set. Milestone 1 calibrates them against labelled
  datasets and publishes the calibration with each release.
