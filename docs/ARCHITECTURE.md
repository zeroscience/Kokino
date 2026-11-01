# Kokino Forensic Toolkit - Architecture and Roadmap

Kokino is a digital forensics platform by Zero Science Lab for disk and
incident-response investigations, to be released under an open-source license.
Its tagline: every finding, traceable to the byte. The goal is to be the fastest, most
verifiable and most usable open-source alternative to Autopsy, EnCase, FTK and
X-Ways for computer forensics.

Out of scope by design: network forensics (PCAP) and mobile device acquisition.
Mobile *extraction parsing* may be added later as plugins.

## 1. Principles

1. **Evidence is never modified.** Every evidence source is opened read-only.
   Hex "edits" are stored as an overlay in the case, never written to evidence.
2. **Every claim links to bytes.** Each finding, timeline entry and indicator
   carries the evidence id, volume offset and MFT record (or equivalent) it was
   derived from, so the examiner can jump to the raw bytes and verify.
3. **Explainable heuristics.** Scores (for example the anti-forensics likelihood)
   show every contributing indicator, its weight and its source. No black boxes.
4. **Deterministic and reproducible.** The same input with the same Kokino
   version gives the same output. Tool version and parser versions are recorded
   in the case and in reports.
5. **Hash-chained audit log.** Every examiner action (case created, evidence
   added, hash computed, analysis run, patch overlay, export) is appended to an
   audit log where each entry includes the SHA-256 of the previous entry.
6. **Memory-safe parsing.** Evidence is hostile input. Parsers are Rust. Any
   future C/C++ or Python plugin runs out-of-process.
7. **One engine, two faces.** The CLI (`kokino analyze`) and the GUI
   (`kokino serve`) call the same library code and produce identical results.
8. **Local first, team ready.** The GUI is served on 127.0.0.1 by default.
   Every examiner signs in with their own account, and every action in a case
   is attributed to that account. LAN mode (`--listen`) is HTTPS only.

## 2. Components

```
                +-------------------------------------------------+
  Browser  <--> | kokino-server  (axum, sessions, roles, TLS)     |
  (ui/)         |   REST API, background jobs, embedded UI assets |
                +---------------------+---------------------------+
  kokino CLI  ------------------------+
                                      |
                +---------------------v---------------------------+
                | kokino-analysis                                 |
                |   signatures, entropy, timeline (MACB),         |
                |   timestamp anomalies, anti-forensics scoring,  |
                |   summary / impact                              |
                +----------+------------------+-------------------+
                           |                  |
                +----------v------+   +-------v-------------------+
                | kokino-ntfs     |   | kokino-fat                |
                |  MFT walk, SI/FN|   |  FAT12/16/32, exFAT,      |
                |  ADS, data runs |   |  deleted entries          |
                +----------+------+   +---------------------------+
                           |
                +----------v--------------------------------------+
                | kokino-image                                    |
                |  EvidenceSource: raw, split raw (.001), VHD     |
                |  E01 (EWF v1), volume systems: MBR, GPT         |
                +----------+--------------------------------------+
                           |
                +----------v--------------------------------------+
                | kokino-core                                     |
                |  case store, audit log, hashing, time helpers   |
                +-------------------------------------------------+
```

| Crate | Responsibility |
|---|---|
| `kokino-core` | Case directory layout and members, hash-chained audit log, MD5/SHA-1/SHA-256 streaming hashing, FILETIME helpers, user accounts (Argon2id) |
| `kokino-image` | `EvidenceSource` (read-only `Read + Seek`), raw / split raw / VHD footer, MBR and GPT parsing, `SubReader` for a volume window |
| `kokino-ntfs` | Walks every MFT record including deleted ones, collects $STANDARD_INFORMATION and $FILE_NAME times, streams (ADS), data runs, resolves full paths and orphans |
| `kokino-fat` | FAT12/16/32 and exFAT: boot sector, FAT and allocation bitmap, directory walk with long names and exFAT entry sets, deleted entries (long names restored from the checksum, contiguous content recovery, reuse detection), cluster extents and free runs. Produces the same `FsEntry` rows as `kokino-ntfs` |
| `kokino-analysis::photo` | Photo forensics: JPEG marker parser and baseline Huffman decoder (DCT coefficients, luminance), EXIF reader, PNG/BMP readers, double-compression score, thumbnail comparison, libjpeg table identification, trailing data, LSB chi-square test; evidence-wide scan with a same-camera cross-check. The pixel views (error level, noise, clones...) run in the browser (`ui/js/photo.js`) |
| `kokino-analysis::hashsets` | Hash set store (one SQLite file per set, binary hashes per algorithm), importers (NSRL RDS v3/2.x, CSV, lists), per-evidence file hashing and set matching |
| `kokino-analysis` | `fs::Fs` opens NTFS or FAT behind one interface (scan, read, extents, free runs) for every consumer below. File signature detection and extension mismatch, Shannon entropy, MACB timeline, timestamp anomaly rules, anti-forensics indicators and score, summary |
| `kokino-server` | HTTP API, sessions and access control, TLS, job runner with progress, hex reads, patch overlay, case reports (`casereport`: one document model rendered to HTML and .docx), embedded `ui/` |
| `kokino-cli` | `kokino serve`, `kokino user`, `kokino analyze`, `kokino hash`, `kokino verify-audit` |

## 3. Accounts and access

| Role | Can do |
|---|---|
| Admin | Manage accounts and case members, open every case, everything an examiner can |
| Examiner | Create cases (becomes lead examiner), work assigned cases: add evidence, analyze, overlay edits, exports, reports |
| Reviewer | Open assigned cases read-only: summary, explorer, timeline, hex, audit log, HTML report. No exports, no edits |

Per-case access is `examiner` or `reviewer`; an account with the reviewer role
is always capped at reviewer. Unassigned cases answer 404, so their existence
is not revealed. The first admin is created through a one-time setup link
printed by `kokino serve`; `kokino user add|reset|role|disable|list` works on
the server console for recovery.

Mechanics:

- Passwords: Argon2id (RFC 9106 defaults), minimum 12 characters. Unknown
  usernames still cost a hash, so timing does not reveal valid accounts.
- Admin-created and admin-reset passwords are temporary; the user must choose
  their own before anything else works.
- Sessions: 192-bit random id in an HttpOnly, SameSite=Strict cookie (Secure
  over TLS), 60 minute idle and 12 hour absolute lifetime, held in memory (a
  restart signs everyone out). A password change ends the user's other
  sessions; disabling an account or resetting its password ends all of them.
- CSRF: state-changing requests need `x-requested-with: kokino`, which other
  sites cannot send without a CORS preflight that Kokino never grants.
- Brute force: backoff after 5 failures per username and 20 per client
  address (30 s doubling to 15 min); every failure and lockout is in the system
  audit log.
- Host header (or HTTP/2 :authority) must be a loopback name, an IP literal or a
  `--hostname`, which blocks DNS rebinding.
- LAN mode: any non-loopback `--listen` address forces HTTPS (TLS 1.2/1.3 via
  rustls). Bring a certificate with `--tls-cert/--tls-key`, or Kokino generates
  a self-signed one and prints its SHA-256 fingerprint so examiners can check
  the browser warning against it. HSTS is sent over TLS.

## 4. Case layout on disk

```
<cases-root>/.kokino/
  users.json           accounts: role, Argon2id hash, status (no plaintext)
  system-audit.jsonl   hash-chained sign-ins, failures, account and member changes
  tls/                 self-signed certificate for LAN mode (reused while names match)

<cases-root>/<case-id>/
  case.json            name, lead examiner, members and their access, created, tool version
  audit.jsonl          hash-chained examiner actions
  evidence/<eid>.json  path, size, format, MD5/SHA-1/SHA-256, acquisition notes
  analysis/<eid>.json  cached analysis result (deterministic, re-creatable)
  patches/<eid>.json   hex overlay edits (never applied to evidence)
  exports/             files exported by the examiner (hash recorded in audit)
```

The JSON analysis cache is the MVP store. Full-text search already lives in
SQLite: `index/<eid>.sqlite` holds an FTS5 table of extracted text chunks, each
with a map from text positions back to source offsets, plus the stream extents
needed to turn a file offset into an image offset (see
`kokino-analysis/src/textindex.rs`). Moving the rest of the case store to
SQLite is planned.

## 5. Anti-forensics likelihood

Each indicator has a weight `w` in (0, 1) representing how strongly it suggests
deliberate anti-forensic activity on its own. Indicators of the same kind are
grouped and saturate (100 timestomped files are stronger than 1, but not 100
times stronger). Groups are combined with a noisy-OR:

```
group_strength = w * (1 - exp(-count / k))
likelihood     = 1 - PRODUCT(1 - group_strength)
```

The UI always shows the per-indicator breakdown and the files behind it. The
number is a triage aid, not a conclusion. See `docs/ANTI-FORENSICS.md`.

## 6. Standards and validation

- Methodology aligned with NIST SP 800-86, ISO/IEC 27037 (identification,
  collection, acquisition, preservation) and ISO/IEC 27042 (analysis and
  interpretation), SWGDE best practices.
- Validation against public datasets with known answers (NIST CFReDS,
  Digital Corpora): done, results in [VALIDATION.md](../VALIDATION.md). To do:
  run it automatically on every release, and add DFRWS challenges.
- Parser fuzzing: done, method and results in [SECURITY.md](../SECURITY.md).
- To do: reproducible, signed release builds with an SBOM (CycloneDX).

## 7. Roadmap

The roadmap, with what is done and what comes next, is in
[ROADMAP.md](../ROADMAP.md).
