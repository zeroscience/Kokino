# Roadmap

What Kokino does today, what comes next and what each next step needs.
Ideas and priorities are welcome: open an issue on GitHub or write to
lab@zeroscience.mk.

Every new parser is fuzzed before it ships ([SECURITY.md](SECURITY.md)) and
checked against public test images with known answers where they exist
([VALIDATION.md](VALIDATION.md)).

## Status: 1.6

1.5.0 and 1.6.0 finished most of what could be built without new test data. What is
left below mostly waits for samples: disks from real Macs, encrypted APFS
volumes, Windows Search databases, XFS and Ex01 images. Security reports
([SECURITY.md](SECURITY.md)) and wrong results (an artifact read
incorrectly, a crash on real evidence) are always fixed first.

Bug reports help most with a sample: the smallest image or file that shows
the problem, or, when the evidence cannot be shared, the error text, the
Kokino version and what the file system or artifact is.

## Done

### Images and volumes
- [x] E01 (with stored-hash check), raw / dd, split raw; MBR and GPT (1.2.5)
- [x] VHD (fixed, dynamic, differencing), VHDX with log replay, VMDK (flat, sparse, stream, split, snapshot chains) (1.2.7, 1.3.1)
- [x] ESXi snapshots: VMFSSPARSE and SESPARSE (1.5.0)
- [x] ISO 9660 (Rock Ridge, Joliet, multisession history) and UDF (1.2.7)
- [x] UDF sparable partitions (DVD-RW, CD-RW) and virtual partitions (CD-R, DVD-R) through the VAT, with files removed between sessions (1.5.0)
- [x] Disk images and ISOs found inside evidence, extracted as evidence of their own (1.3.1)
- [x] BitLocker with a password, recovery password, startup key (.BEK) or clear key; carving decrypted volumes (1.3.1)
- [x] Volume Shadow Copies, including inside BitLocker volumes (1.3.1)
- [x] Triage collections: Velociraptor and KAPE ZIPs, KAPE VHDX output, UAC tar and tar.gz, plain folders (1.3.1)

### File systems
- [x] NTFS: every MFT record, live and deleted, $SI and $FN times, alternate data streams, compressed files (1.2.5)
- [x] NTFS: $UsnJrnl, deleted names in $I30 slack and $LogFile (1.2.8)
- [x] FAT12, FAT16, FAT32 and exFAT (1.2.5)
- [x] ext2/3/4 with deleted entries recovered through the journal (1.2.6)
- [x] ext3/4: names of files deleted long ago, from older copies of folders in the journal (1.5.0)
- [x] HFS+ and APFS with deleted files from old tree nodes (1.2.7)

### Artifacts
- [x] Windows: registry (deleted keys, transaction logs), event logs (.evtx and .evt), Prefetch, LNK, Jump Lists, ShimCache, UserAssist, Amcache, ShellBags, BAM/DAM, SRUM, scheduled tasks (1.2.5 to 1.3.0)
- [x] SRUM: app timeline (time in focus, keyboard and mouse input), push notifications, battery and long-term energy (1.5.0)
- [x] Linux: accounts, logons, auth.log, syslog, journald (compressed fields), cron, systemd, shell histories, SSH keys, packages (1.2.6, 1.3.0)
- [x] macOS: property lists, accounts, launchd persistence, quarantine events, KnowledgeC, Safari, FSEvents (1.3.1)
- [x] Browsers: Chrome, Edge, Brave, Opera, Vivaldi, Firefox, Safari, Internet Explorer 4 to 11 (index.dat, WebCache, cookies), with deleted and carved records (1.2.5 to 1.3.1)
- [x] Email: mbox, .eml, Outlook PST and OST (RTF bodies included), Apple Mail .emlx (1.3.0, 1.3.1)
- [x] Outlook: deleted messages recovered from unused entries of the node index (1.6.0), and from the file's free space by their block trailers (1.6.1)
- [x] Text from Office (old and new), PDF, Outlook .msg and RTF for search (1.3.0)

### Analysis and workflow
- [x] Timeline, full-text search, file carving, picture forensics, byte map and strings (1.2.5)
- [x] Hash sets (NIST NSRL, known-bad lists) and hash analysis (1.2.5)
- [x] Anti-forensics indicators and a scored likelihood (1.2.5)
- [x] Bookmarks, tags and case reports (HTML and Word) (1.2.5)
- [x] Accounts, roles and hash-chained audit logs; lab server mode over HTTPS (1.2.5)
- [x] JSON and CSV exports of every list, in the GUI and with `kokino export` (1.3.0)
- [x] Cross-evidence correlation (1.3.1)
- [x] Case timeline: every evidence item of a case on one timeline (1.4.0)
- [x] Watchlist: hashes, IP addresses, domains, email addresses and file names searched across a whole case (1.4.0)
- [x] Golden results: every test image's key numbers checked on every commit, on Windows, Linux and macOS (1.4.0)
- [x] Watchlists from STIX 2.1 and MISP exports, IP networks, and each sweep compared with the last (1.5.0)
- [x] Plugins: separate programs for artifacts Kokino does not read, each run audited with the plugin's fingerprint (1.5.0)
- [x] Carving: JPEGs in two pieces joined again (1.5.0), in three pieces (1.6.0)
- [x] Plugin rows on the timelines and in the watchlist (1.6.0)
- [x] NIST CFReDS validation every week in CI, against recorded numbers (1.6.0)
- [x] Carving: PNGs in two pieces, through their chunk CRCs (1.6.0)
- [x] Carving: ZIP, Office and OpenDocument files in two pieces, through the central directory and the entry CRC (1.6.1)
- [x] Carving: PDFs in two pieces, through the cross-reference table and the stream checksums (1.6.1)
- [x] `kokino plugin-test` and a guide for plugin authors (1.6.0)
- [x] Dates day first (dd-mm-yyyy) in the GUI, reports and summaries; a website (1.5.0)
- [x] Release SBOM (CycloneDX) and signed build provenance (1.3.1)

## What comes next

In order of priority. "Needs" says what has to exist before the work can
start or be trusted; most items are blocked on test data rather than code.

### 1. Correctness on real evidence
- [ ] **HFS+ and APFS on disks from real Macs.** Needs: images of real Mac disks (current tests use images made with Apple's tools). Risk: the parsers are complete for what the specification describes; real disks show what it does not.
- [ ] **macOS on a real Mac image**: KnowledgeC, FSEvents and launchd across macOS versions. Needs: the same images.
- [ ] **UDF 2.50 metadata partition on a real disc** (Blu-ray). Needs: a disc image.

### 2. Encrypted and compressed data
- [ ] **APFS: FileVault, snapshots and free space.** Needs: an encrypted test image with a known password; the keybag format (documented by Apple and in libfsapfs).
- [ ] **LZFSE** (APFS and HFS+ compression types 11 and 12). Needs: a small, fuzzed decoder; Apple's reference code is open source (BSD).
- [ ] **BitLocker: TPM protectors** from a memory image, and Windows Vista volumes. Needs: a memory image and a Vista image.
- [ ] **Ex01** (EWF version 2). Needs: sample files (libewf has some).

### 3. Deeper Windows
- [ ] **Windows Search** (Windows.edb): file names, contents and times the indexer kept, also for deleted files. The ESE reader exists (SRUM and WebCache use it). Needs: a test database.
- [ ] **$LogFile in full**: redo and undo of MFT changes (what a file looked like before it changed). Needs: a large but well-documented effort (NTFS internals, libfsntfs notes).
- [ ] **SRUM on a real computer's database**: the app timeline, push, battery and energy tables are checked on databases written by Windows' own engine. Needs: a SRUM database copied from a real computer (admin rights and a shadow copy).

### 4. More formats
- [ ] **XFS** (Red Hat and its derivatives default to it). Needs: test images (made with mkfs.xfs) and a parser comparable to ext's.
- [ ] **ESXi snapshots from a real host**: VMFSSPARSE and SESPARSE are checked on images built to QEMU's reading of the formats. Needs: snapshots from an ESXi host.
- [ ] **Written CDs and DVDs from real drives**: UDF sparable and virtual partitions are checked on images built from the specification. Needs: images of real CD-R, DVD-R and DVD-RW discs.
- [ ] **macOS unified logs** (tracev3).
- [ ] **Carving of other fragmented files** (PNG in three pieces, ZIP, Office and PDF documents in three or more, linearized PDFs and PDFs with cross-reference streams), and JPEGs in four or more pieces or progressive JPEGs.

### 5. Workflow
- [ ] **Code-signed Windows and macOS packages.** Needs: a code-signing certificate and an Apple Developer ID; no code.
- [ ] **Optional AI summaries** that only cite linked evidence, off by default and never sending evidence anywhere without the examiner's choice.

Nothing above is promised for a date. If one of these matters to a case you
work on, say so: that moves it up.
