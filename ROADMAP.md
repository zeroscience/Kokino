# Roadmap

What Kokino does today, what comes next and what each next step needs.
Ideas and priorities are welcome: open an issue on GitHub or write to
lab@zeroscience.mk.

Every new parser is fuzzed before it ships ([SECURITY.md](SECURITY.md)) and
checked against public test images with known answers where they exist
([VALIDATION.md](VALIDATION.md)).

## Status: 1.4 and a pause

1.4.0 is the last feature release for a while. Development pauses for a
few months after it; during the pause, security reports
([SECURITY.md](SECURITY.md)) and wrong results (an artifact read
incorrectly, a crash on real evidence) are still handled and fixed in 1.4.x
releases. New features wait for the list below.

Bug reports help most with a sample: the smallest image or file that shows
the problem, or, when the evidence cannot be shared, the error text, the
Kokino version and what the file system or artifact is.

## Done

### Images and volumes
- [x] E01 (with stored-hash check), raw / dd, split raw; MBR and GPT (1.2.5)
- [x] VHD (fixed, dynamic, differencing), VHDX with log replay, VMDK (flat, sparse, stream, split, snapshot chains) (1.2.7, 1.3.1)
- [x] ISO 9660 (Rock Ridge, Joliet, multisession history) and UDF (1.2.7)
- [x] Disk images and ISOs found inside evidence, extracted as evidence of their own (1.3.1)
- [x] BitLocker with a password, recovery password, startup key (.BEK) or clear key; carving decrypted volumes (1.3.1)
- [x] Volume Shadow Copies, including inside BitLocker volumes (1.3.1)
- [x] Triage collections: Velociraptor and KAPE ZIPs, KAPE VHDX output, UAC tar and tar.gz, plain folders (1.3.1)

### File systems
- [x] NTFS: every MFT record, live and deleted, $SI and $FN times, alternate data streams, compressed files (1.2.5)
- [x] NTFS: $UsnJrnl, deleted names in $I30 slack and $LogFile (1.2.8)
- [x] FAT12, FAT16, FAT32 and exFAT (1.2.5)
- [x] ext2/3/4 with deleted entries recovered through the journal (1.2.6)
- [x] HFS+ and APFS with deleted files from old tree nodes (1.2.7)

### Artifacts
- [x] Windows: registry (deleted keys, transaction logs), event logs (.evtx and .evt), Prefetch, LNK, Jump Lists, ShimCache, UserAssist, Amcache, ShellBags, BAM/DAM, SRUM, scheduled tasks (1.2.5 to 1.3.0)
- [x] Linux: accounts, logons, auth.log, syslog, journald (compressed fields), cron, systemd, shell histories, SSH keys, packages (1.2.6, 1.3.0)
- [x] macOS: property lists, accounts, launchd persistence, quarantine events, KnowledgeC, Safari, FSEvents (1.3.1)
- [x] Browsers: Chrome, Edge, Brave, Opera, Vivaldi, Firefox, Safari, Internet Explorer 4 to 11 (index.dat, WebCache, cookies), with deleted and carved records (1.2.5 to 1.3.1)
- [x] Email: mbox, .eml, Outlook PST and OST (RTF bodies included), Apple Mail .emlx (1.3.0, 1.3.1)
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
- [x] Release SBOM (CycloneDX) and signed build provenance (1.3.1)

## After the pause

In order of priority. "Needs" says what has to exist before the work can
start or be trusted; most items are blocked on test data rather than code.

### 1. Correctness on real evidence
- [ ] **HFS+ and APFS on disks from real Macs.** Needs: images of real Mac disks (current tests use images made with Apple's tools). Risk: the parsers are complete for what the specification describes; real disks show what it does not.
- [ ] **macOS on a real Mac image**: KnowledgeC, FSEvents and launchd across macOS versions. Needs: the same images.
- [ ] **UDF 2.50 metadata partition on a real disc** (Blu-ray). Needs: a disc image.
- [ ] **CFReDS validation in CI.** The 83 NIST images are checked by hand before each release ([VALIDATION.md](VALIDATION.md)); a scheduled CI job could download and check them. Needs: a way to cache the images in CI (each is about 1 GB expanded).

### 2. Encrypted and compressed data
- [ ] **APFS: FileVault, snapshots and free space.** Needs: an encrypted test image with a known password; the keybag format (documented by Apple and in libfsapfs).
- [ ] **LZFSE** (APFS and HFS+ compression types 11 and 12). Needs: a small, fuzzed decoder; Apple's reference code is open source (BSD).
- [ ] **BitLocker: TPM protectors** from a memory image, and Windows Vista volumes. Needs: a memory image and a Vista image.
- [ ] **Ex01** (EWF version 2). Needs: sample files (libewf has some).

### 3. Deeper Windows
- [ ] **Windows Search** (Windows.edb): file names, contents and times the indexer kept, also for deleted files. The ESE reader exists (SRUM and WebCache use it). Needs: a test database.
- [ ] **$LogFile in full**: redo and undo of MFT changes (what a file looked like before it changed). Needs: a large but well-documented effort (NTFS internals, libfsntfs notes).
- [x] **SRUM**: app timeline (time in focus, keyboard and mouse input), push notification, battery and long-term energy tables. Still to do: a check on a real computer's database.
- [ ] **Deleted PST items** from the file's free blocks.

### 4. More formats
- [ ] **XFS** (Red Hat and its derivatives default to it). Needs: test images (made with mkfs.xfs) and a parser comparable to ext's.
- [ ] **ESXi snapshots** (VMFSSPARSE, SESPARSE).
- [ ] **UDF virtual (VAT) and sparable partitions** (written CDs and DVDs).
- [x] **Older journal copies of whole directories** on ext3 and ext4 (names of files deleted long ago, also when their inode was reused).
- [ ] **macOS unified logs** (tracev3).
- [x] **Carving of JPEGs in two pieces** (bifragment gap carving, kept only when the joined picture decodes exactly).
- [ ] **Carving of other fragmented files**, and JPEGs in three or more pieces or progressive JPEGs.

### 5. Workflow
- [x] **Watchlist from STIX 2.1 and MISP exports**, IP networks (CIDR), and each sweep compared with the previous one (what is new).
- [ ] **Code-signed Windows and macOS packages.** Needs: a code-signing certificate and an Apple Developer ID; no code.
- [ ] **Plugin interface** for artifacts Kokino does not read yet (a parser as a separate program reading a file and writing JSON). Needs: a stable output format first.
- [ ] **Optional AI summaries** that only cite linked evidence, off by default and never sending evidence anywhere without the examiner's choice.

Nothing above is promised for a date. If one of these matters to a case you
work on, say so: that moves it up.
