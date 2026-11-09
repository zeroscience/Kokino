# Roadmap

What Kokino does today and what comes next. Ideas and priorities are
welcome: open an issue on GitHub or write to lab@zeroscience.mk.

Every new parser is fuzzed before it ships ([SECURITY.md](SECURITY.md)) and
checked against public test images with known answers where they exist
([VALIDATION.md](VALIDATION.md)).

## In 1.2.5

- [x] Images: E01 (with stored-hash check), raw / dd, split raw, fixed VHD; MBR and GPT
- [x] NTFS: every MFT record, live and deleted, $SI and $FN times, alternate data streams, compressed files
- [x] FAT12, FAT16, FAT32 and exFAT: live and deleted files, long names, reuse warnings
- [x] Windows artifacts: registry, event logs, Prefetch, LNK, Jump Lists, ShimCache, UserAssist, Amcache
- [x] Browser history: Chrome, Edge, Brave, Opera, Vivaldi, Firefox
- [x] Full-text search, file carving, picture forensics, byte map and strings
- [x] Hash sets (NIST NSRL, known-bad lists) and hash analysis
- [x] Bookmarks, tags and court-ready case reports (HTML and Word)
- [x] Accounts, roles and hash-chained audit logs; lab server mode over HTTPS
- [x] Packages for Windows (MSI), Linux (.deb, .tar.gz) and macOS (DMG)

## In 1.2.6

### Linux: ext4 and Linux artifacts
- [x] ext2/3/4: inodes, extents, directories, deleted entries (recovered through the journal where possible)
- [x] Linux system summary: users and groups, logins (wtmp, btmp, lastlog), auth.log and syslog, journald, cron and systemd units, shell histories, SSH keys and known hosts, installed packages
- [x] Linux events on the timeline
- [x] Validation against the NIST CFReDS ext images (22 images, VALIDATION.md)
- [x] journald: compressed fields (XZ, LZ4, zstd) (1.3.0)
- [ ] Older journal copies of whole directories (names of files deleted long ago)

## Next

### Virtual and optical disks
- [x] VHDX and VMDK (virtual machines and cloud disks), plus dynamic and differencing VHD and snapshot chains (1.2.7)
- [x] VHDX log replay (1.3.1)
- [ ] ESXi snapshot formats (VMFSSPARSE, SESPARSE)
- [ ] Ex01 (EWF version 2)
- [x] ISO 9660 (Rock Ridge, Joliet, multisession history) and UDF (1.2.7)
- [ ] UDF virtual (VAT) and sparable partitions; UDF 2.50 metadata partition checked on a real disc
- [x] ISO and virtual disk files found inside evidence, extracted as evidence of their own (1.3.1)

## Later

### More file systems and volumes
- [x] HFS+ and APFS (macOS), with deleted files from old catalog and file-system tree nodes (1.2.7)
- [ ] APFS snapshots, encrypted volumes (FileVault) and free space (space manager)
- [ ] HFS+ and APFS checked on disks from real Macs (so far: images made with Apple's own tools)
- [ ] LZFSE decompression (decmpfs types 11 and 12)
- [x] macOS artifacts: property lists, accounts, launchd persistence, quarantine events, KnowledgeC (1.3.1)
- [x] macOS: Safari history and downloads, FSEvents (1.3.1)
- [ ] macOS artifacts: unified logs, checked on a real Mac image
- [ ] XFS
- [x] BitLocker with a password or recovery password; clear key (1.3.1)
- [x] BitLocker: startup keys (.BEK), carving decrypted volumes (1.3.1)
- [ ] BitLocker: TPM protectors (from a memory image), Windows Vista volumes
- [x] Volume Shadow Copies (1.3.1)
- [x] Shadow copies inside BitLocker volumes (1.3.1)

### Deeper NTFS and Windows
- [x] $UsnJrnl (change journal: every file change, grouped per round, paths rebuilt from the journal for folders that are gone) (1.2.8)
- [x] Names of deleted files left in folder index slack ($I30) and in $LogFile (1.2.8)
- [x] ShellBags (UsrClass.dat and NTUSER.DAT) (1.2.8)
- [ ] $LogFile transactions in full (redo/undo of MFT changes)
- [x] SRUM (network and resource use per program, connections) with an ESE database reader (1.2.8)
- [x] BAM/DAM (1.2.8)
- [x] WebCache of Internet Explorer 10 and 11 and the old Edge (1.3.1)
- [ ] SRUM energy, push notification and app timeline tables; Windows Search (Windows.edb)
- [x] Internet Explorer 4 to 9 history, cache and downloads (index.dat), with deleted entries and records carved from free space (1.2.9)
- [x] Internet Explorer cookies (index.dat and the cookie text files) (1.3.0)
- [x] Scheduled tasks (task files and TaskCache, hidden tasks flagged) (1.2.9)
- [x] Deleted registry keys and values from free cells in the hives (1.2.9)
- [x] Registry transaction logs (.LOG1/.LOG2) applied to hives that were not cleanly saved (1.3.0)
- [x] Legacy .evt event logs (Windows NT to 2003), with Windows XP profile paths (1.3.0)

### Content
- [x] Email: mbox mailboxes (Thunderbird, /var/mail) and .eml files (1.3.0)
- [x] Email: Outlook PST and OST (1.3.1)
- [x] Email: RTF-only Outlook message bodies (1.3.1)
- [x] Email: Apple Mail .emlx (1.3.1)
- [ ] Email: deleted PST items (recovered from the file's free blocks)
- [x] Text from legacy Office files (DOC, XLS, PPT), Outlook .msg and RTF (1.3.0)
- [ ] Carving of fragmented files

### Workflow
- [x] Triage collections: Velociraptor and KAPE ZIPs, KAPE VHDX output (1.3.1)
- [x] UAC collections (tar, tar.gz) (1.3.1)
- [x] Triage collections as plain folders (1.3.1)
- [x] JSON and CSV exports of every list, in the GUI and with `kokino export` (1.3.0)
- [ ] Validation suite run automatically on every release
- [x] Release SBOM (CycloneDX) and signed build provenance (1.3.1)
- [ ] Code-signed Windows and macOS packages
- [ ] Plugin interface

### Ideas
- [ ] Optional AI summaries that only cite linked evidence
- [x] Cross-evidence correlation (1.3.1)
