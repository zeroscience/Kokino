# Security

Kokino reads evidence that someone may have prepared to break forensic
tools, and in lab mode it serves several examiners over the network. This
page says how to report a problem, how Kokino defends itself, and what has
been tested so far, with numbers.

## Reporting a vulnerability

Please write to **lab@zeroscience.mk** and do not open a public issue.

Helpful to include:

- the Kokino version and build (Help > About), and the operating system;
- what you did and what happened (a crash, a hang, memory use, a wrong
  result, access you should not have had);
- if a file triggers it, the smallest file you can share. Never send real
  case data: if the problem only shows on real evidence, describe it and we
  will work out a way to reproduce it.

We confirm receipt, keep you informed while we fix it, and credit you in the
changelog unless you prefer otherwise. Fixes go into the next release; there
are no separate patches for older versions.

## Threat model in short

| Who or what | What we assume | What Kokino does |
|---|---|---|
| Evidence images and the files inside them | Hostile: crafted to crash, hang or exhaust the examiner's machine, or to hide data | Read-only access; every parser bounds memory and time by the size of its input; `unsafe` Rust is forbidden in every Kokino crate; parsers fuzzed (below) |
| Databases inside evidence (browser history) | Hostile SQL schema (views, triggers) and corrupt pages | SQLite in defensive mode, `trusted_schema=OFF`, cell size checks, no memory mapping, a time limit per database, views standing in for tables refused |
| BitLocker passwords and recovery passwords | Secret | Used once to find the volume key, never stored or logged; the volume key is kept in the case's `keys` folder and never returned by the API; every unlock and every failed attempt is in the case audit log |
| Signed-in examiners and reviewers | Honest but limited to their cases and role | Per-case membership and roles enforced on the server; every action in a hash-chained audit log |
| Other machines on the lab network | Untrusted | LAN mode is HTTPS only; sign-in required; CSRF header and Host check on every request |
| Other tabs in the examiner's browser | Untrusted | Strict Content-Security-Policy; HttpOnly, SameSite=Strict session cookies |
| Plugins | Trusted code chosen by whoever runs the server | Off unless the server is started with `--plugins <folder>`; started only by examiners with write access; given a copy of one file at a time, never the evidence; no input, a reduced environment, a time limit (the whole process tree is stopped) and limits on output; every run audited with the SHA-256 of the plugin's files. A plugin can still do anything the server's account can: install only plugins you have read |

## Fuzzing the parsers

Every parser that reads bytes from evidence was fuzzed with a purpose-built
mutation fuzzer (`crates/kokino-fuzz`), on stable Rust:

- **Inputs:** small valid samples of each format (the test fixtures, plus
  seeds made by `scripts/make_fuzz_seeds.py`), changed by 1 to 8 stacked
  mutations: bit flips, random bytes, boundary values (0, 0x7F, 0x80, 0xFF,
  0x7FFF_FFFF, 0xFFFF_FFFF and so on, little and big endian), filled
  ranges, copied blocks, truncation, deletion and insertion. Mutations are
  aimed mostly at the non-zero bytes, where the structures are.
- **What counts as a failure:** a panic (integer overflow included: the
  fuzz build checks arithmetic, which release builds do not), a stack
  overflow on a 2 MiB stack (the size of the server's worker threads), one
  allocation over 256 MiB or more than 1 GiB in use from a small input, and
  any input that takes more than 20 seconds.
- **Reproducible:** each input is a pure function of (run seed, input
  number), so every failure is saved and replayed exactly.
  `crates/kokino-fuzz/regress.txt` lists them all, and
  `cargo test -p kokino-fuzz` replays them on every test run.

### Targets and results

| Target | What it covers | Round 1 (5 min) | Round 2 (20 min) | Round 3 (10 min) | Inputs in all | Distinct problems found |
|---|---|--:|--:|--:|--:|---|
| `volume` | MBR, extended and GPT partition tables, file system detection | 14,763 | 118,598 | 60,270 | 193,631 | none |
| `ntfs` | NTFS: boot sector, every MFT record, attributes and attribute lists, data runs, stream reads, free-space bitmap | 59,258 | 90,332 | 43,555 | 193,145 | 3 (hang, memory, panic) |
| `fat` | FAT12, FAT16, FAT32 and exFAT: boot sectors, FAT chains, directories, deleted entries, long names | 26,305 | 236,537 | 123,757 | 386,599 | 4 (memory, overflow) |
| `ewf` | E01 (EWF) images: sections, chunk tables, zlib chunks, stored hashes | 1,825 | 24,544 | 16,317 | 42,686 | 1 (overflow) |
| `registry` | Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, Amcache): cells, key and value lists, the whole key tree | 498,617 | 13,864,683 | 8,879,174 | 23,242,474 | 1 (hang) |
| `evtx` | Windows event logs: chunks, binary XML templates and substitutions | 115,682 | 2,399,729 | 673,160 | 3,188,571 | none |
| `lnk` | LNK shortcuts and shell item lists | 27,451,670 | 5,205,541 | 14,065,882 | 46,723,093 | none |
| `prefetch` | Prefetch files, including Windows 10/11 compressed ones | 5,492,226 | 17,137,541 | 4,574,931 | 27,204,698 | none |
| `jumplist` | Jump Lists: OLE compound files (automatic) and custom destinations | 112,454 | 9,454,092 | 10,774,058 | 20,340,604 | 1 (memory) |
| `xpress` | LZXPRESS Huffman decompression | 157,035 | 1,262,012 | 902,504 | 2,321,551 | none |
| `doc` | Text extraction: ZIP (nested), Word, Excel, PowerPoint, OpenDocument, GZIP, PDF | 8,186,311 | 6,616,068 | 6,774,250 | 21,576,629 | 1 (panic) |
| `photo` | Picture forensics: JPEG decoder, EXIF and thumbnails, quantization tables, PNG, BMP | 167,622 | 2,404,315 | 629,991 | 7,614,505 | 5 (overflow, hang, crash) |
| `carve` | File carving: header and end detection for every carved format | 748,261 | 5,243,806 | 13,246,883 | 19,238,950 | 1 (panic) |
| `browser` | Browser history: Chromium and Firefox SQLite databases | 1,467 | 49,437 | 6,129 | 57,033 | none (1 hang found by review) |
| `strings` | Strings and byte map | 578,058 | 16,647,346 | 4,912,367 | 22,137,771 | none |
| **All** | 15 targets | **43,611,554** | **80,754,581** | **65,683,228** | **194,461,940** | **17, all fixed** |

Each round ran all 15 targets at once, one process each, on an 8-core workstation (Windows 10). Rounds 2 and 3 ran after the fixes from the rounds before them, with new random seeds; two more 5-minute photo rounds followed the JPEG fixes: the first (2,244,470 inputs) found one more crash, fixed, and the second (2,168,107 inputs) found nothing. Those are included in the photo total. Fast targets (LNK, Prefetch, strings) reach millions of inputs a minute; whole-volume targets (NTFS, FAT, EWF, browser databases) parse a full image or database per input and run thousands.

Follow-up rounds after the validation work (VALIDATION.md) added NTFS
decompression and new checks in the NTFS and FAT walkers: a new `lznt1`
target ran 1,938,929 inputs with no finding, and 10 more minutes each on
`ntfs` (190,379 inputs) and `fat` (470,899) found one more crash in the
`ntfs` crate, number 19 below. That brought the total to 197,062,147 inputs
and 18 distinct problems found by fuzzing.

The ext2/3/4 reader and the Linux artifact parsers were fuzzed before they
shipped (in 1.2.6):

| Target | What it covers | Round 1 (10 min) | Round 2 | Inputs in all | Distinct problems found |
|---|---|--:|--:|--:|---|
| `ext` | ext2, ext3 and ext4: superblock, group descriptors, inodes, extent trees, indirect blocks, directories and their slack, orphan scan, journal copies, block bitmap | 311,223 | 710,567 (25 min) + 310,635 (10 min, after the validation fixes) | 1,332,425 | 1 (memory) |
| `linuxlogs` | systemd journal files, wtmp/btmp, syslog lines and their dates, TZif time zones and POSIX rules, apt history, DHCP leases, dpkg status, shell command rules | 9,505,147 | 19,436,254 (15 min) | 28,941,401 | 3 (overflow) |

Virtual disks, optical media and Mac disks (1.2.7):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `vdisk` | VHD dynamic and differencing, VHDX (headers, region table, metadata, block table, sector bitmaps), VMDK (descriptor, sparse grain directory and tables, streamOptimized grains and footer); reads across the whole disk | 10 + 20 + 15 min | 203,015 | none (one 20 s stall in round 2 did not reproduce: the input replays in 9 ms; most likely the antivirus scanning the temporary file this target writes) |
| `optical` | ISO 9660 descriptors, sessions, directory records, Rock Ridge and Joliet; UDF anchor, volume descriptors, partition maps, file set, file entries, allocation descriptors and directory entries | 15 + 15 min | 4,318,442 | 3 (overflow, out-of-range reads) |
| `mac` | HFS+ volume header, catalog, extents and attributes B-trees, journal scan; APFS checkpoints, object maps, file-system trees, old-node scan; decmpfs with zlib and LZVN | 3 x 15 min | 232,151 | 3 (overflows, out-of-range read) |

Deeper NTFS and Windows (1.2.8):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `ntfs` | again, now that the walk also reads every folder's index slack and $LogFile for names | 10 min | 196,853 | none |
| `indx` | folder index (INDX) records with their fixups, deleted folders' index roots, $LogFile record pages; the name carver with a fixed folder and with any parent accepted | 10 min | 35,329,154 | none |
| `usn` | change journal records (versions 2, 3 and 4), split across two buffers as the reader hands them over, grouping into changes, $Max | 10 min | 8,954,455 | none |
| `shellbags` | BagMRU trees in a hive, every shell item kind (root, drive, folder with extension blocks, network, ZIP, URI, control panel, delegate) | 10 min | 15,785,595 | none |
| `ese` | ESE databases (seeds written by esent.dll, 4 and 32 KiB pages): header, pages and tags, B+ trees, catalog, every table's records, long values, 7-bit and XPRESS decompression, and the SRUM reader on top | 15 min | 532,995 | none |
| `registry` | again, as BAM and DAM are read from the SYSTEM hive | 5 min | 26,319,961 | none |
| `ese` | again, after the check against a real SRUM database: every branch level of deeper B+ trees, with a three-level tree as an extra seed | 10 min | 291,544 | none |

Scheduled tasks (1.2.9):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `task` | task XML (elements, entities, triggers, actions), the TaskCache Actions and DynamicInfo blobs, and TaskCache read from a SOFTWARE hive | 10 min | 19,733,957 | none |

Internet Explorer index.dat (1.2.9):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `iecache` | index.dat (header, hash tables, allocation bitmap, URL, LEAK and REDR records, history titles, cache headers, IE 9 download entries), the conversion of each kind of file into web activity, and records read from free space at every 128-byte boundary | 10 + 10 min | 21,653,615 | 1: a record cut off by the end of the file, with its data offset past the bytes that exist, was sliced out of range (panic); fixed |

Deleted registry keys (1.2.9):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `registry` | again, now also searching every hive bin's free space for deleted keys and values, rebuilding their paths and reading their value lists (the seed hives hold deleted keys) | 10 min | 18,700,883 | none |

Exports, legacy Office text and registry logs (1.3.0):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `doc` | again, now with Word, Excel and PowerPoint 97-2003, Outlook .msg and RTF seeds (piece tables, shared strings split over CONTINUE records, text atoms, property sets, RTF groups and escapes) | 10 min | 37,498,697 | none |
| `reglog` | registry transaction logs: base blocks, new-format log entries (Marvin32 checksums, dirty page lists, sequence order across two logs) and old-format dirty sector maps, applied to a dirty hive, then the hive read | 10 min | 58,565,421 | none |

Legacy event logs, email and journald compression (1.3.0):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `evt` | legacy .evt logs: header, records found at any 4-byte boundary, records wrapping around the end of the buffer, strings, SIDs | 10 min | 30,689,834 | none |
| `mail` | mbox splitting, headers and encoded words, MIME parts (nested, attached messages), quoted-printable, base64, charsets, and the search text built from messages and their attachments | 10 min | 7,542,816 | none |
| `journalz` | journald's compressed fields: XZ, LZ4 (Kokino's own decoder) and zstd, from the input and from offsets inside it | 10 min | 45,374,291 | none |
| `linuxlogs` | again, with a journal holding XZ and LZ4 fields | 10 min | 7,898,202 | none |

Shadow copies, BitLocker, triage collections, VHDX logs, Outlook and macOS (1.3.1):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `zip` | ZIP collections read as file systems (central directory, ZIP64, time fields, Velociraptor's escaped names) and nested image detection | 3 x 10 min | 5,383,514 | 2: a crash on escaped names next to multi-byte characters, and runaway memory from claimed sizes; fixed |
| `vss` | Shadow copy catalogs, block lists (full, overlay, forwarded blocks) and snapshot reads across the stores | 3 x 10 min | 9,887,067 | 2: integer overflows on offsets near 2^64, and a stack overflow from a catalog listing thousands of stores; fixed |
| `bde` | BitLocker volume headers, FVE metadata blocks and entries, key protectors, key unwrapping (clear key, startup key files), and the decrypting reader for every method | 3 x 10 min | 4,459,482 | 1: an integer overflow on a boot sector copy offset near 2^64; fixed |
| `tar` | tar and tar.gz collections (UAC): headers and checksums, base-256 sizes, GNU long names, PAX records, hard links, reads | 10 min | 4,169,869 | none |
| `vdisk` | again, with a VHDX whose log holds writes to replay (entries, descriptors, data sectors, the circular log) | 10 min | 36,659 | none |
| `pst` | Outlook PST and OST: header, node and block B-trees, blocks (decoding, inflating), data and subnode trees, heaps, property and table contexts, folders, messages rendered as RFC 822 and parsed back | 2 x 10 min + 5 min | 8,102,508 | 2: a crash on dates outside years 0 to 9999, and a read past the end of a one-byte subnode block; fixed (the third round, with compressed RTF bodies, found nothing) |
| `plist` | Apple property lists, binary (offset tables, object references, counts, every object type) and XML, every value walked | 10 + 5 min | 1,229,272 | 1: an integer overflow converting a huge date; fixed (found in a first round stopped to fix it and not counted) |
| `fsevents` | macOS FSEvents files: gzip, pages of versions 1 to 3, records, flags | 10 min | 50,215,572 | none |
| `webcache` | WebCache (Internet Explorer 10 and 11, old Edge): the ESE database, its Containers table and every container read into web activity | 10 min | 743,157 | none |
| `mail` | again, with Apple Mail .emlx (byte count, message, flags property list) | 5 min | 4,982,274 | none |

The first `vss` round ran an optimized build without overflow checks and
found nothing; the same inputs on the `fuzz` profile (overflow checks on)
found the overflows within seconds, and the stack overflow later. That
round and the first `bde` round were stopped to fix what they found and are
not counted in the inputs; the rounds after the fixes found nothing.

The `vdisk` target writes each input to a file (virtual disks are opened
by path), so it runs far fewer inputs than the others.

Watchlist (1.4.0):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `ioc` | the watchlist parser: indicator kinds, defanged forms, notes, URL hosts, domain and IP comparison | 10 min | 13,628,459 | 1: an IPv4-mapped IPv6 address (::ffff:192.0.2.1) did not match itself, so such an indicator found nothing; fixed (found in a first round stopped to fix it and not counted) |

STIX and MISP watchlists, SRUM app timeline, push and battery tables (1.5.0):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `ioc` | again, with STIX 2.1 bundles and MISP events as seeds, IP networks, and every value looked up as a hash, file, URL, host, mail field and address | 10 min | 5,076,839 | 1: a crash on a STIX pattern with a multi-byte character just before an object name; fixed (found in a first round stopped to fix it and not counted) |
| `ese` | again, with the SRUM fixtures holding the App Timeline Provider, push notification and energy tables | 10 min | 272,618 | 1: integer overflows adding up per-program totals (bytes sent, received, read and written, processor cycles, focus and input time) from huge values; fixed (same first round) |

That first round also stopped on a wrong assumption in the fuzzer's own
check (an IP network does not "match itself" as an address); the check was
corrected and is not counted as a problem.

ext folder names from the journal, JPEGs in two pieces, SRUM long-term energy (1.5.0):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `ext` | again, with every metadata block the journal holds and older copies of directory blocks parsed for names | 10 min | 235,678 | none |
| `carve` | again, with the JPEG join: the header walk, sectors classified as JPEG data or not, the search for the second piece and the strict decode check, with a split picture as an extra seed | 10 min | 43,267,718 | none |
| `ese` | again, with the long-term energy table | 10 min | 192,933 | none |

UDF sparable and virtual partitions, ESXi snapshots (1.5.0):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `optical` | again, with a sparable partition (sparing table) and a virtual partition (VAT found from the end of the image) as seeds | 10 min | 1,335,667 | none |
| `vdisk` | again, with ESXi VMFSSPARSE and SESPARSE extents (opened through a descriptor naming them) as seeds | 10 min | 45,992 | none |

Plugins and UDF sessions (1.5.0):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `plugin` | what a plugin prints (one object with rows and notes, or one row per line) and the patterns that choose its files | 10 min | 32,622,403 | none |
| `optical` | again, with a CD-R image holding two sessions' VATs (files of the earlier session walked through its own VAT) | 10 min | 1,140,617 | none |

JPEGs in three pieces (after 1.5.0):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `carve` | again, with middle pieces kept while looking for the last one and three-piece joins | 10 min | 71,875,548 | none |

PNGs in two pieces and deleted PST items (after 1.5.0):

| Target | What it covers | Rounds | Inputs in all | Distinct problems found |
|---|---|---|--:|---|
| `pst` | again, with the unused slots of node and block index pages read for deleted messages | 10 min | 2,133,614 | none |
| `carve` | again, with the PNG join (chunk walk with CRCs, break points, second piece search) | 10 min | 44,752,447 | none |

In all: 867,947,761 inputs over 41 targets, and 40 distinct problems
found by fuzzing, all fixed.

### What was found and fixed

| # | Parser | Problem | Found by | Cause | Fix |
|---|---|---|---|---|---|
| 1 | NTFS | Hang and runaway memory | Fuzzing | The MFT size declared in `$MFT` was trusted: a few changed bytes claimed billions of records | Bounded by the size of the volume |
| 2 | NTFS | Hang | Fuzzing | The data-run iterator of the `ntfs` crate can return the same error for ever; `flatten()` kept asking | Stop at the first bad run, cap runs and attributes per record |
| 3 | NTFS | Crash (panic in the `ntfs` crate) | Fuzzing | `unreachable!()` on a boot sector shorter than 512 bytes | Length checked first |
| 4 | NTFS | Large allocations | Review (same pattern as 5) | Read buffers sized by the requested or declared length; the free-space bitmap sized by the boot sector | Buffers grow with the bytes read, bitmap bounded by the volume |
| 5 | FAT, exFAT | 16 GB allocation from a 2.6 MB image | Fuzzing | The cluster count from the boot sector sized the in-memory FAT | Capped at the FAT entries really present; reads grow with the data |
| 6 | exFAT | Allocation of up to 128 GiB per cluster | Review (while fixing 5) | Sector and cluster shifts not checked | The specification's limits enforced (512-byte to 4 KiB sectors, clusters up to 32 MiB) |
| 7 | FAT, exFAT | Integer overflow (3 places) | Fuzzing | Offsets and sizes from the boot sector multiplied unchecked | Saturating arithmetic |
| 8 | Jump Lists (OLE) | Over 500 MiB from a 3 KB file | Fuzzing | A DIFAT listing the same sector again and again; sector chains that loop; mini stream cutoff taken from the header | Each sector once per chain, FAT no larger than the file, cutoff fixed at 4096, 256 MiB in all |
| 9 | Registry | Hang | Fuzzing | A key listed under itself made the tree walk grow exponentially | Each key visited once |
| 10 | EWF (E01) | Integer overflow | Fuzzing | Chunk geometry multiplied unchecked | Checked arithmetic, image refused |
| 11 | JPEG | Integer overflow (2 places) | Fuzzing | A DC difference size from the file's Huffman table could reach 255 (valid: 0 to 16) | Refused above 16 |
| 12 | JPEG | Integer overflow | Fuzzing | Coefficient times quantizer on hostile values | Saturating arithmetic |
| 13 | JPEG | 4.6 seconds on a 6.5 KB file | Fuzzing | A second frame header claimed 1.2 gigapixels and the decoder kept decoding padding | Decoding stops 1 KiB past the end of the data (truncated pictures still show what they have) |
| 14 | PDF text | Crash | Fuzzing | A name sliced inside a multi-byte character | Sliced at a character boundary |
| 15 | Carving | Crash | Fuzzing | A 7-byte `%PDF-1.` read as 8 bytes | Bounds checked |
| 16 | Browser history | Hang | Review (proof of concept made) | A database can define `urls` as a never-ending view | SQLite hardening (threat model above); such databases refused |
| 17 | JPEG | Integer overflow | Review (same as 12) | The same multiplication in the gray-level decoder | Saturating arithmetic |
| 18 | JPEG | Crash | Fuzzing | A scan naming a component that a later frame header removed | Scans checked against the frame; DC plane needs a frame |
| 19 | NTFS | Crash (panic in the `ntfs` crate) | Fuzzing (follow-up round) | `unreachable!()` on a `$STANDARD_INFORMATION` value shorter than its structure | Every call into the crate guarded: a bad record is reported as unreadable |
| 20 | ext | 423 MB allocation from an 83 KB image | Fuzzing | A superblock claiming millions of block groups sized the group table and the block bitmap | Both bounded by what the image holds |
| 21 | Time zones (TZif rule) | Integer overflow | Fuzzing | Hours in a POSIX rule string multiplied unchecked | POSIX limits enforced (hours up to 167, minutes and seconds up to 59) |
| 22 | systemd journal | Integer overflow | Fuzzing | Object offsets near the top of the address range added to a header size | Checked arithmetic |
| 23 | systemd journal | Integer overflow | Fuzzing | A data object's size added to its offset | Checked arithmetic |
| 24 | UDF | Integer overflow | Fuzzing | The backup anchor position (image size minus 256 sectors) on images smaller than that | Saturating arithmetic |
| 25 | UDF | Crash (read past the end) | Fuzzing | A file entry cut short at the end of the image was read at its full size | Short entries read as zeros past the end |
| 26 | UDF | Crash (read past the end) | Fuzzing | A short last block of the volume descriptor sequence was read as a full descriptor | The sequence ends at a short block |
| 27 | HFS+ | Integer overflow | Fuzzing | A B-tree node claiming more records than its offset table can hold | The record loop stops before the table runs out |
| 28 | HFS+ | Crash (read past the end) | Fuzzing | A volume header cut short at the end of the image | Short headers refused |
| 29 | APFS | Integer overflow | Fuzzing | A checkpoint address from the superblock multiplied by the block size | Saturating arithmetic for every block address |
| 30 | ZIP collections | Crash (panic) | Fuzzing | A Velociraptor-escaped name (`%xx`) next to a multi-byte character was cut inside the character | Escapes decoded byte by byte |
| 31 | ZIP collections | Runaway memory | Fuzzing | Sizes claimed by a damaged ZIP's directory sized the read and inflate buffers | Capped by the file's size; inflated output limited |
| 32 | Volume Shadow Copies | Integer overflow (2 places) | Fuzzing | A catalog or block list offset near 2^64 plus the block size | Checked arithmetic |
| 33 | Volume Shadow Copies | Stack overflow | Fuzzing | A catalog listing thousands of stores made the block lookup recurse once per store | The lookup is a loop; at most 512 stores, Windows' own limit |
| 34 | BitLocker | Integer overflow | Fuzzing | A boot sector copy or metadata offset near 2^64 | Saturating arithmetic |
| 35 | Outlook PST | Crash (panic in chrono) | Fuzzing | A message time far outside years 0 to 9999 was formatted as an RFC 2822 date | Such dates are left out of the rendered headers |
| 36 | Outlook PST | Crash (read past the end) | Fuzzing | A subnode block one byte long was read for its level | Short blocks read as empty |
| 37 | Property lists | Integer overflow | Fuzzing | A date of about 10^30 seconds converted to Windows time | Saturating arithmetic; such dates read as unknown |
| 38 | Watchlist | Wrong result | Fuzzing | Only one side of an IP comparison was unmapped, so an IPv4-mapped IPv6 indicator never matched | Both sides normalized before comparing |
| 39 | Watchlist (STIX) | Crash (slice inside a character) | Fuzzing | The start of an object name was found one byte after a multi-byte character | Character boundaries kept |
| 40 | SRUM | Integer overflow | Fuzzing | Per-program totals added hourly values near 2^63 | Saturating arithmetic |

Before the fixes, every one of these could stop or slow an ingest, a carving
job or a picture scan, or exhaust the examiner's memory, on purpose-made
evidence. None allowed code execution or wrote to evidence: Kokino has no
`unsafe` code, so the worst a parser bug could do was crash, hang or use
too much memory.

## Server review

Alongside the fuzzing, the server code that handles requests and runs jobs
was reviewed. Fixed:

- **Evidence paths inside the cases directory.** An examiner could add a
  file from the cases directory as evidence (another case's exports or
  audit log, the account file with its password hashes, the TLS key) and
  read it in the hex view. Such paths are now refused (symbolic links
  resolved, letter case ignored on Windows).
- **A parser panic left its job "running" for ever,** which also blocked
  deleting the case. Every background job now catches a panic and ends as
  failed, with a message asking to report it.
- **Reports served without a sandbox.** Case and evidence reports are HTML
  built from evidence text. They were escaped, but now also carry
  `Content-Security-Policy: default-src 'none'; sandbox`, so nothing in a
  report can run script or act as the signed-in examiner.
- **SQLite databases from evidence** are opened as described in the threat
  model above.
- **BitLocker unlocking** (new): the password or recovery password is sent
  once in the request body, used to derive the key and dropped. Only the
  volume key is written, to `keys/<evidence>.json` in the case folder,
  outside `case.json`, so no API response carries it. Reviewers cannot
  unlock (it is a write). Each attempt costs 2^20 SHA-256 rounds on the
  server, as it does on Windows.

Checked and found sound: the server folder browser (examiners and admins
only), export file names (no path separators survive),
report file names (a fixed pattern), downloads (`nosniff`, attachment
names from sanitized parts), session cookies and the CSRF and Host checks.

## Release integrity

Each release carries `SHA256SUMS.txt`, a CycloneDX SBOM listing every
third-party crate in the build (version, package URL, the checksum
Cargo.lock pins, license), and a build provenance attestation for every
file, signed through GitHub's Sigstore integration: it ties the file to
the workflow run and commit that built it. Check a download with
`gh attestation verify <file> --repo zeroscience/Kokino`. The Windows and
macOS packages are not yet code-signed with a publisher certificate.

## Limits of this testing

- The fuzzer is not coverage-guided and runs without sanitizers (no
  libFuzzer or AddressSanitizer, which need nightly Rust). Since Kokino has
  no `unsafe` code, memory-safety bugs would have to come from a dependency;
  the fuzzer looks for panics, hangs and runaway memory, which are what
  safe Rust can still do wrong.
- Third-party code is fuzzed only as Kokino uses it: the `ntfs` crate
  through the NTFS target, zlib (`flate2`) through EWF, ZIP, GZIP and PDF,
  and SQLite through the browser target (SQLite itself is fuzzed
  continuously upstream by OSS-Fuzz).
- The browser target is slow (each input is written to a temporary
  database), so it saw far fewer inputs than the others.
- There has been no external penetration test yet.
- In lab mode, examiners can still add any image file the server can read
  outside the cases directory. Labs that want to restrict this should run
  Kokino under an account that can read only the evidence storage.

## Running the fuzzer yourself

```bash
cargo build --profile fuzz -p kokino-fuzz
./target/fuzz/kokino-fuzz list
./target/fuzz/kokino-fuzz run all --secs 600 --seed 4
./target/fuzz/kokino-fuzz run ntfs --secs 3600
./target/fuzz/kokino-fuzz repro ntfs target/fuzz-findings/ntfs/<file>.bin
```

Findings land in `target/fuzz-findings/<target>/`. Add each to
`crates/kokino-fuzz/regress.txt` once fixed.
