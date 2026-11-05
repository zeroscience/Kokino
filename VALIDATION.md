# Validation against public test images

Kokino's results were checked against public forensic test images that come
with independent ground truth: published hashes, file lists, the original
files, or a documented layout of every deleted file. The test images
themselves are not part of this repository, but the comparison script
(`scripts/validate_cfreds.py`) is, and the steps below let anyone repeat
the whole check.

Thanks to the people behind these collections:

- **Digital Corpora** (digitalcorpora.org), created by Simson Garfinkel and
  colleagues at the Naval Postgraduate School: test disk images with
  documentation, freely available for research and tool testing.
- **NIST CFReDS** (cfreds.nist.gov), the Computer Forensic Reference Data
  Sets of the U.S. National Institute of Standards and Technology, Computer
  Forensics Tool Testing (CFTT) program: here the Deleted File Recovery
  (DFR) test images and their layout document.

Kokino version: 1.2.5 plus the fixes listed in the changelog for the FAT,
exFAT and NTFS images; 1.2.6 for the ext images. Run on Windows 10.

## Summary

| Data set | What was checked | Result |
|---|---|---|
| Digital Corpora `nps-2009-canon2` (FAT32 camera card, E01) | Image hashes against the published SHA-1; recovered pictures against the real files | Both images verify (E01 stored MD5 and published SHA-1); 34 of 36 recoverable pictures recovered byte for byte; the 3 overwritten deleted pictures flagged |
| Digital Corpora `nps-2009-ntfs1` (NTFS, E01) | File list against the DFXML; compressed and EFS-encrypted copies against the plain originals | All files with correct names and sizes; all 9 compressed copies identical to the originals (after adding NTFS decompression, see below); encrypted copies read as ciphertext and now flagged |
| NIST CFReDS DFR, 22 ext images (ext2, ext3, ext4) | Every deleted file with content, block by block; deleted names against NIST's layout | 962 of 965 tagged files complete, 99.9996% of blocks right; 302 files recovered through the ext3/ext4 journal; 2,782 deleted names listed; wrong content without a warning in 1 file |
| A real Windows 10 22H2 SRUM database (SRUDB.dat, 70 MB, unreleased) | Every row and value of every table against Windows' own esent.dll | All 310,255 rows and 2,800,979 values the same, after two fixes (below) |
| NIST CFReDS DFR, 61 images (FAT12/16/32, exFAT, NTFS) | Every deleted file Kokino lists, block by block, against the files' own tags; counts against NIST's layout | 3,048 of 3,323 deleted test files complete, 1,367,020 of 1,370,338 blocks right (99.8%); exFAT 100%, NTFS 100% of blocks; wrong content without a warning in 4 files |

The validation found real problems in Kokino, all fixed before these
results were taken:

1. **NTFS compressed files were read as stored, not decompressed.** Any file
   in a compressed folder had wrong content, hashes, text search and
   exports. Kokino now decompresses LZNT1 (checked against Windows' own
   compressor), including files split over an attribute list.
2. **Deleted exFAT files were assumed to be contiguous.** exFAT keeps the
   FAT chain of a deleted file; Kokino now follows it when it is intact,
   which took fragmented deleted files from half recovered to complete.
3. **No warning when a deleted NTFS file's clusters were reused.** Kokino
   now checks `$Bitmap` and says how many clusters are in use again.
4. **No warning when two deleted files claim the same space** (one overwrote
   the other, then was deleted too, so the space looks free). Kokino now
   notes this on FAT, exFAT and NTFS.
5. **EFS-encrypted files were not marked.** File details now say that
   content, hashes and text are of the ciphertext.

Two new command-line tools came out of this work and stay in the product:
`kokino files` (every file, live and deleted, with MD5, SHA-1 and SHA-256,
and `--extract DIR` to write them out) and `kokino carve` (carved files with
offsets and hashes).

## Digital Corpora: nps-2009-canon2

A 32 MB SD card from a Canon PowerShot SD800 IS, imaged at six points in
its life (gen1 to gen6). The corpus publishes the SHA-1 of each raw image
and, for gen6, a zip of every JPEG that can be recovered from it.

- **Image integrity.** `kokino hash` on gen1 and gen6: the MD5 stored in
  each E01 matches, and the SHA-1 of the media equals the published value
  (`67364b08...` for gen1, `4742c325...` for gen6).
- **Files.** Of the 36 pictures in `files-gen6.zip`, 33 are recovered from
  the file system by `kokino files` with identical SHA-1, and one more
  (IMG_0014, from an earlier generation and no longer in any directory) by
  `kokino carve`, also identical: **34 of 36**.
- **The two not recovered** (IMG_0040, IMG_0041) are each split into three
  or four pieces with other data between them. Carving that assumes a file
  is stored in one piece, as Kokino's does, cannot rejoin them.
- **Overwritten deleted files.** Three deleted entries (IMG_0025, 0030, 0035)
  are not in the corpus's recoverable set because their space was reused.
  Kokino lists them and says, for each, that the first cluster was
  overwritten and to try the carved files.

## Digital Corpora: nps-2009-ntfs1

An NTFS volume with three folders, RAW, Compressed and Encrypted, holding
the same files (PDFs, a JPEG and a heavily fragmented log file), plus EFS
keys. The corpus provides fiwalk DFXML for gen2.

- **Image integrity.** E01 stored MD5 verified for gen1 and gen2.
- **File list.** All 19 files in the DFXML are found, with the same names
  and sizes.
- **Compressed files.** Each file in Compressed must equal its copy in RAW.
  Before the fix none did; now all 9 (4 in gen1, 5 in gen2) are identical,
  including the 21.9 MB log file split over an attribute list.
- **Encrypted files** differ from the originals, as they must (Kokino reads
  EFS ciphertext; the keys are not used), and are now marked as encrypted.

## NIST CFReDS: deleted file recovery

NIST built these images to test deleted-file recovery tools: 1 GB disks
with FAT12, FAT16 and FAT32 partitions, an exFAT partition or an NTFS
partition, on which test files were created, fragmented, nested, braided,
overwritten and deleted in documented steps. Every 512-byte block of a test
file starts with a tag naming its file and position ("File Bellatrix.txt",
"Block 00004 Segment 002 file Bellatrix.txt"), so a recovered file can be
checked block by block.

For every deleted file Kokino lists, `scripts/validate_cfreds.py` checks
the name against the file's own tag, counts the full blocks that carry the
right tag in the right place, and notes whether Kokino warned when content
is wrong. Cases 15 to 17 test attributes and shortcuts of live files, not
deletion, and are left out of the counts.

### By file system

| File system | Images | Deleted test files recovered complete | Blocks right | Wrong content without a warning |
|---|--:|--:|--:|--:|
| FAT12/16/32 | 17 | 1,719 of 1,987 (86.5%) | 219,134 of 222,452 (98.5%) | 1 |
| exFAT | 16 | 660 of 660 (100.0%) | 130,400 of 130,400 (100.0%) | 0 |
| NTFS | 19 | 669 of 676 (99.0%) | 1,017,486 of 1,017,486 (100.0%) | 3 |

### Every image

| Image | NIST case | Deleted with metadata (NIST) | Deleted listed by Kokino | Test files complete | Blocks recovered | Wrong content without a warning |
|---|---|--:|--:|--:|--:|--:|
| `fat-01` | Recover one non-fragmented file. | 3 | 3 | 3 of 3 | 3 of 3 | 0 |
| `fat-01-recycle` | Recover one non-fragmented file. | 3 | 7 | 3 of 5 | 24 of 24 | 0 |
| `ntfs-01` | Recover one non-fragmented file. | 1 | 1 | 1 of 1 | 8 of 8 | 0 |
| `ntfs-01-recycle` | Recover one non-fragmented file. | 1 | 2 | 0 of 1 | 0 of 0 | 1 |
| `xfat-01` | Recover one non-fragmented file. | 1 | 4 | 1 of 1 | 8 of 8 | 0 |
| `fat-02` | Recover file with two fragments. | 3 | 3 | 0 of 3 | 12 of 24 | 0 |
| `ntfs-02` | Recover file with two fragments. | 1 | 1 | 1 of 1 | 16 of 16 | 0 |
| `xfat-02` | Recover file with two fragments. | 1 | 4 | 1 of 1 | 16 of 16 | 0 |
| `fat-03` | Recover file with multiple fragments. | 3 | 3 | 0 of 3 | 12 of 48 | 0 |
| `ntfs-03` | Recover file with multiple fragments. | 1 | 1 | 1 of 1 | 4,116 of 4,116 | 0 |
| `xfat-03` | Recover file with multiple fragments. | 1 | 4 | 1 of 1 | 32 of 32 | 0 |
| `fat-04` | Recover several non-fragmented files with non-ASCII file names. | 0 | 36 | 36 of 36 | 288 of 288 | 0 |
| `ntfs-04` | Recover several non-fragmented files with non-ASCII file names. | 0 | 12 | 12 of 12 | 48 of 48 | 0 |
| `xfat-04` | Recover several non-fragmented files with non-ASCII file names. | 0 | 15 | 12 of 12 | 72 of 72 | 0 |
| `fat-05` | Recover several fragmented files. | 6 | 6 | 0 of 6 | 24 of 48 | 0 |
| `fat-05-braid` | Recover several fragmented files. | 6 | 6 | 0 of 6 | 12 of 24 | 0 |
| `fat-05-nest` | Recover several fragmented files. | 6 | 6 | 0 of 6 | 6 of 12 | 0 |
| `ntfs-05` | Recover several fragmented files. | 2 | 2 | 2 of 2 | 8,208 of 8,208 | 0 |
| `ntfs-05-braid` | Recover several fragmented files. | 2 | 2 | 2 of 2 | 32 of 32 | 0 |
| `ntfs-05-nest` | Recover several fragmented files. | 2 | 2 | 2 of 2 | 32 of 32 | 0 |
| `xfat-05` | Recover several fragmented files. | 2 | 5 | 2 of 2 | 32 of 32 | 0 |
| `xfat-05-braid` | Recover several fragmented files. | 2 | 3 | 2 of 2 | 32 of 32 | 0 |
| `xfat-05-nest` | Recover several fragmented files. | 2 | 5 | 2 of 2 | 64 of 64 | 0 |
| `fat-06` | Recover one large file. | 3 | 3 | 0 of 3 | 204,179 of 204,185 | 0 |
| `ntfs-06` | Recover one large file. | 1 | 1 | 1 of 1 | 1,000,000 of 1,000,000 | 0 |
| `xfat-06` | Recover one large file. | 1 | 2 | 1 of 1 | 127,544 of 127,544 | 0 |
| `fat-07` | Recover one overwritten file. | 9 | 9 | 6 of 8 | 72 of 72 | 0 |
| `ntfs-07` | Recover one overwritten file. | 3 | 3 | 2 of 3 | 16 of 16 | 0 |
| `xfat-07` | Recover one overwritten file. | 3 | 4 | 3 of 3 | 4 of 4 | 0 |
| `fat-08` | Recover several overwritten files. | 43 | 42 | 30 of 33 | 90 of 96 | 1 |
| `ntfs-08` | Recover several overwritten files. | 25 | 13 | 10 of 13 | 62 of 62 | 1 |
| `xfat-08` | Recover several overwritten files. | 14 | 14 | 13 of 13 | 42 of 42 | 0 |
| `fat-09` | Recover large number of files no overwrite. | 780 | 780 | 780 of 780 | 6,240 of 6,240 | 0 |
| `ntfs-09` | Recover large number of files no overwrite. | 260 | 260 | 260 of 260 | 1,040 of 1,040 | 0 |
| `xfat-09` | Recover large number of files no overwrite. | 260 | 261 | 260 of 260 | 260 of 260 | 0 |
| `fat-10` | Recover large number of files, with some overwritten. | 780 | 780 | 780 of 780 | 6,240 of 6,240 | 0 |
| `ntfs-10` | Recover large number of files, with some overwritten. | 757 | 260 | 260 of 260 | 2,080 of 2,080 | 0 |
| `xfat-10` | Recover large number of files, with some overwritten. | 260 | 261 | 260 of 260 | 520 of 520 | 0 |
| `fat-11` | Recover one non-fragmented directory. | 9 | 9 | 9 of 9 | 144 of 144 | 0 |
| `ntfs-11` | Recover one non-fragmented directory. | 3 | 3 | 3 of 3 | 12 of 12 | 0 |
| `ntfs-11-compress` | Recover one non-fragmented directory. | 3 | 3 | 3 of 3 | 96 of 96 | 0 |
| `ntfs-11-mft` | Recover one non-fragmented directory. | 3 | 3 | 3 of 3 | 3 of 3 | 0 |
| `xfat-11` | Recover one non-fragmented directory. | 3 | 6 | 3 of 3 | 12 of 12 | 0 |
| `fat-12` | Recover one fragmented directory. | 27 | 27 | 9 of 27 | 54 of 90 | 0 |
| `ntfs-12` | Recover one fragmented directory. | 9 | 9 | 9 of 9 | 60 of 60 | 0 |
| `xfat-12` | Recover one fragmented directory. | 9 | 12 | 9 of 9 | 120 of 120 | 0 |
| `fat-13` | Recover chaotic file system activity. | 354 | 354 | 57 of 273 | 1,686 of 4,866 | 0 |
| `ntfs-13` | Recover chaotic file system activity. | 135 | 118 | 92 of 93 | 1,617 of 1,617 | 0 |
| `xfat-13` | Recover chaotic file system activity. | 118 | 121 | 90 of 90 | 1,642 of 1,642 | 0 |
| `fat-14` | Recover other file system object. | 9 | 12 | 6 of 6 | 48 of 48 | 0 |
| `ntfs-14` | Recover other file system object. | 15 | 8 | 5 of 6 | 40 of 40 | 1 |
| `xfat-14` | Recover other file system object. | 1 | 5 | 0 of 0 | 0 of 0 | 0 |
| **All 52** | | **3,946** | **3,516** | **3,048 of 3,323** | **1,367,020 of 1,370,338** | **4** |

"Deleted with metadata (NIST)" is NIST's count of deleted files that still
have file system metadata. "Test files complete" counts the deleted files
Kokino lists that are NIST test files (others are, for example, temporary
entries the image-making tools left behind) and how many came back with
every block right. Blocks are full 512-byte blocks, as NIST counts them.

### What the numbers mean

- **FAT fragmented files** (cases 02, 03, 05, 12, 13) come back only up to
  their first fragment. Deleting a file on FAT erases its cluster chain, so
  the rest of the file can only be guessed as following the first cluster.
  Kokino marks every deleted FAT file "Recovered as contiguous" and now
  warns when that guess runs into another file's space. exFAT keeps the
  chain, and there Kokino recovers these same cases completely.
- **NTFS deleted files whose MFT record was reused** (cases 08, 10, 13
  and 14) have no content left to check, so the table above lists only
  those with a record. NIST counts them because their names survive. On
  these Windows 7 images the names are in `$LogFile`, which records every
  folder index change with the entry itself, more than in index slack
  (`$I30`). Kokino now reads both and lists such names (see below).
- **Names** in other scripts (case 04: Korean, Arabic, Urdu, Hebrew,
  Devanagari) come out right on FAT, exFAT and NTFS. The tags inside those
  files use English names, so they were checked by hand.
- **Compressed deleted files** (ntfs-11-compress) are recovered completely:
  NIST lists 0 recoverable blocks because the tags are not visible in the
  raw sectors, but Kokino decompresses them.
- **Wrong content without a warning**: 4 files of 3,323 (in ntfs-01-recycle,
  fat-08, ntfs-08 and ntfs-14), each overwritten by a file that left no
  trace Kokino can see yet.

### NTFS: names without an MFT record (unreleased)

Deleted files Kokino lists on the NTFS images with the full analysis:
those with an MFT record (the table above) plus names found only in
folder indexes or `$LogFile`, against NIST's count of deleted files with
metadata.

| Image | Deleted with metadata (NIST) | With an MFT record | Names without a record | Kokino in all |
|---|--:|--:|--:|--:|
| `ntfs-08` | 25 | 13 | 12 | 25 |
| `ntfs-10` | 757 | 260 | 508 | 768 |
| `ntfs-13` | 135 | 118 | 20 | 138 |
| `ntfs-14` | 15 | 10 | 3 | 13 |

Case 08 now matches exactly. Every name without a record carries the MFT
record it had and says which file holds that record now (in case 08,
Albireo.txt's record 65 holds Sheliak.txt). The 11 extra names in case
10 and 3 in case 13 (and the 2 missing in case 14) are not explained yet:
NIST's layout gives counts, not the names, so they could not be matched
one by one. The other NTFS cases list no name without a record, or one
from the tools that made the image. Hard links (case 15) are recognized
as a second name of the same record, not as a lost file.

## SRUM: a real Windows 10 database (unreleased)

Kokino's ESE reader was first tested only on databases written for the
purpose by esent.dll. To check it on real data, the SRUM database of the
maintainer's own Windows 10 22H2 computer was copied through a shadow
copy (`esentutl /y C:\Windows\System32\sru\SRUDB.dat /vss /d <copy>`):
70 MB, 4 KiB pages, cleanly shut down, about 60 days of records. The copy
was read twice, by Kokino and by Windows' own esent.dll (through its API,
on a second copy), and every row of every table was compared value by
value. The database holds personal usage data and is not published; the
comparison was made with local tools, not shipped.

The first run found two problems:

1. **Large tables read as empty.** Kokino followed only branch pages
   flagged "parent of leaf"; in a tree of three or more levels the branch
   pages above those carry neither that flag nor the leaf flag. SRUM's id
   map (163,087 rows) and several hourly tables read as empty or nearly
   so: 5,000 rows in all instead of 310,255. Kokino now follows every
   non-leaf page of the tree, and only pages that carry the tree's object
   id. Regression test: `win/ese-deep.dat`.
2. **UTF-16 text in a column declared as ANSI** (SRUM's `Tag` column,
   code page 1252) was cut after its first character. Text that is
   clearly UTF-16 is now read as UTF-16.

After the fixes:

| Table | Rows |
|---|--:|
| SruDbIdMapTable (programs, services, users) | 163,087 |
| Application resource usage | 92,077 |
| Network data usage | 932 |
| Network connectivity | 476 |
| Other SRUM tables (8) and ESE's own system tables (4) | 53,683 |
| In all, 16 tables | 310,255 |

All 2,800,979 values are the same in both readers. In the SRUM view every
program and user id resolves, no record lacks a time, and the records
cover the expected 60 days. Many program ids on this computer have the
form `!!<file>!<date>!<hex>!...` instead of a path; Kokino now shows them
by their file name.

Not covered by this database: column compression. Windows stored none of
its values compressed (7-bit or XPRESS), so the 7-bit path is covered only
by the esent.dll-written fixtures and XPRESS only by a test vector. A
dirty database (whose newest records are only in the transaction logs) was
not checked either.

## NIST CFReDS: deleted file recovery on ext2, ext3 and ext4

The same NIST DFR set has 22 ext images (cases 01 to 17 and their
variants). Each is a 1 GB disk with three partitions, ext2, ext3 and ext4,
holding the same test story. `scripts/validate_cfreds.py` checks them the
same way as the FAT and NTFS images, and for ext also runs the full
analysis to count deleted names that have no content left.

| Data | Result |
|---|---|
| Deleted names listed | 2,782 (NIST counts 3,032 deleted files with metadata in the cases that state a number) |
| Deleted names matching NIST's count exactly | 11 of 19 cases with a stated count |
| Deleted files with content | 1,013 (ext2 711, ext3 33, ext4 269) |
| Tagged content complete | 962 of 965 files; 1,852,775 of 1,852,782 blocks right (99.9996%) |
| Recovered through the journal (ext3, ext4) | 302 files |
| Wrong content without a warning | 1 file (ext-07-one, see below) |

| Image | NIST: deleted files with metadata | Deleted names Kokino lists | Deleted files with content | Complete | Through the journal | Wrong, no warning |
|---|--:|--:|--:|--:|--:|--:|
| ext-01 | 3 | 3 | 1 | 1 | 0 | 0 |
| ext-01-recycle | 3 | 15 | 2 | 1 | 0 | 0 |
| ext-02 | 3 | 3 | 1 | 1 | 0 | 0 |
| ext-03 | 3 | 3 | 1 | 1 | 0 | 0 |
| ext-04 | 0 | 36 | 12 | 12 | 0 | 0 |
| ext-05-braid | 6 | 6 | 2 | 2 | 0 | 0 |
| ext-05 | 6 | 6 | 2 | 2 | 0 | 0 |
| ext-05-nest | 6 | 6 | 2 | 2 | 0 | 0 |
| ext-06 | 3 | 3 | 3 | 3 | 2 | 0 |
| ext-07 | 9 | 9 | 7 | 4 | 4 | 0 |
| ext-07-one | 6 | 6 | 5 | 2 | 3 | 1 |
| ext-07-two | 6 | 3 | 3 | 0 | 2 | 0 |
| ext-08 | 26 | 25 | 20 | 15 | 7 | 0 |
| ext-09 | 766 | 832 | 260 | 260 | 0 | 0 |
| ext-10 | 1757 | 1181 | 539 | 539 | 279 | 0 |
| ext-11 | 9 | 9 | 3 | 3 | 0 | 0 |
| ext-12 | 30 | 30 | 12 | 12 | 3 | 0 |
| ext-13 | 384 | 404 | 120 | 92 | 2 | 0 |
| ext-14 | 6 | 24 | 18 | 10 | 0 | 0 |
| ext-15 | - | 0 | 0 | 0 | 0 | 0 |
| ext-16 | - | 178 | 0 | 0 | 0 | 0 |
| ext-17 | - | 0 | 0 | 0 | 0 | 0 |

### What the numbers mean

- **ext2** keeps a deleted file's block pointers but erases the inode
  number from its directory entry. Kokino lists the name (with a note) and
  the content separately, as an orphaned inode under `$OrphanFiles`;
  deleted folders are walked from their orphaned inode, so the files in
  them keep their names. Content: 669 of 711 files complete, the rest
  warned.
- **ext3 and ext4** clear a deleted file's block map and size. The names
  stay (Kokino lists them all), and the content comes back when the journal
  still holds an older copy of the inode: 302 files here. Otherwise the
  name is listed with no content, and only carving can help.
- **Deleted folders on ext3 and ext4** (case 11, 12): the folder's block
  map is cleared too, so Kokino searches the free blocks of its block group
  for the directory block that starts with "." naming the folder's inode.
  Case 11 and 12 names are all found that way.
- **Counts above NIST's** (01-recycle, 04, 09, 13, 14): Kokino lists
  every deleted name it can read, including names NIST counts as "not
  found" (case 04, non-ASCII names whose inode number was erased) and the
  desktop trash's own files (01-recycle). In large indexed folders (09)
  an index split leaves old copies of names behind; those with the same
  inode as a live name are dropped, a few with a reused inode remain.
- **Counts below NIST's** (07-two, 08, 10): new files written after the
  deletes reused the directory entries, so the names are gone; NIST counts
  inode metadata, which survives without a name.
- **Wrong content without a warning**: 1 file. In ext-07-one a deleted
  ext4 file is read through its journal copy, but its blocks were used
  afterwards by another file that was then deleted too. ext4 erased that
  second file's block map, so nothing on the disk shows it ever owned
  those blocks.

The validation found real problems, all fixed before these results:

1. ext2 deleted names whose inode number is erased were dropped.
2. Deleted folders on ext2 were not entered (rmdir sets their size to 0)
   and orphaned folders were listed without their files.
3. Blocks of large indexed folders whose files were all deleted were
   skipped as index blocks, losing every name in them.
4. Old copies of names left by index splits were listed as deleted files.
5. Deleted folders on ext3 and ext4 had no way back to their entries; the
   directory block search was added.

## Repeating it

Download (about 240 MB) into `target/validation/` (ignored by git):

- CFReDS: `https://cfreds-archive.nist.gov/dfr-images/` the `dfr-*-fat`,
  `-xfat`, `-ntfs` and `-ext` `.dd.bz2` images and `setup-july-10-2012.pdf`
  (the ext images are about 55 MB more; keep them in their own folder).
- Digital Corpora: `https://digitalcorpora.s3.amazonaws.com/corpora/drives/`
  `nps-2009-ntfs1/` (`ntfs1-gen1.E01`, `ntfs1-gen2.E01`, `ntfs1-gen2.xml`)
  and `nps-2009-canon2/` (`nps-2009-canon2-gen1.E01`, `-gen6.E01`,
  `files-gen6.zip`, `narrative.txt`).

Then:

```bash
cargo build --release
python scripts/validate_cfreds.py target/validation/cfreds
python scripts/validate_cfreds.py target/validation/cfreds-ext
./target/release/kokino hash target/validation/canon2/nps-2009-canon2-gen6.E01
./target/release/kokino files target/validation/canon2/nps-2009-canon2-gen6.E01
./target/release/kokino carve target/validation/canon2/nps-2009-canon2-gen6.E01
./target/release/kokino files target/validation/ntfs1/ntfs1-gen2.E01
```

and compare with the published hashes, `files-gen6.zip` and the DFXML as
described above. The CFReDS script expands one image at a time (1 GB each)
and deletes it again; it needs PyMuPDF to read NIST's PDF.
