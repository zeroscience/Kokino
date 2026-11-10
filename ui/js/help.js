// About page and the Wiki (user manual). Content lives here as data so the
// app shell only routes to it.

import { h, icon, debounce, api } from "./lib.js";

export const CONTACT = {
  web: "https://www.zeroscience.mk",
  email: "lab@zeroscience.mk",
  github: "https://github.com/zeroscience",
};

const link = (href, text) => h("a.lnk", { href, target: "_blank", rel: "noopener noreferrer" }, text || href);
const mail = (addr) => h("a.lnk", { href: "mailto:" + addr }, addr);
const code = (s) => h("code", s);
const pre = (...lines) => h("pre.cmd", lines.join("\n"));
const p = (...k) => h("p", ...k);
const ul = (...items) => h("ul", items.map((i) => h("li", i)));
const kv = (rows) => h("div.kv", rows.map(([k, v]) => [h("span", k), h("span", v)]));

// ------------------------------------------------------------------ about

// Asks GitHub for the latest release, only when clicked; nothing is
// downloaded or installed. The server records the check in its audit log.
function updateCard(info) {
  const out = h("div.stack");
  const btn = h("button", "Check for updates");
  btn.onclick = async () => {
    btn.disabled = true;
    out.replaceChildren(h("p.muted", "Asking GitHub..."));
    try {
      const u = await api("/update-check");
      out.replaceChildren(
        u.newer
          ? h("div.stack",
            h("p", h("b", `Kokino ${u.latest} is available`), ` (you have ${u.current}; published ${u.published.slice(0, 10)}).`),
            h("p", link(u.url, "Release notes and downloads")),
            u.checksums ? h("details", h("summary", "SHA-256 checksums of the release"), h("pre.cmd", u.checksums)) : null,
            h("p.muted", "Download it from GitHub and check it against the checksums. The Windows installer upgrades in place and keeps cases and accounts."))
          : h("p", `This is the latest release (${u.current}).`));
    } catch (e) {
      out.replaceChildren(h("p", { style: { color: "var(--warn)" } }, e.message));
    }
    btn.disabled = false;
  };
  return h("div.card.stack",
    h("h3", "Updates"),
    p(`Version ${info.version}. Kokino never contacts anything on its own; this button makes one request to GitHub's release list and shows what it finds. The check is recorded in the system audit log. On the command line: `, code("kokino version --check"), "."),
    h("div.row", btn),
    out);
}
const COMPONENTS = [
  ["ntfs", "NTFS structures", "MIT OR Apache-2.0", "Colin Finck"],
  ["SQLite (via rusqlite)", "Browser history databases", "Public domain / MIT", "SQLite developers"],
  ["axum, tokio, hyper", "Web server and async runtime", "MIT", "Tokio project"],
  ["rustls, axum-server, rcgen", "TLS for LAN mode", "Apache-2.0 / ISC / MIT", "rustls project"],
  ["argon2", "Password hashing (Argon2id)", "MIT OR Apache-2.0", "RustCrypto"],
  ["md-5, sha1, sha2", "Evidence hashing", "MIT OR Apache-2.0", "RustCrypto"],
  ["flate2", "zlib for E01 chunks", "MIT OR Apache-2.0", "rust-lang"],
  ["lzma-rs, ruzstd", "XZ and zstd fields in systemd journals", "MIT", "gendx; Moritz Borcherding"],
  ["serde, chrono, clap, uuid", "Data, time, CLI, ids", "MIT OR Apache-2.0", "various"],
  ["rust-embed", "GUI files inside the binary", "MIT", "pyrossh"],
];

export function aboutPage(info) {
  return h("div.stack.about",
    h("div.card.about-hero",
      h("figure.about-art",
        h("div.frame", h("img", { src: "img/painting.jpg", alt: "Painting by Siebe Boersma: a face in sweeping strokes of ochre, olive and brown, with blue skin and green eyes looking out", width: 900, height: 1182 })),
        h("figcaption", "Painting by ", link("https://siebeboersma.nl/", "Siebe Boersma"), " (NL)")),
      h("div",
        h("h1", "Kokino FTK"),
        h("p.muted", { style: { margin: "2px 0 0" } }, "Kokino Forensic Toolkit"),
        h("p.tagline", "Every finding, traceable to the byte."),
        h("p.muted", "Disk forensics by Zero Science Lab"),
        h("div.row.wrap", { style: { marginTop: "12px" } },
          h("span.pill.info", `Version ${info.version}`),
          info.build ? h("span.pill", { title: "Fingerprint of the GUI files served by this build" }, `build ${info.build}`) : null,
          h("span.pill", info.tls ? "HTTPS" : "local"),
        ),
      ),
    ),
    h("div.grid.g2",
      h("div.card.stack",
        h("h3", "What it is"),
        p("Kokino Forensic Toolkit (Kokino FTK) is an open-source digital forensics workbench for disk images. Give it an E01, raw, VHD, VHDX or VMDK image, a disc image or a triage collection (Velociraptor, KAPE, UAC, or a plain folder), and it reads every NTFS, FAT, exFAT, ext2/3/4, HFS+, APFS, ISO 9660 and UDF volume down to the last record, live and deleted, BitLocker volumes once unlocked and every Volume Shadow Copy included, brings back what was erased, and rebuilds what happened on the machine: Windows registry (deleted keys included), event logs, execution traces and scheduled tasks, Linux and macOS accounts, logons, shell histories and persistence, browser history (Internet Explorer's included, even from a formatted disk), email (Outlook PST and OST, Apple Mail, mbox), carved files and edited pictures, and what a case's evidence items have in common, on one case timeline and against a watchlist of known indicators."),
        p("Every finding links to the exact bytes it came from, every indicator of anti-forensic activity explains itself, and every examiner action lands in a hash-chained audit log, so the results hold up in a report and in court."),
        p("One portable binary serves this browser interface on Windows, Linux and macOS, alone on a workstation or for a whole lab over HTTPS."),
        p("The name comes from the Kokino observatory, a Bronze Age megalithic site in North Macedonia (", link("https://en.wikipedia.org/wiki/Kokino", "Wikipedia"), "); the wiki has the story."),
      ),
      h("div.card.stack",
        h("h3", "Forensic principles"),
        ul(
          "Evidence is opened read-only. Hex edits are an overlay stored in the case, never written to the image.",
          "Every examiner action is recorded under the examiner's account in a hash-chained audit log.",
          "Images are hashed (MD5, SHA-1, SHA-256) and checked against the acquisition hash and, for E01, the hash the imager stored.",
          "Indicators are transparent rules with weights and caveats. The score says where to look, never what happened.",
        ),
      ),
    ),
    h("div.card.stack",
      h("h3", "What's next"),
      p("1.4 is the last feature release for a few months. Security reports and wrong results (an artifact read incorrectly, a crash on real evidence) are still fixed in 1.4.x releases."),
      p("After the pause, in order: checks on disks from real Macs; APFS encryption (FileVault), snapshots and LZFSE compression; Windows Search (Windows.edb) and NTFS $LogFile in full; XFS, Ex01 and ESXi snapshots; watchlists from STIX and MISP. Most of these wait for test data rather than code. The full list, with what each item needs, is in ", link("https://github.com/zeroscience/Kokino/blob/main/ROADMAP.md", "ROADMAP.md"), "; if one matters to a case you work on, say so: that moves it up."),
    ),
    updateCard(info),
    h("div.grid.g2",
      h("div.card.stack",
        h("h3", "Contact"),
        kv([
          ["Website", link(CONTACT.web)],
          ["Email", mail(CONTACT.email)],
          ["GitHub", link(CONTACT.github)],
          ["Bugs and ideas", h("span", "Open an issue on GitHub, or write to ", mail(CONTACT.email), ".")],
          ["Security issues", h("span", "Please report privately to ", mail(CONTACT.email), " rather than in a public issue.")],
        ]),
      ),
      h("div.card.stack",
        h("h3", "This installation"),
        kv([
          ["Version", info.version],
          ["GUI build", info.build || "-"],
          ["Connection", info.tls ? "HTTPS (TLS)" : "HTTP on this machine only"],
          ["Vendor", info.vendor],
          ["License", "Apache License 2.0"],
        ]),
        h("p.muted", { style: { fontSize: "12.5px", margin: 0 } }, "Mention the version and build when you report a problem."),
      ),
    ),
    h("div.card.stack",
      h("h3", "Built with"),
      h("p.muted", { style: { margin: 0 } }, "Kokino stands on these open-source components. Thank you to their authors."),
      h("div.scroll", h("table.tbl",
        h("thead", h("tr", h("th", "Component"), h("th", "Used for"), h("th", "License"), h("th", "Authors"))),
        h("tbody", COMPONENTS.map(([n, u, l, a]) => h("tr", h("td", h("b", n)), h("td", u), h("td.mono", l), h("td.muted", a)))),
      )),
      h("p.muted", { style: { fontSize: "12.5px", margin: 0 } }, "Test fixture testfs1 comes from the ntfs crate (MIT OR Apache-2.0).", " Validated against public test images from Digital Corpora (Naval Postgraduate School) and NIST CFReDS (Computer Forensics Tool Testing program); the wiki's Validation section has the results. Thank you to both."),
    ),
    h("div.about-end",
      h("p.muted.center", `Kokino Forensic Toolkit ${info.version} by Zero Science Lab`),
      // Emoji flags show as letters on Windows, so the flag is a picture.
      h("p.muted.center.made", "Made with \u2764\uFE0F in ", h("img", { src: "img/flag-mk.svg", alt: "North Macedonia", title: "North Macedonia", width: 21, height: 11 }))),
  );
}

// ------------------------------------------------------------------ wiki
const WIKI = [
  {
    id: "start", title: "Getting started", icon: "chev",
    body: [
      p("Installed from a release package (Windows MSI, Linux .deb, macOS DMG): start \"Kokino Forensic Toolkit\" from the Start menu, the desktop's application menu or the DMG's \"Start Kokino\", or run ", code("kokino serve"), ". It opens your browser on this machine. To see whether a newer release exists, use Check for updates on the About page (nothing is checked on its own)."),
      p("From source: build once, then start the server."),
      pre("cargo build --release", "./target/release/kokino serve"),
      p("On the very first start there are no accounts yet. The terminal prints a one-time setup link; open it to create the first administrator. Without that link nobody can claim the server. You can also create the first admin on the console:"),
      pre("./target/release/kokino user add jdoe --role admin --display-name \"Jane Doe\""),
      p("Cases are stored in ", code("~/KokinoCases"), " (", code("%USERPROFILE%\\KokinoCases"), " on Windows). Use ", code("--cases D:\\Cases"), " to put them elsewhere. Stop the server with Ctrl+C."),
      h("div.cav", "After upgrading Kokino, open tabs reload themselves on their next request. If a page ever looks out of date, press Ctrl+F5."),
      p(h("b", "Dates and time zones."), " Kokino stores every time as UTC and shows it in your own time zone (this computer's, with summer time applied for each date), day first: ", code("30.10.2026 15:32:05"), ". Tables name the zone in their heading and single times carry their offset (", code("UTC+1"), "). The ", h("b", "Time"), " button next to Theme switches to UTC or any other zone and to ISO (", code("yyyy-mm-dd"), ") or US (", code("mm/dd/yyyy"), ") order; the choice is kept in this browser. FAT and EXIF times are the device's own clock with no zone recorded, so they are shown as stored and marked \"device clock\". Case reports use the local time of the computer that makes them, or UTC if you ask, and say which; command-line output and the server log use the computer's local time with its offset. Stored data (audit logs, case files, ", code("--json"), " output) stays ISO 8601 UTC, as the forensic standards ISO/IEC 27037 and 27042 expect times and zones to be recorded unambiguously."),
    ],
  },
  {
    id: "accounts", title: "Accounts and roles", icon: "users",
    body: [
      kv([
        ["Admin", "Manages accounts and case members, sees every case, can do everything an examiner can."],
        ["Examiner", "Creates cases (and becomes their lead examiner), works assigned cases: evidence, analysis, overlay edits, exports, reports."],
        ["Reviewer", "Opens assigned cases read-only: every view and the HTML report, but no exports, edits or new evidence."],
      ]),
      p("Admins add people under ", h("b", "Users"), ". Kokino generates a temporary password; give it to the person over a separate channel. They must choose their own password at first sign-in."),
      p("Assign people to a case on the case's ", h("b", "Members"), " page. A user who is not a member does not see the case at all. Changes are recorded in the case audit log and the system audit log."),
      p("Passwords need at least 12 characters. After 5 wrong attempts for one user, sign-in waits 30 seconds, doubling up to 15 minutes. Sessions end after 60 minutes idle or 12 hours, and when the server restarts."),
      h("h4", "Locked out?"),
      p("On the server console (works while the server runs):"),
      pre("kokino user list", "kokino user reset jdoe", "kokino user role jdoe admin", "kokino user disable jdoe", "kokino user delete jdoe"),
      h("h4", "Disable or delete?"),
      p("When someone leaves, ", h("b", "Disable"), " is usually right: they can no longer sign in, and everything stays as it was. ", h("b", "Delete"), " (admins, under Users) is for accounts that should not exist at all, or when personal data must go. You type the username to confirm, and Kokino first shows what the account did:"),
      ul(
        h("span", h("b", "Never used"), " (no sign-in, no audit entries, no bookmarks): removed completely, for test accounts and typos."),
        h("span", h("b", "Used:"), " the password and display name are removed and the account is signed out, but the username stays reserved under Deleted accounts. Audit logs, bookmarks and evidence records name it, and those records cannot change, so the name must keep meaning one person; it can never be created again."),
      ),
      p("Either way the account is removed from every case it was assigned to, with an entry in that case's audit log, and the deletion is written to the system audit log. You cannot delete your own account or the last active admin."),
    ],
  },
  {
    id: "evidence", title: "Cases and evidence", icon: "disk",
    body: [
      p("Create a case on the Cases page, then use ", h("b", "+ Add evidence"), ". Browse to the image or paste its path."),
      kv([
        ["E01 (EWF)", "Pick the .E01; the other segments (.E02, ... .EAA) are found automatically. Compressed and uncompressed images both work."],
        ["Raw / dd", ".dd, .raw, .img, .bin, or split .001, .002, ..."],
        ["Virtual disks", "VHD (fixed, dynamic and differencing), VHDX (dynamic, fixed and differencing) and VMDK (flat, sparse, streamOptimized as exported in OVA files, split into 2 GB extents, and snapshots). Pick the disk itself (for VMDK the small descriptor .vmdk, not a -flat or -s001 extent); parents of differencing disks and snapshots are found next to it by the names the disk records, and a parent that changed after the child was made is reported. A VHDX that was not shut down cleanly is read with its log replayed in memory, as Hyper-V would on the next mount (the file is not changed), and the summary says how many writes were replayed. Ex01 is recognized but not read yet."],
        ["Partitions", "MBR (with extended partitions) and GPT, or a single volume with no partition table."],
        ["File systems", "NTFS, FAT12, FAT16, FAT32, exFAT, ext2, ext3, ext4, ISO 9660, UDF, HFS+ and APFS are parsed, live and deleted files alike. Volume Shadow Copies on NTFS volumes are rebuilt and read as volumes of their own (pick them with the volume buttons)."],
        ["BitLocker", "Encrypted volumes (Windows 7 and later, BitLocker To Go) are listed on the Summary with their method, drive label and key protectors. Unlock one there with its password, its 48-digit recovery password or its startup key file ({GUID}.BEK, given as a path on the Kokino server): Kokino keeps the volume key with the case (never the password), records the unlock in the audit log, failed attempts too, and analyzes the evidence again with the decrypted volume as a volume of its own, shadow copies inside it included. Volumes with protection suspended are read without asking. Carving and the text index work on the decrypted volume; carved files from it show their offset in that volume (the hex view shows the image as stored). TPM protectors and Windows Vista volumes are not read."],
        ["Images inside evidence", "Disk images stored as files on the evidence (E01, VHD, VHDX, VMDK, ISO, raw) are listed on the Summary. Extract as evidence copies all of an image's files into the case, checks the copy against the bytes read, records both in the audit log and adds the image as evidence of its own, noting where it came from."],
        ["Folders", "A collection copied out as plain files (KAPE's or Velociraptor's output folder): pick the folder and click Use this folder. Kokino packs it into a tar inside the case, hashing every file into a manifest (manifest.tsv next to the tar, its SHA-256 in the audit log), then examines the tar like any collection. Files in use that cannot be read are listed in the audit entry."],
        ["Triage collections", "Add a Velociraptor offline collection, a KAPE ZIP or a UAC tar / tar.gz as it is: it is read as a file system, and Windows and Linux artifacts are read with the paths they had on the collected system. A .tar.gz is decompressed in memory (up to 1 GiB; decompress larger ones with gzip -d and add the .tar). Checks that need a whole volume are not made from a collection."],
      ]),
      p("If you have the acquisition hash, paste it: Kokino reports whether the image still matches. For E01 it also checks the hash the imaging tool stored inside the file. Both results go into the audit log, and a mismatch is shown in red on the evidence card."),
      p("Hashing and analysis run in the background; progress shows at the top right. ", h("b", "Re-analyze"), " reruns the analysis after a Kokino upgrade; ", h("b", "Re-hash + analyze"), " also recomputes the hashes."),
      p("Open ", h("b", "Acquisition details"), " on an E01 card to see what the imager recorded: case number, examiner, notes, dates, device model and serial, and any sectors it could not read."),
      p("Admins can remove a case with ", h("b", "Delete case"), " on the case page, after typing its name. The evidence image files are never touched. The case folder (analysis, index, carving results, bookmarks, exports and the case audit log) is moved to ", h("code", ".kokino/deleted"), " in the cases directory, not wiped, and the deletion is recorded in the system audit log with each evidence item's SHA-256. Admins bring a case back from ", h("b", "Deleted cases"), " (Restore); the restore is recorded in both audit logs."),
      p("Examiners on a case and admins can change its name and description with ", h("b", "Edit case"), "; admins can also hand it to another lead examiner, who becomes an examiner on the case. The case id and folder stay the same, and each change is recorded in the case audit log with its old and new value."),
    ],
  },
  {
    id: "views", title: "Working with an image", icon: "pie",
    body: [
      kv([
        ["Summary", "Disk layout, counts, the impact summary in plain sentences, the anti-forensics gauge and an activity histogram (click a day to open the timeline)."],
        ["Explorer", "The folder tree including deleted and orphaned entries. Click a file for its detail drawer: both timestamp sets side by side, data streams, signature, entropy, where its MFT record lies on disk, its timeline events and a hex preview."],
        ["Timeline", "MACB events from $SI and $FN interleaved with browser visits, downloads and searches, Windows artifacts and, on NTFS, files created, deleted and renamed per the change journal (USN). Filter by text, date, source, deleted or flagged. The case page Case timeline merges the timelines of all items."],
        ["Web activity", "Browser history per profile (Chrome family, Firefox, Safari, Internet Explorer and the old Edge): visits, downloads, searches and Internet Explorer's cache and cookies. Click a profile card to filter by it."],
        ["Email", "Messages in Outlook PST and OST files, mbox mailboxes and .eml files, with their text and attachments."],
        ["Anti-forensics", "Each indicator with its weight, caveat and the exact files: click Show files to list them, then a file to open it."],
        ["Hex", "The whole image, any size. See Hex and exports."],
      ]),
      h("h4", "Reading timestamps"),
      p("$STANDARD_INFORMATION ($SI) times can be changed by user programs; $FILE_NAME ($FN) times are set by Windows itself and are much harder to forge. A file whose $SI creation is earlier than its $FN creation, or lands on an exact second while $FN does not, is the classic sign of timestomping. All NTFS times are UTC."),
      h("h4", "Deleted files on NTFS"),
      ul(
        h("span", h("b", "MFT records:"), " a deleted file keeps its MFT record (name, times, size, where its content lies) until Windows reuses the record for a new file, which on a busy system happens fast. Kokino reads every record and warns when a deleted file's clusters are in use again."),
        h("span", h("b", "Names without a record:"), " the name often outlives the record. Each folder's index ($I30) keeps removed entries in its slack until they are overwritten, and the NTFS log ($LogFile) records every index change with the entry itself. Kokino reads both and lists names no MFT record accounts for as deleted, marked ", h("i", "Name only"), ", with their $FN times and size and the MFT record they had, but no content (carving may still find it). An old name of a file that was renamed or moved is listed the same way and says what the file is called now."),
        h("span", h("b", "When it was deleted:"), " NTFS keeps no deletion time, but the change journal does: the file details show what the journal recorded for the file, and the Change journal page lists every deletion."),
      ),
    ],
  },
  {
    id: "fat", title: "USB sticks and SD cards (FAT, exFAT)", icon: "disk",
    body: [
      p("FAT12, FAT16, FAT32 and exFAT volumes are parsed like NTFS: Explorer, Timeline, signatures, full-text search, carving, bookmarks and exports all work on them. A disk with several partitions can mix NTFS and FAT; pick the volume at the top of each page."),
      ul(
        h("span", h("b", "Deleted files:"), " a deleted entry keeps its name (long names are restored from their checksum), size and first cluster. The FAT chain is cleared on delete, so Kokino reads the following clusters as contiguous; the drawer says ", h("i", "Recovered as contiguous"), ". A fragmented deleted file can come back partly wrong."),
        h("span", h("b", "Overwritten content:"), " when a deleted file's clusters are in use by another file, or its first cluster no longer starts with the header its type needs (a .jpg without a JPEG header), the drawer shows a parser note. Cameras do this often. Try the Carved files page, which finds pictures by content."),
        h("span", h("b", "Deleted folders:"), " their entries are still read, so files inside them are listed too (as deleted)."),
        h("span", h("b", "Timestamps:"), " FAT has one set (created, modified, accessed date) in the device's local time with no time zone, 2 second precision. Kokino shows them as stored, not converted. exFAT stores a UTC offset, so its times are shown in UTC."),
      ),
      p("There is no $FN, USN journal or alternate data stream on FAT, so the indicators that need them stay silent. Entry ids are assigned by Kokino in directory order; FAT has no record numbers."),
    ],
  },
  {
    id: "linux", title: "Linux disks (ext2, ext3, ext4)", icon: "disk",
    body: [
      p("ext2, ext3 and ext4 volumes are parsed like NTFS: Explorer, Timeline, signatures, full-text search, carving, hashes, bookmarks and exports all work on them. Open a file to see its inode, mode (as ls shows it), owner uid and gid, link target and hard link count."),
      ul(
        h("span", h("b", "Timestamps:"), " every inode has modified (M), accessed (A) and inode changed (C) times, in UTC; ext4 adds the creation time (B) and nanoseconds. A deleted inode also keeps its deletion time, shown as D in the file details and as DEL on the timeline. touch can set M and A to anything, but not C."),
        h("span", h("b", "Deleted names:"), " removing a name only lengthens the entry before it, so the old name stays in the directory until it is reused. Kokino reads those names with strict checks. A deleted name whose inode is now in use (a rename, or the inode reused) is listed without content and says so. ext2 also erases the inode number of a deleted name: the name is listed with a note, its content under $OrphanFiles. Deleted folders are entered through their orphaned inode, or on ext3 and ext4 through their directory block, which Kokino finds by searching the free blocks nearby."),
        h("span", h("b", "Deleted content:"), " ext2 keeps a deleted file's block pointers, so its content is read as is. ext3 and ext4 clear them (and the size). Their journal often still holds an older copy of the inode; when it is the same file (same generation), Kokino reads the content through it and the file shows ", h("i", "Recovered from the journal"), ". Otherwise only the Carved files page can bring the content back, and the summary says how many deleted files that leaves."),
        h("span", h("b", "Orphans:"), " inodes no name points to (deleted files whose names are gone, or files unlinked while still open) are listed under $OrphanFiles as inode-N."),
      ),
      h("h4", "Linux system summary"),
      p("The System summary page reads the machine's own files: os-release, hostname and time zone; accounts from passwd, shadow (only whether and how a password is set, never the hash), group and lastlog; logons, failures, reboots and shutdowns from wtmp, btmp, auth.log or secure and the systemd journal; shell histories; sudo and account changes; installed packages from dpkg, apt, dnf, yum, apk or pacman, with who installed them; persistence (cron, systemd units, rc.local, SSH authorized keys, sudoers, ld.so.preload, shell startup files); USB storage the kernel logged; networks from NetworkManager, DHCP leases, known_hosts and /etc/hosts."),
      ul(
        h("span", h("b", "Syslog times:"), " classic syslog lines (\"Oct 20 10:10:01\") have no year and no time zone. Kokino converts them with the image's own /etc/localtime and counts the year back from the log file's modification time; such events are marked with *. Newer RFC 3339 lines and the journal carry exact UTC times."),
        h("span", h("b", "Shell histories:"), " bash writes its history when the shell exits and records times only when HISTTIMEFORMAT was set; zsh and fish always do. Commands that destroy evidence (shred, history -c, removing logs, touch -d, journal vacuum) are flagged."),
        h("span", h("b", "Journal:"), " fields the journal stored compressed (long messages) are counted, not read, in this version."),
      ),
    ],
  },
  {
    id: "mac", title: "Mac disks (HFS+, APFS)", icon: "disk",
    body: [
      p("HFS+ (Mac OS Extended, also HFSX) and APFS volumes are parsed like the others; an APFS container with several volumes shows each as a top-level folder. The file details show the catalog or inode number, the owner and mode, and the link target."),
      ul(
        h("span", h("b", "Compression:"), " macOS stores many files compressed inside an extended attribute or the resource fork (decmpfs). Kokino decodes zlib and LZVN, so such files show their real size and content; other tools often show them as empty. LZFSE is reported, not decoded yet."),
        h("span", h("b", "Hard links:"), " on HFS+ a hard link is a small record pointing to an iNode file in a hidden folder; Kokino shows the link with the iNode file's content and times."),
        h("span", h("b", "Extended attributes:"), " including com.apple.quarantine, which macOS sets on files that came from the internet (the app that downloaded them and when)."),
        h("span", h("b", "Deleted files on HFS+:"), " removing a file compacts its catalog node, so the record survives only in older copies of that node: in the journal, or in catalog nodes no longer in use. Kokino reads them and lists the files the live catalog no longer has, with their content when the blocks are still free (it says when they are not)."),
        h("span", h("b", "Deleted files on APFS:"), " APFS never changes metadata in place; older copies of the file-system tree stay in free blocks until they are reused. Kokino reads every intact one and lists the names and inodes the current tree no longer has, with the content their old extents point to."),
        h("span", h("b", "Not read yet:"), " encrypted (FileVault) APFS volumes (reported), APFS snapshots, APFS free space for carving, LZFSE compression and macOS unified logs."),
      ),
      h("h4", "macOS system summary"),
      p("On a Mac disk (HFS+ or APFS) or a collection from a Mac, the same page shows the macOS version and build, the computer's name, when the Mac was set up, local accounts (dslocal records; admins from the admin group; Apple's _ service accounts left out), launchd agents and daemons outside /System with the program each runs, downloads from each user's quarantine database (Safari, Mail, browsers: when, from where) and application use from KnowledgeC (which app was in front, and for how long). Shell histories in /Users homes are read like Linux ones; rm -P (secure delete) is flagged. A launchd job is flagged when it runs a program from /tmp, /Users/Shared or a hidden folder, or pipes a download into a shell. FSEvents (/.fseventsd, also on USB drives a Mac used) list every path created, changed, renamed or removed, under Events as File change; they have no time of their own, so each shows when its batch file was written, and they stay off the timeline. Unified logs are not read yet."),
    ],
  },
  {
    id: "optical", title: "Optical discs and .iso files (ISO 9660, UDF)", icon: "disk",
    body: [
      p("Add a .iso file (or a raw image of a CD, DVD or Blu-ray) as evidence like any other image. Explorer, Timeline, signatures, search, hashes, bookmarks and exports work on it; there is no free space to carve on a disc."),
      ul(
        h("span", h("b", "ISO 9660:"), " Rock Ridge gives POSIX names, owners, modes, times and symbolic links (deep folders that Rock Ridge moved to rr_moved are shown where they belong); Joliet gives Unicode names. Times are recorded as local time with its offset from UTC, to the second."),
        h("span", h("b", "Multisession discs:"), " each session adds a new directory tree, and old data stays on the disc. Kokino shows the newest session as the live file system, and lists files that only older sessions have (removed or replaced later) as deleted, with the session they come from. Their content is read from the disc."),
        h("span", h("b", "UDF:"), " DVDs, Blu-ray discs and packet-written media, UDF 1.02 to 2.60. A deleted file's directory entry stays in its folder with a deleted flag; Kokino lists it, with the content its file entry still points to (which may by then belong to something else, and says so). On a disc with both, UDF is used unless the ISO 9660 side has more than one session."),
        h("span", h("b", "Not read yet:"), " UDF virtual partitions (CD-R written incrementally) and sparable partitions (DVD-RW); the summary says when a disc uses them."),
      ),
    ],
  },
  {
    id: "web", title: "Browser history", icon: "globe",
    body: [
      p("Email is on its own page: see Email."),
      p("Kokino reads Chrome, Edge, Brave, Opera, Vivaldi, Firefox and Safari (History.db and Downloads.plist) profiles it finds on any parsed volume, including history still waiting in the -wal file that the browser had not merged yet, and Internet Explorer's index.dat files (Internet Explorer 4 to 9: history, cache and downloads) and WebCache database (WebCacheV01.dat: Internet Explorer 10 and 11 and the old Edge: history, cache, cookies and downloads; a copy taken while in use may lack the newest entries, which are still in its log files)."),
      ul(
        h("span", h("b", "Visits:"), " time, page, how it was reached (typed, link, reload, form...), time on page and visit count."),
        h("span", h("b", "URL table only:"), " pages whose visit rows are gone (expired or deleted selectively); the time shown is the last recorded visit."),
        h("span", h("b", "Downloads:"), " source URL, where it was saved, size, state and the browser's danger warning."),
        h("span", h("b", "Searches:"), " from the browser's own keyword table and from visited search-engine pages."),
        h("span", h("b", "Internet Explorer:"), " one card per index.dat: the main history (last visit of each page), daily and weekly files (one entry per page per day or week), protected-mode history, the cache (IE cache list: URL, cached file, content type) and the download list. A page in both the main and a daily file is shown once. ", h("i", "Deleted entry"), " marks an entry recovered from free blocks inside index.dat; ", h("i", "LEAK"), " a cache entry that was deleted while its file was in use. Daily files keep each visit also in local time, so the card says what the computer's clock was set to."),
        h("span", h("b", "Cookies (Internet Explorer):"), " the cookie index and the cookie text files in the Cookies folders: site, name, value, created, expires and when the site's cookies were last used. Cookie files the index no longer lists, and index entries whose file is gone, are marked."),
        h("span", h("b", "Deleted index.dat files:"), " Carve on the Carved files page: whole index.dat files and single history, cache and download records are recovered from free space (list ie-records)."),
      ),
      p("A history with no visits at all, or a deleted history database, raises the ", h("i", "Browser history cleared"), " indicator."),
    ],
  },
  {
    id: "mail", title: "Email", icon: "mail",
    body: [
      p("Kokino lists the messages in Outlook PST and OST files, Apple Mail folders (.emlx, one mailbox per .mbox folder), mbox mailboxes (Thunderbird and SeaMonkey mail folders, /var/mail and /var/spool/mail on Linux, .mbox files) and single .eml files, live and deleted: date, sender, recipients, subject, attachments and the first words of the text. Click a message for its text, every header and its attachments; Export saves an attachment in the case's exports folder with its hashes in the audit log."),
      ul(
        h("span", h("b", "Deleted in Thunderbird:"), " a message deleted in Thunderbird stays in the mailbox file, marked deleted, until the folder is compacted. Kokino lists it and marks it."),
        h("span", h("b", "Search:"), " message text (quoted-printable, base64 and character sets decoded, HTML without its markup) and document attachments (PDF, Office, ZIP...) are in the full-text index."),
        h("span", h("b", "Timeline:"), " every dated message is an event (source MAIL)."),
        h("span", h("b", "Outlook:"), " PST files (Outlook 97 to today) and OST files (also the compressed ones of Outlook 2013 and later), encrypted or not, of any size: they are read in place. Each message shows its folder; attached messages (forwarded mail, meeting items) are attachments of their own, exported as .eml. Messages whose folder is gone are listed with \"(folder not found)\"."),
        h("span", h("b", "Not read yet:"), " deleted PST items still in the file's free blocks, message bodies kept only as RTF, Apple Mail .emlx and Windows Live Mail stores."),
      ),
    ],
  },
  {
    id: "system", title: "System summary (Windows; Linux and macOS are under their disks)", icon: "monitor",
    body: [
      p("For a Windows volume, Kokino reads the registry hives (SYSTEM, SOFTWARE, SAM, each user's NTUSER.DAT and UsrClass.dat, Amcache.hve), the event logs, Prefetch files, Recent-folder shortcuts, Jump Lists, the NTFS change journal ($UsnJrnl), the SRUM database and the scheduled task files, deleted copies included, recovers deleted keys and values from the hives' free space, and shows them on the System summary page:"),
      ul(
        h("span", h("b", "Overview:"), " computer name, Windows version and build, install date, owner, time zone and last shutdown, plus highlights (log clearing, anti-forensic tools, unusual autostart entries)."),
        h("span", h("b", "Programs run:"), " Prefetch (run count and last eight run times, Windows 10/11 compressed files included), UserAssist (per user, with run count and focus time), BAM and DAM (the last run of each program per user, kept about a week, Windows 10 1709 and later), Amcache (path, SHA-1, first seen), ShimCache and process-creation events (4688)."),
        h("span", h("b", "Files and folders:"), " shortcuts and Jump Lists with the target's volume label, serial number and drive type (which ties a file to a USB stick or network share) and the machine name and MAC address; recent documents, typed paths, the Run box and Explorer searches."),
        h("span", h("b", "Windows XP and 2003:"), " the legacy event logs (SecEvent.Evt, SysEvent.Evt, AppEvent.Evt), including records left in the unused part of the log, are read like the logs of later Windows: their Security events (logons 528/540, failed logons 529-539, log cleared 517, process started 592, accounts created 624, group changes, service installs 601) appear under Events with the user, logon type and address. Profiles under Documents and Settings and a Windows 2000 \\WINNT folder are found too."),
        h("span", h("b", "Deleted registry:"), " keys and values recovered from the free space of every hive. Windows marks a deleted key's cell free but does not clear it. Each key is shown with the path of the key it belonged to, when it last changed before it was deleted (not the deletion itself) and the values still there. Values that an older copy of a live key holds but the key no longer has are listed under that key; values found on their own have no key. Keys that record user activity (recent documents, the Run box, typed addresses, UserAssist, ShellBags...) are named: deleting them is what cleaners do, and the anti-forensics score counts it. Transaction logs (.LOG1/.LOG2) are not applied yet."),
        h("span", h("b", "Folders (ShellBags):"), " every folder a user opened in Explorer, from UsrClass.dat (Windows 7 and later) or NTUSER.DAT, kept after the folder, the USB stick or the network share is gone: full path, when it was last opened, the folder's own times and its MFT record (tied to this volume when it matches). Folders inside ZIP files and on network shares are included."),
        h("span", h("b", "Change journal:"), " Windows records every change to a file in $UsnJrnl: created, written, renamed (with the old name), deleted. Records of one round of changes are combined into one line; filter by kind or path. The journal keeps the newest tens of megabytes, which covers days on a busy system and much longer on a quiet one, and it keeps names and folders of files whose MFT records were reused long ago. The overview says what period it covers."),
        h("span", h("b", "Network use (SRUM):"), " the System Resource Usage Monitor database (SRUDB.dat) records, about every hour and per user, how many bytes each program sent and received over which network (Wi-Fi networks by name) and how much it read and wrote to disk, for the last 30 to 60 days, and when the computer was connected to which network. Programs are listed by data sent; click one for its hours. Hours in which a program sent 100 MiB or more join the Timeline. SRUDB.dat is an ESE database, which Kokino reads itself; one copied from a running system may lack the newest hours, which are then only in its transaction logs (not read), and the page says so."),
        h("span", h("b", "USB and networks:"), " USB storage devices with serial number, drive letter and first, last and removal times; wireless and wired networks with first and last connection and gateway MAC; network interfaces."),
        h("span", h("b", "Accounts and logons:"), " local accounts (SAM) with last logon and logon count, and logons per account from the event logs, with failed attempts, remote desktop sessions and source IP addresses."),
        h("span", h("b", "Events:"), " notable events in plain language: log clearing (1102, 104), logons, account and group changes, services and scheduled tasks, remote desktop, PowerShell script blocks, Defender detections, boots and shutdowns. Click one for every field."),
        h("span", h("b", "Software and autostart:"), " installed programs, Run keys and services, with entries running from user-writable locations marked; and scheduled tasks, from the task files in Windows\\System32\\Tasks and the registry's TaskCache, which also records when each task was created and last ran. Windows' own tasks are behind a toggle. A task whose TaskCache\\Tree key lost its SD value is flagged: it still runs, but schtasks and the Task Scheduler do not list it (the Tarrask technique). A task registered without a task file, or a task file no longer registered, is marked too."),
      ),
      p("The same records join the Timeline (filter Windows) and feed anti-forensics indicators: an event log cleared, an anti-forensic tool in execution records, files renamed AAAA.AAA through ZZZZ.ZZZ in the change journal (SDelete's pattern; the journal keeps their original names), a change journal created long after Windows was installed (deleted and recreated), a scheduled task hidden from the Task Scheduler, and registry keys that record user activity found deleted."),
      p("A hive that was not cleanly saved has its newest changes only in its transaction logs (.LOG1 and .LOG2, or .LOG on Windows XP). Kokino applies them in memory before reading the hive, as Windows would on its next start, checking each log entry's checksums; Sources says what was applied, or why a log could not be used. The evidence is not changed."),
      p("Not yet read: SRUM's energy and app timeline tables, legacy .job task files (Windows XP) and Windows 7 ShimCache."),
    ],
  },
  {
    id: "correlation", title: "Correlation", icon: "layers",
    body: [
      p("The case page Correlation lists what two or more evidence items of the case have in common: user names, computer names, email addresses (senders and recipients), IP addresses (logons and events), USB serial numbers, wireless networks, web domains (visits and downloads) and identical files (the same SHA-256, files of 1 KiB or more, from the hashes taken at analysis). Each value shows the items it was found in and how often; click one to open it. Values are compared without regard to case. Items not analyzed yet are left out and named at the top."),
    ],
  },
  {
    id: "case-timeline", title: "Case timeline", icon: "clock",
    body: [
      p("The case page Case timeline merges the timelines of every analyzed evidence item and volume of the case into one, in time order: the laptop, the USB stick and the server side by side. Each row names its item and volume (v0, v1, ...); click it to open the file, the web activity or the system summary of that item. Filter by text, day range and kind (web, system, deleted, flagged) as on an item's own timeline."),
      p("Times from NTFS, ext, HFS+, APFS and the artifacts are UTC and line up across items. FAT stores the device's local clock with no zone, so a FAT volume's place among the other items depends on that device's time zone: check it before reading order across items."),
    ],
  },
  {
    id: "watchlist", title: "Watchlist (IOC sweep)", icon: "search",
    body: [
      p("The case page Watchlist searches every analyzed evidence item of the case at once for a list of indicators, one per line, recognized by their form:"),
      ul(
        h("span", h("b", "MD5, SHA-1, SHA-256:"), " file contents, from the hashes Hash analysis takes; run Hash analysis on each item first (items without it are named)."),
        h("span", h("b", "IP addresses"), " (IPv4 and IPv6): Windows and Linux event records and logons."),
        h("span", h("b", "Domains and URLs:"), " web visits, downloads, cache and cookies of the domain and its subdomains, email from or to addresses at the domain, and files of exactly that name (", code("ld.so.preload"), " looks like a domain)."),
        h("span", h("b", "Email addresses:"), " senders and recipients (From, To, Cc)."),
        h("span", h("b", "Anything else:"), " a file name (exact, any case) or, with a / or \\ in it, a fragment of a path; deleted files included."),
      ),
      p("Lines starting with # are comments; text after \" #\" on a line is kept as the indicator's note. Defanged forms from reports (hxxp://, [.], (.), [:], [@]) are read as the real thing. Up to 5,000 indicators; up to 500 hits each are listed."),
      p("Each hit opens where it was found: a file in its details drawer, an event or logon in the system summary, a visit in web activity, a message in Email. ", h("b", "Save list"), " keeps the list with the case; saving and each sweep are recorded in the audit log with the number of indicators and hits. Reviewers can run sweeps but not change the saved list."),
    ],
  },
  {
    id: "bookmarks", title: "Bookmarks and tags", icon: "star",
    body: [
      p("Use the ", h("b", "Bookmark"), " button to keep and label what matters: on a file (in its details drawer), an event, a carved file, a search hit, a browser history entry or a byte range in the hex view. Pick tags (Evidence, Relevant, Suspicious, Exculpatory, Follow up, Privileged, Not relevant, or your own) and add a note."),
      ul(
        h("span", h("b", "Snapshot:"), " each bookmark keeps what it points at (name, path, time, offset). For files, Kokino computes the MD5 and SHA-256 of the content from the evidence when you bookmark it."),
        h("span", h("b", "Bookmarks page:"), " under the case in the menu. Filter by tag or text, open an item, edit its tags and note."),
        h("span", h("b", "Quick list:"), " a one-page HTML list of every bookmarked item, or of one tag, with locations, hashes, tags, notes and who bookmarked what."),
        h("span", h("b", "Case report:"), " the full report for handing over, with the bookmarks as numbered exhibits (see Case reports)."),
        h("span", h("b", "Who can:"), " examiners and admins manage all bookmarks; reviewers can add bookmarks and change or remove their own, so a review can be done without write access to the evidence or analysis."),
      ),
      p("Adding, changing and removing bookmarks, and generating the report, are recorded in the case audit log."),
    ],
  },
  {
    id: "hashsets", title: "Hash sets and hash analysis", icon: "hash",
    body: [
      p("A hash set is a list of file hashes. ", h("b", "Known good"), " sets (such as the NIST NSRL) list files of ordinary software, so matching files can be hidden. ", h("b", "Known bad"), " sets list files your lab wants flagged. Admins import them under Hash sets; they are shared by every case and recorded in the system audit log with the SHA-256 of the source file."),
      p("Accepted: NSRL RDS v3 (.db, or the .sql files NIST publishes for full and delta releases), NSRL RDS 2.x NSRLFile.txt, CSV with MD5 / SHA-1 / SHA-256 columns, and plain lists (md5sum and sha256sum output work). Unzip downloads first. From SQL files, only the md5, sha1 and sha256 columns are taken. A hash set database takes roughly 100 bytes per hash on disk; the full NSRL needs several GB free."),
      p(h("b", "Hash analysis"), " (per evidence item, also run at the end of ingest) hashes every file with content and compares it with the enabled sets. Known-bad files get a red badge in Explorer, the Explorer can hide known-good files, and the file details show all three hashes. When sets change, Check again compares the stored hashes without reading the evidence again. Case reports name the sets used."),
      p("A match means identical content, not how a file got there. For deleted files the content is what their clusters hold now. On the console: ", h("code", "kokino hashset import NSRLFile.txt --name NSRL --kind known"), "."),
    ],
  },
  {
    id: "reports", title: "Case reports", icon: "book",
    body: [
      p("The ", h("b", "Case report"), " button on the Bookmarks page (examiners and admins) turns the bookmarks of a case, or the ones with one tag, into a report you can hand over. Give it a title, your reference, who asked for the examination and your summary of findings. Kokino adds the rest:"),
      ul(
        h("span", h("b", "Summary"), " with an exhibit index, and whether every exhibit still matches its hash."),
        h("span", h("b", "Case and evidence:"), " each evidence item with its format, size, path, MD5, SHA-1 and SHA-256, and whether they match the acquisition hash and the hash stored in the image."),
        h("span", h("b", "Exhibits:"), " one per bookmark, numbered E-001, E-002... with its location (volume, path, MFT record or directory entry, image offset), timestamps, size, hashes, automated findings, tags and your note. Kokino reads each exhibit from the evidence again and hashes it: ", h("i", "matches"), " means the content is still exactly what you bookmarked. Pictures are shown from the evidence bytes, a bookmarked region outlined and enlarged; byte ranges and search hits get a hex dump."),
        h("span", h("b", "Chain of custody"), " from the case audit log: when evidence was added, hashed and processed, exports and earlier reports, with the state of the log's hash chain."),
        h("span", h("b", "Methods and tools"), " (what ran, when, with which Kokino version), ", h("b", "limitations"), " (including the caveats of every automated finding cited) and a ", h("b", "sign-off"), " block for signatures. Optionally the full audit log as an appendix."),
      ),
      p("Two files are made: HTML, which you print to PDF from the browser (Ctrl+P, Save as PDF; page numbers and the report id are on every page), and Word (.docx) to edit or add your letterhead. Both are saved in the case's exports folder, and their SHA-256 is written to the case audit log. The Case reports list on the Bookmarks page checks each file against that hash, so you can tell whether a copy was changed after it was made."),
      p("Wording such as an expert declaration depends on your jurisdiction; add it in the summary or in the Word file. On the command line: ", h("code", "kokino report <case folder> --reference LAB-1 --tag Evidence --summary summary.txt"), "."),
    ],
  },
  {
    id: "carving", title: "Carved files", icon: "layers",
    body: [
      p("Carving recovers files that no file system record describes any more, by their content. It runs after analysis (or with ", h("b", "Carve unallocated space"), " on the Carved files page) over every free cluster or block (NTFS, FAT, exFAT, ext2/3/4, HFS+), the space outside partitions and volumes Kokino cannot parse yet. On ext3 and ext4 it is often the only way back to a deleted file's content."),
      ul(
        h("span", h("b", "Formats:"), " JPEG, PNG, GIF, BMP, WebP, PDF, Word, Excel and PowerPoint (DOCX/XLSX/PPTX and the older DOC/XLS/PPT), OpenDocument, EPUB, ZIP, JAR, APK, Outlook MSG, SQLite, Windows executables, DLLs and drivers, GZIP, 7-Zip, WAV, AVI, MP4/MOV, Jump Lists, 64 KiB event log chunks (with their record count and time range, often all that is left of a cleared log) and Internet Explorer index.dat files."),
        h("span", h("b", "Internet Explorer records:"), " every 128-byte boundary of free space is also checked for single index.dat records (history visits, cache entries, cookies, downloads, redirects), which keep that alignment when the file is deleted. They are listed under ie-records with the user, URL, time and whether they lie inside a carved index.dat. On a formatted disk this is often all that is left of the browsing history."),
        h("span", h("b", "Whole files:"), " each format's own structure says where the file ends (JPEG markers, PNG chunks, the ZIP central directory, the PE section table, the SQLite page count, the end of a GZIP stream...), so random bytes that only resemble a header are not listed. A file whose end is missing is kept and marked incomplete."),
        h("span", h("b", "Contiguous:"), " carving assumes a file's clusters were contiguous. One that runs past the end of its free region is marked: its tail may belong to another file."),
        h("span", h("b", "Deleted files:"), " when a carved file starts where a deleted file's data started, the deleted file's path is shown."),
        h("span", h("b", "BitLocker:"), " the free space of an unlocked BitLocker volume is carved decrypted. Those files show their offset as \"vol N: offset\" (inside the decrypted volume N) instead of an image offset; preview, export and hashes read them decrypted. The encrypted bytes themselves are not carved once the volume is unlocked."),
      ),
      p("Pictures appear in a gallery. Every carved file shows its offset (a link to the hex view), size, MD5 and SHA-256. Export writes it to the case's exports folder, records the hashes in the audit log and checks them against the carve. Text inside carved PDFs and Office files is added to the search index (shown as Carved in search results)."),
    ],
  },
  {
    id: "pictures", title: "Pictures (photo forensics)", icon: "image",
    body: [
      p("The Pictures page lists every JPEG, PNG and BMP of an evidence item, live, deleted and carved, with what Kokino found in each. It runs automatically after analysis and carving, or with ", h("b", "Analyze pictures"), "; each run is written to the audit log. Click a picture for the viewer, or use ", h("b", "Analyze picture"), " in a file's drawer or on a carved picture."),
      h("h4", "Findings (computed by Kokino, with what they do not prove)"),
      ul(
        h("span", h("b", "Saved by editing software:"), " Photoshop, GIMP, Lightroom and others named in EXIF, XMP, Adobe segments or comments."),
        h("span", h("b", "EXIF thumbnail shows a different picture:"), " the stored preview is compared with the image (shape and a 6x6 grid). Editors that keep the old EXIF block leave the pre-edit preview behind. Calibrated on real camera photos: unedited ones never reached the threshold; most cloned or painted-over regions and all crops did. Global color changes are not detected."),
        h("span", h("b", "Compressed twice:"), " the DCT coefficient histograms of a re-saved JPEG show periodic peaks and gaps. Calibrated to stay silent on single saves; about 6 in 10 re-saves are caught. Not detectable: a re-save at the same quality, a re-save after a crop that moves the 8x8 grid, or a first save at near-lossless quality (many cameras)."),
        h("span", h("b", "Camera named, but software compression tables:"), " a dedicated camera brand in EXIF while the file uses the standard libjpeg tables that software writes."),
        h("span", h("b", "Compression differs from the same camera's other photos:"), " tables no other photo of that make and model in the evidence uses."),
        h("span", h("b", "Data hidden after the end of the image:"), " bytes after the end marker (an appended ZIP, document or message). Known phone trailers, motion-photo videos and extra MPF images are listed but not flagged."),
        h("span", h("b", "Least significant bits look like hidden data (PNG, BMP):"), " the chi-square test finds the value pairs evened out over a run of the pixel data, from the start or the end, with a control test against naturally smooth histograms. Sequential embedding of 10% or more is found; embedding spread thinly over the whole image, and JPEG stego tools (steghide, F5, OutGuess), are not."),
        h("span", h("b", "Information:"), " GPS position, EXIF changed date differing from the capture date, and JPEGs without EXIF in a camera (DCIM) folder."),
      ),
      h("h4", "Viewer"),
      kv([
        ["Magnifier", "A round lens centered on the cursor that enlarges whatever view is shown, relative to its size on screen (2x to 32x), plain, auto-contrast or equalized, with the pixel coordinates under the cursor. With the lens on, the mouse wheel sets its strength and Shift+wheel zooms the picture."],
        ["Error level", "Saves the picture again as JPEG and shows the difference. Edited or pasted areas often stand out; edges and text always look bright."],
        ["Noise", "Difference to a 3x3 median: regions with a different grain."],
        ["Level sweep", "Stretches a narrow band of brightness to show edges at one level."],
        ["Gradient", "Direction and strength of brightness changes: lighting that does not fit."],
        ["Bit planes", "One bit of one channel. A noise-only run in plane 0 of a lossless picture is how LSB hiding looks."],
        ["Clones", "Copy-move detection: block pairs with the same shift, one color per shift. Edge-like and flat blocks are skipped; repeated patterns can still match."],
        ["Mark region", "Drag a rectangle to bookmark that region with tags and a note; the region and view go into the bookmark report, and the bookmark reopens the viewer on it."],
      ]),
      p("The viewer shows pixels as stored (EXIF rotation and color profiles not applied), so positions match the file. Side panels show the EXIF block, the thumbnail next to the picture and their difference, both quantization tables with the libjpeg quality they match, the coefficient histogram behind the double-compression score, the LSB test curve, and the JPEG segments or PNG chunks."),
      p("Command line: ", h("code", "kokino image <file>"), " prints the same analysis as JSON for one exported picture."),
    ],
  },
  {
    id: "search", title: "Full-text search", icon: "search",
    body: [
      p("Each evidence item has a text index. It is built automatically after analysis; for evidence analyzed before the index existed, open Search and press ", h("b", "Build text index"), ". Building it is an examiner action and is recorded in the audit log."),
      p("What is indexed:"),
      ul(
        h("span", h("b", "Files:"), " every data stream (including alternate data streams) of live and deleted files, as long as the deleted record still describes its clusters. Streams over 512 MiB are indexed up to that size."),
        h("span", h("b", "Unallocated clusters:"), " every cluster or block marked free in the NTFS $Bitmap, the FAT, the exFAT allocation bitmap or the ext block bitmaps. Content of deleted files usually shows up here too, once as the file and once as free space."),
        h("span", h("b", "Outside the volumes:"), " space between and after partitions, and volumes whose file system Kokino cannot parse yet, read raw."),
      ),
      p("Text is extracted like the classic strings tool: runs of at least 4 printable characters in UTF-8 (which covers ASCII) and in UTF-16LE (how Windows stores most text), including Cyrillic and Greek."),
      p("Compressed documents are also opened, so their words are searchable:"),
      ul(
        h("span", h("b", "ZIP and everything built on it:"), " Word, Excel and PowerPoint (DOCX, XLSX, PPTX and macro variants), OpenDocument, EPUB, JAR and plain ZIP archives. Body text, tables, slides, comments, footnotes, tracked deletions and author metadata are read; archives inside archives are opened up to 4 levels deep."),
        h("span", h("b", "PDF:"), " page text (including fonts that need a ToUnicode map, as Word-made PDFs use), document info (title, author, producer, dates) and XMP metadata."),
        h("span", h("b", "GZIP:"), " decompressed and searched like any other content."),
        h("span", h("b", "Word, Excel and PowerPoint 97-2003, Outlook .msg and RTF:"), " the document text (Word through its piece table, Excel's shared strings and sheet names, PowerPoint's slide and notes text), message subjects, bodies and recipients, and the document properties (title, author, keywords, comments, last saved by)."),
      ),
      p("Such hits say where inside the file they are (for example ", h("code", "inside word/document.xml"), " or ", h("code", "inside page 3"), ") and are marked Decoded. Decoded text has no single place in the image, so it has no image offset; open the file to view or export it. Encrypted documents and scanned PDFs without a text layer are not decoded; the first are still covered by the plain strings pass. Each document is limited to 64 MiB per part and 256 MiB in total, so a zip bomb cannot exhaust the machine; anything skipped is listed on the Search page."),
      ul(
        h("span", h("b", "Keywords:"), " whole words, all must appear. \"Quoted phrases\", OR, NOT and prefix* work."),
        h("span", h("b", "Regex:"), " Rust regular expressions inside each extracted string; case-insensitive unless ticked."),
        h("span", h("b", "Presets:"), " email addresses, URLs, IPv4 addresses, payment card numbers (Luhn-checked), IBANs (checksum-checked) and Bitcoin addresses."),
      ),
      p("Each hit shows where it is (file path, free clusters, or outside any partition), the match in context and its offset in the image. Click a row to open the file, or the offset to see the exact bytes in the hex view. Every search, with its query and hit count, is written to the case audit log."),
    ],
  },
  {
    id: "bytes", title: "Byte map and strings", icon: "hex",
    body: [
      p("The ", h("b", "byte map"), " (after the idea of binvis.io) draws data as a square picture along a Hilbert curve: bytes that are near each other in the file stay near each other on screen, so structure shows as shapes. Each cell is one slice, colored by its bytes: 0x00 black, 0xFF white, text blue, other low (control) bytes green, high bytes red. The Entropy view colors by randomness instead: dark for repetitive data, bright pink for compressed or encrypted data. Hover a cell for its offset and make-up; click it to open that place in the hex."),
      p("Look for what does not fit: a block of high entropy inside a document (embedded archive, encrypted payload), text inside a picture, 0xFF or zero runs where data should be (wiped or erased). Each cell is judged from its first 4 KiB, so a small object inside a large cell can be missed; zoom in by opening the file's own map."),
      p(h("b", "Strings"), " lists printable text with its offset: ASCII and UTF-8 (Cyrillic and other scripts included) and UTF-16LE (Windows), at least 5 characters by default. Runs that only look like text (binary tables decoding to accented letters) are filtered out. Up to the first 64 MiB of a file is scanned. Click a string to see it in the hex."),
      p("Where: file details (Byte map, Strings), the Bytes and strings button of a picture or carved file, and the Byte map button in Hex for the whole image. Full-text search across the whole disk is under Search."),
    ],
  },
  {
    id: "hex", title: "Hex and exports", icon: "hex",
    body: [
      p("Go to an offset as a decimal number, ", code("0x"), " hex, or ", code("s:"), " sector number. The data inspector decodes the selected bytes as integers, FILETIME, Unix time and UTF-16."),
      p("Search finds text (ASCII and UTF-16) or hex bytes across the whole image; long searches continue in steps."),
      p(h("b", "Overlay editing:"), " switch it on and type hex digits. Changes are stored in the case and logged; the evidence file is never written. Revert them one by one or all at once."),
      p(h("b", "Lists:"), " Export lists on the evidence summary writes any list (files with their hashes, the timeline, web activity, every Windows and Linux artifact, indicators, carved files) as CSV or JSON, with times in UTC; the Timeline, Web activity and Carved files pages have CSV and JSON buttons for what they show. CSV cells that start like a formula get a leading apostrophe so a spreadsheet does not run them; JSON keeps every value exactly. Each export is saved in the case's exports folder and recorded in the audit log with its SHA-256."),
      p(h("b", "Exports:"), " select a range (click, then shift+click) and export it raw or with the overlay applied. From a file's drawer you can export the file or any of its streams. Every export is hashed, saved in the case's exports folder and logged."),
    ],
  },
  {
    id: "af", title: "Anti-forensics score", icon: "alert",
    body: [
      p("Sixteen documented rules look for timestomping, secure deletion, wiped content, disguised executables, hidden streams, encrypted containers, cleared logs and browser history, and wiping tools that were present, run, downloaded or researched."),
      p("Each rule has a weight and a saturation constant, so 500 similar files count as one behaviour rather than 500 pieces of evidence. The rules are combined into one likelihood from Low to Very high."),
      h("div.cav", "The score tells you where to look first. It is not a finding: read every indicator's caveat and confirm with other artifacts before you rely on it."),
    ],
  },
  {
    id: "report", title: "Reports and audit logs", icon: "chain",
    body: [
      p(h("b", "HTML report"), " (on the evidence card and the summary) is a single self-contained file: case and evidence details, hash verification, acquisition metadata, volumes, the impact summary, every indicator with example files, web activity and limitations. Save it from the browser."),
      p(h("b", "Case audit log:"), " every action on the case, by account, hash-chained. If any entry is altered, removed or reordered, the case shows a red integrity warning and the report says BROKEN."),
      p(h("b", "System audit"), " (admins): sign-ins, failed attempts, lockouts, account changes and case assignments."),
      p("Verify a case log on the console:"),
      pre("kokino verify-audit ~/KokinoCases/<case-id>"),
    ],
  },
  {
    id: "lan", title: "Lab server (LAN) mode", icon: "lock",
    body: [
      p("To let examiners connect from their own machines, listen on the network. Kokino then always uses HTTPS."),
      pre("kokino serve --listen 0.0.0.0 --port 8443 --hostname forensics.lab"),
      ul(
        "Without a certificate Kokino makes a self-signed one and prints its SHA-256 fingerprint. Compare it with what the browser shows before accepting the warning.",
        h("span", "Use your own certificate with ", code("--tls-cert cert.pem --tls-key key.pem"), "."),
        h("span", code("--hostname"), " names only work once DNS or each machine's hosts file knows them; the server's IP address always works."),
        "Allow the program through the firewall on private networks only.",
      ),
    ],
  },
  {
    id: "cli", title: "Command line", icon: "tree",
    body: [
      p("The same engine works without the GUI, for scripting and batch work:"),
      pre(
        "kokino analyze disk.E01 --json analysis.json   # summary on screen, full results as JSON",
        "kokino hash disk.E01                           # MD5/SHA-1/SHA-256; checks the E01 stored hash (exit 3 on mismatch)",
        "kokino files disk.E01 [--json] [--extract DIR] # every file, live and deleted, with MD5/SHA-1/SHA-256; --extract writes them out",
        "kokino analyze disk.E01 --bitlocker-password -  # unlock BitLocker (also --recovery-password, --startup-key FILE.BEK; - asks; analyze, files and carve)",
        "kokino carve disk.E01 [--json]                 # carve free space; each carved file with offset, length and hashes",
        "kokino verify-audit <case folder>              # exit 2 if the chain is broken",
        "kokino purge                                   # remove everything Kokino stored on this machine (asks first)",
        "kokino artifact NTUSER.DAT [--full]            # parse one exported hive (logs next to it are applied), .evtx, .pf, .lnk, Jump List or index.dat",
        "kokino export <case folder> [evidence] [list|all] [--fs N] [--format csv|json]  # lists as CSV or JSON, saved in the case and audited",
        "kokino user add|reset|role|disable|list        # accounts",
        "kokino serve --help                            # all server options",
      ),
    ],
  },
  {
    id: "trouble", title: "Troubleshooting", icon: "shield",
    body: [
      kv([
        ["Page looks old or the menu misbehaves", "Press Ctrl+F5 once."],
        ["\"Session expired\"", "You were idle for 60 minutes or the server restarted. Sign in again; you return to the same page."],
        ["\"Too many failed attempts\"", "Wait the time shown, or ask an admin to reset your password."],
        ["Site can't be reached (LAN)", "Use the server's IP address instead of the hostname, check the port and the firewall."],
        ["\"segment N of the image is missing\"", "Copy all E01 segment files into the same folder with their original names."],
        ["Case shows an audit integrity warning", "Do not edit the case folder. Preserve it as it is and investigate who changed audit.jsonl."],
        ["Web activity says re-analyze", "The evidence was analyzed by an older Kokino. Click Re-analyze."],
      ]),
    ],
  },
  {
    id: "validation", title: "Validation (test images)", icon: "chain",
    body: [
      p("Kokino's results are checked against public forensic test images that come with independent ground truth: published hashes, the original files, file lists and NIST's documented layout of every deleted file. Thank you to the people behind them:"),
      ul(
        h("span", h("b", "Digital Corpora"), " (", link("https://digitalcorpora.org", "digitalcorpora.org"), "), created by Simson Garfinkel and colleagues at the Naval Postgraduate School."),
        h("span", h("b", "NIST CFReDS"), " (", link("https://cfreds.nist.gov", "cfreds.nist.gov"), "), the Computer Forensic Reference Data Sets of NIST's Computer Forensics Tool Testing program: the Deleted File Recovery test images."),
        h("span", h("b", "dfvfs and libyal"), " (Joachim Metz and the log2timeline project): the shadow copy and BitLocker To Go test images and the format documentation behind them."),
        h("span", h("b", "java-libpst, Aspose.Email and pst-extractor"), ": the public Outlook PST and OST sample files."),
      ),
      h("div.scroll", h("table.tbl",
        h("thead", h("tr", h("th", "Data set"), h("th", "Checked"), h("th", "Result"))),
        h("tbody", [
          ["Digital Corpora nps-2009-canon2 (FAT32 camera card)", "Image hashes; recovered pictures against the real files", "Hashes match the published SHA-1; 34 of 36 recoverable pictures byte for byte (33 from the file system, 1 carved); the 3 overwritten deleted pictures flagged"],
          ["Digital Corpora nps-2009-ntfs1 (NTFS)", "File list against DFXML; compressed and encrypted copies against the originals", "All files, names and sizes right; all 9 compressed copies identical to the originals; EFS files read as ciphertext and marked"],
          ["NIST CFReDS deleted file recovery, 22 ext images (ext2, ext3, ext4)", "Every deleted file with content, block by block; deleted names against NIST's layout", "962 of 965 tagged files complete (99.9996% of blocks); 302 recovered through the ext3/ext4 journal; 2,782 deleted names listed; wrong content without a warning in 1 file"],
          ["dfvfs vss.raw (NTFS with two shadow copies)", "Shadow copy IDs and times against dfvfs; the files each snapshot holds", "Both stores found with dfvfs' IDs and times; each snapshot a complete NTFS volume with the files it should and should not have"],
          ["dfvfs bdetogo.raw (BitLocker To Go, AES-128 with diffuser)", "Unlock with the published password; the decrypted files", "Wrong password refused; every file decrypts to the content dfvfs' tests expect"],
          ["Public PST and OST samples (4 files, ANSI to OST 2013)", "Every folder and message; attachments rendered and read back", "89 folders and 95 messages in all, none unreadable; attachments at their stated sizes"],
          ["NIST CFReDS deleted file recovery, 61 images", "Every deleted file, block by block, against each file's own tags", "3,048 of 3,323 deleted test files complete; 99.8% of blocks right (exFAT and NTFS 100%); wrong content without a warning in 4 files"],
        ].map(([a, b, c]) => h("tr", h("td", h("b", a)), h("td", b), h("td", c)))))),
      p("The checks found and fixed real problems: NTFS compressed files are now decompressed (they were read as stored), fragmented deleted exFAT files are followed along their surviving chain, and deleted files whose space was reused, or claimed by another deleted file, are flagged on NTFS as on FAT."),
      h("h3", "Known limits"),
      ul(
        "FAT erases a deleted file's cluster chain, so a fragmented deleted FAT file comes back only up to its first fragment; Kokino marks every deleted FAT file \"Recovered as contiguous\" and warns when the guess runs into another file.",
        "NTFS deleted files whose MFT record was reused have no content to check; their names are found in folder indexes and $LogFile, and the counts come close to NIST's (case 08 exactly). See VALIDATION.md.",
        "ext3 and ext4 clear a deleted file's block map: its content comes back only through an older copy of its inode in the journal, or by carving. ext2 erases the inode number from the deleted name, so the name and the content (under $OrphanFiles) are listed separately.",
        "Carving assumes a file is stored in one piece, so fragmented pictures with no directory entry left are not rejoined.",
      ),
      p("VALIDATION.md in the source has every image's numbers, the method and how to repeat it; ", code("kokino files"), " and ", code("kokino carve"), " are the command-line tools it uses."),
      h("h3", "Golden results"),
      p("Every commit is also checked against recorded results for all the test images in the source (38 analyses: every file system, image format, collection type and virtual disk Kokino reads, BitLocker locked and unlocked), on Windows, Linux and macOS: the volumes found, file statistics, the anti-forensics score, the number of entries in every artifact list and a digest of the file listing. A change in what Kokino finds in any of them stops the build until it is explained."),
    ],
  },
  {
    id: "security", title: "Security and fuzzing", icon: "shield",
    body: [
      p("Evidence can be made to attack the tool that reads it: a disk image, registry hive or picture crafted to crash Kokino, hang an ingest, or use up the examiner's memory. Kokino is written in Rust with ", code("unsafe"), " code forbidden in every crate, and every parser that reads evidence has been fuzzed."),
      h("h3", "Release integrity"),
      p("Every release has ", code("SHA256SUMS.txt"), ", a CycloneDX SBOM (", code("kokino-<version>-sbom.cdx.json"), ": every third-party crate in the build with its version, checksum and license) and a build provenance attestation for every file, signed through GitHub (Sigstore), which ties the file to the workflow run and commit that built it. Check a download with ", code("gh attestation verify <file> --repo zeroscience/Kokino"), ". The Windows and macOS packages are not yet code-signed with a publisher certificate."),
      h("h3", "Fuzzing"),
      p("A purpose-built fuzzer (", code("crates/kokino-fuzz"), ") fed each parser valid samples changed by random and boundary-value mutations: flipped bits, extreme lengths and offsets, cut and spliced data. A failure is any crash, integer overflow, stack overflow, allocation of more than 256 MiB from a small file, or input that takes over 20 seconds. Three rounds over all 15 targets (5, 20 and 10 minutes each, new random seeds every time) and later rounds on pictures, NTFS compression, the file system walkers, the ext reader, the Linux log parsers, virtual disks, optical media, Mac disks, NTFS folder indexes and $LogFile, the change journal, ShellBags, ESE databases (SRUM), scheduled tasks, Internet Explorer index.dat, deleted registry keys, legacy Office files, registry logs, legacy event logs, email, journald compression, ZIP and tar collections, shadow copies, BitLocker, VHDX logs, Outlook PST, property lists, FSEvents, WebCache, Apple Mail and the watchlist ran ", h("b", "669,995,687 inputs"), " and found ", h("b", "38 distinct problems, all fixed"), "; review while fixing found 4 more. Every failing input is kept and replayed by the test suite."),
      h("div.scroll", h("table.tbl",
        h("thead", h("tr", h("th", "Target"), h("th", "Covers"), h("th", "Inputs"), h("th", "Found"))),
        h("tbody", [
        ["volume", "MBR, extended and GPT partition tables, file system detection", "193,631", "none"],
        ["ntfs", "NTFS: boot sector, every MFT record, attributes and attribute lists, data runs, stream reads, free-space bitmap, folder index slack and $LogFile names", "389,998", "3 (hang, memory, panic)"],
        ["fat", "FAT12, FAT16, FAT32 and exFAT: boot sectors, FAT chains, directories, deleted entries, long names", "386,599", "4 (memory, overflow)"],
        ["ext", "ext2, ext3 and ext4: superblock, group descriptors, inodes, extents, indirect blocks, directories and their slack, journal copies", "1,332,425", "1 (memory)"],
        ["linuxlogs", "systemd journal, wtmp/btmp, syslog dates, TZif time zones, apt history, DHCP leases, dpkg status", "28,941,401", "3 (overflow)"],
        ["vdisk", "Virtual disks: VHD, VHDX and VMDK headers, block tables, grain tables, compressed grains, VHDX log replay", "239,674", "none"],
        ["optical", "ISO 9660 (Rock Ridge, Joliet, sessions) and UDF (descriptors, partitions, file entries, directories)", "4,318,442", "3 (overflow, out-of-range reads)"],
        ["mac", "HFS+ (catalog, extents, attributes, journal) and APFS (checkpoints, object maps, file-system trees), decmpfs with zlib and LZVN", "232,151", "3 (overflows, out-of-range read)"],
        ["indx", "NTFS folder index records and $LogFile pages: the name carver behind names without an MFT record", "35,329,154", "none"],
        ["usn", "NTFS change journal records (versions 2 to 4), grouping into changes, $Max", "8,954,455", "none"],
        ["shellbags", "BagMRU trees and every shell item kind", "15,785,595", "none"],
        ["ese", "ESE databases (pages, B+ trees, catalog, records, long values, 7-bit and XPRESS compression) and SRUM, two rounds", "824,539", "none"],
        ["task", "Scheduled task XML, the TaskCache Actions and DynamicInfo blobs, TaskCache in a hive", "19,733,957", "none"],
        ["evt", "Legacy .evt event logs (Windows NT to 2003)", "30,689,834", "none"],
        ["zip", "ZIP collections read as file systems (Velociraptor, KAPE), and nested image detection", "5,383,514", "2 (crash on escaped names, memory; fixed)"],
        ["tar", "tar and tar.gz collections (UAC): headers, GNU long names, PAX records, links", "4,169,869", "none"],
        ["pst", "Outlook PST and OST: B-trees, blocks, data and subnode trees, property and table contexts, messages", "8,102,508", "2 (crash on dates, read past the end; fixed)"],
        ["plist", "Apple property lists, binary and XML", "1,229,272", "1 (overflow on a huge date; fixed)"],
        ["fsevents", "macOS FSEvents: gzip, pages of every version, records", "50,215,572", "none"],
        ["webcache", "WebCache (Internet Explorer 10 and 11, old Edge) read into web activity", "743,157", "none"],
        ["ioc", "The watchlist parser: indicator kinds, defanged forms, URL hosts, domain and IP comparison", "13,628,459", "1 (IPv4-mapped address did not match; fixed)"],
        ["vss", "Volume Shadow Copies: catalog, block lists, overlays and forwarders, snapshot reads", "9,887,067", "2 (overflow, stack overflow; fixed)"],
        ["bde", "BitLocker: metadata, key protectors, key unwrapping, startup key files, the decrypting reader for every method", "4,459,482", "1 (overflow, fixed)"],
        ["mail", "Mailboxes and messages: MIME, encodings, attachments, Apple Mail .emlx", "12,525,090", "none"],
        ["journalz", "journald compressed fields: XZ, LZ4, zstd", "45,374,291", "none"],
        ["reglog", "Registry transaction logs (both formats) applied to a dirty hive", "58,565,421", "none"],
        ["iecache", "Internet Explorer index.dat: records, history, cache, downloads, records in free space", "21,653,615", "1 (out-of-range slice, fixed)"],
        ["ewf", "E01 (EWF) images: sections, chunk tables, zlib chunks, stored hashes", "42,686", "1 (overflow)"],
        ["registry", "Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, Amcache): cells, key and value lists, the whole key tree", "23,242,474", "1 (hang)"],
        ["evtx", "Windows event logs: chunks, binary XML templates and substitutions", "3,188,571", "none"],
        ["lnk", "LNK shortcuts and shell item lists", "46,723,093", "none"],
        ["prefetch", "Prefetch files, including Windows 10/11 compressed ones", "27,204,698", "none"],
        ["jumplist", "Jump Lists: OLE compound files (automatic) and custom destinations", "20,340,604", "1 (memory)"],
        ["xpress", "LZXPRESS Huffman decompression", "2,321,551", "none"],
        ["doc", "Text extraction: ZIP (nested), Word, Excel, PowerPoint, OpenDocument, GZIP, PDF", "21,576,629", "1 (panic)"],
        ["photo", "Picture forensics: JPEG decoder, EXIF and thumbnails, quantization tables, PNG, BMP", "7,614,505", "5 (overflow, hang, crash)"],
        ["carve", "File carving: header and end detection for every carved format", "19,238,950", "1 (panic)"],
        ["browser", "Browser history: Chromium and Firefox SQLite databases", "57,033", "none (1 hang found by review)"],
        ["strings", "Strings and byte map", "22,137,771", "none"]
        ].map(([t, d, n, f]) => h("tr", h("td.mono", t), h("td", d), h("td.num", n), h("td", f)))))),
      p("Examples of what was fixed: an NTFS volume whose ", code("$MFT"), " claimed billions of records, an exFAT boot sector that made Kokino reserve 16 GB for a 2.6 MB image, a Jump List of 3 KB that expanded to over 500 MiB, a registry key listed under itself, and a JPEG declaring 1.2 gigapixels. None of them could run code or change evidence; they could stop or slow a job, or exhaust memory."),
      h("h3", "Other protections"),
      ul(
        h("span", h("b", "Databases from evidence"), " (browser history) are opened in SQLite's defensive mode, with schema SQL not trusted, page checks on and a time limit. A History file that replaces a table with a never-ending view is refused."),
        h("span", h("b", "Background jobs"), " end as failed, with a message, if a parser ever panics, instead of showing as running."),
        h("span", h("b", "Reports"), " are served with a sandbox policy: no scripts run, whatever text the evidence put in them."),
        h("span", h("b", "Evidence paths"), " inside the cases directory are refused, so no one can read another case, the accounts or the TLS key through the hex view."),
      ),
      h("h3", "Reporting a problem"),
      p("Found a file that crashes or hangs Kokino, or a way around a permission? Please write to ", mail(CONTACT.email), " rather than opening a public issue. Include the version and build from the About page, and the smallest file that shows the problem, never real case data. SECURITY.md in the source has the full method, every finding and the limits of the testing."),
    ],
  },
  {
    id: "privacy", title: "Privacy", icon: "lock",
    body: [
      p("Kokino runs entirely on your workstation or lab server. It sends nothing anywhere on its own: no telemetry, no automatic update checks, no crash reports, no fonts or scripts from the internet. The page's security policy only lets it talk to the Kokino server itself, and links to outside sites (Wikipedia, zeroscience.mk) open only when you click them."),
      p("The one exception is the update check, and only when you ask for it: ", code("Check for updates"), " on the About page (or ", code("kokino version --check"), ") makes one HTTPS request from the Kokino server to api.github.com for the latest release, sends nothing about you or your cases (GitHub sees the request and the Kokino version), and is recorded in the system audit log. Nothing is downloaded or installed."),
      p("Evidence images are opened read-only and never changed. Everything Kokino produces stays in the cases folder:"),
      ul(
        h("span", h("b", "Per case:"), " case details and members, evidence records with their hashes, analysis results, the text index, carved-file and picture findings (offsets, hashes and findings, not copies), bookmarks and notes, overlay edits, BitLocker volume keys you unlocked (the keys folder; never the password), exports you chose to make, and the case audit log."),
        h("span", h("b", "In <cases>/.kokino:"), " hash sets (hashsets folder), accounts (Argon2id password hashes, never the passwords themselves), the system audit log (sign-ins, account and membership changes) and, in lab server mode, the TLS certificate."),
        h("span", h("b", "In memory only:"), " sign-in sessions; they end when the server stops."),
        h("span", h("b", "In your browser:"), " only the theme you picked."),
      ),
      p("The text index and findings contain text and details taken from the evidence, so protect the cases folder like the evidence itself: disk encryption, access control and backups. Audit logs are hash-chained and never rewritten, so names in past entries stay even after an account is deleted; that is what keeps the chain of custody verifiable (see Accounts and roles)."),
    ],
  },
  {
    id: "license", title: "License", icon: "book",
    body: [
      p("Kokino FTK is licensed under the ", link("https://www.apache.org/licenses/LICENSE-2.0", "Apache License, Version 2.0"), ". Copyright 2026 Zero Science Lab. The full text is in the LICENSE file shipped with Kokino, with a NOTICE file."),
      ul(
        "You may use, copy, modify and distribute Kokino, including commercially and inside other products.",
        "Keep the license and the NOTICE file with copies, and mark files you changed.",
        "Contributors grant a patent license for their contributions.",
        "It comes without warranty: validate the results for your own casework, as with any forensic tool.",
        "The license does not grant use of the Kokino or Zero Science Lab names and logo beyond saying where the software came from.",
        "The logo painting is by Siebe Boersma and stays the artist's work; the Apache license does not cover it.",
      ),
      p("Third-party components keep their own licenses (MIT, Apache-2.0 and similar); the About page lists them."),
    ],
  },
  {
    id: "name", title: "About the name", icon: "clock",
    body: [
      p("Kokino FTK is named after the Kokino observatory, a Bronze Age megalithic site from around the 19th century BC near Kumanovo, in the northeast of North Macedonia. Stone markers cut into the rock there follow the Sun and the Moon on the horizon, marking sunrise at the solstices and equinoxes: people reading time from traces, as this toolkit does from the bytes on a disk."),
      p("More: ", link("https://en.wikipedia.org/wiki/Kokino", "the observatory on Wikipedia"), "."),
    ],
  },
  {
    id: "art", title: "Logo and artwork", icon: "image",
    body: [
      p("The logo is a detail of a painting by the Dutch artist ", link("https://siebeboersma.nl/", "Siebe Boersma"), ": a face that is mostly hair and brush strokes, with two green eyes looking straight out. A fitting look for a tool whose job is to see what is hidden in plain sight. The whole painting is on the About page."),
      p("The painting stays the work and copyright of Siebe Boersma. It is not covered by Kokino's Apache license, so do not reuse it apart from Kokino without the artist's permission."),
      h("h3", "The original emblem"),
      p("Kokino's first logo, an orbit and sun emblem after the stone markers of the Kokino observatory, with the KOKINO FORENSIC TOOLKIT wordmark:"),
      h("div.wiki-logo", h("img", { src: "img/logo.png", alt: "The original Kokino Forensic Toolkit emblem and wordmark", width: 1200, height: 800 })),
    ],
  },
  {
    id: "contact", title: "Contact and support", icon: "user",
    body: [
      kv([
        ["Website", link(CONTACT.web)],
        ["Email", mail(CONTACT.email)],
        ["GitHub", link(CONTACT.github)],
      ]),
      p("When you report a problem, include the version and build from the About page, what you did, and what you expected. Never send real case data: describe it, or reproduce the problem with a test image."),
      p("Security vulnerabilities: please report privately by email."),
    ],
  },
];

export function wikiPage(startAt) {
  const content = h("div.wiki-body");
  const toc = h("nav.wiki-toc");
  const search = h("input", { type: "search", placeholder: "Search the wiki...", "aria-label": "Search the wiki" });
  const sections = WIKI.map((s) => {
    const el = h("section.card.wiki-sec", { id: "wiki-" + s.id }, h("h2", h("span.ico", icon(s.icon, 18)), s.title), ...s.body);
    return { ...s, el, text: (s.title + " " + el.textContent).toLowerCase() };
  });
  const jump = (s, smooth = true) => s.el.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" });
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    const hits = sections.filter((s) => !q || q.split(/\s+/).every((w) => s.text.includes(w)));
    content.replaceChildren(...(hits.length ? hits.map((s) => s.el) : [h("div.card.empty", "Nothing matches. Try fewer words.")]));
    toc.replaceChildren(h("h3", "Contents"), ...sections.map((s) => h("a", { href: "#/wiki/" + s.id, class: hits.includes(s) ? null : "dim", onclick: (e) => { e.preventDefault(); history.replaceState(null, "", "#/wiki/" + s.id); jump(s); } }, s.title)));
  };
  search.addEventListener("input", debounce(draw, 120));
  draw();
  const page = h("div.wiki",
    h("div.hd", h("div", h("h1", "Wiki"), h("p.muted", { style: { margin: "4px 0 0" } }, "How to use Kokino, from first start to the report.")), h("span.sp"), search),
    h("div.wiki-grid", toc, content),
  );
  // The contents list scrolls on its own: its height is what is left of the
  // window below where it sits (it moves up while the page scrolls).
  const fitToc = () => {
    if (!toc.isConnected) { window.removeEventListener("resize", fitToc); document.removeEventListener("scroll", fitToc, true); return; }
    if (getComputedStyle(toc).position !== "sticky") { toc.style.maxHeight = ""; return; }
    toc.style.maxHeight = `${Math.max(160, window.innerHeight - Math.max(0, toc.getBoundingClientRect().top) - 12)}px`;
  };
  window.addEventListener("resize", fitToc);
  document.addEventListener("scroll", fitToc, true);
  setTimeout(fitToc, 30);
  const target = sections.find((s) => s.id === startAt);
  if (target) setTimeout(() => jump(target, false), 60);
  return page;
}
