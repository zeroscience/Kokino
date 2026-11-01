"""Browser history databases for the ground-truth fixture.

Builds small but schema-faithful SQLite files with Python's sqlite3:

  chrome_history     Chrome "History": a typed Google search recorded in
                     keyword_search_terms, a visit to the SDelete page, a
                     completed SDelete.zip download with its URL chain, a
                     Bing search known only from its URL, and a URL whose
                     visit rows were deleted (URL table only)
  edge_history       Edge "History" with the full schema and no rows: cleared
  firefox_places     Firefox "places.sqlite" in WAL mode: two visits in the
                     main file; a DuckDuckGo search visit, a download
                     annotation and one more visit only in places.sqlite-wal

Times are fixed (2026-10-20, UTC) so tests can assert exact values.
"""

import datetime
import os
import shutil
import sqlite3
import tempfile

EPOCH_1601 = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
EPOCH_1970 = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def at(hh, mm, ss=0):
    return datetime.datetime(2026, 10, 20, hh, mm, ss, tzinfo=datetime.timezone.utc)


def webkit(t):
    return int((t - EPOCH_1601).total_seconds() * 1_000_000)


def prtime(t):
    return int((t - EPOCH_1970).total_seconds() * 1_000_000)


CHROMIUM_SCHEMA = """
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
  visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
  last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
  from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL, segment_id INTEGER,
  visit_duration INTEGER DEFAULT 0 NOT NULL, incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL);
CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL, current_path LONGVARCHAR NOT NULL,
  target_path LONGVARCHAR NOT NULL, start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL, state INTEGER NOT NULL, danger_type INTEGER NOT NULL,
  interrupt_reason INTEGER NOT NULL, hash BLOB NOT NULL, end_time INTEGER NOT NULL, opened INTEGER NOT NULL,
  last_access_time INTEGER NOT NULL, transient INTEGER NOT NULL, referrer VARCHAR NOT NULL,
  site_url VARCHAR NOT NULL, tab_url VARCHAR NOT NULL, tab_referrer_url VARCHAR NOT NULL,
  http_method VARCHAR NOT NULL, by_ext_id VARCHAR NOT NULL, by_ext_name VARCHAR NOT NULL,
  etag VARCHAR NOT NULL, last_modified VARCHAR NOT NULL, mime_type VARCHAR(255) NOT NULL,
  original_mime_type VARCHAR(255) NOT NULL);
CREATE TABLE downloads_url_chains(id INTEGER NOT NULL, chain_index INTEGER NOT NULL, url LONGVARCHAR NOT NULL,
  PRIMARY KEY (id, chain_index));
CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL,
  term LONGVARCHAR NOT NULL, normalized_term LONGVARCHAR NOT NULL);
"""

FIREFOX_SCHEMA = """
CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR,
  visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL,
  frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER, guid TEXT, url_hash INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
  visit_date INTEGER, visit_type INTEGER, session INTEGER, source INTEGER DEFAULT 0 NOT NULL,
  triggeringPlaceId INTEGER);
CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name VARCHAR(32) UNIQUE NOT NULL);
CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER NOT NULL, anno_attribute_id INTEGER,
  content LONGVARCHAR, flags INTEGER DEFAULT 0, expiration INTEGER DEFAULT 0, type INTEGER DEFAULT 0,
  dateAdded INTEGER DEFAULT 0, lastModified INTEGER DEFAULT 0);
"""


def _new(path, schema, wal=False):
    c = sqlite3.connect(path)
    c.execute("PRAGMA page_size = 1024")
    if wal:
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA wal_autocheckpoint = 0")
    c.executescript(schema)
    return c


def chrome_history(tmp):
    p = os.path.join(tmp, "chrome")
    c = _new(p, CHROMIUM_SCHEMA)
    c.execute("INSERT INTO meta VALUES ('version', '67')")
    urls = [
        (1, "https://www.google.com/search?q=how+to+permanently+delete+files", "how to permanently delete files - Google Search", 1, 1, webkit(at(9, 0, 5))),
        (2, "https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete", "SDelete - Sysinternals", 1, 0, webkit(at(9, 1))),
        (3, "https://download.sysinternals.com/files/SDelete.zip", "", 1, 0, webkit(at(9, 2))),
        (4, "https://www.bing.com/search?q=secure+erase+ssd&form=QBLH", "secure erase ssd - Search", 1, 0, webkit(at(9, 30))),
        # Visit rows removed: only the URL table remembers this page.
        (5, "https://files.example.test/upload/quarterly-results.xlsx", "Upload complete", 3, 0, webkit(at(10, 15))),
    ]
    c.executemany("INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?, 0)", urls)
    # transition: 1 typed (0x30000001 = typed + chain start/end), 0 link, 0 link, 1 typed
    visits = [
        (1, 1, webkit(at(9, 0, 5)), 0, 0x30000001, 4_000_000),
        (2, 2, webkit(at(9, 1)), 1, 0x30000000, 52_000_000),
        (3, 3, webkit(at(9, 2)), 2, 0x30000000, 0),
        (4, 4, webkit(at(9, 30)), 0, 0x30000001, 9_000_000),
    ]
    c.executemany("INSERT INTO visits (id, url, visit_time, from_visit, transition, visit_duration) VALUES (?, ?, ?, ?, ?, ?)", visits)
    c.execute(
        "INSERT INTO downloads VALUES (1, 'a1b2', ?, ?, ?, 851264, 851264, 1, 0, 0, x'', ?, 1, 0, 0, ?, '', ?, '', 'GET', '', '', '', '', 'application/x-zip-compressed', 'application/x-zip-compressed')",
        (r"C:\Users\alice\Downloads\SDelete.zip", r"C:\Users\alice\Downloads\SDelete.zip", webkit(at(9, 2)), webkit(at(9, 2, 3)),
         "https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete", "https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete"),
    )
    c.execute("INSERT INTO downloads_url_chains VALUES (1, 0, 'https://download.sysinternals.com/files/SDelete.zip')")
    c.execute("INSERT INTO keyword_search_terms VALUES (2, 1, 'how to permanently delete files', 'how to permanently delete files')")
    c.commit()
    c.close()
    return open(p, "rb").read()


def edge_history(tmp):
    p = os.path.join(tmp, "edge")
    c = _new(p, CHROMIUM_SCHEMA)
    c.execute("INSERT INTO meta VALUES ('version', '67')")
    c.commit()
    c.close()
    return open(p, "rb").read()


def firefox_places(tmp):
    """Returns (places.sqlite, places.sqlite-wal) as the browser left them."""
    p = os.path.join(tmp, "places.sqlite")
    c = _new(p, FIREFOX_SCHEMA, wal=True)
    c.executemany("INSERT INTO moz_places (id, url, title, visit_count, typed, last_visit_date) VALUES (?, ?, ?, ?, ?, ?)", [
        (1, "https://www.mozilla.org/en-US/firefox/new/", "Get Firefox", 1, 0, prtime(at(11, 0))),
        (2, "https://www.veracrypt.fr/en/Downloads.html", "VeraCrypt - Downloads", 1, 1, prtime(at(11, 5))),
    ])
    c.executemany("INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, visit_type, session) VALUES (?, ?, ?, ?, ?, 0)", [
        (1, 0, 1, prtime(at(11, 0)), 1),
        (2, 0, 2, prtime(at(11, 5)), 2),
    ])
    c.executemany("INSERT INTO moz_anno_attributes VALUES (?, ?)", [(1, "downloads/destinationFileURI"), (2, "downloads/metaData")])
    c.commit()
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    # Everything below stays in the WAL only.
    c.executemany("INSERT INTO moz_places (id, url, title, visit_count, typed, last_visit_date) VALUES (?, ?, ?, ?, ?, ?)", [
        (3, "https://duckduckgo.com/?q=veracrypt+hidden+volume&ia=web", "veracrypt hidden volume at DuckDuckGo", 1, 0, prtime(at(11, 20))),
        (4, "https://launchpad.net/veracrypt/trunk/1.26.7/+download/VeraCrypt_Setup_x64_1.26.7.exe", "", 1, 0, prtime(at(11, 22))),
    ])
    c.executemany("INSERT INTO moz_historyvisits (id, from_visit, place_id, visit_date, visit_type, session) VALUES (?, ?, ?, ?, ?, 0)", [
        (3, 0, 3, prtime(at(11, 20)), 1),
        (4, 3, 4, prtime(at(11, 22)), 7),
    ])
    c.executemany("INSERT INTO moz_annos (place_id, anno_attribute_id, content, dateAdded) VALUES (?, ?, ?, ?)", [
        (4, 1, "file:///C:/Users/alice/Downloads/VeraCrypt_Setup_x64_1.26.7.exe", prtime(at(11, 22))),
        (4, 2, '{"state":1,"endTime":%d,"fileSize":38457616}' % (prtime(at(11, 23)) // 1000), prtime(at(11, 22))),
    ])
    c.commit()
    # Copy while the connection is open: closing would checkpoint the WAL.
    db = open(p, "rb").read()
    wal = open(p + "-wal", "rb").read()
    c.close()
    return db, wal


def build():
    tmp = tempfile.mkdtemp(prefix="kokino-fx-")
    try:
        ff, ff_wal = firefox_places(tmp)
        return {"chrome": chrome_history(tmp), "edge": edge_history(tmp), "firefox": ff, "firefox_wal": ff_wal}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
