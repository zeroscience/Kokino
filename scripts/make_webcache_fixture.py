#!/usr/bin/env python3
"""WebCache test database: tests/fixtures/win/WebCacheV01.dat, written by
Windows' own database engine (esent.dll) with the tables and columns
Internet Explorer 10 and 11 and the old Edge use (WebCacheV01.dat in
%LOCALAPPDATA%\\Microsoft\\Windows\\WebCache). Invented lab data: alice,
.test domains.

  Containers      the containers: History, MSHist01... (daily), Content,
                  Cookies, iedownload, DOMStore (not read)
  Container_1     History: two visits (one a Bing search)
  Container_5     daily history: one visit to https://lab.test/admin
  Container_2     Content: a cached logo.png with its response headers
  Container_3     Cookies: lab.test, its cookie file and times
  Container_4     iedownload: tools.zip from downloads.lab.test, saved to
                  C:\\Users\\alice\\Downloads (the entry's response headers
                  end in the URL, the referrer and the path, UTF-16)

Ground truth (tested in kokino-artifacts and kokino-analysis): the times
below, from T0 = 2026-10-20 08:05:30 UTC.

Needs Windows. Usage: python scripts/make_webcache_fixture.py
"""
import datetime
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import make_srum_fixture as m  # noqa: E402

UTC = datetime.timezone.utc
T0 = datetime.datetime(2026, 10, 20, 8, 5, 30, tzinfo=UTC)


def ft(minutes):
    return m.filetime(T0 + datetime.timedelta(minutes=minutes))


# ESE's JET_bitColumnTagged is 0x2 (make_srum_fixture.py's constant of
# that name, 0x4, is JET_bitColumnNotNULL, which SRUM's always-set columns
# do not mind). WebCache leaves tagged columns empty, so the real bit.
TAGGED = 0x2


def tables(table, L, Q, D, U16):
    T = lambda s: s.encode("utf-16-le")
    LT = (m.JET_coltypLongBinary + 1)  # JET_coltypLongText = 12
    containers = [
        (1, "History", "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\"),
        (2, "Content", "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\"),
        (3, "Cookies", "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\"),
        (4, "iedownload", "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\IEDownloadHistory\\"),
        (5, "MSHist012026102020261021", "C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\MSHist012026102020261021\\"),
        (6, "DOMStore", "C:\\Users\\alice\\AppData\\LocalLow\\Microsoft\\Internet Explorer\\DOMStore\\"),
    ]
    table("Containers", [("ContainerId", m.JET_coltypLongLong, m.JET_bitColumnFixed), ("SetId", m.JET_coltypLong, m.JET_bitColumnFixed), ("Flags", m.JET_coltypLong, m.JET_bitColumnFixed),
                         ("LastAccessTime", m.JET_coltypLongLong, m.JET_bitColumnFixed), ("Name", LT, TAGGED, 1200), ("PartitionId", LT, TAGGED, 1200), ("Directory", LT, TAGGED, 1200)],
          [{"ContainerId": Q(i), "SetId": L(0), "Flags": L(0), "LastAccessTime": Q(ft(60)), "Name": T(n), "PartitionId": T("L"), "Directory": T(d)} for i, n, d in containers], key="ContainerId")
    cols = [("EntryId", m.JET_coltypLongLong, m.JET_bitColumnFixed), ("ContainerId", m.JET_coltypLongLong, m.JET_bitColumnFixed), ("CacheId", m.JET_coltypLongLong, m.JET_bitColumnFixed),
            ("UrlHash", m.JET_coltypLongLong, m.JET_bitColumnFixed), ("FileSize", m.JET_coltypLongLong, m.JET_bitColumnFixed), ("Type", m.JET_coltypLong, m.JET_bitColumnFixed),
            ("Flags", m.JET_coltypLong, m.JET_bitColumnFixed), ("AccessCount", m.JET_coltypLong, m.JET_bitColumnFixed), ("SyncTime", m.JET_coltypLongLong, m.JET_bitColumnFixed),
            ("CreationTime", m.JET_coltypLongLong, m.JET_bitColumnFixed), ("ExpiryTime", m.JET_coltypLongLong, m.JET_bitColumnFixed), ("ModifiedTime", m.JET_coltypLongLong, m.JET_bitColumnFixed),
            ("AccessedTime", m.JET_coltypLongLong, m.JET_bitColumnFixed), ("Url", LT, TAGGED, 1200), ("Filename", LT, TAGGED, 1200),
            ("ResponseHeaders", m.JET_coltypLongBinary, TAGGED)]

    def entry(eid, cid, url, accessed, count=1, created=None, modified=0, expires=0, filename=None, headers=None, size=0):
        r = {"EntryId": Q(eid), "ContainerId": Q(cid), "CacheId": Q(0), "UrlHash": Q(eid * 7919), "FileSize": Q(size), "Type": L(0), "Flags": L(0), "AccessCount": L(count),
             "SyncTime": Q(ft(accessed)), "CreationTime": Q(ft(created if created is not None else accessed)), "ExpiryTime": Q(expires), "ModifiedTime": Q(modified), "AccessedTime": Q(ft(accessed)), "Url": T(url)}
        if filename:
            r["Filename"] = T(filename)
        if headers is not None:
            r["ResponseHeaders"] = headers
        return r

    table("Container_1", cols, [
        entry(1, 1, "Visited: alice@https://www.bing.com/search?q=sdelete+download&form=QBLH", 10, count=2),
        entry(2, 1, "Visited: alice@https://downloads.lab.test/tools.zip", 12),
    ], key="EntryId")
    table("Container_5", cols, [entry(3, 5, ":2026102020261021: alice@https://lab.test/admin", 30)], key="EntryId")
    table("Container_2", cols, [entry(4, 2, "https://lab.test/logo.png", 11, filename="logo[1].png", modified=ft(-60 * 24), size=720,
                                      headers=b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 720\r\n\r\n")], key="EntryId")
    table("Container_3", cols, [entry(5, 3, "Cookie:alice@lab.test/", 11, created=11, expires=ft(60 * 24 * 365), filename="QX7LAB01.cookie")], key="EntryId")
    tail = "".join(s + "\0" for s in ["https://downloads.lab.test/tools.zip", "https://lab.test/tools", "C:\\Users\\alice\\Downloads\\tools.zip"]).encode("utf-16-le")
    table("Container_4", cols, [entry(6, 4, "iedownload:{8F1E2D3C-0000-4000-8000-0000000000DD}", 13, created=12,
                                      headers=struct.pack("<IIQ", 0x44, 0, 1_234_567) + bytes(24) + tail, size=1_234_567)], key="EntryId")


def main():
    if m.esent is None:
        sys.exit("needs Windows (esent.dll)")
    os.makedirs(m.OUT, exist_ok=True)
    p = os.path.join(m.OUT, "WebCacheV01.dat")
    m.build(p, 32768, tables=tables)
    print("wrote %s (%d bytes)" % (p, os.path.getsize(p)))


if __name__ == "__main__":
    main()
