#!/usr/bin/env python3
"""SRUM test database: tests/fixtures/win/SRUDB.dat, written by Windows'
own database engine (esent.dll, the Extensible Storage Engine), so the
pages, B-trees, catalog and record layouts are the real thing.

Tables and columns are named as on Windows 10 (System Resource Usage
Monitor). All content is invented: LAB-PC, alice, documentation networks.

  SruDbIdMapTable                           apps, services and user SIDs (7 ids)
  {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}    application resource usage
  {973F5D5C-1D90-4944-BE8E-24B94231A174}    network data usage
  {DD6636C4-8929-4683-974E-22C046A43763}    network connectivity

Ground truth (tested in kokino-artifacts and kokino-analysis):
  - rclone.exe in alice's Temp folder sent 2,147,483,648 bytes over Wi-Fi
    profile 7 between 2026-10-20 09:00 and 11:00 UTC (two hourly records
    of 1 GiB each), and received 4,194,304 bytes;
  - firefox.exe: 300 hourly network records (many pages, so the table is
    a real B-tree with a branch root), 1,000 bytes sent and 50,000
    received each;
  - svchost.exe [wuauserv] runs as SYSTEM (S-1-5-18);
  - app resource usage for rclone.exe: 3 records, 1,000,000 foreground
    cycles each, 2,147,483,648 bytes read in all;
  - one connectivity record: profile 7 connected 2026-10-20 08:55 UTC for
    7,500 seconds.
IdBlob is a compressed column, so the engine stores the ASCII strings
7-bit compressed, as Windows 8 and later do; the path with an umlaut it
keeps as it is.

Needs Windows. Usage: python scripts/make_srum_fixture.py [page size]
(32768 by default, as Windows uses for SRUM).
"""
import ctypes
import datetime
import os
import shutil
import struct
import sys
import tempfile
from ctypes import POINTER, byref, c_size_t, c_uint32, c_ulong, c_ushort, c_void_p, c_wchar_p

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "fixtures", "win")

JET_coltypBit, JET_coltypUnsignedByte, JET_coltypLong, JET_coltypDateTime = 1, 2, 4, 8
JET_coltypLongBinary, JET_coltypLongLong = 11, 15
JET_bitColumnFixed, JET_bitColumnTagged, JET_bitColumnAutoincrement = 0x1, 0x4, 0x10
JET_bitColumnCompressed = 0x80000
JET_paramSystemPath, JET_paramTempPath, JET_paramLogFilePath, JET_paramBaseName = 0, 1, 2, 3
JET_paramRecovery, JET_paramDatabasePageSize, JET_paramCreatePathIfNotExist = 34, 64, 100
JET_bitDbOverwriteExisting = 0x200
JET_prepInsert = 0


class JET_COLUMNDEF(ctypes.Structure):
    _fields_ = [("cbStruct", c_ulong), ("columnid", c_ulong), ("coltyp", c_ulong), ("wCountry", c_ushort), ("langid", c_ushort),
                ("cp", c_ushort), ("wCollate", c_ushort), ("cbMax", c_ulong), ("grbit", c_ulong)]


esent = ctypes.WinDLL("esent.dll") if os.name == "nt" else None


def check(rc, what):
    if rc < 0:
        raise RuntimeError("%s failed: JET error %d" % (what, rc))


def ole_date(dt):
    """OLE Automation date: days since 1899-12-30, as SRUM's TimeStamp."""
    return (dt - datetime.datetime(1899, 12, 30, tzinfo=datetime.timezone.utc)).total_seconds() / 86400.0


def filetime(dt):
    return int((dt - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds() * 10_000_000)


def sid(s):
    p = s.split("-")
    subs = [int(x) for x in p[3:]]
    return bytes([int(p[1]), len(subs)]) + int(p[2]).to_bytes(6, "big") + b"".join(struct.pack("<I", x) for x in subs)


ALICE = "S-1-5-21-1111111111-2222222222-3333333333-1001"
UTC = datetime.timezone.utc
WIFI = (71 << 48) | 0x8001  # InterfaceLuid: IfType 71 (802.11) in the top 16 bits
ETH = (6 << 48) | 0x8000


def build(path, page_size):
    work = tempfile.mkdtemp(prefix="kokino-ese-")
    inst = c_void_p()
    sp = esent.JetSetSystemParameterW
    sp.argtypes = [POINTER(c_void_p), c_void_p, c_ulong, c_size_t, c_wchar_p]
    check(sp(None, None, JET_paramDatabasePageSize, page_size, None), "page size")
    check(esent.JetCreateInstanceW(byref(inst), c_wchar_p("kokino-srum-%d" % os.getpid())), "instance")
    for pid, val in [(JET_paramSystemPath, work + "\\"), (JET_paramTempPath, work + "\\"), (JET_paramLogFilePath, work + "\\"), (JET_paramBaseName, "edb"), (JET_paramRecovery, "Off")]:
        check(sp(byref(inst), None, pid, 0, val), "param %d" % pid)
    check(sp(byref(inst), None, JET_paramCreatePathIfNotExist, 1, None), "create path")
    check(esent.JetInit(byref(inst)), "init")
    ses = c_void_p()
    esent.JetBeginSessionW.argtypes = [c_void_p, POINTER(c_void_p), c_wchar_p, c_wchar_p]
    check(esent.JetBeginSessionW(inst, byref(ses), None, None), "session")
    db = c_uint32()
    tmpdb = os.path.join(work, "SRUDB.dat")
    esent.JetCreateDatabaseW.argtypes = [c_void_p, c_wchar_p, c_wchar_p, POINTER(c_uint32), c_ulong]
    check(esent.JetCreateDatabaseW(ses, tmpdb, None, byref(db), JET_bitDbOverwriteExisting), "create db")

    def table(name, cols, rows):
        check(esent.JetBeginTransaction(ses), "begin")
        tid = c_void_p()
        esent.JetCreateTableW.argtypes = [c_void_p, c_uint32, c_wchar_p, c_ulong, c_ulong, POINTER(c_void_p)]
        check(esent.JetCreateTableW(ses, db, name, 0, 100, byref(tid)), "table " + name)
        ids = {}
        esent.JetAddColumnW.argtypes = [c_void_p, c_void_p, c_wchar_p, POINTER(JET_COLUMNDEF), c_void_p, c_ulong, POINTER(c_ulong)]
        for cname, typ, grbit in cols:
            d = JET_COLUMNDEF(cbStruct=ctypes.sizeof(JET_COLUMNDEF), coltyp=typ, cp=0, grbit=grbit)
            cid = c_ulong()
            check(esent.JetAddColumnW(ses, tid, cname, byref(d), None, 0, byref(cid)), "column " + cname)
            ids[cname] = cid.value
        check(esent.JetCommitTransaction(ses, 0), "commit")
        esent.JetSetColumn.argtypes = [c_void_p, c_void_p, c_ulong, c_void_p, c_ulong, c_ulong, c_void_p]
        esent.JetUpdate.argtypes = [c_void_p, c_void_p, c_void_p, c_ulong, c_void_p]
        esent.JetPrepareUpdate.argtypes = [c_void_p, c_void_p, c_ulong]
        for i, row in enumerate(rows):
            if i % 200 == 0:
                if i:
                    check(esent.JetCommitTransaction(ses, 0), "commit")
                check(esent.JetBeginTransaction(ses), "begin")
            check(esent.JetPrepareUpdate(ses, tid, JET_prepInsert), "prepare")
            for cname, raw in row.items():
                buf = ctypes.create_string_buffer(raw, len(raw))
                check(esent.JetSetColumn(ses, tid, ids[cname], buf, len(raw), 0, None), "set " + cname)
            check(esent.JetUpdate(ses, tid, None, 0, None), "update")
        check(esent.JetCommitTransaction(ses, 0), "commit")
        esent.JetCloseTable.argtypes = [c_void_p, c_void_p]
        check(esent.JetCloseTable(ses, tid), "close table")

    L = lambda v: struct.pack("<i", v)
    Q = lambda v: struct.pack("<q", v)
    D = lambda dt: struct.pack("<d", ole_date(dt))
    U16 = lambda s: (s + "\0").encode("utf-16-le")

    idmap = [
        (0, 1, U16("\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Temp\\rclone.exe")),
        (0, 2, U16("\\Device\\HarddiskVolume3\\Program Files\\Mozilla Firefox\\firefox.exe")),
        (1, 3, U16("wuauserv")),
        (3, 4, sid(ALICE)),
        (3, 5, sid("S-1-5-18")),
        (0, 6, U16("Microsoft.WindowsStore_8wekyb3d8bbwe")),
        # Not 7-bit text (an umlaut): the engine stores it uncompressed.
        (0, 7, U16("\\Device\\HarddiskVolume3\\Users\\alice\\Documents\\M\u00fcller Projekte\\M\u00fcller Projekte Archiv\\M\u00fcller Projekte Archiv 2026\\backup-tool.exe")),
    ]
    table("SruDbIdMapTable", [("IdType", JET_coltypUnsignedByte, JET_bitColumnFixed), ("IdIndex", JET_coltypLong, JET_bitColumnFixed), ("IdBlob", JET_coltypLongBinary, JET_bitColumnTagged | JET_bitColumnCompressed)],
          [{"IdType": bytes([t]), "IdIndex": L(i), "IdBlob": b} for t, i, b in idmap])

    base = datetime.datetime(2026, 10, 20, 10, 0, tzinfo=UTC)
    net = [{"TimeStamp": D(base), "AppId": L(1), "UserId": L(4), "InterfaceLuid": Q(WIFI), "L2ProfileId": L(7), "L2ProfileFlags": L(0), "BytesSent": Q(1 << 30), "BytesRecvd": Q(2 << 20)},
           {"TimeStamp": D(base + datetime.timedelta(hours=1)), "AppId": L(1), "UserId": L(4), "InterfaceLuid": Q(WIFI), "L2ProfileId": L(7), "L2ProfileFlags": L(0), "BytesSent": Q(1 << 30), "BytesRecvd": Q(2 << 20)},
           {"TimeStamp": D(base), "AppId": L(3), "UserId": L(5), "InterfaceLuid": Q(ETH), "L2ProfileId": L(0), "L2ProfileFlags": L(0), "BytesSent": Q(4096), "BytesRecvd": Q(25_000_000)}]
    for h in range(300):
        net.append({"TimeStamp": D(base - datetime.timedelta(hours=300 - h)), "AppId": L(2), "UserId": L(4), "InterfaceLuid": Q(WIFI), "L2ProfileId": L(7), "L2ProfileFlags": L(0), "BytesSent": Q(1000), "BytesRecvd": Q(50_000)})
    auto = ("AutoIncId", JET_coltypLong, JET_bitColumnFixed | JET_bitColumnAutoincrement)
    common = [auto, ("TimeStamp", JET_coltypDateTime, JET_bitColumnFixed), ("AppId", JET_coltypLong, JET_bitColumnFixed), ("UserId", JET_coltypLong, JET_bitColumnFixed)]
    table("{973F5D5C-1D90-4944-BE8E-24B94231A174}", common + [("InterfaceLuid", JET_coltypLongLong, JET_bitColumnFixed), ("L2ProfileId", JET_coltypLong, JET_bitColumnFixed),
          ("L2ProfileFlags", JET_coltypLong, JET_bitColumnFixed), ("BytesSent", JET_coltypLongLong, JET_bitColumnFixed), ("BytesRecvd", JET_coltypLongLong, JET_bitColumnFixed)], net)

    usage_cols = ["ForegroundCycleTime", "BackgroundCycleTime", "FaceTime", "ForegroundBytesRead", "ForegroundBytesWritten", "BackgroundBytesRead", "BackgroundBytesWritten"]
    usage = []
    for h in range(3):
        r = {"TimeStamp": D(base + datetime.timedelta(hours=h)), "AppId": L(1), "UserId": L(4)}
        vals = [1_000_000, 50_000, 0, 715_827_882 + (2 if h == 0 else 0), 4096, 0, 0]
        for c, v in zip(usage_cols, vals):
            r[c] = Q(v)
        r["ForegroundContextSwitches"] = L(1200)
        r["BackgroundContextSwitches"] = L(30)
        usage.append(r)
    table("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", common + [(c, JET_coltypLongLong, JET_bitColumnFixed) for c in usage_cols] +
          [("ForegroundContextSwitches", JET_coltypLong, JET_bitColumnFixed), ("BackgroundContextSwitches", JET_coltypLong, JET_bitColumnFixed)], usage)

    conn = [{"TimeStamp": D(base + datetime.timedelta(hours=1)), "AppId": L(6), "UserId": L(4), "InterfaceLuid": Q(WIFI), "L2ProfileId": L(7), "ConnectedTime": L(7500),
             "ConnectStartTime": Q(filetime(datetime.datetime(2026, 10, 20, 8, 55, tzinfo=UTC))), "L2ProfileFlags": L(0)}]
    table("{DD6636C4-8929-4683-974E-22C046A43763}", common + [("InterfaceLuid", JET_coltypLongLong, JET_bitColumnFixed), ("L2ProfileId", JET_coltypLong, JET_bitColumnFixed),
          ("ConnectedTime", JET_coltypLong, JET_bitColumnFixed), ("ConnectStartTime", JET_coltypLongLong, JET_bitColumnFixed), ("L2ProfileFlags", JET_coltypLong, JET_bitColumnFixed)], conn)

    esent.JetCloseDatabase.argtypes = [c_void_p, c_uint32, c_ulong]
    check(esent.JetCloseDatabase(ses, db, 0), "close db")
    esent.JetDetachDatabaseW.argtypes = [c_void_p, c_wchar_p]
    check(esent.JetDetachDatabaseW(ses, tmpdb), "detach")
    esent.JetEndSession.argtypes = [c_void_p, c_ulong]
    check(esent.JetEndSession(ses, 0), "end session")
    esent.JetTerm.argtypes = [c_void_p]
    check(esent.JetTerm(inst), "term")
    # The engine preallocates 256 pages; the never-written ones at the end
    # are cut off to keep the fixture small (a reader must cope with a
    # database cut short anyway).
    d = open(tmpdb, "rb").read()
    last = max(i for i in range(len(d) // page_size) if any(d[i * page_size:(i + 1) * page_size]))
    open(path, "wb").write(d[:(last + 1) * page_size])
    shutil.rmtree(work, ignore_errors=True)


def main():
    if esent is None:
        sys.exit("needs Windows (esent.dll)")
    page = int(sys.argv[1]) if len(sys.argv) > 1 else 32768
    os.makedirs(OUT, exist_ok=True)
    name = "SRUDB.dat" if page == 32768 else "SRUDB-%dk.dat" % (page // 1024)
    p = os.path.join(OUT, name)
    build(p, page)
    print("wrote %s (%d bytes, %d-byte pages)" % (p, os.path.getsize(p), page))


if __name__ == "__main__":
    main()
