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
  {5C8CF1C7-7257-4F13-B223-970EF5939312}    App Timeline Provider (focus, input)
  {D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}    push notifications
  {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}    energy usage (battery)
  {FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT  long-term energy usage

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
    7,500 seconds;
  - app timeline: rclone.exe (alice) in a period ending 2026-10-20 10:58
    UTC, 600 s in the foreground, 45 s of input (30 keyboard, 15 mouse);
    firefox.exe (alice) ending 09:30 UTC, 1,800 s in the foreground, 900 s
    of input (400 keyboard, 500 mouse), 1,200 s playing audio; wuauserv as
    SYSTEM ending 10:00 UTC with no foreground time or input;
  - three push notifications (toasts of 2,048 bytes) for the Store app,
    user alice, at 10:05, 10:10 and 10:15 UTC;
  - battery: 41,000 of 48,000 mWh (design 50,000, 212 cycles) at 09:30 UTC
    with StateTransition 1, then 15,000 mWh at 10:30 UTC with
    StateTransition 2;
  - long-term energy, one row for 2026-10-20: ActiveAcTime 14,400,
    CsAcTime 3,600, ActiveDcTime 5,400, CsDcTime 28,800, ActiveEnergy 61,000
    (values as stored), capacity 48,000 of 50,000, 212 cycles.
IdBlob is a compressed column, so the engine stores the ASCII strings
7-bit compressed, as Windows 8 and later do; the path with an umlaut it
keeps as it is.

Needs Windows. Usage: python scripts/make_srum_fixture.py [page size]
(32768 by default, as Windows uses for SRUM).

python scripts/make_srum_fixture.py deep writes tests/fixtures/win/ese-deep.dat
instead: one table "Deep" of 400 rows with 180-byte keys (a B+ tree of
three levels or more, 4 KiB pages), N = 0..399, and Note = "row N" stored
as UTF-16 in a column declared as code page 1252.
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
JET_bitIndexPrimary = 0x2
JET_coltypBinary, JET_coltypText = 9, 10
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


def build(path, page_size, deep=False, tables=None):
    """`tables(table, L, Q, D, U16)` makes the tables (SRUM's by default)."""
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
    tmpdb = os.path.join(work, os.path.basename(path))
    esent.JetCreateDatabaseW.argtypes = [c_void_p, c_wchar_p, c_wchar_p, POINTER(c_uint32), c_ulong]
    check(esent.JetCreateDatabaseW(ses, tmpdb, None, byref(db), JET_bitDbOverwriteExisting), "create db")

    def table(name, cols, rows, key=None):
        check(esent.JetBeginTransaction(ses), "begin")
        tid = c_void_p()
        esent.JetCreateTableW.argtypes = [c_void_p, c_uint32, c_wchar_p, c_ulong, c_ulong, POINTER(c_void_p)]
        check(esent.JetCreateTableW(ses, db, name, 0, 100, byref(tid)), "table " + name)
        ids = {}
        esent.JetAddColumnW.argtypes = [c_void_p, c_void_p, c_wchar_p, POINTER(JET_COLUMNDEF), c_void_p, c_ulong, POINTER(c_ulong)]
        for col in cols:
            # (name, type, flags) or (name, type, flags, code page): 1200 for Unicode text.
            cname, typ, grbit = col[:3]
            d = JET_COLUMNDEF(cbStruct=ctypes.sizeof(JET_COLUMNDEF), coltyp=typ, cp=col[3] if len(col) > 3 else 0, grbit=grbit)
            cid = c_ulong()
            check(esent.JetAddColumnW(ses, tid, cname, byref(d), None, 0, byref(cid)), "column " + cname)
            ids[cname] = cid.value
        if key:
            # Primary index on one column: "+Name\0\0".
            k = "+%s\0\0" % key
            esent.JetCreateIndexW.argtypes = [c_void_p, c_void_p, c_wchar_p, c_ulong, c_wchar_p, c_ulong, c_ulong]
            check(esent.JetCreateIndexW(ses, tid, "Primary", JET_bitIndexPrimary, k, 2 * len(k), 100), "index " + key)
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

    if deep:
        # ese-deep.dat: 180-byte keys allow only a few entries per page, so
        # 400 rows make a B+ tree of three levels or more, whose upper
        # branch pages carry neither the leaf nor the parent-of-leaf flag.
        # Note holds UTF-16 in a column declared as code page 1252, as
        # Windows' own SRUM writes some text columns.
        rows = [{"Key": (b"K" * 172) + b"%08d" % i, "N": struct.pack("<i", i), "Note": ("row %d" % i).encode("utf-16-le")} for i in range(400)]
        table("Deep", [("Key", JET_coltypBinary, 0), ("N", JET_coltypLong, JET_bitColumnFixed), ("Note", JET_coltypText, 0)], rows, key="Key")
    L = lambda v: struct.pack("<i", v)
    Q = lambda v: struct.pack("<q", v)
    D = lambda dt: struct.pack("<d", ole_date(dt))
    U16 = lambda s: (s + "\0").encode("utf-16-le")

    if not deep:
        (tables or srum_tables)(table, L, Q, D, U16)

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


def srum_tables(table, L, Q, D, U16):
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

    # App Timeline Provider: the columns Windows 10 has, in its order (the
    # *Timeline columns are bit fields of the period's minutes).
    tl_long = ["Flags"]
    tl_q = ["EndTime"]
    tl_long2 = ["DurationMS", "SpanMS", "TimelineEnd"]
    tl_bits = ["InFocusTimeline", "UserInputTimeline", "CompRenderedTimeline", "CompDirtiedTimeline", "CompPropagatedTimeline", "AudioInTimeline", "AudioOutTimeline", "CpuTimeline", "DiskTimeline", "NetworkTimeline", "MBBTimeline"]
    tl_s = ["InFocusS", "PSMForegroundS", "UserInputS", "CompRenderedS", "CompDirtiedS", "CompPropagatedS", "AudioInS", "AudioOutS"]
    tl_cyc = ["Cycles", "CyclesBreakdown", "CyclesAttr", "CyclesAttrBreakdown", "CyclesWOB", "CyclesWOBBreakdown", "DiskRaw", "NetworkTailRaw", "NetworkBytesRaw", "MBBTailRaw", "MBBBytesRaw"]
    tl_s2 = ["DisplayRequiredS", "DisplayRequiredTimeline", "KeyboardInputTimeline", "KeyboardInputS", "MouseInputS"]

    def tl(ts, app, user, end, dur, focus, inp, kb, mouse, audio):
        row = {"TimeStamp": D(ts), "AppId": L(app), "UserId": L(user), "Flags": L(0), "EndTime": Q(filetime(end)), "DurationMS": L(dur), "SpanMS": L(dur), "TimelineEnd": L(dur // 60000)}
        for c in tl_bits + tl_cyc:
            row[c] = Q(0)
        vals = {"InFocusS": focus, "PSMForegroundS": focus, "UserInputS": inp, "CompRenderedS": focus, "CompDirtiedS": 0, "CompPropagatedS": 0, "AudioInS": 0, "AudioOutS": audio}
        for c in tl_s:
            row[c] = L(vals[c])
        row.update({"DisplayRequiredS": L(0), "DisplayRequiredTimeline": Q(0), "KeyboardInputTimeline": Q(0), "KeyboardInputS": L(kb), "MouseInputS": L(mouse)})
        return row

    day = lambda hh, mm: datetime.datetime(2026, 10, 20, hh, mm, tzinfo=UTC)
    timeline = [tl(day(11, 0), 1, 4, day(10, 58), 3_480_000, 600, 45, 30, 15, 0),
                tl(day(10, 0), 2, 4, day(9, 30), 3_600_000, 1800, 900, 400, 500, 1200),
                tl(day(10, 0), 3, 5, day(10, 0), 3_600_000, 0, 0, 0, 0, 0)]
    table("{5C8CF1C7-7257-4F13-B223-970EF5939312}", common + [(c, JET_coltypLong, JET_bitColumnFixed) for c in tl_long] + [(c, JET_coltypLongLong, JET_bitColumnFixed) for c in tl_q] +
          [(c, JET_coltypLong, JET_bitColumnFixed) for c in tl_long2] + [(c, JET_coltypLongLong, JET_bitColumnFixed) for c in tl_bits] + [(c, JET_coltypLong, JET_bitColumnFixed) for c in tl_s] +
          [(c, JET_coltypLongLong, JET_bitColumnFixed) for c in tl_cyc] + [("DisplayRequiredS", JET_coltypLong, JET_bitColumnFixed), ("DisplayRequiredTimeline", JET_coltypLongLong, JET_bitColumnFixed),
          ("KeyboardInputTimeline", JET_coltypLongLong, JET_bitColumnFixed), ("KeyboardInputS", JET_coltypLong, JET_bitColumnFixed), ("MouseInputS", JET_coltypLong, JET_bitColumnFixed)], timeline)

    push = [{"TimeStamp": D(day(10, m)), "AppId": L(6), "UserId": L(4), "NotificationType": L(1), "PayloadSize": L(2048), "NetworkType": L(1)} for m in (5, 10, 15)]
    table("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}", common + [("NotificationType", JET_coltypLong, JET_bitColumnFixed), ("PayloadSize", JET_coltypLong, JET_bitColumnFixed),
          ("NetworkType", JET_coltypLong, JET_bitColumnFixed)], push)

    def battery(ts, state, charge):
        return {"TimeStamp": D(ts), "AppId": L(0), "UserId": L(0), "EventTimestamp": Q(filetime(ts)), "StateTransition": L(state), "ChargeLevel": L(charge), "CycleCount": L(212),
                "ConfigurationHash": Q(0x1234), "DesignedCapacity": L(50_000), "FullChargedCapacity": L(48_000)}
    table("{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}", common + [("EventTimestamp", JET_coltypLongLong, JET_bitColumnFixed), ("StateTransition", JET_coltypLong, JET_bitColumnFixed),
          ("ChargeLevel", JET_coltypLong, JET_bitColumnFixed), ("CycleCount", JET_coltypLong, JET_bitColumnFixed), ("ConfigurationHash", JET_coltypLongLong, JET_bitColumnFixed),
          ("DesignedCapacity", JET_coltypLong, JET_bitColumnFixed), ("FullChargedCapacity", JET_coltypLong, JET_bitColumnFixed)], [battery(day(9, 30), 1, 41_000), battery(day(10, 30), 2, 15_000)])

    lt_cols = ["ActiveAcTime", "CsAcTime", "ActiveDcTime", "CsDcTime", "ActiveDischargeTime", "CsDischargeTime", "ActiveEnergy", "CsEnergy", "DesignedCapacity", "FullChargedCapacity", "CycleCount"]
    lt_vals = [14_400, 3_600, 5_400, 28_800, 5_400, 28_800, 61_000, 9_000, 50_000, 48_000, 212]
    lt = {"TimeStamp": D(day(23, 0)), "AppId": L(0), "UserId": L(0), "ConfigurationHash": Q(0x1234)}
    lt.update({c: L(v) for c, v in zip(lt_cols, lt_vals)})
    table("{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT", common + [(c, JET_coltypLong, JET_bitColumnFixed) for c in lt_cols] + [("ConfigurationHash", JET_coltypLongLong, JET_bitColumnFixed)], [lt])



def main():
    if esent is None:
        sys.exit("needs Windows (esent.dll)")
    os.makedirs(OUT, exist_ok=True)
    if sys.argv[1:] == ["deep"]:
        page = 4096
        p = os.path.join(OUT, "ese-deep.dat")
        build(p, page, deep=True)
    else:
        page = int(sys.argv[1]) if len(sys.argv) > 1 else 32768
        name = "SRUDB.dat" if page == 32768 else "SRUDB-%dk.dat" % (page // 1024)
        p = os.path.join(OUT, name)
        build(p, page)
    print("wrote %s (%d bytes, %d-byte pages)" % (p, os.path.getsize(p), page))


if __name__ == "__main__":
    main()
