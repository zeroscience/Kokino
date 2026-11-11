"""Kokino plugin: Windows Internet Shortcut files (.url).

Kokino runs:   python parse.py <copy of the file> <its path on the volume>
and reads JSON from standard output:

    {"rows": [{"time": "...", "what": "...", "detail": "...", "fields": {...}}],
     "notes": ["..."]}

An Internet Shortcut is an INI file:

    [InternetShortcut]
    URL=https://lab.test/
    IconFile=C:\\Users\\alice\\AppData\\...\\favicon.ico
    Modified=20E4F1A8C3D5DA0100

Modified, when present, is a FILETIME as 16 hex digits (little-endian)
followed by two more. Standard library only.
"""
import datetime
import json
import sys


def filetime(hexed):
    try:
        raw = bytes.fromhex(hexed[:16])
    except ValueError:
        return ""
    if len(raw) != 8:
        return ""
    ft = int.from_bytes(raw, "little")
    if not ft:
        return ""
    t = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ft // 10)
    if not 1990 <= t.year <= 2100:
        return ""
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    path = sys.argv[1]
    shown = sys.argv[2] if len(sys.argv) > 2 else path
    data = open(path, "rb").read(1 << 20)
    text = data.decode("utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else data.decode("utf-8", "replace")
    section, values = "", {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
        elif "=" in line and section == "internetshortcut":
            k, v = line.split("=", 1)
            values[k.strip().lower()] = v.strip()
    rows, notes = [], []
    if "url" in values:
        rows.append({
            "time": filetime(values.get("modified", "")),
            "what": values["url"],
            "detail": "Internet shortcut " + shown,
            "fields": {k: v for k, v in values.items() if k in ("url", "iconfile", "iconindex", "modified", "hotkey")},
        })
    else:
        notes.append("no [InternetShortcut] URL= line")
    json.dump({"rows": rows, "notes": notes}, sys.stdout)


if __name__ == "__main__":
    main()
