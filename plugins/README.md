# Kokino plugins

A plugin reads an artifact Kokino does not parse itself. It is a separate
program, in any language, in its own folder, described by a `plugin.json`.
Kokino copies every matching file (live or deleted) out of the evidence,
runs the program on the copy and shows the rows it prints: on the evidence
item's **Plugins** page, on the timelines (dated rows) and in the watchlist.

Plugins are off unless the server is started with a plugin folder:

    kokino serve --plugins /path/to/plugins

and they run only when an examiner starts them on an evidence item. From
the command line:

    kokino plugins image.E01 --plugins /path/to/plugins [--only <name>] [--json]

## Write your first plugin

Say you want the address and title from browser bookmark files that
Kokino does not read yet, saved as `*.bookmark`. Five steps:

**1. A folder.** One folder per plugin, named after it; the folder name is
how Kokino refers to the plugin (`--only bookmarks`).

    plugins/
      bookmarks/
        plugin.json
        parse.py

**2. plugin.json.** Which files it wants and how to run it:

```json
{
  "name": "Bookmark files",
  "version": "0.1",
  "description": "Address and title from .bookmark files",
  "match": ["*.bookmark"],
  "command": ["python", "parse.py", "{file}", "{path}"],
  "timeout": 30
}
```

**3. The program.** It gets the path of a copy of one file, and prints
JSON. Start from a template below. Rules of thumb:

- Read only the file you are given; write nothing outside the system's
  temporary folder; no network.
- Times as ISO 8601 in UTC (`2026-10-20T08:05:30Z`), or leave `time` out:
  rows without a time are listed but not put on the timelines.
- One row per thing found. `what` is the main value (an address, a name, a
  command line), `detail` a short sentence, `fields` anything else.
- Something you cannot read: print what you could, and say why in `notes`.
  Exit with a non-zero code only when the file could not be read at all,
  with the reason on standard error.

**4. Try it on a sample**, without a case or a server:

    kokino plugin-test plugins/bookmarks samples/Lab.bookmark --as /Users/alice/Lab.bookmark

It runs the plugin exactly as a real run does (on a copy, with the time
limit and the reduced environment), shows its rows and says whether the
path matches `match`, whether a row's time cannot be read, or a row has no
`what`; it exits with 1 if there is anything to fix. `--json` prints the
result as JSON.

**5. Use it.** Start Kokino with the folder that holds it
(`kokino serve --plugins plugins`), open an evidence item, page
**Plugins**, and run it. The rows show there, dated rows on the timelines,
and the watchlist searches them.

### Templates

Python 3 (standard library only):

```python
import json, sys

def main():
    path, shown = sys.argv[1], sys.argv[2]
    rows, notes = [], []
    with open(path, "rb") as f:
        data = f.read()
    # ... read data, append rows ...
    rows.append({"time": "2026-10-20T08:05:30Z", "what": "...", "detail": "from " + shown, "fields": {}})
    json.dump({"rows": rows, "notes": notes}, sys.stdout)

main()
```

PowerShell (Windows), with
`"command": ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "parse.ps1", "{file}", "{path}"]`:

```powershell
param($File, $Shown)
$rows = @()
$text = Get-Content -LiteralPath $File -Raw
# ... read $text, add rows ...
$rows += @{ what = "..."; detail = "from $Shown" }
@{ rows = $rows; notes = @() } | ConvertTo-Json -Depth 5 -Compress
```

sh (Linux and macOS), with `"command": ["sh", "parse.sh", "{file}", "{path}"]`,
one JSON row per line:

```sh
#!/bin/sh
# ... read "$1" ...
printf '{"what": "%s", "detail": "from %s"}\n' "something" "$2"
```

(Strings printed by hand must be escaped for JSON; a language with a JSON
library is safer.)

## plugin.json

```json
{
  "name": "Internet shortcuts",
  "version": "1.0",
  "description": "What it reads",
  "match": ["*.url"],
  "command": ["python", "parse.py", "{file}", "{path}"],
  "timeout": 30,
  "max_file_size": 1048576
}
```

- `match`: patterns compared with each file's path on the volume, without
  regard to case: `*` is any run of characters except `/`, `**` any run
  including `/`, `?` one character. A pattern without `/` is compared with
  the file name only (`*.url`); with `/`, with the whole path
  (`Users/*/AppData/Roaming/**/*.db`).
- `command`: the program and its arguments. `{file}` becomes the path of
  the copy, `{name}` the file's name and `{path}` its path on the volume.
  It runs in the plugin's folder with no input and a reduced environment.
- `timeout` (seconds, default 60) and `max_file_size` (bytes, default
  256 MiB): a plugin that runs longer is stopped, with everything it
  started; larger files are not given to it.

## Output

JSON on standard output, either one object:

```json
{"rows": [{"time": "2026-10-20T08:05:30Z", "what": "https://lab.test/",
           "detail": "Internet shortcut /Users/alice/Favorites/Lab.url",
           "fields": {"iconfile": "..."}}],
 "notes": ["anything worth knowing"]}
```

or one row object per line. `time` (ISO 8601, UTC) and `fields` are
optional. A non-zero exit code is an error; the first 500 characters of
standard error are shown with it. Limits: 64 MB of output and 200,000 rows
per plugin and evidence item, 10,000 files per plugin.

## What Kokino records

Each run is recorded in the case's audit log with the plugin's name,
version and command, how many files and rows, and the SHA-256 of every file
in the plugin's folder, so a report can say exactly what produced a row.
Raise `version` whenever the plugin changes.

## Safety

A plugin is a program: it runs with the rights of the Kokino server and is
trusted as much as any other tool on the examiner's machine. It is never
given the evidence itself, only a copy of one file at a time, but it can
read and write anything the server can. Install only plugins you have read.

## Example

`internet-shortcut/` reads Windows Internet Shortcut (.url) files with
Python 3's standard library. Try it:

    kokino plugin-test plugins/internet-shortcut Lab.url --as /Users/alice/Favorites/Lab.url
