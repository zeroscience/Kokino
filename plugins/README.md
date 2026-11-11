# Kokino plugins

A plugin reads an artifact Kokino does not parse itself. It is a separate
program in its own folder, described by a `plugin.json`. Kokino copies
every matching file (live or deleted) out of the evidence, runs the program
on the copy and shows the rows it prints.

Plugins are off unless the server is started with a plugin folder:

    kokino serve --plugins /path/to/plugins

and they run only when an examiner starts them on an evidence item (page
**Plugins**). From the command line:

    kokino plugins image.E01 --plugins /path/to/plugins [--only <name>] [--json]

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
standard error are shown with it.

## What Kokino records

Each run is recorded in the case's audit log with the plugin's name,
version and command, how many files and rows, and the SHA-256 of every file
in the plugin's folder, so a report can say exactly what produced a row.

## Safety

A plugin is a program: it runs with the rights of the Kokino server and is
trusted as much as any other tool on the examiner's machine. It is never
given the evidence itself, only a copy of one file at a time, but it can
read and write anything the server can. Install only plugins you have read.

## Example

`internet-shortcut/` reads Windows Internet Shortcut (.url) files with
Python 3's standard library.
