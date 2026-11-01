"""Validate Kokino's deleted-file recovery against NIST CFReDS DFR images.

NIST's deleted file recovery (DFR) test images (cfreds-archive.nist.gov,
dfr-images/) come with a layout document (setup-july-10-2012.pdf) that
says, for every image, how many deleted files still have file system
metadata ("Metadata found N files, not found M"). The test files are
self-describing: every 512-byte block starts with a tag naming its file
and its position ("File X", "Block 00003 Segment 001 file X", "Tail X").

For every deleted file Kokino lists, this script checks:
  - the name: Kokino's name equals the name in the file's own first block
    (FAT replaces the first character of a deleted short name, so that one
    may differ);
  - the blocks: how many full blocks carry the right tag in the right place;
  - the warning: when some blocks are wrong, whether Kokino said so.
and compares the number listed with NIST's "Metadata found".

    python scripts/validate_cfreds.py target/validation/cfreds [kokino]

The folder holds the downloaded dfr-*.dd.bz2 images and the layout PDF.
Each image is expanded to a temporary 1 GB file, analyzed and deleted again.
Writes cfreds-results.json there and prints a summary. Needs PyMuPDF (fitz)
to read the PDF. Nothing from the images is kept.
"""
import bz2
import glob
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAG = re.compile(rb"\nDFR\n(?:File (.+?) path |Block (\d{5,}) Segment \d+ file (.+?) path |Tail (.+?)\n)")


def layout_text(folder):
    cache = os.path.join(folder, "setup.txt")
    if not os.path.exists(cache):
        import fitz
        d = fitz.open(os.path.join(folder, "setup-july-10-2012.pdf"))
        open(cache, "w", encoding="utf-8").write("\n".join(p.get_text() for p in d))
    t = open(cache, encoding="utf-8").read()
    return re.sub(r"Last save[^\n]*\nPage \d+ of \d+ \nTest Images layout.docx \n", "", t)


def metadata_found(t):
    """Image name to (deleted files with metadata, without) from the layout."""
    return {m.group(1): (int(m.group(2)), int(m.group(3))) for m in re.finditer(r"\n((?:fat|xfat|ntfs|ext)-[0-9a-z-]+) Metadata found (\d+) files, not found (\d+)", t)}


def tag(block):
    """(kind, name, block number) of a DFR block, or None."""
    m = TAG.match(block[:200])
    if not m:
        return None
    if m.group(1) is not None:
        return ("file", m.group(1), 0)
    if m.group(2) is not None:
        return ("block", m.group(3), int(m.group(2)))
    return ("tail", m.group(4), None)


def check(data, size):
    """(name from the first block or None, good full blocks, full blocks)."""
    full = size // 512
    first = tag(data[:512])
    if not first or first[0] != "file":
        return None, 0, full
    name = first[1]
    good = 0
    for i in range(full):
        t = tag(data[i * 512:(i + 1) * 512])
        if t and t[1] == name and ((i == 0 and t[0] == "file") or (t[0] == "block" and t[2] == i)):
            good += 1
    return name, good, full


def same_name(kokino, tagged):
    a, b = kokino.lower(), tagged.lower()
    return a == b or (len(a) == len(b) and a[1:] == b[1:])


def main():
    folder = sys.argv[1]
    exe = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "target", "release", "kokino.exe" if os.name == "nt" else "kokino")
    meta = metadata_found(layout_text(folder))
    tmp = os.path.join(folder, "_tmp")
    results = []
    for f in sorted(os.listdir(folder)):
        m = re.match(r"dfr-(\d+)(-[a-z]+)?-(fat|xfat|ntfs|ext)\.dd\.bz2$", f)
        if not m:
            continue
        name = "%s-%s%s" % (m.group(3), m.group(1), m.group(2) or "")
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        raw = os.path.join(tmp, "image.dd")
        with bz2.open(os.path.join(folder, f)) as s, open(raw, "wb") as d:
            shutil.copyfileobj(s, d, 1 << 20)
        out = subprocess.run([exe, "files", "--json", "--extract", os.path.join(tmp, "x"), raw], capture_output=True, text=True, encoding="utf-8")
        rows = [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")]
        r = {"image": name, "nist_metadata_found": meta.get(name, (None, None))[0], "nist_metadata_lost": meta.get(name, (None, None))[1],
             "listed": 0, "tagged": 0, "name_ok": 0, "blocks_good": 0, "blocks": 0, "complete": 0, "incomplete": 0, "incomplete_warned": 0, "untagged": 0, "other_file": 0, "wrong_unwarned": 0, "no_content": 0, "by_fs": {}}
        for row in rows:
            if not row["deleted"]:
                continue
            r["listed"] += 1
            fs = r["by_fs"].setdefault(str(row["fs"]), {"listed": 0, "complete": 0, "no_content": 0})
            fs["listed"] += 1
            if row["size"] == 0:
                # ext3/ext4 clear a deleted file's size and block map; with no
                # journal copy there is nothing to read (carving territory).
                r["no_content"] += 1
                fs["no_content"] += 1
                continue
            base = os.path.basename(row["path"])
            hits = glob.glob(os.path.join(tmp, "x", "fs%d" % row["fs"], "%d-*" % row["record"]))
            data = open(hits[0], "rb").read() if hits else b""
            tname, good, full = check(data, row["size"])
            if tname is None:
                # First block not a test file's header: overwritten, or not test data.
                r["untagged"] += 1
                if row["note"]:
                    r["incomplete_warned"] += 1
                r["incomplete"] += 1
                continue
            r["tagged"] += 1
            # DFR-04 tags carry English names for files named in other scripts.
            # Orphaned inodes (ext) have no name left: judged by their content alone.
            named = same_name(base, tname.decode("utf-8", "replace")) or "-04" in name or (row["path"].startswith("$OrphanFiles/") and base.startswith("inode-"))
            r["name_ok"] += named
            if not named:
                # The first block belongs to another file: wrong content.
                r["other_file"] += 1
                r["incomplete"] += 1
                r["incomplete_warned"] += bool(row["note"])
                r["wrong_unwarned"] += not row["note"]
                continue
            r["blocks_good"] += good
            r["blocks"] += full
            if good == full:
                r["complete"] += 1
                fs["complete"] += 1
            else:
                r["incomplete"] += 1
                r["incomplete_warned"] += bool(row["note"])
                r["wrong_unwarned"] += not row["note"]
        if m.group(3) == "ext":
            # Deleted names with no content left (ext3/ext4 clear the block
            # map) are not in `kokino files`; the full analysis has them.
            aj = os.path.join(tmp, "analysis.json")
            subprocess.run([exe, "analyze", "--json", aj, raw], capture_output=True)
            a = json.load(open(aj, encoding="utf-8")) if os.path.exists(aj) else {"filesystems": []}
            r["names_found"] = sum(1 for fsa in a["filesystems"] for f in fsa["files"] if f["deleted"] and not f["is_dir"] and not f["orphan"])
            r["journal_recovered"] = sum(1 for fsa in a["filesystems"] for f in fsa["files"] if f.get("unix", {}).get("journal_seq") is not None)
            print("    deleted names found %d (NIST metadata found %s), recovered through the journal %d" % (r["names_found"], r["nist_metadata_found"], r["journal_recovered"]))
        results.append(r)
        shutil.rmtree(tmp, ignore_errors=True)
        print("%-16s NIST metadata %5s  listed %5d  names ok %5d/%-5d  complete %5d  blocks %7d/%-7d  incomplete %4d (other file %d, warned %d, wrong unwarned %d, not test data %d)  no content %d  %s" % (
            name, r["nist_metadata_found"], r["listed"], r["name_ok"], r["tagged"], r["complete"], r["blocks_good"], r["blocks"], r["incomplete"], r["other_file"], r["incomplete_warned"], r["wrong_unwarned"], r["untagged"], r["no_content"],
            " ".join("fs%s:%d/%d/%d" % (k, v["listed"], v["complete"], v["no_content"]) for k, v in sorted(r["by_fs"].items()))))
    json.dump(results, open(os.path.join(folder, "cfreds-results.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
