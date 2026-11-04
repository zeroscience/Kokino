"""Optical disc test images for Kokino, built with mkisofs (cdrtools).

    tests/fixtures/iso-rr-joliet.iso   ISO 9660 + Rock Ridge + Joliet
    tests/fixtures/iso-udf.iso         the same with a UDF 1.02 bridge
    tests/fixtures/iso-multisession.iso two sessions: session 1 has
                                        secret-plan.txt, session 2 drops it
                                        and adds added-later.txt

The tree (invented data):

    README.TXT
    A file with a long name and spaces.txt
    Unicode name - Skopje Ohrid.txt  (Joliet and Rock Ridge keep it; ISO
                                      9660 level 1 names are 8.3)
    docs/report.txt                   9,000 bytes (five 2 KiB sectors)
    docs/a/b/c/d/e/f/g/h/deep.txt     nine levels down (Rock Ridge moves
                                      the deepest folder to rr_moved)
    secret-plan.txt                   session 1 only

Every file has a fixed modification time, 2026-10-20 08:05:30 UTC plus a
few minutes per file. mkisofs stamps the volume with the time it runs, so
the images are not byte-reproducible; the tests check content and file
times only.

    MKISOFS="C:/Program Files (x86)/VMware/VMware Player/mkisofs.exe" python scripts/make_iso_fixture.py
"""
import os
import shutil
import subprocess
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
MKISOFS = os.environ.get("MKISOFS", "mkisofs")
T0 = 1792483530

FILES = {
    "README.TXT": b"Kokino optical test disc. Invented data.\n",
    "A file with a long name and spaces.txt": b"long name test\n",
    "Unicode name - Skopje Ohrid.txt".replace(" - ", " \u2013 ").replace("\u2013", "-"): b"names test\n",
    "docs/report.txt": (b"Quarterly report line, lab.test internal.\n" * 220)[:9000],
    "docs/a/b/c/d/e/f/g/h/deep.txt": b"nine levels down\n",
}
SECRET = {"secret-plan.txt": b"SECRET: meet at the lab.test office, 10:00 (test data)\n"}
LATER = {"added-later.txt": b"written in the second session\n"}


def tree(base, files):
    for i, (rel, data) in enumerate(sorted(files.items())):
        p = os.path.join(base, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        t = T0 + 60 * (i + 1)
        os.utime(p, (t, t))
    for d, _, _ in os.walk(base):
        os.utime(d, (T0, T0))


def mk(args, out, cwd):
    # Paths relative to `cwd`: this mkisofs build mishandles Windows paths.
    cmd = [MKISOFS, "-V", "KOKINO_DISC", "-o", "out.iso"] + args  # options before paths
    subprocess.run(cmd, check=True, cwd=cwd, stderr=subprocess.DEVNULL)
    shutil.move(os.path.join(cwd, "out.iso"), out)


def drop_record(disc, lba, prefixes):
    """Removes the directory record whose name starts with one of
    `prefixes` from the first sector of the directory at `lba`."""
    base = lba * 2048
    sec = disc[base:base + 2048]
    out, pos = bytearray(), 0
    while pos < 2048 and sec[pos]:
        n = sec[pos]
        rec = sec[pos:pos + n]
        name = bytes(rec[33:33 + rec[32]])
        if not any(name.startswith(p) for p in prefixes):
            out += rec
        pos += n
    disc[base:base + 2048] = bytes(out).ljust(2048, b"\0")


def mark_udf_deleted(path, name):
    """Sets the deleted bit on the UDF file identifier descriptor (tag 257)
    that names `name` (8-bit OSTA CS0)."""
    d = bytearray(open(path, "rb").read())
    want = b"\x08" + name.encode()
    for sec in range(0, len(d) // 2048):
        blk = d[sec * 2048:(sec + 1) * 2048]
        pos = 0
        while pos + 38 <= 2048 and int.from_bytes(blk[pos:pos + 2], "little") == 257:
            l_fi, l_iu = blk[pos + 19], int.from_bytes(blk[pos + 36:pos + 38], "little")
            if bytes(blk[pos + 38 + l_iu:pos + 38 + l_iu + l_fi]) == want:
                d[sec * 2048 + pos + 18] |= 4
                open(path, "wb").write(d)
                return
            pos += (38 + l_iu + l_fi + 3) & ~3
    raise SystemExit("FID for %s not found" % name)


def main():
    work = tempfile.mkdtemp(prefix="kokino-iso-")
    try:
        one = os.path.join(work, "one")
        tree(one, FILES)
        mk(["-R", "-J", "one"], os.path.join(FIX, "iso-rr-joliet.iso"), work)
        # UDF: one more file, then its directory entry marked deleted (bit 2
        # of the FID characteristics) as a UDF writer does when deleting.
        udf_src = os.path.join(work, "udf")
        tree(udf_src, dict(FILES, **{"deleted-in-udf.txt": b"deleted from the UDF directory (test data)\n"}))
        mk(["-R", "-J", "-udf", "udf"], os.path.join(FIX, "iso-udf.iso"), work)
        mark_udf_deleted(os.path.join(FIX, "iso-udf.iso"), "deleted-in-udf.txt")

        # Two sessions: the second leaves secret-plan.txt out.
        s1dir = os.path.join(work, "s1")
        tree(s1dir, dict(FILES, **SECRET))
        s1 = os.path.join(work, "s1.iso")
        mk(["-R", "-J", "s1"], s1, work)
        s1_sectors = os.path.getsize(s1) // 2048
        next_start = s1_sectors + 150 + 11250 // 100  # the run-out and lead-in a recorder leaves (kept small)
        s2dir = os.path.join(work, "s2")
        tree(s2dir, LATER)
        s2 = os.path.join(work, "s2.iso")
        # -M merges the previous session's tree; files removed from it with -m.
        mk(["-R", "-J", "-M", "s1.iso", "-C", "0,%d" % next_start, "-m", "secret-plan.txt", "s2"], s2, work)
        disc = bytearray(open(s1, "rb").read().ljust(next_start * 2048, b"\0") + open(s2, "rb").read())
        # mkisofs -M carries every old file over (-m only excludes new
        # ones). Burning software removes a file in a new session by leaving
        # its record out of the new directory: do that in session 2's ISO
        # and Joliet root directories.
        for vd in range(next_start + 16, next_start + 32):
            d = disc[vd * 2048:(vd + 1) * 2048]
            if d[1:6] != b"CD001" or d[0] == 255:
                break
            if d[0] in (1, 2):
                lba = int.from_bytes(d[156 + 2:156 + 6], "little")
                drop_record(disc, lba, (b"SECRET", "secret-plan".encode("utf-16-be")))
        with open(os.path.join(FIX, "iso-multisession.iso"), "wb") as f:
            f.write(disc)
        for n in ("iso-rr-joliet.iso", "iso-udf.iso", "iso-multisession.iso"):
            print(n, os.path.getsize(os.path.join(FIX, n)))
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
