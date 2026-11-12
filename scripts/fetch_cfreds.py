"""Downloads the NIST CFReDS deleted file recovery images that
tests/validation/cfreds-expected.json lists, and NIST's layout document,
into a folder (skipping files already there), for validate_cfreds.py.

    python scripts/fetch_cfreds.py <folder> [fat|xfat|ntfs|ext ...]

The images come from https://cfreds-archive.nist.gov/dfr-images/ (about
240 MB compressed in all). Standard library only.
"""
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "https://cfreds-archive.nist.gov/dfr-images/"
PDF = "setup-july-10-2012.pdf"


def file_name(image):
    # "fat-05-braid" -> "dfr-05-braid-fat.dd.bz2"
    kind, rest = image.split("-", 1)
    return "dfr-%s-%s.dd.bz2" % (rest, kind)


def fetch(url, dest):
    for attempt in range(4):
        try:
            tmp = dest + ".part"
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "kokino-validation"}), timeout=120) as r, open(tmp, "wb") as f:
                while True:
                    b = r.read(1 << 20)
                    if not b:
                        break
                    f.write(b)
            os.replace(tmp, dest)
            return
        except OSError as e:
            if attempt == 3:
                raise
            print("  retrying %s (%s)" % (url, e))
            time.sleep(10 * (attempt + 1))


def main():
    folder = sys.argv[1]
    kinds = set(sys.argv[2:])
    os.makedirs(folder, exist_ok=True)
    images = json.load(open(os.path.join(ROOT, "tests", "validation", "cfreds-expected.json"), encoding="utf-8"))
    names = [PDF] + [file_name(i) for i in sorted(images) if not kinds or i.split("-")[0] in kinds]
    for n in names:
        dest = os.path.join(folder, n)
        if os.path.exists(dest) and os.path.getsize(dest) > 0:
            continue
        print("fetching", n)
        fetch(BASE + n, dest)
    print("%d file(s) in %s" % (len(names), folder))


if __name__ == "__main__":
    main()
