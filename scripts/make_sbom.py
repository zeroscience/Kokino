#!/usr/bin/env python3
"""Software bill of materials for a Kokino release: CycloneDX 1.5 JSON.

Every crate in Cargo.lock that comes from crates.io is a component, with
its version, package URL (pkg:cargo/name@version), the SHA-256 Cargo.lock
records for it and, when the crate's source is in the local Cargo
registry (it is after a build), its declared license. Kokino's own crates
are the top component. Nothing is downloaded.

Usage: python scripts/make_sbom.py [--out FILE]   (default: stdout)
"""
import glob
import json
import os
import re
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def lock_packages(path):
    pkgs, cur = [], None
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line == "[[package]]":
            cur = {}
            pkgs.append(cur)
        elif cur is not None:
            m = re.match(r'^(name|version|source|checksum) = "(.*)"$', line)
            if m:
                cur[m.group(1)] = m.group(2)
    return pkgs


def workspace_version():
    m = re.search(r'\[workspace\.package\][^\[]*?version\s*=\s*"([^"]+)"', open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8").read(), re.S)
    return m.group(1) if m else "0.0.0"


def license_of(name, version):
    home = os.environ.get("CARGO_HOME") or os.path.join(os.path.expanduser("~"), ".cargo")
    for d in glob.glob(os.path.join(home, "registry", "src", "*", "%s-%s" % (name, version))):
        try:
            text = open(os.path.join(d, "Cargo.toml"), encoding="utf-8").read()
        except OSError:
            continue
        m = re.search(r'^license\s*=\s*"([^"]+)"', text, re.M)
        if m:
            return m.group(1)
    return None


def build():
    version = workspace_version()
    comps = []
    for p in lock_packages(os.path.join(ROOT, "Cargo.lock")):
        if not p.get("source", "").startswith("registry+"):
            continue
        c = {
            "type": "library",
            "bom-ref": "pkg:cargo/%s@%s" % (p["name"], p["version"]),
            "name": p["name"],
            "version": p["version"],
            "purl": "pkg:cargo/%s@%s" % (p["name"], p["version"]),
        }
        if p.get("checksum"):
            c["hashes"] = [{"alg": "SHA-256", "content": p["checksum"]}]
        lic = license_of(p["name"], p["version"])
        if lic:
            c["licenses"] = [{"expression": lic}]
        comps.append(c)
    comps.sort(key=lambda c: (c["name"], c["version"]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        # Stable for a given version, so the SBOM of a release can be rebuilt.
        "serialNumber": "urn:uuid:%s" % uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/zeroscience/Kokino/releases/v%s" % version),
        "version": 1,
        "metadata": {
            "component": {"type": "application", "bom-ref": "kokino@%s" % version, "name": "kokino", "version": version,
                          "licenses": [{"license": {"id": "Apache-2.0"}}], "supplier": {"name": "Zero Science Lab", "url": ["https://www.zeroscience.mk"]}},
            "tools": {"components": [{"type": "application", "name": "make_sbom.py", "version": version}]},
        },
        "components": comps,
        "dependencies": [{"ref": "kokino@%s" % version, "dependsOn": [c["bom-ref"] for c in comps]}],
    }


def main():
    out = None
    if sys.argv[1:2] == ["--out"] and len(sys.argv) > 2:
        out = sys.argv[2]
    bom = json.dumps(build(), indent=2, sort_keys=False) + "\n"
    if out:
        open(out, "w", encoding="utf-8", newline="\n").write(bom)
        print("wrote %s (%d components)" % (out, len(json.loads(bom)["components"])), file=sys.stderr)
    else:
        sys.stdout.write(bom)


if __name__ == "__main__":
    main()
