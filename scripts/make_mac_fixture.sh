#!/bin/bash
# HFS+ and APFS test images for Kokino, made with Apple's own tools.
#
# Runs on macOS (the "mac-fixtures" GitHub Actions workflow runs it on
# GitHub's macOS runner). Writes raw images and a manifest of what macOS
# reports about every file, which the tests use as ground truth:
#
#   out/hfsplus.img    bare HFS+ (journaled) volume, 8 MiB
#   out/apfs.img       GPT disk with an APFS container, 32 MiB, one
#                      volume (KOKINO_APFS); a container gets one volume
#                      slot per 512 MiB, so a second volume would need a
#                      much larger image
#   out/manifest.txt   stat, extended attributes and flags of every file
#
# The story (invented data) on every volume:
#   hello.txt                   small file with extended attributes,
#                               including a quarantine flag like Safari's
#   Documents/report.txt        9,000 bytes
#   Documents/deep/a/b/c/notes.txt
#   Documents/hello-link.txt    hard link to hello.txt
#   link                        symbolic link to Documents/report.txt
#   compressed.txt              64 KiB of text stored HFS-compressed
#                               (ditto --hfsCompression)
#   Cafe Skopje.txt             with an e-acute (Unicode, decomposed on HFS+)
#   secret.txt                  written, synced, then deleted
#
#   bash scripts/make_mac_fixture.sh out
set -euo pipefail

OUT="${1:-out}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
STAMP=202610200805.30   # 2026-10-20 08:05:30 (the runner's clock is UTC)
export TZ=UTC

populate() {
  local v="$1"
  printf 'Hello from the Kokino macOS test volume.\n' > "$v/hello.txt"
  xattr -w com.kokino.test "lab value" "$v/hello.txt"
  xattr -w com.apple.quarantine "0083;6a1f3c4a;Safari;8F1E2D3C-0000-4000-8000-000000000001" "$v/hello.txt"
  mkdir -p "$v/Documents/deep/a/b/c"
  python3 -c "import sys; sys.stdout.write(('Quarterly report line, lab.test internal.\n' * 220)[:9000])" > "$v/Documents/report.txt"
  printf 'deep note\n' > "$v/Documents/deep/a/b/c/notes.txt"
  ln "$v/hello.txt" "$v/Documents/hello-link.txt"
  ln -s Documents/report.txt "$v/link"
  python3 -c "import sys; sys.stdout.write('compressible line for decmpfs, lab.test\n' * 1600)" > "$WORK/compressed.txt"
  ditto --hfsCompression "$WORK/compressed.txt" "$v/compressed.txt"
  printf 'cafe\n' > "$v/$(printf 'Caf\xc3\xa9 Skopje.txt')"
  printf 'SECRET: meet at the lab.test office, 10:00 (test data)\n' > "$v/secret.txt"
  sync
  sleep 1
  rm "$v/secret.txt"
  # Fixed modification and access times, a minute apart.
  local i=0
  for f in hello.txt Documents/report.txt Documents/deep/a/b/c/notes.txt compressed.txt "$(printf 'Caf\xc3\xa9 Skopje.txt')"; do
    i=$((i + 1))
    touch -t "$(date -j -v+${i}M -f %Y%m%d%H%M.%S "$STAMP" +%Y%m%d%H%M.%S)" "$v/$f"
  done
  touch -h -t "$STAMP" "$v/link"
  sync
}

manifest() {
  local v="$1" name="$2"
  {
    echo "== $name"
    (cd "$v" && find . -print0 | sort -z | while IFS= read -r -d '' f; do
      stat -f "%i %HT %z %Sm %SB %N" -t "%Y-%m-%dT%H:%M:%SZ" "$f"
      ls -ldO "$f" | awk '{print "  flags " $5}'
      xattr -l "$f" 2>/dev/null | sed 's/^/  xattr /'
    done)
  } >> "$OUT/manifest.txt"
}

: > "$OUT/manifest.txt"

# HFS+ (journaled), no partition table.
hdiutil create -size 8m -fs "Journaled HFS+" -volname KOKINO_HFS -layout NONE -ov "$WORK/hfs.dmg"
MNT="$WORK/hfsmnt"
mkdir -p "$MNT"
hdiutil attach "$WORK/hfs.dmg" -mountpoint "$MNT" -nobrowse -owners on
populate "$MNT"
manifest "$MNT" "hfsplus.img"
hdiutil detach "$MNT"
hdiutil convert "$WORK/hfs.dmg" -format UDTO -o "$WORK/hfs"
mv "$WORK/hfs.cdr" "$OUT/hfsplus.img"

# APFS: a GPT disk with one container and one volume.
hdiutil create -size 32m -fs APFS -volname KOKINO_APFS -layout GPTSPUD -ov "$WORK/apfs.dmg"
ATTACH="$(hdiutil attach "$WORK/apfs.dmg" -nobrowse -owners on)"
echo "$ATTACH"
MNT="$(echo "$ATTACH" | awk -F'\t' '/KOKINO_APFS/ {print $NF}' | sed 's/^ *//' | tail -1)"
populate "$MNT"
manifest "$MNT" "apfs.img KOKINO_APFS"
hdiutil detach "$(echo "$ATTACH" | head -1 | awk '{print $1}')"
hdiutil convert "$WORK/apfs.dmg" -format UDTO -o "$WORK/apfs"
mv "$WORK/apfs.cdr" "$OUT/apfs.img"

ls -la "$OUT"
cat "$OUT/manifest.txt"
rm -rf "$WORK"
