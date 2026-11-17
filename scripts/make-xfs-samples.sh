#!/bin/sh
# Makes XFS test images for Kokino's validation: run on any Linux machine
# with xfsprogs (mkfs.xfs), as root (the images are mounted on a loop device).
#
#   sudo sh make-xfs-samples.sh [output folder]
#
# Every image gets a manifest written while it was mounted (inode, mode,
# size, times and SHA-256 of every file, and the same for each file before
# it was deleted), so Kokino's reading can be compared with the kernel's.
# All content is generated test data; nothing from the machine goes in.
# At the end, xfs-samples.tar.gz holds the images and manifests.
set -eu

OUT=${1:-./xfs-samples}
MNT=$(mktemp -d)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

command -v mkfs.xfs >/dev/null || { echo "mkfs.xfs not found: install xfsprogs" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo): the images are mounted" >&2; exit 1; }

# Small v5 file systems need these (as dfvfs does); the kernel then accepts them.
export TEST_DEV=1 TEST_DIR=1 QA_CHECK_FS=1

manifest() {
    # path, inode, mode, uid, gid, links, size, mtime, ctime, atime, birth, sha256
    (cd "$MNT" && find . -mindepth 1 | sort | while IFS= read -r p; do
        s=$(stat -c '%i %f %u %g %h %s %.9Y %.9Z %.9X %.9W' "$p")
        if [ -f "$p" ] && [ ! -L "$p" ]; then h=$(sha256sum "$p" | cut -d' ' -f1); else h=-; fi
        if [ -L "$p" ]; then t=" -> $(readlink "$p")"; else t=""; fi
        echo "$p $s $h$t"
    done)
}

# Deterministic content: n bytes of a numbered pattern.
content() { yes "kokino xfs sample line $2" | head -c "$1"; }

populate() {
    cd "$MNT"
    mkdir small block leaf node deep frag
    # Short form: a few names, kept in the inode.
    for i in 1 2 3; do content 100 "small-$i" > "small/s$i.txt"; done
    # Block form: one directory block.
    for i in $(seq 1 40); do content 300 "block-$i" > "block/file-$(printf %03d "$i").txt"; done
    # Leaf form: several blocks plus a hash index.
    for i in $(seq 1 400); do content 50 "leaf-$i" > "leaf/entry-$(printf %04d "$i").dat"; done
    # Node form: a large folder.
    for i in $(seq 1 6000); do : > "node/n$(printf %05d "$i")"; done
    mkdir -p deep/a/b/c/d && content 5000 deep > deep/a/b/c/d/deep.txt
    # Fragmented files: two files written in turn, one block at a time, so
    # their extents interleave; the big one needs an extent B+tree.
    i=0
    while [ $i -lt 120 ]; do
        content 4096 "frag-a-$i" >> frag/big-fragmented.bin
        content 4096 "frag-b-$i" >> frag/interleaved.bin
        sync
        i=$((i + 1))
    done
    # A sparse file, a preallocated (unwritten) range, an empty file.
    dd if=/dev/zero of=frag/sparse.bin bs=1 count=0 seek=10M 2>/dev/null
    content 4096 sparse-mid | dd of=frag/sparse.bin bs=4096 seek=1000 conv=notrunc 2>/dev/null
    fallocate -l 1M frag/prealloc.bin 2>/dev/null || true
    : > empty.txt
    # Links: short (in the inode), long (in a block), hard.
    ln -s small/s1.txt short-link
    ln -s "$(printf 'deep/%.0s' $(seq 1 60))../../small/s2.txt" long-link
    ln block/file-001.txt hardlink.txt
    # Extended attributes (user namespace).
    if command -v setfattr >/dev/null; then
        setfattr -n user.kokino.note -v "sample attribute" small/s1.txt
        setfattr -n user.kokino.big -v "$(content 3000 xattr)" small/s2.txt
    fi
    # Times set back (timestomping) and set to the far future.
    content 200 stomped > stomped.txt
    touch -d "2001-02-03 04:05:06" stomped.txt
    content 200 future > future.txt
    touch -d "2100-01-01 00:00:00" future.txt 2>/dev/null || true
    # Unicode names.
    content 64 unicode > "caf$(printf '\303\251') r$(printf '\303\251')sum$(printf '\303\251').txt"
    sync
}

delete_some() {
    cd "$MNT"
    # From the short-form folder: the last name, then a middle one.
    rm small/s3.txt small/s2.txt
    # From the block folder: one alone, then two neighbours.
    rm block/file-010.txt
    rm block/file-020.txt block/file-021.txt
    # From the leaf folder, and a fragmented file.
    rm leaf/entry-0100.dat leaf/entry-0101.dat
    rm frag/interleaved.bin
    # A whole folder with its files.
    rm -r deep/a/b
    sync
}

make() {
    name=$1
    shift
    img="$OUT/$name.img"
    rm -f "$img"
    truncate -s "${SIZE:-512M}" "$img"
    if ! mkfs.xfs -q -L kokino-test "$@" "$img"; then
        echo "skipped $name: mkfs.xfs $* failed (older or newer xfsprogs)" >&2
        rm -f "$img"
        return 0
    fi
    if ! mount -o loop "$img" "$MNT"; then
        echo "skipped $name: the kernel would not mount it" >&2
        rm -f "$img"
        return 0
    fi
    populate
    manifest > "$OUT/$name.before.txt"
    delete_some
    cd /
    umount "$MNT"
    # The deleted files' records as they were, for comparison.
    mount -o loop,ro "$img" "$MNT"
    manifest > "$OUT/$name.after.txt"
    umount "$MNT"
    xfs_info "$img" > "$OUT/$name.info.txt" 2>&1 || true
    echo "made $name"
}

make xfs-v5                                   # today's defaults
make xfs-v5-4ag -d agcount=4                  # four allocation groups
make xfs-v5-bigtime -m bigtime=1 -i nrext64=1 # dates past 2038, 64-bit extent counts
make xfs-v5-sparse -i sparse=1,size=1024      # sparse inode chunks, 1 KiB inodes
make xfs-v5-1k -b size=1024 -n size=8192      # 1 KiB blocks, 8 KiB directory blocks
SIZE=128M make xfs-v4 -m crc=0                # the older format (CentOS 6 and 7)

rmdir "$MNT"
mkfs.xfs -V > "$OUT/xfsprogs-version.txt" 2>&1 || true
uname -r > "$OUT/kernel-version.txt"
cd "$OUT" && tar -cSzf xfs-samples.tar.gz ./*.img ./*.txt
echo "done: $OUT/xfs-samples.tar.gz"
