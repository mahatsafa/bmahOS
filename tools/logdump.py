#!/usr/bin/env python3
"""R4: baca LOG.BIN bmahOS (ring rekaman 512 byte) di luar kernel.

Pakai:
    mcopy -i disk.img ::LOG.BIN log.bin     (VMware: qemu-img convert dulu)
    python3 tools/logdump.py log.bin [--boot N] [--status]

Rekaman sah (magic BMLG, versi 1, panjang <= 480, hash = 8 byte pertama
SHA-256 sektor dengan field hash nol) diurutkan menurut seq; header
"=== boot B seq S [panic] ===" dicetak saat boot berganti, setelah celah seq,
atau di rekaman panic pertama (ditulis logdisk_sync saat panic).
Kode keluar: 0 ada rekaman, 1 tidak ada rekaman sah, 2 file salah.
"""
import argparse
import hashlib
import struct
import sys

REC = 512
HDR = 32
TEXT = REC - HDR


def parse(data):
    recs, bad = [], 0
    for off in range(0, len(data) - REC + 1, REC):
        r = data[off:off + REC]
        if r[:4] != b"BMLG":
            continue
        ver, flags, ln, boot, _, seq = struct.unpack_from("<BBHIIQ", r, 4)
        h = hashlib.sha256(r[:24] + b"\0" * 8 + r[32:]).digest()[:8]
        if ver != 1 or ln > TEXT or seq == 0 or h != r[24:32]:
            bad += 1
            continue
        recs.append((seq, boot, flags, r[HDR:HDR + ln]))
    recs.sort()
    return recs, bad


def main():
    p = argparse.ArgumentParser(description="Baca LOG.BIN bmahOS (R4).")
    p.add_argument("file")
    p.add_argument("--boot", type=int, default=None, help="hanya boot ini")
    p.add_argument("--status", action="store_true", help="ringkasan saja")
    a = p.parse_args()
    with open(a.file, "rb") as f:
        data = f.read()
    if not data or len(data) % REC:
        sys.stderr.write("logdump: ukuran %d bukan kelipatan 512\n" % len(data))
        return 2
    recs, bad = parse(data)
    if a.status:
        boots = sorted({b for _, b, _, _ in recs})
        print("rekaman=%d sah=%d rusak=%d boot=%s seq=%s..%s" % (
            len(data) // REC, len(recs), bad, ",".join(map(str, boots)) or "-",
            recs[0][0] if recs else "-", recs[-1][0] if recs else "-"))
        return 0 if recs else 1
    out = sys.stdout.buffer
    prev_boot, prev_seq, prev_panic = None, None, 0
    for seq, boot, flags, text in recs:
        if a.boot is not None and boot != a.boot:
            continue
        if (boot != prev_boot or (prev_seq is not None and seq != prev_seq + 1) or
                (flags & 1) > prev_panic):
            out.write(("=== boot %d seq %d%s ===\n" % (
                boot, seq, " panic" if flags & 1 else "")).encode())
        out.write(text)
        prev_boot, prev_seq, prev_panic = boot, seq, flags & 1
    return 0 if recs else 1


if __name__ == "__main__":
    sys.exit(main())
