#!/usr/bin/env python3
"""P1: screendump QEMU lewat monitor HMP (unix socket) lalu periksa layar.

Pakai: fb-check.py MON_SOCK OUT.ppm
Lulus (kode 0) bila layar hanya berisi latar hitam dan satu warna teks
abu-abu c0c0c0 (warna fbcon), dengan cukup banyak piksel teks, dan baris
teks pertama (16 piksel teratas) tidak kosong.
"""

import os
import socket
import sys
import time


def screendump(sock_path, out):
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock_path)
    s.settimeout(5)
    time.sleep(0.3)
    try:
        s.recv(65536)   # banner HMP
    except socket.timeout:
        pass
    if os.path.exists(out):
        os.remove(out)
    s.sendall(("screendump %s\n" % out).encode())
    for _ in range(50):
        time.sleep(0.2)
        if os.path.exists(out) and os.path.getsize(out) > 0:
            break
    time.sleep(0.5)
    s.close()


def main():
    sock_path, out = sys.argv[1], sys.argv[2]
    screendump(sock_path, out)
    with open(out, "rb") as f:
        data = f.read()
    magic, dims, maxv, px = data.split(b"\n", 3)
    w, h = map(int, dims.split())
    if magic != b"P6" or maxv != b"255" or len(px) < w * h * 3:
        print("fb: ppm tidak dikenal")
        return 1
    colors = {}
    for i in range(0, w * h * 3, 3):
        c = px[i:i + 3]
        colors[c] = colors.get(c, 0) + 1
    fg = colors.get(b"\xc0\xc0\xc0", 0)
    other = {c.hex(): n for c, n in colors.items() if c not in (b"\x00\x00\x00", b"\xc0\xc0\xc0")}
    top = sum(1 for i in range(0, w * 16 * 3, 3) if px[i:i + 3] == b"\xc0\xc0\xc0")
    print("fb: %dx%d warna=%d piksel_teks=%d baris1=%d lain=%s"
          % (w, h, len(colors), fg, top, dict(list(other.items())[:4])))
    return 0 if not other and fg > 5000 and top > 50 else 1


if __name__ == "__main__":
    sys.exit(main())
