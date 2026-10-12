#!/usr/bin/env python3
"""C4: uji echo TCP ujung-ke-ujung. Kirim N byte acak ke port echo bmahOS
sambil menerima balasannya, lalu bandingkan SHA-256 keduanya.

    tcp-echo.py HOST PORT [--size BYTE] [--timeout DETIK]

Keluar 0 bila jumlah byte dan hash sama. Pengirim dan penerima berjalan
bersamaan (thread), karena bmahOS hanya punya buffer 1024 byte: tanpa
membaca balasan, pengirim akan tertahan jendela 0.
"""

import argparse
import hashlib
import os
import socket
import sys
import threading
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("--size", type=int, default=1 << 20)
    p.add_argument("--timeout", type=float, default=300)
    a = p.parse_args()

    data = os.urandom(a.size)
    s = socket.create_connection((a.host, a.port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(a.timeout)
    err = []

    def sender():
        try:
            s.sendall(data)
        except OSError as e:
            err.append("kirim: %s" % e)

    t0 = time.time()
    th = threading.Thread(target=sender, daemon=True)
    th.start()
    h = hashlib.sha256()
    got = 0
    try:
        while got < a.size:
            b = s.recv(65536)
            if not b:
                err.append("koneksi ditutup setelah %d byte" % got)
                break
            h.update(b)
            got += len(b)
    except OSError as e:
        err.append("terima: %s" % e)
    dt = time.time() - t0
    th.join(5)
    # Tutup normal (C3d): FIN kita, bmahOS membalas FIN setelah echo habis.
    try:
        s.shutdown(socket.SHUT_WR)
        s.settimeout(10)
        rest = s.recv(16)
        if rest:
            err.append("data lebih setelah %d byte" % got)
    except OSError as e:
        err.append("tutup: %s" % e)
    s.close()

    sent_hash = hashlib.sha256(data).hexdigest()
    same = got == a.size and h.hexdigest() == sent_hash
    print("tcp-echo: %d/%d byte dalam %.1f s (%.1f KB/s), sha256 %s%s" % (
        got, a.size, dt, got / 1024 / max(dt, 0.001), "SAMA" if same else "BEDA",
        "" if not err else "; " + "; ".join(err)))
    return 0 if same and not err else 1


if __name__ == "__main__":
    sys.exit(main())
