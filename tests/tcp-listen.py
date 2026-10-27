#!/usr/bin/env python3
"""P6-2: pendengar TCP untuk tests/qemu-smoke.sh (`pantau tcp`).

Mendengar TCP di 127.0.0.1:PORT (slirp meneruskan koneksi tamu ke
192.168.50.1:PORT ke loopback host) selama DETIK. Tiap koneksi diterima lalu
langsung ditutup, dan baris "koneksi N" (jumlah sejauh ini) dicetak.
    tcp-listen.py PORT DETIK
"""

import signal
import socket
import sys
import time


def main():
    port, secs = int(sys.argv[1]), float(sys.argv[2])
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    end = time.time() + secs
    n = 0
    while True:
        left = end - time.time()
        if left <= 0:
            return 0
        s.settimeout(min(left, 1.0))
        try:
            c, _ = s.accept()
        except socket.timeout:
            continue
        c.close()
        n += 1
        print("koneksi %d" % n, flush=True)


if __name__ == "__main__":
    sys.exit(main())
