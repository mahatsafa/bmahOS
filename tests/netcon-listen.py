#!/usr/bin/env python3
"""R2: penerima netconsole untuk tests/qemu-smoke.sh.

Mendengar UDP di 127.0.0.1:PORT (slirp meneruskan datagram tamu ke
192.168.50.1:PORT ke loopback host) dan menambahkan payload tiap datagram
ke file OUT sampai DETIK habis atau proses dihentikan (SIGTERM).
    netcon-listen.py PORT OUT DETIK
"""

import signal
import socket
import sys
import time


def main():
    port, out, secs = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    end = time.time() + secs
    with open(out, "ab") as f:
        while True:
            left = end - time.time()
            if left <= 0:
                return 0
            s.settimeout(min(left, 1.0))
            try:
                d = s.recv(65536)
            except socket.timeout:
                continue
            f.write(d)
            f.flush()


if __name__ == "__main__":
    sys.exit(main())
