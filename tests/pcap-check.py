#!/usr/bin/env python3
"""D9: cari teks polos di payload TCP sebuah port dalam file pcap (QEMU filter-dump).

    pcap-check.py FILE PORT TEKS...

Mencetak jumlah segmen/byte port itu dan teks yang ditemukan; keluar 0 bila
ada payload dan tidak satu pun TEKS muncul (dicari di gabungan payload per
arah, jadi teks yang terpotong antar segmen tetap tertangkap).
"""

import struct
import sys


def main():
    path, port, words = sys.argv[1], int(sys.argv[2]), [w.encode() for w in sys.argv[3:]]
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    end = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    off, segs = 24, 0
    streams = {}
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(end + "IIII", data[off:off + 16])
        pkt = data[off + 16:off + 16 + incl]
        off += 16 + incl
        if len(pkt) < 34 or pkt[12:14] != b"\x08\x00" or pkt[23] != 6:
            continue
        ihl = (pkt[14] & 0xF) * 4
        tot = struct.unpack(">H", pkt[16:18])[0]
        tcp = pkt[14 + ihl:14 + tot]
        if len(tcp) < 20:
            continue
        sp, dp = struct.unpack(">HH", tcp[:4])
        if port not in (sp, dp):
            continue
        pl = tcp[(tcp[12] >> 4) * 4:]
        if pl:
            segs += 1
            streams.setdefault((sp, dp), bytearray()).extend(pl)
    total = sum(len(v) for v in streams.values())
    found = sorted({w.decode() for w in words for v in streams.values() if w in v})
    print("port %d: %d segmen data, %d byte, teks ditemukan: %s"
          % (port, segs, total, ", ".join(found) or "-"))
    return 0 if total > 0 and not found else 1


if __name__ == "__main__":
    sys.exit(main())
