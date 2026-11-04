#!/usr/bin/env python3
"""P7: buat file kiriman OTA .bmo (header 64 + tanda tangan 64 + isi).

Header (little endian):
  0  magic "BMOTA1\\0\\0"     8  jenis u32 (1 kernel, 2 app)   12 versi u32
  16 ukuran isi u32          20 cadangan u32 = 0
  24 sha256(isi) 32 byte     56 cadangan 8 byte = 0
Tanda tangan: ECDSA P-256 atas SHA-256(header), format mentah r||s (32+32).
Butuh program openssl. Kunci privat PEM tidak pernah dibaca isinya oleh skrip ini
(hanya diteruskan ke openssl).

  ota-sign.py --kunci K.pem --jenis kernel|app --versi N MASUK KELUAR.bmo
  ota-sign.py --pub K.pem --nama ota_pub_x     (array C kunci publik 65 byte)
  ota-sign.py --cek K.pem FILE.bmo              (verifikasi dengan openssl)
"""
import argparse, hashlib, os, struct, subprocess, sys, tempfile

MAGIC = b"BMOTA1\0\0"
JENIS = {"kernel": 1, "app": 2}
MAKS = {1: 1024 * 1024, 2: 4096 - 128}   # P7-4: file .bmo app = APP.BIN <= 4096 (batas file FAT32)


def der_ke_mentah(der):
    # SEQUENCE { INTEGER r, INTEGER s }, panjang pendek (< 128) untuk P-256.
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("DER tanda tangan tidak dikenal")
    i, out = 2, b""
    for _ in range(2):
        if der[i] != 0x02:
            raise ValueError("DER: bukan INTEGER")
        n = der[i + 1]
        v = der[i + 2:i + 2 + n].lstrip(b"\0")
        if len(v) > 32:
            raise ValueError("DER: integer > 32 byte")
        out += v.rjust(32, b"\0")
        i += 2 + n
    if i != len(der):
        raise ValueError("DER: sisa byte")
    return out


def mentah_ke_der(raw):
    def integer(v):
        v = v.lstrip(b"\0") or b"\0"
        if v[0] & 0x80:
            v = b"\0" + v
        return bytes([2, len(v)]) + v
    body = integer(raw[:32]) + integer(raw[32:])
    return bytes([0x30, len(body)]) + body


def openssl(args, data=None):
    return subprocess.run(["openssl"] + args, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def header(jenis, versi, isi):
    return MAGIC + struct.pack("<IIII", jenis, versi, len(isi), 0) + \
        hashlib.sha256(isi).digest() + b"\0" * 8


def tandatangani(kunci, data):
    der = openssl(["dgst", "-sha256", "-sign", kunci], data)
    return der_ke_mentah(der)


def pub_mentah(kunci):
    der = openssl(["ec", "-in", kunci, "-pubout", "-outform", "DER"])
    q = der[-65:]
    if q[0] != 4:
        raise ValueError("kunci publik bukan titik tak terkompresi P-256")
    return q


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kunci")
    ap.add_argument("--jenis", choices=sorted(JENIS))
    ap.add_argument("--versi", type=int)
    ap.add_argument("--pub")
    ap.add_argument("--nama", default="ota_pub")
    ap.add_argument("--cek")
    ap.add_argument("file", nargs="*")
    a = ap.parse_args()

    if a.pub:
        q = pub_mentah(a.pub)
        print("static const uint8_t %s[65] = {" % a.nama)
        for i in range(0, 65, 12):
            print("    " + ", ".join("0x%02x" % b for b in q[i:i + 12]) + ",")
        print("};")
        return 0

    if a.cek:
        d = open(a.file[0], "rb").read()
        h, sig, isi = d[:64], d[64:128], d[128:]
        if h[:8] != MAGIC or struct.unpack("<I", h[16:20])[0] != len(isi) or \
                hashlib.sha256(isi).digest() != h[24:56]:
            print("format/ukuran/sha256 salah")
            return 1
        with tempfile.TemporaryDirectory() as t:
            pem = os.path.join(t, "pub.pem")
            open(pem, "wb").write(openssl(["ec", "-in", a.cek, "-pubout"]))
            sf = os.path.join(t, "sig.der")
            open(sf, "wb").write(mentah_ke_der(sig))
            r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pem, "-signature", sf],
                               input=h, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(r.stdout.decode().strip() or r.stderr.decode().strip())
        return r.returncode

    if not (a.kunci and a.jenis and a.versi is not None and len(a.file) == 2):
        ap.error("butuh --kunci --jenis --versi MASUK KELUAR")
    isi = open(a.file[0], "rb").read()
    j = JENIS[a.jenis]
    if not 0 < len(isi) <= MAKS[j]:
        sys.exit("isi %d byte di luar batas jenis %s (1..%d)" % (len(isi), a.jenis, MAKS[j]))
    if not 0 <= a.versi <= 0xFFFFFFFF:
        sys.exit("versi di luar u32")
    h = header(j, a.versi, isi)
    with open(a.file[1], "wb") as f:
        f.write(h + tandatangani(a.kunci, h) + isi)
    print("%s: jenis=%s versi=%d ukuran=%d sha256=%s" %
          (a.file[1], a.jenis, a.versi, len(isi), hashlib.sha256(isi).hexdigest()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
