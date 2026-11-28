#!/usr/bin/env python3
# F7 SSH-1a: pembuat vektor tetap untuk test_vektor() di test_ssh.c, TANPA memakai kode server.
# Masukan (stdin) = keluaran test_ssh dengan SSH_VEC_DUMP=1 (baris "nama=hex"). Python murni:
# X25519 RFC 7748 (tangga Montgomery), SHA-256 hashlib, string/mpint RFC 4251, turunan kunci RFC 4253 7.2.
# Keluaran = konstanta C untuk ditempel ke test_ssh.c. Vektor terikat ke entropi stub yang
# deterministik (g_ent_ctr = 0 sebelum sesi); bila urutan pemakaian DRBG di ssh.c berubah, bangkitkan ulang:
#   SSH_VEC_DUMP=1 build/host/test_ssh | python3 tests/host/ssh_vectors.py
import hashlib, sys

P = 2**255 - 19
A24 = 121665


def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    u = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2 + z2) % P; aa = a * a % P
        b = (x2 - z2) % P; bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P; d = (x3 - z3) % P
        da = d * a % P; cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * ((da - cb) ** 2) % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def string(b):
    return len(b).to_bytes(4, "big") + b


def mpint(b):
    b = b.lstrip(b"\0")
    if b and b[0] & 0x80:
        b = b"\0" + b
    return string(b)


d = {}
for line in sys.stdin:
    if "=" in line and not line.startswith(" "):
        k, v = line.strip().split("=", 1)
        d[k] = bytes.fromhex(v)

K = x25519(d["x"], d["qs"])
assert x25519(d["x"], bytes([9]) + bytes(31)) == d["qc"], "Q_C tidak cocok dengan x"
kmp = mpint(K)
H = hashlib.sha256(string(d["vc"]) + string(d["vs"]) + string(d["ic"]) + string(d["is"]) +
                   string(d["ks"]) + string(d["qc"]) + string(d["qs"]) + kmp).digest()


def kdf(letter):
    return hashlib.sha256(kmp + H + letter + H).digest()


print("#define VEC_K    \"%s\"" % K.hex())
print("#define VEC_H    \"%s\"" % H.hex())
print("#define VEC_IV_C \"%s\"   // A: IV c2s, 12 byte" % kdf(b"A")[:12].hex())
print("#define VEC_IV_S \"%s\"   // B: IV s2c, 12 byte" % kdf(b"B")[:12].hex())
print("#define VEC_KEY_C \"%s\"  // C: kunci c2s, 16 byte" % kdf(b"C")[:16].hex())
print("#define VEC_KEY_S \"%s\"  // D: kunci s2c, 16 byte" % kdf(b"D")[:16].hex())
