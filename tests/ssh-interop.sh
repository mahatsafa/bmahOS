#!/bin/bash
# F7 SSH-1a: uji interop transport SSH-2 dengan klien OpenSSH sungguhan (tanpa QEMU).
# ssh.c berjalan di tests/host/ssh_interop.c (soket 127.0.0.1, port acak); klien `ssh` lokal
# tersambung tanpa kunci pengguna, harus sampai kex + ecdsa host key + "Permission denied (publickey)".
# Dipanggil manual: tests/ssh-interop.sh  (dilewati dengan kode 0 bila ssh/openssl/clang tidak ada)
set -u
cd "$(dirname "$0")/.."
for t in ssh openssl clang; do
    command -v "$t" >/dev/null || { echo "ssh-interop: DILEWATI ($t tidak ada)"; exit 0; }
done
D=build/ssh-interop
mkdir -p "$D"
make --no-print-directory build/host/libbearssl.a >/dev/null || exit 1
openssl ecparam -name prime256v1 -genkey -noout -outform DER -out "$D/hostkey.der" 2>/dev/null || exit 1
clang -std=gnu11 -g -O1 -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all \
    -DBMAHOS_HOST_TEST -Ikernel -Itests/host -Ithird_party/bearssl/inc \
    tests/host/ssh_interop.c kernel/ssh.c tests/host/stubs.c build/host/libbearssl.a -o "$D/ssh_interop" || exit 1

fail=0
run() {   # nama opsi...
    local nama=$1; shift
    : > "$D/srv.out"; : > "$D/srv.err"
    "$D/ssh_interop" "$D/hostkey.der" 1 > "$D/srv.out" 2> "$D/srv.err" &
    local pid=$!
    for _ in $(seq 50); do grep -q '^FP ' "$D/srv.out" && break; sleep 0.1; done
    local port fp
    port=$(sed -n 's/^PORT //p' "$D/srv.out"); fp=$(sed -n 's/^FP //p' "$D/srv.out")
    : > "$D/known_hosts"
    timeout 20 ssh -vvv -F /dev/null -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="$D/known_hosts" -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey \
        -o HostKeyAlgorithms=ecdsa-sha2-nistp256 "$@" uji@127.0.0.1 true > "$D/ssh.log" 2>&1
    wait "$pid" 2>/dev/null
    tr -d '\r' < "$D/ssh.log" > "$D/ssh.log2" && mv "$D/ssh.log2" "$D/ssh.log"
    local ok=1 hasil=""
    grep -Eq 'kex: algorithm: curve25519-sha256(@libssh.org)?$' "$D/ssh.log" || { ok=0; hasil="$hasil kex?"; }
    grep -q 'kex: host key algorithm: ecdsa-sha2-nistp256' "$D/ssh.log" || { ok=0; hasil="$hasil hostkey?"; }
    grep -q "Server host key: ecdsa-sha2-nistp256 $fp" "$D/ssh.log" || { ok=0; hasil="$hasil fingerprint?"; }
    grep -q 'Permission denied (publickey)' "$D/ssh.log" || { ok=0; hasil="$hasil auth?"; }
    grep -Eqi 'Corrupted MAC|message authentication code|Bad packet|connection corrupted|Protocol error|Connection closed by|Connection reset' "$D/ssh.log" && { ok=0; hasil="$hasil galat-protokol?"; }
    grep -Eq "kex: algorithm: ${KEXWANT:-curve25519-sha256}$" "$D/ssh.log" || { ok=0; hasil="$hasil kex-dipilih?"; }
    # strict KEX (Terrapin): urutan pesan dan reset nomor urut di kedua arah (OpenSSH -vvv)
    grep -q 'will use strict KEX ordering' "$D/ssh.log" || { ok=0; hasil="$hasil strict-kex?"; }
    grep -q 'resetting send seqnr 3$' "$D/ssh.log" || { ok=0; hasil="$hasil reset-kirim?"; }
    grep -q 'resetting read seqnr 3$' "$D/ssh.log" || { ok=0; hasil="$hasil reset-baca?"; }
    local n1 n2 n3 n4
    n1=$(grep -n 'SSH2_MSG_KEXINIT received' "$D/ssh.log" | head -1 | cut -d: -f1)
    n2=$(grep -n 'SSH2_MSG_KEX_ECDH_REPLY received' "$D/ssh.log" | head -1 | cut -d: -f1)
    n3=$(grep -n 'SSH2_MSG_NEWKEYS received' "$D/ssh.log" | head -1 | cut -d: -f1)
    n4=$(grep -n 'SSH2_MSG_SERVICE_ACCEPT received' "$D/ssh.log" | head -1 | cut -d: -f1)
    if [ -z "$n1" ] || [ -z "$n2" ] || [ -z "$n3" ] || [ -z "$n4" ] || ! [ "$n1" -lt "$n2" -a "$n2" -lt "$n3" -a "$n3" -lt "$n4" ]; then
        ok=0; hasil="$hasil urutan-pesan?"
    fi
    local ciph; ciph=$(sed -n 's/.*kex: server->client cipher: \([^ ]*\).*/\1/p' "$D/ssh.log" | head -1)
    if [ $ok = 1 ]; then echo "ssh-interop OK    $nama cipher=$ciph fp=$fp"
    else echo "ssh-interop GAGAL $nama ($hasil ) lihat $D/ssh.log $D/srv.err"; fail=1; fi
}
run "bawaan"
KEXWANT=curve25519-sha256 run "aes128-gcm" -c aes128-gcm@openssh.com -o KexAlgorithms=curve25519-sha256
KEXWANT=curve25519-sha256 run "chacha-lalu-gcm" -c chacha20-poly1305@openssh.com,aes128-gcm@openssh.com -o KexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org
KEXWANT=curve25519-sha256@libssh.org run "kex-libssh" -o KexAlgorithms=curve25519-sha256@libssh.org
exit $fail
