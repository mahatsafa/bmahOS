#!/usr/bin/env bash
# Uji asap bmahOS di QEMU (q35 + OVMF, E1000 + AHCI, user networking).
#
# Boot build/bmahOS.iso dengan disk FAT32 sementara berisi KEY.TXT ACAK
# (dibuat ulang tiap jalan, bukan kunci asli), lalu cek log serial dan
# perintah jarak jauh lewat client/bmctl.py. Terakhir mengirim reboot
# berprivilege; QEMU dijalankan dengan -no-reboot sehingga keluar saat reset.
#
# Pakai: make test   (atau tests/qemu-smoke.sh setelah make iso)
# Variabel: QEMU, OVMF_CODE, OVMF_VARS, BMTEST_PORT (default 17778),
#           BMTEST_BOOT_TIMEOUT (detik, default 180)
# Tanpa KVM (TCG) boot lebih lambat, tapi tetap jalan.

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ISO="$ROOT/build/bmahOS.iso"
WORK="$ROOT/build/test"
QEMU="${QEMU:-$(command -v qemu-system-x86_64 2>/dev/null || echo /usr/libexec/qemu-kvm)}"
OVMF_CODE="${OVMF_CODE:-/usr/share/edk2/ovmf/OVMF_CODE.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/edk2/ovmf/OVMF_VARS.fd}"
PORT="${BMTEST_PORT:-17778}"
TPORT="${BMTEST_TCP_PORT:-17007}"   # C4: echo TCP port 7
CPORT="${BMTEST_CLI_PORT:-17779}"   # D1: CLI TCP port 7779
BOOT_TIMEOUT="${BMTEST_BOOT_TIMEOUT:-180}"

PASS=0
FAIL=0
QPID=""

ok()   { echo "PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

cleanup() {
    if [ -n "$QPID" ] && kill -0 "$QPID" 2>/dev/null; then
        kill "$QPID" 2>/dev/null
    fi
}
trap cleanup EXIT

for f in "$ISO" "$OVMF_CODE" "$OVMF_VARS"; do
    [ -f "$f" ] || { echo "tidak ada: $f"; exit 2; }
done
for t in "$QEMU" mkfs.vfat mcopy mtype fsck.fat python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "butuh program: $t"; exit 2; }
done

rm -rf "$WORK"
mkdir -p "$WORK"
LOG="$WORK/serial.log"
KEY="$WORK/KEY.TXT"
DISK="$WORK/disk.img"

python3 -c 'import secrets; print(secrets.token_hex(16), end="")' > "$KEY"
dd if=/dev/zero of="$DISK" bs=1M count=64 status=none
mkfs.vfat -F 32 "$DISK" >/dev/null
mcopy -i "$DISK" "$KEY" ::KEY.TXT
# D4: kunci peran read-only (acak, berbeda dari KEY.TXT).
ROKEY="$WORK/KEYRO.TXT"
python3 -c 'import secrets; print(secrets.token_hex(16), end="")' > "$ROKEY"
mcopy -i "$DISK" "$ROKEY" ::KEYRO.TXT
cp "$OVMF_VARS" "$WORK/vars.fd"

"$QEMU" -machine q35 -m 512M -cpu max \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$WORK/vars.fd" \
    -cdrom "$ISO" \
    -drive id=d0,file="$DISK",format=raw,if=none -device ide-hd,drive=d0,bus=ide.1 \
    -netdev user,id=n0,net=192.168.50.0/24,host=192.168.50.1,hostfwd=udp:127.0.0.1:$PORT-192.168.50.200:7778,hostfwd=tcp:127.0.0.1:$TPORT-192.168.50.200:7,hostfwd=tcp:127.0.0.1:$CPORT-192.168.50.200:7779 \
    -device e1000,netdev=n0 \
    -display none -serial file:"$LOG" -no-reboot \
    >"$WORK/qemu.out" 2>&1 &
QPID=$!

echo "QEMU pid $QPID, menunggu net task (maks ${BOOT_TIMEOUT} s)..."
waited=0
until grep -q "net task dimulai" "$LOG" 2>/dev/null; do
    if ! kill -0 "$QPID" 2>/dev/null; then
        echo "QEMU berhenti sebelum net task jalan:"
        tail -20 "$WORK/qemu.out" "$LOG" 2>/dev/null
        exit 1
    fi
    if [ "$waited" -ge "$BOOT_TIMEOUT" ]; then
        echo "timeout menunggu boot"; tail -20 "$LOG"; exit 1
    fi
    sleep 1
    waited=$((waited + 1))
done
echo "boot selesai dalam ~${waited} s"

BM="python3 $ROOT/client/bmctl.py --key $KEY --host 127.0.0.1 --port $PORT --timeout 10"

# F1.8: CHAL hanya dilayani setelah kolam entropi cukup (build NORDRAND:
# beberapa detik dari jitter). Build NOENTROPY tidak pernah siap.
NOENTROPY=0
if strings "$ROOT/build/kernel.elf" | grep -q "build NOENTROPY"; then
    NOENTROPY=1
fi

check "DRBG self-test PASS (CAVP)"      'grep -aq "DRBG: self-test PASS" "$LOG"'
check "entropi: tolak sebelum siap"     'grep -aq "Entropi: tolak sebelum siap PASS" "$LOG"'

# Kirim CHAL mentah N kali (jeda 60 ms, di bawah batas 20/s per IP).
# Keluaran: satu balasan per baris.
chal() {
    python3 - "$PORT" "$1" <<'PYEOF'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(10)
for _ in range(int(sys.argv[2])):
    s.sendto(b"CHAL", ("127.0.0.1", int(sys.argv[1])))
    print(s.recvfrom(4096)[0].decode().strip())
    time.sleep(0.06)
PYEOF
}

if [ "$NOENTROPY" -eq 1 ]; then
    echo "build NOENTROPY: hanya uji penolakan, lalu selesai"
    sleep 5
    check "NOENTROPY: kolam tidak pernah siap" '! grep -aq "Entropi: siap" "$LOG"'
    check "NOENTROPY: CHAL ditolak" '[ "$(chal 1)" = "ERR: entropi belum cukup, coba lagi" ]'
    check "NOENTROPY: pping gagal tertutup" '! $BM pping 2>/dev/null | grep -q "^ppong"'
    check "tanpa exception/fault di log" \
        '! grep -qiE "EXCEPTION|#GP|#PF|fault|panic|FATAL" "$LOG"'
    echo
    echo "hasil: $PASS lulus, $FAIL gagal (log: $LOG)"
    [ "$FAIL" -eq 0 ]
    exit
fi

waited=0
until grep -aq "Entropi: siap" "$LOG" 2>/dev/null; do
    if [ "$waited" -ge "$BOOT_TIMEOUT" ]; then
        break
    fi
    sleep 1
    waited=$((waited + 1))
done
check "entropi: kolam siap (DRBG ter-seed)" 'grep -aq "Entropi: siap tick=" "$LOG"'
grep -a "Entropi: siap" "$LOG"

# 40 nonce: semua unik, 32 hex, dan proporsi bit 1 di 5120 bit dalam
# 0,45..0,55 (simpangan baku ~0,007; batas ini ~7 sigma).
NONCES="$(chal 40)"
check "nonce: 40 CHAL, semua unik dan 32 hex" \
    '[ "$(echo "$NONCES" | grep -cE "^nonce: [0-9a-f]{32}$")" -eq 40 ] &&
     [ "$(echo "$NONCES" | sort -u | wc -l)" -eq 40 ]'
check "nonce: proporsi bit 1 dalam 0,45..0,55" \
    'echo "$NONCES" | python3 -c "
import sys
b = \"\".join(l.split()[1] for l in sys.stdin if l.startswith(\"nonce: \"))
ones = bin(int(b, 16)).count(\"1\") if b else 0
n = len(b) * 4
print(\"bit 1: %d dari %d\" % (ones, n), file=sys.stderr)
sys.exit(0 if n and 0.45 <= ones / n <= 0.55 else 1)"'
# Batas laju 20 datagram/s per IP sumber (B4) berlaku juga untuk uji ini:
# di QEMU dengan KVM (CI) semua perintah bisa jatuh dalam satu jendela 1 s.
# Jeda > 1 s memulai jendela baru sebelum rangkaian perintah berikutnya.
sleep 1.2
METRICS="$($BM metrics)"   # sekali saja: tiap perintah = 2 datagram dari jatah 20/s
check "metrics entropy_ready=1" 'echo "$METRICS" | grep -q "^entropy_ready=1$"'
check "timer self-test PASS (C3a)" 'grep -aq "^Timer: self-test PASS" "$LOG"'
check "metrics ktimer_fired >= 5"  '[ "$(echo "$METRICS" | sed -n "s/^ktimer_fired=//p")" -ge 5 ]'

check "CPUID: vendor dilaporkan"  'grep -aq "CPU: vendor=[^ ]" "$LOG"'
check "CPUID: semua kunci fitur" 'grep -a "CPU: fitur" "$LOG" | grep -q "rdrand=[01] rdseed=[01] nx=[01] smep=[01] smap=[01] umip=[01] pcid=[01] apic=[01] x2apic=[01] tsc=[01] tsc_invarian=[01] sse2=[01]"'
check "CPUID: nx=1 cocok NX self-test" 'grep -aq "CPU: fitur.* nx=1" "$LOG" && grep -q "NX: self-test PASS" "$LOG"'
check "kprintf self-test PASS"   'grep -aq "kprintf: self-test PASS" "$LOG"'
check "tanpa PANIC/ASSERT gagal" '! grep -aq "PANIC:" "$LOG"'
check "self-test crypto (5 PASS)" '[ "$(grep -v ct_memeq "$LOG" | grep -c "^Crypto: .* PASS")" -eq 5 ]'
check "ct_memeq self-test PASS"  'grep -aq "^Crypto: ct_memeq PASS" "$LOG"'
# F1.9: kode mesin ct_memeq hanya boleh punya satu lompatan bersyarat (ulangan
# loop i < n), tanpa call, dan dipakai auth.o untuk 2 HMAC + 1 nonce.
# Sengaja ketat untuk build tanpa -O: bila CFLAGS diberi -O, gcc menambah
# cabang n == 0 (masih aman) dan cek ini gagal, yang memaksa audit ulang.
CT_ASM="$(objdump -d --no-show-raw-insn --disassemble=ct_memeq "$ROOT/build/kernel.elf" | sed -n "/<ct_memeq>:/,\$p")"
check "ct_memeq: 1 lompatan bersyarat, tanpa call" \
    '[ "$(echo "$CT_ASM" | grep -E "\sj[a-z]+\s" | grep -vc "\sjmp\s")" -eq 1 ] &&
     ! echo "$CT_ASM" | grep -qE "\scall"'
check "auth.o memanggil ct_memeq 7x (D1: + login TCP, D2: + perintah TCP, D4: + login ro, KEYRO)" '[ "$(objdump -dr "$ROOT/build/auth.o" | grep -c "R_X86_64_PLT32.*ct_memeq\|R_X86_64_PC32.*ct_memeq")" -eq 7 ]'
check "PCI-1 menemukan AHCI"     'grep -q "PCI-1: AHCI di" "$LOG"'
check "PCI-1 menemukan E1000"    'grep -q "PCI-1: E1000 di" "$LOG"'
check "KEY.TXT dimuat"           'grep -q "Net-11: kunci dimuat" "$LOG"'
check "D4: KEYRO.TXT dimuat"     'grep -q "D4: kunci read-only dimuat" "$LOG"'
check "reset ACPI terdeteksi"    'grep -q "ACPI-R: reset ACPI siap" "$LOG"'
check "NX self-test (B3)"        'grep -q "NX: self-test PASS" "$LOG"'
check "PMM free/realloc PASS"    'grep -aq "PMM free/realloc test: PASS" "$LOG"'
if ! grep -q "PROD: task uji dilewati" "$LOG"; then
    check "user mode + spawn jalan (hello 2x)" '[ "$(grep -c "^hello" "$LOG")" -eq 2 ]'
fi

check "ping -> pong"             '[ "$($BM ping)" = "pong" ]'
check "uptime"                   '$BM uptime | grep -q "^uptime: "'
check "metrics kunci=nilai"      '$BM metrics | grep -q "^uptime_ticks="'
check "metrics rx_missed/rx_nobuf" '$BM metrics | grep -q "^rx_nobuf="'

# PIT-1: laju tick terhadap jam dinding harus ~100/s (dulu 200/s di QEMU).
tick_now() { $BM metrics | sed -n "s/^uptime_ticks=//p"; }
T0=$(date +%s.%N); U0=$(tick_now); sleep 6; T1=$(date +%s.%N); U1=$(tick_now)
HZ=$(python3 -c "print(round(($U1 - $U0) / ($T1 - $T0)))" 2>/dev/null || echo 0)
echo "info  laju tick: $HZ tick/s"
check "laju tick 85..115 per detik (PIT-1)" '[ "$HZ" -ge 85 ] && [ "$HZ" -le 115 ]'

# C4: echo TCP 1 MB lewat slirp (klien TCP Linux sungguhan), hash harus sama.
ECHO_OUT="$(python3 "$ROOT/tests/tcp-echo.py" 127.0.0.1 "$TPORT" --size 1048576 --timeout 300 2>&1)"
ECHO_RC=$?
echo "info  $ECHO_OUT"
check "C4: echo TCP 1 MB identik (sha256)" '[ "$ECHO_RC" -eq 0 ]'

# D1: login TCP port 7779 (klien socket Linux, kunci uji acak).
LOGIN_OUT="$(python3 "$ROOT/tests/tcp-login.py" 127.0.0.1 "$CPORT" "$KEY" "$ROKEY" 2>&1)"
echo "$LOGIN_OUT" | sed "s/^/info  /"
check "D1: login TCP benar -> OK login" \
    'echo "$LOGIN_OUT" | grep -q "^OK login-benar$"'
check "D2: shell TCP ping/pping/metrics (> 1024 byte), baris diulang -> ERR + ditutup" \
    'echo "$LOGIN_OUT" | grep -q "^OK shell-perintah$"'
check "D2: shell TCP uptime lalu exit -> bye + ditutup" \
    'echo "$LOGIN_OUT" | grep -q "^OK shell-exit$"'
check "D1: hmac atas nonce koneksi lain -> ERR login gagal + ditutup" \
    'echo "$LOGIN_OUT" | grep -q "^OK login-nonce-lain$"'
check "D1: tanpa login 10 s -> ERR login timeout + ditutup" \
    'echo "$LOGIN_OUT" | grep -q "^OK login-timeout$"'
check "D4: sesi read-only: uptime/metrics jalan, pping/reboot ERR peran, kunci admin ditolak" \
    'echo "$LOGIN_OUT" | grep -q "^OK ro-sesi$"'
check "D5: audit admin: login/cmd/tolak-peran; audit gagal: login gagal/timeout/hmac" \
    'echo "$LOGIN_OUT" | grep -q "^OK audit$"'
check "D5: audit dan audit gagal di sesi read-only -> ERR peran read-only" \
    'echo "$LOGIN_OUT" | grep -q "^OK audit-ro$"'

python3 -c 'import secrets; print("x" + secrets.token_hex(16), end="")' > "$WORK/bad.txt"

# D3: bmctl.py --tcp (sekali jalan, interaktif lewat pipa, kunci salah). Jeda
# 2,5 s: sesi yang ditutup server menyisakan TIME_WAIT 2 s (maks 2 per IP).
BMT="python3 $ROOT/client/bmctl.py --tcp --host 127.0.0.1 --port $CPORT --timeout 15"
sleep 2.5
T_OUT="$($BMT --key "$KEY" uptime pping metrics 2>&1)"; T_RC=$?
check "D3: bmctl --tcp uptime pping metrics (satu sesi, rc 0)" \
    '[ "$T_RC" -eq 0 ] && echo "$T_OUT" | grep -q "^uptime: " && echo "$T_OUT" | grep -q "^ppong$" && echo "$T_OUT" | grep -q "^ktimer_cancelled=" && echo "$T_OUT" | grep -q "^bye$"'
sleep 2.5
T_OUT="$(printf 'ping\n\nhelp\n' | $BMT --key "$KEY" 2>&1)"; T_RC=$?
check "D3: bmctl --tcp interaktif (stdin pipa, EOF -> exit)" \
    '[ "$T_RC" -eq 0 ] && echo "$T_OUT" | grep -q "^pong$" && echo "$T_OUT" | grep -q "^perintah: " && echo "$T_OUT" | grep -q "^bye$"'
sleep 2.5
T_OUT="$($BMT --key "$WORK/bad.txt" ping 2>&1)"; T_RC=$?
check "D3: bmctl --tcp kunci salah -> ERR login gagal, rc 1" \
    '[ "$T_RC" -eq 1 ] && echo "$T_OUT" | grep -q "^ERR: login gagal$"'
sleep 2.5
T_OUT="$($BMT --key "$ROKEY" uptime pping 2>&1)"; T_RC=$?
check "D4: bmctl --tcp kunci read-only: uptime jalan, pping ERR peran, rc 1" \
    '[ "$T_RC" -eq 1 ] && echo "$T_OUT" | grep -q "^uptime: " && echo "$T_OUT" | grep -q "^ERR: peran read-only$" && echo "$T_OUT" | grep -q "^bye$"'
check "kunci salah ditolak" \
    'python3 $ROOT/client/bmctl.py --key $WORK/bad.txt --host 127.0.0.1 --port $PORT --timeout 10 ping | grep -q "^ERR: hmac salah"'

# D5: audit lewat UDP (jalur nonce, admin), baris AUDIT di serial tetapi
# tidak di ring log (perintah `log` boleh untuk peran read-only).
sleep 1.2
$BM ping >/dev/null 2>&1
AU_OUT="$($BM audit 2>&1)"
AUF_OUT="$($BM "audit gagal" 2>&1)"
check "D5: UDP audit: perintah udp admin tercatat, terakhir = audit itu sendiri" \
    'echo "$AU_OUT" | head -1 | grep -q "^audit ok: total=" && echo "$AU_OUT" | grep -q " udp admin cmd ping$" && echo "$AU_OUT" | tail -1 | grep -q " udp admin cmd audit$"'
check "D5: UDP audit gagal: hmac salah dari jalur UDP tercatat (kode 5)" \
    'echo "$AUF_OUT" | grep -q " udp none cmd-gagal kode=5$"'
check "D5: baris AUDIT di serial (login, cmd, gagal), tidak di perintah log" \
    'grep -aq "AUDIT #[0-9]* t=[0-9]* .* tcp admin login" "$LOG" && grep -aq "AUDIT #.* udp admin cmd audit" "$LOG" && grep -aq "AUDIT #.* login-gagal kode=5" "$LOG" && ! $BM log | grep -q AUDIT'

# D6: FAT32 tulis lewat shell TCP (admin), UDP, dan penolakan read-only.
# Isi disk diperiksa lagi dari host (fsck.fat, mtype) setelah QEMU keluar,
# dan oleh kernel di boot kedua (qemu-rawnet.py test_fs_persist).
sleep 2.5
FS_OUT="$($BMT --key "$KEY" ls "tulis catatan.txt baris satu" \
    "tambah CATATAN.TXT baris dua" "baca CATATAN.TXT" "tulis KEY.TXT x" "baca KEY.TXT" \
    "tulis A.B.C x" 2>&1)"
echo "$FS_OUT" | sed "s/^/info  fs: /" | head -20
check "D6: ls (fs: mode=tulis) + tulis/tambah/baca CATATAN.TXT lewat TCP" \
    'echo "$FS_OUT" | grep -q "^KEY.TXT 32$" && echo "$FS_OUT" | grep -q "^fs: mode=tulis " && echo "$FS_OUT" | grep -q "^OK CATATAN.TXT ukuran=11$" && echo "$FS_OUT" | grep -q "^OK CATATAN.TXT ukuran=21$" && echo "$FS_OUT" | grep -A2 "^isi CATATAN.TXT ukuran=21:$" | tail -1 | grep -q "^baris dua$"'
check "D6: KEY.TXT dilindungi (tulis/baca), nama bukan 8.3 ditolak" \
    '[ "$(echo "$FS_OUT" | grep -c "^ERR: fs: nama dilindungi$")" -eq 2 ] && echo "$FS_OUT" | grep -q "^ERR: fs: nama bukan 8.3"'
sleep 2.5
FS_ARGS=("tulis PANJANG.TXT")
for i in $(seq 0 127); do
    FS_ARGS+=("tambah PANJANG.TXT $(printf 'baris-%04d-xxxxxxxxxxxxxxxxxxxx' "$i")")
done
FS_ARGS+=("tambah PANJANG.TXT lebih" "baca PANJANG.TXT 4064")
FS_OUT="$($BMT --key "$KEY" "${FS_ARGS[@]}" 2>&1)"
check "D6: 128 baris -> 4096 byte (8 cluster), baris ke-129 ERR melebihi 4096" \
    '[ "$(echo "$FS_OUT" | grep -c "^OK PANJANG.TXT ukuran=")" -eq 129 ] && echo "$FS_OUT" | grep -q "^OK PANJANG.TXT ukuran=4096$" && echo "$FS_OUT" | grep -q "^ERR: fs: file melebihi 4096 byte$" && echo "$FS_OUT" | grep -q "^baris-0127-x*$"'
sleep 2.5
FS_OUT="$($BMT --key "$ROKEY" ls "tulis RO.TXT x" "baca CATATAN.TXT" 2>&1)"
check "D6: read-only: ls/tulis/baca -> ERR peran read-only" \
    '[ "$(echo "$FS_OUT" | grep -c "^ERR: peran read-only$")" -eq 3 ]'
sleep 1.2
FS_U1="$($BM "tulis UDP.TXT dari udp" 2>&1)"
FS_U2="$($BM "baca UDP.TXT" 2>&1)"
check "D6: UDP (jalur nonce) tulis + baca UDP.TXT" \
    '[ "$FS_U1" = "OK UDP.TXT ukuran=9" ] && echo "$FS_U2" | tail -1 | grep -q "^dari udp$"'

# D7: CONFIG.CFG (set/config) + hapus/ganti lewat shell TCP. cli_idle=600
# dibiarkan tersimpan: boot kedua (qemu-rawnet.py test_config) membacanya.
check "D7: serial boot pertama: CONFIG: sumber=bawaan (tidak ada file)" \
    'grep -aq "CONFIG: sumber=bawaan (tidak ada file) cli_idle=300 udp_rate=20 echo=1" "$LOG"'
sleep 2.5
CF_OUT="$($BMT --key "$KEY" config "set cli_idle 600" config "tulis HAPUS.TXT x" \
    "hapus HAPUS.TXT" "tulis GANTI.TXT isi ganti" "ganti GANTI.TXT GANTI2.TXT" \
    "hapus CONFIG.CFG" "set echo 2" 2>&1)"
echo "$CF_OUT" | sed "s/^/info  cfg: /" | head -20
check "D7: config awal default, set cli_idle 600 tersimpan, config sumber=disk" \
    'echo "$CF_OUT" | grep -q "^config: sumber=bawaan (tidak ada file)$" && echo "$CF_OUT" | grep -q "^OK cli_idle=600 (tersimpan)$" && echo "$CF_OUT" | grep -q "^config: sumber=disk$" && echo "$CF_OUT" | grep -q "^cli_idle=600$"'
check "D7: hapus/ganti lewat TCP, CONFIG.CFG dilindungi, set nilai salah ERR" \
    'echo "$CF_OUT" | grep -q "^OK hapus HAPUS.TXT$" && echo "$CF_OUT" | grep -q "^OK ganti GANTI.TXT -> GANTI2.TXT$" && echo "$CF_OUT" | grep -q "^ERR: fs: nama dilindungi$" && echo "$CF_OUT" | grep -qF "ERR: config: format: set echo 0..1|-"'
sleep 2.5
CF_OUT="$($BMT --key "$ROKEY" config "set echo 0" 2>&1)"
check "D7: read-only: config boleh, set -> ERR peran read-only" \
    'echo "$CF_OUT" | grep -q "^config: sumber=disk$" && echo "$CF_OUT" | grep -q "^cli_idle=600$" && echo "$CF_OUT" | grep -q "^ERR: peran read-only$"'

# Replay: datagram yang sama dikirim dua kali, yang kedua harus ditolak.
# Argumen: mode (nonce|counter) dan perintah. Keluaran: "<balasan1>|<balasan2>".
replay() {
    python3 - "$KEY" "$PORT" "$1" "$2" <<'PYEOF'
import hashlib, hmac, socket, sys, time
key = open(sys.argv[1], "rb").read().rstrip(b"\r\n \x00")
addr = ("127.0.0.1", int(sys.argv[2]))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(10)
if sys.argv[3] == "nonce":
    s.sendto(b"CHAL", addr)
    head = s.recvfrom(4096)[0].decode().strip()[len("nonce: "):]
else:
    head = "%d" % int(time.time() * 1000)
msg = "%s %s" % (head, sys.argv[4])
pkt = ("%s %s" % (msg, hmac.new(key, msg.encode(), hashlib.sha256).hexdigest())).encode()
out = []
for _ in range(2):
    s.sendto(pkt, addr)
    out.append(s.recvfrom(4096)[0].decode().strip())
print("|".join(out))
PYEOF
}

REPLAY="$(replay nonce ping)"
check "replay jalur nonce ditolak" \
    '[ "${REPLAY%%|*}" = "pong" ] && [ "${REPLAY#*|}" = "ERR: nonce tidak dikenal atau sudah dipakai" ]'

REPLAY="$(replay counter ping)"
if strings "$ROOT/build/kernel.elf" | grep -q "jalur counter dimatikan"; then
    check "jalur counter dimatikan (B2)" \
        '[ "${REPLAY%%|*}" = "ERR: jalur counter dimatikan; kirim CHAL lalu <nonce> <perintah> <hmac>" ]'
else
    check "replay jalur counter ditolak (LEGACYCTR)" \
        '[ "${REPLAY%%|*}" = "pong" ] && [ "${REPLAY#*|}" = "ERR: counter replay" ]'
fi

sleep 1.2   # jendela batas laju baru (lihat di atas)
check "pping -> ppong"           '[ "$($BM pping)" = "ppong" ]'
check "reboot diterima"          '[ "$($BM reboot)" = "reboot: dimulai" ]'

for _ in $(seq 1 30); do
    kill -0 "$QPID" 2>/dev/null || break
    sleep 1
done
check "mesin reset (QEMU keluar)" '! kill -0 "$QPID" 2>/dev/null'
# Kalau reboot gagal, QEMU pertama masih memegang disk.img dan boot kedua
# akan gagal ikut; matikan supaya tahap berikutnya berdiri sendiri.
if kill -0 "$QPID" 2>/dev/null; then
    kill "$QPID" 2>/dev/null
    wait "$QPID" 2>/dev/null
fi
check "reboot lewat reset ACPI"   'grep -q "ACPI-R: reboot via register reset FADT" "$LOG" && ! grep -q "lanjut 8042" "$LOG"'

check "tanpa exception/fault di log" \
    '! grep -qiE "EXCEPTION|#GP|#PF|fault|panic|FATAL" "$LOG"'

# D6: disk setelah boot pertama (QEMU sudah keluar) dibaca dari host.
printf 'baris satu\nbaris dua\n' > "$WORK/catatan.want"
for i in $(seq 0 127); do printf 'baris-%04d-xxxxxxxxxxxxxxxxxxxx\n' "$i"; done > "$WORK/panjang.want"
check "D6: fsck.fat -n bersih setelah tulis (FAT, dir, FSInfo)" \
    'fsck.fat -n "$DISK" >"$WORK/fsck.out" 2>&1'
check "D6: mtype dari host = isi yang ditulis kernel; KEY.TXT tidak berubah" \
    'mtype -i "$DISK" ::CATATAN.TXT | cmp -s - "$WORK/catatan.want" && mtype -i "$DISK" ::PANJANG.TXT | cmp -s - "$WORK/panjang.want" && mtype -i "$DISK" ::KEY.TXT | cmp -s - "$KEY"'
printf '# bmahOS CONFIG.CFG (ditulis oleh perintah set)\ncli_idle=600\nudp_rate=20\necho=1\n' \
    > "$WORK/config.want"
check "D7: mtype CONFIG.CFG kanonik; CONFIG.TMP/HAPUS.TXT/GANTI.TXT tidak ada; GANTI2.TXT ada" \
    'mtype -i "$DISK" ::CONFIG.CFG | cmp -s - "$WORK/config.want" && ! mtype -i "$DISK" ::CONFIG.TMP >/dev/null 2>&1 && ! mtype -i "$DISK" ::HAPUS.TXT >/dev/null 2>&1 && ! mtype -i "$DISK" ::GANTI.TXT >/dev/null 2>&1 && [ "$(mtype -i "$DISK" ::GANTI2.TXT)" = "isi ganti" ]'

# Tahap 2: boot kedua dengan frame Ethernet mentah (lihat tests/qemu-rawnet.py).
echo
echo "boot kedua: uji frame mentah (-netdev dgram)..."
RAW_OUT="$(python3 "$ROOT/tests/qemu-rawnet.py" --qemu "$QEMU" \
    --ovmf-code "$OVMF_CODE" --ovmf-vars "$OVMF_VARS" --iso "$ISO" \
    --disk "$DISK" --key "$KEY" --work "$WORK" --boot-timeout "$BOOT_TIMEOUT")"
RAW_RC=$?
echo "$RAW_OUT"
PASS=$((PASS + $(echo "$RAW_OUT" | grep -c '^PASS')))
FAIL=$((FAIL + $(echo "$RAW_OUT" | grep -c '^FAIL')))
if [ "$RAW_RC" -ne 0 ] && ! echo "$RAW_OUT" | grep -q '^FAIL'; then
    bad "qemu-rawnet.py keluar dengan kode $RAW_RC"
fi
# D7: boot kedua menulis CONFIG.CFG lewat UDP (set echo/udp_rate, dikembalikan).
check "D7: setelah boot kedua: fsck.fat -n bersih, CONFIG.CFG kanonik" \
    'fsck.fat -n "$DISK" >"$WORK/fsck2.out" 2>&1 && mtype -i "$DISK" ::CONFIG.CFG | cmp -s - "$WORK/config.want" && ! mtype -i "$DISK" ::CONFIG.TMP >/dev/null 2>&1'

# Tahap 3: boot tanpa NIC dan tanpa disk (seperti hardware tanpa driver yang
# cocok). Kernel harus melewati driver yang tidak ada tanpa exception.
echo
echo "boot ketiga: tanpa NIC dan tanpa disk..."
BARE="$WORK/serial-bare.log"
cp "$OVMF_VARS" "$WORK/vars-bare.fd"
timeout "$BOOT_TIMEOUT" "$QEMU" -machine q35 -m 512M -cpu max \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$WORK/vars-bare.fd" \
    -cdrom "$ISO" -nic none -display none -serial file:"$BARE" -no-reboot \
    >"$WORK/qemu-bare.out" 2>&1 &
BPID=$!
for _ in $(seq 1 "$BOOT_TIMEOUT"); do
    grep -q "RX belum di-init, net task berhenti" "$BARE" 2>/dev/null && break
    kill -0 "$BPID" 2>/dev/null || break
    sleep 1
done
sleep 2
kill "$BPID" 2>/dev/null
wait "$BPID" 2>/dev/null
check "tanpa NIC: E1000 dilewati"      'grep -q "PCI-1: E1000 tidak ditemukan" "$BARE"'
check "tanpa NIC: net task berhenti rapi" 'grep -q "RX belum di-init, net task berhenti" "$BARE"'
check "tanpa NIC: tanpa exception"     '! grep -qE "EXCEPTION|#GP|#PF|panic|FATAL -" "$BARE"'
check "D7: tanpa disk: CONFIG: sumber=bawaan (tanpa disk)" \
    'grep -q "CONFIG: sumber=bawaan (tanpa disk) cli_idle=300 udp_rate=20 echo=1" "$BARE"'

echo
echo "hasil: $PASS lulus, $FAIL gagal (log: $LOG)"
[ "$FAIL" -eq 0 ]
