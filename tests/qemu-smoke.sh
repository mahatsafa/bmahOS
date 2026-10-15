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
SPORT="${BMTEST_TLS_PORT:-17780}"   # D9: CLI TLS port 7780
NCPORT="${BMTEST_NETCON_PORT:-17666}"   # R2: penerima netconsole (slirp .1 -> 127.0.0.1)
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
for t in "$QEMU" mkfs.vfat mcopy mtype fsck.fat python3 openssl; do
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
# D9: identitas TLS acak per jalan (kunci EC P-256 + sertifikat self-signed).
openssl ecparam -name prime256v1 -genkey -noout -outform DER -out "$WORK/TLSKEY.DER" 2>/dev/null
openssl req -new -x509 -key "$WORK/TLSKEY.DER" -keyform DER -days 3650 \
    -subj /CN=bmahOS-uji -outform DER -out "$WORK/TLSCERT.DER" 2>/dev/null
mcopy -i "$DISK" "$WORK/TLSKEY.DER" ::TLSKEY.DER
mcopy -i "$DISK" "$WORK/TLSCERT.DER" ::TLSCERT.DER
TLSPIN="$(sha256sum "$WORK/TLSCERT.DER" | cut -d" " -f1)"
cp "$OVMF_VARS" "$WORK/vars.fd"

"$QEMU" -machine q35 -m 512M -cpu max \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$WORK/vars.fd" \
    -cdrom "$ISO" \
    -drive id=d0,file="$DISK",format=raw,if=none -device ide-hd,drive=d0,bus=ide.1 \
    -netdev user,id=n0,net=192.168.50.0/24,host=192.168.50.1,hostfwd=udp:127.0.0.1:$PORT-192.168.50.200:7778,hostfwd=tcp:127.0.0.1:$TPORT-192.168.50.200:7,hostfwd=tcp:127.0.0.1:$CPORT-192.168.50.200:7779,hostfwd=tcp:127.0.0.1:$SPORT-192.168.50.200:7780 \
    -object filter-dump,id=fd0,netdev=n0,file="$WORK/net.pcap" \
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
# D9a: BearSSL freestanding: tanpa instruksi SSE (register xmm/ymm/zmm) dan
# hanya butuh memcpy/memmove/memset/memcmp/strlen dari luar pustaka.
BLIB="$ROOT/build/libbearssl.a"
check "D9a: libbearssl.a tanpa instruksi SSE" \
    '[ -s "$BLIB" ] && ! objdump -d "$BLIB" | grep -qE "%[xyz]mm[0-9]"'
check "D9a: libbearssl.a hanya butuh mem*/strlen dari luar" \
    '[ -s "$BLIB" ] && [ "$(nm -u "$BLIB" | awk "/ U /{print \$2}" | grep -v "^br_" |
       sort -u | tr "\n" " ")" = "memcmp memcpy memmove memset strlen " ]'
check "PCI-1 menemukan AHCI"     'grep -q "PCI-1: AHCI di" "$LOG"'
check "PCI-1 menemukan E1000"    'grep -q "PCI-1: E1000 di" "$LOG"'
check "KEY.TXT dimuat"           'grep -q "Net-11: kunci dimuat" "$LOG"'
check "D4: KEYRO.TXT dimuat"     'grep -q "D4: kunci read-only dimuat" "$LOG"'
check "reset ACPI terdeteksi"    'grep -q "ACPI-R: reset ACPI siap" "$LOG"'
check "NX self-test (B3)"        'grep -q "NX: self-test PASS" "$LOG"'
check "TSS-1: iopb_offset=0x68 (I/O ring 3 ditolak)" 'grep -q "TSS-1: iopb_offset=0x68 (tanpa peta I/O)" "$LOG"'
check "PMM free/realloc PASS"    'grep -aq "PMM free/realloc test: PASS" "$LOG"'
if ! grep -q "PROD: task uji dilewati" "$LOG"; then
    check "user mode + spawn jalan (hello 2x)" '[ "$(grep -c "^hello" "$LOG")" -eq 2 ]'
else
    # R1: perintah uji panic tidak ada di build PROD (dicek di biner; mengirimnya
    # akan menaruh "cmd panic pf" di baris AUDIT dan memicu grep "panic").
    check "R1: PROD: tanpa kode uji panic (simbol + string)" \
        '! nm "$ROOT/build/kernel.elf" | grep -q panic_test_ && ! strings "$ROOT/build/kernel.elf" | grep -q "panic: uji"'
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

# R3: registry metrik. Halaman <= 1400 byte diakhiri metrics_lanjut=<i>;
# bmctl mengikuti halaman; awalan; argumen salah; CPU/memori/uptime.
R3_N=97
sleep 1.2
R3_P1="$($BM "metrics 0")"   # mulai eksplisit: bmctl tidak mengikuti halaman
R3_ALL="$($BM metrics)"
check "R3: metrics halaman 1 <= 1400 byte, baris akhir metrics_lanjut=" \
    '[ "$(printf "%s\n" "$R3_P1" | wc -c)" -le 1400 ] && echo "$R3_P1" | tail -1 | grep -q "^metrics_lanjut=[0-9]*$"'
check "R3: bmctl metrics (UDP) ikuti halaman: $R3_N kunci unik, akhir audit_seq" \
    '[ "$(echo "$R3_ALL" | grep -c "^[a-z0-9_]*=[0-9]*$")" -eq $R3_N ] && [ "$(echo "$R3_ALL" | cut -d= -f1 | sort -u | wc -l)" -eq $R3_N ] && ! echo "$R3_ALL" | grep -q "^metrics_lanjut=" && echo "$R3_ALL" | tail -1 | grep -q "^audit_seq="'
r3v() { echo "$R3_ALL" | sed -n "s/^$1=//p"; }
echo "info  R3: cpu_busy_pct=$(r3v cpu_busy_pct) cpu_idle_ticks=$(r3v cpu_idle_ticks) uptime_ticks=$(r3v uptime_ticks) mem_total_kb=$(r3v mem_total_kb) mem_free_kb=$(r3v mem_free_kb) stack_net_used=$(r3v stack_net_used)"
check "R3: cpu_busy_pct 0..100, mem_free_kb < mem_total_kb, uptime_s ~ uptime_ticks/100, heap_used <= heap_mapped" \
    '[ "$(r3v cpu_busy_pct)" -le 100 ] && [ "$(r3v mem_free_kb)" -lt "$(r3v mem_total_kb)" ] && [ "$(r3v uptime_s)" -ge $(( $(r3v uptime_ticks) / 100 )) ] && [ "$(r3v uptime_s)" -le $(( $(r3v uptime_ticks) / 100 + 5 )) ] && [ "$(r3v heap_used)" -le "$(r3v heap_mapped)" ]'
if grep -q "PROD: task uji dilewati" "$LOG"; then
    check "R3: PROD: task idle terukur (cpu_idle_ticks > separuh uptime_ticks)" \
        '[ $(( $(r3v cpu_idle_ticks) * 2 )) -gt "$(r3v uptime_ticks)" ]'
fi
check "R3: kunci baru: stack_net_used > 0, tls_hs_ok dan netcon_sent ada" \
    '[ "$(r3v stack_net_used)" -gt 0 ] && [ -n "$(r3v tls_hs_ok)" ] && [ -n "$(r3v netcon_sent)" ]'
sleep 1.2
R3_TCP="$($BM "metrics tcp_")"
check "R3: metrics tcp_ (awalan): 20 kunci, semua tcp_" \
    '[ "$(echo "$R3_TCP" | grep -c "^tcp_[a-z_]*=[0-9]*$")" -eq 20 ] && [ "$(echo "$R3_TCP" | wc -l)" -eq 20 ]'
check "R3: metrics argumen salah -> ERR, awalan tanpa kunci -> ERR" \
    '$BM "metrics TCP" | grep -q "^ERR: metrics \[awalan\] \[mulai\]$" && $BM "metrics zzz" | grep -q "^ERR: metrics: tidak ada kunci yang cocok$"'

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

# D9: CLI TLS port 7780 (Python ssl/OpenSSL), pin = sha256 sertifikat uji.
check "D9: serial: TLS aktif port 7780, pin = sha256 TLSCERT.DER" \
    'grep -aq "TLS: aktif port 7780 pin=$TLSPIN" "$LOG"'
sleep 2.5
TLS_OUT="$(python3 "$ROOT/tests/tls-login.py" 127.0.0.1 "$SPORT" "$KEY" "$ROKEY" \
    "$WORK/TLSCERT.DER" 2>&1)"
echo "$TLS_OUT" | sed "s/^/info  /"
check "D9: TLS AES-128-GCM: login, uptime, metrics > 1 KB, tls (pin, sesi), exit" \
    'echo "$TLS_OUT" | grep -q "^OK aes$"'
check "D9: TLS ChaCha20-Poly1305: login + ping" 'echo "$TLS_OUT" | grep -q "^OK chacha$"'
check "D9: TLS kunci read-only: uptime jalan, pping ERR peran" \
    'echo "$TLS_OUT" | grep -q "^OK ro$"'
check "D9: pin salah -> klien berhenti sebelum kirim data" \
    'echo "$TLS_OUT" | grep -q "^OK pin-salah$"'
check "D9: hmac salah lewat TLS -> ERR login gagal + ditutup" \
    'echo "$TLS_OUT" | grep -q "^OK hmac-salah$"'
check "D9: klien TLS 1.3 saja ditolak (hanya TLS 1.2)" \
    'echo "$TLS_OUT" | grep -q "^OK tls13-ditolak$"'
check "D9: teks polos ke 7780 tidak dilayani" \
    'echo "$TLS_OUT" | grep -q "^OK teks-polos-ditolak$"'
sleep 1.2
TLS_ST="$($BM tls 2>&1)"
echo "$TLS_ST" | sed "s/^/info  tls: /"
STK="$(echo "$TLS_ST" | sed -n "s/^stack_net: terpakai_maks=\([0-9]*\) dari 32768$/\1/p")"
check "D9: UDP tls: aktif, ok >= 5, gagal >= 1, stack net task < 24 KB dari 32 KB" \
    'echo "$TLS_ST" | grep -q "^tls: aktif port 7780$" && echo "$TLS_ST" | grep -q "^pin: $TLSPIN$" && [ "$(echo "$TLS_ST" | sed -n "s/.* ok=\([0-9]*\) gagal=\([0-9]*\) .*/\1/p")" -ge 5 ] && [ "$(echo "$TLS_ST" | sed -n "s/.* gagal=\([0-9]*\) .*/\1/p")" -ge 1 ] && [ -n "$STK" ] && [ "$STK" -lt 24576 ]'
check "D9: pcap: payload 7780 tanpa teks polos (banner, login, perintah, keluaran)" \
    'python3 "$ROOT/tests/pcap-check.py" "$WORK/net.pcap" 7780 "bmahOS login" "nonce:" "OK login" "uptime" "metrics" "END " "tcp_rx=" "pong"'
check "D9: pcap kontrol: payload 7779 memuat teks polos (penangkapan bekerja)" \
    '! python3 "$ROOT/tests/pcap-check.py" "$WORK/net.pcap" 7779 "bmahOS login" >/dev/null'
check "D9: AUDIT di serial: login lewat tls" 'grep -aq "AUDIT #.* tls admin login" "$LOG"'

# D9c: bmctl.py --tls (pin dari file; pin salah -> rc 2 tanpa login).
echo "$TLSPIN" > "$WORK/tlspin.txt"
BMS="python3 $ROOT/client/bmctl.py --tls --host 127.0.0.1 --port $SPORT --timeout 20"
sleep 2.5
S_OUT="$($BMS --pin "$WORK/tlspin.txt" --key "$KEY" uptime pping 2>&1)"; S_RC=$?
check "D9c: bmctl --tls --pin file: uptime pping, rc 0" \
    '[ "$S_RC" -eq 0 ] && echo "$S_OUT" | grep -q "^uptime: " && echo "$S_OUT" | grep -q "^ppong$" && echo "$S_OUT" | grep -q "^bye$"'
sleep 2.5
S_OUT="$($BMS --pin "$(printf "%064d" 0)" --key "$KEY" uptime 2>&1)"; S_RC=$?
check "D9c: bmctl --tls pin salah -> rc 2, tanpa login" \
    '[ "$S_RC" -eq 2 ] && echo "$S_OUT" | grep -q "pin sertifikat beda: server $TLSPIN" && ! echo "$S_OUT" | grep -q "^uptime"'
S_OUT="$($BMS --key "$KEY" uptime 2>&1)"; S_RC=$?
check "D9c: bmctl --tls tanpa pin -> rc 2" \
    '[ "$S_RC" -eq 2 ] && echo "$S_OUT" | grep -q "butuh --pin"'
sleep 2.5
S_OUT="$($BMS --pin "$WORK/tlspin.txt" --key "$ROKEY" metrics "metrics cpu_" 2>&1)"; S_RC=$?
check "R3: bmctl --tls kunci read-only: metrics lengkap ($R3_N kunci) + metrics cpu_, rc 0" \
    '[ "$S_RC" -eq 0 ] && [ "$(echo "$S_OUT" | grep -c "^[a-z0-9_]*=[0-9]*$")" -eq $(( R3_N + 2 )) ] && [ "$(echo "$S_OUT" | grep -c "^cpu_busy_pct=")" -eq 2 ] && [ "$(echo "$S_OUT" | grep -c "^tls_sess_active=1$")" -eq 1 ] && ! echo "$S_OUT" | grep -q "^metrics_lanjut=" && echo "$S_OUT" | grep -q "^bye$"'


python3 -c 'import secrets; print("x" + secrets.token_hex(16), end="")' > "$WORK/bad.txt"

# D3: bmctl.py --tcp (sekali jalan, interaktif lewat pipa, kunci salah). Jeda
# 2,5 s: sesi yang ditutup server menyisakan TIME_WAIT 2 s (maks 2 per IP).
BMT="python3 $ROOT/client/bmctl.py --tcp --host 127.0.0.1 --port $CPORT --timeout 15"
sleep 2.5
T_OUT="$($BMT --key "$KEY" uptime pping metrics 2>&1)"; T_RC=$?
check "D3: bmctl --tcp uptime pping metrics (satu sesi, rc 0)" \
    '[ "$T_RC" -eq 0 ] && echo "$T_OUT" | grep -q "^uptime: " && echo "$T_OUT" | grep -q "^ppong$" && echo "$T_OUT" | grep -q "^ktimer_cancelled=" && echo "$T_OUT" | grep -q "^bye$"'
check "R3: bmctl --tcp metrics semua halaman: $R3_N kunci, cli_sess_active=1" \
    '[ "$(echo "$T_OUT" | grep -c "^[a-z0-9_]*=[0-9]*$")" -eq $R3_N ] && echo "$T_OUT" | grep -q "^cli_sess_active=1$" && ! echo "$T_OUT" | grep -q "^metrics_lanjut="'
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

# D9d: cli_plain=0 (7779 RST) dan udp_admin=0 (UDP hanya baca) diatur lewat
# TLS, lalu dikembalikan ke bawaan untuk uji berikutnya.
sleep 2.5
D_OUT="$($BMS --pin "$WORK/tlspin.txt" --key "$KEY" "set cli_plain 0" "set udp_admin 0" 2>&1)"
sleep 2.5
P_OUT="$($BMT --key "$KEY" uptime 2>&1)"; P_RC=$?
echo "info  D9d 7779: rc=$P_RC $P_OUT"
sleep 1.2
U_PP="$($BM pping 2>&1)"
U_UP="$($BM uptime 2>&1)"
sleep 2.5
R_OUT="$($BMS --pin "$WORK/tlspin.txt" --key "$KEY" "set cli_plain -" "set udp_admin -" \
    config 2>&1)"
check "D9d: set cli_plain 0 + udp_admin 0 lewat TLS tersimpan" \
    'echo "$D_OUT" | grep -q "^OK cli_plain=0 (tersimpan)$" && echo "$D_OUT" | grep -q "^OK udp_admin=0 (tersimpan)$"'
check "D9d: cli_plain=0 -> bmctl --tcp 7779 gagal terhubung (rc 2)" \
    '[ "$P_RC" -eq 2 ] && ! echo "$P_OUT" | grep -q "^uptime"'
check "D9d: udp_admin=0 -> UDP pping ERR, UDP uptime jalan" \
    '[ "$U_PP" = "ERR: udp_admin=0: hanya perintah baca lewat UDP (pakai TLS 7780)" ] && echo "$U_UP" | grep -q "^uptime: "'
check "D9d: dikembalikan lewat TLS: cli_plain=1 udp_admin=1" \
    'echo "$R_OUT" | grep -q "^cli_plain=1$" && echo "$R_OUT" | grep -q "^udp_admin=1$"'

# R2: netconsole ke 192.168.50.1:$NCPORT (slirp -> 127.0.0.1), lalu dikembalikan
# ke bawaan (netcon=0) supaya CONFIG.CFG kanonik dan boot kedua tidak terpengaruh.
NCLOG="$WORK/netcon1.bin"
: > "$NCLOG"
python3 "$ROOT/tests/netcon-listen.py" "$NCPORT" "$NCLOG" 30 &
NCPID=$!
sleep 2.5
NC_ON="$($BMS --pin "$WORK/tlspin.txt" --key "$KEY" "set netcon_port $NCPORT" "set netcon 1" \
    2>&1)"
sleep 3
NC_ST="$($BMS --pin "$WORK/tlspin.txt" --key "$KEY" netcon "set netcon -" "set netcon_port -" \
    2>&1)"
sleep 1
kill "$NCPID" 2>/dev/null
wait "$NCPID" 2>/dev/null
echo "$NC_ST" | sed "s/^/info  R2: /"
echo "info  R2: diterima $(wc -c < "$NCLOG") byte netconsole"
check "R2: serial: netcon siap (bawaan nonaktif, tujuan .1:6666)" \
    'grep -aq "R2: netcon siap aktif=0 tujuan=192.168.50.1:6666" "$LOG"'
check "R2: set netcon lewat TLS, status aktif + MAC slirp, kembali ke bawaan" \
    'echo "$NC_ON" | grep -q "^OK netcon=1 (tersimpan)$" && echo "$NC_ST" | grep -q "^netcon: aktif=1 tujuan=192.168.50.1:$NCPORT port_sumber=6665$" && echo "$NC_ST" | grep -q "^netcon: mac=[0-9a-f:]\{17\} arp=[1-9]" && echo "$NC_ST" | grep -q "^OK netcon=0 (tersimpan)$" && echo "$NC_ST" | grep -q "^OK netcon_port=6666 (tersimpan)$"'
check "R2: penerima UDP host dapat baris log (MAC tujuan, TLS handshake)" \
    'grep -aq "^R2: netcon MAC tujuan 192.168.50.1 = [0-9a-f:]\{17\}$" "$NCLOG" && grep -aq "^D9: TLS handshake OK" "$NCLOG"'

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
printf '# bmahOS CONFIG.CFG (ditulis oleh perintah set)\ncli_idle=600\nudp_rate=20\necho=1\ncli_plain=1\nudp_admin=1\nnetcon=0\nnetcon_host=1\nnetcon_port=6666\n' \
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
check "D9: tanpa disk: TLS nonaktif" 'grep -q "TLS: nonaktif (TLSKEY.DER tidak ada)" "$BARE"'

# R1: panic handler (build dev saja). Satu QEMU TANPA -no-reboot: panic pf ->
# reboot otomatis -> panic df (RSP rusak, harus lewat IST1) -> reboot -> panic
# assert -> reboot. Log serial berlanjut melewati reset.
if ! grep -q "PROD: task uji dilewati" "$LOG"; then
    echo
    echo "boot keempat: uji panic pf/df/assert (~2 menit)..."
    PLOG="$WORK/serial-panic.log"
    cp "$OVMF_VARS" "$WORK/vars-panic.fd"
    "$QEMU" -machine q35 -m 512M -cpu max \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
        -drive if=pflash,format=raw,file="$WORK/vars-panic.fd" \
        -cdrom "$ISO" \
        -drive id=d0,file="$DISK",format=raw,if=none -device ide-hd,drive=d0,bus=ide.1 \
        -netdev user,id=n0,net=192.168.50.0/24,host=192.168.50.1,hostfwd=udp:127.0.0.1:$PORT-192.168.50.200:7778 \
        -device e1000,netdev=n0 \
        -display none -serial file:"$PLOG" \
        >"$WORK/qemu-panic.out" 2>&1 &
    PQPID=$!
    # wait_n POLA N: tunggu sampai POLA muncul >= N kali di PLOG; 0 = berhasil.
    wait_n() {
        for _ in $(seq 1 "$BOOT_TIMEOUT"); do
            c="$(grep -ac "$1" "$PLOG" 2>/dev/null)"
            [ "${c:-0}" -ge "$2" ] && return 0
            kill -0 "$PQPID" 2>/dev/null || return 1
            sleep 1
        done
        return 1
    }
    PANIC_REPLY=""
    PANIC_WAIT=""
    # R2: netcon=1 tersimpan di disk -> berlaku juga setelah tiap reboot.
    PNCLOG="$WORK/netcon-panic.bin"
    : > "$PNCLOG"
    python3 "$ROOT/tests/netcon-listen.py" "$NCPORT" "$PNCLOG" 600 &
    PNCPID=$!
    if wait_n "Entropi: siap" 1 && wait_n "net task dimulai" 1; then
        sleep 1
        PNC_SET="$($BM "set netcon_port $NCPORT" 2>&1)"
        sleep 1.2
        PNC_SET="$PNC_SET $($BM "set netcon 1" 2>&1)"
    fi
    i=0
    for kind in pf df assert; do
        i=$((i + 1))
        wait_n "Entropi: siap" "$i" || break
        wait_n "net task dimulai" "$i" || break
        sleep 1
        PANIC_REPLY="$PANIC_REPLY$($BM "panic $kind" 2>&1)
"
        wait_n "PANIC: reboot otomatis dalam 10 detik" "$i" || break
        t0=$(date +%s)
        wait_n "ACPI-R: reboot via register reset FADT" "$i" || break
        PANIC_WAIT="$PANIC_WAIT $(($(date +%s) - t0))"
    done
    wait_n "PCI-1: E1000 di" 4
    kill "$PQPID" 2>/dev/null
    wait "$PQPID" 2>/dev/null
    kill "$PNCPID" 2>/dev/null
    wait "$PNCPID" 2>/dev/null
    echo "info  R2: netconsole panic $(wc -c < "$PNCLOG") byte, set: $PNC_SET"
    tr -d '\r' < "$PLOG" > "$WORK/serial-panic.txt"
    "$ROOT/tools/symbolize.sh" "$PLOG" > "$WORK/panic-sym.txt" 2>&1 || true
    echo "balasan:"; echo "$PANIC_REPLY"
    echo "jeda panic -> reboot (s):$PANIC_WAIT"
    grep -a "^PANIC" "$WORK/serial-panic.txt" | head -20
    cat "$WORK/panic-sym.txt"
    P="$WORK/serial-panic.txt"
    check "R1: balasan perintah panic (pf, df, assert)" \
        '[ "$(echo "$PANIC_REPLY" | grep -c "^panic: uji \(pf\|df\|assert\) dalam 1 detik$")" -eq 3 ]'
    check "R1: 4 boot (3 reboot otomatis setelah panic)" '[ "$(grep -c "PCI-1: E1000 di" "$P")" -eq 4 ]'
    check "R1: pf: #PF page fault error=0x2 [tidak-ada tulis kernel], CR2=0" \
        'grep -q "^PANIC: exception #PF page fault (vektor 14) error=0x2 \[tidak-ada tulis kernel\]$" "$P" && grep -q "^PANIC: CR0=0x[0-9a-f]* CR2=0x0000000000000000 " "$P"'
    check "R1: pf: mode kernel, stack biasa, register lengkap" \
        'grep -q "^PANIC: RIP=0xffffffff8.* CS=0x8 .* mode=kernel$" "$P" && grep -q "^PANIC: RSP=.* stack=biasa$" "$P" && grep -q "^PANIC: R13=0x.* R15=0x" "$P"'
    check "R1: df: #DF double fault lewat IST1" \
        'grep -q "^PANIC: exception #DF double fault (vektor 8) error=0x0$" "$P" && grep -q "^PANIC: RSP=.* stack=IST1$" "$P"'
    check "R1: assert: baris ASSERT + trace" \
        'grep -q "^PANIC: ASSERT gagal: g_panic_test_kind != 3 di kernel/panic.c:[0-9]* (panic_test_assert)$" "$P"'
    check "R1: trace 3x (>= 4 frame)" \
        '[ "$(grep -c "^PANIC: trace \([4-9]\|1[0-6]\) frame (" "$P")" -eq 3 ]'
    check "R1: symbolize: pemicu -> panic_test_fire -> ktimer_run" \
        'grep -q "^#0 .* panic_test_pf " "$WORK/panic-sym.txt" && grep -q "^#0 .* panic_test_df " "$WORK/panic-sym.txt" && grep -q "^#1 .* panic_test_assert " "$WORK/panic-sym.txt" && [ "$(grep -c " panic_test_fire " "$WORK/panic-sym.txt")" -eq 3 ] && [ "$(grep -c " ktimer_run " "$WORK/panic-sym.txt")" -eq 3 ]'
    # Jeda tiap panic harus 9..13 s (PANIC_REBOOT_S 10 + reset ACPI).
    panic_wait_ok() {
        [ "$#" -eq 3 ] || return 1
        for w in "$@"; do
            [ "$w" -ge 9 ] && [ "$w" -le 13 ] || return 1
        done
    }
    check "R1: reboot setelah ~10 s (3x 9..13 s)" 'panic_wait_ok $PANIC_WAIT'
    check "R2: set netcon 1 lewat UDP sebelum panic" \
        'echo "$PNC_SET" | grep -q "OK netcon_port=$NCPORT (tersimpan)" && echo "$PNC_SET" | grep -q "OK netcon=1 (tersimpan)"'
    check "R2: dump panic pf/df/assert lewat netconsole (3x), tanpa register umum" \
        'grep -aq "^PANIC: exception #PF page fault (vektor 14) error=0x2" "$PNCLOG" && grep -aq "^PANIC: exception #DF double fault (vektor 8)" "$PNCLOG" && grep -aq "^PANIC: ASSERT gagal: g_panic_test_kind != 3" "$PNCLOG" && [ "$(grep -ac "^PANIC: reboot otomatis dalam 10 detik$" "$PNCLOG")" -eq 3 ] && [ "$(grep -ac "^PANIC: trace #0 " "$PNCLOG")" -eq 2 ] && grep -aq "^PANIC: RIP=" "$PNCLOG" && ! grep -aqE "^PANIC: (RAX|RSI|R9|R13)=" "$PNCLOG"'
    check "R1: tanpa panic bersarang / PIT macet" \
        '! grep -qE "fault di dalam panic handler|PIT tidak berjalan|PANIC-UJI" "$P"'
fi

echo
echo "hasil: $PASS lulus, $FAIL gagal (log: $LOG)"
[ "$FAIL" -eq 0 ]
