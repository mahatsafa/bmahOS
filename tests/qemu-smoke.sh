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
for t in "$QEMU" mkfs.vfat mcopy python3; do
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
cp "$OVMF_VARS" "$WORK/vars.fd"

"$QEMU" -machine q35 -m 512M -cpu max \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$WORK/vars.fd" \
    -cdrom "$ISO" \
    -drive id=d0,file="$DISK",format=raw,if=none -device ide-hd,drive=d0,bus=ide.1 \
    -netdev user,id=n0,net=192.168.50.0/24,host=192.168.50.1,hostfwd=udp:127.0.0.1:$PORT-192.168.50.200:7778 \
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

check "self-test crypto (5 PASS)" '[ "$(grep -c "^Crypto: .* PASS" "$LOG")" -eq 5 ]'
check "PCI-1 menemukan AHCI"     'grep -q "PCI-1: AHCI di" "$LOG"'
check "PCI-1 menemukan E1000"    'grep -q "PCI-1: E1000 di" "$LOG"'
check "KEY.TXT dimuat"           'grep -q "Net-11: kunci dimuat" "$LOG"'
check "reset ACPI terdeteksi"    'grep -q "ACPI-R: reset ACPI siap" "$LOG"'

check "ping -> pong"             '[ "$($BM ping)" = "pong" ]'
check "uptime"                   '$BM uptime | grep -q "^uptime: "'
check "metrics kunci=nilai"      '$BM metrics | grep -q "^uptime_ticks="'

python3 -c 'import secrets; print("x" + secrets.token_hex(16), end="")' > "$WORK/bad.txt"
check "kunci salah ditolak" \
    'python3 $ROOT/client/bmctl.py --key $WORK/bad.txt --host 127.0.0.1 --port $PORT --timeout 10 ping | grep -q "^ERR: hmac salah"'

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

check "pping -> ppong"           '[ "$($BM pping)" = "ppong" ]'
check "reboot diterima"          '[ "$($BM reboot)" = "reboot: dimulai" ]'

for _ in $(seq 1 30); do
    kill -0 "$QPID" 2>/dev/null || break
    sleep 1
done
check "mesin reset (QEMU keluar)" '! kill -0 "$QPID" 2>/dev/null'
check "reboot lewat reset ACPI"   'grep -q "ACPI-R: reboot via register reset FADT" "$LOG" && ! grep -q "lanjut 8042" "$LOG"'

check "tanpa exception/fault di log" \
    '! grep -qiE "EXCEPTION|#GP|#PF|fault|panic|FATAL" "$LOG"'

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

echo
echo "hasil: $PASS lulus, $FAIL gagal (log: $LOG)"
[ "$FAIL" -eq 0 ]
