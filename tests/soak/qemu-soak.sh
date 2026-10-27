#!/bin/bash
# R8: pra-uji soak di QEMU (TCG) dengan client/soak.py lewat hostfwd slirp.
# Pakai: rm -rf build; make iso PROD=1; tests/soak/qemu-soak.sh [durasi_s] [interval_s]
# Hasil: build/soak/ (serial.log, metrik.jsonl, klien.jsonl, status.json, laporan.md).
# Disk uji dibuat seperti qemu-smoke (kunci acak, TLS acak, LOG.BIN 64 KB).
# ICMP tidak lewat slirp -> --tanpa-ping. Kode keluar = kode analisis (0 lulus).
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ISO="$ROOT/build/bmahOS.iso"
WORK="$ROOT/build/soak"
QEMU="${QEMU:-$(command -v qemu-system-x86_64 2>/dev/null || echo /usr/libexec/qemu-kvm)}"
OVMF_CODE="${OVMF_CODE:-/usr/share/edk2/ovmf/OVMF_CODE.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/edk2/ovmf/OVMF_VARS.fd}"
DURASI="${1:-3600}"
INTERVAL="${2:-300}"
B=27000   # dasar port hostfwd (beda dari qemu-smoke 17xxx)
QPID=""

cleanup() {
    if [ -n "$QPID" ] && kill -0 "$QPID" 2>/dev/null; then kill "$QPID"; fi
}
trap cleanup EXIT

[ -f "$ISO" ] || { echo "tidak ada: $ISO"; exit 2; }
rm -rf "$WORK"
mkdir -p "$WORK"
LOG="$WORK/serial.log"
KEY="$WORK/KEY.TXT"
DISK="$WORK/disk.img"

python3 -c 'import secrets; print(secrets.token_hex(16), end="")' > "$KEY"
dd if=/dev/zero of="$DISK" bs=1M count=64 status=none
mkfs.vfat -F 32 "$DISK" >/dev/null
mcopy -i "$DISK" "$KEY" ::KEY.TXT
openssl ecparam -name prime256v1 -genkey -noout -outform DER -out "$WORK/TLSKEY.DER" 2>/dev/null
openssl req -new -x509 -key "$WORK/TLSKEY.DER" -keyform DER -days 3650 \
    -subj /CN=bmahOS-soak -outform DER -out "$WORK/TLSCERT.DER" 2>/dev/null
mcopy -i "$DISK" "$WORK/TLSKEY.DER" ::TLSKEY.DER
mcopy -i "$DISK" "$WORK/TLSCERT.DER" ::TLSCERT.DER
head -c 65536 /dev/zero > "$WORK/LOG.BIN"
mcopy -i "$DISK" "$WORK/LOG.BIN" ::LOG.BIN
sha256sum "$WORK/TLSCERT.DER" | cut -d" " -f1 > "$WORK/tlspin.txt"
cp "$OVMF_VARS" "$WORK/vars.fd"

FWD="hostfwd=udp:127.0.0.1:$((B+7778))-192.168.50.200:7778"
FWD="$FWD,hostfwd=udp:127.0.0.1:$((B+7777))-192.168.50.200:7777"
FWD="$FWD,hostfwd=tcp:127.0.0.1:$((B+7))-192.168.50.200:7"
FWD="$FWD,hostfwd=tcp:127.0.0.1:$((B+7779))-192.168.50.200:7779"
FWD="$FWD,hostfwd=tcp:127.0.0.1:$((B+7780))-192.168.50.200:7780"

"$QEMU" -machine q35 -m 512M -cpu max \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$WORK/vars.fd" \
    -cdrom "$ISO" \
    -drive id=d0,file="$DISK",format=raw,if=none -device ide-hd,drive=d0,bus=ide.1 \
    -netdev user,id=n0,net=192.168.50.0/24,host=192.168.50.1,$FWD \
    -device e1000,netdev=n0 \
    -display none -serial file:"$LOG" -no-reboot \
    >"$WORK/qemu.out" 2>&1 &
QPID=$!

echo "QEMU pid $QPID, menunggu net task..."
for _ in $(seq 180); do
    grep -q "net task dimulai" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || { echo "QEMU berhenti"; tail "$LOG"; exit 1; }
    sleep 1
done
until grep -q "Entropi: siap" "$LOG" 2>/dev/null; do sleep 1; done
sleep 3

python3 "$ROOT/client/soak.py" --key "$KEY" --pin "$WORK/tlspin.txt" \
    --host 127.0.0.1 --udp $((B+7778)) --udp-echo $((B+7777)) --echo $((B+7)) \
    --cli $((B+7779)) --tls $((B+7780)) --tanpa-ping \
    --durasi "$DURASI" --interval "$INTERVAL" --keluar "$WORK"
echo "soak.py selesai (rc $?)"
kill -0 "$QPID" 2>/dev/null && echo "QEMU masih hidup" || echo "QEMU MATI"
cleanup
python3 "$ROOT/tests/soak/analisis.py" "$WORK" --serial "$LOG" --pemanasan "$INTERVAL" \
    | tee "$WORK/laporan.md"
exit "${PIPESTATUS[0]}"
