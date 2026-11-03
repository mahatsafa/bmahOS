#!/usr/bin/env bash
# P7-3: uji OTA A/B dengan boot dari DISK (tanpa CD): Limine di EFI/BOOT,
# limine.conf 512 byte, slot KERNA.ELF/KERNB.ELF 1 MB. QEMU TANPA -no-reboot:
# reboot (ota coba, ota batal, panic, rollback) memuat ulang dari disk yang sama,
# log serial berlanjut di satu file. Bukti tiap boot: baris "PCI-1: E1000 di".
#
# Dev (kunci uji tests/ota/ota-uji.pem):
#   boot 1  A (limine.conf), OTA.BIN dibuat; ota coba ditolak (B tanpa catatan);
#           kirim kernel v10 -> B; ota coba -> reboot
#   boot 2  B percobaan sisa 2; ota sah -> aktif B; kirim v11 -> A; ota coba
#   boot 3  A percobaan; ota batal -> reboot
#   boot 4  B (aktif); ota coba (A masih sah) -> reboot
#   boot 5  A percobaan -> sehat 60 s -> dikukuhkan; kirim v12 RUSAK -> B; ota coba
#   boot 6-8  B percobaan sisa 2/1/0 -> panic (penanda P7UJI:panik)
#   boot 9  B, sisa habis -> rollback: B gagal, limine.conf ke A, reboot
#   boot 10 A; ota coba -> ERR slot B tidak sah. QEMU dimatikan, limine.conf diubah
#           dari host ke slot B (simulasi crash di tengah rollback)
#   boot 11 B tanpa percobaan -> limine.conf diperbaiki, reboot
#   boot 12 A biasa
# PROD (kunci uji ditolak): boot dari disk slot A, ota coba ditolak, kiriman ditolak.
#
# Pakai: make test (setelah qemu-smoke) atau make test-ota.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ELF="$ROOT/build/kernel.elf"
EFI="$ROOT/tools/limine/bin/BOOTX64.EFI"
WORK="$ROOT/build/test-ota"
QEMU="${QEMU:-$(command -v qemu-system-x86_64 2>/dev/null || echo /usr/libexec/qemu-kvm)}"
OVMF_CODE="${OVMF_CODE:-/usr/share/edk2/ovmf/OVMF_CODE.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/edk2/ovmf/OVMF_VARS.fd}"
CPORT="${BMTEST_OTA_CLI_PORT:-18779}"   # CLI TCP 7779
OPORT="${BMTEST_OTA_OTA_PORT:-18781}"   # OTA 7781
BOOT_TIMEOUT="${BMTEST_BOOT_TIMEOUT:-180}"

PASS=0
FAIL=0
QPID=""

ok()   { echo "PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

stop_qemu() {
    if [ -n "$QPID" ] && kill -0 "$QPID" 2>/dev/null; then
        kill "$QPID" 2>/dev/null
        wait "$QPID" 2>/dev/null
    fi
    QPID=""
}
trap stop_qemu EXIT

for f in "$ELF" "$EFI" "$OVMF_CODE" "$OVMF_VARS"; do
    [ -f "$f" ] || { echo "tidak ada: $f"; exit 2; }
done
for t in "$QEMU" mkfs.vfat mcopy mmd mtype fsck.fat python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "butuh program: $t"; exit 2; }
done

rm -rf "$WORK"
mkdir -p "$WORK"
LOG="$WORK/serial.log"
KEY="$WORK/KEY.TXT"
DISK="$WORK/disk.img"

conf() {   # $1 = default_entry -> limine.conf 512 byte (pola P7-0)
    python3 - "$WORK/limine.conf" "$1" <<'LCEOF'
import sys
t = ("timeout: 3\ndefault_entry: %s\n\n" % sys.argv[2] +
     "/bmahOS slot A\n    protocol: limine\n    path: boot():/KERNA.ELF\n    cmdline: slot=A\n\n"
     "/bmahOS slot B\n    protocol: limine\n    path: boot():/KERNB.ELF\n    cmdline: slot=B\n\n")
t += "#" + "-" * (512 - len(t) - 2) + "\n"
assert len(t) == 512
open(sys.argv[1], "w").write(t)
LCEOF
}

python3 -c 'import secrets; print(secrets.token_hex(16), end="")' > "$KEY"
dd if=/dev/zero of="$DISK" bs=1M count=128 status=none
mkfs.vfat -F 32 -s 2 "$DISK" >/dev/null
mmd -i "$DISK" ::EFI ::EFI/BOOT
mcopy -i "$DISK" "$EFI" ::EFI/BOOT/BOOTX64.EFI
conf 1
mcopy -i "$DISK" "$WORK/limine.conf" ::limine.conf
cp "$ELF" "$WORK/KERNA.ELF"
truncate -s 1048576 "$WORK/KERNA.ELF"
head -c 1048576 /dev/zero > "$WORK/KERNB.ELF"
mcopy -i "$DISK" "$WORK/KERNA.ELF" ::KERNA.ELF
mcopy -i "$DISK" "$WORK/KERNB.ELF" ::KERNB.ELF
mcopy -i "$DISK" "$KEY" ::KEY.TXT
cp "$OVMF_VARS" "$WORK/vars.fd"

start_qemu() {
    "$QEMU" -machine q35 -m 512M -cpu max \
        -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
        -drive if=pflash,format=raw,file="$WORK/vars.fd" \
        -drive id=d0,file="$DISK",format=raw,if=none \
        -device ide-hd,drive=d0,bus=ide.1,bootindex=1 \
        -netdev user,id=n0,net=192.168.50.0/24,host=192.168.50.1,hostfwd=tcp:127.0.0.1:$CPORT-192.168.50.200:7779,hostfwd=tcp:127.0.0.1:$OPORT-192.168.50.200:7781 \
        -device e1000,netdev=n0 \
        -display none -serial file:"$LOG.$1" \
        >"$WORK/qemu.$1.out" 2>&1 &
    QPID=$!
}

SLOG=""   # log serial QEMU yang sedang jalan
boots() { grep -ac "PCI-1: E1000 di" "$SLOG" 2>/dev/null; }
# Tunggu boot ke-$1 (dalam QEMU ini) siap menerima perintah: net task jalan
# ("R5: watchdog aktif") sesudah baris PCI E1000 ke-$1 (entropi dicetak sebelum PCI;
# boot yang panic/rollback di kmain tidak sampai net task).
siap_ke() {
    awk -v n="$1" '/PCI-1: E1000 di/ { c++ } c == n && /R5: watchdog aktif/ { f = 1 }
                   END { exit !f }' "$SLOG" 2>/dev/null
}
wait_boot() {
    local t=0
    until siap_ke "$1"; do
        if ! kill -0 "$QPID" 2>/dev/null || [ "$t" -ge "$BOOT_TIMEOUT" ]; then
            echo "info  boot ke-$1 tidak siap (t=$t s)"
            tail -5 "$SLOG"
            return 1
        fi
        sleep 1
        t=$((t + 1))
    done
    sleep 2
}
# Tunggu pola muncul (maks $2 detik).
wait_line() {
    local t=0
    until grep -aq "$1" "$SLOG" 2>/dev/null; do
        [ "$t" -ge "$2" ] && return 1
        kill -0 "$QPID" 2>/dev/null || return 1
        sleep 1
        t=$((t + 1))
    done
}

BMT="python3 $ROOT/client/bmctl.py --tcp --host 127.0.0.1 --port $CPORT --timeout 20 --key $KEY"
cmd() { sleep 2.5; $BMT "$@" 2>&1; }
kirim() { sleep 2.5; $BMT --ota-port "$OPORT" --ota "$1" 2>&1; }
OSIGN="python3 $ROOT/client/ota-sign.py --kunci $ROOT/tests/ota/ota-uji.pem --jenis kernel"
KSZ="$(stat -c %s "$ELF")"
$OSIGN --versi 10 "$ELF" "$WORK/v10.bmo" >/dev/null
$OSIGN --versi 11 "$ELF" "$WORK/v11.bmo" >/dev/null
python3 - "$ELF" "$WORK/rusak.elf" <<'PYEOF'
import sys
d = open(sys.argv[1], "rb").read()
assert d.count(b"P7UJI:sehat") == 1, "penanda P7UJI:sehat harus tepat satu"
open(sys.argv[2], "wb").write(d.replace(b"P7UJI:sehat", b"P7UJI:panik"))
PYEOF
$OSIGN --versi 12 "$WORK/rusak.elf" "$WORK/v12.bmo" >/dev/null

start_qemu 1
SLOG="$LOG.1"
echo "QEMU pid $QPID (boot dari disk), menunggu boot 1..."
if ! wait_boot 1; then
    bad "boot 1 dari disk (slot A) tidak siap"
    echo; echo "hasil qemu-ota: $PASS lulus, $FAIL gagal"; exit 1
fi
if grep -q "PROD: task uji dilewati" "$SLOG"; then PROD=1; else PROD=0; fi
check "P7-3: boot dari disk: Limine cmdline slot=A, OTA.BIN dibuat, aktif A (limine.conf)" \
    'grep -aq "^P7: cmdline=\"slot=A\"" "$SLOG" && grep -aq "^P7: ota siap berjalan=A aktif=A (limine.conf) OTA.BIN=kosong slot A v0 slot B v0" "$SLOG"'
R1="$(cmd "ota coba" "ota sah" "ota batal")"
echo "$R1" | sed "s/^/info  boot1: /"
check "P7-3: ota coba (B tanpa catatan) / ota sah / ota batal tanpa percobaan -> ERR" \
    'echo "$R1" | grep -q "^ERR: slot B tidak berstatus sah$" && echo "$R1" | grep -q "^ERR: tidak ada boot percobaan yang berjalan$" && echo "$R1" | grep -q "^ERR: tidak ada percobaan$"'

if [ "$PROD" = 1 ]; then
    K1="$(kirim "$WORK/v10.bmo")"
    check "P7-3: PROD: kernel bertanda tangan kunci uji ditolak" \
        'echo "$K1" | grep -q "^ERR ota: tanda tangan tidak sah$"'
    check "P7-3: PROD: tanpa PANIC" '! grep -aq "PANIC" "$SLOG"'
    stop_qemu
    echo
    echo "hasil qemu-ota: $PASS lulus, $FAIL gagal (log: $LOG.*)"
    [ "$FAIL" -eq 0 ]
    exit
fi

# ---- boot 1 -> 2: v10 ke B, ota coba ----
K1="$(kirim "$WORK/v10.bmo")"
echo "$K1" | sed "s/^/info  kirim v10: /"
check "P7-3: v10 -> slot B ditulis + dibaca balik" \
    'echo "$K1" | grep -q "^OK ota: slot B versi 10 ukuran $KSZ "'
C1="$(cmd "ota coba")"
check "P7-3: ota coba -> OK coba slot B versi 10, 3 boot percobaan; reboot" \
    'echo "$C1" | grep -q "^OK ota: coba slot B versi 10, 3 boot percobaan; reboot$"'
wait_boot 2
check "P7-3: boot 2: Limine memuat slot B (cmdline slot=B), boot percobaan sisa 2" \
    '[ "$(boots)" -eq 2 ] && grep -aq "^P7: cmdline=\"slot=B\"" "$SLOG" && grep -aq "^P7: boot percobaan slot B versi 10 (sisa 2)" "$SLOG"'
S2="$(cmd ota "ota coba" "ota sah" ota)"
echo "$S2" | sed "s/^/info  boot2: /"
check "P7-3: boot 2: status coba B sisa 2 (berjalan); ota coba kedua ditolak" \
    'echo "$S2" | grep -q "^coba: slot B sisa 2 (berjalan; dikukuhkan setelah sehat 60 s)$" && echo "$S2" | grep -q "^ERR: percobaan sudah berjalan / tertunda (ota sah / ota batal)$"'
check "P7-3: ota sah -> slot B dikukuhkan; status aktif B tanpa baris coba" \
    'echo "$S2" | grep -q "^OK ota: slot B dikukuhkan$" && echo "$S2" | grep -q "^ota: berjalan=B aktif=B (OTA.BIN)" && [ "$(echo "$S2" | grep -c "^coba:")" -eq 1 ] && grep -aq "^P7: slot B versi 10 dikukuhkan (ota sah)" "$SLOG"'

# ---- boot 2 -> 3: v11 ke A, coba, batal ----
K2="$(kirim "$WORK/v11.bmo")"
check "P7-3: boot 2 (B berjalan): v11 -> slot A" \
    'echo "$K2" | grep -q "^OK ota: slot A versi 11 ukuran $KSZ "'
C2="$(cmd "ota coba")"
check "P7-3: ota coba slot A versi 11" \
    'echo "$C2" | grep -q "^OK ota: coba slot A versi 11, 3 boot percobaan; reboot$"'
wait_boot 3
check "P7-3: boot 3: slot A percobaan sisa 2" \
    '[ "$(boots)" -eq 3 ] && grep -aq "^P7: boot percobaan slot A versi 11 (sisa 2)" "$SLOG"'
B3="$(cmd "ota batal")"
check "P7-3: ota batal -> kembali ke slot aktif B; reboot" \
    'echo "$B3" | grep -q "^OK ota: percobaan slot A dibatalkan, slot aktif B; reboot$"'
wait_boot 4
S4="$(cmd ota)"
echo "$S4" | sed "s/^/info  boot4: /"
check "P7-3: boot 4: B (aktif), slot A tetap sah v11, tanpa percobaan" \
    '[ "$(boots)" -eq 4 ] && [ "$(grep -ac "^P7: cmdline=\"slot=B\"" "$SLOG")" -eq 2 ] && echo "$S4" | grep -q "^ota: berjalan=B aktif=B (OTA.BIN)" && echo "$S4" | grep -q "^slot A: sah versi=11 " && ! echo "$S4" | grep -q "^coba:"'

# ---- boot 4 -> 5: coba lagi, dikukuhkan otomatis ----
C4="$(cmd "ota coba")"
check "P7-3: ota coba lagi (A sah setelah batal)" \
    'echo "$C4" | grep -q "^OK ota: coba slot A versi 11"'
wait_boot 5
check "P7-3: boot 5: slot A percobaan sisa 2, dikukuhkan otomatis setelah sehat 60 s" \
    'grep -aq "^P7: boot percobaan slot A versi 11 (sisa 2)" "$SLOG" && wait_line "^P7: slot A versi 11 dikukuhkan (sehat 60 s)" 120'
S5="$(cmd ota)"
check "P7-3: boot 5: aktif A (OTA.BIN), slot B sah v10" \
    'echo "$S5" | grep -q "^ota: berjalan=A aktif=A (OTA.BIN)" && echo "$S5" | grep -q "^slot B: sah versi=10 " && ! echo "$S5" | grep -q "^coba:"'

# ---- boot 5 -> 9: v12 rusak ke B, 3x panic, rollback ----
K5="$(kirim "$WORK/v12.bmo")"
check "P7-3: v12 (penanda P7UJI:panik) -> slot B" \
    'echo "$K5" | grep -q "^OK ota: slot B versi 12 "'
C5="$(cmd "ota coba")"
check "P7-3: ota coba slot B versi 12" \
    'echo "$C5" | grep -q "^OK ota: coba slot B versi 12, 3 boot percobaan; reboot$"'
wait_line "^P7: rollback: slot B gagal 3 boot percobaan, kembali ke slot A, reboot" 400
wait_boot 10
check "P7-3: 3 boot percobaan B (sisa 2, 1, 0) masing-masing panic penanda uji" \
    'grep -aq "^P7: boot percobaan slot B versi 12 (sisa 2)" "$SLOG" && grep -aq "^P7: boot percobaan slot B versi 12 (sisa 1)" "$SLOG" && grep -aq "^P7: boot percobaan slot B versi 12 (sisa 0)" "$SLOG" && [ "$(grep -ac "^PANIC: P7: uji kernel rusak (penanda P7UJI:panik)" "$SLOG")" -eq 3 ]'
check "P7-3: boot 9: rollback ke A + reboot; boot 10 slot A" \
    'grep -aq "^P7: rollback: slot B gagal 3 boot percobaan, kembali ke slot A, reboot" "$SLOG" && [ "$(boots)" -eq 10 ] && [ "$(grep -a "^P7: cmdline=" "$SLOG" | tail -1 | tr -d "\r")" = "P7: cmdline=\"slot=A\"" ]'
S10="$(cmd ota "ota coba")"
echo "$S10" | sed "s/^/info  boot10: /"
check "P7-3: boot 10: aktif A, slot B gagal v12; ota coba -> ERR slot B tidak sah" \
    'echo "$S10" | grep -q "^ota: berjalan=A aktif=A (OTA.BIN)" && echo "$S10" | grep -q "^slot B: gagal versi=12 " && echo "$S10" | grep -q "^ERR: slot B tidak berstatus sah$"'
stop_qemu
check "P7-3: disk dari host: limine.conf default_entry 1, fsck bersih" \
    'mtype -i "$DISK" ::limine.conf | grep -q "^default_entry: 1$" && [ "$(mtype -i "$DISK" ::limine.conf | wc -c)" -eq 512 ] && fsck.fat -n "$DISK" >"$WORK/fsck.out" 2>&1'

# ---- boot 11-12: limine.conf menunjuk B tanpa percobaan -> diperbaiki ----
conf 2
mcopy -o -i "$DISK" "$WORK/limine.conf" ::limine.conf
start_qemu 2
SLOG="$LOG.2"
wait_boot 2
check "P7-3: limine.conf salah (B, tanpa percobaan) -> diperbaiki + reboot -> slot A" \
    'grep -aq "^P7: limine.conf menunjuk slot B, bukan aktif A: diperbaiki, reboot" "$SLOG" && [ "$(boots)" -eq 2 ] && [ "$(grep -a "^P7: cmdline=" "$SLOG" | tail -1 | tr -d "\r")" = "P7: cmdline=\"slot=A\"" ]'
stop_qemu
check "P7-3: hanya 3 panic (uji), tanpa exception/watchdog/tidak sehat" \
    '[ "$(grep -ac "^PANIC: reboot otomatis dalam 10 detik" "$LOG.1")" -eq 3 ] && ! grep -aqE "^PANIC: (exception|watchdog|P7: boot percobaan)" "$LOG.1" && ! grep -aq "PANIC" "$LOG.2"'

echo
echo "hasil qemu-ota: $PASS lulus, $FAIL gagal (log: $LOG.*)"
[ "$FAIL" -eq 0 ]
