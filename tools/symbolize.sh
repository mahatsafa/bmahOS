#!/bin/bash
# R1: terjemahkan baris "PANIC: trace #N 0x..." di log serial menjadi
# fungsi + file:baris. ELF harus dari build yang sama dengan ISO yang panic.
# Pakai: tools/symbolize.sh <log-serial> [build/kernel.elf]
set -e
LOG="${1:?pakai: tools/symbolize.sh <log-serial> [kernel.elf]}"
ELF="${2:-build/kernel.elf}"
tr -d '\r' < "$LOG" |
    sed -n 's/.*PANIC: trace \(#[0-9]*\) \(0x[0-9a-f]*\).*/\1 \2/p' |
    while read -r n addr; do
        a="$addr"
        # #1 dst. = alamat kembali (sesudah call): mundur 1 byte ke instruksi call.
        if [ "$n" != "#0" ]; then
            a=$(printf '0x%x' $((addr - 1)))
        fi
        printf '%-4s %s %s\n' "$n" "$addr" "$(addr2line -f -s -e "$ELF" "$a" | paste -sd' ')"
    done
