# Arsitektur bmahOS

Status: setelah F1.4 (2026-10-11). Peta ini menggambarkan kode yang ada, bukan rencana. Perbarui bila modul,
urutan boot, atau peta memori berubah.

## 1. Gambaran

Kernel monolitik x86_64, satu CPU, di-boot Limine (UEFI). Semua kode berjalan di ring 0 kecuali task uji
user mode (ring 3). Tidak ada SMP, tidak ada filesystem tulis, tidak ada loader ELF (program = biner datar
satu halaman).

Build tanpa optimasi (`CFLAGS` tanpa `-O`). Semua `kernel/*.c` dikompilasi otomatis (`wildcard` di Makefile)
dan semuanya bergantung pada `kernel/*.h`.

## 2. Modul

Satu header bersama: `kernel/kernel.h`. Aturannya: simbol yang hanya dipakai di dalam satu modul tetap
`static`; hanya simbol lintas modul yang dideklarasikan di header (dikelompokkan per modul).

| File | Isi | Bergantung pada |
|---|---|---|
| `kernel.c` | `kmain` (urutan boot), request Limine, ring log, net task dan idle task, `e1000_irq_service`, uji NX, kode uji user mode | semua modul |
| `serial.c` | COM1 115200 (polling), `serial_write*`, peredam log (`g_serial_mute`) | port I/O di header |
| `cpu.c` | GDT, TSS (rsp0), IDT dan tabel vektor | `gdt.S`, `interrupt.S` |
| `cpufeat.c` | CPUID sekali saat boot: vendor, family/model, hypervisor, fitur (rdrand, rdseed, nx, smep, smap, umip, pcid, apic, x2apic, tsc, tsc_invarian, sse2) di `g_cpu` + serial | — |
| `kprintf.c` | `kprintf` (serial), `ksnprintf` (buffer), `kassert_fail` untuk `ASSERT()` (cetak `PANIC: ... file:baris`, lalu berhenti), self-test format | serial |
| `trap.c` | `exception_dispatcher`, `irq_handler`, syscall `int 0x80` (test/write/exit), `trigger_*` uji | sched, vmm, apic |
| `pmm.c` | bitmap frame fisik (maks 4 GiB), frame 0 tidak pernah dibagikan | Limine memmap |
| `vmm.c` | page table 4 level, `vmm_map`, NX, klon PML4 kernel, validasi pointer user, heap kernel (`kmalloc`/`kfree` bump) | pmm |
| `acpi.c` | RSDP, MADT (alamat LAPIC/IOAPIC, override IRQ0), FADT (register reset) | Limine RSDP |
| `pic.c` | remap dan mask 8259, PIT | — |
| `apic.c` | Local APIC (EOI), IOAPIC (redirection table) | acpi, vmm |
| `pci.c` | config space mekanisme #1, pencarian AHCI dan E1000 | — |
| `ahci.c` | inisialisasi port, `ahci_read` (polling, satu frame) | pci, vmm, pmm |
| `fat32.c` | validasi BPB, root directory, cluster chain, `fat32_find_file`/`fat32_load_file`; D6: tulis root dir (`fat32_write_name`, `fat32_read_name`, `fat32_root_read`) dengan urutan tulis aman; D7: `fat32_delete_name`, `fat32_rename_name`, `fat32_replace_name` (ganti isi atomik lewat file sementara) | ahci |
| `fscmd.c` | D6: perintah `ls`/`baca`/`tulis`/`tambah` (D7: + `hapus`/`ganti`; nama 8.3, nama dilindungi, teks), dipanggil dari `priv_cmd_execute` | fat32, cmd, kprintf |
| `sched.c` | `task_t`, scheduler round-robin preemptive, sleep/wait/exit, semaphore, task user, `spawn` | vmm, pmm, `task.S` |
| `ktimer.c` | timer dengan callback (`ktimer_start/cancel/run`), senarai terurut deadline, callback dijalankan loop net task; self-test boot | sched (`task_sleep` di self-test) |
| `e1000.c` | driver Intel 8254x: ring TX/RX (64 slot), kirim, eksperimen GSI INTx, statistik | pci, vmm, apic |
| `net.c` | ARP, IPv4, ICMP echo, UDP (echo 7777), batas laju, TCP (port 7: tabel 4 TCB maks 2 per IP, buffer 1024 byte per koneksi, kirim stop-and-wait, retransmisi lewat ktimer, penutupan FIN/TIME_WAIT, echo sementara), dispatch RX, `net_poll` | e1000, auth, entropy, ktimer |
| `crypto.c` | SHA-256, HMAC-SHA256, `ct_memeq` (perbandingan waktu-konstan), self-test vektor resmi | — |
| `entropy.c` | kolam entropi (jitter TSC dari IRQ timer/E1000 dan RX, rdseed/rdrand), HMAC-DRBG SP 800-90A, `entropy_get` (0 = belum cukup, pemanggil menolak), self-test CAVP | crypto, cpufeat |
| `auth.c` | kunci dari `KEY.TXT`, nonce (tabel 16 slot, isi dari `entropy_get`), verifikasi HMAC, perintah berprivilege, reboot, pintu UDP 7778 | crypto, entropy, fat32, cmd |
| `audit.c` | D5: audit log di RAM (ring ok 16 + ring gagal 8, entri IP:port, peran, kejadian, kode, perintah, tick), baris `AUDIT` ke UART tanpa ring log, `audit_dump` untuk perintah `audit` | kprintf, serial, cmd |
| `cmd.c` | isi perintah baca (`help uptime mem log irq stats metrics mac ip tasks`) dan pengirim balasan | net, sched, log |
| `gdt.S`, `interrupt.S`, `task.S` | muat GDT/TSS, stub ISR/IRQ, `context_switch`, `enter_usermode` | — |

## 3. Urutan boot (`kmain`)

1. `serial_init`, `cpu_features_init` (CPUID), `kprintf_selftest`, `entropy_init` (self-test DRBG, rdseed/rdrand, RTC), PCI scan dan `pci_find_devices`, `nx_init`.
2. GDT + TSS, IDT (vektor 0-19, 32, 33, 0x80), cetak register segmen.
3. PMM dari memmap Limine (uji alloc/free), VMM (dump PML4, NX di half atas), heap kernel.
4. ACPI (MADT, FADT), Local APIC, AHCI (lalu FAT32: baca `HELLO.TXT`, `spawn` dari `PROG.BIN`),
   E1000 (ring TX/RX, crypto self-test, muat kunci dari `KEY.TXT`), IOAPIC untuk IRQ0, eksperimen GSI E1000,
   remap PIC, PIT 100 Hz.
5. Task: A/B (uji semaphore), tiga task user (isolasi, `sys_write`, `sys_exit`), `spawn` kode uji,
   uji NX, net task (bila E1000 ada), idle task. Build `PROD=1` membuat task uji tetapi mereset `task_count`
   sebelum net task, jadi task uji tidak pernah dijadwalkan.
6. `context_switch` ke task pertama; `kmain` tidak kembali.

## 4. Peta memori virtual

| Alamat | Isi |
|---|---|
| `0x400000` ... `0x10000000` | ruang user (kode dan stack per task, alokasi bump mulai `0x400000`) |
| HHDM (`hhdm_offset` dari Limine, PML4[0x100]) | alias semua RAM fisik, dipakai kernel untuk mengakses frame |
| `0xFFFF910000000000` | MMIO Local APIC |
| `0xFFFF910000001000` | MMIO IOAPIC |
| `0xFFFF910000002000` | MMIO AHCI (ABAR) |
| `0xFFFF910000003000` | MMIO E1000 (BAR0) |
| `0xFFFF980000000000` | heap kernel (`KHEAP_START`), tumbuh per halaman |
| PML4[0x1FF] | image kernel higher-half (.text/.data) |

Setiap task user punya PML4 sendiri (klon entri kernel bersama: HHDM, MMIO, heap, kernel). Halaman data,
stack, heap, dan MMIO diberi NX.

## 5. Eksekusi dan konkurensi

- Satu CPU. Timer 100 Hz memanggil `schedule()` (preemptive). Interrupt E1000 dan tick timer membangunkan
  net task lewat semaphore `g_net_rx_sem`.
- Semua jaringan (RX, protokol, perintah, TCP) berjalan hanya di net task, jadi tidak ada lock di stack
  jaringan. Bagian yang dipakai bersama interrupt memakai `irq_save`/`irq_restore`.
- Jalur paket masuk: `e1000` RX ring → `net_poll` → `net_rx_dispatch` → ARP / IPv4 → ICMP / UDP / TCP →
  (UDP 7778) `net_cmd_handle` → `auth` → `cmd`.

## 6. Pengujian

`make test` (`tests/qemu-smoke.sh`) mem-boot ISO tiga kali di QEMU (jaringan slirp, jaringan mentah lewat
`tests/qemu-rawnet.py`, tanpa NIC dan disk) dan mencocokkan log serial serta balasan jaringan. CI menjalankan
build default dan `PROD=1`.

`make host-test` (F1.7) menjalankan uji unit di host Linux dengan ASan + UBSan (`clang`, ganti lewat
`HOST_CC`). Tiap `tests/host/test_X.c` dikompilasi bersama modul yang diuji dan `tests/host/stubs.c`
(stub `serial_*` yang menangkap keluaran). `net.c`, `auth.c`, dan `entropy.c` di-`#include` langsung oleh ujinya supaya
fungsi `static` bisa diuji. Saat `BMAHOS_HOST_TEST` aktif, `kernel.h` mengganti `cli`/`sti` dan port I/O
dengan no-op (instruksi itu fault di user mode); build kernel tidak berubah.

| Uji | Isi |
|---|---|
| `test_crypto` | SHA-256 (FIPS 180-4, sejuta 'a', panjang 0..200 + semua titik potong update), HMAC RFC 4231 kasus 1-7, panjang kunci 0..130, `ct_memeq` (panjang 0..64, tiap bit, pointer tidak sejajar) |
| `test_kprintf` | `ksnprintf` dibandingkan `snprintf` libc untuk semua ukuran buffer, `%p`, NULL, format tak dikenal, self-test |
| `test_net` | checksum (RFC 1071, acak 0..1500 byte), ARP, ICMP, UDP echo/7778, TCP RST + handshake port 7, kirim data TCP (putaran 2^32, jendela 0/penuh, stop-and-wait, aliran 20 ribu byte utuh), retransmisi (jeda 100/200/400/800/800 tick, RST setelah 5x, ACK sebagian mengembalikan RTO), penutupan (pasif, aktif saat diam, bersamaan, TIME_WAIT, FIN_WAIT_2 habis, data setelah FIN -> RST), batas 2000 segmen/s per koneksi dan 10 ACK duplikat/s, batas ukuran, frame dipotong di semua panjang, 200 ribu frame acak (checksum dibetulkan); tiap frame keluar dicek checksum-nya |
| `test_ktimer` | urutan deadline (sama = urutan pasang), batal, pasang ulang (juga dari callback, `ticks = 0` = 1), batal dari callback, 200 ribu operasi acak dibandingkan model |
| `test_entropy` | HMAC-DRBG vs 32 vektor CAVP, estimator (teratur = 0 bit), tolak sebelum siap, siap tepat setelah 256 tick berjitter, batas kolam cepat, jeda reseed, 100 ribu nonce unik, FIPS 140-2 (monobit, poker, runs) atas keluaran |
| `test_auth` | `auth_load_key`, jalur counter, jalur nonce (TTL, sekali pakai, slot tidak dibebaskan saat HMAC salah), `net_cmd_handle` (CHAL, batas 4 nonce per IP), potongan + 100 ribu pesan acak; D5: audit jalur UDP, `audit` hanya admin |
| `test_audit` | D5: format baris, semua jenis kejadian, sanitasi/potong teks perintah, ring memutar, banjir gagal tidak menyentuh ring ok, UART saat dibungkam, keluaran maksimum `...(terpotong)` |

Frame dan pesan dimasukkan dalam buffer `malloc` seukuran persis, jadi pembacaan lewat batas tertangkap ASan.
Uji juga dicek dengan mutasi (pemeriksaan batas di kode kernel dihapus satu per satu): tiap mutasi
pemeriksaan batas/HMAC/TTL/replay membuat `make host-test` gagal.
