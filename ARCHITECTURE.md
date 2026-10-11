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
| `trap.c` | `exception_dispatcher`, `irq_handler`, syscall `int 0x80` (test/write/exit), `trigger_*` uji | sched, vmm, apic |
| `pmm.c` | bitmap frame fisik (maks 4 GiB), frame 0 tidak pernah dibagikan | Limine memmap |
| `vmm.c` | page table 4 level, `vmm_map`, NX, klon PML4 kernel, validasi pointer user, heap kernel (`kmalloc`/`kfree` bump) | pmm |
| `acpi.c` | RSDP, MADT (alamat LAPIC/IOAPIC, override IRQ0), FADT (register reset) | Limine RSDP |
| `pic.c` | remap dan mask 8259, PIT | — |
| `apic.c` | Local APIC (EOI), IOAPIC (redirection table) | acpi, vmm |
| `pci.c` | config space mekanisme #1, pencarian AHCI dan E1000 | — |
| `ahci.c` | inisialisasi port, `ahci_read` (polling, satu frame) | pci, vmm, pmm |
| `fat32.c` | validasi BPB, root directory, cluster chain, `fat32_find_file`/`fat32_load_file` | ahci |
| `sched.c` | `task_t`, scheduler round-robin preemptive, sleep/wait/exit, semaphore, task user, `spawn` | vmm, pmm, `task.S` |
| `e1000.c` | driver Intel 8254x: ring TX/RX (64 slot), kirim, eksperimen GSI INTx, statistik | pci, vmm, apic |
| `net.c` | ARP, IPv4, ICMP echo, UDP (echo 7777), batas laju, TCP (port 7), dispatch RX, `net_poll` | e1000, auth |
| `crypto.c` | SHA-256, HMAC-SHA256, self-test vektor resmi | — |
| `auth.c` | kunci dari `KEY.TXT`, nonce (tabel 16 slot), verifikasi HMAC, perintah berprivilege, reboot, pintu UDP 7778 | crypto, fat32, cmd |
| `cmd.c` | isi perintah baca (`help uptime mem log irq stats metrics mac ip tasks`) dan pengirim balasan | net, sched, log |
| `gdt.S`, `interrupt.S`, `task.S` | muat GDT/TSS, stub ISR/IRQ, `context_switch`, `enter_usermode` | — |

## 3. Urutan boot (`kmain`)

1. `serial_init`, `cpu_features_init` (CPUID), PCI scan dan `pci_find_devices`, `nx_init`.
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
