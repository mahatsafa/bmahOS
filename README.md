# bmahOS

Sistem operasi eksperimental x86_64 yang ditulis dari nol (freestanding, UEFI via Limine).
Dikembangkan dan diuji di VMware Workstation. Belum pernah diuji di hardware asli.

## Target

- HP Stream Notebook PC 11 (Intel Celeron N2840, 2 GB RAM, x86_64, UEFI)

## Tujuan

- Ringan, headless/server, operasi 24/7
- Administrasi jarak jauh
- Jaringan, monitoring sistem dan jaringan
- Dapat menjalankan beban kerja IoT dan robotika (jangka panjang, bukan fokus pengembangan saat ini)
- Open source

## Status (terverifikasi lewat log serial dan Wireshark di VMware)

- Boot: Limine UEFI, GDT/TSS, IDT, exception handler, PMM (bitmap), VMM (paging), kernel heap
- Multitasking preemptive (timer 100 Hz via LAPIC/IOAPIC), semaphore, user mode (ring 3) dengan syscall
- Storage: PCI, AHCI (baca blok), FAT32 (baca file, root directory), `spawn()` program dari disk
- Jaringan (NIC Intel 82545EM / E1000 emulasi VMware): TX/RX ring, ARP, IPv4, ICMP echo, UDP
- Interrupt RX E1000 via IOAPIC (GSI INTx ditemukan lewat eksperimen), net task tidur sampai ada paket
- Task idle (`hlt`), build produksi tanpa task uji

## Build

Kebutuhan: `gcc`, `ld`, `xorriso`, dan Limine di `tools/limine` (binary + protocol headers).

    make iso            # build biasa (task uji ikut jalan, untuk pengembangan)
    make iso PROD=1     # build produksi (task uji dilewati, hanya net + idle)

Hasil: `build/bmahOS.iso`.

## Konfigurasi saat ini (hardcode)

- IP: `192.168.50.200` (jaringan VMnet2 host-only VMware)
- Disk FAT32 harus berisi `KEY.TXT` (kunci autentikasi, 16 sampai 64 byte). Tanpa file ini semua
  perintah ditolak. **Jangan commit kunci.** `testdisk/` ada di `.gitignore`.

## Perintah jarak jauh (UDP port 7778)

Datagram: `<counter> <perintah> <hmac-hex-64>`

- `hmac` = HMAC-SHA256 (kunci dari `KEY.TXT`) atas string `<counter> <perintah>`
- `counter` harus lebih besar dari counter terakhir yang diterima (anti-replay)

Perintah (hanya baca): `help`, `ping`, `uptime`, `mem`, `log`, `irq`, `mac`, `ip`, `tasks`

UDP echo tanpa autentikasi ada di port 7777.

Contoh klien (PowerShell) ada di riwayat pengembangan; implementasinya hanya `HMACSHA256` dan `UdpClient`.

## Arah berikutnya (belum dikerjakan)

- Statistik/metrics: satu perintah yang mengembalikan semua counter (paket, error, memori, autentikasi)
- TCP, lalu CLI interaktif di atasnya dengan autentikasi challenge-response
- SSH hanya dipertimbangkan setelah itu

## Batasan yang diketahui

- Autentikasi hanya menjamin keaslian perintah, bukan kerahasiaan balasan (teks polos)
- Counter anti-replay disimpan di RAM; setelah reboot datagram lama bisa diputar ulang sekali
- Belum ada rate limiting untuk datagram dengan autentikasi gagal
- GSI interrupt E1000 (19) adalah hasil pengamatan di VMware, bukan nilai universal
- Hanya driver E1000; belum ada driver untuk NIC hardware target
- Belum ada TCP, DHCP, atau IPv6

## Catatan pengembangan

Perubahan dibuat lewat patch Python yang atomik (semua penggantian teks harus cocok persis sekali,
kalau tidak file tidak berubah), diverifikasi dengan `git diff`, build, boot di VMware, dan pengecekan
log serial sebelum commit.
