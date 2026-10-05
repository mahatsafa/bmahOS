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
- Perintah jarak jauh terautentikasi HMAC-SHA256 (SHA-256/HMAC ditulis sendiri, self-test vektor resmi saat boot)
- Challenge-response nonce untuk perintah berprivilege, termasuk `reboot` (8042, cadangan triple fault)
- Batas laju 100 datagram/detik, ring log 8 KB, counter di perintah `stats` dan `metrics`

## Build

Kebutuhan: `gcc`, `ld`, `xorriso`, dan Limine di `tools/limine` (binary + protocol headers).

    make iso            # build biasa (task uji ikut jalan, untuk pengembangan)
    make iso PROD=1     # build produksi (task uji dilewati, hanya net + idle)

Flag uji (bisa digabung):

    NOIRQ=1             # jaringan tanpa interrupt E1000 (hanya dibangunkan tiap tick)
    NORDRAND=1          # nonce tanpa rdrand (uji jalur cadangan sumber acak)
    NOKBDRESET=1        # reboot tanpa 8042 (uji jalur cadangan triple fault)

Hasil: `build/bmahOS.iso`.

## Konfigurasi saat ini (hardcode)

- IP: `192.168.50.200` (jaringan VMnet2 host-only VMware)
- Disk FAT32 harus berisi `KEY.TXT` (kunci autentikasi, 16 sampai 64 byte). Tanpa file ini semua
  perintah ditolak. **Jangan commit kunci.** `testdisk/` ada di `.gitignore`.

## Perintah jarak jauh (UDP port 7778)

Semua datagram melewati batas laju global (100 per detik); sisanya dibuang sebelum log dan HMAC.

### Perintah baca (jalur counter)

Datagram: `<counter> <perintah> <hmac-hex-64>`

- `hmac` = HMAC-SHA256 (kunci dari `KEY.TXT`) atas string `<counter> <perintah>`
- `counter` harus lebih besar dari counter terakhir yang diterima (anti-replay)

Perintah: `help`, `ping`, `uptime`, `mem`, `log`, `irq`, `stats`, `metrics`, `mac`, `ip`, `tasks`

`metrics` mengembalikan semua counter dalam format stabil untuk skrip, satu `kunci=nilai` per baris
(uptime, memori, frame RX per jenis, TX ok/gagal, ARP/ICMP/UDP, autentikasi, perintah berprivilege).

### Perintah berprivilege (jalur nonce)

1. Kirim `CHAL`; balasan `nonce: <32 hex>` (16 byte acak dari SHA-256 atas rdrand, TSC, tick, RTC, pool).
2. Kirim `<nonce> <perintah> <hmac-hex-64>`, `hmac` atas string `<nonce> <perintah>`.

Nonce berlaku 5 detik dan sekali pakai; tabel 4 slot (CHAL baru menggusur yang tertua). Nonce dicari
sebelum HMAC dihitung, dan baru dihapus setelah HMAC valid. Karena tabel ada di RAM, datagram yang
direkam sebelum reboot tidak bisa diputar ulang.

Perintah: `pping` (balas `ppong`, untuk uji), `reboot` (balasan dikirim dulu, lalu reset).

Kode tolak (juga dihitung di baris `priv:` perintah `stats`): nonaktif, format, nonce tidak dikenal/
sudah dipakai, kedaluwarsa, hmac salah.

UDP echo tanpa autentikasi ada di port 7777.

Contoh klien (PowerShell) ada di riwayat pengembangan; implementasinya hanya `HMACSHA256` dan `UdpClient`.

## Hardware target (hasil pemeriksaan dari Linux di HP Stream)

- CPU: Intel Celeron N2840
- Jaringan: hanya Wi-Fi Realtek RTL8723BE (PCIe); driver Linux memuat firmware
  `rtlwifi/rtl8723befw_36.bin`. Tidak ada Ethernet kabel
- USB: hanya controller xHCI
- Penyimpanan internal: eMMC (~29 GB), bukan SATA/AHCI
- Akibatnya driver E1000 dan AHCI yang ada sekarang tidak berlaku di hardware asli; yang dibutuhkan
  driver SDHCI (eMMC) dan salah satu dari driver Wi-Fi atau xHCI + USB Ethernet

## Arah berikutnya (belum dikerjakan)

- TCP, lalu CLI interaktif di atasnya dengan autentikasi challenge-response
- SSH hanya dipertimbangkan setelah itu

## Batasan yang diketahui

- Autentikasi hanya menjamin keaslian perintah, bukan kerahasiaan balasan (teks polos)
- Counter anti-replay jalur baca disimpan di RAM; setelah reboot datagram baca lama bisa diputar ulang
  sekali (perintah berprivilege tidak terpengaruh karena memakai nonce)
- Batas laju bersifat global; saat banjir, perintah sah ikut terbuang
- Tabel nonce 4 slot: banjir `CHAL` bisa menggusur nonce klien sah (penolakan layanan ringan)
- Tanpa rdrand, nonce hanya bergantung pada TSC, tick, RTC, dan pool (kualitas entropi belum dinilai)
- Reset lewat ACPI belum ada (FADT belum di-parse)
- GSI interrupt E1000 (19) adalah hasil pengamatan di VMware, bukan nilai universal
- Hanya driver E1000; belum ada driver untuk NIC hardware target
- Belum ada TCP, DHCP, atau IPv6

## Catatan pengembangan

Perubahan dibuat lewat patch Python yang atomik (semua penggantian teks harus cocok persis sekali,
kalau tidak file tidak berubah), diverifikasi dengan `git diff`, build, boot di VMware, dan pengecekan
log serial sebelum commit.
