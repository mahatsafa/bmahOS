# bmahOS

Sistem operasi eksperimental x86_64 yang ditulis dari nol (freestanding, UEFI via Limine).
Dikembangkan dan diuji di VMware Workstation, dengan uji otomatis di QEMU (`make test`).
Belum pernah diuji di hardware asli.

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
- PCI: AHCI dan E1000 dicari otomatis (kelas/vendor/device ID), bukan alamat bus tetap
- Storage: AHCI (baca blok), FAT32 (baca file, root directory), `spawn()` program dari disk
- Jaringan (NIC Intel 82545EM / E1000 emulasi VMware): TX/RX ring, ARP, IPv4, ICMP echo, UDP
- Interrupt RX E1000 via IOAPIC (GSI INTx ditemukan lewat eksperimen), net task tidur sampai ada paket
- Task idle (`hlt`), build produksi tanpa task uji
- Perintah jarak jauh terautentikasi HMAC-SHA256 (SHA-256/HMAC ditulis sendiri, self-test vektor resmi saat boot)
- Challenge-response nonce untuk perintah berprivilege, termasuk `reboot` (register reset ACPI dari
  FADT, lalu 8042, lalu cadangan triple fault)
- Batas laju 100 datagram/detik, ring log 8 KB, counter di perintah `stats` dan `metrics`

## Build

Kebutuhan: `gcc`, `ld`, `xorriso`, dan Limine 12.5.2 di `tools/limine` (`tools/` tidak ikut git):

    git clone --depth=1 --branch=v12.5.2 https://github.com/Limine-Bootloader/Limine.git tools/limine
    cd tools/limine && ./bootstrap && ./configure && make && cd ../..

Build:

    make iso            # build biasa (task uji ikut jalan, untuk pengembangan)
    make iso PROD=1     # build produksi (task uji dilewati, hanya net + idle)

Flag uji (bisa digabung):

    NOIRQ=1             # jaringan tanpa interrupt E1000 (hanya dibangunkan tiap tick)
    NORDRAND=1          # nonce tanpa rdrand (uji jalur cadangan sumber acak)
    NOKBDRESET=1        # reboot tanpa 8042 (uji jalur cadangan triple fault)
    NOACPIRESET=1       # reboot tanpa register reset ACPI (uji jalur 8042)

Hasil: `build/bmahOS.iso`.

## Uji otomatis (QEMU)

    make test           # build lalu jalankan tests/qemu-smoke.sh
    make test PROD=1    # flag build lain juga bisa dipakai

Kebutuhan tambahan: QEMU (`qemu-system-x86_64` atau `qemu-kvm`), OVMF (`edk2-ovmf`), `mkfs.vfat`
(`dosfstools`), `mcopy` (`mtools`), `python3`. KVM tidak wajib (tanpa KVM lebih lambat).

Skrip membuat disk FAT32 sementara dengan `KEY.TXT` acak (bukan kunci asli), boot ISO di QEMU q35
dengan E1000 + AHCI, lalu memeriksa: self-test crypto, deteksi PCI, kunci dimuat, `ping`/`uptime`/
`metrics`, kunci salah dan replay ditolak, `pping` berprivilege, `reboot` lewat reset ACPI, dan log
tanpa exception. Semua file uji ada di `build/test/`.

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

### Klien: `client/bmctl.py`

Python 3 tanpa pustaka tambahan (Windows dan Linux). File kunci berisi sama dengan `KEY.TXT`.

    python client/bmctl.py --key ~/bmahos-key.txt uptime
    python client/bmctl.py --key ~/bmahos-key.txt metrics
    python client/bmctl.py --key ~/bmahos-key.txt --priv pping
    python client/bmctl.py --key ~/bmahos-key.txt --priv reboot

Alamat default `192.168.50.200:7778` (ubah dengan `--host`/`--port` atau `BMAHOS_HOST`/`BMAHOS_PORT`).
Jalur baca memakai counter = waktu Unix dalam milidetik. Kode keluar: 0 sukses, 1 balasan `ERR`,
2 tidak ada balasan.

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
- Reset ACPI hanya mendukung register reset di ruang I/O (umum: port `0xCF9`); ruang memori/PCI
  belum, reboot lalu memakai 8042
- GSI interrupt E1000 (19) adalah hasil pengamatan di VMware, bukan nilai universal
- Hanya driver E1000 (device ID `0x100F` 82545EM dan `0x100E` 82540EM yang sudah diuji); belum ada
  driver untuk NIC hardware target
- Hanya controller AHCI pertama yang dipakai
- Belum ada TCP, DHCP, atau IPv6

## Catatan pengembangan

Perubahan dibuat lewat patch Python yang atomik (semua penggantian teks harus cocok persis sekali,
kalau tidak file tidak berubah), diverifikasi dengan `git diff`, build, `make test`, boot di VMware,
dan pengecekan log serial sebelum commit.

## Lisensi

MIT, lihat [LICENSE](LICENSE). Limine (di `tools/limine`, tidak ikut repo) memakai lisensinya sendiri.
