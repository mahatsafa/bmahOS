# DECISIONS

Format: memilih X karena Y, alternatif Z. Tambahkan di akhir; jangan menulis ulang yang lama.

## 2026-10-09 (catatan awal, dari riwayat proyek)
- **Lisensi MIT** (file LICENSE sejak 3868b98), karena proyek belajar yang ingin mudah dipakai ulang; alternatif GPL/Apache ditolak karena tidak ada kebutuhan paten atau copyleft.
- **Semua perintah jarak jauh lewat nonce (B2)**, jalur counter dimatikan, karena counter dari RTC rawan selisih jam dan tidak tahan replay setelah reboot; alternatif boot-id ditolak (round trip sama + protokol ketiga). `LEGACYCTR=1` menyalakan lagi hanya untuk uji.
- **Tabel nonce 16 slot, maks 4 per IP (M1)**, karena banjir CHAL satu IP tidak boleh menggusur klien sah; alternatif tabel per-IP terpisah ditolak (lebih kompleks). Batas: 16 IP palsu masih bisa menggusur.
- **TCP minimal (C0)**: satu koneksi, stop-and-wait, jendela 1024, MSS 536, RTO tetap, ISN dari SHA-256 pool nonce; alternatif tabel koneksi dan congestion control ditunda karena tujuan awal hanya CLI satu sesi.
- **HP Stream 11 tetap Debian**; bmahOS tidak dipasang di sana (hanya Wi-Fi RTL8723BE, xHCI, eMMC). Target perangkat keras ditetapkan di H0.
- **IoT bukan target**; beban kerja IoT lewat socket API (P5).
- **Kripto**: tidak menulis primitif baru selain SHA-256/HMAC yang sudah ada dan teruji vektor resmi; enkripsi/TLS memakai library teruji (D8).
- **Patch lewat skrip Python atomik** (assert count==1), karena penggantian teks yang tidak cocok harus gagal keras, bukan diam-diam.

## 2026-10-09 (F1.4 pola pemecahan kernel.c)
- **Satu modul = kernel/<nama>.c, deklarasi lintas-modul di kernel/kernel.h** (satu header bersama dulu; dipecah per modul bila membengkak), karena kernel.c memakai banyak helper inline bersama (port I/O, irq_save). Alternatif header per modul sejak awal ditolak: terlalu banyak file sebelum polanya terbukti.
- **Hanya simbol lintas-modul yang kehilangan `static`**; sisanya tetap static di modulnya. Bukti pemindahan murni: baris yang dihapus dari kernel.c harus sama dengan baris di file baru, kecuali `static`.
- **Makefile memakai wildcard kernel/*.c dan objek bergantung pada kernel/*.h.**
- Modul 1 (serial): serial_init/putc/write/write_hex + g_serial_mute pindah ke serial.c; outb/inb/outl/inl dan irq_save/irq_restore (static inline) ke kernel.h; log_capture tetap di kernel.c (non-static) sampai modul log/cmd.
- Modul 2 (cpu): GDT/TSS/IDT (struct gdt_entry/tss/idt_entry, bmahOS_gdt/tss/idt, gdt_init, idt_init, load, dump) pindah ke kernel/cpu.c; tipe struct dan simbol yang dipakai kernel.c (bmahOS_tss.rsp0, bmahOS_gdt, bmahOS_idt, tss_load_asm, tss_read_asm) dideklarasikan di kernel.h. exception_dispatcher/irq_handler dan fungsi trigger_* uji tetap di kernel.c (pindah bersama modul sched/uji). Deteksi simbol lintas-modul memakai skrip (patch_f14_cpu.py) yang mengabaikan komentar dan string.
