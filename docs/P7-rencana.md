# P7 OTA A/B: rencana desain (disetujui pengguna 2026-11-02)

Tujuan: kernel baru dikirim lewat jaringan, ditulis ke slot yang tidak aktif, dicoba, lalu dikukuhkan bila
sehat atau dikembalikan otomatis ke slot lama bila crash berulang. Syarat R5 (watchdog) dan D6 (FAT32 tulis)
sudah ada.

## Keputusan (semua pilihan A)

1. **Tanda tangan**: ECDSA P-256 + SHA-256 dari BearSSL (sudah di kernel, tanpa library baru).
   Penandatanganan di CentOS dengan `openssl` (`tools/ota-sign.py`).
2. **Kunci**: build dev memakai kunci uji yang di-commit (make test dan CI bisa menandatangani);
   build PROD memakai kunci asli: kunci publik di-commit, kunci privat hanya di CentOS `~/bmahos-ota/`
   (tidak pernah ke shared folder). Image dev tidak bisa dipasang di PROD. CI PROD hanya menguji penolakan.
3. **Pemilihan slot**: boot dari disk. Disk berisi `EFI/BOOT/BOOTX64.EFI`, `limine.conf`, `KERNA.ELF`,
   `KERNB.ELF`. `limine.conf` tepat 512 byte (diisi baris komentar `#`), kernel berganti slot dengan menimpa
   satu sektor itu (atomik, entri direktori/LFN tidak disentuh). Tiap entri `cmdline: slot=A|B`. ISO tetap
   ada sebagai penyelamat manual. Risiko: EFI VMware mungkin tidak boot dari FAT32 tanpa tabel partisi;
   dicek di P7-0, cadangannya MBR + offset partisi di fat32.c.
4. **Slot**: `KERNA.ELF`/`KERNB.ELF` 1 MB tetap, dibuat dari host, ditimpa per sektor seperti LOG.BIN (R4);
   batas peta file (64 KB) dinaikkan. Status di `OTA.BIN` (512 byte): slot aktif, slot coba, sisa percobaan,
   versi + sha256 per slot. File kiriman `.bmo` = header (magic, jenis kernel/app, versi, ukuran, sha256)
   + isi + tanda tangan atas header.
5. **Pengiriman**: perintah admin `ota terima <jenis> <ukuran> <sha256>` (TLS 7780 atau TCP 7779) membuka
   port TCP 7781 sekali pakai, 60 s, hanya IP sesi admin itu; data mentah ke RAM, cek tanda tangan, tulis
   slot, baca balik + cek sha256. Klien `bmctl.py --ota` dan `bmota` (bmtcp.ps1).
6. **Boot percobaan**: `ota coba` -> OTA.BIN {coba, sisa=3} + `default_entry` slot baru + reboot. Kernel
   slot coba, tepat setelah FAT32 terpasang: sisa=0 -> kembalikan limine.conf ke slot lama + reboot
   (rollback), selain itu sisa-1. Sehat = 60 s tanpa panic/watchdog, net task jalan, port CLI/TLS siap ->
   dikukuhkan otomatis; `ota sah` lebih cepat, `ota batal` membatalkan. Versi < slot aktif ditolak
   (versi = `git rev-list --count`). Celah: crash sebelum FAT32 terpasang = boot berulang; jalan keluar
   menu Limine (timeout 3 s) atau ISO (dicatat di THREAT_MODEL).
7. **APP.BIN** memakai format `.bmo` yang sama, wajib bertanda tangan di dev dan PROD (THREAT_MODEL 23);
   tanpa tanda tangan ditolak + satu baris serial. APP.BIN di disk.vmdk diganti lewat `ota terima app`.

## Sub-langkah (commit terpisah, masing-masing diuji)

- **P7-0** uji boot dari disk di QEMU dan VMware (tanpa kode kernel): limine.conf 512 byte, `cmdline slot=`,
  boot order .vmx lewat skrip.
- **P7-1a** refactor: peta file besar + baca cmdline Limine.
- **P7-1** `kernel/ota.c`: parser header + verifikasi ECDSA, `tools/ota-sign.py`, host-test + target fuzz.
- **P7-2** `ota terima` + port 7781 + tulis slot + `ota status` + klien.
- **P7-3** boot percobaan, penghitung, rollback, pengukuhan; `tests/qemu-ota.sh` (boot dari disk): B sehat
  dikukuhkan, B rusak (flag uji panic dini) kembali ke A setelah 3 kali.
- **P7-4** APP.BIN bertanda tangan; uji VMware penuh; PROTOCOL/THREAT_MODEL/DECISIONS; centang P7 -> M-B.
