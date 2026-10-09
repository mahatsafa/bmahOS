# Berkontribusi ke bmahOS

Proyek belajar OS x86_64 dari nol. Baca dulu `ROADMAP.md` (urutan tahap) dan `THREAT_MODEL.md` (aturan bagian 7).

## Aturan singkat
- Satu tahap = satu commit (atau beberapa commit kecil milik tahap itu). Refactor dan fitur tidak digabung.
- Setiap perubahan menambah uji di `make test`; harus hijau pada build default dan `make test PROD=1`.
- Semua panjang dari luar divalidasi sebelum dipakai; setiap tabel/buffer punya batas dan perilaku saat penuh; gagal tertutup.
- Jangan menulis primitif kripto baru. Jangan commit kunci (`KEY.TXT`, `key.txt`).
- Pesan commit jujur soal apa yang sudah dan belum terbukti (QEMU/VMware).

## Membangun dan menguji
    make iso            # build dev
    make iso PROD=1     # build produksi
    make test           # 3 boot QEMU, kunci uji acak

Kebutuhan uji: QEMU, OVMF (edk2-ovmf), dosfstools, mtools, python3. Detail di README.md.

## Lisensi
MIT (lihat LICENSE). Dengan berkontribusi, kamu setuju kontribusimu berlisensi sama.
