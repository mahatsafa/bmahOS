#ifndef BMAHOS_SSH_H
#define BMAHOS_SSH_H

#include <stdint.h>

// ---- ssh.c (F7 SSH-1a: inti transport SSH-2 sisi server, mesin keadaan murni) ----
// Tanpa I/O: pemanggil (net task, SSH-1b) menyuap byte TCP dengan ssh_feed() dan
// mengirim byte keluar dari ssh_out_peek()/ssh_out_consume(). Primitif dari BearSSL.
// Profil: kex curve25519-sha256, kunci host ecdsa-sha2-nistp256, cipher
// aes128-gcm@openssh.com (chacha20-poly1305 TIDAK ada: lihat ssh.c), tanpa kompresi.

#define SSH_MAX_SESS     2        // = batas TCB port 22
#define SSH_PKT_MAX      35000    // packet_length maksimum (RFC 4253 6.1)
#define SSH_IBUF_SIZE    (SSH_PKT_MAX + 4 + 16 + 24)   // 4 panjang + 16 tag + sisa banner
#define SSH_OBUF_SIZE    4096
#define SSH_OUT_RESERVE  1024     // ruang keluar minimum agar satu paket masuk diproses
#define SSH_AUTH_MAX     4        // percobaan userauth sebelum DISCONNECT
#define SSH_UNIMPL_MAX   16       // UNIMPLEMENTED per sesi sebelum DISCONNECT
#define SSH_PKT_LIMIT    (1u << 28)   // paket per arah sebelum DISCONNECT
#define SSH_BYTE_LIMIT   (1ull << 30) // byte per arah sebelum DISCONNECT

// ssh_state()
#define SSH_ST_FREE      0   // slot kosong
#define SSH_ST_VERSION   1   // menunggu baris versi klien
#define SSH_ST_KEX       2   // pertukaran kunci (KEXINIT .. NEWKEYS klien)
#define SSH_ST_SERVICE   3   // kunci aktif, menunggu SERVICE_REQUEST
#define SSH_ST_AUTH      4   // ssh-userauth diterima (userauth = SSH-2)
#define SSH_ST_CLOSING   5   // selesai/gagal: kirim sisa keluaran lalu tutup

// ssh_open(): kode gagal
#define SSH_ERR_FULL     (-1)   // slot habis
#define SSH_ERR_NOKEY    (-2)   // kunci host belum dimuat
#define SSH_ERR_ENTROPY  (-3)   // entropi belum cukup (gagal tertutup)

// Kunci host: DER SEC1/PKCS#8 EC P-256. Return 1 bila sah (kunci, blob K_S, fingerprint
// siap), 0 bila tidak (kunci lama dihapus). Buffer der dipakai tanpa diubah.
int ssh_load_key(const uint8_t *der, uint32_t len);
int ssh_key_loaded(void);
const char *ssh_fingerprint(void);   // "SHA256:<base64 tanpa =>", "" bila belum dimuat
void ssh_unload_key(void);           // nolkan kunci host (uji)

int ssh_open(void);                  // slot (>= 0) atau SSH_ERR_*; banner + KEXINIT sudah di antrean keluar
// Suap masukan; return byte yang dikonsumsi. Keluaran hampir penuh (< SSH_OUT_RESERVE
// kosong) -> 0 (backpressure, pemanggil mengirim ulang nanti). len=0 (d boleh 0) hanya
// melanjutkan pemrosesan sisa di buffer masuk (panggil setelah ssh_out_consume()).
uint32_t ssh_feed(int s, const volatile uint8_t *d, uint32_t len);
const uint8_t *ssh_out_peek(int s, uint32_t *len);
void ssh_out_consume(int s, uint32_t n);
void ssh_close(int s);               // nolkan seluruh slot (kunci sesi, buffer)
int ssh_state(int s);
const char *ssh_why(int s);          // alasan penutupan ("" bila belum)
int ssh_done(int s);                 // 1: CLOSING dan keluaran sudah habis -> tutup TCP
int ssh_cipher_active(int s);        // 1 bila kunci cipher keluar sudah aktif (uji/metrik)

#endif
