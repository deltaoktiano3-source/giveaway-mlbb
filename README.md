# Giveaway MLBB — backend starter

Ini adalah starter project backend yang dapat dijalankan lokal dan dikembangkan untuk deployment.

## Menjalankan secara lokal
1. Pasang Node.js 20 atau lebih baru.
2. Ekstrak folder project.
3. Salin `.env.example` menjadi `.env`.
4. Isi `SESSION_SECRET` dengan string acak panjang (minimal 32 karakter), `ADMIN_EMAIL`, dan `ADMIN_PASSWORD` unik.
5. Jalankan `npm install`.
6. Jalankan `npm start`.
7. Buka `http://localhost:3000`.

Admin dibuat otomatis saat server pertama kali dijalankan berdasarkan `ADMIN_EMAIL` dan `ADMIN_PASSWORD` di `.env`. Jangan gunakan password contoh.

## Fitur backend
- SQLite untuk pengguna, hadiah, klaim, dan sesi.
- Password akun website di-hash dengan bcrypt.
- Session cookie HttpOnly, SameSite=Lax, Secure saat production.
- Proteksi CSRF token untuk request perubahan data.
- Rate limiting login/registrasi/klaim.
- Peran admin diperiksa di backend.
- Klaim unik per pengguna dan hadiah.
- Admin dapat melihat klaim dan menyetujui/menolak melalui API.
- Email notifikasi admin opsional melalui SMTP; password/OTP/token tidak pernah dimasukkan ke email.
- CAPTCHA hCaptcha diverifikasi di backend jika secret dikonfigurasi; wajib di production.

## Sebelum online/production
- Gunakan HTTPS dan host yang mendukung Node.js.
- Set `NODE_ENV=production`, `SESSION_SECRET`, CAPTCHA keys, dan SMTP credentials di environment variables hosting.
- Atur domain, HTTPS, reverse proxy, backup database, log, monitoring, dan kebijakan retensi data.
- Gunakan SMTP provider tepercaya dan verifikasi domain pengirim.
- Uji pemulihan password, verifikasi email, audit log, kebijakan privasi, syarat giveaway, dan prosedur sengketa sebelum menerima pengguna sungguhan.
- Periksa batasan/ketentuan layanan game dan jangan menjanjikan transfer akun jika tidak diizinkan oleh penyedia game.
- Starter ini belum menyediakan upload file gambar; gunakan URL HTTPS gambar yang sudah di-host. Jangan izinkan upload arbitrer tanpa validasi file dan batas ukuran.
- Untuk produksi skala besar, gunakan PostgreSQL, store sesi terkelola, migrasi database, dan review keamanan profesional.

## Catatan CAPTCHA
Frontend starter ini belum menyematkan widget hCaptcha karena site key bersifat konfigurasi. Tambahkan widget resmi ke form, kirim token hasilnya sebagai `captchaToken` ke endpoint `/api/login` dan `/api/register`. Server sudah menolak token kosong ketika secret tersedia. Jangan menganggap checkbox visual sebagai CAPTCHA sungguhan.

## Catatan privasi
Email admin ada di konfigurasi server `.env` dan tidak ditampilkan pada halaman publik. Jangan pernah mengirim password, kode OTP, session cookie, API key, atau token ke administrator lewat email.
