# SIMPAN P3K Bali

Aplikasi pemantauan layanan P3K untuk Dinas Kesehatan Provinsi Bali. Satu halaman web (`index.html`) dengan backend serverless di folder `api/`, data tersimpan di Upstash Redis. Tidak ada proses build dan tidak ada dependensi npm.

## Isi proyek

- `index.html` : tampilan aplikasi
- `api/[action].js` : API (login, laporan, verifikasi, password, log)
- `lib/p3k.js` : fungsi bantu (Redis, sesi, hash password, pembatas percobaan login)
- `vercel.json` : header keamanan (CSP, X-Frame-Options, dll.)
- `.env.example` : daftar environment variable

## Deploy ke Vercel

1. Taruh folder ini di repositori GitHub (bisa lewat upload di situs GitHub dari HP), lalu di vercel.com pilih Add New > Project > import repositori. Framework Preset: **Other**. Build command dan output directory dikosongkan.
   Alternatif lewat terminal (Termux/PC): `npm i -g vercel`, masuk ke folder proyek, jalankan `vercel` lalu `vercel --prod`.
2. Buka proyek di Vercel > tab **Storage** > buat database **Upstash Redis** (Marketplace) dan hubungkan ke proyek. Vercel otomatis mengisi `KV_REST_API_URL` dan `KV_REST_API_TOKEN`. Pilih region database yang dekat (misalnya Singapura).
3. Settings > **Environment Variables**, tambahkan:
   - `SESSION_SECRET` : string acak min. 32 karakter. Buat dengan `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
   - `INIT_PASSWORD` : password awal sementara yang kuat untuk semua wilayah
   - `RECOVERY_CODE` : kode pemulihan akun Provinsi
4. Deploy ulang (Deployments > Redeploy) supaya variable terbaca. Untuk kecepatan, atur Settings > Functions > Function Region ke Singapore (sin1) agar dekat dengan Bali.

## Login pertama

1. Login sebagai **Provinsi Bali** dengan `INIT_PASSWORD`. Aplikasi memaksa ganti password. Pilih password kuat.
2. Beri tiap kabupaten/kota `INIT_PASSWORD` (lewat telepon/WA resmi). Saat login pertama mereka wajib mengganti password, dan selama belum diganti mereka tidak bisa mengirim laporan.
3. Setelah semua wilayah mengganti password, `INIT_PASSWORD` boleh diubah atau dihapus. Hanya wilayah yang belum pernah mengganti password yang terpengaruh.

Jika `INIT_PASSWORD` tidak diisi, password lama masih diterima satu kali (dicek di server) lalu wajib diganti. Cara ini kurang aman karena hash lama pernah terlihat di kode sumber versi sebelumnya. Isi `INIT_PASSWORD`.

## Keamanan yang sudah ada

- Password disimpan di server dengan scrypt + salt. Tidak ada hash atau password di kode yang dikirim ke browser.
- Sesi memakai cookie HttpOnly, Secure, SameSite=Strict, kedaluwarsa 15 menit tanpa aktivitas, maksimum 12 jam.
- Hak akses dicek di server: kabupaten hanya bisa membaca, mengirim, dan menghapus laporan sendiri. Hanya Provinsi yang bisa verifikasi, reset password, dan melihat log.
- Pembatas percobaan login di server (5x salah = kunci 30 detik per IP dan wilayah, plus batas per wilayah), pembatas permintaan reset dan kode pemulihan.
- Validasi semua input laporan di server. Log aktivitas ditulis server, tidak bisa dipalsukan dari browser.

## Catatan pemakaian

- Data diperbarui otomatis tiap 30 detik saat tab terbuka, dan langsung setelah aksi sendiri. Ini menjaga pemakaian Upstash tetap rendah (paket gratis punya batas perintah per bulan).
- Data ada di Upstash Redis. Ekspor CSV rutin lewat menu Unduh sebagai cadangan.
- Password lama yang lupa: wilayah kabupaten minta reset lewat "Lupa password?", Provinsi membuat password sementara di tab Reset Password. Provinsi yang lupa memakai `RECOVERY_CODE`.

## Menjalankan lokal

Buat file `.env.local` dari `.env.example`, isi nilai Upstash (salin dari dashboard Vercel/Upstash), lalu `npx vercel dev`.
