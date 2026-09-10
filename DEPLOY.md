# Q-Shield — Deployment & Rencana Migrasi Basis Data

**Status:** P2, rencana. Yang berjalan sekarang adalah SQLite.

---

## 1. Kenapa masih SQLite, dengan angkanya

Handoff meminta "rencana migrasi SQLite → Postgres **atau** justifikasi
tertulis kenapa tetap SQLite". Ini justifikasinya, dan dasarnya ukuran,
bukan selera.

| Beban | Hasil |
|---|---|
| 60 permintaan HTTP serentak (1 proses, threadpool) | 0 galat, hitungan tepat |
| 200 permintaan HTTP serentak | 0 galat, ~142 permintaan/detik |
| 12 proses × 200 tulis serentak | 2400/2400 konsisten, ~2.800 tulis/detik |
| 20 proses × 200 tulis serentak | 4000/4000 konsisten, ~3.000 tulis/detik |

Kebutuhan panggung 3 Oktober: dua sampai tiga ponsel. Marginnya ratusan
kali lipat. **Untuk demo, SQLite bukan kompromi — ia lebih dari cukup,
dan nol proses tambahan yang bisa mati di depan juri.**

Angka-angka itu baru benar setelah tiga perbaikan yang tercatat di
`PROCESS-LOG.md`: `record()` dibuat atomik (Keputusan 21), urutan
`PRAGMA busy_timeout` dibetulkan, dan retry terbatas saat inisialisasi
dingin. Sebelum itu, 25 dari 60 permintaan serentak gagal.

### Batas yang sebenarnya

Yang akan memaksa pindah **bukan** kecepatan:

1. **Berbagi data antar-PJP.** Ini inti proposisi nilai Q-Shield —
   stiker penipu tidak berhenti di batas satu penyelenggara. Berbagi
   menuntut basis data yang bisa dijangkau banyak pihak lewat jaringan.
   SQLite adalah berkas di satu mesin. **Ini alasan utamanya.**
2. **Ketersediaan.** Satu berkas di satu mesin tidak punya replika,
   tidak punya failover.
3. **Operasional.** Backup panas, point-in-time recovery, kontrol akses
   per-peran — semuanya bawaan Postgres, semuanya kerja tangan di SQLite.
4. **Penulis lintas mesin.** Serialisasi penulis masih ~3.000/detik,
   tapi itu berlaku per berkas, bukan per klaster.

---

## 2. Rencana migrasi

### 2.1 Yang sudah siap dipindah

Skema sengaja dibuat portabel sejak awal: tidak ada fitur khusus SQLite
selain tipe kolom, tidak ada trigger, tidak ada view.

| SQLite | Postgres |
|---|---|
| `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGSERIAL PRIMARY KEY` |
| `TEXT` untuk waktu (ISO-8601 UTC) | `TIMESTAMPTZ` |
| `REAL` | `DOUBLE PRECISION` |
| `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` | **identik** |
| `INSERT OR IGNORE` | `INSERT ... ON CONFLICT DO NOTHING` |
| `INSERT OR REPLACE` (`seed_binding`) | `INSERT ... ON CONFLICT DO UPDATE` |
| `PRAGMA table_info` (di migrasi & test) | `information_schema.columns` |

Upsert atomik di `record()` sudah memakai sintaks standar yang sama —
itu bukan kebetulan, dan itulah alasan Keputusan 21 dikerjakan lebih
dulu, terpisah dari pertanyaan basis data.

### 2.2 Yang harus berubah di kode

Semuanya terkurung di `store.py`; `binding.py` dan `behavior.py` tidak
mengimpor `store.py`, jadi seluruh logika penilaian tidak tersentuh.

1. **Ganti koneksi tunggal + `RLock` dengan connection pool.**
   `RLock` melindungi satu koneksi sqlite3 bersama. Postgres butuh pool
   (`psycopg_pool`), dan kuncinya dilepas. Ini perubahan terbesar.
2. **Hilangkan `BEGIN IMMEDIATE`.** Ganti dengan transaksi biasa;
   upsert-nya sudah atomik tanpa itu.
3. **Placeholder `?` → `%s`.**
4. **`_migrate()` dan `_migrate_device_ref()`** diganti alat migrasi
   sungguhan (Alembic), bukan `ALTER TABLE` bersyarat.
5. **`PRAGMA` dibuang**, diganti setelan koneksi pool.

### 2.3 Perpindahan data

Basis data demo tidak perlu dipindah — `seed.py` membuatnya ulang.
Untuk data lapangan nanti:

1. `QSHIELD_DEVICE_SALT` **harus ikut dipindahkan.** Kalau garamnya
   berubah, seluruh `device_ref` lama tidak lagi cocok dan setiap
   perangkat yang pernah tercatat akan terhitung sebagai pengamat baru
   — `observer_count` menggelembung dan status `verified` jadi palsu.
   Ini butir paling mudah dilupakan dalam migrasi ini.
2. Salin `bindings` lebih dulu, `observations` menyusul (kunci asing).
3. Verifikasi dengan menjalankan `tests/test_invariants.py` terhadap
   basis data hasil migrasi — terutama invarian #8, yang menjalankan
   serangan perangkaian jejak.

### 2.4 Kapan

Setelah code freeze 30 September dan setelah onsite. Melakukannya
sebelum itu menambah satu proses yang bisa gagal di panggung, dan
tidak menyelesaikan satu pun masalah yang kita punya hari ini.

---

## 3. Secrets

| Nama | Sifat | Kalau bocor | Kalau hilang |
|---|---|---|---|
| `QSHIELD_API_KEYS` | hash sha256, bukan kunci mentah | tidak langsung bisa dipakai | terbitkan ulang per PJP |
| kunci API mentah | dipegang PJP | penyerang bisa memanggil API atas nama PJP itu | terbitkan ulang |
| `QSHIELD_DEVICE_SALT` | **rahasia sungguhan** | mempermudah pengujian keberadaan perangkat yang pengenalnya sudah diketahui | **hitungan pengamat rusak** — lihat 2.3 |

Aturan yang berlaku sekarang:

- Kunci mentah tidak pernah disimpan Q-Shield di mana pun, dan tidak
  pernah masuk log — bahkan saat autentikasi gagal.
- `config.py` tidak pernah mencetak nilai rahasia; hanya panjang dan
  sidik jari 8 karakter, cukup untuk memastikan dua mesin memakai nilai
  yang sama tanpa menuliskannya.
- Garam yang tidak disetel dibangkitkan sekali lalu disimpan di basis
  data. Aman untuk satu mesin; **dua instans yang berbagi basis data
  wajib memakai `QSHIELD_DEVICE_SALT` yang sama secara eksplisit.**

Menuju produksi: pindahkan keduanya ke secret manager, jangan ke berkas
`.env` yang ikut ter-commit. `.gitignore` sudah mengecualikan
`venue.json` dan basis data, tapi tidak ada yang mencegah seseorang
membuat `.env` — itu disiplin, bukan kontrol.

---

## 4. Menjalankan dengan container

```bash
docker build -t qshield:0.1.0 .
docker run --rm -p 8000:8000 \
  -e QSHIELD_API_KEYS="pjp-alpha:<sha256>" \
  -e QSHIELD_DEVICE_SALT="<garam>" \
  -v "$PWD/data:/data" \
  qshield:0.1.0
```

Atau `docker compose up`.

Yang disengaja pada image-nya:

- **Berjalan sebagai pengguna non-root.** Proses yang tidak butuh root
  tidak boleh punya root.
- **Tidak ada secret yang dipanggang ke dalam image.** Semuanya lewat
  env saat run; image boleh dibagikan, konfigurasinya tidak.
- **Basis data di volume**, bukan di lapisan image — supaya data tidak
  hilang saat image diperbarui.
- **Healthcheck menunjuk `/api/v1/health`**, endpoint yang memang
  terbuka tanpa autentikasi untuk keperluan ini.
- **Tidak ada `--reload`.** Itu untuk pengembangan.

### Apa yang sudah diverifikasi, dan apa yang belum

**Belum diverifikasi:** image-nya sendiri belum pernah di-`docker build`
— daemon Docker tidak berjalan di mesin tempat ini ditulis. Anggap
Dockerfile-nya belum teruji sampai ada yang membangunnya.

**Sudah diverifikasi**, dengan menjalankan jalur yang sama tanpa Docker:

- `pip install .` dari repo bersih menghasilkan paket yang lengkap —
  kesepuluh modul `qshield` terimpor
- `uvicorn qshield.api:app` menyala dan melayani
- perintah `HEALTHCHECK` dijalankan apa adanya → `200`
- autentikasi aktif dengan env sungguhan: tanpa kunci `401`, dengan
  kunci lolos
- audit log keluar ke stdout tanpa tertahan buffer

Yang tersisa untuk diuji setelah daemon-nya hidup: build image-nya,
lalu ulangi empat pemeriksaan di atas dari dalam container.

### Untuk demo 3 Oktober

**Jangan pakai container.** Jalankan langsung dengan `uvicorn` di
laptop, seperti selama ini. Docker menambah satu lapis yang bisa gagal
pagi hari-H, dan tidak memberi satu pun keuntungan di panggung.
Container ada di sini untuk menunjukkan kesiapan produksi kepada juri,
bukan untuk dipakai di depan mereka.
