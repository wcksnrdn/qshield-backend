# Q-Shield — Threat Model

**Status:** draf untuk direview Filbert Alfredo Saputro
**Versi:** 1.0 — 10 September 2026
**Cakupan:** Q-Shield Layer 1 (ikatan merchant-lokasi) dan Layer 2 (perilaku artefak QR)

Setiap mitigasi di dokumen ini menunjuk ke test yang membuktikannya.
Klaim keamanan tanpa test yang menjalankannya adalah klaim kosong, dan
kolom terakhir di tiap tabel ada supaya itu bisa diperiksa, bukan
dipercaya.

---

## 1. Apa yang Q-Shield lakukan, dan apa yang tidak

Menyebut batasnya lebih dulu mencegah dokumen ini mengklaim wilayah yang
bukan miliknya.

**Yang dilakukan.** Q-Shield adalah lapisan verifikasi kepercayaan
**pra-pembayaran**. Ia menjawab satu pertanyaan sebelum pengguna
memasukkan PIN: apakah artefak QR yang barusan dipindai memang milik
merchant yang seharusnya berada di lokasi ini.

**Yang tidak dilakukan.** Q-Shield bukan sistem pembayaran, tidak
menyentuh dana, tidak memindahkan uang, dan tidak menggantikan
pemeriksaan mana pun yang sudah dilakukan PJP. Ia juga tidak mengubah
standar QRIS maupun perangkat merchant — justru itu prasyarat desainnya.

**Konsekuensi keamanan yang penting:** karena Q-Shield tidak memindahkan
dana, kompromi total terhadapnya **tidak** langsung menyebabkan kerugian
finansial. Yang hilang adalah sinyal peringatan. Ini menurunkan dampak
sebagian besar ancaman di bawah, dan disebut di sini supaya penilaian
risikonya proporsional.

---

## 2. Batas kepercayaan

```
  [Pengguna + kamera HP]           ZONA TIDAK DIPERCAYA
            │                      artefak fisik dikendalikan siapa saja
            │  payload QRIS, lat/lng, accuracy, device_anon_id
            ▼
  ══════════════════════════════   BATAS 1: masuk API
            │                      validasi ketat, rate limit, batas ukuran
            ▼
  [FastAPI /api/v1/verify]         ZONA SEMI-DIPERCAYA
            │                      logika penilaian, tanpa state per-pengguna
            ▼
  ══════════════════════════════   BATAS 2: masuk penyimpanan
            │                      query berparameter, skema tanpa identitas
            ▼
  [SQLite / Postgres]              ZONA DIPERCAYA
            │                      bindings + observations
            ▼
  ══════════════════════════════   BATAS 3: keluar ke log
            │                      audit tanpa PII
            ▼
  [stdout / agregator log]
```

Yang paling menentukan: **Batas 1**. Semua yang datang dari klien —
termasuk koordinat dan `accuracy_m` — adalah klaim, bukan fakta. Server
tidak punya cara memverifikasinya secara independen. Seluruh dokumen ini
berdiri di atas pengakuan itu.

---

## 3. Aset

| # | Aset | Kenapa berharga bagi penyerang | Dampak bila jatuh |
|---|---|---|---|
| A1 | Integritas basis data binding | binding palsu yang terlihat mapan membuat stiker penipu lolos sebagai `verified` | **Tinggi** — inti nilai sistem |
| A2 | Ketersediaan endpoint verifikasi | verifikasi mati = pengguna kembali membayar tanpa perlindungan | Sedang |
| A3 | Privasi lokasi pengguna | data pergerakan bernilai komersial dan berisiko hukum (UU PDP) | **Tinggi** — lihat §7 |
| A4 | Kredibilitas putusan | positif palsu beruntun membuat pengguna mengabaikan peringatan | Sedang-Tinggi |
| A5 | Jejak audit | jejak yang bisa dipalsukan/dihapus menutupi serangan | Sedang |

Perhatikan A4. Sistem anti-fraud yang terlalu sering salah akan
diabaikan, dan pengguna yang mengabaikan peringatan sama tidak
terlindunginya dengan pengguna yang tidak punya sistem sama sekali.
Positif palsu diperlakukan sebagai ancaman keamanan di dokumen ini,
bukan sekadar gangguan UX.

---

## 4. Profil penyerang

| Profil | Kemampuan | Motivasi |
|---|---|---|
| **P1 — Penempel stiker** | akses fisik ke lokasi merchant, printer, HP biasa | mengalihkan pembayaran ke rekeningnya |
| **P2 — Penipu terkoordinasi** | P1 + banyak perangkat, banyak lokasi, mampu skrip | mencemari basis data agar stikernya terlihat sah |
| **P3 — Penyerang teknis** | akses API langsung, mampu memalsukan permintaan, mock location, perangkat di-root | membobol atau memutarbalikkan logika penilaian |
| **P4 — Penguntit privasi** | akses baca ke basis data atau log (orang dalam, atau lewat kebocoran) | merekonstruksi pergerakan orang |
| **P5 — Perusak** | akses API, tanpa target finansial | membuat sistem tidak berguna atau tidak dipercaya |

---

## 5. Ancaman, mitigasi, dan buktinya

### 5.1 Terhadap integritas binding (A1)

| # | Ancaman | Aktor | Mitigasi | Bukti |
|---|---|---|---|---|
| T1 | Sticker swap: stiker penipu menutupi yang asli | P1 | Konflik NMID di jangkar mapan → `anomaly`, bobot berskala dengan jumlah pengamat | `test_adversarial.py` "Sticker swap di jangkar mapan"; `test_invariants.py` #5 |
| T2 | Swap sambil menggeser titik GPS agar jatuh di sel geohash lain | P1, P3 | Jangkar ditentukan **jarak haversine**, bukan kesamaan sel; indeks presisi 7 + 8 tetangga mencakup 100% radius 100 m | `test_adversarial.py` (60 posisi dalam radius 45 m, nol lolos); `test_invariants.py` #1 |
| T3 | Membangun reputasi dengan memindai stiker sendiri berulang kali | P2 | Pemindaian `anomaly` tidak pernah dicatat sebagai observation | `test_invariants.py` #3 (8x); `test_adversarial.py` (25x) |
| T4 | Priming pelan di lokasi kosong lalu klaim `verified` | P2 | Butuh `MIN_OBSERVERS`=3 **dan** `MIN_AGE_HOURS`=24; status tetap `unknown` sampai keduanya terpenuhi | `test_adversarial.py` (30 device boneka) |
| T5 | Ketiadaan bukti dikonversi jadi kepercayaan | P2 | `unknown` tidak pernah menghasilkan `proceed`, dijaga struktural di `_floor_action()` | `test_invariants.py` #2 |
| T6 | Stiker dicetak ulang dengan CRC yang benar | P1, P3 | CRC valid tidak menyelamatkan; jangkar yang menangkap. Layer 2 menambah deteksi kontradiksi struktural | `test_adversarial.py` "CRC ditambal"; "NMID dipalsukan" |
| T7 | Payload dibangkitkan ulang oleh generator penyerang | P3 | Sinyal struktural Layer 2: QR statis membawa nominal, tag wajib hilang, NMID cacat bentuk — 0 positif palsu dari 20.000 payload sah | `calibrate_layer2.py` bagian 3 |

### 5.2 Terhadap ketersediaan (A2)

| # | Ancaman | Aktor | Mitigasi | Bukti |
|---|---|---|---|---|
| T8 | Payload raksasa menghabiskan CPU parser | P3, P5 | Badan permintaan dipotong 8 KB di lapisan HTTP; payload dibatasi 1024 karakter. 8 MB kini ditolak 43 ms (sebelumnya 1.890 ms) | `test_hardening.py` "Payload kebesaran" |
| T9 | Banjir permintaan | P3, P5 | Rate limit jendela geser, bawaan 60/menit per klien | `test_hardening.py` "Rate limit menahan banjir" |
| T10 | Penghitung rate limit sendiri jadi jalur kehabisan memori | P5 | `MAX_TRACKED_KEYS` + pemangkasan kunci kedaluwarsa | `limits.py:_prune` |

### 5.3 Terhadap kredibilitas putusan (A4)

| # | Ancaman | Aktor | Mitigasi | Bukti |
|---|---|---|---|---|
| T11 | Meracuni jangkar merchant jujur agar skornya naik (DoS reputasi) | P5 | `repeated_anomaly_at_anchor` dimatikan bila yang memindai adalah merchant **mapan** di jangkar itu; "mapan" diambil dari putusan Layer 1 | `test_adversarial.py` "Meracuni jangkar merchant jujur" |
| T12 | Merchant bersebelahan saling memicu alarm | — (bukan serangan, tapi merusak A4) | Koeksistensi dibedakan dari penggantian: bila keduanya mapan dan aktif → `adjacent_merchant`, bobot ringan | `test_invariants.py` #7 (jarak 5-35 m) |
| T13 | Putusan palsu dari GPS yang tidak layak dipercaya | P3 | `accuracy_m` > 100 m → menolak memberi putusan lokasi, `unknown` + alasan eksplisit | `test_invariants.py` #6 |
| T14 | Sinyal yang menandai merchant sah sebagai penyerang | — | Konstanta wajib punya dasar empiris; sinyal yang gagal kalibrasi dibuang, bukan dipaksakan | `calibrate_layer2.py` — sinyal lonjakan pemindaian dibuang |

### 5.4 Terhadap privasi (A3)

| # | Ancaman | Aktor | Mitigasi | Bukti |
|---|---|---|---|---|
| T15 | Basis data dipakai merekonstruksi pergerakan orang | P4 | Tidak ada `user_id` di skema mana pun; `observations` tidak menyimpan koordinat. Yang disimpan **ikatan**, bukan **kunjungan** | `test_invariants.py` #8 |
| T16 | Jejak audit membocorkan apa yang tidak dibocorkan skema | P4 | Log tidak pernah memuat `device_anon_id`, koordinat presisi, IP, atau payload mentah. Lokasi dicatat sebagai sel ~152 m | `test_hardening.py` "Audit log tidak memuat identitas" |
| T17 | Alamat IP tersimpan lewat rate limiter | P4 | Kunci = hash SHA-256 terpotong, hanya di memori, hilang saat jendela lewat | `test_hardening.py` "Rate limit tidak menyimpan alamat IP" |
| T18 | Agregat Layer 2 diam-diam memperkenalkan pelacakan | P4 | Agregat menempel pada baris **binding**, bukan device: hitungan dan waktu, bukan siapa | `test_invariants.py` #8 (skema diperiksa ulang tiap run) |

### 5.5 Terhadap batas masuk (semua aset)

| # | Ancaman | Aktor | Mitigasi | Bukti |
|---|---|---|---|---|
| T19 | SQL injection lewat `device_anon_id` atau payload | P3 | Seluruh query berparameter; `device_anon_id` dibatasi `^[A-Za-z0-9_-]+$` | `test_hardening.py` "charset aman" |
| T20 | Karakter kendali / null byte menembus parser atau basis data | P3 | `payload` dibatasi ASCII yang bisa dicetak di batas sistem | `test_hardening.py` "Karakter kendali" |
| T21 | Situs pihak ketiga memanggil API dari browser korban | P3 | CORS dibatasi daftar origin lewat env; tidak lagi `["*"]` | `test_hardening.py` "CORS tidak lagi terbuka" |
| T22 | Tanggapan API di-embed / di-sniff tipe kontennya | P3 | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` | `test_hardening.py` "Header keamanan" |
| T23 | Nilai numerik ekstrem (`1e300`, NaN) merusak perhitungan | P3 | `lat`/`lng`/`accuracy_m` dibatasi rentang; NaN/inf ditolak lapisan JSON | `test_hardening.py` "accuracy_m punya batas atas" |
| T24 | Mode replay demo dipakai membobol invarian | P3 | `location_source` hanya melabeli, tidak mengubah penilaian; tidak bisa memaksa `verified` dari GPS buruk; default `live` | `test_hardening.py` empat pemeriksaan mode replay |

---

## 6. Risiko residual — yang belum ditahan

Bagian ini sengaja ditulis selengkap bagian mitigasi. Batasan yang
diketahui dan diakui jauh lebih tidak berbahaya daripada batasan yang
disembunyikan, dan `test_adversarial.py` menguji sistem agar tidak
diam-diam mengklaim bisa menahan hal-hal di bawah ini.

| # | Risiko residual | Kenapa belum ditahan | Rencana | Dampak nyata |
|---|---|---|---|---|
| R1 | **Mock location / GPS palsu** | Server tidak bisa memverifikasi koordinat yang diklaim klien | Deteksi integritas perangkat; butuh SDK native | Terbatas: spoof **tidak** memberi keuntungan untuk NMID yang bukan milik penyerang — swap tetap tertangkap (diuji) |
| R2 | **Replay QR dinamis** | Tidak ada pelacakan nonce per transaksi; butuh keterlibatan PJP | Di luar jangkauan lapisan pra-pembayaran | Sistem tidak mengklaim bisa (diuji) |
| R3 | **Merchant berjarak <15 m** | Presisi GPS tidak cukup memisahkan | Ambient WiFi fingerprinting; tidak tersedia lewat browser | Ditangani sebagian oleh `adjacent_merchant` |
| R4 | **Cold start** | Basis data kosong tidak punya bukti apa pun | Pendaftaran mandiri merchant | Ditangani jujur: `unknown`, bukan `verified` |
| R5 | **Merchant sah pindah lokasi** | Relokasi tidak bisa dibedakan dari swap tanpa konfirmasi | Jalur konfirmasi merchant | Memicu peringatan sekali (diuji) |
| R6 | **Merchant keliling** | Model jangkar mengasumsikan lokasi tetap | Penandaan khusus saat pendaftaran | Belum ditangani sama sekali |
| R7 | **Sidik jari encoding belum tervalidasi lapangan** | Belum punya korpus payload QRIS asli dari berbagai acquirer | Kumpulkan korpus | Bobot kecil dan dibatasi bersama; tidak pernah bisa menggerakkan tier sendirian |
| R8 | **Rate limit per-IP kasar di balik NAT** | Satu alamat mewakili banyak perangkat | Rate limit per `device_anon_id` sebagai lapis tambahan | Bawaan longgar; bisa dimatikan untuk demo |
| R10 | **Penyerang yang menang balapan cold start** | **Dimitigasi sebagian.** `ADJACENT_MIN_RATIO` = 0,10 menuntut basis pengamat sebanding sebelum pengecualian koeksistensi berlaku; serangan modal minimum (3 device) tidak lagi lolos. Penyerang yang mengeluarkan >5 device masih lolos | Penutupan penuh lewat R1 atau R9 | Sedang — biaya penyerang naik, celah belum tertutup |
| R9 | **Belum ada autentikasi klien** | PoC; endpoint terbuka | API key / mTLS per PJP sebelum produksi | Siapa pun bisa mengirim pengamatan — jalur pencemaran basis data yang paling lebar saat ini |

### Proposal untuk R10 — belum diterapkan, butuh keputusan tim

**Jalur eksploitasinya.** Penyerang menempel stiker di merchant **baru**
yang jangkarnya belum terbentuk, lalu memupuknya dengan 3 device selama
24 jam — semuanya sah menurut aturan, karena belum ada konflik. Begitu
merchant sungguhan ikut mapan, keduanya dianggap koeksistensi dan
**stiker palsu jadi `verified` secara permanen.**

Yang sudah aman: jangkar yang korbannya **sudah** mapan tidak bisa
dibajak lewat API sama sekali. Diuji — 10 pemindaian dari 10 device
menghasilkan nol binding, karena anomali tidak pernah dicatat
(Keputusan 7). Jendela serangannya khusus periode cold start (R4).

**Kenapa tidak langsung ditambal.** Perbaikan yang jelas — menuntut
jarak minimum antar-jangkar sebelum sesuatu disebut "bersebelahan" —
menyentuh invarian §7, dan invarian tidak diubah tanpa persetujuan tim.
Lebih dari itu, perbaikan naif justru berbahaya: galat GPS membuat dua
lapak yang benar-benar bersebelahan kadang tercatat berjarak <5 m, jadi
ambang jarak yang terlalu ketat akan menandai ruko dan food court sah
sebagai serangan — merusak aset A4, persis yang dicegah Keputusan 5.

**Tiga opsi, sudah dikalibrasi** (`scripts/calibrate_adjacency.py`):

**Opsi A — koeksistensi menghasilkan `unknown`, bukan `verified`.**
Terukur sebagai yang **paling mahal**, dan ini membatalkan dugaan awal
kami. Karena `ANCHOR_RADIUS_M` = 50 m, apa pun yang berada dalam radius
itu memicu `adjacent_merchant` — bukan cuma lapak yang benar-benar
berdempetan:

| Tata letak | Jarak | Pemindaian sah yang turun ke `warn` |
|---|---|---|
| warung soliter | — | 0,0% |
| ruko 4 pintu | 8 m | 100,0% |
| pertokoan jalan | 20 m | 100,0% |
| pujasera kecil | 4 m | 100,0% |
| food court mall | 3 m | 100,0% |
| pasar tradisional | 2,5 m | 100,0% |

Artinya **setiap** pemindaian di area komersial mana pun berakhir
`warn`. Itu menghancurkan aset A4: peringatan yang selalu muncul adalah
peringatan yang diabaikan. **Opsi A ditolak.**

**Opsi B — jarak minimum antar-jangkar.** Gugur secara empiris. Koordinat
jangkar ditetapkan dari pengamatan pertama, jadi galat GPS satu pembacaan
(sigma ~8 m) melekat permanen padanya. Sebaran jarak jangkar untuk swap
di titik yang sama dan untuk merchant yang benar-benar bersebelahan
tumpang tindih hampir sempurna justru di jarak yang paling penting:

| Jarak nyata | Jangkar merchant sah (p10-p90) | Jangkar swap | Tumpang tindih |
|---|---|---|---|
| 2,5 m | 3,2-18,1 m | 2,8-17,6 m | 79,1% |
| 4 m | 3,5-18,6 m | 2,8-17,6 m | 78,0% |
| 8 m | 5,0-21,4 m | 2,8-17,6 m | 71,9% |
| 15 m | 8,7-26,6 m | 2,8-17,6 m | 48,7% |
| 25 m | 16,7-36,5 m | 2,8-17,6 m | 11,8% |

Ini batasan R3 yang muncul lagi, bukan parameter yang bisa disetel.
**Opsi B ditolak.**

**Opsi C — pengecualian koeksistensi menuntut basis pengamat yang
sebanding.** Merchant yang benar-benar bersebelahan menghisap lalu lintas
kaki yang sama, jadi jumlah pengamatnya sepadan. Penyerang yang memupuk 3
device di sebelah merchant 47 pengamat tidak. Aturannya perbandingan,
bukan jarak — sehingga tata letak padat tidak tersentuh sama sekali:

| Rasio | Pasangan merchant sah tertolak | Device yang harus dikeluarkan penyerang |
|---|---|---|
| 0,00 (sekarang) | 0,0% | 3 |
| 0,05 | 0,8% | 3 |
| **0,10** | **3,5%** | **5** |
| 0,15 | 7,3% | 8 |
| 0,25 | 13,6% | 12 |
| 0,40 | 23,9% | 19 |

**Diterapkan: opsi C dengan rasio 0,10** (`binding.ADJACENT_MIN_RATIO`),
disetujui tim 10 September 2026. Biaya 3,5% pada pasangan
merchant sah — dan itu pun hanya berlaku pada pasangan yang sama-sama
sudah mapan, bukan pada seluruh pemindaian seperti opsi A.

**Kejujuran yang harus disampaikan bersama angka ini:** opsi C
**menaikkan biaya** penyerang, tidak menutup celahnya. Penyerang yang mau
mengeluarkan lebih banyak device tetap lolos. Yang berubah adalah
serangan 3-device yang murah jadi tidak lagi cukup. Penutupan sungguhan
menuntut R1 (integritas perangkat) atau R9 (autentikasi klien) — dan itu
memang jawaban yang benar untuk pertanyaan ini.

**R9 adalah risiko terbuka terbesar saat ini** dan sengaja ditaruh
terakhir agar tidak tenggelam. Rate limiting memperlambat pencemaran
basis data, tapi tidak menghentikan penyerang yang sabar. Autentikasi
klien adalah prasyarat produksi, bukan penyempurnaan.

---

## 7. Analisis privasi

Sistem yang mengumpulkan lokasi saat orang bertransaksi bisa dengan mudah
menjadi alat pelacakan berkedok anti-fraud. Tidak ada PJP yang berani
memakainya, dan tidak seharusnya ada.

Tiga properti yang membuat Q-Shield tidak bisa dipakai begitu, dan
semuanya bersifat **struktural** — bukan kebijakan yang bisa dicabut
diam-diam:

1. **Tidak ada `user_id` di skema mana pun.** Bukan "tidak dipakai",
   melainkan tidak ada kolomnya.
2. **`observations` tidak menyimpan koordinat.** Tabel itu hanya
   menghubungkan binding dengan `device_anon_id`. Tanpa koordinat per
   pengamatan, tidak ada deret waktu-tempat yang bisa dirangkai.
   Koordinat hanya ada pada `bindings`, yaitu properti lokasi **merchant**.
3. **Agregat Layer 2 menempel pada binding, bukan device.** Konsekuensi
   yang diterima sadar: Q-Shield tidak bisa mendeteksi perjalanan
   mustahil per perangkat.

Kalimat yang meringkas seluruhnya: **yang disimpan adalah ikatan, bukan
kunjungan.**

Konsekuensi regulasi. Karena tidak ada data pribadi yang tersimpan,
berbagi data binding antar-PJP tidak menyentuh kerahasiaan bank maupun
UU PDP — dan justru berbagi itulah yang membuat lapisan ini bekerja,
karena stiker penipu tidak berhenti di batas satu penyelenggara.

**Cara membuktikannya, bukan mengklaimnya.** `test_invariants.py` #8
membaca skema langsung lewat `PRAGMA table_info` setiap kali dijalankan
dan gagal kalau ada kolom beraroma identitas atau koordinat di
`observations`. `test_hardening.py` melakukan hal setara untuk log.
Pertanyaan "bagaimana kalian membuktikan tidak menyimpan identitas
pengguna" dijawab dengan menjalankan dua berkas itu.

---

## 8. Yang harus dikerjakan sebelum produksi

Diurutkan berdasarkan risiko, bukan usaha.

1. **Autentikasi klien** (R9) — prasyarat, bukan penyempurnaan
2. **Deteksi integritas perangkat** (R1) — menutup jalur pencemaran terkuat
3. **Migrasi ke Postgres** — SQLite tidak menangani tulis serentak dari banyak proses
4. **Jalur konfirmasi merchant** (R5, R6) — dibutuhkan sebelum merchant sah kena imbas
5. **Kalibrasi lapangan seluruh parameter** — nilai sekarang titik awal demo, bukan hasil data nyata
6. **Rotasi dan retensi log** — jejak audit tumbuh tanpa batas
7. **Korpus payload QRIS asli** (R7) — memvalidasi sinyal sidik jari encoding

---

## 9. Catatan untuk review

Filbert — tiga hal yang paling perlu pandangan kedua:

1. **§6 R9 (belum ada autentikasi klien).** Apakah penilaian dampaknya
   sudah tepat, dan apakah rate limiting cukup sebagai mitigasi sementara
   untuk demo?
2. **§6 R10.** Pertanyaan ini sudah diuji dan jawabannya: jangkar yang
   korbannya sudah mapan **tidak** bisa dibajak lewat API, tapi penyerang
   yang menang balapan cold start lolos sebagai "merchant bersebelahan".
   Yang perlu pandangan kedua adalah pilihan A vs B dan biaya opsi A.
3. **§6 R10.** Opsi C rasio 0,10 sudah diterapkan dan diuji. Yang tersisa:
   apakah biaya penyerang ">5 device" cukup untuk demo, atau perlu
   dinaikkan ke 0,15 (7,3% positif palsu / 8 device) sebelum onsite?

4. **§7.** Argumen privasi ini yang akan dipakai menjawab pertanyaan
   Kaspersky. Apakah ada celah yang bisa dibantah?
