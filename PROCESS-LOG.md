# Q-Shield — Process Log

Catatan keputusan desain, temuan, dan alasan di baliknya.
Ditulis berurutan supaya jejak berpikirnya bisa ditelusuri.

**Tim:** Satria Ardan Wicaksono, Vyone Louis, Filbert Alfredo Saputro
**Kompetisi:** HackNusa 2026 — track Secure Digital Payments & Fintech

---

## Ringkasan celah yang ditangani

> QRIS memverifikasi rekening merchant yang tertanam dalam sebuah kode,
> tetapi tidak ada lapisan mana pun dalam stack yang memverifikasi ikatan
> antara rekening itu, artefak fisik yang menampilkannya, dan lokasi
> tempat artefak itu dipasang.

Konsekuensinya: stiker QRIS palsu adalah payload yang **sah secara sintaksis**.
CRC-nya valid, formatnya benar, nama merchant bisa ditiru persis. Tidak ada
yang bisa membedakannya dari yang asli tanpa mengetahui merchant mana yang
seharusnya berada di lokasi itu — dan tidak ada satu pihak pun yang saat ini
memegang informasi tersebut.

---

## Arsitektur

```
Next.js (scanner, UI)  ──HTTP──>  FastAPI  ──>  SQLite / Postgres
                                     │
                                     ├── qshield/emvco.py     parser payload
                                     ├── qshield/geo.py       geohash + jarak
                                     ├── qshield/binding.py   Layer 1 + komposisi
                                     ├── qshield/behavior.py  Layer 2
                                     └── qshield/store.py     persistensi
```

Logika penilaian sengaja dipisah dari database (`binding.py` dan
`behavior.py` tidak mengimpor `store.py`) supaya bisa diuji tanpa I/O dan
supaya aturan bisa dibaca sebagai satu berkas utuh. `behavior.py` menerima
agregat lewat `AnchorState`, bukan lewat query — alasan yang sama.

Backend disusun sebagai package src-layout (`src/qshield/`) yang di-install
lewat `pip install -e .`, dipisah dari `scripts/` (skrip yang dijalankan
langsung: seed data, kalibrasi) dan `tests/` (test_*.py, dijalankan langsung
tanpa pytest).

---

## Keputusan 1 — Jangkar ditentukan oleh jarak, bukan kesamaan geohash

**Rancangan awal:** simpan `geohash_8` sebagai jangkar; dua pemindaian
dianggap satu lokasi kalau geohash-nya sama.

**Masalah yang ditemukan saat pengujian:** pergeseran 20 meter mengubah
geohash-8 pada **81,9%** kasus. Penyebabnya sel presisi 8 hanya berukuran
±38 × 19 meter, sehingga titik di dekat tepi sel jatuh ke sel berbeda.
Akibatnya binding tidak pernah terakumulasi — dan seluruh mekanisme
konsensus mandul.

**Pengujian lanjutan** (`calibrate_geo.py`) mengukur cakupan tiap presisi
terhadap radius pencarian:

| radius | presisi 6 | presisi 7 | presisi 8 |
|---|---|---|---|
| 30 m | 100% | 100% | 96,9% |
| 50 m | 100% | 100% | 78,9% |
| 100 m | 100% | 100% | 43,1% |

**Keputusan:** geohash presisi 7 (±152 × 153 m) dipakai **hanya sebagai
indeks query**; kecocokan jangkar ditentukan oleh jarak haversine dengan
radius 50 m. Presisi 7 ditambah 8 sel tetangganya terbukti mencakup 100%
titik dalam radius 100 m.

**Catatan:** radius 50 m adalah kompromi, bukan nilai benar. Terlalu ketat
membuat binding tidak terakumulasi karena galat GPS; terlalu longgar
membuat merchant bersebelahan tercampur. Nilai final semestinya
dikalibrasi dari data lapangan.

---

## Keputusan 2 — Tiga status, dan "belum dikenal" bukan "aman"

Sistem tidak pernah menyatakan sebuah binding aman hanya karena belum ada
konflik. Statusnya:

| Status | Arti |
|---|---|
| `verified` | cukup pengamat independen, konsisten lintas waktu |
| `unknown` | belum cukup bukti — jujur, dan tetap berguna |
| `anomaly` | terdeteksi konflik |

Ini menjawab masalah *cold start*. Hari pertama sistem berjalan, database
kosong, dan menyatakan "aman" akan berbahaya. Analogi yang dipakai:
antivirus tidak mengklaim berkas tak dikenal itu bersih.

Pemindaian di lokasi tak dikenal menghasilkan `unknown` + `warn`, bukan
`proceed`. Pengguna berhak tahu bahwa lokasi belum terverifikasi.

---

## Keputusan 3 — Empat tingkat friksi, bukan blokir biner

| Skor | Aksi |
|---|---|
| 0–25 | `proceed` |
| 26–50 | `warn` |
| 51–75 | `step_up` |
| 76–100 | `cooling_off` |

Alasannya bukan teknis melainkan ekonomis: false positive pada sistem
pembayaran itu mahal. Pengguna yang transaksinya diblokir tanpa alasan akan
berhenti memakai fiturnya, dan itu justru merusak inklusi keuangan — hal
yang seharusnya dilindungi.

*Cooling-off* dipilih sebagai respons risiko tertinggi karena seluruh modus
rekayasa sosial bergantung pada tekanan waktu. Menunda lebih efektif
daripada menolak.

---

## Keputusan 4 — Bobot sinyal berskala dengan kekuatan bukti

Awalnya konflik NMID diberi bobot datar (+70). Pengujian menunjukkan ini
keliru: konflik pada binding dengan 47 pengamat adalah bukti jauh lebih
kuat daripada konflik pada binding yang baru mencapai ambang minimum,
tetapi keduanya menghasilkan aksi yang sama.

Sekarang bobotnya `60 + min(25, observer_count // 2)`. Binding 47 pengamat
menghasilkan skor 83 (*cooling-off*); binding 3 pengamat menghasilkan 61
(*step-up*).

---

## Keputusan 5 — Membedakan merchant bersebelahan dari pertukaran stiker

**Masalah:** dua merchant sah berjarak 8 meter (ruko, food court) saling
memicu alarm. Ini akan menghancurkan kepercayaan pada sistem.

**Wawasan:** pertukaran stiker berarti binding lama **berhenti terlihat**
dan yang baru muncul. Kalau dua NMID sama-sama mapan dan sama-sama masih
aktif di jangkar yang sama, itu koeksistensi.

**Implementasi:** bila NMID yang dipindai juga sudah `is_established`,
sinyal berubah dari `nmid_changed_at_anchor` menjadi `adjacent_merchant`
dengan bobot jauh lebih ringan (+20, bukan +85).

Ini batas nyata pendekatan GPS-only, dan alasan teknis mengapa
*ambient WiFi fingerprinting* diperlukan menuju MVP.

---

## Keputusan 6 — Privasi tertanam di skema, bukan di kebijakan

Sistem mengumpulkan lokasi pengguna saat bertransaksi. Tanpa desain yang
hati-hati, ini menjadi alat pelacakan berkedok anti-fraud — dan tidak ada
penyelenggara jasa pembayaran yang berani memakainya.

Yang diterapkan:

- **Tidak ada `user_id` di skema mana pun.**
- Tabel `observations` **tidak menyimpan koordinat**, sehingga tidak dapat
  dipakai merekonstruksi pergerakan seseorang. Koordinat hanya ada pada
  binding, yaitu properti lokasi merchant.
- `device_anon_id` hanya untuk menghitung pengamat unik, bukan identitas.
- Yang disimpan adalah **ikatan**, bukan **kunjungan**.

> **Koreksi (Keputusan 24).** Klaim "tidak dapat dipakai merekonstruksi
> pergerakan" pada butir kedua di atas **tidak benar** sampai 10
> September 2026. `observations` memang tidak menyimpan koordinat, tapi
> ia menyimpan `device_anon_id` apa adanya — dan satu JOIN ke `bindings`
> memulihkan koordinat lengkap beserta urutan waktunya. Lihat
> Keputusan 24 untuk perbaikannya.

Desain ini juga yang memungkinkan berbagi data antar-PJP tanpa melanggar
kerahasiaan bank maupun UU PDP.

---

## Keputusan 7 — Anomali tidak membangun reputasi

Pemindaian yang menghasilkan `anomaly` **tidak dicatat** sebagai pengamatan.
Tanpa aturan ini, penyerang bisa mencemari basis data dengan memindai
stikernya sendiri berulang kali sampai binding palsu terlihat mapan.

Diuji: 5 pemindaian anomali berturut-turut tidak menambah satu pun binding.

---

## Keputusan 8 — Akurasi GPS diperiksa sebelum dipercaya

Bila `accuracy_m > 100`, verifikasi lokasi dilewati dan sistem mengembalikan
`unknown` + `warn` dengan alasan eksplisit. Lebih baik mengaku tidak tahu
daripada memberi keputusan berdasarkan jangkar yang tidak dapat dipercaya.

---

## Keputusan 9 — Layer 2 adalah jalur QR, bukan transfer manual

Dokumen fase 1 memakai istilah "Layer 2" untuk dua hal yang berbeda.
PDF dan catatan ini menyebutnya *behavioral scoring untuk transfer
manual* — modus rekayasa sosial yang tidak melibatkan QR sama sekali.
Handoff fase 2 menyebutnya sinyal *perilaku transaksi/QR* yang menyatu
dengan putusan Layer 1.

Keduanya sistem yang berbeda. Yang berbasis transfer manual tidak punya
payload maupun jangkar untuk dinilai, jadi aturan "melengkapi, bukan
menggantikan putusan Layer 1" tidak berlaku untuknya — tidak ada putusan
Layer 1 ketika tidak ada QR.

**Keputusan:** Layer 2 = jalur QR. Alasannya bukan cuma kemudahan:
lapisan ini pra-pembayaran, dan pada transfer manual tidak ada artefak
yang bisa diperiksa sebelum korban menekan kirim. Menilai rekening tujuan
adalah pekerjaan PJP dengan data yang tidak kami punya.

Scoring transfer manual tetap di peta jalan, dan sekarang disebut dengan
namanya sendiri supaya tidak tertukar lagi.

---

## Keputusan 10 — Layer 2 hanya boleh menaikkan risiko

Layer 1 menjawab "apakah merchant ini yang seharusnya ada di lokasi ini".
Layer 2 menjawab "apakah artefak yang dipindai berperilaku seperti QR yang
sah". Dua pertanyaan berbeda yang bisa gagal sendiri-sendiri: stiker palsu
di lokasi yang belum punya jangkar lolos Layer 1, tapi payload-nya sering
mengkhianati dirinya sendiri.

Aturan komposisinya (`binding.compose`) ada tiga, dan ketiganya searah:

1. Skor dijumlah lalu dijepit 0-100. **Tidak ada satu pun bobot negatif di
   `behavior.py`.** Tidak adanya sinyal Layer 2 bukan bukti keabsahan —
   logika yang persis sama dengan Keputusan 2.
2. Layer 2 tidak pernah bisa menaikkan status ke arah `verified`. Ia hanya
   menurunkan: kontradiksi struktural jadi `anomaly`; sinyal lain apa pun
   menurunkan `verified` jadi `unknown`, karena jangkarnya boleh jadi benar
   tapi artefaknya diragukan. Status `anomaly` dari Layer 1 tidak pernah
   dicabut Layer 2.
3. Aksi tetap dipetakan ke empat tier lewat ambang yang sama. Layer 2 tidak
   memperkenalkan skala baru.

Diuji sebagai serangan tersendiri: payload yang sempurna bersih tidak
menurunkan skor Layer 1 dan tidak mencabut `anomaly`.

---

## Keputusan 11 — Layer 2 mengingat jangkar, bukan orang

Sinyal perilaku terkuat biasanya butuh riwayat per-perangkat: kecepatan
pemindaian, perjalanan mustahil, pola percobaan. Semuanya menuntut hal
yang sengaja tidak disimpan sejak Keputusan 6 — koordinat per pengamatan.

Yang dipilih: agregat menempel pada baris **binding**, bukan pada device.
Isinya hitungan dan waktu, bukan siapa. Tidak ada baris per-device baru,
tidak ada koordinat tambahan, tidak ada yang bisa dirangkai jadi jejak
seseorang. Invarian privasi bertahan bukan karena kebijakan, tapi karena
datanya memang tidak ada.

Konsekuensinya jujur: Q-Shield tidak bisa mendeteksi perjalanan mustahil
per perangkat. Itu harga yang dibayar sadar.

**`anomaly_attempts` dan Keputusan 7.** Counter ini naik saat sebuah
jangkar jadi sasaran pemindaian yang ditolak — dan itu tidak melanggar
"anomali tidak membangun reputasi". Bedanya penting: `observer_count`
tidak disentuh, tidak ada observation yang dicatat, dan angkanya **hanya
pernah menaikkan risiko, tidak pernah menurunkan**. Anomali tetap tidak
bisa membangun reputasi; yang bisa ia bangun hanyalah kecurigaan.

**Jalur serangan yang ditutup di sini.** Counter yang menaikkan risiko
sebuah jangkar adalah senjata bermata dua: penyerang bisa memakainya untuk
menyerang merchant jujur, cukup dengan menempel stiker palsu berkali-kali
di depan warung korban sampai skornya naik. Karena itu sinyalnya dimatikan
ketika yang memindai adalah merchant yang **sudah mapan di jangkar itu** —
dan "mapan" diambil dari putusan Layer 1, bukan dari tebakan siapa binding
dominan. Bedanya nyata di food court: jangkar dominan bisa milik Toko A,
tapi pelanggan Toko B yang sama-sama mapan berhak tidak ikut kena sinyal
serangan yang ditujukan ke tetangganya. Diuji: setelah 15 serangan ke
jangkar Toko A, kedua merchant sah tetap `proceed` dengan skor Layer 2 nol.

---

## Keputusan 12 — "Unknown" ternyata masih bisa berarti "proceed"

Ditemukan saat menulis regression test untuk invarian, bukan saat menulis
fitur. Kodenya melanggar keputusannya sendiri.

Keputusan 2 menyatakan pemindaian yang belum terverifikasi menghasilkan
`unknown` + `warn`, bukan `proceed`. Kenyataannya hanya pemindaian
**pertama** yang begitu (+35 → `warn`). Begitu binding punya satu
pengamatan, sinyalnya berganti jadi `young_binding` dengan bobot +15 —
dan 15 jatuh di tier `proceed`.

Yang membuatnya serius: **jalurnya dikendalikan penyerang.** Memindai
stiker sendiri satu kali menurunkan skor dari 35 ke 15, dan sejak itu QR
yang sama sekali belum terverifikasi dilewatkan tanpa friksi.

**Perbaikan:** dijaga struktural di ujung `evaluate()` dan `compose()` —
status `unknown` tidak pernah menghasilkan `proceed`, berapa pun skornya.
Bukan lewat penyetelan bobot, supaya sinyal baru mana pun tidak bisa
membuka lagi celah yang sama.

Pelajarannya: invarian yang hanya hidup di dokumen bukan invarian. Yang
mengubahnya jadi invarian sungguhan adalah `tests/test_invariants.py`.

---

## Keputusan 13 — Sinyal lonjakan pemindaian dibuang setelah dikalibrasi

Sinyal ini sempat ditulis: lonjakan pemindaian di satu jangkar dianggap
mencurigakan. `scripts/calibrate_layer2.py` membatalkannya.

Membangun reputasi palsu butuh `MIN_OBSERVERS` = 3 device berbeda **dan**
rentang `MIN_AGE_HOURS` = 24 jam. Artinya serangannya pelan, bukan
meledak — puncaknya 3 pemindaian per jendela.

| ambang | positif palsu (merchant sah) | deteksi serangan |
|---|---|---|
| 5 | 100,0% | 0,0% |
| 30 | 100,0% | 0,0% |
| 120 | 1,8% | 0,0% |

Tidak ada satu pun ambang yang berguna. Ambang yang cukup rendah untuk
menangkap serangan menandai 100% warung laris; ambang yang bisa ditoleransi
warung laris melewatkan 100% serangan. Volume pemindaian memang tidak
memisahkan penyerang dari merchant sibuk.

**Keputusan:** sinyalnya dibuang, kolom `scan_window_*` ikut dibuang dari
skema. Pertahanan yang benar untuk probing otomatis adalah rate limiting —
kontrol akses, bukan skor risiko. Dicatat di sini supaya tidak ada yang
menambahkannya kembali dengan niat baik.

Yang lolos kalibrasi: 20.000 payload sah dan bervariasi menghasilkan **0
positif palsu** struktural. Itu memang diharapkan — sinyal struktural
menguji kontradiksi terhadap spec, bukan kemiripan statistik.

---

## Keputusan 14 — Parameter cetak QR juga dikalibrasi

Prop fisik adalah titik kegagalan yang gampang dilupakan: QR yang cantik di
layar bisa gagal dibaca kamera di atas kertas, di bawah lampu ruangan.

Tebakan awal — koreksi galat `H` karena stiker tercetak kena lipatan dan
pantulan — **keliru, dan `H` justru yang paling buruk.** Payload QRIS
sepanjang ~150 karakter memaksa `H` naik ke versi 10 (57x57 modul), dan
kerapatan itu merugikan lebih besar daripada untung koreksinya.

| EC | versi | modul | terbaca |
|---|---|---|---|
| L | 5 | 37 | 16/18 |
| M | 6 | 41 | 16/18 |
| Q | 8 | 49 | **16/18** |
| H | 10 | 57 | 11/18 |

`Q` dipilih: skor puncak dengan koreksi galat tertinggi di antara yang
seri. Sembilan kondisi diuji — diperkecil, diburamkan, dimiringkan,
diredupkan, diberi derau. Lima berstatus wajib; kegagalan pada "miring 25
derajat" sengaja tidak dijadikan syarat karena itu batas detektor OpenCV,
sedangkan pemindai HP tinggal digeser penggunanya.

---

## Keputusan 15 — Pengerasan diukur dulu, baru ditambal

Permukaan serangan diperiksa sebelum satu baris pun ditulis. Yang
ditemukan, dan semuanya nyata:

| Titik | Kondisi awal |
|---|---|
| panjang payload | tanpa batas — 16 MB menghabiskan ~1,9 detik CPU sebelum ditolak |
| `accuracy_m` | tanpa batas atas, `1e300` diterima |
| `device_anon_id` | menerima null byte, path traversal, string SQL |
| CORS | `allow_origins=["*"]` |
| header keamanan | tidak ada satu pun |
| rate limit | tidak ada; 200 permintaan beruntun semuanya lolos |

Batas payload **1024 karakter** punya dasar ukur, bukan tebakan: QR demo
148-158 karakter, QR yang dimuati semaksimal mungkin tapi masih sah 503.
Badan permintaan dipotong lebih awal lagi di 8 KB pada lapisan HTTP —
payload 8 MB kini ditolak dalam 43 ms, bukan 1.890 ms.

**Rate limiting adalah utang dari Keputusan 13.** Waktu sinyal "lonjakan
pemindaian" dibuang, alasannya: volume permintaan itu urusan kontrol
akses, bukan skor risiko. Berkas `limits.py` yang membayar utang itu.

Penghitungnya dikunci pada hash terpotong dari alamat IP, hanya hidup di
memori proses, dan tidak pernah masuk basis data maupun log. Invarian §8
berlaku untuk seluruh sistem, bukan cuma untuk tabel.

Batasan yang diakui: penguncian per-IP itu kasar. Di balik NAT — persis
situasi WiFi acara — seluruh ruangan terlihat sebagai satu alamat. Karena
itu bawaannya longgar (60/menit) dan ada `QSHIELD_RATE_LIMIT=off`.
Menolak permintaan juri di tengah demo jauh lebih mahal daripada
melayani beberapa probe berlebih.

---

## Keputusan 16 — Audit mencatat putusan, bukan siapa yang memindai

Satu baris JSON per putusan. Yang dicatat: `nmid`, nama merchant,
`geohash_7`, verdict, action, skor, sinyal, rincian layer, `accuracy_m`,
`location_source`, `processing_ms`.

Yang **tidak pernah** dicatat, beserta alasannya:

| Tidak dicatat | Alasan |
|---|---|
| `device_anon_id` | dipakai menghitung pengamat unik (Keputusan 6); menuliskannya ke log membangun jejak yang justru dihindari skemanya |
| koordinat presisi | bisa merekonstruksi posisi pemindai |
| alamat IP | lihat `limits.py` — tidak pernah keluar dari memori |
| payload mentah | memuat identitas merchant lengkap, tidak dibutuhkan untuk audit putusan |

Lokasi dicatat sebagai sel geohash presisi 7 (~152 m): cukup untuk
menelusuri jangkar mana yang terlibat, terlalu kasar untuk menunjukkan
seseorang berdiri di mana.

Diuji eksplisit di `test_hardening.py` — skema yang bersih tidak ada
gunanya kalau log-nya bocor.

---

## Keputusan 17 — Jalur cadangan demo mengaku dirinya replay

Ini bukan bagian dari produk, tapi ini yang menentukan apakah juri
melihat produknya bekerja.

Jangkar Q-Shield terikat koordinat spesifik, jadi seluruh seed lama tidak
relevan begitu pindah venue. Lebih buruk lagi, GPS di dalam gedung kerap
melaporkan akurasi >100 m — dan invarian §6 akan menolak memberi putusan.
Sistemnya benar, tapi demonya mati.

`scripts/venue_fixture.py` merekam koordinat di luar gedung pagi hari-H,
lalu memutar ulang naskah demo dari rekaman itu. Perintah `record`
**menolak** menyimpan rekaman dengan akurasi >100 m — rekaman seperti itu
tidak akan berguna, dan lebih baik ketahuan pagi-pagi daripada di depan
juri.

**Yang diputar ulang ditandai eksplisit sebagai replay** — di permintaan
(`location_source`), di tanggapan, di alasan paling depan, dan di jejak
audit. Penilaiannya tidak berubah sedikit pun, dan mode ini tidak bisa
dipakai membobol invarian akurasi GPS. Keduanya diuji.

Alasannya bukan teknis melainkan strategis: replay yang disamarkan seolah
live adalah kebohongan kecil yang akan dicium juri, dan sekali ketahuan,
seluruh klaim lain ikut diragukan. Mengakuinya justru menguatkan —
menolak memberi putusan saat sinyal buruk memang fitur, bukan bug, dan
demo yang jujur soal batasnya adalah demo yang argumennya konsisten.

---

## Keputusan 18 — Threat model, dan satu celah yang ditemukan saat menulisnya

`THREAT-MODEL.md` menyusun batas kepercayaan, aset, profil penyerang, dan
24 ancaman — masing-masing menunjuk ke test yang membuktikan mitigasinya.
Klaim keamanan tanpa test yang menjalankannya adalah klaim kosong, dan
kolom terakhir tiap tabel ada supaya itu bisa diperiksa, bukan dipercaya.

Menulisnya menghasilkan satu temuan yang tidak muncul saat menulis fitur.
Pertanyaan yang semula hanya hendak diajukan ke Filbert — "bisakah
penyerang membuat NMID-nya sendiri jadi mapan di jangkar korban?" —
ternyata punya dua jawaban.

**Yang aman:** jangkar yang korbannya sudah mapan tidak bisa dibajak
lewat API sama sekali. Diuji: 10 pemindaian dari 10 device menghasilkan
**nol** binding, karena anomali tidak pernah dicatat (Keputusan 7).

**Yang bocor (R10):** kalau penyerang menang balapan *cold start* —
menempel stiker di merchant baru yang jangkarnya belum terbentuk, lalu
memupuknya dengan 3 device selama 24 jam — maka begitu merchant sungguhan
ikut mapan, aturan `adjacent_merchant` (Keputusan 5) menganggap keduanya
koeksistensi **tanpa memeriksa jarak antar-jangkar**. Jarak 0 m pun
lolos, dan stiker palsu jadi `verified` permanen.

Alasannya tidak ditambal langsung: perbaikan yang jelas menyentuh
invarian §7, dan invarian tidak diubah tanpa persetujuan tim. Lebih dari
itu, perbaikan naif justru berbahaya — galat GPS membuat dua lapak yang
benar-benar bersebelahan kadang tercatat berjarak <5 m, jadi ambang jarak
yang terlalu ketat akan menandai ruko sah sebagai serangan, persis yang
dicegah Keputusan 5.

Dua opsi beserta rekomendasi ada di `THREAT-MODEL.md` §6. Ringkasnya:
koeksistensi sebaiknya menghasilkan `unknown`, bukan `verified` — kalau
dua merchant mapan berbagi satu jangkar, sistem memang tidak tahu stiker
mana yang sedang dilihat, dan mengaku tidak tahu lebih jujur daripada
menebak. Biayanya harus diukur dulu sebelum diputuskan.

Sementara itu celahnya dikunci sebagai batasan yang diakui di
`test_adversarial.py`, supaya kalau ada yang memperbaikinya, test-nya
memberi tahu.

---

## Keputusan 19 — Biaya R10 diukur, dan rekomendasi awal dibatalkan

`scripts/calibrate_adjacency.py` mengukur harga tiga usulan penutup celah
R10. Hasilnya membatalkan rekomendasi yang ditulis sendiri di Keputusan 18.

**Opsi A ternyata yang paling mahal.** Dugaannya: menurunkan koeksistensi
dari `verified` ke `unknown` cuma merepotkan food court. Kenyataannya
`ANCHOR_RADIUS_M` = 50 m membuat apa pun dalam radius itu memicu
`adjacent_merchant` — termasuk pertokoan berjarak 20 m. Biayanya **100%
pemindaian sah turun ke `warn`** di setiap tata letak selain warung
soliter. Peringatan yang selalu muncul adalah peringatan yang diabaikan,
dan itu menghancurkan aset A4. Ditolak.

**Opsi B gugur secara empiris.** Koordinat jangkar ditetapkan dari
pengamatan pertama, jadi galat GPS satu pembacaan melekat permanen.
Sebaran jarak jangkar untuk swap di titik yang sama dan untuk merchant
yang benar-benar bersebelahan tumpang tindih **72-79%** justru di jarak
2,5-8 m, yaitu pujasera dan pasar. Ini batasan R3 yang muncul lagi, bukan
parameter yang bisa disetel. Ditolak.

**Opsi C yang bertahan.** Pengecualian koeksistensi menuntut basis
pengamat yang sebanding dengan tetangganya — aturannya perbandingan,
bukan jarak, sehingga tata letak padat tidak tersentuh sama sekali. Pada
rasio 0,10: **3,5%** pasangan merchant sah tertolak, dan biaya penyerang
naik dari 3 ke 5 device.

Yang harus disampaikan bersama angka itu: opsi C **menaikkan biaya**
penyerang, tidak menutup celahnya. Penutupan sungguhan menuntut R1
(integritas perangkat) atau R9 (autentikasi klien).

Belum diterapkan — menyentuh invarian §7, jadi menunggu persetujuan tim.

Pelajaran yang layak dicatat: rekomendasi di Keputusan 18 ditulis dengan
percaya diri dan salah. Yang membatalkannya bukan argumen yang lebih
bagus, melainkan enam baris tabel.

---

## Keputusan 20 — Opsi C diterapkan, R10 turun jadi dimitigasi sebagian

Disetujui tim 10 September 2026. `ADJACENT_MIN_RATIO = 0.10` di
`binding.py`: pengecualian koeksistensi kini menuntut basis pengamat yang
sebanding dengan tetangga terkuat, bukan sekadar `is_established`.

Satu baris kondisi, satu konstanta. Yang menuntun pilihannya adalah tabel
di Keputusan 19, bukan selera.

Karena ini mengubah ambang, invarian §7 menuntut skenario ruko diuji
ulang — dan `test_invariants.py` #7 kini menguji dua sisi sekaligus:
pasangan merchant sah yang timpang tapi wajar (30-vs-47, 12-vs-90,
10-vs-47, 5-vs-47) tetap dapat pengecualian, sedangkan 3-vs-47 tidak.

Status R10 berubah dari **terbuka** menjadi **dimitigasi sebagian**, dan
`test_adversarial.py` sekarang memisahkan keduanya dengan jujur:

| Skenario | Status |
|---|---|
| Bajak jangkar yang korbannya sudah mapan | ditahan penuh — 0 binding dari 10 percobaan |
| Cold start modal murah (3 device) | **ditahan** — sejak Keputusan 20 |
| Cold start modal besar (>5 device) | belum ditahan; menuntut R1 atau R9 |

Yang tidak boleh hilang dari narasi: ini menaikkan biaya penyerang dari 3
device ke lebih dari 5, bukan menutup celahnya. Menyebutnya "sudah aman"
akan mengulang persis kesalahan yang dikoreksi Keputusan 12.

---

## Keputusan 21 — record() dibuat atomik; bukan SQLite yang salah

Ditemukan saat memeriksa kesiapan demo, bukan saat menulis fitur. Enam
puluh permintaan yang datang bersamaan — persis situasi dua-tiga HP
memindai serentak — menghasilkan:

```
  galat            25 dari 60
  observations     41   (harusnya 60)
  observer_count   40   (harusnya 60)
```

Dua penyebab berbeda, dan penting membedakannya karena obatnya beda:

| Gejala | Penyebab |
|---|---|
| `InterfaceError`, `another row available` | satu koneksi sqlite3 dipakai bersama lintas thread tanpa kunci |
| `UNIQUE constraint failed`, hitungan hilang | `record()` melakukan SELECT lalu INSERT/UPDATE terpisah — baca-ubah-tulis tanpa transaksi |

**Yang kedua bukan kelemahan SQLite.** Urutan baca-ubah-tulis yang sama
akan balapan di Postgres juga; ia hanya akan mengeluh dengan kalimat
berbeda. Pindah database tanpa membetulkan ini berarti membayar ongkos
migrasi dan tetap kehilangan data — cuma pesan errornya yang ganti
bahasa. Ini alasan `record()` dibetulkan lebih dulu, terpisah dari
pertanyaan SQLite-versus-Postgres.

Yang dikerjakan:

- `threading.RLock` melindungi koneksi bersama
- `record()` berjalan dalam satu transaksi `BEGIN IMMEDIATE`
- SELECT-lalu-INSERT diganti **upsert atomik** (`ON CONFLICT DO UPDATE
  ... RETURNING`), sehingga tidak ada celah antara memeriksa dan menulis
- penambahan `observer_count` dilakukan di dalam SQL, bukan di Python
- `PRAGMA journal_mode = WAL` dan `busy_timeout`

Sesudahnya:

```
   60 thread serentak    0 galat   60/60 konsisten
  200 thread serentak    0 galat  200/200 konsisten   142 permintaan/detik
   50 permintaan device SAMA -> observer_count tetap 1
```

Angka 142 permintaan/detik itu sekaligus menjawab pertanyaan
SQLite-versus-Postgres untuk demo: kebutuhan panggung 2-3 HP, marginnya
puluhan kali lipat. Postgres tetap dibutuhkan menuju produksi — penulis
lintas proses masih diserialisasi — tapi bukan untuk 3 Oktober, dan
bukan untuk memperbaiki bug ini.

Dikunci di `test_hardening.py`: tiga pemeriksaan konkurensi.

---

## Keputusan 22 — Autentikasi klien menutup R9, dan R8 ikut terbawa

R9 ditandai sendiri di threat model sebagai risiko terbuka terbesar:
tanpa autentikasi, siapa pun bisa mengirim pengamatan, dan basis data
binding adalah aset A1.

**Klien di sini adalah PJP, bukan orang.** Satu kunci mewakili satu
penyelenggara yang memanggil Q-Shield sebelum PIN entry. Ini yang
menjaga invarian §8 tetap utuh: `client_id` mengidentifikasi lembaga,
dan diuji tidak pernah masuk tabel `bindings` maupun `observations` —
hanya ke jejak audit, tempat ia memang dibutuhkan untuk menjawab
"putusan ini diminta siapa".

Tiga sifat yang disengaja:

1. **Gagal tertutup.** Kalau `QSHIELD_API_KEYS` kosong dan `QSHIELD_AUTH`
   tidak disetel `off`, endpoint verifikasi mengembalikan `503` — bukan
   melayani tanpa autentikasi. Ketiadaan konfigurasi bukan izin, logika
   yang persis sama dengan Keputusan 2.
2. **Kunci disimpan sebagai hash.** Konfigurasi yang bocor tidak langsung
   memberi kunci yang bisa dipakai. Kunci mentah tidak pernah masuk log,
   bahkan saat autentikasi gagal — diuji.
3. **Perbandingan waktu-tetap.** `hmac.compare_digest`, dan seluruh
   daftar klien ditelusuri sampai habis alih-alih berhenti di kecocokan
   pertama, supaya lama eksekusinya tidak membocorkan posisi.

**R8 ikut tertutup tanpa pekerjaan tambahan.** Begitu ada identitas
klien, kuota tidak perlu lagi dikunci ke alamat IP — dan itu persis
keluhan R8: di balik NAT, seluruh ruangan berbagi satu alamat, sehingga
kuota per-IP menghukum pengguna yang tidak salah. Sekarang kuncinya
`client:<client_id>`. Autentikasi harus berjalan di luar pembatas laju
supaya urutannya benar; susunan middleware ditata ulang untuk itu dan
alasannya ditulis di tempatnya.

Yang tersisa sebagai risiko terbuka terbesar sekarang **R1 (mock
location)** — dan itu juga yang menyisakan R10, karena penyerang
bermodal besar masih bisa memupuk binding dari perangkat yang
koordinatnya dipalsukan di balik PJP yang sah.

---

## Keputusan 23 — R1 dipersempit dari sisi server; accuracy_m jadi wajib

R1 (mock location) tidak bisa ditutup dari sisi server — server tidak
punya cara memverifikasi koordinat yang diklaim klien, dan penutupannya
menuntut deteksi integritas perangkat lewat SDK native. Yang bisa
dikerjakan adalah mempersempitnya.

**Sinyal baru: akurasi yang mustahil secara fisik.** GNSS ponsel
konsumen tidak pernah melaporkan radius keyakinan di bawah satu meter;
yang terbaik pun berhenti di sekitar 3 m. Ambang 1,0 m sengaja dipasang
jauh di bawah kemampuan perangkat asli supaya nyaris mustahil menandai
pemindaian sah. Diuji: 0-0,99 m ditandai, 1-99 m lolos bersih.

Ini menangkap pemalsu yang mengarang angka tanpa memikirkan apakah
angkanya mungkin — dan itu memang kelas penyerang yang nyata.

**`accuracy_m` sekarang WAJIB.** Ini temuan yang lebih penting daripada
sinyalnya. Selama field itu opsional, ada pintu keluar dari invarian §8
— eh, §6 — yang menganga: penyerang yang akurasinya buruk cukup tidak
mengirimkannya, dan pemeriksaan ">100 m" tidak pernah berjalan. Suite
adversarial punya skenario "akurasi dipalsukan tinggi" tapi tidak punya
"akurasi dihilangkan".

Sempat dicoba menutupnya sebagai sinyal risiko (`accuracy_missing`, +15)
dan itu keliru dua kali: menghukum absennya sebuah field sambil
mendeklarasikan field itu opsional adalah desain yang tidak koheren,
dan sebuah pintu keluar dari invarian terlalu serius untuk diselesaikan
dengan menambah skor. Sekarang absennya ditolak `422` di batas sistem,
tempat kontrak masukan memang seharusnya ditegakkan.

Konsekuensi kontrak: klien wajib mengirim `accuracy_m`. Geolocation API
browser selalu memberikan `coords.accuracy` bersama koordinatnya, jadi
klien mana pun sudah memegangnya — tapi ini perubahan kontrak, dan
frontend perlu tahu.

---

## Keputusan 24 — Klaim privasi dibuat benar, bukan sekadar ditulis

Ditemukan saat menyiapkan mitigasi R1. Rencananya mengusulkan deteksi
perjalanan mustahil per perangkat sebagai proposal privasi — lalu
ketahuan datanya sudah ada di sana sejak awal, tanpa pernah diputuskan.

**Klaim yang ternyata salah.** Keputusan 6 dan `THREAT-MODEL.md` §7
menyatakan `observations` tidak dapat dipakai merekonstruksi pergerakan
seseorang, dengan alasan tabel itu tidak menyimpan koordinat. Alasannya
benar, kesimpulannya tidak:

```sql
SELECT o.observed_at, b.lat, b.lng, b.merchant_name
FROM observations o JOIN bindings b ON b.id = o.binding_id
WHERE o.device_anon_id = 'budi-hp-anon-001'
ORDER BY o.observed_at
```

Koordinat penuh, berurutan waktu, satu perangkat. Persis jejak yang
skema ini dirancang untuk tidak bisa hasilkan.

Yang membuatnya lebih buruk: `test_invariants.py` #8 ikut lolos. Ia
memeriksa nama kolom dan memastikan `observations` tidak punya kolom
koordinat — dan berhenti di situ. Pemeriksaan yang memberi rasa aman
palsu lebih berbahaya daripada tidak ada pemeriksaan sama sekali.

**Perbaikannya.** `device_anon_id` tidak lagi disimpan apa adanya. Yang
masuk tabel adalah `device_ref = sha256(garam || binding_id ||
device_anon_id)` — **dilingkupi per-binding dengan sengaja**:

- perangkat yang sama menghasilkan nilai **berbeda** di tiap binding
- dedup per binding tetap bekerja, dan itu satu-satunya fungsi yang
  memang dibutuhkan
- baris tidak bisa dirangkai antar-binding jadi jejak perjalanan

Basis data lama ikut dimigrasi: nilai lamanya di-hash di tempat lalu
kolomnya dibuang. Berhenti memakai kolom tidak cukup — data yang masih
ada tetap terbaca oleh siapa pun yang memegang berkasnya.

**Invarian #8 sekarang diuji dengan menyerangnya**, bukan dengan
membaca nama kolom: JOIN memakai pengenal mentah, perangkaian baris
antar-lokasi lewat `device_ref`, dan penghitungan rujukan dari pengenal
yang sudah diketahui penyerang. Ketiganya harus gagal, dan dedup harus
tetap utuh.

**Sisa risiko, disebut terus terang.** Pihak yang SUDAH mengetahui
sebuah `device_anon_id` masih bisa menghitung rujukannya di tiap binding
dan menguji keberadaannya. Pihak itu adalah PJP yang menerbitkan
pengenal tersebut — dan PJP sudah tahu transaksi penggunanya sendiri,
jadi Q-Shield tidak menambah paparan baru di sana. Yang hilang adalah
kemampuan siapa pun yang memegang basis data Q-Shield untuk memakainya
sebagai alat pelacak.

**Konsekuensi untuk R1.** Perbaikan ini menutup pintu deteksi perjalanan
mustahil per perangkat dari data tersimpan — mitigasi terkuat yang
tersedia untuk mock location. Itu pertukaran yang diambil sadar:
privasi yang benar-benar berlaku lebih berharga daripada satu sinyal
anti-fraud tambahan, terutama karena klaim privasi inilah yang dipakai
menjawab Kaspersky dan yang memungkinkan berbagi data antar-PJP.

---

## Keputusan 25 — SQLite dipertahankan untuk demo, dengan angkanya

Handoff meminta rencana migrasi Postgres **atau** justifikasi tertulis
kenapa tetap SQLite. Ini justifikasinya, dan dasarnya ukuran.

| Beban | Hasil |
|---|---|
| 60 permintaan HTTP serentak | 0 galat, hitungan tepat |
| 200 permintaan HTTP serentak | 0 galat, ~142 permintaan/detik |
| 12 proses x 200 tulis | 2400/2400 konsisten, ~2.800 tulis/detik |
| 20 proses x 200 tulis | 4000/4000 konsisten, ~3.000 tulis/detik |

Kebutuhan panggung: dua sampai tiga ponsel. Marginnya ratusan kali
lipat, dan SQLite tidak menambah satu pun proses yang bisa mati di
depan juri.

**Yang akan memaksa pindah bukan kecepatan, melainkan berbagi data
antar-PJP** — inti proposisi nilai Q-Shield, karena stiker penipu tidak
berhenti di batas satu penyelenggara. Berbagi menuntut basis data yang
bisa dijangkau banyak pihak lewat jaringan; SQLite adalah berkas di satu
mesin. Rencana lengkapnya di `DEPLOY.md`.

**Dua bug ditemukan saat mengukurnya.**

*Urutan PRAGMA.* `busy_timeout` dipasang setelah `journal_mode = WAL`,
padahal peralihan ke WAL sendiri butuh kunci eksklusif sesaat. Pada saat
paling rawan itu, tidak ada timeout sama sekali. Terukur: 5 dari 6
proses gagal start hanya karena urutan dua baris terbalik.

*Inisialisasi dingin.* DDL menuntut kunci eksklusif, dan beberapa proses
yang membuka basis data yang belum ada secara bersamaan — persis
`uvicorn --workers N` saat start dingin — masih bisa bertabrakan.
Ditutup dengan retry terbatas yang melempar galat aslinya setelah
percobaan habis, bukan menelannya.

---

## Keputusan 26 — Kontrak API dikunci sebelum freeze

`accuracy_m` yang berubah jadi wajib (Keputusan 23) adalah perubahan
yang **memecah klien**. Perubahan seperti itu boleh terjadi sebelum ada
klien eksternal, asal disengaja dan tercatat. Yang tidak boleh adalah
terjadi tanpa ada yang menyadarinya sampai frontend rusak di depan juri.

`API.md` menuliskan kontraknya, dan `tests/test_contract.py`
menegakkannya dengan membaca skema OpenAPI yang dihasilkan kode.

Pemisahan yang disengaja:

| Terbuka | Tertutup |
|---|---|
| `signals`, `reasons` — tempat sinyal baru mendarat tanpa memecah klien | `verdict`, `action`, `location_source` — klien memetakannya ke UI, nilai tak dikenal membuat mereka tidak tahu harus menampilkan apa |

Diuji terhadap penyimpangan sungguhan, bukan sekadar dijalankan hijau:
disimulasikan seseorang menjadikan `accuracy_m` opsional lagi dan
menambah field debug ke tanggapan; empat dari enam bagian menangkapnya.

---

## Keputusan 27 — Preflight: satu perintah sebelum juri datang

`scripts/preflight.py` memeriksa hal-hal yang kalau salah baru ketahuan
di depan juri: konfigurasi, basis data, kecocokan jangkar dengan
koordinat venue, prop tercetak, putusan API, dan seluruh suite.

Diuji terhadap kegagalan yang paling mungkin terjadi hari-H — seed masih
dibuat untuk lokasi lama:

```
[GAGAL] jangkar terkuat berjarak 118292 m dari koordinat venue
        python scripts/seed.py $(python scripts/venue_fixture.py coords)
```

Perintah perbaikannya ikut dicetak, karena pagi hari-H bukan waktu untuk
mengingat-ingat.

**Bug yang ditemukan saat membangunnya.** `RateLimiter` membaca
`QSHIELD_RATE_LIMIT` untuk flag `disabled` bahkan ketika kuota
disodorkan eksplisit ke konstruktornya. Artinya kode yang membuat
limiter secara programatik diam-diam kehilangan seluruh pembatasan
begitu env itu terpasang — dan kuota yang diminta eksplisit justru yang
paling tidak boleh diabaikan diam-diam. Sekarang argumen eksplisit
menang atas env.

Preflight sendiri juga tidak menyetel env untuk melewati autentikasi; ia
mengganti objeknya. Preflight harus melaporkan mesin apa adanya, bukan
mesin yang sudah diubahnya sendiri.

---

## Keputusan 28 — Scanner disajikan backend, dan HTTPS ternyata wajib

**Temuan yang mengubah rencana.** Kamera (`getUserMedia`) dan GPS
(`navigator.geolocation`) sama-sama menuntut *secure context*. Membuka
`http://192.168.x.x:8000` dari HP bukan secure context, jadi browser
memblokir keduanya — tanpa bisa dinegosiasikan. `localhost` dikecualikan,
tapi HP tidak bisa membuka localhost laptop.

Artinya tanpa HTTPS, frontend secantik apa pun tidak bisa memindai
maupun tahu lokasi, dan demo mati sebelum dimulai. Ini tidak muncul di
catatan fase 1 mana pun. `scripts/make_cert.py` menutupnya; SAN-nya
memuat IP LAN, karena browser modern mengabaikan Common Name sepenuhnya.

**Halaman mandiri, bukan Next.js.** Satu berkas HTML tanpa build step,
tanpa npm, tanpa CDN, disajikan dari proses yang sama dengan API.
Alasannya seluruhnya soal hari-H:

- WiFi acara diasumsikan buruk, jadi tidak boleh ada yang perlu diunduh
- satu origin berarti tidak ada urusan CORS sama sekali
- satu proses berarti satu hal yang bisa mati, bukan dua
- tidak ada `npm install` yang bisa gagal pagi hari-H

Plus Jakarta Sans dipakai kalau memang terpasang di perangkat; kalau
tidak, jatuh ke font sistem — bukan ke permintaan jaringan.

**Yang ditampilkan adalah `reasons`, bukan `risk_score`.** Angka tidak
bisa dijelaskan ke pengguna maupun juri; kalimatnya bisa. Skornya tetap
ada sebagai chip kecil untuk yang ingin melihat.

**Cooling-off menampilkan hitung mundur.** Keputusan 3 memilih penundaan
sebagai respons risiko tertinggi karena seluruh modus rekayasa sosial
bergantung pada tekanan waktu. Kalau penundaannya tidak terlihat, alasan
memilihnya ikut hilang.

**Yang belum diverifikasi:** tampilannya belum pernah dilihat di browser
sungguhan — tidak ada browser tool di mesin ini. Yang sudah diperiksa
tanpa browser: seluruh ID yang dirujuk JS ada di HTML, setiap kelas yang
dipasang JS punya aturan CSS, dan `tests/test_frontend.py` memastikan
badan permintaan yang disusun halaman lolos validasi API sekaligus
setiap field yang dibacanya memang ada di tanggapan. Rupanya harus
dilihat sendiri sebelum gladi bersih.

---

## Keputusan 29 — "Belum dikenal" bukan peringatan, dan tidak boleh terlihat begitu

Muncul dari pengujian lapangan: memindai QRIS merchant sungguhan di
jalan menghasilkan "Periksa dulu" untuk **semua**-nya, sementara stiker
palsu tertangkap seketika. Reaksi penggunanya tepat — kalau semuanya
disuruh diperiksa, pengguna ikut ragu pada yang benar.

**Diagnosisnya bukan penilaian yang kurang tajam.** Setiap merchant baru
memang `first_observation` → `unknown` → `warn`, persis seperti
Keputusan 2 dan invarian §2 menuntut. Tidak ada yang bisa diperbaiki di
skor: `_floor_action()` memastikan `unknown` tidak pernah jatuh ke
`proceed`, dan itu memang harus begitu.

**Yang keliru adalah tier `warn` mencampur dua hal yang sangat berbeda:**

| Ketiadaan bukti | Ada yang janggal |
|---|---|
| `first_observation` | `nmid_second_location` |
| `young_binding` | `adjacent_merchant` |
| `low_gps_accuracy` | `implausible_accuracy` |
| | `repeated_anomaly_at_anchor`, `noncanonical_*` |

Kolom kiri tidak menuduh apa pun. Menampilkannya dengan alarm amber yang
sama seperti kolom kanan membuat pengguna cemas tanpa sebab — dan
sistem anti-fraud yang terlalu sering terlihat cemas akan diabaikan.
Pengguna yang mengabaikan peringatan sama tidak terlindunginya dengan
yang tidak punya sistem sama sekali. Ini aset A4 di threat model.

**Perbaikannya di penyampaian, bukan di penilaian.** Aksi tetap `warn`;
yang berubah hanya tampilan ketika sebuah pemindaian HANYA membawa
sinyal ketiadaan bukti. Tidak ada perubahan skor, tidak ada perubahan
kontrak API — `signals` memang sudah ada di tanggapan dan kosakatanya
terbuka.

**Kalimatnya dijaga ketat.** Stiker palsu di lokasi yang belum punya
jangkar juga mendarat di keadaan netral ini — sistem memang tidak bisa
membedakannya (batasan cold start, R4). Karena itu keterangannya
menjelaskan kenapa STATUSNYA belum diketahui dan **tidak pernah**
menyiratkan merchantnya aman, lalu ditutup dengan pemeriksaan yang bisa
dilakukan pengguna sendiri tanpa bergantung pada data kami: cocokkan
nama merchant di layar pembayaran dengan nama di tokonya.

Dikunci di `test_frontend.py`: cold start netral, sementara sinyal
janggal dan anomaly tidak ikut dilunakkan — termasuk memeriksa bahwa
kalimatnya masih memuat penegasan "tidak akan menyatakan aman".

**Catatan istilah.** Permintaan awalnya berbunyi "perkuat model ML".
Q-Shield tidak punya model ML dan tidak pernah punya — ia sistem aturan
deterministik dan konsensus pengamatan. Menyebutnya ML di depan juri
akan mengundang pertanyaan "dilatih dengan dataset apa" yang tidak ada
jawabannya. Sifat deterministik itu justru kekuatannya: setiap putusan
bisa ditelusuri baris per baris.

---

## Keputusan 30 — Pendaftaran merchant menutup R4, R5, dan R6 sekaligus

Cold start adalah batasan yang paling terasa di lapangan: setiap
merchant sungguhan yang dipindai berakhir `warn`, karena NMID-nya
memang belum pernah dilihat. Solusinya sudah ada di peta jalan sejak
fase 1 ("pendaftaran mandiri & jalur konfirmasi"); yang membuatnya bisa
dikerjakan sekarang adalah lapisan autentikasi PJP (Keputusan 22).

**Kenapa PJP yang mendaftarkan.** PJP sudah tahu NMID mana milik
merchant mana — itu data onboarding mereka. Jadi pendaftaran bukan
klaim baru yang perlu dipercaya, melainkan pemindahan pengetahuan yang
sudah ada ke tempat yang bisa dipakai memverifikasi.

Tiga batasan tertutup dengan satu fitur:

| | Sebelum | Sesudah |
|---|---|---|
| R4 cold start | tiap merchant baru `warn` | terdaftar -> `verified` seketika |
| R5 merchant pindah | memicu alarm sekali | daftar ulang di lokasi baru |
| R6 merchant keliling | belum ditangani sama sekali | `is_mobile`, ikatan lokasi tidak berlaku |

**Pemeriksaan terhadap kedelapan invarian dilakukan sebelum menulis
kode**, dan tiga di antaranya memaksa perubahan rancangan:

- **§2** — pendaftaran menghasilkan `verified`. Boleh, karena
  pendaftaran adalah BUKTI (pernyataan pihak yang meng-onboard), bukan
  ketiadaan bukti.
- **§5** — rumus `60 + min(25, n//2)` dikunci invarian, jadi konflik di
  jangkar terdaftar mendapat **sinyal sendiri**
  (`nmid_changed_at_registered_anchor`, bobot datar 85) alih-alih
  mengubah rumus lama. Datar, karena pendaftaran tidak menguat seiring
  bertambahnya pemindai.
- **§8** — atribusi PJP perlu dicatat untuk pencabutan, tapi tidak boleh
  masuk tabel pengamatan. Solusinya tabel terpisah: `bindings` dan
  `observations` berisi jejak pengguna dan tunduk aturan privasi;
  `registrations` berisi pernyataan lembaga dan tunduk aturan
  akuntabilitas. Aturannya beda, jadi tabelnya beda.

**Jalur kepercayaan baru berarti permukaan serangan baru,** dan itu
diakui terus terang: kunci PJP yang bocor bisa dipakai mendaftarkan
stiker palsu sebagai `verified`. Mitigasinya bukan mencegah — melainkan
membuatnya terlacak dan bisa dibatalkan: tiap pendaftaran mencatat
pendaftarnya, PJP tidak bisa membajak pendaftaran PJP lain (409), hanya
pendaftarnya yang bisa mencabut (403), dan sinyalnya selalu berbeda dari
konsensus sehingga auditor tahu mana yang mana.

Pencabutan mengembalikan status tanpa menghapus pengamatan: konsensus
yang sudah terkumpul adalah bukti yang sah, terlepas dari status
pendaftarannya.

**Dua bug ditemukan saat menguji, keduanya dari interaksi fitur baru
dengan yang lama:**

1. *Binding merchant keliling mengklaim lokasi.* Gerobak siomay yang
   pernah mangkal di suatu titik membuat warung di titik itu terlihat
   seperti pertukaran stiker. Satu pendaftaran keliling bisa meracuni
   setiap jangkar yang pernah disinggahinya.
2. *Merchant baru daftar selalu gagal uji `ADJACENT_MIN_RATIO`.* Ia
   punya nol pengamat, jadi rasionya selalu kalah terhadap tetangga mana
   pun — merchant yang baru didaftarkan langsung dituduh menggusur
   tetangganya sendiri. Binding terdaftar kini lolos uji rasio tanpa
   syarat; buktinya pernyataan, bukan jumlah pengamat. Ini tidak membuka
   lagi celah R10, karena jalur murah 3-device tidak melewati
   pendaftaran.

**Bug ketiga, tidak berhubungan tapi ikut ketahuan:** `seed.py` menghapus
`qshield.db` tanpa berkas pendamping `-wal`/`-shm`, sehingga SQLite
menemukan sidekar yatim dan gagal dengan "disk I/O error". Efek samping
WAL yang diaktifkan di Keputusan 25 — dan persis akan menggigit saat
re-seed di venue.

---

## Keputusan 31 — Integritas perangkat: slotnya, bukan SDK-nya

R1 selama ini dicatat sebagai "butuh SDK native", dan itu membingkai
masalahnya keliru. Q-Shield bukan aplikasi pengguna akhir — ia lapisan
yang **diintegrasikan PJP**. Dan PJP sudah punya aplikasi native.

Jadi pemeriksaan integritas perangkat bukan pekerjaan kami. Yang kami
butuhkan hanyalah **slot di protokol** supaya klien native bisa
mengisinya:

```json
"device_integrity": {
  "mock_location": false, "rooted": false,
  "attested": true, "platform": "android"
}
```

Ini mengubah jawaban pitch dari "kami belum bisa" menjadi "protokolnya
sudah siap; klien web kami sendiri yang tidak bisa mengisinya, dan itu
batasan klien web, bukan batasan sistemnya."

**Rantai kepercayaannya disebut terus terang.** Q-Shield tidak bisa
memverifikasi field ini — klien bisa berbohong. Yang membuatnya berarti
adalah `attested`: hasil Play Integrity / App Attest yang diverifikasi
PJP di server mereka sendiri, lalu dipertanggungkan lewat kunci API
mereka. Kami tidak memercayai perangkatnya; kami memercayai PJP yang
menyatakan sudah memeriksanya — dan kunci API itulah yang membuat
pertanggungan itu punya nama.

**`mock_location: true` menolak memberi putusan lokasi**, bukan menambah
skor. Alasannya: GPS yang diakui palsu menempatkan kita di posisi yang
persis sama dengan akurasi >100 m — jangkarnya tidak layak dinilai. Satu
masalah, satu perlakuan. Bedanya cuma niat, dan itu tercermin di skor
dasar yang lebih tinggi (65 vs 40).

**Ketiadaan laporan TIDAK dihukum.** Ini pelajaran yang sudah dibayar
sekali di Keputusan 23: `accuracy_missing` pernah dijadikan sinyal
risiko dan itu keliru, karena menghukum sesuatu yang klien memang tidak
bisa berikan. Setiap klien web akan selalu kosong di sini.

Yang dilakukan sebagai gantinya: ketiadaannya **diungkapkan** lewat
field `device_integrity: "not_provided"` di tanggapan dan di jejak
audit. Artinya "pemeriksaan ini tidak pernah dijalankan" — bukan
"dijalankan lalu lolos". Sama persis dengan pola `location_source`:
pengungkapan, bukan skor.

Panduan integrasinya ada di `INTEGRATION.md`, ditulis untuk dibaca
tim engineering PJP — termasuk peringatan agar tidak mengirim
`attested: true` sebelum benar-benar memverifikasinya, karena itu
memindahkan risiko ke pengguna mereka sendiri.

---

## Keputusan 32 — Kalimat terpenting akhirnya punya gambarnya

Naskah pitch menyebut *"The PIN was never entered"* sebagai kalimat
paling penting. Tapi sampai hari ini frontend hanya menampilkan verdict
— tidak ada layar PIN sama sekali. Juri mendengar klaimnya tanpa pernah
melihat apa yang dimaksud.

Sekarang tiap tier memetakan ke perlakuan bayar yang berbeda:

| Tier | Yang terjadi di layar |
|---|---|
| `proceed` | layar PIN muncul seperti biasa |
| `warn` | alasan ditampilkan, pengguna boleh lanjut |
| `step_up` | konfirmasi dulu — PIN hanya lewat klik sadar |
| `cooling_off` | **layar PIN tidak pernah dirender** |

Kata "dirender" itu penting dan diuji: pada `cooling_off`, layar PIN
bukan disembunyikan lewat CSS, melainkan **tidak pernah dibuat**.
`test_frontend.py` memeriksa cabang itu tidak memanggil `layarPin()`
sama sekali — kalau suatu saat ada yang mengubahnya jadi
"tampilkan-lalu-sembunyikan", testnya gagal.

**Penanda SIMULASI dipasang permanen di markup, bukan disuntik JS.**
Halaman yang meniru layar bayar sungguhan tanpa penanda adalah templat
phishing, terlepas dari niat pembuatnya. Penanda yang disuntik JS bisa
dilewati dengan mematikan satu baris; yang ada di markup tidak.

---

## Keputusan 33 — Peragaan lintas-PJP, dan skenario pertamanya yang keliru

Berbagi data antar-PJP adalah pembeda terkuat Q-Shield, tapi selama ini
hanya diucapkan, tidak pernah diperlihatkan. `scripts/demo_lintas_pjp.py`
menjalankan kejadian yang sama di dua dunia berdampingan: tiap PJP
menyimpan datanya sendiri, versus satu lapisan binding dipakai bersama.

**Skenario pertamanya salah, dan salahnya menarik.** Versi awal menyeed
kedua PJP dengan 47 pengamatan yang sama — dan hasilnya, serangan
tertahan di kedua dunia. Berbagi data tampak tidak ada gunanya.

Penyebabnya: skenario itu mengandaikan dua penyelenggara mengumpulkan
data identik secara terpisah. Kalau itu benar, berbagi memang percuma.
Tapi itu bukan keadaan sebenarnya — **adopsi selalu timpang.**
Pelanggan sebuah warung kebanyakan memakai satu aplikasi, dan tidak ada
satu penyelenggara pun yang melihat semua merchant.

Dengan skenario yang benar:

```
                       DUNIA A (terpisah)     DUNIA B (berbagi)
  Dompet Alpha         anomaly/cooling_off    anomaly/cooling_off
  Bayar Beta           unknown/warn  35       anomaly/cooling_off  95
```

Di dunia terpisah, `Bayar Beta` tidak punya dasar untuk menghentikannya
— jangkar warung tidak pernah terbentuk di basis datanya, jadi stiker
palsu tampak seperti merchant baru biasa, dan penggunanya diteruskan ke
layar PIN. Di dunia berbagi, 47 pengamatan yang dikumpulkan pengguna
pesaingnya melindunginya.

Pelajarannya bukan cuma soal naskah demo: skenario yang dipilih
sembarangan bisa membuat fitur yang berguna tampak sia-sia, atau
sebaliknya. Skenario adalah bagian dari klaim, dan harus diperiksa
sekeras kodenya.

---

## Keputusan 34 — Jangkar menajam seiring pengamatan

Selama ini koordinat jangkar ditetapkan dari pengamatan **pertama** dan
tidak pernah diperbarui. Galat satu pembacaan GPS melekat permanen, dan
puluhan pengamatan berikutnya tidak dipakai memperbaikinya sama sekali.
Terukur: setelah 47 pengamatan, jangkar masih meleset 6,9 m — sama
buruknya dengan hari pertama.

Ini janggal, karena seluruh mekanisme Q-Shield dibangun di atas gagasan
bahwa banyak pengamatan independen lebih kuat daripada satu. Prinsip itu
dipakai untuk `observer_count`, tapi tidak untuk koordinatnya sendiri.

Sekarang jangkar adalah **rata-rata berjalan**. Galatnya turun sebagai
sigma/akar(n):

| pengamatan | jangkar beku | rata-rata berjalan | membaik |
|---|---|---|---|
| 3 | 6,6 m | 4,2 m | 1,6x |
| 10 | 6,4 m | 2,3 m | 2,8x |
| 47 | 6,3 m | 1,0 m | **6,3x** |
| 100 | 6,3 m | 0,7 m | 9,3x |

Ini langsung mempersempit R3 (merchant berjarak <15 m): jangkar dengan
galat 1 m memisahkan dua lapak jauh lebih baik daripada jangkar dengan
galat 6 m.

**Penghalusan membuka serangan baru, dan itu dikalibrasi sebelum
diterapkan.** Pemindaian dari tepi radius menarik titik tengah, dan
begitu jangkarnya bergeser, radius barunya menjangkau lebih jauh lagi —
penyerang berjalan menuntun jangkar keluar dari warung. Tanpa batas,
seretannya mencapai 38 m.

Tiga hal menahannya, dan dua di antaranya sudah ada sejak awal:

1. **Batas geser 20 m** dari titik mula-mula. Dipilih dari kalibrasi:
   titik benar sendiri bisa berjarak ~16 m (2 sigma) dari pembacaan
   pertama, jadi batas di bawah itu mengunci jangkar pada galat awalnya
   dan membuang seluruh manfaatnya.
2. **Hanya pengamat BARU yang menggeser.** Pemindaian berulang dari satu
   device tidak menggerakkan apa pun — diuji, 100 pemindaian menggeser
   0,000 m. Menyeret sejauh N langkah menuntut N pengenal perangkat
   berbeda: ongkos yang sama dengan memalsukan konsensus.
3. **Batas sel geohash**, yang ditemukan saat menguji dan bukan
   dirancang. `record()` mencocokkan binding lewat sel presisi 7, jadi
   pemindaian di luar sel itu membuat binding BARU alih-alih menggeser
   yang ada. Serangan seret hanya mungkin dari dalam sel yang sama.

Poin ketiga membuat model kalibrasi pertama saya keliru — ia
mengandaikan setiap pemindaian menyuap binding yang sama. Modelnya
dipertahankan sebagai batas ATAS dan dicatat demikian, karena batas yang
dipilih darinya aman untuk kasus yang lebih longgar.

**Jangkar TERDAFTAR tidak dihaluskan.** Koordinatnya pernyataan
penyelenggara, bukan taksiran dari pengamatan; membiarkan pemindai
menggesernya berarti membiarkan mereka memindahkan merchant yang sudah
dinyatakan resmi berada di suatu titik.

---

## Hasil pengujian

```
test_emvco.py        parser, CRC16, payload cacat, QR dinamis
test_geo.py          roundtrip, arah tetangga, kasus batas, kutub
test_binding.py      13 skenario termasuk ruko dan relokasi merchant
test_api.py          end-to-end, akumulasi, latency
test_invariants.py   satu pemeriksaan per invarian, keluar bukan-nol
                     kalau ada yang jebol
test_adversarial.py  15 skenario dari sisi penyerang, termasuk empat
                     batasan yang diakui — diuji agar sistem tetap jujur
test_hardening.py    25 pemeriksaan: validasi input, autentikasi klien,
                     rate limit, header, audit tanpa PII, mode replay,
                     dan konkurensi
test_contract.py     kunci bentuk API v1 — gagal kalau ada yang bergeser
test_frontend.py     kecocokan halaman scanner dengan API
test_registration.py 14 pemeriksaan: fungsi pendaftaran dan penyalahgunaannya
```

Dokumen ancaman terpisah ada di `THREAT-MODEL.md`.

`test_invariants.py` bukan test fitur. Tugasnya satu: memastikan tidak ada
perubahan di masa depan yang diam-diam melanggar keputusan yang sudah
dibayar dengan pengujian empiris. Invarian 1, 5, dan 7 tidak sekadar
mengunci konstanta tapi menguji ulang buktinya — cakupan presisi 7 versus
8, rumus bobot, dan koeksistensi ruko pada 5-35 m.

Empat skenario terakhir di `test_adversarial.py` adalah serangan yang
**memang belum ditahan**: spoof koordinat, replay QR dinamis, relokasi
merchant sah, dan sisa celah cold start R10 (penyerang bermodal besar). Untuk itu yang diuji bukan "apakah tertangkap" melainkan
"apakah sistem tetap jujur" — batasan yang diketahui tidak boleh diam-diam
berubah jadi klaim aman, dan itu bentuk kegagalan yang paling berbahaya.

**Latensi** (200 permintaan, SQLite lokal):

```
p50  2,8 ms      p95  3,5 ms      maks  22,4 ms
```

Anggaran 200 ms terpenuhi dengan margin besar. Angka ini belum termasuk
latensi jaringan dan belum diuji pada volume produksi.

---

## Batasan yang diketahui

Dicatat terbuka; sebagian menjadi isi *Pathway*.

1. **Presisi GPS.** Merchant berjarak <15 m sulit dibedakan. Perlu ambient
   WiFi fingerprinting — tidak tersedia di browser, karenanya PoC ini
   berbasis web dan MVP memerlukan SDK native.
2. **Mock location.** GPS palsu dapat mencemari basis data. Mitigasinya
   adalah deteksi integritas perangkat, yang memerlukan SDK native.
   Diuji dan dicatat: spoof koordinat tidak memberi penyerang keuntungan
   apa pun untuk NMID yang bukan miliknya — swap tetap tertangkap.
3. **Cold start.** Diatasi sebagian oleh status `unknown` yang jujur;
   solusi penuhnya adalah pendaftaran mandiri oleh merchant.
4. **Merchant berpindah.** Relokasi sah akan memicu peringatan sekali.
   Perlu jalur konfirmasi merchant.
5. **Merchant keliling.** Belum ditangani. Perlu penandaan khusus saat
   pendaftaran.
6. **Scoring transfer manual belum ada.** Layer 2 jalur QR sudah jalan
   (Keputusan 9-11); modus rekayasa sosial lewat transfer bank manual
   masih berupa rancangan dan kini disebut dengan namanya sendiri.

7. **Replay QR dinamis.** Tidak ada pelacakan nonce per transaksi;
   mendeteksinya butuh keterlibatan PJP dan berada di luar jangkauan
   lapisan pra-pembayaran. Diuji bahwa sistem tidak mengklaim bisa.

8. **Sidik jari encoding belum tervalidasi lapangan.** Sinyal urutan tag
   dan huruf CRC memisahkan "dicetak ulang" dari "generator acquirer yang
   rewel" berdasarkan asumsi, bukan korpus payload QRIS asli. Karena itu
   bobotnya kecil dan totalnya dibatasi bersama — tidak pernah bisa
   menggerakkan tier sendirian.

---

## Parameter yang dapat dikalibrasi

Semua berada di `binding.py`, sengaja tidak ditanam di dalam logika.

| Parameter | Nilai | Alasan |
|---|---|---|
| `ANCHOR_RADIUS_M` | 50 | kompromi galat GPS vs merchant bersebelahan |
| `INDEX_PRECISION` | 7 | terbukti mencakup 100% radius 100 m |
| `MIN_OBSERVERS` | 3 | satu pengamat tidak pernah cukup |
| `MIN_AGE_HOURS` | 24 | stiker palsu berumur pendek; waktu menyaring |
| `SCATTER_MIN_KM` | 1,0 | mencegah jitter GPS terhitung sebagai area baru |
| `STALE_DAYS` | 90 | binding lama tidak boleh memblokir merchant baru |

Layer 2 di `behavior.py`:

| Parameter | Nilai | Alasan |
|---|---|---|
| `W_STRUCTURAL` | 70 | kontradiksi spec, bukan kemiripan statistik — 0 positif palsu dari 20.000 payload sah |
| `W_TAG_ORDER` | 15 | sidik jari encoding, **belum tervalidasi lapangan** |
| `W_CRC_CASE` | 10 | idem |
| `SOFT_FINGERPRINT_CAP` | 25 | sekumpulan sinyal lemah tidak boleh menumpuk jadi setara satu bukti kuat |
| `W_ANOMALY_BASE` | 12 | berskala dengan jumlah percobaan, pola yang sama dengan Keputusan 4 |
| `W_ANOMALY_CAP` | 30 | sendirian tidak pernah cukup mencapai `cooling_off` |

Nilai-nilai ini adalah titik awal untuk demo, bukan hasil kalibrasi lapangan.
Yang sudah punya dasar empiris: presisi geohash (`calibrate_geo.py`), bobot
struktural dan ambang lonjakan (`calibrate_layer2.py`), serta parameter cetak
QR (`make_qr.py --calibrate`).
