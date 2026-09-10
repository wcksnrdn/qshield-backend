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

## Hasil pengujian

```
test_emvco.py        parser, CRC16, payload cacat, QR dinamis
test_geo.py          roundtrip, arah tetangga, kasus batas, kutub
test_binding.py      13 skenario termasuk ruko dan relokasi merchant
test_api.py          end-to-end, akumulasi, latency
test_invariants.py   satu pemeriksaan per invarian, keluar bukan-nol
                     kalau ada yang jebol
test_adversarial.py  13 skenario dari sisi penyerang, termasuk tiga
                     batasan yang diakui — diuji agar sistem tetap jujur
```

`test_invariants.py` bukan test fitur. Tugasnya satu: memastikan tidak ada
perubahan di masa depan yang diam-diam melanggar keputusan yang sudah
dibayar dengan pengujian empiris. Invarian 1, 5, dan 7 tidak sekadar
mengunci konstanta tapi menguji ulang buktinya — cakupan presisi 7 versus
8, rumus bobot, dan koeksistensi ruko pada 5-35 m.

Tiga skenario terakhir di `test_adversarial.py` adalah serangan yang
**memang belum ditahan**: spoof koordinat, replay QR dinamis, relokasi
merchant sah. Untuk itu yang diuji bukan "apakah tertangkap" melainkan
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
