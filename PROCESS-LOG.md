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
                                     ├── qshield/emvco.py    parser payload
                                     ├── qshield/geo.py      geohash + jarak
                                     ├── qshield/binding.py  logika konsensus
                                     └── qshield/store.py    persistensi
```

Logika penilaian sengaja dipisah dari database (`binding.py` tidak mengimpor
`store.py`) supaya bisa diuji tanpa I/O dan supaya aturan bisa dibaca sebagai
satu berkas utuh.

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

## Hasil pengujian

```
test_emvco.py     parser, CRC16, payload cacat, QR dinamis
test_geo.py       roundtrip, arah tetangga, kasus batas, kutub
test_binding.py   13 skenario termasuk ruko dan relokasi merchant
test_api.py       end-to-end, akumulasi, latency
```

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
   adalah deteksi integritas perangkat, yang justru menjadi alasan Layer 2
   diperlukan.
3. **Cold start.** Diatasi sebagian oleh status `unknown` yang jujur;
   solusi penuhnya adalah pendaftaran mandiri oleh merchant.
4. **Merchant berpindah.** Relokasi sah akan memicu peringatan sekali.
   Perlu jalur konfirmasi merchant.
5. **Merchant keliling.** Belum ditangani. Perlu penandaan khusus saat
   pendaftaran.
6. **Layer 2 belum diimplementasikan.** Behavioral scoring untuk transfer
   manual masih berupa rancangan.

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

Nilai-nilai ini adalah titik awal untuk demo, bukan hasil kalibrasi lapangan.
