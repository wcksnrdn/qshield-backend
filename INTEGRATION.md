# Integrasi Q-Shield untuk PJP

Panduan untuk penyedia jasa pembayaran yang memasang Q-Shield sebagai
lapisan verifikasi pra-pembayaran di aplikasinya.

---

## 1. Di mana Q-Shield dipanggil

Tepat **setelah QR dipindai, sebelum layar PIN muncul.**

```
  kamera → payload QRIS
                │
                ▼
       POST /api/v1/verify          ← Q-Shield di sini
                │
        ┌───────┴────────┐
        │                │
    proceed          selain proceed
        │                │
        ▼                ▼
   layar PIN       friksi sesuai tier
```

Q-Shield tidak memindahkan dana, tidak menyentuh saldo, dan tidak
menggantikan pemeriksaan apa pun yang sudah Anda lakukan. Ia menambah
satu pertanyaan yang selama ini tidak dijawab siapa pun: **apakah
artefak fisik yang menampilkan QR ini memang milik merchant yang
seharusnya berada di titik ini.**

---

## 2. Memetakan empat tier ke UI Anda

| Tier | Arti | Saran perlakuan |
|---|---|---|
| `proceed` | ikatan merchant-lokasi cocok | lanjut ke PIN seperti biasa |
| `warn` | belum cukup bukti, atau ada yang janggal | tampilkan `reasons`, pengguna bisa lanjut |
| `step_up` | ada yang tidak sesuai di lokasi ini | minta konfirmasi tambahan sebelum PIN |
| `cooling_off` | ketidaksesuaian serius | **tunda**, jangan sekadar tolak |

**Tentang `cooling_off`.** Yang diminta adalah penundaan, bukan
penolakan. Seluruh modus rekayasa sosial bergantung pada tekanan waktu —
korban ditelepon, diburu-buru, diminta cepat. Menunda mematahkan
tekanannya; menolak hanya membuat korban mencari jalan lain.

**Petakan `action`, bukan `verdict`.** `verdict` menjawab "apa yang kami
ketahui"; `action` menjawab "apa yang sebaiknya dilakukan". Yang kedua
itulah yang menentukan layar.

**Tampilkan `reasons`, jangan `risk_score`.** Angka tidak bisa
dijelaskan ke pengguna maupun ke regulator. Kalimatnya bisa.

**Perlakukan `unknown` sebagai peringatan, bukan lampu hijau.** Ini
invarian sistem, bukan preferensi: ketiadaan bukti bukan bukti
ketiadaan.

---

## 3. Integritas perangkat — bagian yang hanya Anda bisa isi

Ini bagian terpenting dokumen ini.

Q-Shield berjalan di server dan tidak bisa memeriksa perangkat pengguna.
Klien web bahkan tidak bisa menanyakannya — browser sengaja tidak
membocorkan konfigurasi sistem ke halaman. **Aplikasi native Anda bisa.**

```json
POST /api/v1/verify
{
  "payload": "...",
  "lat": -6.914744, "lng": 107.609810, "accuracy_m": 8.5,
  "device_anon_id": "<uuid acak per perangkat>",
  "device_integrity": {
    "mock_location": false,
    "rooted": false,
    "attested": true,
    "platform": "android"
  }
}
```

### Dari mana nilainya diambil

| Field | Android | iOS |
|---|---|---|
| `mock_location` | `Location.isMock()` (API 31+) atau `isFromMockProvider()` | tidak tersedia; kirim `null` |
| `rooted` | pemeriksaan root milik Anda sendiri | pemeriksaan jailbreak milik Anda sendiri |
| `attested` | **Play Integrity API**, diverifikasi di server Anda | **App Attest / DeviceCheck**, diverifikasi di server Anda |
| `platform` | `"android"` | `"ios"` |

### Rantai kepercayaannya, disebut terus terang

Q-Shield **tidak bisa memverifikasi** field-field ini. Field-nya
dilaporkan klien, dan klien bisa berbohong.

Yang membuatnya berarti adalah `attested`: hasil attestation yang
**Anda** verifikasi di server Anda sendiri, lalu Anda pertanggungkan
lewat kunci API Anda. Q-Shield tidak memercayai perangkatnya — Q-Shield
memercayai **Anda** yang menyatakan sudah memeriksanya.

Karena itu jangan kirim `attested: true` kalau Anda belum
memverifikasinya di sisi server. Itu bukan sekadar tidak akurat; itu
memindahkan risiko ke pengguna Anda sendiri.

### Apa yang terjadi pada tiap nilai

| Kondisi | Akibat |
|---|---|
| blok tidak dikirim | `device_integrity: "not_provided"` — **tidak ada penalti** |
| semua bersih, `attested: true` | `"attested"` |
| dilaporkan tanpa attestation | `"reported"` |
| `rooted: true` | `"failed"` + skor |
| `attested: false` | `"failed"` + skor |
| `mock_location: true` | `"failed"` — **putusan lokasi ditolak sama sekali** |

Ketiadaan blok ini tidak dihukum. Setiap klien web akan selalu kosong di
sini, dan menghukumnya berarti menghukum pengguna untuk sesuatu yang
bukan kesalahan mereka. Yang dilakukan sebagai gantinya: ketiadaannya
**diungkapkan** di tanggapan, supaya jelas pemeriksaan itu tidak pernah
dijalankan — bukan dijalankan lalu lolos.

---

## 4. Mendaftarkan merchant Anda

Anda sudah tahu NMID mana milik merchant mana — itu data onboarding
Anda. Memindahkannya ke Q-Shield menutup masalah *cold start*: merchant
tidak perlu menunggu tiga pengamat independen selama 24 jam.

```json
POST /api/v1/merchants
{
  "nmid": "ID1024365478912",
  "lat": -6.914744, "lng": 107.609810,
  "merchant_name": "WARUNG BU SRI",
  "is_mobile": false
}
```

- **Merchant pindah?** Daftarkan ulang di koordinat baru. Jangkar lama
  otomatis berhenti berstatus resmi.
- **Merchant keliling?** `is_mobile: true`. Ikatan lokasi tidak
  diberlakukan, dan bindingnya tidak akan mengklaim titik yang
  disinggahinya.
- **Kunci Anda bocor?** `DELETE /api/v1/merchants/{nmid}` untuk tiap
  NMID yang terlanjur didaftarkan. Hanya pendaftarnya yang bisa
  mencabut, dan setiap pendaftaran tercatat beserta pendaftarnya.

Pendaftaran menghasilkan sinyal `registered_merchant` yang **berbeda**
dari `established_binding`. Auditor selalu bisa membedakan "terverifikasi
karena Anda menyatakannya" dari "terverifikasi karena banyak orang
mengamatinya".

---

## 5. Privasi — yang perlu Anda ketahui sebelum menandatangani apa pun

Q-Shield dirancang supaya bisa dipakai tanpa memindahkan data pribadi
nasabah Anda.

- **Tidak ada `user_id` di skema mana pun.** Bukan "tidak dipakai" —
  tidak ada kolomnya.
- `device_anon_id` yang Anda kirim **tidak pernah disimpan apa adanya.**
  Yang masuk basis data adalah hash yang dilingkupi per-binding,
  sehingga baris pengamatan tidak bisa dirangkai antar-lokasi menjadi
  jejak perjalanan.
- Tabel pengamatan **tidak menyimpan koordinat**.
- Jejak audit mencatat putusan dan alasannya, bukan siapa yang memindai:
  tanpa `device_anon_id`, tanpa koordinat presisi, tanpa alamat IP.

Cara membuktikannya, bukan memercayainya:

```bash
python tests/test_invariants.py     # menjalankan tiga serangan perangkaian jejak
python tests/test_hardening.py      # memeriksa isi jejak audit
```

Karena tidak ada data pribadi yang tersimpan, berbagi data binding
antar-PJP tidak menyentuh kerahasiaan bank maupun UU PDP. Dan berbagi
itulah yang membuat lapisan ini bekerja — stiker penipu tidak berhenti
di batas satu penyelenggara.

---

## 6. Operasional

| Hal | Nilai |
|---|---|
| Autentikasi | header `X-API-Key`, satu kunci per PJP |
| Kuota bawaan | 60 permintaan/menit per klien |
| Anggaran latensi | p50 ~3 ms, p95 ~6 ms (SQLite lokal, belum termasuk jaringan) |
| Versi | `/api/v1/` — lihat `API.md` untuk kebijakan perubahan |

`signals` dan `reasons` adalah **daftar terbuka** — sinyal baru bisa
muncul tanpa naik versi, jadi abaikan nilai yang tidak Anda kenali.
`verdict` dan `action` adalah **kosakata tertutup** — nilai baru di sana
berarti versi baru.
