# Q-Shield API v1

**Status:** stabil menuju code freeze 30 September 2026
**Dikunci oleh:** `tests/test_contract.py`

Bentuk API di dokumen ini bukan deskripsi, melainkan **kontrak**.
`test_contract.py` membacanya dari skema OpenAPI yang dihasilkan kode
dan gagal kalau ada yang bergeser — field hilang, wajib berubah jadi
opsional, tipe bergeser, atau nilai enum bertambah diam-diam.

---

## Kebijakan versi

Prefiks `/api/v1/` bukan hiasan. Aturannya:

| Perubahan | Butuh versi baru? |
|---|---|
| Menambah field **opsional** pada permintaan | tidak |
| Menambah field pada tanggapan | tidak — klien wajib mengabaikan yang tidak dikenal |
| Menambah nilai baru pada `signals` atau `reasons` | tidak — keduanya daftar terbuka |
| Menjadikan field permintaan **wajib** | **ya** |
| Menghapus atau mengganti nama field | **ya** |
| Menambah nilai pada `verdict`, `action`, `location_source` | **ya** — kosakata tertutup, klien memetakannya ke UI |
| Mengetatkan batas validasi | **ya** kalau menolak permintaan yang tadinya sah |

`signals` dan `reasons` sengaja **terbuka**: itu tempat sinyal baru
mendarat tanpa memecah klien. `verdict` dan `action` sengaja
**tertutup**: klien memetakannya ke tampilan, dan nilai tak dikenal
membuat mereka tidak tahu harus menampilkan apa.

### Perubahan yang sudah terjadi

| Tanggal | Perubahan | Sifat |
|---|---|---|
| 10 Sep 2026 | `layers` ditambahkan ke tanggapan | aditif |
| 10 Sep 2026 | `location_source` ditambahkan (permintaan opsional + tanggapan) | aditif |
| 10 Sep 2026 | **`accuracy_m` jadi wajib** | **memecah klien** |
| 10 Sep 2026 | `X-API-Key` jadi syarat pada `/verify` | **memecah klien** |
| 11 Sep 2026 | `POST/DELETE /api/v1/merchants` ditambahkan | aditif |
| 11 Sep 2026 | sinyal `registered_merchant`, `nmid_changed_at_registered_anchor`, `mobile_merchant` | aditif — `signals` memang daftar terbuka |

Dua yang terakhir terjadi sebelum ada klien eksternal, jadi versinya
tidak dinaikkan. Setelah code freeze, perubahan sekelas itu menuntut
`/api/v2/`.

---

## Autentikasi

```
X-API-Key: <kunci mentah>
```

Wajib pada `/api/v1/verify`. Terbitkan lewat
`python scripts/make_apikey.py <client_id>`.

| Kode | Arti |
|---|---|
| `401` | kunci tidak valid atau tidak disertakan |
| `503` | server belum dikonfigurasi kunci sama sekali (gagal tertutup) |

Untuk demo lokal, jalankan dengan `QSHIELD_AUTH=off`.

---

## `POST /api/v1/verify`

### Permintaan

| Field | Tipe | Wajib | Batas | Catatan |
|---|---|---|---|---|
| `payload` | string | ya | 8–1024 char, ASCII yang bisa dicetak | string QRIS mentah hasil scan |
| `lat` | number | ya | −90…90 | |
| `lng` | number | ya | −180…180 | |
| `device_anon_id` | string | ya | 8–64 char, `[A-Za-z0-9_-]` | pengenal acak per perangkat, **bukan** identitas pengguna |
| `accuracy_m` | number | ya | 0…100000 | radius keyakinan GPS dalam meter |
| `location_source` | string | tidak | `live` \| `replay` | bawaan `live` |

`accuracy_m` wajib dengan sengaja. Tanpa tahu seberapa bagus fix-nya,
jangkar tidak bisa dinilai — dan kalau field ini opsional, penyerang
yang akurasinya buruk tinggal tidak mengirimkannya untuk melewati
pemeriksaan ">100 m".

`device_anon_id` tidak pernah disimpan apa adanya; lihat `PROCESS-LOG.md`
Keputusan 24.

```json
{
  "payload": "00020101021126660014ID.CO.QRIS.WWW...",
  "lat": -6.914744,
  "lng": 107.609810,
  "device_anon_id": "550e8400-e29b-41d4-a716-446655440000",
  "accuracy_m": 12
}
```

### Tanggapan `200`

| Field | Tipe | Catatan |
|---|---|---|
| `verdict` | string | `verified` \| `unknown` \| `anomaly` — **tertutup** |
| `action` | string | `proceed` \| `warn` \| `step_up` \| `cooling_off` — **tertutup** |
| `risk_score` | integer | 0–100 |
| `reasons` | array of string | penjelasan siap tampil, bahasa manusia — **terbuka** |
| `signals` | array of string | nama sinyal untuk analitik — **terbuka** |
| `layers` | object | `{ "location": int, "behavior": int }` |
| `merchant` | object | `nmid`, `name`, `city`, `criteria`, `is_static` |
| `location_source` | string | `live` \| `replay` |
| `processing_ms` | number | |

```json
{
  "verdict": "anomaly",
  "action": "cooling_off",
  "risk_score": 83,
  "reasons": ["Merchant ID berbeda dari 47 pengamatan sebelumnya di lokasi ini"],
  "signals": ["nmid_changed_at_anchor"],
  "layers": { "location": 83, "behavior": 0 },
  "merchant": {
    "nmid": "ID1024365478912", "name": "WARUNG BU SRI",
    "city": "BANDUNG", "criteria": "Usaha Mikro", "is_static": true
  },
  "location_source": "live",
  "processing_ms": 2.8
}
```

**`reasons` yang dipakai, bukan `risk_score`.** Angka tidak bisa
dijelaskan ke pengguna maupun auditor; kalimatnya bisa. `risk_score`
ada untuk analitik dan penyetelan ambang, bukan untuk ditampilkan.

### Kode kesalahan

| Kode | Sebab |
|---|---|
| `401` | kunci API tidak valid atau tidak disertakan |
| `413` | badan permintaan > 8 KB |
| `422` | field tidak lolos validasi, atau payload QRIS tidak bisa diurai |
| `429` | kuota terlampaui — lihat `Retry-After` |
| `503` | autentikasi belum dikonfigurasi di server |

### Header tanggapan

`X-RateLimit-Limit`, `X-RateLimit-Remaining`, dan pada `429`
`Retry-After`. Seluruh tanggapan membawa `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Cache-Control`.

---

## `POST /api/v1/merchants`

Mendaftarkan ikatan merchant-lokasi. Yang mendaftarkan adalah PJP yang
meng-onboard merchant, jadi ia memang mengetahui NMID mana milik siapa.
Menutup cold start: merchant tidak perlu menunggu tiga pengamat selama
24 jam.

| Field | Tipe | Wajib | Catatan |
|---|---|---|---|
| `nmid` | string | ya | 3–32 karakter alfanumerik |
| `lat` | number | ya | |
| `lng` | number | ya | |
| `merchant_name` | string | tidak | maks 99 karakter |
| `is_mobile` | boolean | tidak | merchant keliling — ikatan lokasi tidak berlaku |

Mendaftarkan NMID yang sudah terdaftar oleh **PJP yang sama** berarti
memperbarui — inilah jalur relokasi merchant. Jangkar lama otomatis
berhenti berstatus resmi.

| Kode | Arti |
|---|---|
| `201` | terdaftar |
| `401` | kunci API tidak valid |
| `409` | NMID sudah didaftarkan penyelenggara lain |
| `422` | field tidak lolos validasi |

## `DELETE /api/v1/merchants/{nmid}`

Mencabut pendaftaran. **Hanya PJP yang mendaftarkan yang boleh.**

Pencabutan mengembalikan status, **tidak menghapus pengamatan** —
konsensus yang sudah terkumpul adalah bukti yang sah, terlepas dari
status pendaftaran.

| Kode | Arti |
|---|---|
| `200` | dicabut |
| `403` | bukan pendaftarnya |
| `404` | NMID tidak terdaftar |

### Catatan keamanan

Ini **jalur kepercayaan baru**. Kunci PJP yang bocor bisa dipakai
mendaftarkan stiker palsu sebagai `verified`. Itu tidak bisa dicegah
dari sisi Q-Shield — yang bisa dilakukan adalah membuatnya terlacak dan
bisa dibatalkan: tiap pendaftaran mencatat pendaftarnya, dan sinyal
`registered_merchant` selalu berbeda dari `established_binding`
sehingga auditor tahu sebuah verdict `verified` datang dari pernyataan
atau dari konsensus.

## `GET /api/v1/health`

Terbuka tanpa autentikasi, untuk monitoring.

```json
{ "status": "ok", "bindings": 5, "observations": 128, "merchants": 3 }
```

---

## Catatan untuk klien

1. **Abaikan field tanggapan yang tidak dikenal.** Field baru bisa
   muncul tanpa naik versi.
2. **Tampilkan `reasons`, bukan `risk_score`.**
3. **Petakan `action`, bukan `verdict`,** ke perilaku UI. `verdict`
   menjawab "apa yang kami ketahui", `action` menjawab "apa yang
   sebaiknya dilakukan" — dan yang kedua itulah yang menentukan layar.
4. **Perlakukan `unknown` sebagai peringatan, bukan lampu hijau.**
   Ini invarian, bukan preferensi: ketiadaan bukti bukan kepercayaan.
5. **Teruskan `coords.accuracy` apa adanya** dari Geolocation API.
   Jangan dibulatkan, jangan diisi nilai tetap — keduanya menghasilkan
   penilaian yang salah, dan nilai di bawah 1 m ditandai sebagai
   mustahil secara fisik.
