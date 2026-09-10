# Q-Shield — PoC

Verifikasi kepercayaan QRIS sebelum PIN entry, dua lapis:

- **Layer 1 — ikatan merchant-lokasi.** Apakah merchant ini memang yang
  seharusnya ada di lokasi ini.
- **Layer 2 — perilaku artefak QR.** Apakah kode yang barusan dipindai
  berperilaku seperti QR yang sah.

Keduanya bisa gagal sendiri-sendiri, jadi Layer 2 **melengkapi**, bukan
menggantikan, putusan Layer 1. Aturan komposisinya ada di
`binding.compose()` dan dicatat sebagai Keputusan 10 di `PROCESS-LOG.md`.

## Menjalankan

```bash
python -m venv .venv && source .venv/bin/activate   # sekali saja
pip install -e .                                     # install package qshield (editable)
python scripts/seed.py                               # isi data demo, cetak QR asli & palsu
uvicorn qshield.api:app --reload --host 0.0.0.0 --port 8000
```

Dokumentasi interaktif: http://localhost:8000/docs

## Menguji

```bash
python tests/test_emvco.py
python tests/test_geo.py
python tests/test_binding.py
python tests/test_invariants.py               # kunci regresi kedelapan invarian
python tests/test_adversarial.py              # 13 skenario dari sisi penyerang
python tests/test_hardening.py                # input, auth, rate limit, audit, konkurensi
PYTHONPATH=scripts python tests/test_api.py   # test_api.py mengimpor scripts/seed.py

python scripts/calibrate_geo.py               # kalibrasi presisi geohash
python scripts/calibrate_layer2.py            # kalibrasi konstanta Layer 2
```

`test_invariants.py` keluar dengan status bukan-nol kalau ada satu invarian
yang jebol — jalankan itu sebelum commit apa pun yang menyentuh penilaian.

## Struktur

```
src/qshield/     package utama — import sebagai `qshield` setelah `pip install -e .`
  emvco.py         parser payload QRIS (EMVCo TLV) + CRC16
  geo.py           geohash encode/decode, tetangga, haversine
  binding.py       Layer 1 — konsensus lokasi, plus aturan komposisi
  behavior.py      Layer 2 — sinyal struktural & perilaku artefak QR
  store.py         persistensi SQLite
  auth.py          autentikasi klien PJP (kunci disimpan sebagai hash)
  limits.py        pembatasan laju (memori, tanpa menyimpan IP)
  audit.py         jejak audit terstruktur tanpa PII
  api.py           endpoint FastAPI
scripts/         skrip yang dijalankan langsung, bukan bagian dari package
  seed.py             isi data demo, cetak QR asli & palsu
  make_qr.py          cetak prop QR + verifikasi keterbacaan (OpenCV)
  venue_fixture.py    rekam koordinat venue, putar ulang naskah demo
  make_apikey.py      terbitkan kunci API untuk satu PJP
  calibrate_geo.py    kalibrasi presisi geohash
  calibrate_layer2.py kalibrasi konstanta Layer 2
tests/           test_*.py — dijalankan langsung (bukan lewat pytest)
```

`pip install -e .` membuat `qshield` importable dari mana saja di dalam
venv ini (dipakai oleh `uvicorn qshield.api:app`, `tests/`, dan
`scripts/`), tanpa perlu `PYTHONPATH` manual — kecuali `test_api.py`,
yang juga mengimpor `scripts/seed.py` secara langsung.

Keputusan desain dan temuan tercatat di `PROCESS-LOG.md`.

## Troubleshooting: `ModuleNotFoundError: No module named 'qshield'`

Proyek ini ada di `~/Documents`, yang di macOS biasanya disinkron iCloud
Drive. iCloud kadang diam-diam nge-flag file
`.venv/lib/python*/site-packages/__editable__.qshield-*.pth` (dibuat oleh
`pip install -e .`) sebagai **hidden**, dan Python 3.14 melewati file
`.pth` yang hidden tanpa pesan error — jadi `import qshield` gagal walau
sudah ter-install, dan bisa berulang meski sudah pernah "sembuh".

Sudah ditambal secara permanen: `.venv/bin/activate` mengisi
`PYTHONPATH` ke `src/` setiap kali di-source, jadi tidak lagi bergantung
pada file `.pth` itu sama sekali. Kalau bikin ulang `.venv` dari nol dan
error ini muncul lagi, cek dulu:

```bash
echo $PYTHONPATH   # harus mengandung .../src setelah `source .venv/bin/activate`
```

Kalau venv memang dibuat ulang, tambal manualnya:
```bash
chflags nohidden .venv/lib/python*/site-packages/__editable__.qshield-*.pth
```
— tapi ini tidak permanen selama proyek masih di folder yang disinkron
iCloud. Solusi paling tuntas: pindahkan proyek ke folder yang tidak
disinkron iCloud (mis. di luar `~/Documents`/`~/Desktop`).

## Prop fisik untuk demo

```bash
pip install -e '.[props]'                     # qrcode, pillow, opencv
python scripts/make_qr.py -6.2088 106.8456    # koordinat SAMA dengan seed.py
python scripts/make_qr.py --calibrate         # sapu ulang parameter cetak
```

Mencetak empat skenario ke `props/` lalu memverifikasi tiap berkas lewat
OpenCV dalam sembilan kondisi — diperkecil, diburamkan, dimiringkan,
diredupkan, diberi derau. Jangan cetak apa pun yang belum berstatus `SIAP`.

## Jalur cadangan demo (GPS indoor)

GPS di dalam gedung kerap melaporkan akurasi >100 m, dan invarian §6 akan
menolak memberi putusan — sistemnya benar, tapi demonya mati. Siapkan
rekamannya **sebelum** hari-H, jangan panik di lokasi.

```bash
# PAGI, DI LUAR GEDUNG, berdiri persis di titik demo
python scripts/venue_fixture.py record -6.9147 107.6098 --accuracy 8

# seed dan prop pakai koordinat yang SAMA
python scripts/seed.py    $(python scripts/venue_fixture.py coords)
python scripts/make_qr.py $(python scripts/venue_fixture.py coords)

# gladi bersih / fallback saat GPS ruangan payah
python scripts/venue_fixture.py replay
```

Yang diputar ulang ditandai eksplisit sebagai replay — di permintaan
(`location_source`), di tanggapan, di alasan paling depan, dan di jejak
audit. Penilaiannya tidak berubah sedikit pun, dan mode ini tidak bisa
dipakai membobol invarian akurasi GPS (diuji di `test_hardening.py`).
Sampaikan terus terang ke juri: menolak memberi putusan saat sinyal buruk
memang fitur, bukan bug.

## Konfigurasi

Semua lewat env var, semuanya punya nilai bawaan yang aman:

| Variabel | Bawaan | Guna |
|---|---|---|
| `QSHIELD_API_KEYS` | *(kosong)* | `client_id:sha256` dipisah koma; kosong = endpoint verifikasi menolak melayani |
| `QSHIELD_AUTH` | *(kosong)* | `off` mematikan autentikasi, untuk demo lokal |
| `QSHIELD_ALLOWED_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | daftar origin CORS |
| `QSHIELD_RATE_LIMIT` | `60` | permintaan per jendela; `off` mematikan |
| `QSHIELD_RATE_WINDOW` | `60` | panjang jendela (detik) |
| `QSHIELD_LOG_LEVEL` | `INFO` | level audit log |
| `QSHIELD_VENUE_FIXTURE` | `venue.json` | berkas rekaman koordinat |

Di WiFi acara yang ber-NAT seluruh ruangan terlihat sebagai satu alamat —
kalau rate limit mulai menolak permintaan sah saat gladi bersih, jalankan
dengan `QSHIELD_RATE_LIMIT=off`.

## Autentikasi klien

Klien Q-Shield adalah **PJP**, bukan orang. Satu kunci mewakili satu
penyelenggara yang memanggil API sebelum PIN entry.

```bash
python scripts/make_apikey.py pjp-alpha     # cetak kunci + baris env
export QSHIELD_API_KEYS="pjp-alpha:<sha256>"
```

Klien menyertakannya sebagai header:

```
X-API-Key: <kunci mentah>
```

Tiga sifat yang disengaja:

- **Gagal tertutup.** Kalau `QSHIELD_API_KEYS` kosong dan `QSHIELD_AUTH`
  tidak disetel `off`, endpoint verifikasi mengembalikan `503`, bukan
  melayani tanpa autentikasi. Ketiadaan konfigurasi bukan izin — logika
  yang sama dengan invarian §2.
- **Kunci disimpan sebagai hash.** Konfigurasi yang bocor tidak langsung
  memberi penyerang kunci yang bisa dipakai, dan kunci mentah tidak
  pernah masuk log — bahkan saat autentikasi gagal.
- **Kuota dihitung per klien, bukan per IP.** Ini yang menutup batasan R8:
  di balik NAT seluruh ruangan berbagi satu alamat.

Untuk demo lokal jalankan dengan `QSHIELD_AUTH=off`.

## Endpoint

```
GET  /api/v1/health
POST /api/v1/verify
```

Contoh permintaan:

```json
{
  "payload": "00020101021126660014ID.CO.QRIS.WWW...",
  "lat": -6.914744,
  "lng": 107.609810,
  "device_anon_id": "uuid-v4",
  "accuracy_m": 12
}
```

Contoh tanggapan:

```json
{
  "verdict": "anomaly",
  "action": "cooling_off",
  "risk_score": 83,
  "reasons": [
    "Merchant ID berbeda dari 47 pengamatan sebelumnya di lokasi ini"
  ],
  "signals": ["nmid_changed_at_anchor"],
  "layers": { "location": 83, "behavior": 0 },
  "processing_ms": 2.8
}
```

`layers` memisahkan sumbangan tiap lapisan supaya bisa ditelusuri dari mana
skornya datang — `location` untuk Layer 1, `behavior` untuk Layer 2.
