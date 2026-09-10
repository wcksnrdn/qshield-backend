# Q-Shield — PoC Layer 1

Verifikasi ikatan merchant-lokasi sebelum PIN entry.

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
PYTHONPATH=scripts python tests/test_api.py   # test_api.py mengimpor scripts/seed.py
python scripts/calibrate_geo.py               # kalibrasi presisi geohash
```

## Struktur

```
src/qshield/     package utama — import sebagai `qshield` setelah `pip install -e .`
  emvco.py         parser payload QRIS (EMVCo TLV) + CRC16
  geo.py           geohash encode/decode, tetangga, haversine
  binding.py       logika konsensus dan penilaian risiko
  store.py         persistensi SQLite
  api.py           endpoint FastAPI
scripts/         skrip yang dijalankan langsung, bukan bagian dari package
  seed.py          isi data demo, cetak QR asli & palsu
  calibrate_geo.py kalibrasi presisi geohash
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
  "processing_ms": 2.8
}
```
