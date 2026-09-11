"""
Isi database dengan riwayat untuk skenario demo.

Lokasi "warung" bisa diatur agar cocok dengan tempat kalian merekam.
GPS HP akan melaporkan koordinat asli, jadi jangkar di database
harus berada di lokasi yang sama supaya skenario berjalan.

  python seed.py                          pakai koordinat bawaan (Bandung)
  python seed.py -6.2088 106.8456         pakai koordinat sendiri
  python seed.py --here                   ambil dari IP (kasar, ±beberapa km)
"""

import os
import sys
from datetime import datetime, timedelta, timezone

from qshield import emvco
from qshield.store import Store

NOW = datetime.now(timezone.utc)

DEFAULT_LAT, DEFAULT_LNG = -6.914744, 107.609810

WARUNG = {
    "nmid": "ID1024365478912",
    "pan": "936000149000000001",
    "name": "WARUNG BU SRI",
    "lat": DEFAULT_LAT,
    "lng": DEFAULT_LNG,
}

PENIPU = {
    "nmid": "ID1099887766554",
    "pan": "936000149000000002",
    "name": "WARUNG BU SRI",
}

# Lokasi lain tempat NMID penipu ikut muncul, relatif jauh dari warung.
SEBAR = [
    (-6.2088, 106.8456, "Jakarta Pusat"),
    (-7.2575, 112.7521, "Surabaya"),
    (-6.5971, 106.8060, "Bogor"),
]


def make_qr(nmid, pan, name, city="BANDUNG"):
    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": pan, "02": nmid, "03": "UMI",
    })
    return emvco.build({
        "00": "01", "01": "11", "26": acct, "52": "5812",
        "53": "360", "58": "ID", "59": name, "60": city, "61": "40257",
    })


def _shift(lat, lng, north_m, east_m):
    import math
    return (
        lat + north_m / 111320,
        lng + east_m / (111320 * math.cos(math.radians(lat))),
    )


def main(lat=None, lng=None):
    lat = lat if lat is not None else DEFAULT_LAT
    lng = lng if lng is not None else DEFAULT_LNG
    WARUNG["lat"], WARUNG["lng"] = lat, lng

    # WAL meninggalkan dua berkas pendamping. Menghapus berkas utama
    # saja membuat SQLite menemukan -wal/-shm yatim dan gagal dengan
    # "disk I/O error" — persis saat kalian re-seed di venue.
    for akhiran in ("", "-wal", "-shm"):
        berkas = "qshield.db" + akhiran
        if os.path.exists(berkas):
            os.remove(berkas)
    s = Store("qshield.db")

    # Jangkar utama: warung sah dengan riwayat panjang.
    s.seed_binding(
        nmid=WARUNG["nmid"], lat=lat, lng=lng,
        merchant_name=WARUNG["name"], observer_count=47,
        first_seen=NOW - timedelta(days=180),
        last_seen=NOW - timedelta(hours=6),
    )

    # Sebaran NMID penipu. Titik pertama digeser 3 km dari lokasi kalian
    # supaya sinyal scatter tetap masuk akal di mana pun demo dijalankan.
    near_lat, near_lng = _shift(lat, lng, 3000, 1500)
    for plat, plng in [(near_lat, near_lng)] + [(a, b) for a, b, _ in SEBAR[1:]]:
        s.seed_binding(
            nmid=PENIPU["nmid"], lat=plat, lng=plng,
            merchant_name="WARUNG BU SRI", observer_count=2,
            first_seen=NOW - timedelta(days=3),
            last_seen=NOW - timedelta(hours=8),
        )

    print("Seed selesai:", s.stats())
    print()
    print(f"Jangkar warung : {lat:.6f}, {lng:.6f}")
    print()
    print("QR ASLI   ", make_qr(WARUNG["nmid"], WARUNG["pan"], WARUNG["name"]))
    print()
    print("QR PALSU  ", make_qr(PENIPU["nmid"], PENIPU["pan"], PENIPU["name"]))
    s.close()


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) >= 2:
        main(float(args[0]), float(args[1]))
    else:
        main()