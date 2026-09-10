"""
Jalur cadangan demo: rekam koordinat venue, putar ulang di dalam gedung.

Masalah yang diselesaikan. Jangkar Q-Shield terikat koordinat spesifik,
jadi seluruh seed lama tidak relevan begitu pindah venue. Lebih buruk
lagi, GPS di dalam gedung kerap melaporkan akurasi >100 m — dan invarian
§6 akan menolak memberi putusan. Sistemnya benar, tapi demonya mati.

Cara pakainya di hari-H:

  1. PAGI, DI LUAR GEDUNG, berdiri persis di titik demo:
       python scripts/venue_fixture.py record -6.9147 107.6098 --accuracy 8
     Koordinat dari HP (Google Maps -> tekan lama -> salin koordinat).
     Rekam saat akurasinya masih bagus.

  2. Seed basis data dengan koordinat yang sama:
       python scripts/seed.py $(python scripts/venue_fixture.py coords)

  3. Cetak prop dengan koordinat yang sama:
       python scripts/make_qr.py $(python scripts/venue_fixture.py coords)

  4. Gladi bersih, dan kalau GPS di dalam ruangan ternyata payah:
       python scripts/venue_fixture.py replay

Yang diputar ulang ditandai eksplisit sebagai replay — di permintaan, di
tanggapan, dan di jejak audit. Menyamarkannya seolah live adalah
kebohongan kecil yang akan dicium juri. Mengakuinya justru menguatkan:
menolak memberi putusan saat sinyal buruk memang fitur, bukan bug.
"""

import json
import os
import sys
from datetime import datetime, timezone

BERKAS = os.environ.get("QSHIELD_VENUE_FIXTURE", "venue.json")


def simpan(lat, lng, accuracy, label):
    data = {
        "label": label,
        "lat": lat,
        "lng": lng,
        "accuracy_m": accuracy,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(BERKAS, "w") as f:
        json.dump(data, f, indent=2)
    return data


def muat():
    if not os.path.exists(BERKAS):
        print(f"Belum ada rekaman di {BERKAS}.", file=sys.stderr)
        print("Rekam dulu di LUAR gedung:", file=sys.stderr)
        print("  python scripts/venue_fixture.py record LAT LNG --accuracy 8",
              file=sys.stderr)
        sys.exit(1)
    with open(BERKAS) as f:
        return json.load(f)


def cmd_record(argv):
    angka = [a for a in argv if not a.startswith("--")]
    if len(angka) < 2:
        print("Butuh koordinat: record LAT LNG [--accuracy N] [--label ...]",
              file=sys.stderr)
        sys.exit(2)
    accuracy = 10.0
    if "--accuracy" in argv:
        accuracy = float(argv[argv.index("--accuracy") + 1])
    label = "titik demo"
    if "--label" in argv:
        label = argv[argv.index("--label") + 1]

    if accuracy > 100:
        print(f"TOLAK: akurasi {accuracy:.0f} m sudah di atas ambang invarian §6.")
        print("Rekaman ini tidak akan berguna — rekam ulang di luar gedung,")
        print("di tempat terbuka, dan tunggu sampai akurasinya turun.")
        sys.exit(1)

    d = simpan(float(angka[0]), float(angka[1]), accuracy, label)
    print(f"Terekam ke {BERKAS}")
    print(f"  {d['label']}: {d['lat']:.6f}, {d['lng']:.6f}  (+/- {d['accuracy_m']:.0f} m)")
    print()
    print("Berikutnya, pakai koordinat yang SAMA untuk seed dan prop:")
    print(f"  python scripts/seed.py {d['lat']:.6f} {d['lng']:.6f}")
    print(f"  python scripts/make_qr.py {d['lat']:.6f} {d['lng']:.6f}")


def cmd_coords(argv):
    d = muat()
    print(f"{d['lat']:.6f} {d['lng']:.6f}")


def cmd_show(argv):
    d = muat()
    umur = datetime.now(timezone.utc) - datetime.fromisoformat(d["recorded_at"])
    print(json.dumps(d, indent=2))
    print()
    print(f"Umur rekaman: {umur.total_seconds() / 3600:.1f} jam")
    if umur.days >= 1:
        print("PERINGATAN: rekaman lebih dari sehari. Kalau venue-nya beda,")
        print("rekam ulang — jangkar lama tidak akan cocok.")


def cmd_replay(argv):
    """Jalankan seluruh naskah demo memakai koordinat rekaman."""
    import tempfile
    from datetime import timedelta

    # Gladi bersih dijalankan di dalam proses, bukan lewat jaringan:
    # pembatas laju dan autentikasi klien tidak relevan di sini.
    os.environ.setdefault("QSHIELD_RATE_LIMIT", "off")
    os.environ.setdefault("QSHIELD_AUTH", "off")
    from fastapi.testclient import TestClient

    from qshield import api, emvco
    from qshield.store import Store
    import seed

    d = muat()
    lat, lng, acc = d["lat"], d["lng"], d["accuracy_m"]

    db = os.path.join(tempfile.mkdtemp(), "replay.db")
    api.store = Store(db)
    now = datetime.now(timezone.utc)
    api.store.seed_binding(
        nmid=seed.WARUNG["nmid"], lat=lat, lng=lng,
        merchant_name=seed.WARUNG["name"], observer_count=47,
        first_seen=now - timedelta(days=180), last_seen=now - timedelta(hours=6),
    )
    c = TestClient(api.app)

    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": seed.PENIPU["pan"],
        "02": seed.PENIPU["nmid"], "03": "UMI"})
    dasar = {"00": "01", "01": "11", "26": acct, "52": "5812", "53": "360",
             "58": "ID", "59": seed.PENIPU["name"], "60": "BANDUNG",
             "61": "40257"}

    naskah = [
        ("1. Pelanggan memindai QR asli di warung",
         seed.make_qr(seed.WARUNG["nmid"], seed.WARUNG["pan"], seed.WARUNG["name"]),
         acc, "verified / proceed — jangkar cocok, 47 pengamatan"),
        ("2. Stiker penipu ditempel menutupi yang asli",
         seed.make_qr(seed.PENIPU["nmid"], seed.PENIPU["pan"], seed.PENIPU["name"]),
         acc, "anomaly / cooling_off — PIN-nya tidak pernah dimasukkan"),
        ("3. QR yang dibangkitkan ulang, cacat bentuknya",
         emvco.build({**dasar, "54": "250000.00"}),
         acc, "Layer 2 menangkap kontradiksi struktural"),
        ("4. GPS memburuk — sistem menolak memberi putusan",
         seed.make_qr(seed.WARUNG["nmid"], seed.WARUNG["pan"], seed.WARUNG["name"]),
         250.0, "unknown / warn — mengaku tidak tahu, bukan menebak"),
    ]

    print("=" * 70)
    print("PUTAR ULANG NASKAH DEMO — koordinat dari rekaman, bukan GPS langsung")
    print("=" * 70)
    print(f"  {d['label']}: {lat:.6f}, {lng:.6f}  (+/- {acc:.0f} m)")
    print(f"  direkam {d['recorded_at']}")
    print()

    gagal = 0
    for i, (judul, payload, accuracy, harapan) in enumerate(naskah):
        r = c.post("/api/v1/verify", json={
            "payload": payload, "lat": lat, "lng": lng,
            "device_anon_id": f"gladi-bersih-{i:04d}",
            "accuracy_m": accuracy,
            "location_source": "replay",
        })
        j = r.json()
        print("-" * 70)
        print(judul)
        print(f"  -> {j['verdict']} / {j['action']}   skor {j['risk_score']}"
              f"  (L1 {j['layers']['location']} + L2 {j['layers']['behavior']})")
        print(f"     sumber lokasi: {j['location_source']}")
        for alasan in j["reasons"]:
            print(f"     - {alasan}")
        print(f"     harapan: {harapan}")
        if j["location_source"] != "replay":
            print("     GAGAL: penanda replay tidak muncul di tanggapan")
            gagal += 1
        print()

    print("-" * 70)
    if gagal:
        print(f"{gagal} langkah bermasalah.")
        return 1
    print("Naskah utuh. Setiap langkah ditandai replay secara terbuka —")
    print("sampaikan itu ke juri, jangan disembunyikan.")
    return 0


PERINTAH = {
    "record": cmd_record,
    "replay": cmd_replay,
    "show": cmd_show,
    "coords": cmd_coords,
}

if __name__ == "__main__":
    argv = sys.argv[1:]
    if not argv or argv[0] not in PERINTAH:
        print(__doc__)
        print(f"Perintah: {', '.join(PERINTAH)}")
        sys.exit(0 if not argv else 2)
    sys.exit(PERINTAH[argv[0]](argv[1:]) or 0)
