"""Test API end-to-end lewat TestClient."""

import os

# Test ini sengaja membanjiri API, jadi pembatasan laju dimatikan di sini,
# begitu juga autentikasi klien — keduanya diuji tersendiri di
# tests/test_hardening.py.
os.environ["QSHIELD_RATE_LIMIT"] = "off"
os.environ["QSHIELD_AUTH"] = "off"


import seed
from fastapi.testclient import TestClient

seed.main()

from qshield import api
from qshield.api import app

api.store.close()
from qshield.store import Store
api.store = Store("qshield.db")

client = TestClient(app)

QR_ASLI = seed.make_qr(seed.WARUNG["nmid"], seed.WARUNG["pan"], seed.WARUNG["name"])
QR_PALSU = seed.make_qr(seed.PENIPU["nmid"], seed.PENIPU["pan"], seed.PENIPU["name"])
LAT, LNG = seed.WARUNG["lat"], seed.WARUNG["lng"]


def call(payload, lat=LAT, lng=LNG, device="demo-device-0001", acc=12.0):
    body = {"payload": payload, "lat": lat, "lng": lng,
            "device_anon_id": device, "accuracy_m": acc}
    return client.post("/api/v1/verify", json=body)


def show(label, r):
    d = r.json()
    print(f"\n{label}")
    print(f"  HTTP {r.status_code}")
    if r.status_code != 200:
        print(f"  {d}")
        return d
    print(f"  {d['verdict']} / {d['action']}  skor {d['risk_score']}  "
          f"{d['processing_ms']} ms")
    print(f"  merchant: {d['merchant']['name']}  ({d['merchant']['nmid']})")
    for x in d["reasons"]:
        print(f"  - {x}")
    return d


print("=" * 66)
print("A. Health")
print("=" * 66)
print(" ", client.get("/api/v1/health").json())

print()
print("=" * 66)
print("B. SKENARIO 1 — scan QR asli di warung")
print("=" * 66)
d = show("hasil", call(QR_ASLI))
assert d["verdict"] == "verified" and d["action"] == "proceed"

print()
print("=" * 66)
print("C. SKENARIO 2 — stiker palsu di lokasi yang sama")
print("=" * 66)
d = show("hasil", call(QR_PALSU))
assert d["verdict"] == "anomaly"
assert "nmid_changed_at_anchor" in d["signals"] or "nmid_scatter" in d["signals"]

print()
print("=" * 66)
print("D. SKENARIO 3 — NMID tersebar, discan di lokasi keempat")
print("=" * 66)
d = show("hasil", call(QR_PALSU, lat=-6.9000, lng=107.6200))
assert d["verdict"] == "anomaly" and "nmid_scatter" in d["signals"]

print()
print("=" * 66)
print("E. Stiker palsu TIDAK ikut membangun reputasi")
print("=" * 66)
before = client.get("/api/v1/health").json()
for i in range(5):
    call(QR_PALSU, device=f"dev-{i:04d}")
after = client.get("/api/v1/health").json()
print(f"  sebelum {before}")
print(f"  sesudah {after}")
assert before["bindings"] == after["bindings"], "anomali tidak boleh dicatat"
print("  OK — 5 scan anomali tidak menambah binding")

print()
print("=" * 66)
print("F. Akurasi GPS buruk")
print("=" * 66)
d = show("hasil", call(QR_ASLI, acc=350))
assert d["signals"] == ["low_gps_accuracy"]

print()
print("=" * 66)
print("G. Payload rusak")
print("=" * 66)
show("hasil", call("00020101021126"))
show("hasil", call(QR_ASLI[:-4] + "0000"))

print()
print("=" * 66)
print("H. Akumulasi pengamat di lokasi baru")
print("=" * 66)
NEW_LAT, NEW_LNG = -6.200000, 106.816666
QR_BARU = seed.make_qr("ID1033334444555", "936000149000000009", "KOPI PAGI", "JAKARTA")
for i in range(4):
    d = call(QR_BARU, lat=NEW_LAT, lng=NEW_LNG, device=f"newdev-{i:04d}").json()
    print(f"  scan {i+1}: {d['verdict']:9} skor {d['risk_score']:3}  {d['reasons'][0][:52]}")
print("  (status tetap unknown: ambang usia 24 jam belum terpenuhi)")

print()
print("=" * 66)
print("I. Latency")
print("=" * 66)
import time
times = []
for i in range(200):
    t = time.perf_counter()
    call(QR_ASLI, device=f"perf-{i}")
    times.append((time.perf_counter() - t) * 1000)
times.sort()
print(f"  p50 {times[100]:.1f} ms   p95 {times[190]:.1f} ms   max {times[-1]:.1f} ms")
assert times[190] < 200, "p95 melebihi anggaran 200 ms"

print("\n\nSemua test API lolos.")
