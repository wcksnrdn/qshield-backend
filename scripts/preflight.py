"""
Pemeriksaan pra-demo. Jalankan pagi hari-H, sebelum juri datang.

    python scripts/preflight.py

Memeriksa satu per satu hal yang kalau salah baru ketahuan di depan
juri: konfigurasi, basis data, jangkar venue, prop tercetak, dan apakah
API benar-benar menjawab. Keluar dengan status bukan-nol kalau ada yang
tidak siap, supaya bisa dipakai sebagai gerbang, bukan sekadar bacaan.

Yang TIDAK diperiksa di sini: apakah GPS di ruangan bagus. Itu memang
tidak bisa diketahui sampai kalian berdiri di sana — dan justru untuk
itulah `venue_fixture.py replay` disiapkan.
"""

import os
import subprocess
import sys
from datetime import datetime, timezone

AKAR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_hasil = []


def periksa(nama, wajib=True):
    def deco(fn):
        try:
            pesan = fn()
            _hasil.append((nama, "SIAP", pesan or "", wajib))
        except AssertionError as exc:
            _hasil.append((nama, "GAGAL", str(exc), wajib))
        except Exception as exc:
            _hasil.append((nama, "GAGAL", f"{type(exc).__name__}: {exc}", wajib))
        return fn
    return deco


@periksa("Konfigurasi tidak meninggalkan lubang")
def _c1():
    from qshield import config
    bahaya = [p for t, p in config.warnings() if t == "BAHAYA"]
    if bahaya:
        # Untuk demo lokal ini memang disengaja, jadi bukan kegagalan —
        # tapi harus terbaca, bukan tersembunyi.
        return ("sengaja terbuka untuk demo: "
                + "; ".join(p.split(" — ")[0] for p in bahaya))
    return "seluruh lapis pertahanan aktif"


@periksa("Basis data ada dan berisi jangkar")
def _c2():
    from qshield.store import Store
    path = os.environ.get("QSHIELD_DB", os.path.join(AKAR, "qshield.db"))
    assert os.path.exists(path), (
        f"{path} tidak ada — jalankan scripts/seed.py dulu")
    s = Store(path)
    st = s.stats()
    s.close()
    assert st["bindings"] > 0, "basis data kosong — jalankan scripts/seed.py"
    return (f"{st['bindings']} binding, {st['merchants']} merchant, "
            f"{st['observations']} pengamatan")


@periksa("Jangkar demo cocok dengan koordinat venue")
def _c3():
    import json

    from qshield import geo
    from qshield.store import Store

    fixture = os.environ.get(
        "QSHIELD_VENUE_FIXTURE", os.path.join(AKAR, "venue.json"))
    assert os.path.exists(fixture), (
        "venue.json belum ada — rekam di LUAR gedung: "
        "python scripts/venue_fixture.py record LAT LNG --accuracy 8")

    with open(fixture) as f:
        v = json.load(f)

    umur = datetime.now(timezone.utc) - datetime.fromisoformat(v["recorded_at"])
    assert v["accuracy_m"] <= 100, (
        f"rekaman punya akurasi {v['accuracy_m']:.0f} m — di atas ambang "
        f"invarian §6, rekam ulang di tempat terbuka")

    s = Store(os.environ.get("QSHIELD_DB", os.path.join(AKAR, "qshield.db")))
    baris = s.conn.execute(
        "SELECT nmid, lat, lng, merchant_name FROM bindings "
        "ORDER BY observer_count DESC LIMIT 1").fetchone()
    s.close()
    assert baris, "tidak ada binding untuk dicocokkan"

    jarak = geo.haversine_m(v["lat"], v["lng"], baris["lat"], baris["lng"])
    assert jarak <= 50, (
        f"jangkar terkuat berjarak {jarak:.0f} m dari koordinat venue — "
        f"seed dibuat untuk lokasi lain. Jalankan ulang:\n"
        f"           python scripts/seed.py "
        f"$(python scripts/venue_fixture.py coords)")

    jam = umur.total_seconds() / 3600
    return (f"{baris['merchant_name']} berjarak {jarak:.0f} m dari titik "
            f"venue; rekaman berumur {jam:.1f} jam")


@periksa("Prop QR tercetak dan terbaca", wajib=False)
def _c4():
    props = os.path.join(AKAR, "props")
    assert os.path.isdir(props), (
        "folder props/ belum ada — jalankan: python scripts/make_qr.py "
        "$(python scripts/venue_fixture.py coords)")
    berkas = sorted(f for f in os.listdir(props) if f.endswith(".png"))
    assert berkas, "props/ kosong"
    return f"{len(berkas)} berkas: {', '.join(berkas)}"


@periksa("API menjawab dan putusannya benar")
def _c5():
    import json
    import tempfile

    from fastapi.testclient import TestClient

    from qshield import api, auth, emvco
    from qshield.limits import RateLimiter

    # Pemeriksaan ini memanggil API di dalam proses, jadi autentikasi dan
    # pembatas laju dilewati dengan MENGGANTI OBJEKNYA, bukan dengan
    # menyetel env. Menyetel env akan mencemari laporan konfigurasi di
    # pemeriksaan pertama — preflight harus melaporkan mesin apa adanya,
    # bukan mesin yang sudah diubahnya sendiri.
    clients_asli, limiter_asli = api.clients, api.limiter
    api.clients = auth.ClientRegistry(spec="", auth_setting="off")
    api.limiter = RateLimiter(max_requests=10_000, window_seconds=60)

    fixture = os.environ.get(
        "QSHIELD_VENUE_FIXTURE", os.path.join(AKAR, "venue.json"))
    with open(fixture) as f:
        v = json.load(f)

    sys.path.insert(0, os.path.join(AKAR, "scripts"))
    import seed

    c = TestClient(api.app)
    asli = seed.make_qr(seed.WARUNG["nmid"], seed.WARUNG["pan"],
                        seed.WARUNG["name"])
    palsu = seed.make_qr(seed.PENIPU["nmid"], seed.PENIPU["pan"],
                         seed.PENIPU["name"])

    def minta(payload, dev):
        return c.post("/api/v1/verify", json={
            "payload": payload, "lat": v["lat"], "lng": v["lng"],
            "device_anon_id": dev, "accuracy_m": v["accuracy_m"]}).json()

    a = minta(asli, "preflight-asli-01")
    assert a["verdict"] == "verified" and a["action"] == "proceed", (
        f"QR ASLI menghasilkan {a['verdict']}/{a['action']}, bukan "
        f"verified/proceed — demo skenario 1 akan gagal")

    b = minta(palsu, "preflight-palsu-01")
    assert b["verdict"] == "anomaly" and b["action"] == "cooling_off", (
        f"QR PALSU menghasilkan {b['verdict']}/{b['action']}, bukan "
        f"anomaly/cooling_off — demo skenario 2 akan gagal")

    api.clients, api.limiter = clients_asli, limiter_asli
    return (f"asli -> {a['verdict']}/{a['action']}, "
            f"palsu -> {b['verdict']}/{b['action']} (skor {b['risk_score']})")


@periksa("Halaman scanner tersaji")
def _c6():
    from fastapi.testclient import TestClient

    from qshield import api
    r = TestClient(api.app).get("/")
    assert r.status_code == 200, f"GET / -> {r.status_code}"
    assert "Q-Shield" in r.text, "halaman tidak memuat judulnya"
    return f"{len(r.text)} byte, mandiri tanpa build step"


@periksa("Sertifikat HTTPS cocok dengan IP laptop sekarang")
def _c7():
    import socket
    import subprocess

    cert = os.path.join(AKAR, "certs", "cert.pem")
    assert os.path.exists(cert), (
        "certs/cert.pem belum ada. Kamera dan GPS di HP menuntut HTTPS:\n"
        "           python scripts/make_cert.py")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    hasil = subprocess.run(
        ["openssl", "x509", "-in", cert, "-noout", "-text"],
        capture_output=True, text=True)
    san = [b for b in hasil.stdout.split("\n") if "IP Address" in b]
    assert san, "sertifikat tidak punya Subject Alternative Name"
    assert ip in san[0], (
        f"IP laptop sekarang {ip}, tapi sertifikat dibuat untuk "
        f"{san[0].strip()}. Pindah WiFi? Jalankan ulang:\n"
        f"           python scripts/make_cert.py")

    sisa = subprocess.run(
        ["openssl", "x509", "-in", cert, "-noout", "-checkend", "86400"],
        capture_output=True, text=True)
    assert sisa.returncode == 0, "sertifikat kedaluwarsa dalam 24 jam"
    return f"berlaku untuk {ip}, dan masih hidup"


@periksa("Seluruh suite pengujian hijau", wajib=False)
def _c6():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [env.get("PYTHONPATH", ""), os.path.join(AKAR, "src"),
         os.path.join(AKAR, "scripts")])
    # Suite mengatur sendiri sakelarnya; env dari sini tidak boleh ikut
    # menentukan hasilnya.
    env.pop("QSHIELD_AUTH", None)
    env.pop("QSHIELD_RATE_LIMIT", None)
    gagal = []
    berkas = sorted(f for f in os.listdir(os.path.join(AKAR, "tests"))
                    if f.startswith("test_") and f.endswith(".py"))
    for t in berkas:
        r = subprocess.run(
            [sys.executable, os.path.join(AKAR, "tests", t)],
            capture_output=True, env=env, cwd=AKAR)
        if r.returncode != 0:
            gagal.append(t)
    assert not gagal, f"gagal: {', '.join(gagal)}"
    return f"{len(berkas)} suite lolos"


# --- Laporan -------------------------------------------------------

print("=" * 70)
print("PREFLIGHT — kesiapan demo Q-Shield")
print("=" * 70)
print()

gagal_wajib = 0
gagal_opsional = 0
for nama, status, pesan, wajib in _hasil:
    tanda = "SIAP " if status == "SIAP" else ("GAGAL" if wajib else "belum")
    print(f"  [{tanda}]  {nama}")
    if pesan:
        for baris in pesan.split("\n"):
            print(f"           {baris}")
    if status == "GAGAL":
        if wajib:
            gagal_wajib += 1
        else:
            gagal_opsional += 1
    print()

print("-" * 70)
if gagal_wajib:
    print(f"{gagal_wajib} pemeriksaan WAJIB gagal. Demo belum siap.")
    sys.exit(1)
if gagal_opsional:
    print(f"Siap, dengan {gagal_opsional} catatan opsional di atas.")
    sys.exit(0)
print("Semua siap.")
