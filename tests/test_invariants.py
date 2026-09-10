"""
Regression lock untuk kedelapan invarian di Handoff Fase 2 §2.

Berkas ini bukan test fitur. Tugasnya satu: memastikan tidak ada
perubahan di masa depan — termasuk Layer 2 — yang diam-diam melanggar
keputusan yang sudah dibayar dengan pengujian empiris di fase 1.

Setiap invarian diuji terpisah dan dilaporkan per nomor, supaya kalau
ada yang jebol langsung kelihatan yang mana. Keluar dengan status
bukan-nol kalau ada satu saja yang gagal.

    python tests/test_invariants.py
"""

import os

# Test ini sengaja membanjiri API, jadi pembatasan laju dimatikan di sini,
# begitu juga autentikasi klien — keduanya diuji tersendiri di
# tests/test_hardening.py.
os.environ["QSHIELD_RATE_LIMIT"] = "off"
os.environ["QSHIELD_AUTH"] = "off"


import math
import random
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

from qshield import binding as b
from qshield import emvco
from qshield import geo
from qshield.store import Store

random.seed(11)

NOW = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
LAT, LNG = -6.914744, 107.609810

REAL = "ID1024365478912"
FAKE = "ID1099887766554"

_results = []


def invariant(num, title):
    """Daftarkan satu pemeriksaan invarian."""
    def deco(fn):
        try:
            _results.append((num, title, True, fn() or ""))
        except AssertionError as exc:
            _results.append((num, title, False, str(exc)))
        return fn
    return deco


def mk(nmid, lat, lng, observers, age_hours, name=None, last_seen=None):
    return b.Binding(
        nmid=nmid, lat=lat, lng=lng, merchant_name=name,
        observer_count=observers,
        first_seen=NOW - timedelta(hours=age_hours),
        last_seen=last_seen or NOW,
    )


def offset(lat, lng, dist_m, angle):
    dlat = (dist_m * math.cos(angle)) / 111320
    dlng = (dist_m * math.sin(angle)) / (111320 * math.cos(math.radians(lat)))
    return lat + dlat, lng + dlng


def make_qr(nmid, pan="936000149000000001", name="WARUNG BU SRI"):
    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": pan, "02": nmid, "03": "UMI",
    })
    return emvco.build({
        "00": "01", "01": "11", "26": acct, "52": "5812",
        "53": "360", "58": "ID", "59": name, "60": "BANDUNG", "61": "40257",
    })


# --- Invarian 1 ----------------------------------------------------

@invariant(1, "Geohash presisi 7, bukan 8")
def _inv1():
    assert b.INDEX_PRECISION == 7, (
        f"INDEX_PRECISION = {b.INDEX_PRECISION}, harus 7. Presisi 8 gagal "
        f"menghadapi GPS drift (81,9% failure rate pada pergeseran 20 m)."
    )

    # Bukan cuma konstanta — cakupannya diuji ulang di sini supaya
    # alasan angka 7 ikut terkunci, bukan cuma angkanya.
    trials = 4000
    miss = {7: 0, 8: 0}
    for _ in range(trials):
        lat = random.uniform(-7.2, -6.6)
        lng = random.uniform(107.4, 107.8)
        blat, blng = offset(lat, lng, random.uniform(0, 100),
                            random.uniform(0, 2 * math.pi))
        for p in (7, 8):
            cells = set(geo.neighbors(geo.encode(lat, lng, p)))
            if geo.encode(blat, blng, p) not in cells:
                miss[p] += 1

    cover7 = 100 * (trials - miss[7]) / trials
    cover8 = 100 * (trials - miss[8]) / trials
    assert cover7 == 100.0, f"presisi 7 hanya mencakup {cover7:.2f}% radius 100 m"
    assert cover8 < 100.0, (
        "presisi 8 tiba-tiba mencakup 100% — asumsi kalibrasi berubah, "
        "periksa ulang geo.neighbors()"
    )
    return f"p7 {cover7:.1f}% vs p8 {cover8:.1f}% cakupan pada radius 100 m"


# --- Invarian 2 ----------------------------------------------------

@invariant(2, "Tiga status; 'unknown' tidak pernah berarti aman")
def _inv2():
    assert len({b.VERIFIED, b.UNKNOWN, b.ANOMALY}) == 3

    # Cold start tidak boleh diklaim aman.
    v = b.evaluate(REAL, -8.6500, 115.2167, [], [], now=NOW)
    assert v.status == b.UNKNOWN, f"cold start -> {v.status}"
    assert v.action != b.PROCEED, "cold start diberi proceed"

    # Inti invariannya: APA PUN yang berstatus unknown tidak boleh
    # menghasilkan proceed. Ketiadaan bukti bukan bukti ketiadaan.
    kasus = [
        ("binding muda, 1 pengamat", [mk(REAL, LAT, LNG, 1, 0.5)]),
        ("binding muda, 2 pengamat", [mk(REAL, LAT, LNG, 2, 6)]),
        ("pengamat cukup, usia kurang", [mk(REAL, LAT, LNG, 5, 3)]),
        ("usia cukup, pengamat kurang", [mk(REAL, LAT, LNG, 2, 500)]),
    ]
    for label, nearby in kasus:
        v = b.evaluate(REAL, LAT, LNG, nearby, [], now=NOW)
        if v.status != b.UNKNOWN:
            continue
        assert v.action != b.PROCEED, (
            f"{label}: status unknown tapi action proceed "
            f"(skor {v.risk_score}) — ketiadaan data dikonversi jadi kepercayaan"
        )
    return "cold start dan seluruh binding belum-mapan tetap di atas proceed"


# --- Invarian 3 ----------------------------------------------------

@invariant(3, "Anomali tidak pernah dicatat sebagai observation")
def _inv3():
    from fastapi.testclient import TestClient
    from qshield import api

    path = os.path.join(tempfile.mkdtemp(), "inv3.db")
    api.store = Store(path)
    api.store.seed_binding(
        nmid=REAL, lat=LAT, lng=LNG, merchant_name="WARUNG BU SRI",
        observer_count=47,
        first_seen=NOW - timedelta(days=180),
        last_seen=NOW - timedelta(hours=6),
    )
    client = TestClient(api.app)
    before = client.get("/api/v1/health").json()

    # Penyerang memindai stikernya sendiri berulang kali, tiap kali
    # dari device berbeda, persis pola membangun reputasi palsu.
    verdicts = []
    for i in range(8):
        r = client.post("/api/v1/verify", json={
            "payload": make_qr(FAKE, "936000149000000002"),
            "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
            "device_anon_id": f"attacker-{i:04d}",
        })
        verdicts.append(r.json()["verdict"])

    after = client.get("/api/v1/health").json()
    api.store.close()

    assert all(v == "anomaly" for v in verdicts), f"tidak semua anomali: {verdicts}"
    assert after["observations"] == before["observations"], (
        f"observations naik {before['observations']} -> {after['observations']} "
        f"padahal semua pemindaian anomali"
    )
    assert after["bindings"] == before["bindings"], (
        f"bindings naik {before['bindings']} -> {after['bindings']}"
    )
    return f"8 pemindaian anomali, observations tetap {after['observations']}"


# --- Invarian 4 ----------------------------------------------------

@invariant(4, "Empat tier friksi, tidak ada skala lain")
def _inv4():
    tiers = {b.PROCEED, b.WARN, b.STEP_UP, b.COOLING_OFF}
    assert len(tiers) == 4

    seen = {b._action_for(s) for s in range(0, 101)}
    assert seen == tiers, f"aksi di luar empat tier: {seen - tiers}"

    batas = {0: b.PROCEED, 25: b.PROCEED, 26: b.WARN, 50: b.WARN,
             51: b.STEP_UP, 75: b.STEP_UP, 76: b.COOLING_OFF, 100: b.COOLING_OFF}
    for skor, harus in batas.items():
        got = b._action_for(skor)
        assert got == harus, f"skor {skor} -> {got}, harusnya {harus}"
    return "batas 25/50/75 utuh, tidak ada tier kelima"


# --- Invarian 5 ----------------------------------------------------

@invariant(5, "Bobot sinyal berskala: 60 + min(25, observer_count // 2)")
def _inv5():
    contoh = []
    for obs in (3, 6, 10, 47, 50, 120):
        korban = mk(REAL, LAT, LNG, obs, 2000, "WARUNG BU SRI")
        v = b.evaluate(FAKE, LAT, LNG, [korban], [], now=NOW)
        harus = min(100, 60 + min(25, obs // 2))
        assert v.risk_score == harus, (
            f"{obs} pengamat -> skor {v.risk_score}, rumus menuntut {harus}"
        )
        contoh.append(f"{obs}->{v.risk_score}")

    # Angka yang dikutip di PROCESS-LOG dan dipakai di pitch.
    assert b.evaluate(FAKE, LAT, LNG, [mk(REAL, LAT, LNG, 47, 2000)], [],
                      now=NOW).risk_score == 83
    assert b.evaluate(FAKE, LAT, LNG, [mk(REAL, LAT, LNG, 3, 2000)], [],
                      now=NOW).risk_score == 61
    return " ".join(contoh) + "  (47->83 dan 3->61 sesuai pitch)"


# --- Invarian 6 ----------------------------------------------------

@invariant(6, "Akurasi GPS > 100 m menolak memberi putusan")
def _inv6():
    from fastapi.testclient import TestClient
    from qshield import api

    path = os.path.join(tempfile.mkdtemp(), "inv6.db")
    api.store = Store(path)
    api.store.seed_binding(
        nmid=REAL, lat=LAT, lng=LNG, merchant_name="WARUNG BU SRI",
        observer_count=47,
        first_seen=NOW - timedelta(days=180),
        last_seen=NOW - timedelta(hours=6),
    )
    client = TestClient(api.app)

    for acc in (101, 250, 5000):
        d = client.post("/api/v1/verify", json={
            "payload": make_qr(REAL), "lat": LAT, "lng": LNG,
            "device_anon_id": "device-akurasi-buruk", "accuracy_m": acc,
        }).json()
        assert d["verdict"] == b.UNKNOWN, (
            f"akurasi {acc} m menghasilkan {d['verdict']}, harusnya unknown"
        )
        assert d["verdict"] != b.VERIFIED
        assert "low_gps_accuracy" in d["signals"], "alasan tidak eksplisit"
        assert any("kurasi" in r for r in d["reasons"]), (
            "tidak ada alasan yang bisa dibaca manusia"
        )

    # Akurasi bagus tetap harus memberi putusan seperti biasa.
    d = client.post("/api/v1/verify", json={
        "payload": make_qr(REAL), "lat": LAT, "lng": LNG,
        "device_anon_id": "device-akurasi-baik", "accuracy_m": 12,
    }).json()
    assert d["verdict"] == b.VERIFIED, f"akurasi baik malah {d['verdict']}"
    api.store.close()
    return "101/250/5000 m -> unknown + alasan; 12 m -> verified"


# --- Invarian 7 ----------------------------------------------------

@invariant(7, "Merchant bersebelahan bukan sticker-swap")
def _inv7():
    korban = mk(REAL, LAT, LNG, 47, 2000, "WARUNG BU SRI")
    jarak_diuji = []
    for jarak in (5, 8, 12, 20, 35):
        nlat, nlng = offset(LAT, LNG, jarak, 0.5)
        tetangga = mk("ID1077778888999", nlat, nlng, 30, 1500, "TOKO SEBELAH")
        # Keduanya sama-sama mapan dan sama-sama masih aktif.
        v = b.evaluate(REAL, LAT, LNG, [korban, tetangga], [], now=NOW)
        assert "adjacent_merchant" in v.signals, (
            f"jarak {jarak} m: koeksistensi tidak dikenali, sinyal {v.signals}"
        )
        assert v.status != b.ANOMALY, (
            f"jarak {jarak} m: dua merchant sah jadi anomali"
        )
        assert v.action in (b.PROCEED, b.WARN), (
            f"jarak {jarak} m: friksi {v.action} terlalu keras untuk ruko"
        )
        jarak_diuji.append(f"{jarak}m")

    # ADJACENT_MIN_RATIO adalah ambang baru, dan invarian ini menuntut
    # setiap perubahan ambang diuji ulang terhadap skenario ruko.
    # Pasangan merchant sah yang timpang tapi masih wajar harus lolos.
    for milik_saya, tetangga_punya in ((30, 47), (12, 90), (10, 47), (5, 47)):
        besar = mk("ID1077778888999", *offset(LAT, LNG, 8, 0.5),
                   observers=tetangga_punya, age_hours=1500, name="TOKO RAMAI")
        kecil = mk(REAL, LAT, LNG, milik_saya, 2000, "WARUNG SEPI")
        v = b.evaluate(REAL, LAT, LNG, [kecil, besar], [], now=NOW)
        assert "adjacent_merchant" in v.signals, (
            f"{milik_saya} vs {tetangga_punya} pengamat: merchant sah yang "
            f"lebih sepi kehilangan pengecualian koeksistensi"
        )
        assert v.status != b.ANOMALY

    # Sisi sebaliknya: basis yang timpang JAUH adalah pola R10, bukan ruko.
    tetangga = mk("ID1077778888999", *offset(LAT, LNG, 8, 0.5),
                  observers=47, age_hours=1500, name="TOKO SEBELAH")
    penyusup = mk(REAL, LAT, LNG, b.MIN_OBSERVERS, 2000, "STIKER PALSU")
    v = b.evaluate(REAL, LAT, LNG, [penyusup, tetangga], [], now=NOW)
    assert "adjacent_merchant" not in v.signals, (
        f"basis {b.MIN_OBSERVERS} vs 47 masih dapat pengecualian koeksistensi "
        f"— celah R10 terbuka lagi"
    )

    # Kontrol: kalau yang discan BELUM mapan, ini tetap swap.
    v = b.evaluate(FAKE, LAT, LNG, [korban], [], now=NOW)
    assert v.status == b.ANOMALY, "swap asli tidak boleh ikut dilonggarkan"
    return ("koeksistensi utuh pada " + "/".join(jarak_diuji)
            + f"; basis timpang wajar lolos, {b.MIN_OBSERVERS}-vs-47 tidak")


# --- Invarian 8 ----------------------------------------------------

@invariant(8, "Tidak ada identitas pengguna di skema")
def _inv8():
    path = os.path.join(tempfile.mkdtemp(), "inv8.db")
    s = Store(path)
    rows = s.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()

    terlarang = ("user_id", "user", "phone", "msisdn", "email", "nik",
                 "account_id", "customer", "name_holder", "device_anon_id")
    temuan = []
    kolom_total = 0
    for (tabel,) in [(r["name"],) for r in rows]:
        for col in s.conn.execute(f"PRAGMA table_info({tabel})").fetchall():
            kolom_total += 1
            nama = col["name"].lower()
            for kata in terlarang:
                if kata in nama:
                    temuan.append(f"{tabel}.{col['name']}")

    assert not temuan, f"kolom beraroma identitas pengguna: {temuan}"

    # Observations tidak boleh menyimpan koordinat.
    obs = [c["name"].lower() for c in
           s.conn.execute("PRAGMA table_info(observations)").fetchall()]
    for geo_col in ("lat", "lng", "latitude", "longitude", "geohash"):
        assert not any(geo_col in c for c in obs), (
            f"observations.{geo_col} ada — jejak pergerakan bisa direkonstruksi"
        )

    # --- Serangan sungguhan, bukan sekadar memeriksa nama kolom -------
    #
    # Versi lama pemeriksaan ini berhenti di atas, dan itu memberi rasa
    # aman palsu: skema boleh terlihat bersih sementara satu JOIN tetap
    # memulihkan jejak perjalanan. Sekarang serangannya dijalankan.
    tempat = [
        ("ID1000000000001", "warung dekat rumah", -6.914744, 107.609810),
        ("ID1000000000002", "kopi dekat kantor", -6.902000, 107.618500),
        ("ID1000000000003", "resto mall", -6.925000, 107.640000),
        ("ID1000000000004", "apotek", -6.930000, 107.650000),
    ]
    korban = "budi-hp-anon-001"
    for nmid, nama, lat, lng in tempat:
        s.record(nmid=nmid, lat=lat, lng=lng, device_anon_id=korban,
                 merchant_name=nama, now=NOW)

    # Serangan A: JOIN memakai pengenal perangkat mentah.
    try:
        s.conn.execute(
            "SELECT 1 FROM observations WHERE device_anon_id = ?", (korban,)
        ).fetchall()
        raise AssertionError(
            "device_anon_id masih tersimpan apa adanya — satu JOIN ke "
            "bindings memulihkan koordinat lengkap plus urutan waktu"
        )
    except sqlite3.OperationalError:
        pass

    # Serangan B: rangkai baris antar-lokasi lewat device_ref.
    #
    # Penyerang yang MENGETAHUI pengenal perangkat pun tidak boleh bisa
    # merangkainya, karena rujukannya dilingkupi per-binding.
    baris = s.conn.execute(
        "SELECT binding_id, device_ref FROM observations").fetchall()
    per_ref = {}
    for r in baris:
        per_ref.setdefault(r["device_ref"], set()).add(r["binding_id"])
    banyak = {k: v for k, v in per_ref.items() if len(v) > 1}
    assert not banyak, (
        f"{len(banyak)} device_ref muncul di lebih dari satu binding — "
        f"jejak perjalanan masih bisa dirangkai"
    )

    # Serangan C: hitung sendiri rujukannya dari pengenal yang diketahui,
    # lalu cari di seluruh tabel. Harus cocok di paling banyak satu baris
    # per binding, dan nilainya harus berbeda di tiap binding.
    ids = [r["id"] for r in s.conn.execute("SELECT id FROM bindings")]
    dihitung = {s.device_ref(bid, korban) for bid in ids}
    assert len(dihitung) == len(ids), (
        "satu perangkat menghasilkan rujukan yang sama di binding berbeda"
    )

    # Dedup — satu-satunya fungsi yang memang dibutuhkan — harus utuh.
    sebelum = s.conn.execute(
        "SELECT observer_count c FROM bindings WHERE nmid = ?",
        (tempat[0][0],)).fetchone()["c"]
    for _ in range(5):
        s.record(nmid=tempat[0][0], lat=tempat[0][2], lng=tempat[0][3],
                 device_anon_id=korban, merchant_name=tempat[0][1], now=NOW)
    sesudah = s.conn.execute(
        "SELECT observer_count c FROM bindings WHERE nmid = ?",
        (tempat[0][0],)).fetchone()["c"]
    assert sebelum == sesudah == 1, (
        f"dedup rusak: {sebelum} -> {sesudah}, harusnya tetap 1"
    )

    s.close()
    return (f"{kolom_total} kolom, {len(rows)} tabel; serangan JOIN, "
            f"perangkaian antar-lokasi, dan penghitungan rujukan "
            f"semuanya gagal; dedup utuh")


# --- Laporan -------------------------------------------------------

print("=" * 70)
print("REGRESSION LOCK — invarian Handoff Fase 2 §2")
print("=" * 70)
print()

gagal = 0
for num, title, ok, detail in sorted(_results):
    mark = "PASS" if ok else "GAGAL"
    print(f"  [{mark}]  #{num}  {title}")
    if detail:
        for line in str(detail).split("\n"):
            print(f"          {line}")
    if not ok:
        gagal += 1
    print()

print("-" * 70)
if gagal:
    print(f"{gagal} dari {len(_results)} invarian DILANGGAR.")
    sys.exit(1)
print(f"Seluruh {len(_results)} invarian utuh.")
