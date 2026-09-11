"""
Pendaftaran merchant — fungsinya, dan penyalahgunaannya.

Pendaftaran menutup cold start (R4), relokasi (R5), dan merchant
keliling (R6). Tapi ia juga menciptakan JALUR KEPERCAYAAN BARU, dan
jalur kepercayaan baru adalah permukaan serangan baru. Setengah berkas
ini menguji fungsinya; setengahnya lagi menguji batasnya.

    python tests/test_registration.py
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["QSHIELD_RATE_LIMIT"] = "off"
os.environ.pop("QSHIELD_AUTH", None)

from fastapi.testclient import TestClient

from qshield import api, auth, emvco
from qshield import binding as bd
from qshield.store import Store

NOW = datetime.now(timezone.utc)
LAT, LNG = -6.914744, 107.609810

KUNCI_A, KUNCI_B = auth.new_key(), auth.new_key()
H_A = {auth.API_KEY_HEADER: KUNCI_A}
H_B = {auth.API_KEY_HEADER: KUNCI_B}

_hasil = []


def cek(nama):
    def deco(fn):
        try:
            _hasil.append((nama, True, fn() or ""))
        except AssertionError as exc:
            _hasil.append((nama, False, str(exc)))
        return fn
    return deco


def siapkan():
    api.store = Store(os.path.join(tempfile.mkdtemp(), "reg.db"))
    api.clients = auth.ClientRegistry(
        spec=f"pjp-alpha:{auth.hash_key(KUNCI_A)},"
             f"pjp-beta:{auth.hash_key(KUNCI_B)}", auth_setting="")
    return TestClient(api.app)


def qr(nmid, pan="936000149000000001", nama="MERCHANT"):
    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": pan, "02": nmid, "03": "UMI"})
    return emvco.build({
        "00": "01", "01": "11", "26": acct, "52": "5812", "53": "360",
        "58": "ID", "59": nama, "60": "BANDUNG", "61": "40257"})


def daftar(c, nmid, lat=LAT, lng=LNG, nama="MERCHANT", mobile=False, h=H_A):
    return c.post("/api/v1/merchants", json={
        "nmid": nmid, "lat": lat, "lng": lng,
        "merchant_name": nama, "is_mobile": mobile}, headers=h)


def pindai(c, nmid, pan="936000149000000001", nama="MERCHANT",
           lat=LAT, lng=LNG, dev="warga-0001", h=H_A):
    return c.post("/api/v1/verify", json={
        "payload": qr(nmid, pan, nama), "lat": lat, "lng": lng,
        "device_anon_id": dev, "accuracy_m": 9.0}, headers=h).json()


# ================================================================
# Fungsinya
# ================================================================

@cek("Pendaftaran menutup cold start")
def _r1():
    c = siapkan()
    N = "ID1055555555555"
    sebelum = pindai(c, N, dev="warga-0001")
    assert sebelum["action"] == "warn", f"pra-daftar {sebelum['action']}"
    assert "first_observation" in sebelum["signals"]

    assert daftar(c, N).status_code == 201
    sesudah = pindai(c, N, dev="warga-0002")
    assert sesudah["verdict"] == "verified", f"pasca-daftar {sesudah['verdict']}"
    assert sesudah["action"] == "proceed"
    assert "registered_merchant" in sesudah["signals"]
    return "warn -> proceed tanpa menunggu 3 pengamat x 24 jam"


@cek("Terdaftar dan terkonsensus dibedakan di putusan")
def _r2():
    c = siapkan()
    N, M = "ID1055555555555", "ID1066666666666"
    daftar(c, N)
    api.store.seed_binding(
        nmid=M, lat=-6.95, lng=107.65, merchant_name="LAMA",
        observer_count=47, first_seen=NOW - timedelta(days=180),
        last_seen=NOW - timedelta(hours=2))

    a = pindai(c, N, dev="warga-0001")
    b = pindai(c, M, nama="LAMA", lat=-6.95, lng=107.65, dev="warga-0002")

    assert "registered_merchant" in a["signals"]
    assert "established_binding" in b["signals"]
    assert "registered_merchant" not in b["signals"]
    # Auditor berhak tahu KENAPA sesuatu terverifikasi.
    assert any("terdaftar" in r.lower() for r in a["reasons"])
    assert any("pengamatan" in r.lower() for r in b["reasons"])
    return "sinyal dan alasannya berbeda, bukan cuma statusnya sama"


@cek("Stiker palsu di jangkar terdaftar tertangkap lebih keras")
def _r3():
    c = siapkan()
    N = "ID1055555555555"
    daftar(c, N)
    d = pindai(c, "ID1099887766554", "936000149000000002",
               dev="penyerang-0001")
    assert d["verdict"] == "anomaly", f"-> {d['verdict']}"
    assert d["action"] == "cooling_off"
    assert "nmid_changed_at_registered_anchor" in d["signals"]
    assert d["risk_score"] >= 76, f"skor {d['risk_score']} tidak cukup keras"
    return f"skor {d['risk_score']} / cooling_off"


@cek("Relokasi sah tidak lagi memicu alarm di tempat baru (R5)")
def _r4():
    c = siapkan()
    N = "ID1055555555555"
    daftar(c, N)
    pindai(c, N, dev="warga-0001")

    BARU_LAT, BARU_LNG = -6.9000, 107.6200
    assert daftar(c, N, lat=BARU_LAT, lng=BARU_LNG).status_code == 201

    baru = pindai(c, N, lat=BARU_LAT, lng=BARU_LNG, dev="warga-0002")
    assert baru["verdict"] == "verified", f"lokasi baru -> {baru['verdict']}"
    assert "registered_merchant" in baru["signals"]
    return "didaftarkan ulang di lokasi baru -> langsung verified"


@cek("Merchant keliling tidak terikat lokasi (R6)")
def _r5():
    c = siapkan()
    N = "ID1077777777777"
    daftar(c, N, nama="SIOMAY KELILING", mobile=True)
    for i, (la, ln) in enumerate([(LAT, LNG), (-6.94, 107.64),
                                  (-6.2, 106.8), (-7.25, 112.75)]):
        d = pindai(c, N, nama="SIOMAY KELILING", lat=la, lng=ln,
                   dev=f"warga-kel-{i:04d}")
        assert d["verdict"] == "verified", f"di titik {i} -> {d['verdict']}"
        assert "mobile_merchant" in d["signals"]
        assert "nmid_scatter" not in d["signals"], "sebaran masih dihukum"
    return "4 kota berbeda, tidak satu pun memicu sinyal sebaran"


@cek("Merchant keliling tidak mengklaim lokasi yang disinggahinya")
def _r6():
    c = siapkan()
    KEL, TETAP = "ID1077777777777", "ID1088888888888"
    daftar(c, KEL, nama="SIOMAY", mobile=True)
    for i in range(3):
        pindai(c, KEL, nama="SIOMAY", dev=f"warga-k-{i:04d}")

    # Warung tetap di titik yang sama tidak boleh tertuduh.
    daftar(c, TETAP, nama="WARUNG TETAP")
    d = pindai(c, TETAP, "936000149000000008", nama="WARUNG TETAP",
               dev="warga-t-0001")
    assert d["verdict"] == "verified", (
        f"gerobak yang pernah mangkal membuat warung jadi {d['verdict']}")
    assert "nmid_changed_at_registered_anchor" not in d["signals"]
    return "gerobak yang mangkal tidak menjadikan titik itu miliknya"


@cek("Dua merchant terdaftar bersebelahan tetap koeksis (invarian 7)")
def _r7():
    c = siapkan()
    A, B = "ID1011111111111", "ID1022222222222"
    daftar(c, A, lat=-6.920, lng=107.600, nama="TOKO A")
    daftar(c, B, lat=-6.92007, lng=107.600, nama="TOKO B")
    for n, pan, nm, la in ((A, "936000149000000011", "TOKO A", -6.920),
                           (B, "936000149000000022", "TOKO B", -6.92007)):
        d = pindai(c, n, pan, nama=nm, lat=la, lng=107.600,
                   dev=f"warga-{nm[-1]}-0001")
        assert d["verdict"] != "anomaly", f"{nm} -> {d['verdict']}"
        assert "adjacent_merchant" in d["signals"], (
            f"{nm}: koeksistensi tidak dikenali")
    return "keduanya verified; ADJACENT_MIN_RATIO tidak menghukum yang baru daftar"


# ================================================================
# Penyalahgunaannya
# ================================================================

@cek("Tanpa kunci, tidak bisa mendaftar")
def _s1():
    c = siapkan()
    r = c.post("/api/v1/merchants", json={
        "nmid": "ID1055555555555", "lat": LAT, "lng": LNG})
    assert r.status_code == 401, f"HTTP {r.status_code}"
    r2 = c.post("/api/v1/merchants", json={
        "nmid": "ID1055555555555", "lat": LAT, "lng": LNG},
        headers={auth.API_KEY_HEADER: "tebakan-ngawur"})
    assert r2.status_code == 401
    return "401 tanpa kunci dan dengan kunci salah"


@cek("PJP tidak bisa membajak pendaftaran PJP lain")
def _s2():
    c = siapkan()
    N = "ID1055555555555"
    assert daftar(c, N, h=H_A).status_code == 201
    r = daftar(c, N, lat=-6.2, lng=106.8, h=H_B)
    assert r.status_code == 409, f"PJP lain berhasil memindahkan: {r.status_code}"

    # Dan lokasinya tidak bergeser sedikit pun.
    d = pindai(c, N, dev="warga-0001")
    assert d["verdict"] == "verified", "jangkar asli rusak oleh percobaan bajakan"
    return "409, dan jangkar aslinya tidak bergeser"


@cek("Hanya pendaftarnya yang boleh mencabut")
def _s3():
    c = siapkan()
    N = "ID1055555555555"
    daftar(c, N, h=H_A)
    assert c.delete(f"/api/v1/merchants/{N}", headers=H_B).status_code == 403
    assert c.delete(f"/api/v1/merchants/{N}", headers=H_A).status_code == 200
    assert c.delete("/api/v1/merchants/ID1099999999999",
                    headers=H_A).status_code == 404
    return "403 untuk PJP lain, 200 untuk pendaftarnya, 404 kalau tidak ada"


@cek("Pencabutan mengembalikan status, bukan menghapus pengamatan")
def _s4():
    c = siapkan()
    N = "ID1055555555555"
    daftar(c, N)
    for i in range(3):
        pindai(c, N, dev=f"warga-{i:04d}")
    obs = api.store.conn.execute(
        "SELECT COUNT(*) c FROM observations").fetchone()["c"]

    c.delete(f"/api/v1/merchants/{N}", headers=H_A)

    # Diperiksa TEPAT setelah pencabutan, sebelum pemindaian berikutnya —
    # pemindaian itu sendiri sah menambah pengamatan baru, dan
    # mencampurnya ke dalam hitungan membuat pemeriksaan ini menguji
    # hal yang salah.
    sesudah = api.store.conn.execute(
        "SELECT COUNT(*) c FROM observations").fetchone()["c"]
    assert sesudah == obs, (
        f"pengamatan ikut terhapus: {obs} -> {sesudah}. Konsensus yang sudah "
        f"terkumpul adalah bukti yang sah, terlepas dari status pendaftaran.")

    d = pindai(c, N, dev="warga-9999")
    assert "registered_merchant" not in d["signals"], "masih terdaftar"
    assert d["verdict"] != "verified", (
        "pencabutan tidak menurunkan status — binding tetap diperlakukan resmi")
    return f"status dicabut, {obs} pengamatan tetap utuh"


@cek("Pendaftaran tidak memalsukan konsensus (invarian 3)")
def _s5():
    c = siapkan()
    N = "ID1055555555555"
    daftar(c, N)
    baris = api.store.conn.execute(
        "SELECT observer_count FROM bindings WHERE nmid = ?", (N,)).fetchone()
    assert baris["observer_count"] == 0, (
        f"pendaftaran menaikkan observer_count jadi {baris['observer_count']} — "
        f"itu memalsukan konsensus")
    obs = api.store.conn.execute(
        "SELECT COUNT(*) c FROM observations").fetchone()["c"]
    assert obs == 0, "pendaftaran mencatat observation"
    return "observer_count tetap 0; pendaftaran bukan pengamatan"


@cek("Atribusi PJP tercatat dan bisa ditelusuri")
def _s6():
    c = siapkan()
    daftar(c, "ID1055555555555", h=H_A)
    daftar(c, "ID1066666666666", h=H_B)
    baris = api.store.conn.execute(
        "SELECT nmid, registrar FROM registrations ORDER BY nmid").fetchall()
    peta = {r["nmid"]: r["registrar"] for r in baris}
    assert peta["ID1055555555555"] == "pjp-alpha"
    assert peta["ID1066666666666"] == "pjp-beta"

    # Kolom pendaftar TIDAK BOLEH merembes ke tabel pengamatan.
    for tabel in ("bindings", "observations"):
        kolom = [k["name"].lower() for k in
                 api.store.conn.execute(f"PRAGMA table_info({tabel})")]
        assert not any("registrar" in k for k in kolom), (
            f"{tabel} menyimpan pendaftar — pernyataan lembaga merembes "
            f"ke tabel pengamatan pengguna")
    return "terlacak di registrations; tidak merembes ke bindings/observations"


@cek("Registrations tidak memuat identitas pengguna (invarian 8)")
def _s7():
    c = siapkan()
    daftar(c, "ID1055555555555")
    kolom = [k["name"].lower() for k in
             api.store.conn.execute("PRAGMA table_info(registrations)")]
    terlarang = ("user", "device", "phone", "msisdn", "email", "nik", "customer")
    temuan = [k for k in kolom for t in terlarang if t in k]
    assert not temuan, f"kolom beraroma identitas pengguna: {temuan}"
    # registrar adalah LEMBAGA, bukan orang — dan itu memang perlu.
    assert "registrar" in kolom
    return f"{len(kolom)} kolom; registrar = PJP, bukan pengguna"


print("=" * 70)
print("PENDAFTARAN MERCHANT")
print("=" * 70)
print()
gagal = 0
for nama, ok, detail in _hasil:
    print(f"  [{'OK   ' if ok else 'GAGAL'}]  {nama}")
    if detail:
        print(f"           {detail}")
    if not ok:
        gagal += 1
print()
print("-" * 70)
if gagal:
    print(f"{gagal} dari {len(_hasil)} pemeriksaan GAGAL.")
    sys.exit(1)
print(f"Seluruh {len(_hasil)} pemeriksaan lolos.")
