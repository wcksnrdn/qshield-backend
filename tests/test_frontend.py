"""
Kunci kecocokan frontend dengan API.

Frontend dan backend gampang menyimpang diam-diam: field diganti nama di
server, halaman tetap tampil, dan yang hilang cuma satu baris keterangan
yang tidak ada yang sadar sampai di depan juri.

Berkas ini membaca `web/index.html` dan memastikan:
  - halaman benar-benar mandiri (tidak ada permintaan ke luar)
  - badan permintaan yang disusun JS lolos validasi API
  - setiap field yang DIBACA JS memang ada di tanggapan
  - kosakata aksi/verdict yang dipetakan JS sama persis dengan API

    python tests/test_frontend.py
"""

import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["QSHIELD_AUTH"] = "off"
os.environ["QSHIELD_RATE_LIMIT"] = "off"

from fastapi.testclient import TestClient

from qshield import api, emvco
from qshield import binding as bd
from qshield.store import Store

NOW = datetime.now(timezone.utc)
LAT, LNG, NMID = -6.914744, 107.609810, "ID1024365478912"

HALAMAN = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "qshield", "web", "index.html")

_hasil = []


def cek(nama):
    def deco(fn):
        try:
            _hasil.append((nama, True, fn() or ""))
        except AssertionError as exc:
            _hasil.append((nama, False, str(exc)))
        return fn
    return deco


def klien():
    api.store = Store(os.path.join(tempfile.mkdtemp(), "fe.db"))
    api.store.seed_binding(
        nmid=NMID, lat=LAT, lng=LNG, merchant_name="WARUNG BU SRI",
        observer_count=47, first_seen=NOW - timedelta(days=180),
        last_seen=NOW - timedelta(hours=6))
    return TestClient(api.app)


def qr(nmid=NMID, pan="936000149000000001"):
    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": pan, "02": nmid, "03": "UMI"})
    return emvco.build({
        "00": "01", "01": "11", "26": acct, "52": "5812", "53": "360",
        "58": "ID", "59": "WARUNG BU SRI", "60": "BANDUNG", "61": "40257"})


with open(HALAMAN) as f:
    HTML = f.read()
SCRIPT = HTML[HTML.index("<script>"):HTML.index("</script>")]


@cek("Halaman disajikan API dan benar-benar mandiri")
def _f1():
    r = klien().get("/")
    assert r.status_code == 200, f"GET / -> {r.status_code}"
    assert "text/html" in r.headers["content-type"]

    # Yang dicari adalah URL sungguhan, bukan kata "CDN" — halaman ini
    # justru memuat komentar yang menyebutnya, dan mencocokkan kata
    # membuat pemeriksaan gagal karena dokumentasinya sendiri.
    luar = re.findall(r'(?:src|href)\s*=\s*"(https?://[^"]+)"', r.text)
    assert not luar, f"halaman meminta sumber luar: {luar}"
    url = re.findall(r'https?://(?!127\.0\.0\.1|localhost)[^\s"\')<]+', r.text)
    assert not url, f"ada URL eksternal di halaman: {url[:3]}"
    assert "@import" not in r.text, "ada @import CSS yang menarik sumber luar"
    # Font Google akan gagal tanpa internet; harus ada fallback sistem.
    assert "-apple-system" in r.text, "tidak ada fallback font sistem"
    return f"{len(r.text)} byte, nol permintaan ke luar"


@cek("Badan permintaan yang disusun JS lolos validasi API")
def _f2():
    # Persis bentuk yang dibangun `verifikasi()` di halaman.
    body = {
        "payload": qr(),
        "device_anon_id": "550e8400-e29b-41d4-a716-446655440000",
        "lat": LAT, "lng": LNG, "accuracy_m": 8.5,
        "location_source": "live",
    }
    r = klien().post("/api/v1/verify", json=body)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:160]}"

    # device_anon_id dari crypto.randomUUID() harus lolos pola server.
    pola = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
    assert pola.match(body["device_anon_id"]), (
        "UUID v4 tidak cocok dengan pola device_anon_id di server")
    return "UUID v4 + accuracy pecahan diterima"


@cek("Setiap field yang dibaca JS ada di tanggapan")
def _f3():
    d = klien().post("/api/v1/verify", json={
        "payload": qr(), "device_anon_id": "frontend-uji-0001",
        "lat": LAT, "lng": LNG, "accuracy_m": 8.5}).json()

    # Field yang dirujuk kode halaman, dikumpulkan dari sumbernya.
    # `detail` dikecualikan: itu milik tanggapan GAGAL, dan halaman
    # membacanya hanya di cabang penanganan error.
    HANYA_ERROR = {"detail"}
    dibaca_akar = set(re.findall(r'\bd\.(\w+)', SCRIPT)) - HANYA_ERROR
    hilang = dibaca_akar - set(d)
    assert not hilang, f"JS membaca field yang tidak ada: {sorted(hilang)}"

    # Dan pastikan cabang error itu memang benar: server betul-betul
    # mengembalikan `detail` saat menolak.
    gagal = klien().post("/api/v1/verify", json={
        "payload": "bukan-qris", "device_anon_id": "frontend-uji-0002",
        "lat": LAT, "lng": LNG, "accuracy_m": 8.5})
    assert gagal.status_code == 422
    assert "detail" in gagal.json(), (
        "halaman membaca d.detail saat gagal, tapi server tidak mengirimnya")

    # Sub-objek yang dipakai halaman.
    for k in ("location", "behavior"):
        assert k in d["layers"], f"layers.{k} hilang"
    for k in ("name", "nmid", "city"):
        assert k in d["merchant"], f"merchant.{k} hilang"
    assert isinstance(d["reasons"], list) and d["reasons"], "reasons kosong"
    return f"{len(dibaca_akar)} field akar + layers + merchant cocok"


@cek("Kosakata aksi dan verdict dipetakan lengkap")
def _f4():
    aksi_js = set(re.findall(r'^\s*(\w+):\s*\{t:', SCRIPT, re.M))
    aksi_api = {bd.PROCEED, bd.WARN, bd.STEP_UP, bd.COOLING_OFF}
    assert aksi_js == aksi_api, (
        f"peta aksi tidak lengkap — hilang {aksi_api - aksi_js}, "
        f"asing {aksi_js - aksi_api}")

    blok = re.search(r'const VERDICT = \{([^}]+)\}', SCRIPT).group(1)
    verdict_js = {b.split(":")[0].strip() for b in blok.split(",") if ":" in b}
    verdict_api = {bd.VERIFIED, bd.UNKNOWN, bd.ANOMALY}
    assert verdict_js == verdict_api, (
        f"peta verdict tidak lengkap: {verdict_api ^ verdict_js}")
    return f"{len(aksi_js)} aksi, {len(verdict_js)} verdict terpetakan"


@cek("Empat tier menghasilkan tampilan yang berbeda")
def _f5():
    gaya = HTML[HTML.index("<style>"):HTML.index("</style>")]
    for aksi in (bd.PROCEED, bd.WARN, bd.STEP_UP, bd.COOLING_OFF):
        assert f".a-{aksi}" in gaya, f"tier {aksi} tidak punya gaya sendiri"
    # Cooling-off adalah PENUNDAAN, bukan penolakan — hitung mundurnya
    # bagian dari responsnya, bukan hiasan.
    assert "cool-timer" in gaya and "hitungMundur" in SCRIPT, (
        "cooling_off tidak menampilkan penundaan")
    return "empat tier punya warna sendiri; cooling_off menampilkan hitung mundur"


@cek("Halaman memberi tahu saat konteks tidak aman")
def _f6():
    # Kamera dan geolocation menuntut secure context. Kalau halaman
    # dibuka lewat http dari HP, keduanya diblokir — dan itu harus
    # dijelaskan lengkap dengan cara memperbaikinya, bukan gagal diam.
    assert "isSecureContext" in SCRIPT, "tidak memeriksa secure context"
    assert "make_cert.py" in SCRIPT, (
        "tidak memberi tahu cara memperbaiki konteks tidak aman")
    assert "replay" in SCRIPT, "tidak menawarkan jalan keluar replay"
    return "diperiksa di muka, dengan perintah perbaikannya"


@cek("Mode replay bisa dijalankan dari halaman")
def _f7():
    d = klien().post("/api/v1/verify", json={
        "payload": qr(), "device_anon_id": "frontend-replay-01",
        "lat": LAT, "lng": LNG, "accuracy_m": 8.0,
        "location_source": "replay"}).json()
    assert d["location_source"] == "replay"
    assert "replay" in HTML, "tidak ada elemen penanda replay"
    assert 'id="replay"' in HTML, "penanda replay tidak punya wadah"
    return "replay ditandai di tanggapan dan punya wadah di halaman"


@cek("Skenario demo utama tampil benar")
def _f8():
    c = klien()

    def minta(payload, dev):
        return c.post("/api/v1/verify", json={
            "payload": payload, "device_anon_id": dev,
            "lat": LAT, "lng": LNG, "accuracy_m": 8.0}).json()

    asli = minta(qr(), "frontend-asli-01")
    assert asli["action"] == "proceed", f"QR asli -> {asli['action']}"

    palsu = minta(qr("ID1099887766554", "936000149000000002"),
                  "frontend-palsu-01")
    assert palsu["action"] == "cooling_off", f"QR palsu -> {palsu['action']}"
    assert palsu["reasons"], "tidak ada alasan untuk ditampilkan"
    return (f"asli -> {asli['action']}, palsu -> {palsu['action']} "
            f"({len(palsu['reasons'])} alasan tampil)")


@cek("Cold start tampil netral, kejanggalan tetap amber")
def _f9():
    import re as _re
    blok = _re.search(r'BELUM_KENAL = new Set\(\[([^\]]+)\]', HTML).group(1)
    belum = {x.strip().strip('"') for x in blok.split(",") if x.strip()}

    def polos(d):
        sig = d.get("signals") or []
        return d["action"] == "warn" and sig and all(x in belum for x in sig)

    c = klien()

    def minta(payload, lat, lng, dev, acc=9.0):
        return c.post("/api/v1/verify", json={
            "payload": payload, "lat": lat, "lng": lng,
            "device_anon_id": dev, "accuracy_m": acc}).json()

    # Merchant sungguhan yang belum dikenal: netral, bukan alarm.
    baru = minta(qr("ID1055555555555", "936000149000005"), -6.95, 107.65, "ui-baru-0001")
    assert baru["action"] == "warn", "tier berubah — invarian §2 tersentuh?"
    assert polos(baru), f"cold start tidak tampil netral: {baru['signals']}"

    # Kejanggalan sungguhan harus TETAP amber, bukan ikut dilunakkan.
    janggal = minta(qr(), LAT, LNG, "ui-janggal-001", acc=0.4)
    assert not polos(janggal), (
        f"sinyal janggal ikut dilunakkan jadi netral: {janggal['signals']}")

    # Anomaly tidak boleh tersentuh sama sekali.
    palsu = minta(qr("ID1099887766554", "936000149000000002"), LAT, LNG, "ui-palsu-0001")
    assert palsu["action"] == "cooling_off" and not polos(palsu)

    # Dan yang paling penting: keadaan netral TIDAK BOLEH menyiratkan aman.
    teks = _re.search(r'nb\.innerHTML = ([^;]+);', SCRIPT).group(1)
    assert "tidak akan menyatakan aman" in teks, (
        "keterangan cold start tidak menegaskan bahwa ini bukan klaim aman")
    assert "cocokkan nama merchant" in teks.lower(), (
        "tidak memberi pengguna pemeriksaan yang bisa dilakukan sendiri")
    return "cold start netral; kejanggalan & anomaly tidak ikut dilunakkan"


print("=" * 70)
print("FRONTEND <-> API")
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
