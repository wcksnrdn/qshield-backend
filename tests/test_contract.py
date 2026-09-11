"""
Kunci kontrak API v1.

Berkas ini tidak menguji perilaku. Tugasnya menahan **perubahan bentuk**
yang tidak disengaja: field yang hilang, field wajib yang berubah jadi
opsional (atau sebaliknya), tipe yang bergeser, nilai enum yang
bertambah diam-diam.

Alasannya konkret. `accuracy_m` sempat opsional lalu dijadikan wajib —
itu perubahan yang benar, tapi ia MEMATAHKAN klien. Perubahan seperti
itu boleh terjadi, asal disengaja dan tercatat. Yang tidak boleh adalah
terjadi tanpa ada yang menyadarinya sampai frontend rusak di depan juri.

Kalau test ini gagal, tanyakan dulu: perubahannya disengaja?
  ya    perbarui KONTRAK di bawah, catat di API.md, beri tahu frontend
  tidak batalkan perubahannya

    python tests/test_contract.py
"""

import json
import os
import sys

os.environ["QSHIELD_AUTH"] = "off"
os.environ["QSHIELD_RATE_LIMIT"] = "off"

from qshield.api import app

# --- Kontrak v1 ----------------------------------------------------
#
# Ini SATU-SATUNYA sumber kebenaran bentuk API v1. Mengubah kode tanpa
# mengubah tabel ini akan menggagalkan test.

PERMINTAAN_WAJIB = {
    "payload", "lat", "lng", "device_anon_id", "accuracy_m",
}
PERMINTAAN_OPSIONAL = {
    "location_source",
    # Ditambahkan 11 Sep 2026. ADITIF dan opsional dengan sengaja:
    # klien web tidak akan pernah bisa mengisinya, dan menjadikannya
    # wajib berarti mengunci seluruh klien web keluar.
    "device_integrity",
}
PERMINTAAN_TIPE = {
    "device_integrity": "object",
    "payload": "string",
    "lat": "number",
    "lng": "number",
    "device_anon_id": "string",
    "accuracy_m": "number",
    "location_source": "string",
}

TANGGAPAN_FIELD = {
    "verdict": "string",
    "action": "string",
    "risk_score": "integer",
    "reasons": "array",
    "signals": "array",
    "layers": "object",
    "merchant": "object",
    "location_source": "string",
    # Pengungkapan, bukan skor: "not_provided" berarti pemeriksaan
    # integritas tidak pernah dijalankan, bukan dijalankan lalu lolos.
    "device_integrity": "string",
    "processing_ms": "number",
}

LAYERS_FIELD = {"location": "integer", "behavior": "integer"}
MERCHANT_FIELD = {"nmid", "name", "city", "criteria", "is_static"}

# Kosakata tertutup. Menambah nilai di sini adalah perubahan kontrak:
# klien memetakan nilai-nilai ini ke UI, dan nilai tak dikenal membuat
# mereka tidak tahu harus menampilkan apa.
VERDICT_SAH = {"verified", "unknown", "anomaly"}
ACTION_SAH = {"proceed", "warn", "step_up", "cooling_off"}
LOCATION_SOURCE_SAH = {"live", "replay"}
INTEGRITAS_SAH = {"not_provided", "reported", "attested", "failed"}

JALUR = {
    "/api/v1/health",
    "/api/v1/verify",
    # Ditambahkan 11 Sep 2026 bersama pendaftaran merchant. ADITIF —
    # endpoint baru tidak memecah klien yang sudah ada.
    "/api/v1/merchants",
    "/api/v1/merchants/{nmid}",
}

_hasil = []


def cek(nama):
    def deco(fn):
        try:
            _hasil.append((nama, True, fn() or ""))
        except AssertionError as exc:
            _hasil.append((nama, False, str(exc)))
        return fn
    return deco


SKEMA = app.openapi()


def _tipe(d: dict) -> str:
    """Tipe efektif sebuah field di skema OpenAPI.

    Field opsional bertipe objek muncul sebagai
    `anyOf: [{$ref: ...}, {type: null}]`, jadi cabang `$ref` harus ikut
    diperiksa — bukan hanya cabang yang punya `type`.
    """
    if "type" in d:
        return d["type"]
    for kunci in ("anyOf", "allOf", "oneOf"):
        for cabang in d.get(kunci, []):
            if "$ref" in cabang:
                return "object"
            if cabang.get("type") and cabang["type"] != "null":
                return cabang["type"]
    if "$ref" in d:
        return "object"
    return "?"


@cek("Jalur endpoint tidak berubah")
def _k1():
    ada = {p for p in SKEMA["paths"] if p.startswith("/api/")}
    assert ada == JALUR, f"jalur berubah: {ada ^ JALUR}"
    assert all(p.startswith("/api/v1/") for p in ada), (
        "ada endpoint di luar prefiks versi"
    )
    return f"{len(ada)} endpoint"


@cek("Endpoint baru tertutup secara bawaan")
def _k1b():
    # Daftar putih, bukan daftar hitam: endpoint yang lupa didaftarkan
    # jadi TERTUTUP, bukan terbuka. Kebalikannya adalah cara paling umum
    # sebuah API bocor saat berkembang.
    from qshield import api as _api
    for jalur in SKEMA["paths"]:
        if not jalur.startswith("/api/"):
            continue
        butuh = _api._butuh_kunci(jalur)
        if jalur in _api.JALUR_TERBUKA:
            assert not butuh, f"{jalur} ada di daftar putih tapi tetap dikunci"
        else:
            assert butuh, f"{jalur} TERBUKA tanpa kunci — tidak disengaja?"
    terbuka = sorted(_api.JALUR_TERBUKA)
    return f"hanya {', '.join(terbuka)} yang terbuka"


@cek("Field permintaan dan status wajibnya utuh")
def _k2():
    vr = SKEMA["components"]["schemas"]["VerifyRequest"]
    wajib = set(vr.get("required", []))
    semua = set(vr["properties"])

    assert wajib == PERMINTAAN_WAJIB, (
        f"field wajib berubah — hilang {PERMINTAAN_WAJIB - wajib}, "
        f"bertambah {wajib - PERMINTAAN_WAJIB}"
    )
    assert semua == PERMINTAAN_WAJIB | PERMINTAAN_OPSIONAL, (
        f"daftar field berubah: "
        f"{semua ^ (PERMINTAAN_WAJIB | PERMINTAAN_OPSIONAL)}"
    )
    for nama, harus in PERMINTAAN_TIPE.items():
        got = _tipe(vr["properties"][nama])
        assert got == harus, f"{nama}: tipe {got}, kontrak menuntut {harus}"
    return f"{len(wajib)} wajib, {len(PERMINTAAN_OPSIONAL)} opsional"


@cek("Batas validasi permintaan tidak melonggar diam-diam")
def _k3():
    props = SKEMA["components"]["schemas"]["VerifyRequest"]["properties"]
    batas = {
        ("payload", "maxLength"): 1024,
        ("payload", "minLength"): 8,
        ("lat", "minimum"): -90, ("lat", "maximum"): 90,
        ("lng", "minimum"): -180, ("lng", "maximum"): 180,
        ("device_anon_id", "minLength"): 8,
        ("device_anon_id", "maxLength"): 64,
        ("accuracy_m", "minimum"): 0,
    }
    for (field, kunci), harus in batas.items():
        got = props[field].get(kunci)
        assert got == harus, f"{field}.{kunci} = {got}, kontrak menuntut {harus}"
    return f"{len(batas)} batas terkunci"


@cek("Bentuk tanggapan utuh")
def _k4():
    vres = SKEMA["components"]["schemas"]["VerifyResponse"]
    semua = set(vres["properties"])
    assert semua == set(TANGGAPAN_FIELD), (
        f"field tanggapan berubah: {semua ^ set(TANGGAPAN_FIELD)}"
    )
    for nama, harus in TANGGAPAN_FIELD.items():
        got = _tipe(vres["properties"][nama])
        assert got == harus, f"{nama}: tipe {got}, kontrak menuntut {harus}"

    layers = SKEMA["components"]["schemas"]["LayerScores"]
    assert set(layers["properties"]) == set(LAYERS_FIELD), (
        f"rincian layer berubah: {set(layers['properties'])}"
    )
    merchant = SKEMA["components"]["schemas"]["MerchantOut"]
    assert set(merchant["properties"]) == MERCHANT_FIELD, (
        f"blok merchant berubah: {set(merchant['properties'])}"
    )
    return f"{len(TANGGAPAN_FIELD)} field + layers + merchant"


@cek("Kosakata verdict/action/location_source tertutup")
def _k5():
    from qshield import binding as bd

    assert {bd.VERIFIED, bd.UNKNOWN, bd.ANOMALY} == VERDICT_SAH, (
        "daftar verdict berubah — klien memetakannya ke UI"
    )
    assert {bd.PROCEED, bd.WARN, bd.STEP_UP, bd.COOLING_OFF} == ACTION_SAH, (
        "daftar action berubah — ini juga invarian §4"
    )
    ls = SKEMA["components"]["schemas"]["VerifyRequest"]["properties"][
        "location_source"]
    assert set(ls.get("enum", [])) == LOCATION_SOURCE_SAH, (
        f"nilai location_source berubah: {ls.get('enum')}"
    )
    return (f"{len(VERDICT_SAH)} verdict, {len(ACTION_SAH)} action, "
            f"{len(LOCATION_SOURCE_SAH)} location_source")


@cek("Integritas perangkat opsional, dan ketiadaannya diungkapkan")
def _k5b():
    import tempfile as _tf
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz

    from fastapi.testclient import TestClient as _TC

    from qshield import api as _api, auth as _auth, emvco as _em
    from qshield.limits import RateLimiter as _RL
    from qshield.store import Store as _St

    NOW = _dt.now(_tz.utc)
    LAT, LNG, NMID = -6.914744, 107.609810, "ID1024365478912"
    _api.store = _St(os.path.join(_tf.mkdtemp(), "integ.db"))
    _api.clients = _auth.ClientRegistry(spec="", auth_setting="off")
    _api.limiter = _RL(max_requests=10_000, window_seconds=60)
    _api.store.seed_binding(
        nmid=NMID, lat=LAT, lng=LNG, merchant_name="WARUNG BU SRI",
        observer_count=47, first_seen=NOW - _td(days=180),
        last_seen=NOW - _td(hours=6))
    acct = _em.build_tlv({"00": "ID.CO.QRIS.WWW", "01": "936000149000000001",
                          "02": NMID, "03": "UMI"})
    payload = _em.build({"00": "01", "01": "11", "26": acct, "52": "5812",
                         "53": "360", "58": "ID", "59": "W", "60": "B",
                         "61": "40257"})
    c = _TC(_api.app)

    def minta(dev, di=None):
        body = {"payload": payload, "lat": LAT, "lng": LNG,
                "device_anon_id": dev, "accuracy_m": 9.0}
        if di is not None:
            body["device_integrity"] = di
        return c.post("/api/v1/verify", json=body).json()

    # Klien web tidak boleh dihukum untuk sesuatu yang browser memang
    # tidak izinkan — kesalahan yang pernah dibuat pada accuracy_missing.
    web = minta("kontrak-web-001")
    assert web["device_integrity"] == "not_provided"
    assert web["action"] == "proceed", (
        f"klien web dihukum jadi {web['action']} karena tidak bisa melapor")

    bersih = minta("kontrak-nat-001", {
        "mock_location": False, "rooted": False, "attested": True,
        "platform": "android"})
    assert bersih["device_integrity"] == "attested"
    assert bersih["action"] == "proceed"

    # GPS yang diakui palsu: menolak memberi putusan lokasi, sama seperti
    # akurasi buruk — masalahnya sama, jangkarnya tidak layak dinilai.
    palsu = minta("kontrak-nat-002", {"mock_location": True, "attested": True})
    assert palsu["verdict"] != "verified", f"mock GPS -> {palsu['verdict']}"
    assert palsu["action"] in ("step_up", "cooling_off")
    assert "mock_location_reported" in palsu["signals"]
    assert palsu["device_integrity"] == "failed"
    return "web tidak dihukum; attested lolos; mock GPS menolak putusan lokasi"


@cek("Tanggapan sungguhan cocok dengan kontraknya")
def _k6():
    import tempfile
    from datetime import datetime, timedelta, timezone

    from fastapi.testclient import TestClient

    from qshield import api, auth, emvco
    from qshield.limits import RateLimiter
    from qshield.store import Store

    NOW = datetime.now(timezone.utc)
    LAT, LNG, NMID = -6.914744, 107.609810, "ID1024365478912"
    api.store = Store(os.path.join(tempfile.mkdtemp(), "kontrak.db"))
    api.clients = auth.ClientRegistry(spec="", auth_setting="off")
    api.limiter = RateLimiter(max_requests=10_000, window_seconds=60)
    api.store.seed_binding(
        nmid=NMID, lat=LAT, lng=LNG, merchant_name="WARUNG BU SRI",
        observer_count=47, first_seen=NOW - timedelta(days=180),
        last_seen=NOW - timedelta(hours=6))

    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": "936000149000000001",
        "02": NMID, "03": "UMI"})
    payload = emvco.build({
        "00": "01", "01": "11", "26": acct, "52": "5812", "53": "360",
        "58": "ID", "59": "WARUNG BU SRI", "60": "BANDUNG", "61": "40257"})

    d = TestClient(api.app).post("/api/v1/verify", json={
        "payload": payload, "lat": LAT, "lng": LNG,
        "device_anon_id": "kontrak-device-1", "accuracy_m": 12.0}).json()

    assert set(d) == set(TANGGAPAN_FIELD), (
        f"tanggapan nyata menyimpang dari skema: {set(d) ^ set(TANGGAPAN_FIELD)}"
    )
    assert d["verdict"] in VERDICT_SAH, f"verdict asing: {d['verdict']}"
    assert d["action"] in ACTION_SAH, f"action asing: {d['action']}"
    assert d["location_source"] in LOCATION_SOURCE_SAH
    assert d["device_integrity"] in INTEGRITAS_SAH, (
        f"status integritas asing: {d['device_integrity']}")
    assert set(d["layers"]) == set(LAYERS_FIELD)
    assert set(d["merchant"]) == MERCHANT_FIELD
    assert isinstance(d["risk_score"], int) and 0 <= d["risk_score"] <= 100
    assert isinstance(d["reasons"], list) and d["reasons"], "reasons kosong"
    return f"{d['verdict']}/{d['action']}, {len(d)} field cocok"


# --- Laporan -------------------------------------------------------

print("=" * 70)
print("KONTRAK API v1")
print("=" * 70)
print()

gagal = 0
for nama, ok, detail in _hasil:
    print(f"  [{'OK   ' if ok else 'BEDA '}]  {nama}")
    if detail:
        print(f"           {detail}")
    if not ok:
        gagal += 1
print()
print("-" * 70)
if gagal:
    print(f"{gagal} bagian kontrak BERUBAH.")
    print("Kalau disengaja: perbarui tabel KONTRAK di berkas ini, catat di")
    print("API.md, dan beri tahu frontend. Kalau tidak: batalkan perubahannya.")
    sys.exit(1)
print(f"Kontrak v1 utuh — {len(_hasil)} bagian diperiksa.")
