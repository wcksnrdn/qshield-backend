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
}
PERMINTAAN_TIPE = {
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
    if "type" in d:
        return d["type"]
    for kunci in ("anyOf", "allOf", "oneOf"):
        if kunci in d:
            for cabang in d[kunci]:
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
