"""
Pengujian pengerasan: validasi input, pembatasan laju, header, audit log.

Berkas ini TIDAK mematikan rate limiting — justru itu yang diuji di sini,
sementara suite lain mematikannya supaya bisa membanjiri API.

Bagian audit log adalah yang paling penting untuk auditor: ia membuktikan
invarian §8 berlaku bukan cuma di tabel, tapi juga di apa yang kami tulis
ke stdout. Skema yang bersih tidak ada gunanya kalau log-nya bocor.

    python tests/test_hardening.py
"""

import io
import json
import logging
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from qshield import api, audit, auth, emvco
from qshield.limits import RateLimiter
from qshield.store import Store

NOW = datetime.now(timezone.utc)
LAT, LNG = -6.914744, 107.609810
NMID = "ID1024365478912"

_hasil = []


def cek(nama):
    def deco(fn):
        try:
            _hasil.append((nama, True, fn() or ""))
        except AssertionError as exc:
            _hasil.append((nama, False, str(exc)))
        return fn
    return deco


# Kunci demo, dibuat sekali per proses. Nilai mentahnya tidak pernah
# ditulis ke berkas mana pun.
KUNCI_UJI = auth.new_key()
REGISTRY_UJI = auth.ClientRegistry(
    spec=f"pjp-alpha:{auth.hash_key(KUNCI_UJI)}", auth_setting="")


def siapkan(limiter=None, clients=None):
    api.store = Store(os.path.join(tempfile.mkdtemp(), "hard.db"))
    api.store.seed_binding(
        nmid=NMID, lat=LAT, lng=LNG, merchant_name="WARUNG BU SRI",
        observer_count=47,
        first_seen=NOW - timedelta(days=180), last_seen=NOW - timedelta(hours=6),
    )
    api.limiter = limiter or RateLimiter(max_requests=10_000, window_seconds=60)
    # Sebagian besar pemeriksaan di berkas ini bukan tentang autentikasi,
    # jadi bawaannya dimatikan; yang mengujinya menyodorkan registry sendiri.
    api.clients = clients or auth.ClientRegistry(spec="", auth_setting="off")
    return TestClient(api.app)


def qr(nmid=NMID, pan="936000149000000001"):
    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": pan, "02": nmid, "03": "UMI"})
    return emvco.build({
        "00": "01", "01": "11", "26": acct, "52": "5812", "53": "360",
        "58": "ID", "59": "WARUNG BU SRI", "60": "BANDUNG", "61": "40257"})


def kirim(c, **ganti):
    body = {"payload": qr(), "lat": LAT, "lng": LNG,
            "device_anon_id": "demo-device-0001", "accuracy_m": 12.0}
    body.update(ganti)
    return c.post("/api/v1/verify", json=body)


# --- Validasi input ------------------------------------------------

@cek("Payload kebesaran ditolak sebelum menyentuh parser")
def _v1():
    c = siapkan()
    assert kirim(c, payload="0" * 2000).status_code == 422, "2000 char lolos"
    assert c.post("/api/v1/verify", json={
        "payload": "0" * 200_000, "lat": LAT, "lng": LNG,
        "device_anon_id": "demo-device-0001"}).status_code == 413, (
        "badan raksasa tidak ditolak di lapisan HTTP")
    assert kirim(c).status_code == 200, "payload wajar ikut tertolak"
    return f"batas {api.MAX_PAYLOAD_CHARS} char / {api.MAX_BODY_BYTES} byte badan"


@cek("Karakter kendali tidak pernah sampai ke parser")
def _v2():
    c = siapkan()
    for jahat in ("\x00", "\x1b", "\x7f"):
        p = qr()
        r = kirim(c, payload=p[:20] + jahat + p[20:])
        assert r.status_code == 422, f"{jahat!r} lolos ke parser"
    return "null byte, escape, DEL — semuanya ditolak di batas"


@cek("device_anon_id dibatasi ke charset aman")
def _v3():
    c = siapkan()
    for jahat in ("../../etc/passwd", "'; DROP TABLE bindings;--",
                  "\x00binary", "spasi di dalam"):
        assert kirim(c, device_anon_id=jahat).status_code == 422, (
            f"{jahat!r} diterima")
    for sah in ("demo-device-0001", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"):
        assert kirim(c, device_anon_id=sah).status_code == 200, f"{sah} ditolak"
    return "traversal, SQL, null byte ditolak; UUID diterima"


@cek("accuracy_m punya batas atas")
def _v4():
    c = siapkan()
    assert kirim(c, accuracy_m=api.MAX_ACCURACY_M).status_code == 200
    assert kirim(c, accuracy_m=api.MAX_ACCURACY_M + 1).status_code == 422
    assert kirim(c, accuracy_m=1e300).status_code == 422
    return f"di atas {api.MAX_ACCURACY_M:,} m ditolak sebagai data ngawur"


# --- Pembatasan laju -----------------------------------------------

@cek("Rate limit menahan banjir permintaan")
def _r1():
    c = siapkan(RateLimiter(max_requests=10, window_seconds=60))
    kode = [kirim(c, device_anon_id=f"flood-{i:04d}").status_code
            for i in range(25)]
    assert kode.count(200) == 10, f"lolos {kode.count(200)}, harusnya 10"
    assert kode.count(429) == 15, f"ditolak {kode.count(429)}, harusnya 15"

    r = kirim(c, device_anon_id="flood-9999")
    assert r.headers.get("Retry-After"), "429 tanpa Retry-After"
    assert r.headers.get("X-RateLimit-Limit") == "10"
    return "10 lolos, 15 ditolak, Retry-After terpasang"


@cek("Rate limit tidak menyimpan alamat IP")
def _r2():
    rl = RateLimiter(max_requests=5, window_seconds=60)
    ip = "203.0.113.42"
    kunci = rl.key_for(ip)
    rl.check(kunci)
    assert ip not in kunci, "alamat mentah muncul di kunci"
    semua = json.dumps({k: len(v) for k, v in rl._hits.items()})
    assert ip not in semua, "alamat mentah tersimpan di penghitung"
    assert len(kunci) == 16, "kunci bukan hash terpotong"
    return f"{ip} -> {kunci} (hash terpotong, tidak bisa dibalik ke IP)"


@cek("Kuota eksplisit tidak bisa dimatikan diam-diam oleh env")
def _r4():
    lama = os.environ.get("QSHIELD_RATE_LIMIT")
    os.environ["QSHIELD_RATE_LIMIT"] = "off"
    try:
        # Dibuat dengan kuota eksplisit: env tidak boleh mengalahkannya.
        rl = RateLimiter(max_requests=3, window_seconds=60)
        assert not rl.disabled, (
            "QSHIELD_RATE_LIMIT=off mematikan limiter yang dibuat eksplisit"
        )
        kode = [rl.check("k")[0] for _ in range(5)]
        assert kode.count(True) == 3, f"lolos {kode.count(True)}, harusnya 3"

        # Tanpa argumen, env tetap berlaku.
        assert RateLimiter().disabled, "env tidak lagi dihormati"
    finally:
        if lama is None:
            os.environ.pop("QSHIELD_RATE_LIMIT", None)
        else:
            os.environ["QSHIELD_RATE_LIMIT"] = lama
    return "argumen eksplisit menang atas env; tanpa argumen env berlaku"


@cek("Rate limit bisa dimatikan untuk demo ber-NAT")
def _r3():
    lama = os.environ.get("QSHIELD_RATE_LIMIT")
    os.environ["QSHIELD_RATE_LIMIT"] = "off"
    try:
        rl = RateLimiter()
        assert rl.disabled, "env 'off' tidak mematikan pembatas"
        assert all(rl.check("k")[0] for _ in range(500)), "masih menolak"
    finally:
        if lama is None:
            os.environ.pop("QSHIELD_RATE_LIMIT", None)
        else:
            os.environ["QSHIELD_RATE_LIMIT"] = lama
    return "QSHIELD_RATE_LIMIT=off melewatkan 500 permintaan"


# --- Header & CORS -------------------------------------------------

@cek("Header keamanan terpasang di semua respons")
def _h1():
    c = siapkan()
    harus = {"x-content-type-options": "nosniff", "x-frame-options": "DENY",
             "referrer-policy": "no-referrer", "cache-control": "no-store"}
    for r in (c.get("/api/v1/health"), kirim(c)):
        for k, v in harus.items():
            assert r.headers.get(k) == v, f"{k} = {r.headers.get(k)}"
    return ", ".join(harus)


@cek("CORS tidak lagi terbuka untuk semua origin")
def _h2():
    c = siapkan()
    assert "*" not in api.ALLOWED_ORIGINS, "allow_origins masih berisi '*'"
    jahat = c.options("/api/v1/verify", headers={
        "Origin": "https://penyerang.example",
        "Access-Control-Request-Method": "POST"})
    assert jahat.headers.get("access-control-allow-origin") is None, (
        "origin asing diizinkan")
    sah = c.options("/api/v1/verify", headers={
        "Origin": api.ALLOWED_ORIGINS[0],
        "Access-Control-Request-Method": "POST"})
    assert sah.headers.get("access-control-allow-origin") == api.ALLOWED_ORIGINS[0]
    return f"hanya {', '.join(api.ALLOWED_ORIGINS)}"


# --- Audit log -----------------------------------------------------

@cek("Audit log tidak memuat identitas maupun koordinat presisi")
def _a1():
    c = siapkan()
    log = audit.get_logger()
    tangkap = io.StringIO()
    h = logging.StreamHandler(tangkap)
    h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h)
    try:
        device = "rahasia-device-42"
        kirim(c, device_anon_id=device, accuracy_m=12)
        kirim(c, payload="bukan-qris-sama-sekali", device_anon_id=device)
    finally:
        log.removeHandler(h)

    baris = [b for b in tangkap.getvalue().strip().split("\n") if b]
    assert baris, "tidak ada satu pun baris audit"
    mentah = "\n".join(baris)

    assert device not in mentah, "device_anon_id bocor ke log"
    for koord in (str(LAT), str(LNG), f"{LAT:.6f}", f"{LNG:.6f}"):
        assert koord not in mentah, f"koordinat presisi {koord} bocor ke log"

    entri = json.loads(baris[0])
    for wajib in ("ts", "event", "verdict", "action", "risk_score",
                  "signals", "layers", "geohash_7"):
        assert wajib in entri, f"field audit '{wajib}' hilang"
    for terlarang in ("device_anon_id", "lat", "lng", "ip", "payload"):
        assert terlarang not in entri, f"field '{terlarang}' ada di audit"

    assert len(entri["geohash_7"]) == 7, "geohash bukan presisi 7"
    return (f"{len(baris)} baris; putusan tercatat, pemindainya tidak "
            f"(sel {entri['geohash_7']}, ~152 m)")


@cek("Permintaan yang ditolak ikut tercatat")
def _a2():
    c = siapkan()
    log = audit.get_logger()
    tangkap = io.StringIO()
    h = logging.StreamHandler(tangkap)
    h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h)
    try:
        kirim(c, payload="000201tidakvalidsamasekali")
        c.post("/api/v1/verify", json={
            "payload": "0" * 200_000, "lat": LAT, "lng": LNG,
            "device_anon_id": "demo-device-0001"})
    finally:
        log.removeHandler(h)

    peristiwa = [json.loads(b)["reason"]
                 for b in tangkap.getvalue().strip().split("\n") if b
                 and json.loads(b).get("event") == "rejected"]
    assert "parse_error" in peristiwa, f"parse_error tidak tercatat: {peristiwa}"
    assert "body_too_large" in peristiwa, f"body_too_large tidak tercatat"
    return f"tercatat: {', '.join(sorted(set(peristiwa)))}"


# --- Mode replay ---------------------------------------------------

@cek("Mode replay tidak mengubah penilaian sedikit pun")
def _m1():
    c = siapkan()
    live = kirim(c, device_anon_id="banding-live-01", accuracy_m=8).json()
    rep = kirim(c, device_anon_id="banding-replay1", accuracy_m=8,
                location_source="replay").json()

    assert rep["verdict"] == live["verdict"], "replay mengubah verdict"
    assert rep["action"] == live["action"], "replay mengubah tier friksi"
    assert rep["risk_score"] == live["risk_score"], "replay mengubah skor"
    assert rep["layers"] == live["layers"], "replay mengubah rincian layer"
    return f"live dan replay sama-sama {live['verdict']}/{live['action']}"


@cek("Mode replay tidak bisa membobol invarian akurasi GPS")
def _m2():
    c = siapkan()
    d = kirim(c, device_anon_id="banding-replay2", accuracy_m=250,
              location_source="replay").json()
    assert d["verdict"] != "verified", "replay memaksa verified dari GPS buruk"
    assert d["action"] != "proceed", "replay memaksa proceed dari GPS buruk"
    assert any("kurasi" in r for r in d["reasons"])
    return "akurasi 250 m tetap ditolak walau ditandai replay"


@cek("Replay selalu mengaku dirinya replay")
def _m3():
    c = siapkan()
    log = audit.get_logger()
    tangkap = io.StringIO()
    h = logging.StreamHandler(tangkap)
    h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h)
    try:
        d = kirim(c, device_anon_id="banding-replay3",
                  location_source="replay").json()
    finally:
        log.removeHandler(h)

    assert d["location_source"] == "replay", "tanggapan tidak menandai replay"
    assert "replayed_location" in d["signals"], "sinyal replay tidak muncul"
    assert any("diputar ulang" in r for r in d["reasons"]), (
        "tidak ada alasan yang bisa dibaca manusia soal replay")
    assert d["reasons"][0].startswith("Koordinat diputar ulang"), (
        "penanda replay tidak di posisi paling depan")

    baris = [b for b in tangkap.getvalue().strip().split("\n") if b]
    entri = json.loads(baris[0])
    assert entri["location_source"] == "replay", "audit tidak mencatat replay"
    return "ditandai di tanggapan, sinyal, alasan terdepan, dan jejak audit"


@cek("Default tetap live — replay tidak pernah tidak sengaja aktif")
def _m4():
    c = siapkan()
    d = kirim(c, device_anon_id="banding-default").json()
    assert d["location_source"] == "live", f"default = {d['location_source']}"
    assert "replayed_location" not in d["signals"]
    r = kirim(c, device_anon_id="banding-ngaco", location_source="palsu")
    assert r.status_code == 422, "nilai location_source sembarang diterima"
    return "default 'live'; nilai di luar live/replay ditolak"


# --- Autentikasi klien ---------------------------------------------

@cek("Endpoint verifikasi menolak klien tanpa kunci")
def _t1():
    c = siapkan(clients=REGISTRY_UJI)
    for label, header in (("tanpa kunci", {}),
                          ("kunci ngawur", {auth.API_KEY_HEADER: "tebakan"}),
                          ("kunci hampir benar",
                           {auth.API_KEY_HEADER: KUNCI_UJI[:-1] + "X"})):
        r = c.post("/api/v1/verify", json={
            "payload": qr(), "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
            "device_anon_id": "demo-device-0001"}, headers=header)
        assert r.status_code == 401, f"{label} -> HTTP {r.status_code}"

    r = c.post("/api/v1/verify", json={
        "payload": qr(), "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
        "device_anon_id": "demo-device-0001"},
        headers={auth.API_KEY_HEADER: KUNCI_UJI})
    assert r.status_code == 200, f"kunci benar ditolak: {r.status_code}"
    return "tanpa kunci / ngawur / hampir benar semua 401; yang benar lolos"


@cek("Tanpa konfigurasi, sistem gagal TERTUTUP")
def _t2():
    c = siapkan(clients=auth.ClientRegistry(spec="", auth_setting=""))
    r = c.post("/api/v1/verify", json={
        "payload": qr(), "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
        "device_anon_id": "demo-device-0001"},
        headers={auth.API_KEY_HEADER: KUNCI_UJI})
    assert r.status_code == 503, (
        f"HTTP {r.status_code} — ketiadaan konfigurasi diperlakukan sebagai izin"
    )
    # Health tetap hidup supaya monitoring tahu servisnya menyala.
    assert c.get("/api/v1/health").status_code == 200
    return "503, bukan 200 — ketiadaan konfigurasi bukan izin"


@cek("Kunci API tidak pernah masuk log, bahkan saat gagal")
def _t3():
    c = siapkan(clients=REGISTRY_UJI)
    bocoran = "KUNCI-RAHASIA-JANGAN-BOCOR"
    log = audit.get_logger()
    tangkap = io.StringIO()
    h = logging.StreamHandler(tangkap)
    h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h)
    try:
        for kunci in (bocoran, KUNCI_UJI):
            c.post("/api/v1/verify", json={
                "payload": qr(), "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
                "device_anon_id": "demo-device-0001"},
                headers={auth.API_KEY_HEADER: kunci})
    finally:
        log.removeHandler(h)

    isi = tangkap.getvalue()
    assert bocoran not in isi, "kunci yang salah ikut tercatat"
    assert KUNCI_UJI not in isi, "kunci yang benar ikut tercatat"

    entri = [json.loads(b) for b in isi.strip().split("\n") if b]
    ditolak = [e for e in entri if e.get("event") == "rejected"]
    lolos = [e for e in entri if e.get("event") == "verify"]
    assert ditolak and ditolak[0]["reason"] == "auth_failed"
    assert lolos and lolos[0]["client"] == "pjp-alpha", (
        "client_id tidak tercatat di jejak audit"
    )
    return "kunci tidak bocor; client_id tercatat sebagai 'pjp-alpha'"


@cek("Kunci disimpan sebagai hash, bukan teks asli")
def _t4():
    reg = auth.ClientRegistry(
        spec=f"pjp-beta:{auth.hash_key(KUNCI_UJI)}", auth_setting="")
    tersimpan = json.dumps(reg._clients)
    assert KUNCI_UJI not in tersimpan, "kunci mentah tersimpan di registry"
    assert reg.authenticate(KUNCI_UJI) == "pjp-beta"
    assert reg.authenticate(KUNCI_UJI + "x") is None
    assert reg.authenticate("") is None
    assert reg.authenticate(None) is None
    return "registry hanya memegang sha256; kunci mentah tidak ada di memori"


@cek("client_id tidak pernah masuk tabel basis data")
def _t5():
    c = siapkan(clients=REGISTRY_UJI)
    c.post("/api/v1/verify", json={
        "payload": qr(), "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
        "device_anon_id": "demo-device-0001"},
        headers={auth.API_KEY_HEADER: KUNCI_UJI})

    tabel = [r["name"] for r in api.store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")]
    for t in tabel:
        kolom = [k["name"].lower() for k in
                 api.store.conn.execute(f"PRAGMA table_info({t})")]
        for terlarang in ("client", "api_key", "pjp"):
            assert not any(terlarang in k for k in kolom), (
                f"{t} punya kolom '{terlarang}' — client_id merembes ke skema"
            )
    return f"{len(tabel)} tabel diperiksa; client_id hanya hidup di jejak audit"


@cek("Kuota dihitung per klien, bukan per alamat IP")
def _t6():
    # Ini yang menutup batasan R8: di balik NAT seluruh ruangan berbagi
    # satu alamat, jadi kuota per-IP menghukum pengguna yang tidak salah.
    c = siapkan(limiter=RateLimiter(max_requests=5, window_seconds=60),
                clients=REGISTRY_UJI)
    kode = []
    for i in range(8):
        r = c.post("/api/v1/verify", json={
            "payload": qr(), "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
            "device_anon_id": f"kuota-{i:04d}"},
            headers={auth.API_KEY_HEADER: KUNCI_UJI})
        kode.append(r.status_code)
    assert kode.count(200) == 5 and kode.count(429) == 3, f"pola {kode}"

    # Semua permintaan datang dari alamat yang sama (TestClient), jadi
    # kalau kuotanya masih per-IP, klien kedua ikut terkena. Buktikan
    # kuncinya memang client_id.
    kunci_dipakai = [k for k in api.limiter._hits if k.startswith("client:")]
    assert kunci_dipakai == ["client:pjp-alpha"], (
        f"kuota tidak dikunci ke client_id: {list(api.limiter._hits)}"
    )
    return "kuota dikunci ke 'client:pjp-alpha', bukan alamat IP (menutup R8)"


# --- Konkurensi ----------------------------------------------------

@cek("Permintaan serentak tidak merusak hitungan pengamat")
def _k1():
    c = siapkan()
    galat = []

    def kirim(i):
        try:
            r = c.post("/api/v1/verify", json={
                "payload": qr(), "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
                "device_anon_id": f"paralel-{i:04d}"})
            if r.status_code != 200:
                galat.append(f"HTTP {r.status_code}")
        except Exception as exc:
            galat.append(f"{type(exc).__name__}: {exc}")

    N = 60
    utas = [threading.Thread(target=kirim, args=(i,)) for i in range(N)]
    mulai = time.perf_counter()
    for u in utas:
        u.start()
    for u in utas:
        u.join()
    lama = (time.perf_counter() - mulai) * 1000

    assert not galat, f"{len(galat)} permintaan gagal: {sorted(set(galat))}"

    obs = api.store.conn.execute(
        "SELECT COUNT(*) c FROM observations").fetchone()["c"]
    oc = api.store.conn.execute(
        "SELECT observer_count FROM bindings WHERE nmid = ?",
        (NMID,)).fetchone()["observer_count"]

    # Jangkar sudah diseed 47 pengamat, jadi N device baru menambahkannya.
    assert obs == N, f"observations {obs}, harusnya {N}"
    assert oc == 47 + N, f"observer_count {oc}, harusnya {47 + N}"
    return f"{N} thread serentak, {lama:.0f} ms, nol galat, hitungan tepat"


@cek("Device yang sama dikirim serentak tetap dihitung sekali")
def _k2():
    c = siapkan()

    def kirim():
        c.post("/api/v1/verify", json={
            "payload": qr(), "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
            "device_anon_id": "device-yang-sama"})

    utas = [threading.Thread(target=kirim) for _ in range(50)]
    for u in utas:
        u.start()
    for u in utas:
        u.join()

    oc = api.store.conn.execute(
        "SELECT observer_count FROM bindings WHERE nmid = ?",
        (NMID,)).fetchone()["observer_count"]
    obs = api.store.conn.execute(
        "SELECT COUNT(*) c FROM observations").fetchone()["c"]
    assert obs == 1, f"observations {obs}, idempotensi jebol"
    assert oc == 48, f"observer_count {oc}, harusnya 47 + 1"
    return "50 permintaan paralel dari satu device -> tetap 1 pengamat"


@cek("Kapasitas jauh di atas kebutuhan demo")
def _k3():
    c = siapkan()
    N = 200

    def kirim(i):
        c.post("/api/v1/verify", json={
            "payload": qr(), "lat": LAT, "lng": LNG, "accuracy_m": 12.0,
            "device_anon_id": f"beban-{i:04d}"})

    utas = [threading.Thread(target=kirim, args=(i,)) for i in range(N)]
    mulai = time.perf_counter()
    for u in utas:
        u.start()
    for u in utas:
        u.join()
    detik = time.perf_counter() - mulai
    laju = N / detik

    obs = api.store.conn.execute(
        "SELECT COUNT(*) c FROM observations").fetchone()["c"]
    assert obs == N, f"observations {obs}, harusnya {N}"
    # Demo memakai 2-3 HP. Margin puluhan kali lipat sudah lebih dari cukup.
    assert laju > 50, f"hanya {laju:.0f} permintaan/detik"
    return f"{N} serentak dalam {detik * 1000:.0f} ms = {laju:.0f} permintaan/detik"


# --- Laporan -------------------------------------------------------

print("=" * 70)
print("PENGERASAN — validasi input, rate limit, header, audit")
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
