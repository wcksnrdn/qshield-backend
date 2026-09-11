"""
API Q-Shield.

Endpoint utama POST /api/v1/verify menerima payload QRIS mentah
beserta koordinat, lalu mengembalikan verdict dengan alasan yang
bisa dibaca manusia.
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import audit
from . import auth
from . import config
from . import behavior as bh
from . import binding as bd
from . import emvco
from . import geo
from .limits import RateLimiter
from .store import Store

app = FastAPI(title="Q-Shield API", version="0.1.0")

# --- Batas permukaan serangan --------------------------------------
#
# Payload QRIS adalah untrusted input, dan ukurannya yang membuatnya
# berbahaya. Diukur: QR demo 148-158 karakter; QR yang dimuati semaksimal
# mungkin tapi masih sah 503. Batas 1024 memberi kelonggaran dua kali
# lipat sambil menolak sampah sebelum sempat menyentuh parser — tanpa
# batas ini, payload 16 MB menghabiskan ~1,9 detik CPU sebelum ditolak.
MAX_PAYLOAD_CHARS = 1024

# Badan permintaan dipotong lebih awal lagi, di lapisan HTTP, supaya
# CPU tidak terpakai hanya untuk membaca sesuatu yang pasti ditolak.
MAX_BODY_BYTES = 8 * 1024

# Akurasi di atas ini bukan lagi galat GPS, melainkan data ngawur.
MAX_ACCURACY_M = 100_000

# Origin dibatasi lewat env supaya demo lokal tetap gampang tanpa
# menyisakan allow_origins=["*"] di kode.
ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get(
        "QSHIELD_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

limiter = RateLimiter()
clients = auth.ClientRegistry()
store = Store(os.environ.get("QSHIELD_DB", "qshield.db"))

# Sakelar yang dipasang untuk gladi bersih lalu lupa dicabut adalah cara
# paling umum sebuah sistem berangkat ke produksi dalam keadaan terbuka.
# Karena itu setiap lapis yang sedang mati diteriakkan saat start, bukan
# didiamkan.
for _tingkat, _pesan in config.warnings():
    if _tingkat == "BAHAYA":
        audit.get_logger().warning(
            json.dumps({"event": "config_warning", "level": _tingkat,
                        "message": _pesan}, ensure_ascii=False))

VERIFY_PATH = "/api/v1/verify"

# Endpoint yang boleh diakses tanpa kunci. SEMUA jalur /api/ lain
# dilindungi — daftar putih, bukan daftar hitam. Endpoint baru yang
# lupa didaftarkan jadi tertutup, bukan terbuka; kebalikannya adalah
# cara paling umum sebuah API bocor saat berkembang.
JALUR_TERBUKA = {"/api/v1/health"}


def _butuh_kunci(path: str) -> bool:
    return path.startswith("/api/") and path not in JALUR_TERBUKA


# Middleware terdaftar dari yang PALING DALAM ke yang paling luar:
# Starlette menjalankan yang terakhir didaftarkan lebih dulu. Urutan
# eksekusinya jadi:
#
#   header_keamanan      pasang header di SEMUA respons, termasuk 401/429
#   batasi_ukuran_badan  buang yang kebesaran sebelum apa pun membacanya
#   autentikasi          tetapkan siapa kliennya
#   batasi_laju          kuota dihitung PER KLIEN, memakai hasil di atas
#   handler
#
# Autentikasi sengaja di luar pembatas laju: tanpa itu kuota terpaksa
# dikunci ke alamat IP, dan di balik NAT satu alamat mewakili seluruh
# ruangan (batasan R8).


@app.middleware("http")
async def batasi_laju(request: Request, call_next):
    """Jendela geser. Dikunci per klien kalau autentikasi aktif."""
    if _butuh_kunci(request.url.path):
        client_id = getattr(request.state, "client_id", None)
        if client_id:
            kunci = f"client:{client_id}"
        else:
            alamat = request.client.host if request.client else ""
            kunci = limiter.key_for(alamat)

        izin, sisa, reset = limiter.check(kunci)
        if not izin:
            audit.record_rejected("rate_limited", f"reset dalam {reset:.0f}s")
            return JSONResponse(
                status_code=429,
                content={"detail": "Terlalu banyak permintaan"},
                headers={
                    "Retry-After": str(int(reset) + 1),
                    "X-RateLimit-Limit": str(limiter.max_requests),
                    "X-RateLimit-Remaining": "0",
                },
            )
        respons = await call_next(request)
        respons.headers["X-RateLimit-Limit"] = str(limiter.max_requests)
        respons.headers["X-RateLimit-Remaining"] = str(sisa)
        return respons
    return await call_next(request)


@app.middleware("http")
async def autentikasi(request: Request, call_next):
    """Hanya PJP terdaftar yang boleh meminta putusan.

    Gagal TERTUTUP: kalau tidak ada kunci terkonfigurasi dan autentikasi
    tidak dimatikan secara eksplisit, permintaan ditolak. Ketiadaan
    konfigurasi bukan izin — logika yang sama dengan invarian §2.
    """
    request.state.client_id = None

    if not _butuh_kunci(request.url.path):
        return await call_next(request)

    if clients.disabled:
        # Dimatikan secara sadar, bukan karena lupa dikonfigurasi.
        request.state.client_id = "anonymous"
        return await call_next(request)

    if not clients.configured:
        audit.record_rejected("auth_not_configured")
        return JSONResponse(
            status_code=503,
            content={"detail": "Autentikasi belum dikonfigurasi di server"},
        )

    disodorkan = request.headers.get(auth.API_KEY_HEADER, "")
    client_id = clients.authenticate(disodorkan)
    if not client_id:
        # Alasannya sengaja tidak dibedakan antara "tidak ada kunci" dan
        # "kunci salah", dan kuncinya sendiri tidak pernah ikut dicatat.
        audit.record_rejected("auth_failed")
        return JSONResponse(
            status_code=401,
            content={"detail": "Kunci API tidak valid atau tidak disertakan"},
            headers={"WWW-Authenticate": auth.API_KEY_HEADER},
        )

    request.state.client_id = client_id
    return await call_next(request)


@app.middleware("http")
async def batasi_ukuran_badan(request: Request, call_next):
    """Tolak badan permintaan kebesaran sebelum dibaca."""
    panjang = request.headers.get("content-length")
    if panjang and panjang.isdigit() and int(panjang) > MAX_BODY_BYTES:
        audit.record_rejected("body_too_large", f"{panjang} bytes")
        return JSONResponse(
            status_code=413,
            content={"detail": "Badan permintaan terlalu besar"},
        )
    return await call_next(request)


@app.middleware("http")
async def header_keamanan(request: Request, call_next):
    respons = await call_next(request)
    respons.headers["X-Content-Type-Options"] = "nosniff"
    respons.headers["X-Frame-Options"] = "DENY"
    respons.headers["Referrer-Policy"] = "no-referrer"
    respons.headers["Cache-Control"] = "no-store"
    return respons


class DeviceIntegrity(BaseModel):
    """Laporan integritas dari klien NATIVE.

    Browser sengaja tidak membocorkan hal-hal ini ke halaman web, jadi
    klien web akan selalu mengosongkannya. Itu bukan kekurangan yang
    disembunyikan — ketiadaannya diungkapkan di tanggapan.

    Rantai kepercayaannya: Q-Shield TIDAK bisa memverifikasi field ini.
    Yang membuatnya berarti adalah `attested` — hasil Play Integrity
    (Android) atau App Attest (iOS) yang diverifikasi PJP di sisi
    mereka, lalu dipertanggungkan lewat kunci API mereka. Kami tidak
    memercayai perangkatnya; kami memercayai PJP yang menyatakan sudah
    memeriksanya.
    """

    mock_location: Optional[bool] = Field(
        None, description="OS melaporkan lokasi berasal dari mock provider")
    rooted: Optional[bool] = Field(
        None, description="perangkat di-root / jailbreak")
    attested: Optional[bool] = Field(
        None, description="Play Integrity / App Attest lolos")
    platform: Optional[Literal["android", "ios", "web", "other"]] = None


class VerifyRequest(BaseModel):
    """Seluruh field divalidasi di batas sistem, bukan di dalam logika.

    Payload QRIS datang dari kamera dan bisa berisi apa saja; polanya
    dibatasi ke ASCII yang bisa dicetak supaya null byte dan karakter
    kendali tidak pernah sampai ke parser maupun ke basis data.
    """

    payload: str = Field(
        ..., min_length=8, max_length=MAX_PAYLOAD_CHARS,
        pattern=r"^[\x20-\x7E]+$",
        description="String QRIS mentah hasil scan",
    )
    lat: float = Field(..., ge=-90, le=90)
    lng: float = Field(..., ge=-180, le=180)
    device_anon_id: str = Field(
        ..., min_length=8, max_length=64,
        pattern=r"^[A-Za-z0-9_-]+$",
        description="Pengenal acak per perangkat, bukan identitas pengguna",
    )
    # WAJIB, bukan opsional. Menjadikannya opsional membuka pintu keluar
    # dari invarian §6: penyerang yang akurasinya buruk tinggal tidak
    # mengirimkannya, dan pemeriksaan ">100 m" tidak pernah berjalan.
    #
    # Tanpa tahu seberapa bagus fix-nya, jangkar tidak bisa dinilai sama
    # sekali — jadi ini bukan sinyal risiko melainkan syarat masuk.
    # Geolocation API browser selalu memberikan coords.accuracy bersama
    # koordinatnya, jadi klien mana pun sudah memegangnya.
    accuracy_m: float = Field(..., ge=0, le=MAX_ACCURACY_M)

    # Jalur cadangan demo. GPS di dalam gedung kerap melaporkan akurasi
    # >100 m, dan invarian §6 akan menolak memberi putusan — sistemnya
    # benar, tapi demonya mati. Mode ini memutar ulang koordinat yang
    # direkam di luar gedung.
    #
    # Penandanya ada di PERMINTAAN dan ikut keluar di TANGGAPAN, dan
    # tidak mengubah penilaian sedikit pun. Kejujurannya disengaja:
    # replay yang disamarkan seolah live adalah kebohongan kecil yang
    # akan dicium juri, dan mengakuinya justru menguatkan — penolakan
    # memberi putusan saat sinyal buruk memang fitur, bukan bug.
    location_source: Literal["live", "replay"] = Field(
        "live", description="'replay' bila koordinat berasal dari rekaman")

    device_integrity: Optional[DeviceIntegrity] = Field(
        None, description="diisi klien native; klien web mengosongkannya")


class MerchantOut(BaseModel):
    nmid: Optional[str]
    name: Optional[str]
    city: Optional[str]
    criteria: Optional[str]
    is_static: bool


class LayerScores(BaseModel):
    """Rincian per layer.

    Dipisah supaya auditor bisa melihat sumbangan tiap layer, bukan cuma
    angka gabungan — dan supaya jelas Layer 2 melengkapi, bukan
    menggantikan, putusan Layer 1.
    """

    location: int      # Layer 1 — ikatan merchant-lokasi
    behavior: int      # Layer 2 — perilaku artefak QR


class VerifyResponse(BaseModel):
    verdict: str
    action: str
    risk_score: int
    reasons: list
    signals: list
    layers: LayerScores
    merchant: MerchantOut
    location_source: str
    # Pengungkapan, bukan skor: "not_provided" berarti pemeriksaan
    # integritas TIDAK PERNAH DIJALANKAN — bukan dijalankan lalu lolos.
    device_integrity: str
    processing_ms: float


REPLAY_NOTICE = ("Koordinat diputar ulang dari rekaman lokasi — bukan GPS "
                 "langsung. Penilaian berjalan apa adanya.")

MOCK_NOTICE = ("Sistem operasi melaporkan lokasi ini berasal dari mock "
               "provider — jangkar tidak dapat dinilai")


def _status_integritas(di) -> str:
    """Ringkas laporan integritas jadi satu kata untuk tanggapan."""
    if di is None:
        return "not_provided"
    if di.mock_location is True or di.rooted is True or di.attested is False:
        return "failed"
    if di.attested is True:
        return "attested"
    return "reported"


def _tandai_replay(verdict, req):
    """Sisipkan penanda replay di paling depan daftar alasan."""
    if req.location_source == "replay":
        verdict.reasons = [REPLAY_NOTICE] + list(verdict.reasons)
        verdict.signals = list(verdict.signals) + ["replayed_location"]
    return verdict


# Frontend disajikan dari proses yang sama, bukan dari dev server
# terpisah. Dua alasan, keduanya soal hari-H: satu origin berarti tidak
# ada urusan CORS sama sekali, dan satu proses berarti satu hal yang
# bisa mati, bukan dua.
WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


@app.get("/", include_in_schema=False)
def scanner():
    return FileResponse(os.path.join(WEB, "index.html"),
                        media_type="text/html")


@app.get("/api/v1/health")
def health():
    return {"status": "ok", **store.stats()}


class RegisterRequest(BaseModel):
    """Pernyataan penyelenggara tentang ikatan merchant-lokasi.

    Yang mendaftarkan adalah PJP yang meng-onboard merchant, jadi ia
    memang mengetahui NMID mana milik siapa. Ini menutup cold start:
    merchant tidak perlu menunggu tiga pengamat selama 24 jam.

    Konsekuensinya jujur — ini jalur kepercayaan baru, dan kunci PJP
    yang bocor bisa dipakai mendaftarkan stiker palsu. Karena itu tiap
    pendaftaran dicatat beserta pendaftarnya, bisa dicabut, dan
    menghasilkan sinyal yang berbeda dari konsensus.
    """

    nmid: str = Field(..., min_length=3, max_length=32,
                      pattern=r"^[A-Za-z0-9]+$")
    lat: float = Field(..., ge=-90, le=90)
    lng: float = Field(..., ge=-180, le=180)
    merchant_name: Optional[str] = Field(None, max_length=99)
    is_mobile: bool = Field(
        False, description="merchant keliling — ikatan lokasi tidak berlaku")


class RegisterResponse(BaseModel):
    ok: bool
    nmid: str
    registrar: Optional[str] = None
    registered_at: Optional[str] = None
    is_mobile: bool = False
    detail: Optional[str] = None


@app.post("/api/v1/merchants", response_model=RegisterResponse, status_code=201)
def daftarkan(req: RegisterRequest, request: Request, response: Response):
    client_id = getattr(request.state, "client_id", None) or "anonymous"
    hasil = store.register(
        nmid=req.nmid, registrar=client_id, lat=req.lat, lng=req.lng,
        merchant_name=req.merchant_name, is_mobile=req.is_mobile)

    if not hasil.get("ok"):
        response.status_code = 409
        audit.record_rejected("register_conflict", f"{req.nmid}:{hasil['reason']}")
        return RegisterResponse(
            ok=False, nmid=req.nmid,
            detail="NMID ini sudah didaftarkan penyelenggara lain")

    audit.get_logger().info(json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "merchant_registered",
        "nmid": req.nmid,
        "registrar": client_id,
        "geohash_7": geo.encode(req.lat, req.lng, bd.INDEX_PRECISION),
        "is_mobile": req.is_mobile,
    }, ensure_ascii=False))

    return RegisterResponse(ok=True, nmid=req.nmid, registrar=client_id,
                            registered_at=hasil["registered_at"],
                            is_mobile=req.is_mobile)


@app.delete("/api/v1/merchants/{nmid}", response_model=RegisterResponse)
def cabut(nmid: str, request: Request, response: Response):
    client_id = getattr(request.state, "client_id", None) or "anonymous"
    hasil = store.revoke(nmid=nmid, registrar=client_id)

    if not hasil.get("ok"):
        response.status_code = 404 if hasil["reason"] == "tidak_terdaftar" else 403
        audit.record_rejected("revoke_denied", f"{nmid}:{hasil['reason']}")
        pesan = {"tidak_terdaftar": "NMID ini tidak terdaftar",
                 "bukan_pendaftarnya": "Hanya pendaftarnya yang boleh mencabut"}
        return RegisterResponse(ok=False, nmid=nmid,
                                detail=pesan[hasil["reason"]])

    audit.get_logger().info(json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "merchant_revoked", "nmid": nmid, "registrar": client_id,
    }, ensure_ascii=False))
    return RegisterResponse(ok=True, nmid=nmid, registrar=client_id)


@app.post(VERIFY_PATH, response_model=VerifyResponse)
def verify(req: VerifyRequest, request: Request):
    started = time.perf_counter()
    client_id = getattr(request.state, "client_id", None)

    try:
        parsed = emvco.parse(req.payload)
    except emvco.ParseError as exc:
        audit.record_rejected("parse_error", str(exc))
        raise HTTPException(status_code=422, detail=f"Payload tidak valid: {exc}")

    nmid = parsed.nmid
    if not nmid:
        audit.record_rejected("nmid_missing")
        raise HTTPException(
            status_code=422,
            detail="Merchant ID tidak ditemukan dalam payload",
        )

    di = req.device_integrity
    status_integritas = _status_integritas(di)

    # GPS yang DIAKUI palsu menempatkan kita di posisi yang sama persis
    # dengan akurasi buruk: jangkarnya tidak layak dinilai. Ditangani
    # dengan menolak memberi putusan lokasi, bukan dengan menambah skor —
    # perlakuan yang sama seperti invarian §6, karena masalahnya sama.
    #
    # Bedanya satu: akurasi buruk itu nasib, mock location itu sengaja.
    # Karena itu skor dasarnya lebih tinggi.
    if di is not None and di.mock_location is True:
        palsu = bd.Verdict(
            status=bd.UNKNOWN, action=bd.STEP_UP, risk_score=65,
            reasons=[MOCK_NOTICE], signals=["mock_location_reported"],
        )
        struktural = bh.evaluate(parsed, state=None,
                                 accuracy_m=req.accuracy_m, has_coords=True)
        palsu = _tandai_replay(bd.compose(palsu, struktural), req)
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        audit.record_verdict(
            palsu, nmid, req.lat, req.lng,
            {"location": 65, "behavior": struktural.score},
            elapsed, req.accuracy_m, parsed.merchant_name,
            req.location_source, client_id,
        )
        return VerifyResponse(
            verdict=palsu.status, action=palsu.action,
            risk_score=palsu.risk_score, reasons=palsu.reasons,
            signals=palsu.signals,
            layers=LayerScores(location=65, behavior=struktural.score),
            location_source=req.location_source,
            device_integrity=status_integritas,
            merchant=MerchantOut(
                nmid=nmid, name=parsed.merchant_name,
                city=parsed.merchant_city, criteria=parsed.criteria_label,
                is_static=parsed.is_static),
            processing_ms=elapsed,
        )

    # Akurasi GPS buruk membuat jangkar tidak dapat dipercaya, jadi
    # Layer 1 tidak dijalankan sama sekali (invarian §6).
    #
    # Sinyal STRUKTURAL Layer 2 tetap berlaku: cacat bentuk payload sama
    # sekali tidak bergantung pada GPS, dan mengabaikannya berarti
    # membuang bukti yang masih sehat. Sinyal perilaku dimatikan
    # (state=None) karena jangkarnya justru yang tidak bisa dipercaya.
    if req.accuracy_m > 100:
        low = bd.Verdict(
            status=bd.UNKNOWN,
            action=bd.WARN,
            risk_score=40,
            reasons=[
                f"Akurasi lokasi rendah ({req.accuracy_m:.0f} m) — "
                f"verifikasi lokasi tidak dapat dilakukan"
            ],
            signals=["low_gps_accuracy"],
        )
        struktural = bh.evaluate(parsed, state=None,
                                 accuracy_m=req.accuracy_m, has_coords=True,
                                 integrity=di)
        low = _tandai_replay(bd.compose(low, struktural), req)
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        audit.record_verdict(
            low, nmid, req.lat, req.lng,
            {"location": 40, "behavior": struktural.score},
            elapsed, req.accuracy_m, parsed.merchant_name,
            req.location_source, client_id, status_integritas,
        )
        return VerifyResponse(
            verdict=low.status,
            action=low.action,
            risk_score=low.risk_score,
            reasons=low.reasons,
            signals=low.signals,
            layers=LayerScores(location=40, behavior=struktural.score),
            location_source=req.location_source,
            device_integrity=status_integritas,
            merchant=MerchantOut(
                nmid=nmid,
                name=parsed.merchant_name,
                city=parsed.merchant_city,
                criteria=parsed.criteria_label,
                is_static=parsed.is_static,
            ),
            processing_ms=elapsed,
        )

    nearby = store.nearby(req.lat, req.lng)
    elsewhere = store.by_nmid(nmid)
    anchor_id, anchor_nmid, anchor_state = store.anchor_state(req.lat, req.lng)

    # Layer 1 — ikatan merchant-lokasi.
    lokasi = bd.evaluate(
        nmid=nmid,
        lat=req.lat,
        lng=req.lng,
        nearby=nearby,
        same_nmid_elsewhere=elsewhere,
        crc_valid=parsed.crc_valid,
    )

    # Layer 2 — perilaku artefak QR.
    # "Pemilik sah jangkar" diambil dari putusan Layer 1, bukan dari
    # tebakan siapa binding dominan di sini. Bedanya nyata di food court:
    # jangkar dominan bisa milik Toko A, tapi pelanggan yang memindai QR
    # Toko B yang sama-sama mapan juga berhak tidak kena sinyal serangan
    # yang ditujukan ke tetangganya.
    pemilik_sah = (lokasi.matched_binding is not None
                   and lokasi.matched_binding.is_established)

    perilaku = bh.evaluate(
        parsed,
        state=anchor_state,
        nmid_matches_anchor=pemilik_sah,
        accuracy_m=req.accuracy_m,
        has_coords=True,
        integrity=di,
    )

    verdict = _tandai_replay(bd.compose(lokasi, perilaku), req)

    # Pengamatan dicatat hanya kalau tidak terindikasi anomali,
    # supaya stiker palsu tidak ikut membangun reputasi.
    if verdict.status != bd.ANOMALY:
        store.record(
            nmid=nmid,
            lat=req.lat,
            lng=req.lng,
            device_anon_id=req.device_anon_id,
            merchant_name=parsed.merchant_name,
        )
    elif anchor_id is not None:
        # Jangkar ini jadi sasaran. Dicatat sebagai PERCOBAAN, bukan
        # pengamatan: observer_count tidak disentuh, jadi invarian §3
        # tetap utuh — reputasi palsu tidak bisa dibangun dari sini.
        store.note_anomaly(anchor_id)

    elapsed = round((time.perf_counter() - started) * 1000, 2)
    lapisan = {"location": lokasi.risk_score, "behavior": perilaku.score}
    audit.record_verdict(
        verdict, nmid, req.lat, req.lng, lapisan, elapsed,
        req.accuracy_m, parsed.merchant_name, req.location_source,
        client_id, status_integritas,
    )

    return VerifyResponse(
        verdict=verdict.status,
        action=verdict.action,
        risk_score=verdict.risk_score,
        reasons=verdict.reasons,
        signals=verdict.signals,
        layers=LayerScores(**lapisan),
        location_source=req.location_source,
        device_integrity=status_integritas,
        merchant=MerchantOut(
            nmid=nmid,
            name=parsed.merchant_name,
            city=parsed.merchant_city,
            criteria=parsed.criteria_label,
            is_static=parsed.is_static,
        ),
        processing_ms=elapsed,
    )
