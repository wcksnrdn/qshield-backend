"""
API Q-Shield.

Endpoint utama POST /api/v1/verify menerima payload QRIS mentah
beserta koordinat, lalu mengembalikan verdict dengan alasan yang
bisa dibaca manusia.
"""

import os
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import audit
from . import behavior as bh
from . import binding as bd
from . import emvco
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
store = Store("qshield.db")


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
async def batasi_laju(request: Request, call_next):
    """Jendela geser per klien; lihat limits.py untuk catatan privasinya."""
    if request.url.path == "/api/v1/verify":
        klien = request.client.host if request.client else ""
        izin, sisa, reset = limiter.check(limiter.key_for(klien))
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
async def header_keamanan(request: Request, call_next):
    respons = await call_next(request)
    respons.headers["X-Content-Type-Options"] = "nosniff"
    respons.headers["X-Frame-Options"] = "DENY"
    respons.headers["Referrer-Policy"] = "no-referrer"
    respons.headers["Cache-Control"] = "no-store"
    return respons


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
    accuracy_m: Optional[float] = Field(None, ge=0, le=MAX_ACCURACY_M)


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
    processing_ms: float


@app.get("/api/v1/health")
def health():
    return {"status": "ok", **store.stats()}


@app.post("/api/v1/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    started = time.perf_counter()

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

    # Akurasi GPS buruk membuat jangkar tidak dapat dipercaya, jadi
    # Layer 1 tidak dijalankan sama sekali (invarian §6).
    #
    # Sinyal STRUKTURAL Layer 2 tetap berlaku: cacat bentuk payload sama
    # sekali tidak bergantung pada GPS, dan mengabaikannya berarti
    # membuang bukti yang masih sehat. Sinyal perilaku dimatikan
    # (state=None) karena jangkarnya justru yang tidak bisa dipercaya.
    if req.accuracy_m and req.accuracy_m > 100:
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
        struktural = bh.evaluate(parsed, state=None)
        low = bd.compose(low, struktural)
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        audit.record_verdict(
            low, nmid, req.lat, req.lng,
            {"location": 40, "behavior": struktural.score},
            elapsed, req.accuracy_m, parsed.merchant_name,
        )
        return VerifyResponse(
            verdict=low.status,
            action=low.action,
            risk_score=low.risk_score,
            reasons=low.reasons,
            signals=low.signals,
            layers=LayerScores(location=40, behavior=struktural.score),
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
    )

    verdict = bd.compose(lokasi, perilaku)

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
        req.accuracy_m, parsed.merchant_name,
    )

    return VerifyResponse(
        verdict=verdict.status,
        action=verdict.action,
        risk_score=verdict.risk_score,
        reasons=verdict.reasons,
        signals=verdict.signals,
        layers=LayerScores(**lapisan),
        merchant=MerchantOut(
            nmid=nmid,
            name=parsed.merchant_name,
            city=parsed.merchant_city,
            criteria=parsed.criteria_label,
            is_static=parsed.is_static,
        ),
        processing_ms=elapsed,
    )
