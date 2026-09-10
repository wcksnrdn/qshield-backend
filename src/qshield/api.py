"""
API Q-Shield.

Endpoint utama POST /api/v1/verify menerima payload QRIS mentah
beserta koordinat, lalu mengembalikan verdict dengan alasan yang
bisa dibaca manusia.
"""

import time
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import behavior as bh
from . import binding as bd
from . import emvco
from .store import Store

app = FastAPI(title="Q-Shield API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # PoC; batasi di produksi
    allow_methods=["*"],
    allow_headers=["*"],
)

store = Store("qshield.db")


class VerifyRequest(BaseModel):
    payload: str = Field(..., description="String QRIS mentah hasil scan")
    lat: float = Field(..., ge=-90, le=90)
    lng: float = Field(..., ge=-180, le=180)
    device_anon_id: str = Field(..., min_length=8, max_length=64)
    accuracy_m: Optional[float] = Field(None, ge=0)


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
        raise HTTPException(status_code=422, detail=f"Payload tidak valid: {exc}")

    nmid = parsed.nmid
    if not nmid:
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
        elapsed = (time.perf_counter() - started) * 1000
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
            processing_ms=round(elapsed, 2),
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

    elapsed = (time.perf_counter() - started) * 1000

    return VerifyResponse(
        verdict=verdict.status,
        action=verdict.action,
        risk_score=verdict.risk_score,
        reasons=verdict.reasons,
        signals=verdict.signals,
        layers=LayerScores(location=lokasi.risk_score, behavior=perilaku.score),
        merchant=MerchantOut(
            nmid=nmid,
            name=parsed.merchant_name,
            city=parsed.merchant_city,
            criteria=parsed.criteria_label,
            is_static=parsed.is_static,
        ),
        processing_ms=round(elapsed, 2),
    )
