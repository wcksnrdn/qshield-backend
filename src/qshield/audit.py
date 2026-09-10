"""
Jejak audit terstruktur.

Satu baris JSON per putusan, ke stdout. Formatnya sengaja machine
readable supaya bisa diarahkan ke agregator log tanpa parsing khusus.

Apa yang DICATAT, dan mengapa boleh:
  nmid, merchant   properti merchant, bukan orang — sama persis dengan
                   yang memang sudah disimpan tabel bindings
  geohash_7        sel kasar ~152 m, jangkar merchant, bukan posisi
                   pengguna
  verdict, action, risk_score, signals, layers, processing_ms

Apa yang TIDAK PERNAH dicatat, dan mengapa:
  device_anon_id   dipakai menghitung pengamat unik (Keputusan 6);
                   menuliskannya ke log akan membangun jejak yang
                   justru dihindari skemanya
  lat/lng presisi  koordinat mentah bisa merekonstruksi posisi pemindai
  alamat IP        lihat limits.py — tidak pernah keluar dari memori
  payload mentah   memuat identitas merchant lengkap dan tidak
                   dibutuhkan untuk audit putusan

Aturannya satu kalimat: yang dicatat adalah PUTUSAN dan alasannya,
bukan siapa yang memindai.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone

LOGGER_NAME = "qshield.audit"

_logger = None


def get_logger() -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger

    log = logging.getLogger(LOGGER_NAME)
    log.setLevel(os.environ.get("QSHIELD_LOG_LEVEL", "INFO").upper())
    log.propagate = False
    if not log.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(h)
    _logger = log
    return log


def record_verdict(
    verdict,
    nmid,
    lat,
    lng,
    layers,
    processing_ms,
    accuracy_m=None,
    merchant_name=None,
    location_source="live",
) -> dict:
    """Tulis satu baris audit. Mengembalikan dict yang ditulis (untuk test)."""
    from . import binding as bd
    from . import geo

    entri = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "verify",
        "nmid": nmid,
        "merchant": merchant_name,
        # Sengaja sel presisi 7, bukan koordinat: cukup untuk menelusuri
        # kembali jangkar mana yang terlibat, terlalu kasar untuk
        # menunjukkan seseorang berdiri di mana.
        "geohash_7": geo.encode(lat, lng, bd.INDEX_PRECISION),
        "verdict": verdict.status,
        "action": verdict.action,
        "risk_score": verdict.risk_score,
        "signals": verdict.signals,
        "layers": layers,
        "accuracy_m": round(accuracy_m) if accuracy_m is not None else None,
        # Ikut dicatat supaya jejak audit bisa membedakan putusan dari
        # GPS langsung dan dari rekaman — tanpa ini, log demo dan log
        # sungguhan tidak bisa dipisahkan setelah acara.
        "location_source": location_source,
        "processing_ms": processing_ms,
    }
    get_logger().info(json.dumps(entri, ensure_ascii=False))
    return entri


def record_rejected(alasan: str, detail: str = "") -> dict:
    """Catat permintaan yang ditolak sebelum sempat dinilai."""
    entri = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "rejected",
        "reason": alasan,
        "detail": detail[:200],
    }
    get_logger().warning(json.dumps(entri, ensure_ascii=False))
    return entri
