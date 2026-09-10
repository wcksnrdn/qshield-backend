"""
Pembatasan laju permintaan.

Ini pertahanan yang benar untuk probing otomatis — dan alasannya
tercatat: Keputusan 13 membuang sinyal "lonjakan pemindaian" justru
karena volume permintaan adalah urusan kontrol akses, bukan skor
risiko. Berkas ini yang mengambil alih pekerjaan itu.

Catatan privasi. Penghitung dikunci pada hash terpotong dari alamat IP,
disimpan HANYA di memori proses, dan hilang begitu jendelanya lewat.
Tidak pernah masuk basis data, tidak pernah masuk log. Alamat IP mentah
tidak pernah disimpan di mana pun — invarian §8 berlaku untuk seluruh
sistem, bukan cuma untuk tabel.

Batasan yang diketahui: penguncian per-IP itu kasar. Di balik NAT —
persis situasi WiFi acara — semua ponsel terlihat sebagai satu alamat.
Karena itu nilai bawaannya longgar, dan bisa diatur lewat env var
tanpa mengubah kode.
"""

import hashlib
import os
import threading
import time
from collections import defaultdict, deque

# Longgar dengan sengaja. Satu orang memindai QR paling banter beberapa
# kali per menit, tapi di balik NAT satu alamat bisa mewakili seluruh
# ruangan. Menolak permintaan sah di depan juri jauh lebih mahal
# daripada melayani beberapa probe berlebih.
DEFAULT_MAX_REQUESTS = 60
DEFAULT_WINDOW_SECONDS = 60

# Batasi jumlah kunci yang diingat supaya penghitungnya sendiri tidak
# jadi jalur kehabisan memori.
MAX_TRACKED_KEYS = 10_000


# Nilai env "off" / "0" mematikan pembatasan sepenuhnya. Ini bukan
# kemalasan: di WiFi acara yang ber-NAT, seluruh ruangan — termasuk juri —
# terlihat sebagai satu alamat, dan menolak permintaan mereka di tengah
# demo jauh lebih mahal daripada melayani beberapa probe berlebih.
# Dipakai juga oleh test yang memang perlu membanjiri API.
MATIKAN = ("off", "0", "false", "no")


def _env_int(nama: str, bawaan: int) -> int:
    try:
        nilai = int(os.environ.get(nama, bawaan))
        return nilai if nilai > 0 else bawaan
    except (TypeError, ValueError):
        return bawaan


class RateLimiter:
    """Jendela geser sederhana, aman dipakai lintas thread."""

    def __init__(self, max_requests: int = None, window_seconds: int = None):
        setelan = os.environ.get("QSHIELD_RATE_LIMIT", "").strip().lower()
        self.disabled = setelan in MATIKAN
        self.max_requests = max_requests or _env_int(
            "QSHIELD_RATE_LIMIT", DEFAULT_MAX_REQUESTS)
        self.window = window_seconds or _env_int(
            "QSHIELD_RATE_WINDOW", DEFAULT_WINDOW_SECONDS)
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def key_for(client_host: str) -> str:
        """Hash terpotong; alamat aslinya tidak pernah disimpan."""
        if not client_host:
            client_host = "unknown"
        return hashlib.sha256(client_host.encode("utf-8")).hexdigest()[:16]

    def _prune(self, sekarang: float) -> None:
        """Buang kunci yang seluruh jejaknya sudah kedaluwarsa."""
        mati = [k for k, d in self._hits.items()
                if not d or d[-1] <= sekarang - self.window]
        for k in mati:
            del self._hits[k]

    def check(self, key: str, now: float = None):
        """Kembalikan (diizinkan, sisa_kuota, detik_sampai_reset)."""
        if self.disabled:
            return True, self.max_requests, 0.0

        now = now if now is not None else time.monotonic()
        batas_bawah = now - self.window

        with self._lock:
            if len(self._hits) > MAX_TRACKED_KEYS:
                self._prune(now)

            jejak = self._hits[key]
            while jejak and jejak[0] <= batas_bawah:
                jejak.popleft()

            if len(jejak) >= self.max_requests:
                reset = max(0.0, jejak[0] + self.window - now)
                return False, 0, reset

            jejak.append(now)
            sisa = self.max_requests - len(jejak)
            reset = max(0.0, jejak[0] + self.window - now)
            return True, sisa, reset

    def reset(self) -> None:
        """Kosongkan seluruh penghitung. Dipakai test."""
        with self._lock:
            self._hits.clear()
