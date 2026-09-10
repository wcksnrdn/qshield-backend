"""
Autentikasi klien.

R9 di THREAT-MODEL.md: tanpa ini, siapa pun bisa mengirim pengamatan ke
API. Rate limiting memperlambat pencemaran basis data, tapi tidak
menghentikan penyerang yang sabar — dan basis data binding adalah aset
A1, inti nilai sistem.

Klien di sini adalah **penyelenggara jasa pembayaran**, bukan orang.
Satu kunci mewakili satu PJP yang memanggil Q-Shield sebelum PIN entry.
Ini penting untuk invarian §8: `client_id` mengidentifikasi lembaga,
bukan pengguna akhir, dan tidak pernah masuk tabel `bindings` maupun
`observations` — hanya ke jejak audit, tempat ia memang dibutuhkan
untuk menjawab "putusan ini diminta siapa".

Kunci disimpan sebagai **hash**, bukan teks asli. Konfigurasi yang bocor
tidak langsung memberi penyerang kunci yang bisa dipakai.

Konfigurasi:

    QSHIELD_API_KEYS="pjp-alpha:<sha256>,pjp-beta:<sha256>"
    QSHIELD_AUTH=off        # matikan eksplisit, untuk demo lokal

Bikin kunci baru:

    python scripts/make_apikey.py pjp-alpha

Kalau `QSHIELD_API_KEYS` kosong dan `QSHIELD_AUTH` tidak disetel `off`,
endpoint verifikasi **menolak melayani**. Gagal tertutup, bukan gagal
terbuka: ketiadaan konfigurasi bukan izin — logika yang sama dengan
invarian §2, di mana ketiadaan bukti bukan kepercayaan.
"""

import hashlib
import hmac
import os
import secrets

API_KEY_HEADER = "X-API-Key"

MATIKAN = ("off", "0", "false", "no")

# Panjang kunci mentah dalam byte sebelum di-hex.
KEY_BYTES = 32


def hash_key(raw: str) -> str:
    """Hash kunci mentah jadi hex sha256."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def new_key() -> str:
    """Kunci acak baru, aman secara kriptografis."""
    return secrets.token_urlsafe(KEY_BYTES)


class ClientRegistry:
    """Daftar PJP yang boleh memanggil API."""

    def __init__(self, spec: str = None, auth_setting: str = None):
        if spec is None:
            spec = os.environ.get("QSHIELD_API_KEYS", "")
        if auth_setting is None:
            auth_setting = os.environ.get("QSHIELD_AUTH", "")

        self.disabled = auth_setting.strip().lower() in MATIKAN
        self._clients = {}

        for bagian in spec.split(","):
            bagian = bagian.strip()
            if not bagian or ":" not in bagian:
                continue
            client_id, digest = bagian.split(":", 1)
            client_id, digest = client_id.strip(), digest.strip().lower()
            if client_id and digest:
                self._clients[client_id] = digest

    @property
    def configured(self) -> bool:
        return bool(self._clients)

    @property
    def client_ids(self) -> list:
        return sorted(self._clients)

    def authenticate(self, presented: str):
        """Kembalikan client_id kalau kuncinya cocok, None kalau tidak.

        Perbandingan memakai hmac.compare_digest supaya lama eksekusinya
        tidak bergantung pada berapa banyak karakter awal yang cocok —
        tanpa itu, penyerang bisa menebak kunci satu karakter per kali
        lewat pengukuran waktu.
        """
        if not presented:
            return None
        digest = hash_key(presented)
        cocok = None
        # Seluruh daftar tetap ditelusuri sampai habis, tidak berhenti di
        # kecocokan pertama, supaya waktunya tidak membocorkan posisi.
        for client_id, tersimpan in self._clients.items():
            if hmac.compare_digest(digest, tersimpan):
                cocok = client_id
        return cocok
