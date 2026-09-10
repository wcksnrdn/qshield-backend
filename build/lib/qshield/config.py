"""
Konfigurasi terpusat dan pemeriksaan keamanannya.

Setiap modul tetap membaca env var-nya sendiri — mereka harus bisa
dipakai berdiri sendiri di test. Yang dikerjakan berkas ini berbeda:
menyediakan SATU tempat untuk melihat konfigurasi yang sedang berlaku,
dan menilai apakah kombinasinya aman.

Alasannya praktis. Setelan Q-Shield tersebar di lima modul, dan
sebagian di antaranya bisa dimatikan secara sengaja untuk demo
(`QSHIELD_AUTH=off`, `QSHIELD_RATE_LIMIT=off`). Sakelar yang dipasang
untuk gladi bersih lalu lupa dicabut adalah cara paling umum sebuah
sistem berangkat ke produksi dalam keadaan terbuka.

Nilai rahasia tidak pernah dikembalikan apa adanya oleh berkas ini —
hanya panjangnya dan sidik jari pendeknya, cukup untuk memastikan dua
mesin memakai nilai yang sama tanpa menuliskan nilainya ke mana pun.
"""

import hashlib
import os

# Setelan yang isinya rahasia. Tidak pernah dicetak apa adanya.
RAHASIA = ("QSHIELD_API_KEYS", "QSHIELD_DEVICE_SALT")

SETELAN = (
    ("QSHIELD_AUTH", "", "kosong = autentikasi aktif; 'off' mematikannya"),
    ("QSHIELD_API_KEYS", "", "daftar client_id:sha256"),
    ("QSHIELD_RATE_LIMIT", "60", "permintaan per jendela; 'off' mematikan"),
    ("QSHIELD_RATE_WINDOW", "60", "panjang jendela, detik"),
    ("QSHIELD_ALLOWED_ORIGINS",
     "http://localhost:3000,http://127.0.0.1:3000", "origin CORS"),
    ("QSHIELD_DEVICE_SALT", "", "garam device_ref; kosong = dibangkitkan"),
    ("QSHIELD_LOG_LEVEL", "INFO", "level audit log"),
    ("QSHIELD_DB", "qshield.db", "lokasi basis data"),
)


def _sidik(nilai: str) -> str:
    """Sidik jari pendek: cukup untuk membandingkan, bukan memulihkan."""
    return hashlib.sha256(nilai.encode("utf-8")).hexdigest()[:8]


def effective() -> dict:
    """Konfigurasi yang sedang berlaku, dengan rahasia disamarkan."""
    keluar = {}
    for nama, bawaan, _ in SETELAN:
        mentah = os.environ.get(nama, "")
        if not mentah:
            keluar[nama] = {"nilai": bawaan, "sumber": "bawaan"}
            continue
        if nama in RAHASIA:
            keluar[nama] = {
                "nilai": f"<{len(mentah)} karakter, sidik {_sidik(mentah)}>",
                "sumber": "env",
            }
        else:
            keluar[nama] = {"nilai": mentah, "sumber": "env"}
    return keluar


def warnings() -> list:
    """Kombinasi setelan yang berbahaya kalau dibawa ke produksi.

    Mengembalikan daftar (tingkat, pesan). Tingkat 'BAHAYA' berarti
    sistem sedang berjalan tanpa satu lapis pertahanan yang seharusnya
    ada; 'catatan' berarti layak diperiksa tapi bukan lubang.
    """
    keluar = []

    auth_mati = os.environ.get("QSHIELD_AUTH", "").strip().lower() in (
        "off", "0", "false", "no")
    kunci = os.environ.get("QSHIELD_API_KEYS", "").strip()

    if auth_mati:
        keluar.append(("BAHAYA", (
            "QSHIELD_AUTH=off — endpoint verifikasi melayani siapa pun. "
            "Hanya untuk demo lokal; jangan pernah begini di produksi.")))
    elif not kunci:
        keluar.append(("catatan", (
            "QSHIELD_API_KEYS kosong — endpoint verifikasi akan menjawab 503. "
            "Ini gagal tertutup dan memang disengaja, tapi berarti belum ada "
            "klien yang bisa memakainya.")))

    laju = os.environ.get("QSHIELD_RATE_LIMIT", "").strip().lower()
    if laju in ("off", "0", "false", "no"):
        keluar.append(("BAHAYA", (
            "QSHIELD_RATE_LIMIT=off — tidak ada pembatasan laju sama sekali.")))

    origins = os.environ.get("QSHIELD_ALLOWED_ORIGINS", "")
    if "*" in origins:
        keluar.append(("BAHAYA", (
            "QSHIELD_ALLOWED_ORIGINS memuat '*' — CORS terbuka untuk "
            "situs mana pun.")))

    if not os.environ.get("QSHIELD_DEVICE_SALT", "").strip():
        keluar.append(("catatan", (
            "QSHIELD_DEVICE_SALT tidak disetel — garam dibangkitkan sekali "
            "lalu disimpan di basis data. Aman untuk satu mesin, tapi dua "
            "instans yang berbagi basis data harus memakai garam yang sama, "
            "dan garam yang hilang membuat pengamat lama terhitung ulang.")))

    return keluar


def report() -> str:
    """Ringkasan yang bisa dibaca manusia. Tidak memuat nilai rahasia."""
    baris = ["Konfigurasi yang berlaku", "-" * 62]
    for nama, _, guna in SETELAN:
        info = effective()[nama]
        tanda = " " if info["sumber"] == "env" else "."
        baris.append(f" {tanda} {nama:<26} {info['nilai']}")
        baris.append(f"     {guna}")
    baris.append("")
    baris.append("  (tanda '.' = memakai nilai bawaan)")

    peringatan = warnings()
    if peringatan:
        baris.append("")
        baris.append("Peringatan")
        baris.append("-" * 62)
        for tingkat, pesan in peringatan:
            baris.append(f"  [{tingkat}] {pesan}")
    return "\n".join(baris)
