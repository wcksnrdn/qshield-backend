"""
Peragaan: kenapa berbagi data antar-PJP itu inti proposisi nilainya.

Dijalankan sebagai naskah bernarasi, bukan sebagai test. Tujuannya satu:
membuat sebab-akibat TERLIHAT. Di atas dua ponsel, juri hanya melihat
dua layar; mereka tidak bisa melihat bahwa perlindungan di ponsel kedua
datang dari pemindaian di ponsel pertama.

Dua dunia dijalankan berdampingan dengan kejadian yang sama persis:

  TERPISAH  tiap PJP punya basis datanya sendiri (keadaan hari ini)
  BERBAGI   satu lapisan binding dipakai bersama (Q-Shield)

    python scripts/demo_lintas_pjp.py
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QSHIELD_RATE_LIMIT", "off")
os.environ.setdefault("QSHIELD_AUTH", "off")

from fastapi.testclient import TestClient

from qshield import api, emvco
from qshield.store import Store

NOW = datetime.now(timezone.utc)
LAT, LNG = -6.914744, 107.609810

WARUNG = "ID1024365478912"
PENIPU = "ID1099887766554"

ALPHA = "Dompet Alpha"
BETA = "Bayar Beta"


def qr(nmid, pan):
    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": pan, "02": nmid, "03": "UMI"})
    return emvco.build({
        "00": "01", "01": "11", "26": acct, "52": "5812", "53": "360",
        "58": "ID", "59": "WARUNG BU SRI", "60": "BANDUNG", "61": "40257"})


QR_ASLI = qr(WARUNG, "936000149000000001")
QR_PALSU = qr(PENIPU, "936000149000000002")


def basis_baru(nama, pengamat):
    """Basis data dengan riwayat sebanyak yang PJP itu memang punya.

    Kuncinya di sini ADOPSI YANG TIMPANG, dan itulah keadaan sebenarnya
    di lapangan: pelanggan Warung Bu Sri kebanyakan memakai satu
    aplikasi. Menyeed kedua PJP dengan 47 pengamatan yang sama berarti
    mengandaikan keduanya mengumpulkan data identik secara terpisah —
    dan kalau itu benar, berbagi data memang tidak ada gunanya.
    """
    s = Store(os.path.join(tempfile.mkdtemp(), f"{nama}.db"))
    if pengamat:
        s.seed_binding(
            nmid=WARUNG, lat=LAT, lng=LNG, merchant_name="WARUNG BU SRI",
            observer_count=pengamat, first_seen=NOW - timedelta(days=180),
            last_seen=NOW - timedelta(hours=6))
    return s


def pindai(store, payload, device):
    api.store = store
    return TestClient(api.app).post("/api/v1/verify", json={
        "payload": payload, "lat": LAT, "lng": LNG,
        "device_anon_id": device, "accuracy_m": 9.0}).json()


def baris(pjp, siapa, d):
    tanda = {"proceed": "LANJUT", "warn": "periksa", "step_up": "tahan",
             "cooling_off": "DIHENTIKAN"}[d["action"]]
    print(f"    {pjp:<14} {siapa:<22} {tanda:<11} {d['verdict']}")
    return d


def serangan(store_alpha, store_beta, judul):
    print()
    print("  " + judul)
    print("  " + "-" * 66)

    # Hari 1 — pengguna PJP Alpha yang lebih dulu kena stiker palsu.
    a = pindai(store_alpha, QR_PALSU, "alpha-korban-01")
    baris(ALPHA, "korban pertama", a)

    # Hari 2 — pengguna PJP Beta datang ke warung yang sama.
    b = pindai(store_beta, QR_PALSU, "beta-korban-01")
    baris(BETA, "korban berikutnya", b)
    return a, b


print("=" * 72)
print("BERBAGI DATA ANTAR-PJP — kenapa itu bukan fitur tambahan")
print("=" * 72)
print()
print("  Warung Bu Sri sudah lama berjualan. Pelanggannya kebanyakan")
print(f"  memakai {ALPHA} — 47 pengamatan terkumpul di sana.")
print(f"  {BETA} belum pernah melihat warung ini sama sekali.")
print()
print("  Adopsi yang timpang seperti ini adalah keadaan normal, bukan")
print("  kasus khusus. Tidak ada satu penyelenggara pun yang melihat")
print("  semua merchant.")
print()
print("  Lalu penipu menempel stiker palsu, dan pengguna kedua aplikasi")
print("  memindainya.")

# --- Dunia 1: tiap PJP punya basis datanya sendiri -----------------
alpha_sendiri = basis_baru("alpha", 47)
beta_sendiri = basis_baru("beta", 0)       # belum pernah lihat warung ini
a1, b1 = serangan(
    alpha_sendiri, beta_sendiri,
    "DUNIA A — tiap PJP menyimpan datanya sendiri (keadaan hari ini)")

# --- Dunia 2: satu lapisan binding dipakai bersama ------------------
bersama = basis_baru("bersama", 47)
a2, b2 = serangan(
    bersama, bersama,
    "DUNIA B — satu lapisan binding dipakai bersama (Q-Shield)")

print()
print("=" * 72)
print("YANG BERBEDA")
print("=" * 72)
print()

anchor = bersama.conn.execute(
    "SELECT nmid, observer_count, anomaly_attempts FROM bindings "
    "WHERE nmid = ?", (WARUNG,)).fetchone()

print(f"  Pengguna {ALPHA} terlindungi di kedua dunia — basis datanya")
print(f"  sendiri sudah cukup. Yang menentukan adalah pengguna {BETA}:")
print()
print(f"      DUNIA A   {b1['verdict']:<9} / {b1['action']:<12} skor {b1['risk_score']:>3}")
print(f"      DUNIA B   {b2['verdict']:<9} / {b2['action']:<12} skor {b2['risk_score']:>3}")
print()
if b1["action"] != "cooling_off" and b2["action"] == "cooling_off":
    print(f"  Di dunia A, {BETA} TIDAK PUNYA DASAR untuk menghentikannya.")
    print(f"  Jangkar warung tidak pernah terbentuk di basis datanya, jadi")
    print(f"  stiker palsu itu tampak seperti merchant baru biasa — dan")
    print(f"  pengguna diteruskan ke layar PIN.")
    print()
    print(f"  Di dunia B, 47 pengamatan yang dikumpulkan pengguna {ALPHA}")
    print(f"  melindungi pengguna {BETA} yang belum pernah ke sana.")
    print(f"  Dua perusahaan yang bersaing, satu korban yang tidak jadi.")
print()
print(f"  Jangkar warung juga mencatat serangannya:")
print(f"      anomaly_attempts = {anchor['anomaly_attempts']}")
print(f"      observer_count   = {anchor['observer_count']}  (tidak naik — "
      f"anomali tidak membangun reputasi)")

print()
print("=" * 72)
print("DAN INI YANG MEMBUATNYA MUNGKIN")
print("=" * 72)
print()
kolom = [c["name"] for c in bersama.conn.execute("PRAGMA table_info(observations)")]
print(f"  Tabel yang dibagikan tidak memuat identitas siapa pun:")
print(f"      observations({', '.join(kolom)})")
print()
print("  Tidak ada user_id. Tidak ada koordinat. device_ref adalah hash")
print("  yang dilingkupi per-binding, jadi barisnya tidak bisa dirangkai")
print("  antar-lokasi menjadi jejak perjalanan.")
print()
print("  Karena tidak ada data pribadi yang berpindah, berbagi ini tidak")
print("  menyentuh kerahasiaan bank maupun UU PDP — dan itulah alasan")
print("  teknis kenapa PJP yang bersaing tetap bisa duduk di lapisan yang")
print("  sama.")
print()
print("  Buktinya bisa dijalankan, bukan dipercaya:")
print("      python tests/test_invariants.py     (invarian #8)")

bersama.close()
alpha_sendiri.close()
beta_sendiri.close()
