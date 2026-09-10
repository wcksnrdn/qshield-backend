"""
Suite adversarial — sistem diuji dari sisi penyerang.

Berbeda dari test_binding.py yang menguji "apakah aturannya jalan",
berkas ini menguji "apakah aturannya bisa ditembus". Tiap skenario
ditulis sebagai serangan dengan tujuan yang jelas, lalu diperiksa
apakah sistem menahannya.

Bagian terakhir sengaja berisi serangan yang MEMANG BELUM ditahan.
Untuk itu yang diuji bukan "apakah tertangkap" melainkan "apakah
sistem tetap jujur" — batasan yang diketahui tidak boleh berubah
jadi klaim aman. Itu bentuk kegagalan yang paling berbahaya.

    python tests/test_adversarial.py
"""

import os

# Test ini sengaja membanjiri API, jadi pembatasan laju dimatikan di sini.
# Pengujian rate limiting-nya sendiri ada di tests/test_hardening.py.
os.environ["QSHIELD_RATE_LIMIT"] = "off"


import sys
import tempfile
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from qshield import api, emvco
from qshield import binding as bd
from qshield.store import Store

NOW = datetime.now(timezone.utc)

LAT, LNG = -6.914744, 107.609810
KORBAN = "ID1024365478912"
PENYERANG = "ID1099887766554"
TETANGGA = "ID1077778888999"

_hasil = []


def serangan(nama, ditahan=True):
    """Daftarkan satu skenario. ditahan=False untuk batasan yang diakui."""
    def deco(fn):
        try:
            _hasil.append((nama, ditahan, True, fn() or ""))
        except AssertionError as exc:
            _hasil.append((nama, ditahan, False, str(exc)))
        return fn
    return deco


def fresh_store():
    """Store baru berisi satu warung mapan sebagai korban."""
    s = Store(os.path.join(tempfile.mkdtemp(), "adv.db"))
    s.seed_binding(
        nmid=KORBAN, lat=LAT, lng=LNG, merchant_name="WARUNG BU SRI",
        observer_count=47,
        first_seen=NOW - timedelta(days=180),
        last_seen=NOW - timedelta(hours=6),
    )
    api.store = s
    return s, TestClient(api.app)


def qr(nmid, pan="936000149000000002", extra=None, nama="WARUNG BU SRI",
       statis=True):
    acct = emvco.build_tlv({
        "00": "ID.CO.QRIS.WWW", "01": pan, "02": nmid, "03": "UMI",
    })
    fields = {
        "00": "01", "01": "11" if statis else "12", "26": acct, "52": "5812",
        "53": "360", "58": "ID", "59": nama, "60": "BANDUNG", "61": "40257",
    }
    fields.update(extra or {})
    return emvco.build(fields)


def scan(client, payload, lat=LAT, lng=LNG, device="penyerang-0001", acc=None):
    body = {"payload": payload, "lat": lat, "lng": lng,
            "device_anon_id": device}
    if acc is not None:
        body["accuracy_m"] = acc
    return client.post("/api/v1/verify", json=body).json()


# ==================================================================
# Serangan yang harus ditahan
# ==================================================================

@serangan("Sticker swap di jangkar mapan")
def _a1():
    _, c = fresh_store()
    d = scan(c, qr(PENYERANG))
    assert d["verdict"] == "anomaly", f"swap lolos sebagai {d['verdict']}"
    assert d["action"] == "cooling_off", f"friksi cuma {d['action']}"
    assert "nmid_changed_at_anchor" in d["signals"]
    return f"skor {d['risk_score']} -> {d['action']}"


@serangan("Sticker swap sambil menggeser titik GPS 20-45 m")
def _a2():
    import math
    import random
    random.seed(3)
    _, c = fresh_store()
    lolos = 0
    for _ in range(60):
        jarak = random.uniform(0, 45)
        sudut = random.uniform(0, 2 * math.pi)
        dlat = (jarak * math.cos(sudut)) / 111320
        dlng = (jarak * math.sin(sudut)) / (111320 * math.cos(math.radians(LAT)))
        d = scan(c, qr(PENYERANG), lat=LAT + dlat, lng=LNG + dlng,
                 device="penyerang-0001")
        if d["verdict"] != "anomaly":
            lolos += 1
    assert lolos == 0, f"{lolos}/60 pergeseran berhasil menghindari deteksi"
    return "60 posisi dalam radius 45 m, tidak satu pun lolos"


@serangan("Membangun reputasi lewat pemindaian anomali berulang")
def _a3():
    s, c = fresh_store()
    sebelum = c.get("/api/v1/health").json()
    for i in range(25):
        scan(c, qr(PENYERANG), device=f"penyerang-{i:04d}")
    sesudah = c.get("/api/v1/health").json()

    assert sesudah["observations"] == sebelum["observations"], (
        f"observations naik jadi {sesudah['observations']}"
    )
    assert sesudah["bindings"] == sebelum["bindings"], (
        f"binding baru terbentuk: {sesudah['bindings']}"
    )
    # Dan setelah 25 percobaan, NMID penyerang tetap tidak dikenal.
    d = scan(c, qr(PENYERANG), device="penyerang-9999")
    assert d["verdict"] == "anomaly"
    return f"25 percobaan, observations tetap {sesudah['observations']}"


@serangan("Priming pelan di lokasi kosong lalu klaim verified")
def _a4():
    s = Store(os.path.join(tempfile.mkdtemp(), "prime.db"))
    api.store = s
    c = TestClient(api.app)
    # Lokasi perawan: tidak ada jangkar, jadi tidak ada konflik.
    jauh_lat, jauh_lng = -8.6500, 115.2167
    aksi = []
    for i in range(30):
        d = scan(c, qr(PENYERANG), lat=jauh_lat, lng=jauh_lng,
                 device=f"boneka-{i:04d}")
        aksi.append((d["verdict"], d["action"]))

    assert all(v != "verified" for v, _ in aksi), (
        "binding mencapai verified tanpa menunggu ambang usia"
    )
    assert all(a != "proceed" for _, a in aksi), (
        "status unknown diberi proceed — ketiadaan bukti jadi kepercayaan"
    )
    return f"30 device boneka: tetap {aksi[-1][0]}/{aksi[-1][1]}"


@serangan("Akurasi GPS dipalsukan tinggi untuk melewati Layer 1")
def _a5():
    _, c = fresh_store()
    for acc in (150, 900, 50000):
        d = scan(c, qr(PENYERANG), acc=acc)
        assert d["verdict"] != "verified", f"akurasi {acc} -> verified"
        assert d["action"] != "proceed", f"akurasi {acc} -> proceed"
    return "150/900/50000 m tidak satu pun menghasilkan proceed"


@serangan("Payload cacat disembunyikan di balik akurasi GPS buruk")
def _a6():
    _, c = fresh_store()
    d = scan(c, qr(PENYERANG, extra={"54": "500000.00"}), acc=800)
    assert d["verdict"] == "anomaly", (
        f"kontradiksi struktural ikut hilang saat GPS buruk ({d['verdict']})"
    )
    assert "static_qr_with_amount" in d["signals"]
    return "GPS buruk tidak menutupi cacat bentuk payload"


@serangan("Meracuni jangkar merchant jujur (denial of service)")
def _a7():
    s, c = fresh_store()
    s.seed_binding(
        nmid=TETANGGA, lat=LAT - 0.00007, lng=LNG, merchant_name="TOKO SEBELAH",
        observer_count=30,
        first_seen=NOW - timedelta(days=90), last_seen=NOW - timedelta(hours=2),
    )
    for i in range(15):
        scan(c, qr(PENYERANG), device=f"penyerang-{i:04d}")

    korban = scan(c, qr(KORBAN, pan="936000149000000001"), device="pelanggan-0001")
    sebelah = scan(c, qr(TETANGGA, pan="936000149000000003"),
                   lat=LAT - 0.00007, device="pelanggan-0002")

    assert korban["layers"]["behavior"] == 0, (
        f"merchant jujur kena skor Layer 2 {korban['layers']['behavior']}"
    )
    assert korban["action"] == "proceed", f"korban diberi {korban['action']}"
    assert sebelah["layers"]["behavior"] == 0, (
        f"merchant sebelah kena skor Layer 2 {sebelah['layers']['behavior']}"
    )
    assert sebelah["action"] == "proceed", f"tetangga diberi {sebelah['action']}"
    return "15 serangan, kedua merchant sah tetap proceed dengan L2 = 0"


@serangan("QR dicetak ulang: CRC ditambal agar cocok")
def _a8():
    _, c = fresh_store()
    # Penyerang menyusun ulang payload dan menghitung CRC yang benar,
    # jadi pemeriksaan CRC saja tidak akan menangkapnya.
    p = qr(PENYERANG)
    assert emvco.parse(p).crc_valid, "prasyarat: CRC memang valid"
    d = scan(c, p)
    assert d["verdict"] == "anomaly", "CRC valid membuat swap lolos"
    return "CRC valid tidak menyelamatkan swap — jangkar yang menangkap"


@serangan("Merchant ID dipalsukan agar tidak sesuai format QRIS")
def _a9():
    _, c = fresh_store()
    for buruk in ("ID99", "XX1024365478912", "ID10243654789123456"):
        d = scan(c, qr(buruk), lat=-8.65, lng=115.2167)
        assert d["verdict"] == "anomaly", f"NMID '{buruk}' lolos"
        assert "malformed_nmid" in d["signals"]
    return "tiga bentuk NMID cacat, semua ditolak"


@serangan("Layer 2 dipakai memutihkan lokasi yang mencurigakan")
def _a10():
    _, c = fresh_store()
    bersih = scan(c, qr(PENYERANG))
    # Payload yang sempurna bersih tidak boleh MENURUNKAN skor Layer 1.
    assert bersih["risk_score"] >= bersih["layers"]["location"], (
        "Layer 2 mengurangi skor Layer 1"
    )
    assert bersih["layers"]["behavior"] >= 0
    assert bersih["verdict"] == "anomaly", "Layer 2 mencabut anomaly Layer 1"
    return "payload bersih tidak menurunkan skor maupun mencabut anomaly"


# ==================================================================
# Batasan yang diakui — di sini yang diuji adalah KEJUJURAN sistem
# ==================================================================

@serangan("Koordinat GPS dipalsukan (mock location)", ditahan=False)
def _b1():
    _, c = fresh_store()
    # Penyerang mengaku berada di warung padahal tidak. Server tidak
    # punya cara memverifikasi ini — lihat Batasan 2 di PROCESS-LOG.
    d = scan(c, qr(KORBAN, pan="936000149000000001"), device="pemalsu-0001")
    assert d["verdict"] == "verified", (
        "prasyarat batasan berubah — koordinat palsu kini tertangkap?"
    )
    # Yang penting: batasannya tidak bertambah parah. Koordinat palsu
    # tidak memberi penyerang apa pun untuk NMID YANG BUKAN MILIKNYA.
    d2 = scan(c, qr(PENYERANG), device="pemalsu-0002")
    assert d2["verdict"] == "anomaly", (
        "spoof koordinat memberi keuntungan untuk NMID asing"
    )
    return ("BELUM DITAHAN: butuh device integrity. Tapi spoof tidak "
            "memberi keuntungan untuk NMID asing")


@serangan("Replay QR dinamis yang sudah dipakai", ditahan=False)
def _b2():
    _, c = fresh_store()
    dinamis = qr(KORBAN, pan="936000149000000001",
                 extra={"54": "25000.00"}, statis=False)
    a = scan(c, dinamis, device="pelanggan-0001")
    b = scan(c, dinamis, device="pelanggan-0002")
    assert a["verdict"] == b["verdict"], "prasyarat: tidak ada pelacakan nonce"
    # Sistem tidak mengklaim bisa mendeteksinya, dan tidak boleh
    # memberi sinyal palsu seolah bisa.
    assert "replay" not in " ".join(a["signals"]), "mengklaim deteksi replay"
    return ("BELUM DITAHAN: butuh nonce per transaksi di sisi PJP, "
            "di luar jangkauan lapisan pra-pembayaran")


@serangan("Merchant sah pindah lokasi", ditahan=False)
def _b3():
    _, c = fresh_store()
    d = scan(c, qr(KORBAN, pan="936000149000000001"),
             lat=-6.9000, lng=107.6200, device="pelanggan-0001")
    # Relokasi memicu peringatan sekali — itu memang perilaku yang diakui.
    assert d["verdict"] != "verified", "lokasi baru langsung diklaim verified"
    assert d["action"] != "proceed", "lokasi baru langsung diberi proceed"
    return (f"memicu {d['verdict']}/{d['action']} seperti didokumentasikan — "
            f"perlu jalur konfirmasi merchant")


# ==================================================================
# Laporan
# ==================================================================

print("=" * 72)
print("SUITE ADVERSARIAL")
print("=" * 72)
print()

gagal = 0
print("Serangan yang harus ditahan")
print("-" * 72)
for nama, ditahan, ok, detail in _hasil:
    if not ditahan:
        continue
    print(f"  [{'DITAHAN' if ok else 'JEBOL  '}]  {nama}")
    if detail:
        print(f"             {detail}")
    if not ok:
        gagal += 1

print()
print("Batasan yang diakui — diuji agar sistem tetap jujur")
print("-" * 72)
for nama, ditahan, ok, detail in _hasil:
    if ditahan:
        continue
    print(f"  [{'JUJUR  ' if ok else 'REGRESI'}]  {nama}")
    if detail:
        print(f"             {detail}")
    if not ok:
        gagal += 1

print()
print("-" * 72)
if gagal:
    print(f"{gagal} dari {len(_hasil)} skenario GAGAL.")
    sys.exit(1)
print(f"Seluruh {len(_hasil)} skenario sesuai harapan.")
