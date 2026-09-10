"""Kalibrasi konstanta Layer 2, diuji secara empiris.

Mengikuti pola calibrate_geo.py: setiap angka di behavior.py harus bisa
ditunjuk dasarnya. Yang tidak lolos pemeriksaan di sini tidak boleh
tinggal di kode hanya karena kedengarannya masuk akal.

Tiga hal yang diperiksa:
  1. ambang lonjakan pemindaian — apakah sinyalnya memang memisahkan
     penyerang dari merchant ramai
  2. eskalasi percobaan anomali berulang
  3. laju positif palsu sinyal struktural terhadap payload yang sah
"""

import math
import random

from qshield import behavior as bh
from qshield import binding as bd
from qshield import emvco

random.seed(7)

HARI_DISIMULASI = 400

# Profil lalu lintas merchant sah, transaksi per jam pada jam buka.
# Angka kasar tapi rentangnya sengaja lebar supaya kesimpulannya tidak
# bergantung pada satu tebakan.
PROFIL = [
    ("warung sepi", 3),
    ("warung sedang", 12),
    ("warung ramai", 30),
    ("kaki lima jam makan", 60),
    ("minimarket", 90),
]

JAM_BUKA = 12
AMBANG_DIUJI = [5, 8, 12, 20, 30, 50, 80, 120]


def puncak_jendela(laju_per_jam, jam_buka=JAM_BUKA):
    """Hitungan tertinggi yang pernah dilihat penghitung jendela tetap.

    Meniru semantik store.record(): satu jendela 60 menit, direset
    begitu lewat — bukan sliding window.
    """
    kedatangan = []
    t = 0.0
    total_menit = jam_buka * 60
    while t < total_menit:
        # Proses Poisson: jeda antar-kedatangan terdistribusi eksponensial.
        t += random.expovariate(laju_per_jam / 60.0)
        if t < total_menit:
            kedatangan.append(t)

    puncak = 0
    mulai = None
    hitung = 0
    for waktu in kedatangan:
        if mulai is None or waktu - mulai > bh.SCAN_BURST_WINDOW_MIN:
            mulai, hitung = waktu, 1
        else:
            hitung += 1
        puncak = max(puncak, hitung)
    return puncak


print("=" * 72)
print("1. AMBANG LONJAKAN PEMINDAIAN")
print("=" * 72)
print()
print("a. Berapa sering merchant SAH melewati tiap ambang?")
print("-" * 72)
print(f"  {'profil':<22}{'puncak/jam':>12}", "".join(f"{a:>7}" for a in AMBANG_DIUJI))

fp_maks = {a: 0.0 for a in AMBANG_DIUJI}
for nama, laju in PROFIL:
    puncaks = [puncak_jendela(laju) for _ in range(HARI_DISIMULASI)]
    rerata = sum(puncaks) / len(puncaks)
    baris = []
    for a in AMBANG_DIUJI:
        pct = 100 * sum(1 for p in puncaks if p >= a) / len(puncaks)
        fp_maks[a] = max(fp_maks[a], pct)
        baris.append(f"{pct:6.1f}%")
    print(f"  {nama:<22}{rerata:>12.1f}", "".join(baris))

print()
print("b. Apakah ambang itu menangkap serangan yang sebenarnya?")
print("-" * 72)
print(f"  Membangun reputasi palsu butuh MIN_OBSERVERS={bd.MIN_OBSERVERS} device")
print(f"  berbeda DAN rentang MIN_AGE_HOURS={bd.MIN_AGE_HOURS} jam.")
print("  Artinya serangannya pelan, bukan meledak:")
print()

deteksi = {a: 0 for a in AMBANG_DIUJI}
PERCOBAAN = 2000
for _ in range(PERCOBAAN):
    # Penyerang menyebar device seminimal mungkin melewati ambang usia.
    rentang_jam = bd.MIN_AGE_HOURS + random.uniform(0.5, 48)
    waktu = sorted(random.uniform(0, rentang_jam * 60)
                   for _ in range(bd.MIN_OBSERVERS))
    puncak, mulai, hitung = 0, None, 0
    for w in waktu:
        if mulai is None or w - mulai > bh.SCAN_BURST_WINDOW_MIN:
            mulai, hitung = w, 1
        else:
            hitung += 1
        puncak = max(puncak, hitung)
    for a in AMBANG_DIUJI:
        if puncak >= a:
            deteksi[a] += 1

print(f"  {'ambang':>8}{'positif palsu (merchant sah)':>32}{'deteksi serangan':>20}")
for a in AMBANG_DIUJI:
    print(f"  {a:>8}{fp_maks[a]:>31.1f}%{100 * deteksi[a] / PERCOBAAN:>19.1f}%")

print()
print("  Kesimpulan")
print("  " + "-" * 68)
print(f"  Puncak serangan maksimum {bd.MIN_OBSERVERS} pemindaian — di bawah SETIAP")
print("  ambang yang masih bisa diterima merchant ramai. Sinyal lonjakan")
print("  menangkap 0% serangan sambil tetap menghukum merchant sibuk.")
print("  Volume pemindaian TIDAK memisahkan penyerang dari warung laris;")
print("  pertahanan yang benar untuk probing otomatis adalah rate limiting.")

print()
print("=" * 72)
print("2. ESKALASI PERCOBAAN ANOMALI BERULANG")
print("=" * 72)
print()
print("  Naik hanya bila yang memindai BUKAN merchant mapan di jangkar ini,")
print("  supaya penyerang tidak bisa memakainya menyerang merchant jujur.")
print()
print(f"  {'percobaan':>10}{'bobot L2':>10}{'L1 cold start':>16}{'gabungan':>10}  aksi")
for n in (1, 2, 3, 5, 10):
    bobot = min(bh.W_ANOMALY_CAP, bh.W_ANOMALY_BASE * n)
    # Skenario terburuk yang wajar: jangkar tak dikenal (L1 = 35).
    gabungan = min(100, 35 + bobot)
    print(f"  {n:>10}{bobot:>10}{35:>16}{gabungan:>10}  {bd._action_for(gabungan)}")
print()
print(f"  Batas {bh.W_ANOMALY_CAP} dipilih supaya sinyal ini sendirian tidak pernah")
print("  cukup menyeret pemindaian bersih sampai cooling_off — ia mempertajam")
print("  bukti lain, bukan menggantikannya.")

print()
print("=" * 72)
print("3. POSITIF PALSU SINYAL STRUKTURAL")
print("=" * 72)
print()

KOTA = ["BANDUNG", "JAKARTA PUSAT", "SURABAYA", "KOTA BOGOR", "DENPASAR"]
MCC = ["5812", "5411", "5814", "5999", "7230"]
KRITERIA = ["UMI", "UKE", "UME", "UBE"]
PJP = ["93600014", "93600911", "93600520", "93600768"]

palsu = 0
CONTOH = 20000
for _ in range(CONTOH):
    nmid = "ID" + "".join(random.choice("0123456789") for _ in range(13))
    pan = random.choice(PJP) + "".join(random.choice("0123456789") for _ in range(10))
    fields = {
        "00": "01",
        "01": "11",
        "26": emvco.build_tlv({
            "00": "ID.CO.QRIS.WWW", "01": pan, "02": nmid,
            "03": random.choice(KRITERIA),
        }),
        "52": random.choice(MCC),
        "53": "360",
        "58": "ID",
        "59": random.choice(["WARUNG BU SRI", "TOKO SEJAHTERA", "KOPI KENANGAN"]),
        "60": random.choice(KOTA),
    }
    # Field opsional memang boleh ada atau tidak.
    if random.random() < 0.7:
        fields["61"] = str(random.randint(10000, 99999))
    if random.random() < 0.3:
        fields["62"] = emvco.build_tlv({"01": str(random.randint(1, 999999))})

    hasil = bh.evaluate(emvco.parse(emvco.build(fields)))
    if hasil.score or hasil.hard_violation:
        palsu += 1

print(f"  {CONTOH} payload sah dan bervariasi -> {palsu} positif palsu "
      f"({100 * palsu / CONTOH:.3f}%)")
print()
print("  Nol positif palsu memang diharapkan: sinyal struktural menguji")
print("  KONTRADIKSI terhadap spec, bukan kemiripan statistik. Yang tidak")
print("  bisa dijamin skrip ini adalah laju positif palsu sinyal SIDIK JARI")
print("  (urutan tag, huruf CRC) terhadap generator acquirer sungguhan —")
print("  itu butuh korpus payload QRIS asli yang belum kami punya, dan")
print("  karena itu bobotnya kecil serta dibatasi bersama.")
