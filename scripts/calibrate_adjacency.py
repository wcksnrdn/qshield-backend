"""Kalibrasi celah R10: berapa mahal menutupnya?

THREAT-MODEL.md R10 mencatat bahwa aturan `adjacent_merchant` memberi
pengecualian koeksistensi tanpa memeriksa apa pun selain "keduanya
mapan". Penyerang yang menang balapan cold start lolos lewat situ.

Skrip ini mengukur harga dari dua usulan penutupnya, supaya keputusannya
diambil dari angka dan bukan dari selera:

  Opsi A  koeksistensi menghasilkan `unknown`, bukan `verified`
          -> biaya: pemindaian sah yang turun dari proceed ke warn

  Opsi C  pengecualian koeksistensi menuntut basis pengamat yang
          SEBANDING dengan tetangganya, bukan sekadar mapan
          -> biaya: pasangan merchant sah yang ikut tertolak
          -> untung: jumlah device yang harus dikeluarkan penyerang

Tata letak merchant di bawah adalah model kasar, bukan survei. Rentangnya
sengaja lebar supaya kesimpulannya tidak bergantung pada satu tebakan.
"""

import math
import random
from datetime import datetime, timedelta, timezone

from qshield import binding as bd

random.seed(17)

NOW = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
PUSAT_LAT, PUSAT_LNG = -6.914744, 107.609810

# Galat GPS satu pembacaan. Koordinat jangkar ditetapkan dari pengamatan
# PERTAMA, jadi galat ini melekat permanen pada jangkar itu.
GPS_SIGMA_M = 8.0

TRIALS = 400

# (nama, jumlah merchant, jarak antar-merchant dalam meter)
TATA_LETAK = [
    ("warung soliter", 1, 0),
    ("ruko 4 pintu", 4, 8),
    ("pertokoan jalan", 10, 20),
    ("pujasera kecil", 8, 4),
    ("food court mall", 20, 3),
    ("pasar tradisional", 40, 2.5),
]


def geser(lat, lng, utara_m, timur_m):
    return (lat + utara_m / 111320,
            lng + timur_m / (111320 * math.cos(math.radians(lat))))


def derau():
    """Satu pembacaan GPS: galat radial, arah acak."""
    r = abs(random.gauss(0, GPS_SIGMA_M))
    a = random.uniform(0, 2 * math.pi)
    return r * math.cos(a), r * math.sin(a)


def bangun_lokasi(jumlah, jarak):
    """Sebar merchant dalam grid persegi serapat jarak yang diminta."""
    sisi = max(1, int(math.ceil(math.sqrt(jumlah))))
    titik = []
    for i in range(jumlah):
        baris, kolom = divmod(i, sisi)
        titik.append(geser(PUSAT_LAT, PUSAT_LNG, baris * jarak, kolom * jarak))
    return titik


def merchant_binding(nmid, lokasi, pengamat, umur_jam=2000):
    """Binding dengan koordinat jangkar yang sudah kena galat GPS."""
    dn, de = derau()
    lat, lng = geser(lokasi[0], lokasi[1], dn, de)
    return bd.Binding(
        nmid=nmid, lat=lat, lng=lng, merchant_name=nmid,
        observer_count=pengamat,
        first_seen=NOW - timedelta(hours=umur_jam), last_seen=NOW,
    )


def pengamat_realistis():
    """Sebaran jumlah pengamat merchant sah.

    Lognormal: kebanyakan merchant sedang, sedikit yang sangat ramai.
    Dipotong di bawah pada MIN_OBSERVERS karena yang di bawah itu
    belum mapan dan tidak masuk kasus koeksistensi sama sekali.
    """
    return max(bd.MIN_OBSERVERS, int(random.lognormvariate(3.0, 0.9)))


# ==================================================================
print("=" * 74)
print("1. BIAYA OPSI A — pemindaian sah yang turun dari proceed ke warn")
print("=" * 74)
print()
print(f"  radius jangkar {bd.ANCHOR_RADIUS_M} m, galat GPS sigma {GPS_SIGMA_M:.0f} m")
print()
print(f"  {'tata letak':<22}{'merchant':>10}{'jarak':>8}{'kena adjacent':>16}")
print("  " + "-" * 70)

biaya_a = {}
for nama, jumlah, jarak in TATA_LETAK:
    kena = total = 0
    for _ in range(TRIALS):
        lokasi = bangun_lokasi(jumlah, jarak)
        bindings = [merchant_binding(f"ID{i:013d}", lokasi[i], pengamat_realistis())
                    for i in range(jumlah)]
        # Satu pelanggan memindai satu merchant yang dipilih acak.
        idx = random.randrange(jumlah)
        dn, de = derau()
        slat, slng = geser(lokasi[idx][0], lokasi[idx][1], dn, de)

        v = bd.evaluate(bindings[idx].nmid, slat, slng, bindings, [], now=NOW)
        total += 1
        if "adjacent_merchant" in v.signals:
            kena += 1

    pct = 100 * kena / total
    biaya_a[nama] = pct
    print(f"  {nama:<22}{jumlah:>10}{jarak:>7.1f}m{pct:>15.1f}%")

print()
print("  Artinya: di tata letak dengan angka tinggi, opsi A membuat")
print("  hampir SETIAP pemindaian sah berakhir di tier `warn`.")

# ==================================================================
print()
print("=" * 74)
print("2. APAKAH JARAK ANTAR-JANGKAR BISA MEMISAHKAN? (dasar opsi B)")
print("=" * 74)
print()
print("  Dua sebaran dibandingkan:")
print("    sah    dua merchant benar-benar bersebelahan, jarak nyata D")
print("    swap   penyerang di TITIK YANG SAMA, jarak nyata 0 m")
print("  Keduanya sama-sama kena galat GPS pada jangkarnya.")
print()
print(f"  {'jarak nyata':>12}{'jangkar sah (p10-p90)':>26}{'jangkar swap':>18}{'tumpang tindih':>16}")
print("  " + "-" * 70)

def jarak_jangkar(jarak_nyata, n=4000):
    keluar = []
    for _ in range(n):
        a = merchant_binding("A", (PUSAT_LAT, PUSAT_LNG), 10)
        lokasi_b = geser(PUSAT_LAT, PUSAT_LNG, jarak_nyata, 0)
        b = merchant_binding("B", lokasi_b, 10)
        keluar.append(a.distance_m(b.lat, b.lng))
    return sorted(keluar)

swap = jarak_jangkar(0.0)
for d in (2.5, 4, 8, 15, 25):
    sah = jarak_jangkar(d)
    p10, p90 = sah[len(sah) // 10], sah[9 * len(sah) // 10]
    s10, s90 = swap[len(swap) // 10], swap[9 * len(swap) // 10]
    # Berapa persen pasangan swap yang jatuh di dalam rentang p10-p90 sah?
    tumpang = 100 * sum(1 for x in swap if p10 <= x <= p90) / len(swap)
    print(f"  {d:>11.1f}m{p10:>13.1f}-{p90:<11.1f}{s10:>7.1f}-{s90:<9.1f}{tumpang:>15.1f}%")

print()
print("  Kesimpulan: pada jarak yang justru paling penting (2,5-8 m, yaitu")
print("  pujasera dan pasar), sebaran swap hampir seluruhnya tumpang tindih")
print("  dengan sebaran merchant sah. Jarak antar-jangkar TIDAK memisahkan")
print("  keduanya — ini batasan R3, bukan sesuatu yang bisa disetel.")
print("  Opsi B gugur.")

# ==================================================================
print()
print("=" * 74)
print("3. OPSI C — pengecualian koeksistensi menuntut basis yang sebanding")
print("=" * 74)
print()
print("  Gagasannya: merchant yang benar-benar bersebelahan menghisap lalu")
print("  lintas kaki yang sama, jadi jumlah pengamatnya sepadan. Penyerang")
print("  yang memupuk 3 device di sebelah merchant 47 pengamat tidak.")
print()
print("  Aturan uji: pengecualian berlaku hanya bila")
print("      pengamat_yang_dipindai >= rasio x pengamat_tetangga_terkuat")
print()
print(f"  {'rasio':>8}{'pasangan sah tertolak':>26}{'device yang harus':>20}")
print(f"  {'':>8}{'(positif palsu baru)':>26}{'dikeluarkan penyerang':>20}")
print("  " + "-" * 70)

PASANGAN = 6000
for rasio in (0.0, 0.05, 0.10, 0.15, 0.25, 0.40, 0.60):
    tertolak = 0
    for _ in range(PASANGAN):
        a, b = pengamat_realistis(), pengamat_realistis()
        # Yang dipindai adalah salah satu dari keduanya, acak.
        dipindai, tetangga = (a, b) if random.random() < 0.5 else (b, a)
        if dipindai < rasio * tetangga:
            tertolak += 1
    pct = 100 * tertolak / PASANGAN

    # Biaya penyerang: melawan korban dengan 47 pengamat (angka pitch).
    butuh = max(bd.MIN_OBSERVERS, math.ceil(rasio * 47))
    print(f"  {rasio:>8.2f}{pct:>25.1f}%{butuh:>16} device")

print()
print("  Catatan jujur: opsi C MENAIKKAN BIAYA penyerang, tidak menutup")
print("  celahnya. Penyerang yang mau mengeluarkan lebih banyak device")
print("  tetap lolos. Yang berubah adalah serangan 3-device yang murah")
print("  jadi tidak lagi cukup.")

# ==================================================================
print()
print("=" * 74)
print("RINGKASAN")
print("=" * 74)
print()
padat = max(biaya_a.values())
jarang = biaya_a["warung soliter"]
print(f"  Opsi A  biaya 0% di warung soliter, tapi sampai {padat:.0f}% di")
print("          tata letak padat. Setiap pemindaian di food court dan")
print("          pasar berakhir `warn` — merusak aset A4 (kredibilitas).")
print()
print("  Opsi B  gugur. Galat GPS membuat sebaran jarak jangkar swap dan")
print("          merchant sah tumpang tindih hampir sempurna di 2,5-8 m.")
print()
print("  Opsi C  menaikkan biaya penyerang dari 3 device ke belasan tanpa")
print("          menyentuh tata letak padat sama sekali, karena aturannya")
print("          soal perbandingan basis pengamat, bukan soal jarak.")
