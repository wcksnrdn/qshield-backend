"""Kalibrasi penghalusan jangkar: seberapa banyak untungnya, dan
seberapa jauh penyerang bisa menyeretnya.

Koordinat jangkar saat ini ditetapkan dari pengamatan PERTAMA dan tidak
pernah diperbarui. Galat satu pembacaan GPS (sigma ~8 m) melekat
permanen, dan puluhan pengamatan berikutnya tidak dipakai sama sekali.

Rata-rata berjalan memperbaikinya — galat rata-rata turun sebagai
sigma/akar(n). Tapi ia juga menciptakan serangan baru: pemindaian yang
menarik titik tengah bisa dipakai MENYERET jangkar menjauh dari merchant
sungguhan, sedikit demi sedikit.

Skrip ini mengukur keduanya, lalu memilih batas geser dari angkanya.
"""

import math
import random

from qshield import binding as bd
from qshield import geo

random.seed(23)

SIGMA_M = 8.0          # galat satu pembacaan GPS
BENAR = (-6.914744, 107.609810)
PERCOBAAN = 400

BATAS_DIUJI = [10, 15, 20, 25, 35, 50, None]


def geser(lat, lng, utara, timur):
    return (lat + utara / 111320,
            lng + timur / (111320 * math.cos(math.radians(lat))))


def derau(lat, lng, sigma=SIGMA_M):
    r = abs(random.gauss(0, sigma))
    a = random.uniform(0, 2 * math.pi)
    return geser(lat, lng, r * math.cos(a), r * math.sin(a))


def pusatkan(awal, titik, batas):
    """Rata-rata berjalan dengan batas geser dari jangkar mula-mula.

    CATATAN MODEL. Versi pertama skrip ini mengandaikan setiap pemindaian
    menyuap satu binding yang sama, dan itu keliru: record() mencocokkan
    binding lewat sel geohash-7 (~152 m), jadi pemindaian yang jatuh di
    sel lain membuat binding BARU alih-alih menggeser yang ada. Serangan
    seret karena itu hanya mungkin dari dalam sel yang sama.

    Model di bawah tetap dipertahankan sebagai batas ATAS — ia
    mengandaikan penyerang selalu berhasil mengenai sel yang benar,
    sehingga angkanya lebih pesimistis daripada kenyataan. Batas yang
    dipilih dari sini aman untuk kasus yang lebih longgar.

    Syarat kedua yang tidak dimodelkan di sini dan menaikkan ongkos
    serangan jauh lebih banyak: jangkar hanya dihaluskan saat ada
    PENGAMAT BARU. Menyeret sejauh N langkah menuntut N pengenal
    perangkat berbeda, bukan N pemindaian.
    """
    lat, lng = awal
    n = 1
    for plat, plng in titik:
        # Hanya pemindaian di dalam radius jangkar yang ikut menggeser.
        if geo.haversine_m(lat, lng, plat, plng) > bd.ANCHOR_RADIUS_M:
            continue
        n += 1
        baru_lat = lat + (plat - lat) / n
        baru_lng = lng + (plng - lng) / n
        if batas is not None:
            if geo.haversine_m(awal[0], awal[1], baru_lat, baru_lng) > batas:
                continue
        lat, lng = baru_lat, baru_lng
    return lat, lng


print("=" * 74)
print("1. SEBERAPA BANYAK UNTUNGNYA")
print("=" * 74)
print()
print(f"  galat satu pembacaan GPS: sigma {SIGMA_M:.0f} m")
print()
print(f"  {'pengamatan':>12}{'jangkar beku':>16}{'rata-rata berjalan':>22}{'membaik':>10}")
print("  " + "-" * 68)

for n in (3, 5, 10, 20, 47, 100):
    beku, halus = [], []
    for _ in range(PERCOBAAN):
        titik = [derau(*BENAR) for _ in range(n)]
        awal = titik[0]
        beku.append(geo.haversine_m(awal[0], awal[1], *BENAR))
        p = pusatkan(awal, titik[1:], None)
        halus.append(geo.haversine_m(p[0], p[1], *BENAR))
    b = sum(beku) / len(beku)
    h = sum(halus) / len(halus)
    print(f"  {n:>12}{b:>14.1f} m{h:>20.1f} m{b / h:>9.1f}x")

print()
print("=" * 74)
print("2. SEBERAPA JAUH PENYERANG BISA MENYERETNYA")
print("=" * 74)
print()
print("  Penyerang memindai berulang kali dari tepi radius jangkar,")
print("  menarik titik tengah ke arahnya. Merchant sah 47 pengamatan.")
print()
print(f"  {'batas geser':>13}{'geser oleh 20 serangan':>26}{'geser oleh 200':>18}")
print("  " + "-" * 68)

for batas in BATAS_DIUJI:
    hasil = {}
    for jumlah_serangan in (20, 200):
        geseran = []
        for _ in range(60):
            jujur = [derau(*BENAR) for _ in range(47)]
            awal = jujur[0]
            # Penyerang menarik ke satu arah tetap, dari tepi radius.
            arah = random.uniform(0, 2 * math.pi)
            tarik = geser(*BENAR, (bd.ANCHOR_RADIUS_M - 2) * math.cos(arah),
                          (bd.ANCHOR_RADIUS_M - 2) * math.sin(arah))
            titik = jujur[1:] + [tarik] * jumlah_serangan
            p = pusatkan(awal, titik, batas)
            geseran.append(geo.haversine_m(p[0], p[1], *BENAR))
        hasil[jumlah_serangan] = sum(geseran) / len(geseran)
    label = "tanpa batas" if batas is None else f"{batas} m"
    print(f"  {label:>13}{hasil[20]:>24.1f} m{hasil[200]:>16.1f} m")

print()
print("=" * 74)
print("KESIMPULAN")
print("=" * 74)
print()
print("  Tanpa batas, jangkar bisa diseret sampai ke tepi radius — dan")
print("  begitu ia bergeser, radius barunya menjangkau lebih jauh lagi.")
print("  Penyerang berjalan menuntun jangkarnya keluar dari warung.")
print()
print("  Batas geser menghentikannya, tapi tidak boleh terlalu ketat:")
print(f"  titik benar sendiri bisa berjarak ~{2 * SIGMA_M:.0f} m dari pembacaan")
print("  pertama, jadi batas di bawah itu justru mengunci jangkar pada")
print("  galat awalnya dan membuang seluruh manfaatnya.")
