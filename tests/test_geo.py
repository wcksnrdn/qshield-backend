"""Verifikasi geo.py secara numerik, bukan dengan mempercayai tabel."""

import random

from qshield import geo

random.seed(42)

print("=" * 64)
print("1. Roundtrip encode -> decode")
print("=" * 64)

worst = 0.0
for _ in range(2000):
    lat = random.uniform(-85, 85)
    lng = random.uniform(-179, 179)
    gh = geo.encode(lat, lng, 9)
    dlat, dlng = geo.decode(gh)
    err = geo.haversine_m(lat, lng, dlat, dlng)
    worst = max(worst, err)

print(f"  error terburuk presisi 9: {worst:.2f} m")
assert worst < 5, "roundtrip meleset terlalu jauh"
print("  OK")

print()
print("=" * 64)
print("2. Arah tetangga benar secara geografis")
print("=" * 64)

failures = 0
checked = 0
for _ in range(3000):
    lat = random.uniform(-80, 80)
    lng = random.uniform(-175, 175)
    for prec in (6, 7, 8):
        gh = geo.encode(lat, lng, prec)
        clat, clng = geo.decode(gh)
        for direction, (dlat_sign, dlng_sign) in {
            "n": (1, 0), "s": (-1, 0), "e": (0, 1), "w": (0, -1),
        }.items():
            nb = geo.adjacent(gh, direction)
            nlat, nlng = geo.decode(nb)
            checked += 1
            if dlat_sign > 0 and not nlat > clat:
                failures += 1
            if dlat_sign < 0 and not nlat < clat:
                failures += 1
            if dlng_sign > 0 and not (nlng > clng or clng > 170):
                failures += 1
            if dlng_sign < 0 and not (nlng < clng or clng < -170):
                failures += 1

print(f"  diperiksa {checked} arah, gagal {failures}")
assert failures == 0, "tabel tetangga salah arah"
print("  OK")

print()
print("=" * 64)
print("3. Tetangga saling bersebelahan (tidak melompat)")
print("=" * 64)

gh = geo.encode(-6.9147, 107.6098, 8)
lat_min, lat_max, lng_min, lng_max = geo.bounds(gh)
cell_h = geo.haversine_m(lat_min, lng_min, lat_max, lng_min)
cell_w = geo.haversine_m(lat_min, lng_min, lat_min, lng_max)
print(f"  sel presisi 8: {cell_w:.0f} m x {cell_h:.0f} m")

clat, clng = geo.decode(gh)
for nb in geo.neighbors(gh)[1:]:
    nlat, nlng = geo.decode(nb)
    d = geo.haversine_m(clat, clng, nlat, nlng)
    assert d < max(cell_w, cell_h) * 2.5, f"tetangga {nb} terlalu jauh: {d:.0f} m"
print(f"  9 sel unik: {len(set(geo.neighbors(gh))) == 9}")
assert len(set(geo.neighbors(gh))) == 9
print("  OK")

print()
print("=" * 64)
print("4. Masalah batas sel — inti perbaikan ini")
print("=" * 64)

boundary_hits = 0
covered_by_neighbors = 0
trials = 5000

for _ in range(trials):
    lat = random.uniform(-8, -6)
    lng = random.uniform(106, 108)
    gh_a = geo.encode(lat, lng, 8)

    # geser ~20 m ke arah acak
    ang = random.uniform(0, 6.283)
    import math
    dlat = (20 * math.cos(ang)) / 111320
    dlng = (20 * math.sin(ang)) / (111320 * math.cos(math.radians(lat)))
    gh_b = geo.encode(lat + dlat, lng + dlng, 8)

    if gh_a != gh_b:
        boundary_hits += 1
        if gh_b in geo.neighbors(gh_a):
            covered_by_neighbors += 1

pct = 100 * boundary_hits / trials
cover = 100 * covered_by_neighbors / boundary_hits if boundary_hits else 100
print(f"  presisi 8 — geser 20 m ubah sel: {pct:.1f}% kasus")
print(f"  presisi 8 — tertangkap cek tetangga: {cover:.1f}%")
assert cover < 100.0, (
    "Presisi 8 seharusnya TIDAK menutup semua kasus. "
    "Sel setinggi 19 m bisa terlompati oleh geser 20 m."
)
print("  presisi 8 terbukti tidak layak jadi indeks")

# Presisi 7 adalah yang dipakai sistem (lihat binding.INDEX_PRECISION).
misses7 = 0
for _ in range(trials):
    lat = random.uniform(-8, -6)
    lng = random.uniform(106, 108)
    ang = random.uniform(0, 6.283)
    d = random.uniform(0, 50)
    import math
    dlat = (d * math.cos(ang)) / 111320
    dlng = (d * math.sin(ang)) / (111320 * math.cos(math.radians(lat)))
    cells = set(geo.neighbors(geo.encode(lat, lng, 7)))
    if geo.encode(lat + dlat, lng + dlng, 7) not in cells:
        misses7 += 1

cover7 = 100 * (trials - misses7) / trials
print(f"  presisi 7 — cakupan radius 50 m: {cover7:.2f}%")
assert cover7 == 100.0, "presisi 7 harus menutup radius 50 m sepenuhnya"
print("  OK — presisi 7 layak dipakai sebagai indeks")

print()
print("=" * 64)
print("5. Kasus ekstrem")
print("=" * 64)

for lat, lng, label in [
    (0, 0, "titik nol"),
    (-6.9147, 179.9999, "dekat antimeridian"),
    (89.9, 10, "dekat kutub utara"),
    (-89.9, 10, "dekat kutub selatan"),
]:
    gh = geo.encode(lat, lng, 8)
    nb = geo.neighbors(gh)
    assert len(nb) == 9
    print(f"  {label:22} {gh}  tetangga OK")

print("\n\nSemua verifikasi lolos.")
