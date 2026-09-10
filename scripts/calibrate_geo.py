"""Cari presisi geohash minimum yang menjamin cakupan penuh
untuk radius pencarian tertentu, diuji secara empiris."""

import math
import random

from qshield import geo

random.seed(7)

RADII = [30, 50, 75, 100]
PRECISIONS = [5, 6, 7, 8]
TRIALS = 20000


def offset(lat, lng, dist_m, angle):
    dlat = (dist_m * math.cos(angle)) / 111320
    dlng = (dist_m * math.sin(angle)) / (111320 * math.cos(math.radians(lat)))
    return lat + dlat, lng + dlng


print("Ukuran sel per presisi (di sekitar Bandung)")
print("-" * 52)
for p in PRECISIONS:
    gh = geo.encode(-6.9147, 107.6098, p)
    la0, la1, ln0, ln1 = geo.bounds(gh)
    h = geo.haversine_m(la0, ln0, la1, ln0)
    w = geo.haversine_m(la0, ln0, la0, ln1)
    print(f"  presisi {p}:  {w:7.1f} m  x  {h:7.1f} m")

print()
print("Cakupan: apakah binding dalam radius R selalu terjaring")
print("oleh sel query + 8 tetangganya?")
print("-" * 52)
print(f"  {'radius':>8}", "".join(f"{'p' + str(p):>10}" for p in PRECISIONS))

results = {}
for radius in RADII:
    row = []
    for prec in PRECISIONS:
        misses = 0
        for _ in range(TRIALS):
            lat = random.uniform(-7.2, -6.6)
            lng = random.uniform(107.4, 107.8)
            d = random.uniform(0, radius)
            ang = random.uniform(0, 2 * math.pi)
            blat, blng = offset(lat, lng, d, ang)

            query_cells = set(geo.neighbors(geo.encode(lat, lng, prec)))
            if geo.encode(blat, blng, prec) not in query_cells:
                misses += 1
        pct = 100 * (TRIALS - misses) / TRIALS
        results[(radius, prec)] = pct
        row.append(f"{pct:9.2f}%")
    print(f"  {radius:>6} m", "".join(row))

print()
print("Kesimpulan")
print("-" * 52)
for radius in RADII:
    safe = [p for p in PRECISIONS if results[(radius, p)] == 100.0]
    best = max(safe) if safe else None
    print(f"  radius {radius:>3} m -> presisi indeks tertinggi yang aman: {best}")
