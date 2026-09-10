"""
Geohash: encode, decode, dan pencarian sel tetangga.

Dipakai hanya sebagai indeks kasar untuk mempersempit query.
Penentuan jangkar yang sebenarnya memakai jarak haversine,
karena geohash punya masalah batas sel: dua titik berjarak
beberapa meter bisa jatuh di sel berbeda kalau kebetulan
berada di tepi.
"""

from math import radians, sin, cos, asin, sqrt

BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz"
DECODE_MAP = {c: i for i, c in enumerate(BASE32)}

NEIGHBOR_TABLE = {
    "n": ("p0r21436x8zb9dcf5h7kjnmqesgutwvy", "bc01fg45238967deuvhjyznpkmstqrwx"),
    "s": ("14365h7k9dcfesgujnmqp0r2twvyx8zb", "238967debc01fg45kmstqrwxuvhjyznp"),
    "e": ("bc01fg45238967deuvhjyznpkmstqrwx", "p0r21436x8zb9dcf5h7kjnmqesgutwvy"),
    "w": ("238967debc01fg45kmstqrwxuvhjyznp", "14365h7k9dcfesgujnmqp0r2twvyx8zb"),
}

BORDER_TABLE = {
    "n": ("prxz", "bcfguvyz"),
    "s": ("028b", "0145hjnp"),
    "e": ("bcfguvyz", "prxz"),
    "w": ("0145hjnp", "028b"),
}

EARTH_RADIUS_KM = 6371.0088


def encode(lat: float, lng: float, precision: int = 8) -> str:
    lat_range = [-90.0, 90.0]
    lng_range = [-180.0, 180.0]
    out = []
    bits = 0
    bit_count = 0
    even = True

    while len(out) < precision:
        if even:
            mid = (lng_range[0] + lng_range[1]) / 2
            if lng > mid:
                bits = (bits << 1) | 1
                lng_range[0] = mid
            else:
                bits <<= 1
                lng_range[1] = mid
        else:
            mid = (lat_range[0] + lat_range[1]) / 2
            if lat > mid:
                bits = (bits << 1) | 1
                lat_range[0] = mid
            else:
                bits <<= 1
                lat_range[1] = mid
        even = not even
        bit_count += 1
        if bit_count == 5:
            out.append(BASE32[bits])
            bits = 0
            bit_count = 0

    return "".join(out)


def bounds(geohash: str):
    """Kembalikan (lat_min, lat_max, lng_min, lng_max) sel geohash."""
    lat_range = [-90.0, 90.0]
    lng_range = [-180.0, 180.0]
    even = True

    for ch in geohash.lower():
        if ch not in DECODE_MAP:
            raise ValueError(f"Karakter geohash tidak valid: {ch}")
        val = DECODE_MAP[ch]
        for shift in range(4, -1, -1):
            bit = (val >> shift) & 1
            if even:
                mid = (lng_range[0] + lng_range[1]) / 2
                if bit:
                    lng_range[0] = mid
                else:
                    lng_range[1] = mid
            else:
                mid = (lat_range[0] + lat_range[1]) / 2
                if bit:
                    lat_range[0] = mid
                else:
                    lat_range[1] = mid
            even = not even

    return lat_range[0], lat_range[1], lng_range[0], lng_range[1]


def decode(geohash: str):
    """Titik tengah sel geohash."""
    lat_min, lat_max, lng_min, lng_max = bounds(geohash)
    return (lat_min + lat_max) / 2, (lng_min + lng_max) / 2


def adjacent(geohash: str, direction: str) -> str:
    """Sel tetangga pada arah n/s/e/w."""
    geohash = geohash.lower()
    direction = direction.lower()
    if not geohash:
        raise ValueError("Geohash kosong")
    if direction not in NEIGHBOR_TABLE:
        raise ValueError(f"Arah tidak dikenal: {direction}")

    last = geohash[-1]
    parent = geohash[:-1]
    idx = len(geohash) % 2  # 0 = panjang genap, 1 = panjang ganjil

    if last in BORDER_TABLE[direction][idx] and parent:
        parent = adjacent(parent, direction)

    return parent + BASE32[NEIGHBOR_TABLE[direction][idx].index(last)]


def neighbors(geohash: str) -> list:
    """Delapan sel di sekeliling, plus sel itu sendiri di posisi pertama."""
    n = adjacent(geohash, "n")
    s = adjacent(geohash, "s")
    e = adjacent(geohash, "e")
    w = adjacent(geohash, "w")
    return [
        geohash,
        n, s, e, w,
        adjacent(n, "e"), adjacent(n, "w"),
        adjacent(s, "e"), adjacent(s, "w"),
    ]


def haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Jarak dua titik dalam meter."""
    rlat1, rlng1, rlat2, rlng2 = map(radians, (lat1, lng1, lat2, lng2))
    dlat = rlat2 - rlat1
    dlng = rlng2 - rlng1
    a = sin(dlat / 2) ** 2 + cos(rlat1) * cos(rlat2) * sin(dlng / 2) ** 2
    return EARTH_RADIUS_KM * 2 * asin(sqrt(a)) * 1000
