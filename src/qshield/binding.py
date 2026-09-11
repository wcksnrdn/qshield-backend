"""
Logika binding merchant-lokasi.

Jangkar ditentukan oleh JARAK, bukan oleh kesamaan sel geohash.
Geohash presisi 7 dipakai semata sebagai indeks untuk mempersempit
query; sel presisi 7 berukuran ~152 x 153 m sehingga sel itu
ditambah 8 tetangganya dijamin mencakup seluruh titik dalam
radius 100 m (diverifikasi di calibrate_geo.py).

Memakai kesamaan geohash sebagai jangkar adalah kesalahan:
sel presisi 8 hanya setinggi 19 m, sehingga dua pemindaian di
warung yang sama kerap jatuh di sel berbeda.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from . import geo

# --- Parameter yang bisa dikalibrasi -------------------------------

ANCHOR_RADIUS_M = 50        # dua pemindaian dianggap satu jangkar
INDEX_PRECISION = 7         # presisi geohash untuk indeks query
AREA_PRECISION = 6          # presisi untuk deteksi sebaran antar-area
SCATTER_MIN_KM = 1.0        # jarak minimum agar dianggap area berbeda

# Konflik di jangkar TERDAFTAR. Datar, bukan berskala dengan jumlah
# pengamat — pendaftaran bukan bukti yang menumpuk seiring waktu,
# melainkan pernyataan pihak yang meng-onboard merchant. Kekuatannya
# tidak bertambah karena lebih banyak orang memindai.
#
# Nilainya dipilih supaya sendirian pun mendarat di cooling_off (>=76),
# setara konflik konsensus 50 pengamat. Alasannya: penyelenggara
# menyatakan merchant INI yang ada di sini, dan yang dipindai bukan dia.
W_REGISTERED_CONFLICT = 85

MIN_OBSERVERS = 3           # device unik sebelum binding dianggap mapan
ADJACENT_MIN_RATIO = 0.10   # basis pengamat minimum relatif tetangga
MIN_AGE_HOURS = 24          # rentang minimal pengamatan pertama ke terakhir
SCATTER_MIN_AREAS = 2       # jumlah area lain yang memicu alarm sebaran
STALE_DAYS = 90             # binding tak terlihat selama ini dianggap usang

VERIFIED = "verified"
UNKNOWN = "unknown"
ANOMALY = "anomaly"

PROCEED = "proceed"
WARN = "warn"
STEP_UP = "step_up"
COOLING_OFF = "cooling_off"

THRESHOLDS = [(25, PROCEED), (50, WARN), (75, STEP_UP)]


@dataclass
class Binding:
    """Satu pasangan (merchant, jangkar lokasi) yang pernah diamati."""

    nmid: str
    lat: float
    lng: float
    geohash_7: str = ""
    geohash_6: str = ""
    merchant_name: Optional[str] = None
    observer_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    registered_at: Optional[datetime] = None
    is_mobile: bool = False

    def __post_init__(self):
        if not self.geohash_7:
            self.geohash_7 = geo.encode(self.lat, self.lng, INDEX_PRECISION)
        if not self.geohash_6:
            self.geohash_6 = geo.encode(self.lat, self.lng, AREA_PRECISION)

    @property
    def age_hours(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return (self.last_seen - self.first_seen).total_seconds() / 3600

    @property
    def is_registered(self) -> bool:
        return self.registered_at is not None

    @property
    def is_established(self) -> bool:
        """Cukup bukti untuk dianggap mapan.

        Pendaftaran oleh penyelenggara memenuhinya tanpa menunggu
        konsensus: itu pernyataan pihak yang meng-onboard merchant, dan
        pernyataan adalah BUKTI — bukan ketiadaan bukti, sehingga
        invarian §2 tidak dilanggar.

        Yang tidak boleh hilang: sumbernya tetap bisa dibedakan lewat
        is_registered, dan penilaian memakai sinyal yang berbeda untuk
        keduanya. "Terverifikasi karena terdaftar" dan "terverifikasi
        karena diamati banyak orang" adalah dua klaim yang berbeda
        kekuatannya, dan auditor berhak tahu yang mana.
        """
        if self.is_registered:
            return True
        return (
            self.observer_count >= MIN_OBSERVERS
            and self.age_hours >= MIN_AGE_HOURS
        )

    def is_stale(self, now: datetime) -> bool:
        if not self.last_seen:
            return False
        return (now - self.last_seen) > timedelta(days=STALE_DAYS)

    def distance_m(self, lat: float, lng: float) -> float:
        return geo.haversine_m(self.lat, self.lng, lat, lng)

    def at_same_anchor(self, lat: float, lng: float,
                       radius_m: float = ANCHOR_RADIUS_M) -> bool:
        return self.distance_m(lat, lng) <= radius_m


@dataclass
class Verdict:
    status: str
    action: str
    risk_score: int
    reasons: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    matched_binding: Optional[Binding] = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.status,
            "action": self.action,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "signals": self.signals,
        }


def index_cells(lat: float, lng: float) -> list:
    """Sel geohash yang harus dicari untuk menemukan binding di sekitar."""
    return geo.neighbors(geo.encode(lat, lng, INDEX_PRECISION))


def _action_for(score: int) -> str:
    for limit, action in THRESHOLDS:
        if score <= limit:
            return action
    return COOLING_OFF


def _floor_action(status: str, action: str) -> str:
    """Invarian §2: "unknown" tidak pernah berarti aman.

    Binding yang belum mapan bisa berskor rendah (mis. young_binding = 15)
    dan jatuh ke proceed — itu mengubah ketiadaan bukti jadi kepercayaan,
    dan penyerang mengendalikan jalurnya: cukup pindai stikernya sendiri
    sekali agar skornya turun dari 35 ke 15.

    Dijaga struktural di sini, bukan lewat penyetelan bobot, supaya sinyal
    baru mana pun — termasuk Layer 2 — tidak bisa membuka celah yang sama.
    """
    if status == UNKNOWN and action == PROCEED:
        return WARN
    return action


def _distinct_areas(bindings: list, lat: float, lng: float) -> list:
    """Kelompokkan binding jadi area yang benar-benar berjauhan.

    Mencegah satu lokasi dihitung berkali-kali hanya karena
    koordinatnya bergeser sedikit antar pengamatan.
    """
    clusters = []
    for b in sorted(bindings, key=lambda x: -x.observer_count):
        if b.distance_m(lat, lng) <= SCATTER_MIN_KM * 1000:
            continue
        if any(
            geo.haversine_m(b.lat, b.lng, c.lat, c.lng) <= SCATTER_MIN_KM * 1000
            for c in clusters
        ):
            continue
        clusters.append(b)
    return clusters


def evaluate(
    nmid: str,
    lat: float,
    lng: float,
    nearby: list,
    same_nmid_elsewhere: list,
    crc_valid: bool = True,
    now: Optional[datetime] = None,
) -> Verdict:
    """Nilai satu pemindaian.

    nearby               binding hasil query indeks di sekitar titik ini,
                         belum disaring jarak
    same_nmid_elsewhere  binding dengan NMID sama di mana pun
    """
    now = now or datetime.now(timezone.utc)
    score = 0
    reasons = []
    signals = []

    if not crc_valid:
        return Verdict(
            status=ANOMALY,
            action=COOLING_OFF,
            risk_score=95,
            reasons=["Checksum QR tidak valid — kode kemungkinan dicetak ulang"],
            signals=["crc_invalid"],
        )

    # Saring berdasarkan jarak sebenarnya, bukan kesamaan sel.
    at_anchor = [b for b in nearby if b.at_same_anchor(lat, lng)]
    current = next((b for b in at_anchor if b.nmid == nmid), None)
    others = [b for b in at_anchor if b.nmid != nmid]

    # --- Merchant keliling yang terdaftar ----------------------------
    #
    # Model jangkar mengandaikan lokasi tetap, dan itu tidak berlaku
    # untuk pedagang keliling. Hanya PJP yang bisa menandainya, jadi
    # pengecualian ini adalah tanggung jawab penyelenggara yang
    # menyatakannya — bukan sesuatu yang bisa diklaim pemindai.
    kandidat = ([current] if current else []) + list(same_nmid_elsewhere)
    keliling = next((b for b in kandidat if b.is_registered and b.is_mobile), None)
    if keliling is not None:
        reasons.append(
            f"Terdaftar sebagai merchant keliling"
            + (f" — {keliling.merchant_name}" if keliling.merchant_name else "")
        )
        signals.append("mobile_merchant")
        return Verdict(
            status=VERIFIED, action=PROCEED, risk_score=0,
            reasons=reasons, signals=signals, matched_binding=current,
        )

    # --- Sinyal 1: NMID berubah di jangkar yang sudah mapan ---------
    # Merchant keliling TIDAK mengklaim lokasi, jadi bindingnya tidak
    # boleh membuat merchant lain terlihat seperti pertukaran stiker.
    # Gerobak siomay yang pernah mangkal di suatu titik tidak menjadikan
    # titik itu miliknya. Tanpa pengecualian ini, satu pendaftaran
    # keliling bisa meracuni setiap jangkar yang pernah disinggahinya.
    conflicting = [b for b in others
                   if b.is_established and not b.is_stale(now)
                   and not (b.is_registered and b.is_mobile)]
    if conflicting:
        # Yang terdaftar didahulukan sebagai pembanding: pernyataan
        # penyelenggara lebih otoritatif daripada akumulasi pengamatan,
        # berapa pun jumlahnya.
        strongest = max(
            conflicting, key=lambda b: (b.is_registered, b.observer_count))
        # Bobot naik seiring kekuatan bukti: binding dengan 40+ pengamat
        # adalah bukti jauh lebih kuat daripada yang baru mencapai ambang.
        confidence = min(25, strongest.observer_count // 2)

        # Pertukaran stiker berarti binding lama berhenti terlihat.
        # Kalau NMID yang discan JUGA sudah mapan dan masih aktif,
        # keduanya hidup berdampingan — ciri merchant bersebelahan
        # (ruko, food court), bukan penggantian.
        #
        # Tapi "mapan" saja tidak cukup, dan itu celah R10: penyerang yang
        # menang balapan cold start bisa memupuk binding palsu sampai
        # mapan dengan MIN_OBSERVERS device saja, lalu ikut menikmati
        # pengecualian ini selamanya.
        #
        # Karena itu basis pengamatnya harus SEBANDING dengan tetangga.
        # Merchant yang benar-benar bersebelahan menghisap lalu lintas
        # kaki yang sama, jadi jumlah pengamatnya sepadan; penyerang yang
        # memupuk 3 device di sebelah merchant 47 pengamat tidak.
        #
        # Rasio 0,10 dikalibrasi di calibrate_adjacency.py: 3,5% pasangan
        # merchant sah tertolak, dan biaya penyerang naik dari 3 ke 5
        # device. Perbandingan dipilih, bukan jarak — opsi berbasis jarak
        # gugur karena galat GPS membuat sebaran jangkar swap dan merchant
        # bersebelahan tumpang tindih 72-79% pada 2,5-8 m.
        #
        # Jujur soal batasnya: ini MENAIKKAN biaya penyerang, bukan
        # menutup celahnya. Penutupan sungguhan menuntut integritas
        # perangkat atau autentikasi klien.
        # Binding TERDAFTAR lolos uji rasio tanpa syarat: buktinya adalah
        # pernyataan penyelenggara, bukan jumlah pengamat. Merchant yang
        # baru didaftarkan punya nol pengamat, dan tanpa pengecualian ini
        # ia langsung dituduh menggusur tetangganya sendiri.
        #
        # Ini tidak membuka lagi celah R10: yang ditutup ADJACENT_MIN_RATIO
        # adalah penyerang yang memupuk binding dengan tiga device murah,
        # dan jalur itu tidak melewati pendaftaran. Untuk mendaftar,
        # penyerang butuh kunci PJP — jalur kepercayaan yang berbeda,
        # yang punya pencatatan dan pencabutannya sendiri.
        basis_sebanding = current is not None and (
            current.is_registered
            or current.observer_count
            >= ADJACENT_MIN_RATIO * strongest.observer_count
        )
        coexisting = (current is not None and current.is_established
                      and basis_sebanding)

        if coexisting:
            score += 20
            signals.append("adjacent_merchant")
            reasons.append(
                f"Terdapat merchant lain dalam radius "
                f"{strongest.distance_m(lat, lng):.0f} m yang juga aktif "
                f"— kemungkinan lokasi bersebelahan"
            )
        elif strongest.is_registered:
            # Sinyal TERPISAH, bukan rumus konsensus yang diubah —
            # invarian §5 mengunci rumus itu apa adanya.
            score += W_REGISTERED_CONFLICT
            signals.append("nmid_changed_at_registered_anchor")
            reasons.append(
                "Lokasi ini terdaftar resmi atas merchant lain oleh "
                "penyelenggara pembayaran"
            )
        else:
            score += 60 + confidence
            signals.append("nmid_changed_at_anchor")
            reasons.append(
                f"Merchant ID berbeda dari {strongest.observer_count} pengamatan "
                f"sebelumnya di lokasi ini"
            )
            if strongest.merchant_name:
                reasons.append(
                    f"Lokasi ini konsisten terdaftar sebagai "
                    f"{strongest.merchant_name}"
                )

    # --- Sinyal 2: satu NMID tersebar di banyak area ----------------
    elsewhere = [
        b for b in same_nmid_elsewhere
        if b.distance_m(lat, lng) > SCATTER_MIN_KM * 1000
    ]
    areas = _distinct_areas(elsewhere, lat, lng)
    if len(areas) >= SCATTER_MIN_AREAS:
        score += 60
        signals.append("nmid_scatter")
        farthest = max(areas, key=lambda b: b.distance_m(lat, lng))
        reasons.append(
            f"Merchant ID yang sama terdeteksi di {len(areas) + 1} area berbeda, "
            f"terjauh {farthest.distance_m(lat, lng) / 1000:.0f} km — "
            f"pola khas stiker yang disebar"
        )
    elif len(areas) == 1:
        score += 25
        signals.append("nmid_second_location")
        reasons.append(
            f"Merchant ID ini juga tercatat di lokasi lain berjarak "
            f"{areas[0].distance_m(lat, lng) / 1000:.1f} km"
        )

    # --- Riwayat jangkar ini sendiri --------------------------------
    if current and current.is_registered:
        # Dibedakan dari konsensus dengan sengaja: "terdaftar" dan
        # "diamati banyak orang" adalah dua klaim berbeda kekuatannya,
        # dan auditor berhak tahu yang mana yang berlaku.
        if not conflicting and not areas:
            score = max(0, score - 20)
        signals.append("registered_merchant")
        reasons.append(
            "Terdaftar resmi di lokasi ini oleh penyelenggara pembayaran"
            + (f" sebagai {current.merchant_name}" if current.merchant_name else "")
        )
    elif current and current.is_established:
        if not conflicting and not areas:
            score = max(0, score - 20)
        signals.append("established_binding")
        reasons.append(
            f"Konsisten dengan {current.observer_count} pengamatan sebelumnya "
            f"di lokasi ini"
        )
    elif current:
        score += 15
        signals.append("young_binding")
        reasons.append(
            f"Binding baru — baru {current.observer_count} pengamatan, "
            f"belum cukup untuk diverifikasi"
        )
    elif not conflicting:
        score += 35
        signals.append("first_observation")
        reasons.append("Lokasi ini belum pernah tercatat sebelumnya")

    score = max(0, min(100, score))

    if ("nmid_changed_at_anchor" in signals
            or "nmid_changed_at_registered_anchor" in signals
            or "nmid_scatter" in signals):
        status = ANOMALY
    elif current and current.is_established and score <= 25:
        status = VERIFIED
    else:
        status = UNKNOWN

    if not reasons:
        reasons.append("Belum ada cukup data untuk memverifikasi lokasi ini")

    return Verdict(
        status=status,
        action=_floor_action(status, _action_for(score)),
        risk_score=score,
        reasons=reasons,
        signals=signals,
        matched_binding=current,
    )


# --- Komposisi Layer 1 + Layer 2 -----------------------------------


def compose(verdict: "Verdict", behavior) -> "Verdict":
    """Gabungkan putusan Layer 1 dengan hasil Layer 2 jadi satu putusan.

    Layer 1 menjawab "apakah merchant ini memang yang seharusnya di sini".
    Layer 2 menjawab "apakah artefak yang dipindai berperilaku seperti QR
    yang sah". Keduanya bisa gagal sendiri-sendiri, jadi Layer 2
    MELENGKAPI, bukan menggantikan.

    Tiga aturan, dan ketiganya searah:

    1. Skor dijumlah lalu dijepit 0-100. Layer 2 tidak punya bobot negatif
       sama sekali — tidak adanya sinyal Layer 2 bukan bukti keabsahan,
       logika yang sama dengan invarian §2.

    2. Layer 2 tidak pernah bisa MENAIKKAN status ke arah verified.
       Ia hanya bisa menurunkan:
         - kontradiksi struktural  -> anomaly
         - sinyal lain apa pun     -> verified turun jadi unknown,
           karena jangkarnya boleh jadi benar tapi artefaknya diragukan
       Status anomaly dari Layer 1 tidak pernah dicabut Layer 2.

    3. Aksi tetap dipetakan ke empat tier yang sama lewat ambang yang
       sama (invarian §4). Layer 2 tidak memperkenalkan skala baru.
    """
    if behavior is None or (behavior.score == 0 and not behavior.hard_violation):
        return verdict

    score = max(0, min(100, verdict.risk_score + behavior.score))

    if behavior.hard_violation:
        status = ANOMALY
    elif verdict.status == VERIFIED:
        status = UNKNOWN
    else:
        status = verdict.status

    return Verdict(
        status=status,
        action=_floor_action(status, _action_for(score)),
        risk_score=score,
        reasons=verdict.reasons + behavior.reasons,
        signals=verdict.signals + behavior.signals,
        matched_binding=verdict.matched_binding,
    )
