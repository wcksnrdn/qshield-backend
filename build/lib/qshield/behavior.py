"""
Layer 2 — penilaian perilaku pada jalur QR.

Layer 1 menjawab "apakah merchant ini memang yang seharusnya ada di
lokasi ini". Layer 2 menjawab pertanyaan yang berbeda: "apakah artefak
yang barusan dipindai berperilaku seperti QR yang sah". Keduanya bisa
gagal sendiri-sendiri — stiker palsu di lokasi yang belum punya jangkar
lolos Layer 1, tapi payload-nya sering mengkhianati dirinya sendiri.

Dua kelas sinyal:

  struktural   turunan murni dari payload, deterministik, tanpa state.
               Sebagian adalah KONTRADIKSI: payload yang melanggarnya
               tidak mungkin diterbitkan acquirer yang patuh spec.

  perilaku     turunan dari agregat pada baris binding. Tidak ada baris
               per-device baru, tidak ada koordinat — lihat Keputusan 6
               dan invarian §8. Yang diingat sistem adalah properti
               jangkar, bukan kunjungan orang.

Aturan yang tidak boleh dilanggar: Layer 2 HANYA MENAIKKAN risiko,
tidak pernah menurunkan. Tidak adanya sinyal Layer 2 bukan bukti
keabsahan — logika yang sama dengan invarian §2. Karena itu tidak ada
satu pun bobot negatif di berkas ini.

Seperti binding.py, modul ini tidak mengimpor store.py: agregat
diserahkan lewat AnchorState supaya aturannya bisa diuji tanpa I/O.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# --- Parameter yang bisa dikalibrasi -------------------------------
#
# Angka di bawah dikalibrasi lewat scripts/calibrate_layer2.py.
# Yang belum punya dasar empiris ditandai UNCALIBRATED secara eksplisit
# supaya tidak ada konstanta yang menyelinap masuk tanpa alasan.

# Kontradiksi struktural: payload melanggar spec EMVCo/QRIS. Bukan
# probabilistik — acquirer yang patuh tidak bisa menerbitkannya.
W_STRUCTURAL = 70

# Sidik jari encoding. Lemah dan UNCALIBRATED: memisahkan "dicetak ulang
# oleh penyerang" dari "diterbitkan generator yang rewel" butuh korpus
# payload QRIS asli yang belum kami punya. Bobotnya sengaja kecil dan
# totalnya dibatasi agar tidak pernah bisa menggerakkan tier sendirian.
W_TAG_ORDER = 15
W_CRC_CASE = 10
SOFT_FINGERPRINT_CAP = 25

# Percobaan anomali berulang di satu jangkar. Berskala dengan kekuatan
# bukti, pola yang sama dengan invarian §5.
W_ANOMALY_BASE = 12
W_ANOMALY_CAP = 30

# Sinyal "lonjakan pemindaian" pernah ada di sini dan sudah DIBUANG.
# calibrate_layer2.py menunjukkan alasannya: membangun reputasi palsu
# hanya butuh MIN_OBSERVERS=3 device dalam rentang MIN_AGE_HOURS=24 jam,
# jadi serangannya pelan — puncaknya 3 pemindaian. Ambang mana pun yang
# masih bisa ditoleransi warung laris (>=120/jam) melewatkan 100%
# serangan, sementara ambang yang cukup rendah untuk menangkapnya
# menandai 100% merchant sibuk. Volume tidak memisahkan keduanya.
# Pertahanan yang benar untuk probing otomatis adalah rate limiting,
# bukan skor risiko.

# --- Klaim lokasi --------------------------------------------------
#
# Koordinat dan akurasi datang dari klien, dan server tidak punya cara
# memverifikasinya (R1). Yang BISA diperiksa adalah apakah klaimnya
# masuk akal secara fisik — pembohong yang malas sering lupa berbohong
# dengan konsisten.
#
# GNSS ponsel konsumen tidak pernah melaporkan radius keyakinan di bawah
# satu meter; yang terbaik pun berhenti di sekitar 3 m, dan itu butuh
# dual-frequency di bawah langit terbuka. Nilai 0 sama sekali mustahil.
# Ambang 1,0 m sengaja dipasang jauh di bawah kemampuan perangkat asli
# supaya nyaris tidak mungkin menandai pemindaian sah.
MIN_PLAUSIBLE_ACCURACY_M = 1.0
W_IMPLAUSIBLE_ACCURACY = 45

# Catatan: "akurasi tidak dikirim" pernah jadi sinyal risiko di sini dan
# sudah DIBUANG. Menghukum absennya sebuah field sambil mendeklarasikan
# field itu opsional adalah desain yang tidak koheren — dan absennya
# membuka pintu keluar dari invarian §6, yang terlalu serius untuk
# diselesaikan dengan menambah skor. Sekarang accuracy_m wajib, dan
# permintaan tanpanya ditolak 422 di batas sistem.

# NMID QRIS: "ID" + 13 digit.
NMID_LENGTH = 15
NMID_PREFIX = "ID"

# Tag wajib EMVCo Merchant Presented Mode.
MANDATORY_TAGS = ("00", "53", "58", "59", "63")

# Tag 54 (nominal) tidak boleh ada pada QR statis (tag 01 = "11").
TAG_POINT_OF_INITIATION = "01"
TAG_AMOUNT = "54"
STATIC_INDICATOR = "11"


@dataclass
class AnchorState:
    """Agregat perilaku milik satu jangkar.

    Sengaja hanya berisi hitungan dan waktu. Tidak ada device, tidak ada
    koordinat, tidak ada apa pun yang bisa dirangkai jadi jejak seseorang.
    """

    anomaly_attempts: int = 0
    last_anomaly_at: Optional[datetime] = None


@dataclass
class Signal:
    name: str
    weight: int
    reason: str
    hard: bool = False


@dataclass
class BehaviorResult:
    score: int = 0
    signals: list = field(default_factory=list)
    reasons: list = field(default_factory=list)
    hard_violation: bool = False

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "signals": self.signals,
            "reasons": self.reasons,
            "hard_violation": self.hard_violation,
        }


def _location_claim_signals(accuracy_m, has_coords: bool) -> list:
    """Sinyal dari klaim lokasi, tanpa memercayai isinya.

    Tidak satu pun sinyal di sini membuktikan koordinatnya benar — itu
    mustahil dari sisi server (R1). Yang diperiksa hanya apakah klaimnya
    konsisten dengan perangkat yang sungguh-sungguh ada.
    """
    out = []
    if not has_coords or accuracy_m is None:
        return out

    if accuracy_m < MIN_PLAUSIBLE_ACCURACY_M:
        out.append(Signal(
            name="implausible_accuracy",
            weight=W_IMPLAUSIBLE_ACCURACY,
            reason=(
                f"Akurasi lokasi {accuracy_m:.2f} m berada di bawah batas "
                f"fisik GNSS ponsel — nilai ini tidak berasal dari "
                f"penerima sungguhan"
            ),
        ))
    return out


def _structural_signals(parsed) -> list:
    """Sinyal yang seluruhnya turunan dari payload."""
    out = []
    tags = parsed.tags

    # --- Kontradiksi 1: QR statis membawa nominal -------------------
    # Stiker statis dicetak sekali dan dipajang; nominalnya diisi
    # pembayar. Payload statis yang sudah membawa tag 54 berarti ada
    # yang membangkitkan ulang kode itu.
    if tags.get(TAG_POINT_OF_INITIATION, STATIC_INDICATOR) == STATIC_INDICATOR:
        if TAG_AMOUNT in tags:
            out.append(Signal(
                name="static_qr_with_amount",
                weight=W_STRUCTURAL,
                hard=True,
                reason=(
                    f"QR statis membawa nominal terkunci "
                    f"Rp{tags[TAG_AMOUNT]} — stiker statis yang sah tidak "
                    f"pernah mencantumkan nominal"
                ),
            ))

    # --- Kontradiksi 2: tag wajib hilang ----------------------------
    hilang = [t for t in MANDATORY_TAGS if t not in tags]
    if hilang:
        out.append(Signal(
            name="missing_mandatory_tags",
            weight=W_STRUCTURAL,
            hard=True,
            reason=(
                f"Tag wajib EMVCo tidak ada: {', '.join(hilang)} — "
                f"payload tidak diterbitkan penyelenggara yang patuh"
            ),
        ))

    # --- Kontradiksi 3: NMID cacat bentuk ---------------------------
    nmid = parsed.nmid
    if nmid is not None:
        badan = nmid[len(NMID_PREFIX):]
        if (len(nmid) != NMID_LENGTH
                or not nmid.startswith(NMID_PREFIX)
                or not badan.isdigit()):
            out.append(Signal(
                name="malformed_nmid",
                weight=W_STRUCTURAL,
                hard=True,
                reason=(
                    f"Format Merchant ID tidak sesuai standar QRIS "
                    f"('{nmid}' — seharusnya {NMID_PREFIX} + "
                    f"{NMID_LENGTH - len(NMID_PREFIX)} digit)"
                ),
            ))

    # --- Sidik jari encoding (lemah, UNCALIBRATED) ------------------
    # parse_tlv menyisipkan tag sesuai urutan kemunculan, dan dict
    # Python mempertahankan urutan sisip — jadi ini urutan asli payload.
    urutan = list(tags.keys())
    if urutan != sorted(urutan):
        out.append(Signal(
            name="noncanonical_tag_order",
            weight=W_TAG_ORDER,
            reason=(
                "Urutan field payload tidak menaik — pola khas kode yang "
                "dibongkar lalu disusun ulang"
            ),
        ))

    if parsed.crc_found and parsed.crc_found != parsed.crc_found.upper():
        out.append(Signal(
            name="noncanonical_crc_case",
            weight=W_CRC_CASE,
            reason=(
                "Checksum ditulis huruf kecil — penyimpangan dari bentuk "
                "yang diterbitkan acquirer"
            ),
        ))

    return out


def _behavioral_signals(state: Optional[AnchorState], nmid_matches_anchor: bool,
                        now: datetime) -> list:
    """Sinyal dari agregat jangkar."""
    if state is None:
        return []
    out = []

    # --- Jangkar ini pernah diserang --------------------------------
    #
    # Penting: hanya berlaku kalau NMID yang dipindai BUKAN pemilik sah
    # jangkar. Tanpa syarat itu, penyerang bisa menaikkan risiko merchant
    # jujur cukup dengan menempel stiker palsu berkali-kali di depannya —
    # penolakan layanan lewat counter kami sendiri.
    if state.anomaly_attempts > 0 and not nmid_matches_anchor:
        bobot = min(W_ANOMALY_CAP, W_ANOMALY_BASE * state.anomaly_attempts)
        out.append(Signal(
            name="repeated_anomaly_at_anchor",
            weight=bobot,
            reason=(
                f"Lokasi ini sudah {state.anomaly_attempts} kali menjadi "
                f"sasaran pemindaian yang ditolak"
            ),
        ))

    return out


def evaluate(
    parsed,
    state: Optional[AnchorState] = None,
    nmid_matches_anchor: bool = False,
    now: Optional[datetime] = None,
    accuracy_m: Optional[float] = None,
    has_coords: bool = False,
) -> BehaviorResult:
    """Nilai perilaku satu pemindaian.

    parsed               QrisPayload hasil emvco.parse()
    state                agregat jangkar yang cocok, kalau ada
    nmid_matches_anchor  True bila NMID yang dipindai adalah pemilik sah
                         jangkar ini (mematikan sinyal yang bisa
                         disalahgunakan untuk menyerang merchant jujur)
    accuracy_m           akurasi yang DIKLAIM klien, tidak dipercaya
    has_coords           True bila permintaan memang menyertakan koordinat
    """
    now = now or datetime.now(timezone.utc)

    signals = (_structural_signals(parsed)
               + _location_claim_signals(accuracy_m, has_coords)
               + _behavioral_signals(state, nmid_matches_anchor, now))

    # Sidik jari encoding dibatasi bersama-sama: sekumpulan sinyal lemah
    # tidak boleh menumpuk sampai setara satu bukti kuat.
    soft = [s for s in signals if not s.hard
            and s.name.startswith("noncanonical")]
    soft_total = min(SOFT_FINGERPRINT_CAP, sum(s.weight for s in soft))
    lain = [s for s in signals if s not in soft]

    score = min(100, soft_total + sum(s.weight for s in lain))

    return BehaviorResult(
        score=score,
        signals=[s.name for s in signals],
        reasons=[s.reason for s in signals],
        hard_violation=any(s.hard for s in signals),
    )
