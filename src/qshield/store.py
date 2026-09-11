"""
Penyimpanan binding.

SQLite untuk PoC. Skema sengaja dibuat portabel ke Postgres:
tidak ada fitur khusus SQLite selain tipe kolom.

Catatan privasi — ini keputusan desain, bukan detail teknis:
  - tidak ada kolom user_id di mana pun
  - tabel observations tidak menyimpan koordinat, sehingga tidak
    bisa dipakai merekonstruksi pergerakan seseorang
  - device_anon_id TIDAK PERNAH disimpan apa adanya; yang masuk tabel
    adalah hash yang dilingkupi per-binding, sehingga baris pengamatan
    tidak bisa dirangkai antar-lokasi menjadi jejak perjalanan

Agregat Layer 2 (anomaly_attempts) menempel pada baris
BINDING, bukan pada device. Isinya hitungan dan waktu, bukan siapa —
tidak ada baris per-device baru dan tidak ada koordinat tambahan, jadi
tidak ada jejak pergerakan yang bisa direkonstruksi darinya.
"""

import hashlib
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from . import behavior as bh
from . import binding as bd
from . import geo

SCHEMA = """
CREATE TABLE IF NOT EXISTS bindings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    nmid            TEXT    NOT NULL,
    lat             REAL    NOT NULL,
    lng             REAL    NOT NULL,
    geohash_7       TEXT    NOT NULL,
    geohash_6       TEXT    NOT NULL,
    merchant_name   TEXT,
    observer_count  INTEGER NOT NULL DEFAULT 0,
    registered_at   TEXT,
    is_mobile       INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    anomaly_attempts   INTEGER NOT NULL DEFAULT 0,
    last_anomaly_at    TEXT,
    UNIQUE (nmid, geohash_7)
);

-- device_ref = sha256(salt || binding_id || device_anon_id)
--
-- Dilingkupi per-binding DENGAN SENGAJA. Perangkat yang sama
-- menghasilkan nilai berbeda di tiap binding, sehingga:
--   - dedup per binding tetap bekerja (itu satu-satunya yang dibutuhkan)
--   - baris TIDAK BISA dirangkai antar-binding jadi jejak perjalanan
--
-- Versi sebelumnya menyimpan device_anon_id apa adanya, dan satu JOIN ke
-- bindings sudah cukup untuk memulihkan koordinat lengkap plus urutan
-- waktu satu perangkat. Klaim "tidak dapat dipakai merekonstruksi
-- pergerakan" jadi tidak benar. Sekarang benar.
CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    binding_id      INTEGER NOT NULL REFERENCES bindings(id),
    device_ref      TEXT    NOT NULL,
    observed_at     TEXT    NOT NULL,
    UNIQUE (binding_id, device_ref)
);

CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- Pernyataan penyelenggara, bukan pengamatan pengguna. Sengaja tabel
-- TERPISAH dari bindings dan observations: keduanya berisi jejak
-- pengguna dan tunduk pada aturan privasi; yang ini berisi pernyataan
-- lembaga dan tunduk pada aturan akuntabilitas. Kita PERLU tahu PJP
-- mana yang mendaftarkan apa — kalau kuncinya bocor, itu satu-satunya
-- cara mencabut yang terlanjur didaftarkannya.
CREATE TABLE IF NOT EXISTS registrations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    nmid           TEXT    NOT NULL,
    registrar      TEXT    NOT NULL,   -- client_id PJP, bukan pengguna
    lat            REAL    NOT NULL,
    lng            REAL    NOT NULL,
    merchant_name  TEXT,
    is_mobile      INTEGER NOT NULL DEFAULT 0,
    registered_at  TEXT    NOT NULL,
    revoked_at     TEXT,
    UNIQUE (nmid)
);

CREATE INDEX IF NOT EXISTS idx_reg_nmid ON registrations(nmid);
CREATE INDEX IF NOT EXISTS idx_bindings_gh7  ON bindings(geohash_7);
CREATE INDEX IF NOT EXISTS idx_bindings_nmid ON bindings(nmid);
"""


SALT_KEY = "device_salt"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _row_to_binding(row: sqlite3.Row) -> bd.Binding:
    return bd.Binding(
        nmid=row["nmid"],
        lat=row["lat"],
        lng=row["lng"],
        geohash_7=row["geohash_7"],
        geohash_6=row["geohash_6"],
        merchant_name=row["merchant_name"],
        observer_count=row["observer_count"],
        first_seen=_parse(row["first_seen"]),
        last_seen=_parse(row["last_seen"]),
        registered_at=_parse(row["registered_at"]),
        is_mobile=bool(row["is_mobile"]),
    )


class Store:
    # Pembuatan skema pertama kali menjalankan DDL, dan DDL di SQLite
    # menuntut kunci eksklusif. Kalau beberapa proses membuka basis data
    # yang BELUM ADA secara bersamaan — persis yang terjadi saat
    # `uvicorn --workers N` start dingin — salah satunya bisa kena
    # "database is locked" meski busy_timeout sudah terpasang, karena
    # timeout tidak berlaku untuk sebagian jalur DDL.
    #
    # Terukur: pada 12 proses serentak, satu gagal start. Retry terbatas
    # menutupnya tanpa menyembunyikan kesalahan yang sesungguhnya —
    # setelah percobaan habis, galatnya dilempar apa adanya.
    INIT_RETRIES = 5
    INIT_BACKOFF_S = 0.15

    def __init__(self, path: str = "qshield.db"):
        # isolation_level=None mematikan transaksi implisit sqlite3 supaya
        # record() bisa membuka transaksinya sendiri secara eksplisit.
        self.conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row

        # Satu koneksi dipakai bersama oleh seluruh thread — dan uvicorn
        # menjalankan endpoint sync di threadpool, jadi permintaan yang
        # datang bersamaan benar-benar menyentuh koneksi ini serentak.
        # Tanpa kunci, sqlite3 melempar InterfaceError / "another row
        # available" dan hitungan pengamat hilang. Terukur: 25 dari 60
        # permintaan paralel gagal, observations 41 dari 60.
        self._lock = threading.RLock()

        # busy_timeout HARUS lebih dulu dari pragma dan DDL apa pun.
        # Peralihan ke WAL sendiri butuh kunci eksklusif sesaat, dan
        # kalau timeout-nya belum terpasang saat itu, proses kedua yang
        # membuka basis data yang sama langsung kena "database is
        # locked" alih-alih menunggu. Terukur: 5 dari 6 proses gagal
        # start hanya karena urutan dua baris ini terbalik.
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self.conn.execute("PRAGMA foreign_keys = ON")
        # WAL membuat pembaca tidak memblokir penulis.
        self.conn.execute("PRAGMA journal_mode = WAL")
        terakhir = None
        for percobaan in range(self.INIT_RETRIES):
            try:
                self.conn.executescript(SCHEMA)
                self._salt = self._ensure_salt()
                self._migrate()
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) and "busy" not in str(exc):
                    raise
                terakhir = exc
                time.sleep(self.INIT_BACKOFF_S * (percobaan + 1))
        else:
            raise terakhir

    def _ensure_salt(self) -> str:
        """Garam untuk device_ref, stabil sepanjang umur basis data.

        Diambil dari QSHIELD_DEVICE_SALT kalau disetel; kalau tidak,
        dibangkitkan sekali lalu disimpan. Harus stabil — mengubahnya
        membuat hash lama tidak lagi cocok, sehingga perangkat yang
        pernah tercatat terhitung ulang sebagai pengamat baru.

        Garamnya tidak menyembunyikan apa pun dari pemegang basis data;
        yang mencegah perangkaian jejak adalah pelingkupan per-binding.
        Garam menambah lapisan terhadap komputasi awal (precomputation).
        """
        dari_env = os.environ.get("QSHIELD_DEVICE_SALT", "").strip()
        if dari_env:
            return dari_env

        baris = self.conn.execute(
            "SELECT value FROM meta WHERE key = ?", (SALT_KEY,)).fetchone()
        if baris:
            return baris["value"]

        garam = secrets.token_hex(16)
        self.conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)",
            (SALT_KEY, garam))
        baris = self.conn.execute(
            "SELECT value FROM meta WHERE key = ?", (SALT_KEY,)).fetchone()
        return baris["value"]

    def device_ref(self, binding_id: int, device_anon_id: str) -> str:
        """Rujukan perangkat yang hanya berlaku di dalam satu binding."""
        bahan = f"{self._salt}|{binding_id}|{device_anon_id}".encode("utf-8")
        return hashlib.sha256(bahan).hexdigest()

    def _migrate(self):
        """Tambahkan kolom agregat Layer 2 ke database lama.

        SQLite tidak punya ADD COLUMN IF NOT EXISTS, jadi kolom yang ada
        diperiksa dulu. Semua kolom baru punya DEFAULT sehingga baris
        lama tetap sah tanpa backfill.
        """
        ada = {c["name"] for c in
               self.conn.execute("PRAGMA table_info(bindings)").fetchall()}
        tambahan = {
            "anomaly_attempts": "INTEGER NOT NULL DEFAULT 0",
            "last_anomaly_at": "TEXT",
            "registered_at": "TEXT",
            "is_mobile": "INTEGER NOT NULL DEFAULT 0",
        }
        for nama, tipe in tambahan.items():
            if nama not in ada:
                self.conn.execute(
                    f"ALTER TABLE bindings ADD COLUMN {nama} {tipe}")

        self._migrate_device_ref()

    def _migrate_device_ref(self):
        """Ganti kolom device_anon_id lama dengan device_ref berlingkup.

        Basis data lama menyimpan pengenal perangkat apa adanya, dan itu
        bisa di-JOIN jadi jejak perjalanan. Nilai lamanya di-hash di
        tempat lalu kolomnya dibuang — bukan sekadar berhenti dipakai,
        karena data yang masih ada tetap bisa dibaca siapa pun yang
        memegang berkasnya.
        """
        kolom = {c["name"] for c in
                 self.conn.execute("PRAGMA table_info(observations)").fetchall()}
        if "device_anon_id" not in kolom:
            return

        lama = self.conn.execute(
            "SELECT id, binding_id, device_anon_id, observed_at "
            "FROM observations").fetchall()

        self.conn.execute("""
            CREATE TABLE observations_baru (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                binding_id  INTEGER NOT NULL REFERENCES bindings(id),
                device_ref  TEXT    NOT NULL,
                observed_at TEXT    NOT NULL,
                UNIQUE (binding_id, device_ref)
            )""")
        for r in lama:
            self.conn.execute(
                """INSERT OR IGNORE INTO observations_baru
                   (id, binding_id, device_ref, observed_at)
                   VALUES (?, ?, ?, ?)""",
                (r["id"], r["binding_id"],
                 self.device_ref(r["binding_id"], r["device_anon_id"]),
                 r["observed_at"]),
            )
        self.conn.execute("DROP TABLE observations")
        self.conn.execute(
            "ALTER TABLE observations_baru RENAME TO observations")

    def close(self):
        with self._lock:
            self.conn.close()

    # --- pembacaan -------------------------------------------------

    def nearby(self, lat: float, lng: float) -> list:
        """Binding di sel indeks sekitar titik ini.

        Penyaringan jarak dilakukan di binding.evaluate(), bukan di sini.
        """
        cells = bd.index_cells(lat, lng)
        marks = ",".join("?" * len(cells))
        with self._lock:
            rows = self.conn.execute(
                f"SELECT * FROM bindings WHERE geohash_7 IN ({marks})", cells
            ).fetchall()
        return [_row_to_binding(r) for r in rows]

    def by_nmid(self, nmid: str) -> list:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM bindings WHERE nmid = ?", (nmid,)
            ).fetchall()
        return [_row_to_binding(r) for r in rows]

    def anchor_state(self, lat: float, lng: float,
                     now: Optional[datetime] = None):
        """Agregat Layer 2 milik jangkar di titik ini.

        Jangkar diwakili binding paling kuat buktinya di radius jangkar:
        yang sudah mapan kalau ada, kalau tidak yang paling banyak
        pengamatnya. Mengembalikan (binding_id, nmid, AnchorState);
        binding_id None kalau belum ada binding di sini sama sekali.
        """
        now = now or datetime.now(timezone.utc)
        cells = bd.index_cells(lat, lng)
        marks = ",".join("?" * len(cells))
        with self._lock:
            rows = self.conn.execute(
                f"SELECT * FROM bindings WHERE geohash_7 IN ({marks})", cells
            ).fetchall()

        di_jangkar = [
            r for r in rows
            if geo.haversine_m(r["lat"], r["lng"], lat, lng) <= bd.ANCHOR_RADIUS_M
        ]
        if not di_jangkar:
            return None, None, bh.AnchorState()

        mapan = [r for r in di_jangkar if _row_to_binding(r).is_established]
        dipilih = max(mapan or di_jangkar, key=lambda r: r["observer_count"])

        return dipilih["id"], dipilih["nmid"], bh.AnchorState(
            anomaly_attempts=dipilih["anomaly_attempts"],
            last_anomaly_at=_parse(dipilih["last_anomaly_at"]),
        )

    def stats(self) -> dict:
        with self._lock:
            b = self.conn.execute(
                "SELECT COUNT(*) c FROM bindings").fetchone()["c"]
            o = self.conn.execute(
                "SELECT COUNT(*) c FROM observations").fetchone()["c"]
            n = self.conn.execute(
                "SELECT COUNT(DISTINCT nmid) c FROM bindings").fetchone()["c"]
        return {"bindings": b, "observations": o, "merchants": n}

    # --- penulisan -------------------------------------------------

    def record(
        self,
        nmid: str,
        lat: float,
        lng: float,
        device_anon_id: str,
        merchant_name: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> bd.Binding:
        """Catat satu pengamatan. Idempoten per (binding, device).

        Seluruh urutannya berjalan dalam SATU transaksi. Versi lama
        melakukan SELECT lalu INSERT/UPDATE terpisah — dua permintaan yang
        datang bersamaan bisa sama-sama membaca state yang sama, lalu
        sama-sama menulis. Akibatnya terukur: 25 dari 60 permintaan
        paralel gagal dan observer_count berhenti di 40, bukan 60.

        Perlu dicatat, ini bukan kelemahan SQLite. Urutan baca-ubah-tulis
        yang sama akan balapan di Postgres juga; yang menyelesaikannya
        adalah upsert atomik di bawah, bukan pindah database.
        """
        now = now or datetime.now(timezone.utc)
        gh7 = geo.encode(lat, lng, bd.INDEX_PRECISION)
        gh6 = geo.encode(lat, lng, bd.AREA_PRECISION)
        waktu = _iso(now)

        with self._lock:
            # IMMEDIATE mengambil kunci tulis sejak awal, bukan menunggu
            # sampai penulisan pertama — mencegah dua transaksi sama-sama
            # maju lalu salah satunya gagal di tengah jalan.
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                # Upsert: baris dibuat kalau belum ada, diperbarui kalau
                # sudah. Tidak ada celah antara memeriksa dan menulis.
                # merchant_name hanya diisi kalau sebelumnya kosong.
                row = self.conn.execute(
                    """INSERT INTO bindings
                       (nmid, lat, lng, geohash_7, geohash_6, merchant_name,
                        observer_count, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
                       ON CONFLICT (nmid, geohash_7) DO UPDATE SET
                           last_seen = excluded.last_seen,
                           merchant_name = COALESCE(bindings.merchant_name,
                                                    excluded.merchant_name)
                       RETURNING id""",
                    (nmid, lat, lng, gh7, gh6, merchant_name, waktu, waktu),
                ).fetchone()
                binding_id = row["id"]

                # Satu device hanya dihitung sekali per binding. Yang
                # disimpan adalah rujukan berlingkup, bukan pengenalnya.
                inserted = self.conn.execute(
                    """INSERT OR IGNORE INTO observations
                       (binding_id, device_ref, observed_at)
                       VALUES (?, ?, ?)""",
                    (binding_id, self.device_ref(binding_id, device_anon_id),
                     waktu),
                ).rowcount

                if inserted:
                    # Penambahan dilakukan di dalam SQL, bukan di Python,
                    # supaya tidak ada nilai lama yang dibaca lebih dulu.
                    self.conn.execute(
                        """UPDATE bindings
                           SET observer_count = observer_count + 1
                           WHERE id = ?""",
                        (binding_id,),
                    )

                hasil = self.conn.execute(
                    "SELECT * FROM bindings WHERE id = ?", (binding_id,)
                ).fetchone()
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

        return _row_to_binding(hasil)

    # --- pendaftaran merchant --------------------------------------

    def register(self, nmid: str, registrar: str, lat: float, lng: float,
                 merchant_name: Optional[str] = None, is_mobile: bool = False,
                 now: Optional[datetime] = None) -> dict:
        """Catat pernyataan PJP tentang ikatan merchant-lokasi.

        Ini BUKAN pengamatan: observer_count tidak disentuh sama sekali,
        jadi pendaftaran tidak bisa dipakai memalsukan konsensus. Yang
        dilakukannya adalah menandai binding sebagai terdaftar, dan
        penandaan itu punya sinyal sendiri di penilaian — supaya
        verified-karena-terdaftar selalu bisa dibedakan dari
        verified-karena-diamati.
        """
        now = now or datetime.now(timezone.utc)
        gh7 = geo.encode(lat, lng, bd.INDEX_PRECISION)
        gh6 = geo.encode(lat, lng, bd.AREA_PRECISION)
        waktu = _iso(now)

        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                lama = self.conn.execute(
                    "SELECT registrar, revoked_at FROM registrations "
                    "WHERE nmid = ?", (nmid,)).fetchone()
                # Satu PJP tidak boleh membajak pendaftaran PJP lain.
                if lama and lama["registrar"] != registrar and not lama["revoked_at"]:
                    self.conn.execute("ROLLBACK")
                    return {"ok": False, "reason": "terdaftar_pjp_lain"}

                self.conn.execute(
                    """INSERT INTO registrations
                       (nmid, registrar, lat, lng, merchant_name, is_mobile,
                        registered_at, revoked_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                       ON CONFLICT (nmid) DO UPDATE SET
                           registrar = excluded.registrar,
                           lat = excluded.lat, lng = excluded.lng,
                           merchant_name = excluded.merchant_name,
                           is_mobile = excluded.is_mobile,
                           registered_at = excluded.registered_at,
                           revoked_at = NULL""",
                    (nmid, registrar, lat, lng, merchant_name,
                     int(is_mobile), waktu))

                # Relokasi sah: jangkar lama milik NMID ini berhenti
                # dianggap terdaftar, supaya tidak ada dua tempat resmi.
                self.conn.execute(
                    "UPDATE bindings SET registered_at = NULL WHERE nmid = ?",
                    (nmid,))

                self.conn.execute(
                    """INSERT INTO bindings
                       (nmid, lat, lng, geohash_7, geohash_6, merchant_name,
                        observer_count, first_seen, last_seen,
                        registered_at, is_mobile)
                       VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                       ON CONFLICT (nmid, geohash_7) DO UPDATE SET
                           registered_at = excluded.registered_at,
                           is_mobile = excluded.is_mobile,
                           merchant_name = COALESCE(excluded.merchant_name,
                                                    bindings.merchant_name)""",
                    (nmid, lat, lng, gh7, gh6, merchant_name, waktu, waktu,
                     waktu, int(is_mobile)))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return {"ok": True, "nmid": nmid, "registered_at": waktu,
                "registrar": registrar, "is_mobile": is_mobile}

    def revoke(self, nmid: str, registrar: str,
               now: Optional[datetime] = None) -> dict:
        """Cabut pendaftaran. Hanya PJP yang mendaftarkan yang boleh."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            baris = self.conn.execute(
                "SELECT registrar, revoked_at FROM registrations WHERE nmid = ?",
                (nmid,)).fetchone()
            if not baris:
                return {"ok": False, "reason": "tidak_terdaftar"}
            if baris["registrar"] != registrar:
                return {"ok": False, "reason": "bukan_pendaftarnya"}

            self.conn.execute(
                "UPDATE registrations SET revoked_at = ? WHERE nmid = ?",
                (_iso(now), nmid))
            # Bindingnya TIDAK dihapus: pengamatan yang sudah terkumpul
            # tetap sah sebagai bukti konsensus. Yang dicabut hanya
            # status terdaftarnya.
            self.conn.execute(
                "UPDATE bindings SET registered_at = NULL WHERE nmid = ?",
                (nmid,))
        return {"ok": True, "nmid": nmid, "revoked_at": _iso(now)}

    def registration(self, nmid: str):
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM registrations WHERE nmid = ? AND revoked_at IS NULL",
                (nmid,)).fetchone()
        return dict(r) if r else None

    def note_anomaly(self, binding_id: int,
                     now: Optional[datetime] = None) -> None:
        """Catat bahwa jangkar ini menjadi sasaran pemindaian yang ditolak.

        Ini BUKAN observation dan tidak menyentuh observer_count: binding
        palsu tetap tidak bisa membangun reputasi lewat percobaan
        berulang (invarian §3). Counter ini hanya pernah menaikkan risiko,
        tidak pernah menurunkannya, dan diabaikan saat yang memindai
        adalah pemilik sah jangkar — lihat behavior._behavioral_signals().
        """
        now = now or datetime.now(timezone.utc)
        with self._lock:
            self.conn.execute(
                """UPDATE bindings
                   SET anomaly_attempts = anomaly_attempts + 1,
                       last_anomaly_at  = ?
                   WHERE id = ?""",
                (_iso(now), binding_id),
            )

    def seed_binding(
        self,
        nmid: str,
        lat: float,
        lng: float,
        merchant_name: str,
        observer_count: int,
        first_seen: datetime,
        last_seen: datetime,
    ) -> None:
        """Sisipkan binding dengan riwayat siap pakai, untuk demo."""
        gh7 = geo.encode(lat, lng, bd.INDEX_PRECISION)
        gh6 = geo.encode(lat, lng, bd.AREA_PRECISION)
        with self._lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO bindings
                   (nmid, lat, lng, geohash_7, geohash_6, merchant_name,
                    observer_count, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (nmid, lat, lng, gh7, gh6, merchant_name, observer_count,
                 _iso(first_seen), _iso(last_seen)),
            )
