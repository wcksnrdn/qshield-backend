"""
Penyimpanan binding.

SQLite untuk PoC. Skema sengaja dibuat portabel ke Postgres:
tidak ada fitur khusus SQLite selain tipe kolom.

Catatan privasi — ini keputusan desain, bukan detail teknis:
  - tidak ada kolom user_id di mana pun
  - tabel observations tidak menyimpan koordinat, sehingga tidak
    bisa dipakai merekonstruksi pergerakan seseorang
  - device_anon_id hanya dipakai untuk menghitung pengamat unik
"""

import sqlite3
from datetime import datetime, timezone
from typing import Optional

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
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    UNIQUE (nmid, geohash_7)
);

CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    binding_id      INTEGER NOT NULL REFERENCES bindings(id),
    device_anon_id  TEXT    NOT NULL,
    observed_at     TEXT    NOT NULL,
    UNIQUE (binding_id, device_anon_id)
);

CREATE INDEX IF NOT EXISTS idx_bindings_gh7  ON bindings(geohash_7);
CREATE INDEX IF NOT EXISTS idx_bindings_nmid ON bindings(nmid);
"""


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
    )


class Store:
    def __init__(self, path: str = "qshield.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # --- pembacaan -------------------------------------------------

    def nearby(self, lat: float, lng: float) -> list:
        """Binding di sel indeks sekitar titik ini.

        Penyaringan jarak dilakukan di binding.evaluate(), bukan di sini.
        """
        cells = bd.index_cells(lat, lng)
        marks = ",".join("?" * len(cells))
        rows = self.conn.execute(
            f"SELECT * FROM bindings WHERE geohash_7 IN ({marks})", cells
        ).fetchall()
        return [_row_to_binding(r) for r in rows]

    def by_nmid(self, nmid: str) -> list:
        rows = self.conn.execute(
            "SELECT * FROM bindings WHERE nmid = ?", (nmid,)
        ).fetchall()
        return [_row_to_binding(r) for r in rows]

    def stats(self) -> dict:
        b = self.conn.execute("SELECT COUNT(*) c FROM bindings").fetchone()["c"]
        o = self.conn.execute("SELECT COUNT(*) c FROM observations").fetchone()["c"]
        n = self.conn.execute(
            "SELECT COUNT(DISTINCT nmid) c FROM bindings"
        ).fetchone()["c"]
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
        """Catat satu pengamatan. Idempoten per (binding, device)."""
        now = now or datetime.now(timezone.utc)
        gh7 = geo.encode(lat, lng, bd.INDEX_PRECISION)
        gh6 = geo.encode(lat, lng, bd.AREA_PRECISION)

        row = self.conn.execute(
            "SELECT * FROM bindings WHERE nmid = ? AND geohash_7 = ?", (nmid, gh7)
        ).fetchone()

        if row is None:
            cur = self.conn.execute(
                """INSERT INTO bindings
                   (nmid, lat, lng, geohash_7, geohash_6, merchant_name,
                    observer_count, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)""",
                (nmid, lat, lng, gh7, gh6, merchant_name, _iso(now), _iso(now)),
            )
            binding_id = cur.lastrowid
        else:
            binding_id = row["id"]
            self.conn.execute(
                "UPDATE bindings SET last_seen = ? WHERE id = ?",
                (_iso(now), binding_id),
            )
            if merchant_name and not row["merchant_name"]:
                self.conn.execute(
                    "UPDATE bindings SET merchant_name = ? WHERE id = ?",
                    (merchant_name, binding_id),
                )

        # Satu device hanya dihitung sekali per binding.
        inserted = self.conn.execute(
            """INSERT OR IGNORE INTO observations
               (binding_id, device_anon_id, observed_at) VALUES (?, ?, ?)""",
            (binding_id, device_anon_id, _iso(now)),
        ).rowcount

        if inserted:
            self.conn.execute(
                "UPDATE bindings SET observer_count = observer_count + 1 WHERE id = ?",
                (binding_id,),
            )

        self.conn.commit()
        row = self.conn.execute(
            "SELECT * FROM bindings WHERE id = ?", (binding_id,)
        ).fetchone()
        return _row_to_binding(row)

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
        self.conn.execute(
            """INSERT OR REPLACE INTO bindings
               (nmid, lat, lng, geohash_7, geohash_6, merchant_name,
                observer_count, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (nmid, lat, lng, gh7, gh6, merchant_name, observer_count,
             _iso(first_seen), _iso(last_seen)),
        )
        self.conn.commit()
