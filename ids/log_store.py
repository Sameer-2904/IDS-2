"""ids/log_store.py — SQLite persistence layer for the Network IDS.

Stores Alert records and SuspiciousIP aggregates using Python's built-in
sqlite3 module.  WAL journal mode is enabled for better concurrency.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Optional

from ids.models import Alert, AttackType, Severity, SuspiciousIP

# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    severity    TEXT NOT NULL,
    metadata    TEXT
);
"""

_CREATE_SUSPICIOUS_IPS = """
CREATE TABLE IF NOT EXISTS suspicious_ips (
    ip_address      TEXT PRIMARY KEY,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    alert_count     INTEGER NOT NULL DEFAULT 1,
    attack_types    TEXT NOT NULL
);
"""


class LogStore:
    """SQLite-backed persistence layer.

    Parameters
    ----------
    db_path:
        Filesystem path to the SQLite database file, or ``":memory:"`` for an
        in-memory database (useful in tests).
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrent read/write performance.
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(_CREATE_ALERTS)
        self._conn.execute(_CREATE_SUSPICIOUS_IPS)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def save_alert(self, alert: Alert) -> None:
        """INSERT a new alert row.

        ``metadata`` is serialised as a JSON string.
        """
        self._conn.execute(
            """
            INSERT INTO alerts (id, timestamp, src_ip, attack_type, severity, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                alert.id,
                alert.timestamp,
                alert.src_ip,
                alert.attack_type.value if isinstance(alert.attack_type, AttackType) else alert.attack_type,
                alert.severity.value if isinstance(alert.severity, Severity) else alert.severity,
                json.dumps(alert.metadata),
            ),
        )
        self._conn.commit()

    def upsert_suspicious_ip(self, alert: Alert) -> None:
        """Insert or update the SuspiciousIP record for ``alert.src_ip``.

        On first insert:
            - ``first_seen`` and ``last_seen`` are set to ``alert.timestamp``
            - ``alert_count`` is 1
            - ``attack_types`` is ``[alert.attack_type]``

        On subsequent updates:
            - ``last_seen`` is updated only if ``alert.timestamp`` is newer
            - ``alert_count`` is incremented by 1
            - ``attack_types`` is merged (no duplicates)
        """
        attack_type_value = (
            alert.attack_type.value
            if isinstance(alert.attack_type, AttackType)
            else alert.attack_type
        )

        row = self._conn.execute(
            "SELECT first_seen, last_seen, alert_count, attack_types FROM suspicious_ips WHERE ip_address = ?",
            (alert.src_ip,),
        ).fetchone()

        if row is None:
            # First time we see this IP.
            self._conn.execute(
                """
                INSERT INTO suspicious_ips (ip_address, first_seen, last_seen, alert_count, attack_types)
                VALUES (?, ?, ?, 1, ?)
                """,
                (
                    alert.src_ip,
                    alert.timestamp,
                    alert.timestamp,
                    json.dumps([attack_type_value]),
                ),
            )
        else:
            # Merge with existing record.
            existing_types: list[str] = json.loads(row["attack_types"])
            if attack_type_value not in existing_types:
                existing_types.append(attack_type_value)

            # Keep the earlier first_seen; advance last_seen if newer.
            first_seen = row["first_seen"]
            last_seen = row["last_seen"] if row["last_seen"] > alert.timestamp else alert.timestamp

            self._conn.execute(
                """
                UPDATE suspicious_ips
                SET last_seen = ?, alert_count = ?, attack_types = ?
                WHERE ip_address = ?
                """,
                (
                    last_seen,
                    row["alert_count"] + 1,
                    json.dumps(existing_types),
                    alert.src_ip,
                ),
            )

        self._conn.commit()

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_alerts(self, limit: int = 50, offset: int = 0) -> list[Alert]:
        """Return alerts ordered by timestamp DESC.

        Parameters
        ----------
        limit:
            Maximum number of rows to return.
        offset:
            Number of rows to skip (for pagination).
        """
        rows = self._conn.execute(
            """
            SELECT id, timestamp, src_ip, attack_type, severity, metadata
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

        return [_row_to_alert(row) for row in rows]

    def get_alert_count(self) -> int:
        """Return the total number of alert rows in the database."""
        row = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
        return row[0]

    def get_suspicious_ips(self) -> list[SuspiciousIP]:
        """Return all SuspiciousIP records ordered by alert_count DESC."""
        rows = self._conn.execute(
            """
            SELECT ip_address, first_seen, last_seen, alert_count, attack_types
            FROM suspicious_ips
            ORDER BY alert_count DESC
            """,
        ).fetchall()

        return [_row_to_suspicious_ip(row) for row in rows]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def flush(self) -> None:
        """Execute a WAL checkpoint and close the database connection cleanly."""
        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        self._conn.commit()
        self._conn.close()


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _row_to_alert(row: sqlite3.Row) -> Alert:
    """Convert a raw SQLite row to an Alert dataclass instance."""
    return Alert(
        id=row["id"],
        timestamp=row["timestamp"],
        src_ip=row["src_ip"],
        attack_type=AttackType(row["attack_type"]),
        severity=Severity(row["severity"]),
        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
    )


def _row_to_suspicious_ip(row: sqlite3.Row) -> SuspiciousIP:
    """Convert a raw SQLite row to a SuspiciousIP dataclass instance."""
    raw_types: list[str] = json.loads(row["attack_types"])
    return SuspiciousIP(
        ip_address=row["ip_address"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        alert_count=row["alert_count"],
        attack_types=[AttackType(t) for t in raw_types],
    )
