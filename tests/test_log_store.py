"""tests/test_log_store.py — Unit tests for ids/log_store.py.

All tests use an in-memory SQLite database (":memory:") so they are fast,
isolated, and leave no files on disk.
"""

from __future__ import annotations

import pytest

from ids.log_store import LogStore
from ids.models import Alert, AttackType, Severity, SuspiciousIP


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def store() -> LogStore:
    """Return a fresh in-memory LogStore for each test."""
    return LogStore(":memory:")


def make_alert(
    id: str = "alert-1",
    timestamp: str = "2024-01-15T10:00:00.000000Z",
    src_ip: str = "192.168.1.1",
    attack_type: AttackType = AttackType.PORT_SCAN,
    severity: Severity = Severity.MEDIUM,
    metadata: dict | None = None,
) -> Alert:
    return Alert(
        id=id,
        timestamp=timestamp,
        src_ip=src_ip,
        attack_type=attack_type,
        severity=severity,
        metadata=metadata if metadata is not None else {"port_count": 25, "ports_sampled": [80, 443]},
    )


# ---------------------------------------------------------------------------
# save_alert and retrieval
# ---------------------------------------------------------------------------


class TestSaveAlert:
    def test_save_and_retrieve_single_alert(self, store: LogStore) -> None:
        alert = make_alert()
        store.save_alert(alert)

        results = store.get_alerts()
        assert len(results) == 1
        retrieved = results[0]
        assert retrieved.id == alert.id
        assert retrieved.timestamp == alert.timestamp
        assert retrieved.src_ip == alert.src_ip
        assert retrieved.attack_type == alert.attack_type
        assert retrieved.severity == alert.severity
        assert retrieved.metadata == alert.metadata

    def test_metadata_round_trip(self, store: LogStore) -> None:
        """Metadata dict is serialised to JSON and deserialised back correctly."""
        meta = {"port_count": 42, "ports_sampled": [22, 80, 443, 8080]}
        alert = make_alert(metadata=meta)
        store.save_alert(alert)

        retrieved = store.get_alerts()[0]
        assert retrieved.metadata == meta

    def test_empty_metadata_round_trip(self, store: LogStore) -> None:
        alert = make_alert(metadata={})
        store.save_alert(alert)
        retrieved = store.get_alerts()[0]
        assert retrieved.metadata == {}

    def test_alerts_ordered_by_timestamp_desc(self, store: LogStore) -> None:
        a1 = make_alert(id="a1", timestamp="2024-01-15T10:00:00.000000Z")
        a2 = make_alert(id="a2", timestamp="2024-01-15T12:00:00.000000Z")
        a3 = make_alert(id="a3", timestamp="2024-01-15T11:00:00.000000Z")
        for a in (a1, a2, a3):
            store.save_alert(a)

        results = store.get_alerts()
        assert [r.id for r in results] == ["a2", "a3", "a1"]

    def test_get_alerts_limit(self, store: LogStore) -> None:
        for i in range(5):
            store.save_alert(make_alert(id=f"a{i}", timestamp=f"2024-01-15T{10+i:02d}:00:00.000000Z"))

        results = store.get_alerts(limit=3)
        assert len(results) == 3

    def test_get_alerts_offset(self, store: LogStore) -> None:
        for i in range(5):
            store.save_alert(make_alert(id=f"a{i}", timestamp=f"2024-01-15T{10+i:02d}:00:00.000000Z"))

        page1 = store.get_alerts(limit=2, offset=0)
        page2 = store.get_alerts(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        # Pages must not overlap.
        assert {r.id for r in page1}.isdisjoint({r.id for r in page2})

    def test_attack_type_and_severity_enums_preserved(self, store: LogStore) -> None:
        alert = make_alert(
            attack_type=AttackType.BRUTE_FORCE,
            severity=Severity.CRITICAL,
            metadata={"target_port": 22, "attempt_count": 60},
        )
        store.save_alert(alert)
        retrieved = store.get_alerts()[0]
        assert retrieved.attack_type is AttackType.BRUTE_FORCE
        assert retrieved.severity is Severity.CRITICAL


# ---------------------------------------------------------------------------
# get_alert_count
# ---------------------------------------------------------------------------


class TestGetAlertCount:
    def test_empty_store_returns_zero(self, store: LogStore) -> None:
        assert store.get_alert_count() == 0

    def test_count_increments_with_each_save(self, store: LogStore) -> None:
        for i in range(7):
            store.save_alert(make_alert(id=f"a{i}"))
        assert store.get_alert_count() == 7


# ---------------------------------------------------------------------------
# upsert_suspicious_ip — first insert
# ---------------------------------------------------------------------------


class TestUpsertSuspiciousIPFirstInsert:
    def test_first_insert_sets_all_fields(self, store: LogStore) -> None:
        alert = make_alert(
            src_ip="10.0.0.1",
            timestamp="2024-01-15T10:00:00.000000Z",
            attack_type=AttackType.PORT_SCAN,
        )
        store.upsert_suspicious_ip(alert)

        ips = store.get_suspicious_ips()
        assert len(ips) == 1
        ip = ips[0]
        assert ip.ip_address == "10.0.0.1"
        assert ip.first_seen == "2024-01-15T10:00:00.000000Z"
        assert ip.last_seen == "2024-01-15T10:00:00.000000Z"
        assert ip.alert_count == 1
        assert ip.attack_types == [AttackType.PORT_SCAN]


# ---------------------------------------------------------------------------
# upsert_suspicious_ip — subsequent updates
# ---------------------------------------------------------------------------


class TestUpsertSuspiciousIPUpdate:
    def test_alert_count_increments(self, store: LogStore) -> None:
        for i in range(3):
            store.upsert_suspicious_ip(
                make_alert(
                    id=f"a{i}",
                    src_ip="10.0.0.2",
                    timestamp=f"2024-01-15T{10+i:02d}:00:00.000000Z",
                )
            )
        ip = store.get_suspicious_ips()[0]
        assert ip.alert_count == 3

    def test_last_seen_advances_to_latest_timestamp(self, store: LogStore) -> None:
        store.upsert_suspicious_ip(make_alert(src_ip="10.0.0.3", timestamp="2024-01-15T10:00:00.000000Z"))
        store.upsert_suspicious_ip(make_alert(src_ip="10.0.0.3", timestamp="2024-01-15T12:00:00.000000Z"))
        store.upsert_suspicious_ip(make_alert(src_ip="10.0.0.3", timestamp="2024-01-15T11:00:00.000000Z"))

        ip = store.get_suspicious_ips()[0]
        assert ip.last_seen == "2024-01-15T12:00:00.000000Z"

    def test_first_seen_is_preserved(self, store: LogStore) -> None:
        store.upsert_suspicious_ip(make_alert(src_ip="10.0.0.4", timestamp="2024-01-15T10:00:00.000000Z"))
        store.upsert_suspicious_ip(make_alert(src_ip="10.0.0.4", timestamp="2024-01-15T12:00:00.000000Z"))

        ip = store.get_suspicious_ips()[0]
        assert ip.first_seen == "2024-01-15T10:00:00.000000Z"

    def test_attack_types_deduplication(self, store: LogStore) -> None:
        """Inserting the same attack type multiple times must not create duplicates."""
        for _ in range(3):
            store.upsert_suspicious_ip(
                make_alert(src_ip="10.0.0.5", attack_type=AttackType.PORT_SCAN)
            )
        ip = store.get_suspicious_ips()[0]
        assert ip.attack_types.count(AttackType.PORT_SCAN) == 1

    def test_attack_types_merged_without_duplicates(self, store: LogStore) -> None:
        """Different attack types from the same IP are all recorded exactly once."""
        store.upsert_suspicious_ip(
            make_alert(src_ip="10.0.0.6", attack_type=AttackType.PORT_SCAN)
        )
        store.upsert_suspicious_ip(
            make_alert(src_ip="10.0.0.6", attack_type=AttackType.BRUTE_FORCE)
        )
        store.upsert_suspicious_ip(
            make_alert(src_ip="10.0.0.6", attack_type=AttackType.PORT_SCAN)
        )
        store.upsert_suspicious_ip(
            make_alert(src_ip="10.0.0.6", attack_type=AttackType.DOS)
        )

        ip = store.get_suspicious_ips()[0]
        assert set(ip.attack_types) == {AttackType.PORT_SCAN, AttackType.BRUTE_FORCE, AttackType.DOS}
        assert len(ip.attack_types) == 3  # no duplicates


# ---------------------------------------------------------------------------
# get_suspicious_ips ordering
# ---------------------------------------------------------------------------


class TestGetSuspiciousIPsOrdering:
    def test_ordered_by_alert_count_desc(self, store: LogStore) -> None:
        # IP A: 1 alert, IP B: 3 alerts, IP C: 2 alerts
        store.upsert_suspicious_ip(make_alert(src_ip="10.0.1.1"))

        for _ in range(3):
            store.upsert_suspicious_ip(make_alert(src_ip="10.0.1.2"))

        for _ in range(2):
            store.upsert_suspicious_ip(make_alert(src_ip="10.0.1.3"))

        ips = store.get_suspicious_ips()
        assert [ip.ip_address for ip in ips] == ["10.0.1.2", "10.0.1.3", "10.0.1.1"]
        assert [ip.alert_count for ip in ips] == [3, 2, 1]

    def test_empty_store_returns_empty_list(self, store: LogStore) -> None:
        assert store.get_suspicious_ips() == []


# ---------------------------------------------------------------------------
# flush
# ---------------------------------------------------------------------------


class TestFlush:
    def test_flush_closes_connection(self, store: LogStore) -> None:
        """After flush(), the connection is closed; further queries should raise."""
        store.save_alert(make_alert())
        store.flush()

        with pytest.raises(Exception):
            store.get_alert_count()
