"""tests/test_dashboard.py — Unit tests for the IDS Flask dashboard API.

Uses Flask's built-in test client and mock objects for all external
dependencies (alert_manager, log_store, ip_blocker).
"""

from __future__ import annotations

import collections
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from ids.dashboard import create_app
from ids.models import Alert, AttackType, Severity, SuspiciousIP


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_alert(
    id_="alert-1",
    timestamp="2024-01-15T10:30:00.000000Z",
    src_ip="192.168.1.1",
    attack_type=AttackType.PORT_SCAN,
    severity=Severity.MEDIUM,
    metadata=None,
) -> Alert:
    return Alert(
        id=id_,
        timestamp=timestamp,
        src_ip=src_ip,
        attack_type=attack_type,
        severity=severity,
        metadata=metadata or {"port_count": 25},
    )


def _make_suspicious_ip(
    ip_address="10.0.0.1",
    first_seen="2024-01-15T09:00:00.000000Z",
    last_seen="2024-01-15T10:30:00.000000Z",
    alert_count=3,
    attack_types=None,
) -> SuspiciousIP:
    return SuspiciousIP(
        ip_address=ip_address,
        first_seen=first_seen,
        last_seen=last_seen,
        alert_count=alert_count,
        attack_types=attack_types or [AttackType.PORT_SCAN],
    )


@dataclass
class _BlockResult:
    success: bool
    ip: str
    error_message: str | None = None


@pytest.fixture()
def alert_manager():
    """Mock AlertManager with a single alert in the ring buffer."""
    mock = MagicMock()
    mock.get_recent_alerts.return_value = [_make_alert()]
    return mock


@pytest.fixture()
def log_store():
    """Mock LogStore with one suspicious IP."""
    mock = MagicMock()
    mock.get_suspicious_ips.return_value = [_make_suspicious_ip()]
    return mock


@pytest.fixture()
def ip_blocker():
    """Mock IPBlocker that always succeeds."""
    mock = MagicMock()
    mock.block.return_value = _BlockResult(success=True, ip="1.2.3.4")
    mock.unblock.return_value = _BlockResult(success=True, ip="1.2.3.4")
    return mock


@pytest.fixture()
def client(alert_manager, log_store, ip_blocker):
    """Flask test client with all dependencies wired up and IDS ready."""
    stats = collections.deque([10.0, 20.0, 30.0], maxlen=60)
    app = create_app(
        alert_manager=alert_manager,
        log_store=log_store,
        stats_provider=stats,
        ip_blocker=ip_blocker,
        ready=True,
    )
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture()
def client_not_ready(alert_manager, log_store):
    """Flask test client where IDS is not yet ready (ready=False)."""
    app = create_app(
        alert_manager=alert_manager,
        log_store=log_store,
        ready=False,
    )
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture()
def client_no_blocker(alert_manager, log_store):
    """Flask test client without an IP blocker configured."""
    app = create_app(
        alert_manager=alert_manager,
        log_store=log_store,
        ip_blocker=None,
        ready=True,
    )
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# /api/health
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health_ok_when_ready(self, client):
        """GET /api/health returns 200 and {"status": "ok"} when ready=True."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data == {"status": "ok"}

    def test_health_503_when_not_ready(self, client_not_ready):
        """GET /api/health returns 503 and {"status": "starting"} when ready=False."""
        resp = client_not_ready.get("/api/health")
        assert resp.status_code == 503
        data = resp.get_json()
        assert data == {"status": "starting"}


# ---------------------------------------------------------------------------
# /api/stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_json_shape(self, client):
        """GET /api/stats returns correct JSON shape with expected keys."""
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_packets" in data
        assert "pps" in data
        assert "pps_history" in data

    def test_stats_values(self, client):
        """GET /api/stats returns correct computed values from the deque."""
        resp = client.get("/api/stats")
        data = resp.get_json()
        # deque was [10.0, 20.0, 30.0]
        assert data["total_packets"] == 60
        assert data["pps"] == 30.0
        assert data["pps_history"] == [10.0, 20.0, 30.0]

    def test_stats_empty_deque(self, alert_manager, log_store):
        """GET /api/stats returns zeros when the deque is empty."""
        app = create_app(
            alert_manager=alert_manager,
            log_store=log_store,
            stats_provider=collections.deque(maxlen=60),
            ready=True,
        )
        app.config["TESTING"] = True
        with app.test_client() as c:
            resp = c.get("/api/stats")
            data = resp.get_json()
            assert data["total_packets"] == 0
            assert data["pps"] == 0.0
            assert data["pps_history"] == []


# ---------------------------------------------------------------------------
# /api/alerts
# ---------------------------------------------------------------------------


class TestAlerts:
    def test_alerts_json_shape(self, client):
        """GET /api/alerts returns correct JSON envelope shape."""
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "alerts" in data
        assert "total" in data
        assert "page" in data
        assert "size" in data

    def test_alerts_default_pagination(self, client):
        """GET /api/alerts defaults to page=1, size=25."""
        resp = client.get("/api/alerts")
        data = resp.get_json()
        assert data["page"] == 1
        assert data["size"] == 25

    def test_alerts_returns_alert_fields(self, client):
        """Each alert in the response contains the required fields."""
        resp = client.get("/api/alerts")
        data = resp.get_json()
        assert len(data["alerts"]) == 1
        alert = data["alerts"][0]
        for field in ("id", "timestamp", "src_ip", "attack_type", "severity", "metadata"):
            assert field in alert, f"Missing field: {field}"

    def test_alerts_filter_by_src_ip(self, alert_manager, log_store, ip_blocker):
        """GET /api/alerts?q=<ip> filters results by src_ip."""
        alert_manager.get_recent_alerts.return_value = [
            _make_alert(id_="a1", src_ip="10.0.0.1"),
            _make_alert(id_="a2", src_ip="192.168.1.99"),
        ]
        app = create_app(
            alert_manager=alert_manager,
            log_store=log_store,
            ip_blocker=ip_blocker,
            ready=True,
        )
        app.config["TESTING"] = True
        with app.test_client() as c:
            resp = c.get("/api/alerts?q=10.0.0.1")
            data = resp.get_json()
            assert data["total"] == 1
            assert data["alerts"][0]["src_ip"] == "10.0.0.1"

    def test_alerts_filter_by_attack_type(self, alert_manager, log_store, ip_blocker):
        """GET /api/alerts?q=<type> filters results by attack_type."""
        alert_manager.get_recent_alerts.return_value = [
            _make_alert(id_="a1", attack_type=AttackType.PORT_SCAN),
            _make_alert(id_="a2", attack_type=AttackType.DOS),
        ]
        app = create_app(
            alert_manager=alert_manager,
            log_store=log_store,
            ip_blocker=ip_blocker,
            ready=True,
        )
        app.config["TESTING"] = True
        with app.test_client() as c:
            resp = c.get("/api/alerts?q=dos")
            data = resp.get_json()
            assert data["total"] == 1
            assert "DOS" in data["alerts"][0]["attack_type"]

    def test_alerts_pagination_page2(self, alert_manager, log_store, ip_blocker):
        """GET /api/alerts?page=2&size=1 returns the second alert."""
        alert_manager.get_recent_alerts.return_value = [
            _make_alert(id_="a1"),
            _make_alert(id_="a2"),
        ]
        app = create_app(
            alert_manager=alert_manager,
            log_store=log_store,
            ip_blocker=ip_blocker,
            ready=True,
        )
        app.config["TESTING"] = True
        with app.test_client() as c:
            resp = c.get("/api/alerts?page=2&size=1")
            data = resp.get_json()
            assert data["page"] == 2
            assert data["size"] == 1
            assert len(data["alerts"]) == 1
            assert data["alerts"][0]["id"] == "a2"


# ---------------------------------------------------------------------------
# /api/suspicious-ips
# ---------------------------------------------------------------------------


class TestSuspiciousIPs:
    def test_suspicious_ips_json_shape(self, client):
        """GET /api/suspicious-ips returns a list with correct field names."""
        resp = client.get("/api/suspicious-ips")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        entry = data[0]
        for field in ("ip_address", "first_seen", "last_seen", "alert_count", "attack_types"):
            assert field in entry, f"Missing field: {field}"

    def test_suspicious_ips_values(self, client):
        """GET /api/suspicious-ips returns correct values from log_store."""
        resp = client.get("/api/suspicious-ips")
        data = resp.get_json()
        entry = data[0]
        assert entry["ip_address"] == "10.0.0.1"
        assert entry["alert_count"] == 3
        assert "PORT_SCAN" in entry["attack_types"]

    def test_suspicious_ips_empty(self, alert_manager, log_store):
        """GET /api/suspicious-ips returns empty list when log_store has none."""
        log_store.get_suspicious_ips.return_value = []
        app = create_app(alert_manager=alert_manager, log_store=log_store, ready=True)
        app.config["TESTING"] = True
        with app.test_client() as c:
            resp = c.get("/api/suspicious-ips")
            assert resp.get_json() == []


# ---------------------------------------------------------------------------
# /api/block/<ip>
# ---------------------------------------------------------------------------


class TestBlockIP:
    def test_block_ip_success(self, client, ip_blocker):
        """POST /api/block/<ip> with ip_blocker enabled returns success."""
        resp = client.post("/api/block/1.2.3.4")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        ip_blocker.block.assert_called_once_with("1.2.3.4")

    def test_block_ip_no_blocker_returns_400(self, client_no_blocker):
        """POST /api/block/<ip> without ip_blocker returns HTTP 400."""
        resp = client_no_blocker.post("/api/block/1.2.3.4")
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["success"] is False
        assert "not enabled" in data["error"].lower()

    def test_block_ip_blocker_failure(self, alert_manager, log_store):
        """POST /api/block/<ip> propagates failure from ip_blocker."""
        failing_blocker = MagicMock()
        failing_blocker.block.return_value = _BlockResult(
            success=False, ip="1.2.3.4", error_message="Permission denied"
        )
        app = create_app(
            alert_manager=alert_manager,
            log_store=log_store,
            ip_blocker=failing_blocker,
            ready=True,
        )
        app.config["TESTING"] = True
        with app.test_client() as c:
            resp = c.post("/api/block/1.2.3.4")
            data = resp.get_json()
            assert data["success"] is False
            assert data["error"] == "Permission denied"


# ---------------------------------------------------------------------------
# /api/unblock/<ip>
# ---------------------------------------------------------------------------


class TestUnblockIP:
    def test_unblock_ip_success(self, client, ip_blocker):
        """POST /api/unblock/<ip> with ip_blocker enabled returns success."""
        resp = client.post("/api/unblock/1.2.3.4")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        ip_blocker.unblock.assert_called_once_with("1.2.3.4")

    def test_unblock_ip_no_blocker_returns_400(self, client_no_blocker):
        """POST /api/unblock/<ip> without ip_blocker returns HTTP 400."""
        resp = client_no_blocker.post("/api/unblock/1.2.3.4")
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["success"] is False
        assert "not enabled" in data["error"].lower()
