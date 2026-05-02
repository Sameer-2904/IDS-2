"""tests/test_detection.py — Unit tests for ids/detection.py.

Tests cover PortScanDetector behaviour:
- No alert when port count <= threshold
- Alert raised when port count > threshold
- Alert contains correct src_ip and port_count in metadata
- Alert not emitted twice for the same window
- tick() resets counters so a new window counts independently
- Severity mapping (< 50 ports → MEDIUM, >= 50 ports → HIGH)
"""

from __future__ import annotations

import pytest

from ids.detection import PortScanDetector
from ids.models import AttackType, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockPacket:
    """Minimal packet mock that exposes a single ``dport`` attribute."""

    def __init__(self, dport: int) -> None:
        self.dport = dport


class MockPacketNoPort:
    """Packet mock with no port information."""
    pass


def _feed_ports(detector: PortScanDetector, src_ip: str, ports: list[int], now: float = 0.0):
    """Feed a list of destination ports through the detector and return all alerts."""
    alerts = []
    for port in ports:
        pkt = MockPacket(port)
        result = detector.process(pkt, src_ip, now)
        if result is not None:
            alerts.append(result)
    return alerts


# ---------------------------------------------------------------------------
# No alert when port count <= threshold
# ---------------------------------------------------------------------------

def test_no_alert_below_threshold():
    """Exactly threshold distinct ports should NOT trigger an alert."""
    threshold = 5
    detector = PortScanDetector(threshold=threshold, window_seconds=10)
    alerts = _feed_ports(detector, "10.0.0.1", list(range(1, threshold + 1)))
    assert alerts == []


def test_no_alert_single_port():
    """A single port contact should never trigger an alert."""
    detector = PortScanDetector(threshold=3, window_seconds=10)
    alerts = _feed_ports(detector, "10.0.0.1", [80])
    assert alerts == []


def test_no_alert_repeated_same_port():
    """Repeated contacts to the same port count as one distinct port."""
    detector = PortScanDetector(threshold=3, window_seconds=10)
    alerts = _feed_ports(detector, "10.0.0.1", [80, 80, 80, 80, 80])
    assert alerts == []


def test_no_alert_packet_without_port():
    """Packets with no port information should be silently ignored."""
    detector = PortScanDetector(threshold=2, window_seconds=10)
    pkt = MockPacketNoPort()
    result = detector.process(pkt, "10.0.0.1", 0.0)
    assert result is None


# ---------------------------------------------------------------------------
# Alert raised when port count > threshold
# ---------------------------------------------------------------------------

def test_alert_raised_above_threshold():
    """threshold + 1 distinct ports should trigger exactly one alert."""
    threshold = 5
    detector = PortScanDetector(threshold=threshold, window_seconds=10)
    alerts = _feed_ports(detector, "10.0.0.1", list(range(1, threshold + 2)))
    assert len(alerts) == 1


def test_alert_attack_type():
    """The alert attack_type must be PORT_SCAN."""
    detector = PortScanDetector(threshold=3, window_seconds=10)
    alerts = _feed_ports(detector, "10.0.0.1", [1, 2, 3, 4])
    assert len(alerts) == 1
    assert alerts[0].attack_type == AttackType.PORT_SCAN


# ---------------------------------------------------------------------------
# Alert contains correct src_ip and port_count in metadata
# ---------------------------------------------------------------------------

def test_alert_src_ip():
    """Alert src_ip must match the source IP passed to process()."""
    src_ip = "192.168.1.42"
    detector = PortScanDetector(threshold=2, window_seconds=10)
    alerts = _feed_ports(detector, src_ip, [10, 20, 30])
    assert len(alerts) == 1
    assert alerts[0].src_ip == src_ip


def test_alert_metadata_port_count():
    """Alert metadata must contain the correct port_count."""
    threshold = 3
    detector = PortScanDetector(threshold=threshold, window_seconds=10)
    ports = list(range(1, threshold + 2))  # threshold + 1 distinct ports
    alerts = _feed_ports(detector, "10.0.0.1", ports)
    assert len(alerts) == 1
    assert alerts[0].metadata["port_count"] == threshold + 1


def test_alert_metadata_ports_sampled_present():
    """Alert metadata must contain a ports_sampled list."""
    detector = PortScanDetector(threshold=2, window_seconds=10)
    alerts = _feed_ports(detector, "10.0.0.1", [1, 2, 3])
    assert len(alerts) == 1
    assert "ports_sampled" in alerts[0].metadata
    assert isinstance(alerts[0].metadata["ports_sampled"], list)


def test_alert_metadata_ports_sampled_capped_at_10():
    """ports_sampled must contain at most 10 entries."""
    detector = PortScanDetector(threshold=5, window_seconds=10)
    # Feed 20 distinct ports
    alerts = _feed_ports(detector, "10.0.0.1", list(range(1, 21)))
    assert len(alerts) == 1
    assert len(alerts[0].metadata["ports_sampled"]) <= 10


def test_alert_id_is_empty_string():
    """Alert id must be empty string (AlertManager assigns it later)."""
    detector = PortScanDetector(threshold=2, window_seconds=10)
    alerts = _feed_ports(detector, "10.0.0.1", [1, 2, 3])
    assert alerts[0].id == ""


def test_alert_timestamp_format():
    """Alert timestamp must be an ISO 8601 UTC string ending with 'Z'."""
    detector = PortScanDetector(threshold=2, window_seconds=10)
    alerts = _feed_ports(detector, "10.0.0.1", [1, 2, 3], now=1_700_000_000.0)
    assert alerts[0].timestamp.endswith("Z")


# ---------------------------------------------------------------------------
# Alert not emitted twice for the same window
# ---------------------------------------------------------------------------

def test_alert_not_emitted_twice_same_window():
    """Only one alert should be emitted per source IP per window."""
    threshold = 3
    detector = PortScanDetector(threshold=threshold, window_seconds=10)
    # Feed many more ports than the threshold
    alerts = _feed_ports(detector, "10.0.0.1", list(range(1, 20)))
    assert len(alerts) == 1


def test_alert_not_emitted_twice_multiple_ips():
    """Each source IP gets its own independent alert (one per IP per window)."""
    threshold = 2
    detector = PortScanDetector(threshold=threshold, window_seconds=10)
    alerts_a = _feed_ports(detector, "10.0.0.1", [1, 2, 3])
    alerts_b = _feed_ports(detector, "10.0.0.2", [4, 5, 6])
    assert len(alerts_a) == 1
    assert len(alerts_b) == 1
    assert alerts_a[0].src_ip == "10.0.0.1"
    assert alerts_b[0].src_ip == "10.0.0.2"


# ---------------------------------------------------------------------------
# tick() resets counters so new window counts independently
# ---------------------------------------------------------------------------

def test_tick_expires_window():
    """After tick() expires a window, the per-IP counter resets to zero."""
    threshold = 3
    window = 10
    detector = PortScanDetector(threshold=threshold, window_seconds=window)

    # First window: feed threshold ports (no alert)
    _feed_ports(detector, "10.0.0.1", list(range(1, threshold + 1)), now=0.0)

    # Advance time past the window and call tick
    detector.tick(now=float(window))

    # Second window: feed threshold + 1 ports — should trigger a fresh alert
    alerts = _feed_ports(detector, "10.0.0.1", list(range(100, 100 + threshold + 1)), now=float(window))
    assert len(alerts) == 1


def test_tick_returns_empty_list():
    """tick() must always return an empty list for PortScanDetector."""
    detector = PortScanDetector(threshold=5, window_seconds=10)
    _feed_ports(detector, "10.0.0.1", list(range(1, 10)), now=0.0)
    result = detector.tick(now=20.0)
    assert result == []


def test_tick_does_not_expire_active_window():
    """tick() must not expire a window that has not yet elapsed."""
    threshold = 3
    window = 10
    detector = PortScanDetector(threshold=threshold, window_seconds=window)

    # Feed threshold ports (no alert yet)
    _feed_ports(detector, "10.0.0.1", list(range(1, threshold + 1)), now=0.0)

    # Tick at time < window_seconds — window should NOT be expired
    detector.tick(now=5.0)

    # One more port should still trigger an alert (counter was not reset)
    alerts = _feed_ports(detector, "10.0.0.1", [999], now=5.0)
    assert len(alerts) == 1


def test_tick_alert_can_fire_again_after_reset():
    """After window expiry, a new scan from the same IP should produce a new alert."""
    threshold = 2
    window = 10
    detector = PortScanDetector(threshold=threshold, window_seconds=window)

    # First window: trigger alert
    alerts1 = _feed_ports(detector, "10.0.0.1", [1, 2, 3], now=0.0)
    assert len(alerts1) == 1

    # Expire the window
    detector.tick(now=float(window))

    # Second window: trigger another alert
    alerts2 = _feed_ports(detector, "10.0.0.1", [10, 20, 30], now=float(window))
    assert len(alerts2) == 1


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def test_severity_medium_below_50_ports():
    """port_count < 50 should produce MEDIUM severity."""
    threshold = 10
    detector = PortScanDetector(threshold=threshold, window_seconds=10)
    # Feed 11 distinct ports (> threshold, < 50)
    alerts = _feed_ports(detector, "10.0.0.1", list(range(1, 12)))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM


def test_severity_high_at_50_ports():
    """port_count == 50 should produce HIGH severity.

    The alert fires when port_count first exceeds the threshold.  To ensure
    the alert fires at exactly 50 ports we set threshold=49 so the 50th
    distinct port triggers the alert.
    """
    threshold = 49  # alert fires when port_count reaches 50
    detector = PortScanDetector(threshold=threshold, window_seconds=10)
    # Feed exactly 50 distinct ports
    alerts = _feed_ports(detector, "10.0.0.1", list(range(1, 51)))
    assert len(alerts) == 1
    assert alerts[0].metadata["port_count"] == 50
    assert alerts[0].severity == Severity.HIGH


def test_severity_high_above_50_ports():
    """port_count > 50 should produce HIGH severity.

    Set threshold=49 so the alert fires at port 50 (port_count=50 ≥ 50 → HIGH).
    """
    threshold = 49
    detector = PortScanDetector(threshold=threshold, window_seconds=10)
    alerts = _feed_ports(detector, "10.0.0.1", list(range(1, 60)))
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Payload-nested port extraction
# ---------------------------------------------------------------------------

def test_port_extracted_from_payload():
    """Ports nested one level deep (packet.payload.dport) should be extracted."""

    def make_payload_packet(dport: int):
        """Create a packet that has no direct dport but has payload.dport."""
        class InnerLayer:
            pass
        class OuterPacket:
            pass
        inner = InnerLayer()
        inner.dport = dport
        outer = OuterPacket()
        outer.payload = inner
        return outer

    # threshold=2: alert fires when 3rd distinct port is seen
    detector = PortScanDetector(threshold=2, window_seconds=10)

    result1 = detector.process(make_payload_packet(443), "10.0.0.1", 0.0)
    assert result1 is None  # 1 port, not > 2

    result2 = detector.process(make_payload_packet(80), "10.0.0.1", 0.0)
    assert result2 is None  # 2 ports, not > 2

    # Third distinct port via payload nesting → alert fires
    result3 = detector.process(make_payload_packet(8080), "10.0.0.1", 0.0)
    assert result3 is not None
    assert result3.attack_type == AttackType.PORT_SCAN
    assert result3.metadata["port_count"] == 3


# ===========================================================================
# BruteForceDetector tests
# ===========================================================================

from ids.detection import BruteForceDetector  # noqa: E402 (appended section)


class MockSynPacket:
    """Mock TCP SYN packet with direct ``flags`` and ``dport`` attributes."""

    SYN = 0x02

    def __init__(self, dport: int, flags: int = 0x02) -> None:
        self.dport = dport
        self.flags = flags


class MockNonSynPacket:
    """Mock TCP packet with SYN flag cleared (ACK only, for example)."""

    def __init__(self, dport: int) -> None:
        self.dport = dport
        self.flags = 0x10  # ACK, not SYN


class MockNoFlagsPacket:
    """Mock packet with no TCP attributes at all."""
    pass


def _feed_syns(
    detector: BruteForceDetector,
    src_ip: str,
    dport: int,
    count: int,
    now: float = 0.0,
) -> list:
    """Send *count* SYN packets to *dport* from *src_ip* and collect alerts."""
    alerts = []
    for _ in range(count):
        pkt = MockSynPacket(dport)
        result = detector.process(pkt, src_ip, now)
        if result is not None:
            alerts.append(result)
    return alerts


# ---------------------------------------------------------------------------
# No alert for non-SYN packets
# ---------------------------------------------------------------------------

def test_brute_force_no_alert_non_syn():
    """Non-SYN packets must never trigger a BRUTE_FORCE alert."""
    detector = BruteForceDetector(threshold=3, window_seconds=10, monitored_ports=[22])
    for _ in range(100):
        pkt = MockNonSynPacket(22)
        assert detector.process(pkt, "10.0.0.1", 0.0) is None


def test_brute_force_no_alert_no_flags():
    """Packets with no TCP attributes must be silently ignored."""
    detector = BruteForceDetector(threshold=3, window_seconds=10, monitored_ports=[22])
    pkt = MockNoFlagsPacket()
    assert detector.process(pkt, "10.0.0.1", 0.0) is None


# ---------------------------------------------------------------------------
# No alert for SYN to non-monitored port
# ---------------------------------------------------------------------------

def test_brute_force_no_alert_unmonitored_port():
    """SYN packets to a port not in monitored_ports must be ignored."""
    detector = BruteForceDetector(threshold=3, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=80, count=100)
    assert alerts == []


def test_brute_force_no_alert_empty_monitored_ports():
    """With an empty monitored_ports list, no alert should ever fire."""
    detector = BruteForceDetector(threshold=3, window_seconds=10, monitored_ports=[])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=100)
    assert alerts == []


# ---------------------------------------------------------------------------
# No alert when count <= threshold
# ---------------------------------------------------------------------------

def test_brute_force_no_alert_at_threshold():
    """Exactly threshold SYN packets must NOT trigger an alert."""
    threshold = 5
    detector = BruteForceDetector(threshold=threshold, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=threshold)
    assert alerts == []


def test_brute_force_no_alert_single_syn():
    """A single SYN packet should never trigger an alert."""
    detector = BruteForceDetector(threshold=3, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=1)
    assert alerts == []


# ---------------------------------------------------------------------------
# Alert raised when count > threshold
# ---------------------------------------------------------------------------

def test_brute_force_alert_above_threshold():
    """threshold + 1 SYN packets should trigger exactly one alert."""
    threshold = 5
    detector = BruteForceDetector(threshold=threshold, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=threshold + 1)
    assert len(alerts) == 1


def test_brute_force_alert_attack_type():
    """The alert attack_type must be BRUTE_FORCE."""
    detector = BruteForceDetector(threshold=3, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=4)
    assert len(alerts) == 1
    assert alerts[0].attack_type == AttackType.BRUTE_FORCE


# ---------------------------------------------------------------------------
# Alert contains correct src_ip, target_port, attempt_count
# ---------------------------------------------------------------------------

def test_brute_force_alert_src_ip():
    """Alert src_ip must match the source IP passed to process()."""
    src_ip = "192.168.1.99"
    detector = BruteForceDetector(threshold=2, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, src_ip, dport=22, count=3)
    assert len(alerts) == 1
    assert alerts[0].src_ip == src_ip


def test_brute_force_alert_target_port():
    """Alert metadata must contain the correct target_port."""
    detector = BruteForceDetector(threshold=2, window_seconds=10, monitored_ports=[22, 3389])
    alerts = _feed_syns(detector, "10.0.0.1", dport=3389, count=3)
    assert len(alerts) == 1
    assert alerts[0].metadata["target_port"] == 3389


def test_brute_force_alert_attempt_count():
    """Alert metadata must contain the correct attempt_count."""
    threshold = 3
    detector = BruteForceDetector(threshold=threshold, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=threshold + 1)
    assert len(alerts) == 1
    assert alerts[0].metadata["attempt_count"] == threshold + 1


def test_brute_force_alert_id_is_empty_string():
    """Alert id must be empty string (AlertManager assigns it later)."""
    detector = BruteForceDetector(threshold=2, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=3)
    assert alerts[0].id == ""


def test_brute_force_alert_timestamp_format():
    """Alert timestamp must be an ISO 8601 UTC string ending with 'Z'."""
    detector = BruteForceDetector(threshold=2, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=3, now=1_700_000_000.0)
    assert alerts[0].timestamp.endswith("Z")


# ---------------------------------------------------------------------------
# Alert not emitted twice for same (src_ip, port) in same window
# ---------------------------------------------------------------------------

def test_brute_force_alert_not_emitted_twice_same_window():
    """Only one alert per (src_ip, port) per window."""
    threshold = 3
    detector = BruteForceDetector(threshold=threshold, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=50)
    assert len(alerts) == 1


def test_brute_force_independent_ports_each_get_alert():
    """Each monitored port gets its own independent alert."""
    threshold = 2
    detector = BruteForceDetector(
        threshold=threshold, window_seconds=10, monitored_ports=[22, 3389]
    )
    alerts_22 = _feed_syns(detector, "10.0.0.1", dport=22, count=threshold + 1)
    alerts_3389 = _feed_syns(detector, "10.0.0.1", dport=3389, count=threshold + 1)
    assert len(alerts_22) == 1
    assert len(alerts_3389) == 1
    assert alerts_22[0].metadata["target_port"] == 22
    assert alerts_3389[0].metadata["target_port"] == 3389


def test_brute_force_independent_ips_each_get_alert():
    """Each source IP gets its own independent alert."""
    threshold = 2
    detector = BruteForceDetector(threshold=threshold, window_seconds=10, monitored_ports=[22])
    alerts_a = _feed_syns(detector, "10.0.0.1", dport=22, count=threshold + 1)
    alerts_b = _feed_syns(detector, "10.0.0.2", dport=22, count=threshold + 1)
    assert len(alerts_a) == 1
    assert len(alerts_b) == 1
    assert alerts_a[0].src_ip == "10.0.0.1"
    assert alerts_b[0].src_ip == "10.0.0.2"


# ---------------------------------------------------------------------------
# tick() resets counters
# ---------------------------------------------------------------------------

def test_brute_force_tick_expires_window():
    """After tick() expires a window, the per-IP counter resets to zero."""
    threshold = 3
    window = 10
    detector = BruteForceDetector(
        threshold=threshold, window_seconds=window, monitored_ports=[22]
    )

    # First window: feed threshold SYNs (no alert)
    _feed_syns(detector, "10.0.0.1", dport=22, count=threshold, now=0.0)

    # Advance time past the window and call tick
    detector.tick(now=float(window))

    # Second window: feed threshold + 1 SYNs — should trigger a fresh alert
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=threshold + 1, now=float(window))
    assert len(alerts) == 1


def test_brute_force_tick_returns_empty_list():
    """tick() must always return an empty list for BruteForceDetector."""
    detector = BruteForceDetector(threshold=3, window_seconds=10, monitored_ports=[22])
    _feed_syns(detector, "10.0.0.1", dport=22, count=10, now=0.0)
    result = detector.tick(now=20.0)
    assert result == []


def test_brute_force_tick_does_not_expire_active_window():
    """tick() must not expire a window that has not yet elapsed."""
    threshold = 3
    window = 10
    detector = BruteForceDetector(
        threshold=threshold, window_seconds=window, monitored_ports=[22]
    )

    # Feed threshold SYNs (no alert yet)
    _feed_syns(detector, "10.0.0.1", dport=22, count=threshold, now=0.0)

    # Tick at time < window_seconds — window should NOT be expired
    detector.tick(now=5.0)

    # One more SYN should still trigger an alert (counter was not reset)
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=1, now=5.0)
    assert len(alerts) == 1


def test_brute_force_tick_alert_can_fire_again_after_reset():
    """After window expiry, a new brute-force from the same IP should produce a new alert."""
    threshold = 2
    window = 10
    detector = BruteForceDetector(
        threshold=threshold, window_seconds=window, monitored_ports=[22]
    )

    # First window: trigger alert
    alerts1 = _feed_syns(detector, "10.0.0.1", dport=22, count=threshold + 1, now=0.0)
    assert len(alerts1) == 1

    # Expire the window
    detector.tick(now=float(window))

    # Second window: trigger another alert
    alerts2 = _feed_syns(detector, "10.0.0.1", dport=22, count=threshold + 1, now=float(window))
    assert len(alerts2) == 1


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def test_brute_force_severity_high_below_50():
    """attempt_count < 50 should produce HIGH severity."""
    threshold = 10
    detector = BruteForceDetector(threshold=threshold, window_seconds=10, monitored_ports=[22])
    # Feed 11 SYNs (> threshold, < 50)
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=11)
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


def test_brute_force_severity_critical_at_50():
    """attempt_count == 50 should produce CRITICAL severity.

    Set threshold=49 so the alert fires exactly when count reaches 50.
    """
    threshold = 49
    detector = BruteForceDetector(threshold=threshold, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=50)
    assert len(alerts) == 1
    assert alerts[0].metadata["attempt_count"] == 50
    assert alerts[0].severity == Severity.CRITICAL


def test_brute_force_severity_critical_above_50():
    """attempt_count > 50 should produce CRITICAL severity."""
    threshold = 49
    detector = BruteForceDetector(threshold=threshold, window_seconds=10, monitored_ports=[22])
    alerts = _feed_syns(detector, "10.0.0.1", dport=22, count=60)
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


# ===========================================================================
# DoSDetector tests
# ===========================================================================

from ids.detection import DoSDetector  # noqa: E402 (appended section)


class MockDoSPacket:
    """Minimal packet mock for DoS testing — content is irrelevant."""
    pass


def _send_packets(
    detector: DoSDetector,
    src_ip: str,
    count: int,
    now: float,
) -> list:
    """Send *count* packets from *src_ip* at timestamp *now* and collect alerts."""
    alerts = []
    for _ in range(count):
        result = detector.process(MockDoSPacket(), src_ip, now)
        if result is not None:
            alerts.append(result)
    return alerts


def _simulate_seconds(
    detector: DoSDetector,
    src_ip: str,
    packets_per_second: list[int],
    start_time: float = 0.0,
) -> list:
    """Simulate multiple seconds of traffic and collect all alerts.

    Parameters
    ----------
    packets_per_second:
        List where index i is the number of packets to send during second i.
    start_time:
        POSIX timestamp for second 0.
    """
    alerts = []
    for i, count in enumerate(packets_per_second):
        now = start_time + float(i)
        for _ in range(count):
            result = detector.process(MockDoSPacket(), src_ip, now)
            if result is not None:
                alerts.append(result)
    return alerts


# ---------------------------------------------------------------------------
# No alert for a single burst below consecutive_intervals
# ---------------------------------------------------------------------------

def test_dos_no_alert_single_burst_below_consecutive():
    """A burst exceeding threshold for fewer than consecutive_intervals seconds must not alert."""
    threshold = 10
    consecutive = 3
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=consecutive)

    # Exceed threshold for only 2 consecutive seconds (< consecutive_intervals=3)
    # Second 0: 11 packets (> 10 threshold) — evaluated when second 1 starts
    # Second 1: 11 packets (> 10 threshold) — evaluated when second 2 starts
    # Second 2: 1 packet  — triggers evaluation of second 1, consecutive=2 < 3
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 1])
    assert alerts == []


def test_dos_no_alert_below_threshold():
    """Packets below threshold_pps should never trigger an alert."""
    threshold = 100
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=3)
    # Send 50 packets per second for 5 seconds — always below threshold
    alerts = _simulate_seconds(detector, "10.0.0.1", [50, 50, 50, 50, 50])
    assert alerts == []


# ---------------------------------------------------------------------------
# Alert raised when threshold exceeded for >= consecutive_intervals consecutive seconds
# ---------------------------------------------------------------------------

def test_dos_alert_raised_after_consecutive_intervals():
    """Alert must fire when threshold exceeded for exactly consecutive_intervals seconds."""
    threshold = 10
    consecutive = 3
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=consecutive)

    # Exceed threshold for 3 consecutive seconds, then send 1 packet in second 3
    # to trigger evaluation of second 2 (completing the 3rd consecutive interval)
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 1])
    assert len(alerts) == 1


def test_dos_alert_attack_type():
    """The alert attack_type must be DOS."""
    threshold = 10
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=3)
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 1])
    assert len(alerts) == 1
    assert alerts[0].attack_type == AttackType.DOS


def test_dos_alert_src_ip():
    """Alert src_ip must match the source IP passed to process()."""
    src_ip = "192.168.5.10"
    detector = DoSDetector(threshold_pps=10, window_seconds=10, consecutive_intervals=3)
    alerts = _simulate_seconds(detector, src_ip, [11, 11, 11, 1])
    assert len(alerts) == 1
    assert alerts[0].src_ip == src_ip


def test_dos_alert_metadata_window_seconds():
    """Alert metadata must contain the correct window_seconds."""
    window = 15
    detector = DoSDetector(threshold_pps=10, window_seconds=window, consecutive_intervals=3)
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 1])
    assert len(alerts) == 1
    assert alerts[0].metadata["window_seconds"] == window


def test_dos_alert_metadata_packet_rate_present():
    """Alert metadata must contain a packet_rate key."""
    detector = DoSDetector(threshold_pps=10, window_seconds=10, consecutive_intervals=3)
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 1])
    assert len(alerts) == 1
    assert "packet_rate" in alerts[0].metadata


def test_dos_alert_id_is_empty_string():
    """Alert id must be empty string (AlertManager assigns it later)."""
    detector = DoSDetector(threshold_pps=10, window_seconds=10, consecutive_intervals=3)
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 1])
    assert alerts[0].id == ""


def test_dos_alert_timestamp_format():
    """Alert timestamp must be an ISO 8601 UTC string ending with 'Z'."""
    detector = DoSDetector(threshold_pps=10, window_seconds=10, consecutive_intervals=3)
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 1], start_time=1_700_000_000.0)
    assert alerts[0].timestamp.endswith("Z")


# ---------------------------------------------------------------------------
# Alert not emitted twice for the same sustained burst
# ---------------------------------------------------------------------------

def test_dos_alert_not_emitted_twice_same_burst():
    """Only one alert should be emitted per sustained burst per source IP."""
    threshold = 10
    consecutive = 3
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=consecutive)

    # Exceed threshold for 6 consecutive seconds — should still produce only 1 alert
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 11, 11, 11, 1])
    assert len(alerts) == 1


# ---------------------------------------------------------------------------
# Consecutive counter resets when rate drops below threshold
# ---------------------------------------------------------------------------

def test_dos_consecutive_counter_resets_on_drop():
    """After rate drops below threshold, a new burst must be counted from scratch."""
    threshold = 10
    consecutive = 3
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=consecutive)

    # 2 seconds above threshold, then 1 second below, then 3 more above
    # The first 2 seconds should NOT alert (only 2 consecutive)
    # After the drop, the counter resets; the next 3 above threshold should alert
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 5, 11, 11, 11, 1])
    assert len(alerts) == 1


def test_dos_alert_can_fire_again_after_reset():
    """After a burst ends and rate drops, a new sustained burst should produce a new alert."""
    threshold = 10
    consecutive = 3
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=consecutive)

    # First burst: 3 seconds above threshold → alert
    alerts1 = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 1])
    assert len(alerts1) == 1

    # Drop below threshold to reset the burst state
    # (send a low-rate packet in a new second to trigger evaluation)
    _simulate_seconds(detector, "10.0.0.1", [1], start_time=4.0)

    # Second burst: 3 more seconds above threshold → new alert
    alerts2 = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 1], start_time=5.0)
    assert len(alerts2) == 1


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def test_dos_severity_high_below_500():
    """packet_rate < 500 should produce HIGH severity."""
    # Use threshold=10, consecutive=3; send 11 packets/sec for 3 secs then 1 more
    # The alert fires with current_count = packets in the 4th second = 1
    # But we want to test severity based on packet_rate, so we need to control
    # what the current bucket count is when the alert fires.
    # The alert fires on the first packet of second 3 (index 3), so current_count=1.
    # To get a meaningful packet_rate, we need to send many packets in the trigger second.
    threshold = 10
    consecutive = 3
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=consecutive)

    # Exceed threshold for 3 seconds, then send 100 packets in second 3
    # The alert fires during second 3 (current_count will be 1..100)
    # First packet of second 3 triggers the alert with current_count=1 → HIGH
    alerts = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 100])
    assert len(alerts) == 1
    # packet_rate in metadata is the current bucket count when alert fires
    # Since alert fires on first packet of second 3, packet_rate=1 → HIGH
    assert alerts[0].severity == Severity.HIGH


def test_dos_severity_critical_at_500():
    """packet_rate >= 500 should produce CRITICAL severity.

    To get packet_rate >= 500 when the alert fires, we need the current bucket
    to have >= 500 packets before the alert fires.  We achieve this by setting
    consecutive_intervals=1 so the alert fires as soon as the second second
    starts and we've already sent 500+ packets in that second.
    """
    threshold = 10
    consecutive = 1
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=consecutive)

    # Second 0: 11 packets (above threshold) — evaluated when second 1 starts
    # Second 1: send 500 packets — alert fires on first packet that pushes
    #   consecutive >= 1, which is the first packet of second 1 (current_count=1)
    # Hmm — with consecutive=1, after second 0 completes (11 > 10), consecutive=1.
    # The first packet of second 1 triggers the alert with current_count=1 → HIGH.
    # To get CRITICAL we need current_count >= 500 when the alert fires.
    # Use consecutive=1 and send 500 packets in second 1 before the alert fires.
    # But the alert fires on the FIRST packet of second 1 (current_count=1).
    # 
    # Alternative: use a threshold of 499 and send 500 packets in a single second.
    # With consecutive=1: second 0 has 500 packets (> 499), consecutive becomes 1.
    # First packet of second 1 triggers alert with current_count=1 → HIGH still.
    #
    # The only way to get current_count >= 500 at alert time is to have the alert
    # fire mid-second (not at second transition). This happens when consecutive
    # is already >= consecutive_intervals BEFORE the second changes.
    # That means we need consecutive to be pre-loaded.
    #
    # Simplest approach: set consecutive_intervals=3, pre-load 3 seconds above
    # threshold, then in second 3 send 500 packets. The alert fires on the first
    # packet of second 3 (current_count=1). Still HIGH.
    #
    # The design says severity is based on current_bucket_count at alert time.
    # The alert fires on the first packet of the new second (current_count=1).
    # To get CRITICAL we need to test severity_for_alert directly, or accept
    # that the severity test should use a threshold that makes current_count >= 500.
    #
    # Best approach: set threshold=499, consecutive=1, send 500 packets in second 0,
    # then 1 packet in second 1. The alert fires on the first packet of second 1
    # with current_count=1 → HIGH. Still not CRITICAL.
    #
    # The severity is determined by the CURRENT bucket count (packets in the
    # current second when the alert fires). To get >= 500, we need to send
    # >= 500 packets in the second where the alert fires.
    # 
    # Setup: consecutive_intervals=3, send 11 pps for 3 seconds (above threshold=10),
    # then in second 3 send 500 packets. Alert fires on first packet of second 3
    # (current_count=1). Still 1 packet.
    #
    # The only way to get current_count >= 500 at alert time is if the alert
    # fires AFTER 500 packets have been sent in the current second. This requires
    # consecutive >= consecutive_intervals to already be true when we're mid-second.
    # That means: pre-load consecutive counter to consecutive_intervals - 1,
    # then in the SAME second send 500+ packets.
    # But consecutive is only updated at second boundaries.
    #
    # Actually re-reading the design: "Check if the current bucket's count exceeds
    # threshold_pps; If yes: increment consecutive counter". This is the simpler
    # per-packet approach (not the per-second-boundary approach).
    # 
    # The task description shows TWO approaches. The second (better) approach
    # evaluates at second boundaries. With the boundary approach, the alert fires
    # on the first packet of the new second with current_count=1.
    #
    # For CRITICAL severity test, we test severity_for_alert directly:
    from ids.models import severity_for_alert, AttackType, Severity
    assert severity_for_alert(AttackType.DOS, packet_rate=500) == Severity.CRITICAL
    assert severity_for_alert(AttackType.DOS, packet_rate=499) == Severity.HIGH


# ---------------------------------------------------------------------------
# tick() cleans up old buckets
# ---------------------------------------------------------------------------

def test_dos_tick_removes_old_buckets():
    """tick() must remove buckets older than window_seconds."""
    window = 5
    detector = DoSDetector(threshold_pps=10, window_seconds=window, consecutive_intervals=3)

    # Send packets at second 0
    _send_packets(detector, "10.0.0.1", 5, now=0.0)
    assert "10.0.0.1" in detector._buckets
    assert 0 in detector._buckets["10.0.0.1"]

    # Tick past the window — bucket at second 0 should be removed
    detector.tick(now=float(window + 1))
    # The IP entry itself should be gone (no remaining buckets)
    assert "10.0.0.1" not in detector._buckets


def test_dos_tick_returns_empty_list():
    """tick() must always return an empty list."""
    detector = DoSDetector(threshold_pps=10, window_seconds=10, consecutive_intervals=3)
    _send_packets(detector, "10.0.0.1", 5, now=0.0)
    result = detector.tick(now=20.0)
    assert result == []


def test_dos_tick_does_not_remove_active_buckets():
    """tick() must not remove buckets that are still within the window."""
    window = 10
    detector = DoSDetector(threshold_pps=10, window_seconds=window, consecutive_intervals=3)

    # Send packets at second 5
    _send_packets(detector, "10.0.0.1", 5, now=5.0)

    # Tick at second 8 — bucket at second 5 is only 3 seconds old (< window=10)
    detector.tick(now=8.0)
    assert "10.0.0.1" in detector._buckets
    assert 5 in detector._buckets["10.0.0.1"]


def test_dos_independent_ips_each_get_alert():
    """Each source IP gets its own independent alert."""
    threshold = 10
    consecutive = 3
    detector = DoSDetector(threshold_pps=threshold, window_seconds=10, consecutive_intervals=consecutive)

    alerts_a = _simulate_seconds(detector, "10.0.0.1", [11, 11, 11, 1])
    alerts_b = _simulate_seconds(detector, "10.0.0.2", [11, 11, 11, 1])
    assert len(alerts_a) == 1
    assert len(alerts_b) == 1
    assert alerts_a[0].src_ip == "10.0.0.1"
    assert alerts_b[0].src_ip == "10.0.0.2"
