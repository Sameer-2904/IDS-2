"""tests/test_detection_engine.py — Unit tests for DetectionEngine.

Tests cover:
- DetectionEngine instantiates all three detectors with correct config values
- Packets are dequeued and processed by all three detectors
- Alerts from detectors are passed to alert_manager.receive
- Engine stops when stop_event is set
- src_ip extraction from mock packets (direct attribute and Scapy-style)
- Packets with no extractable src_ip are silently skipped
"""

from __future__ import annotations

import queue
import threading
import time
from unittest.mock import MagicMock, patch, call

import pytest

from ids.detection import DetectionEngine
from ids.models import Alert, AttackType, Severity


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_config(
    port_scan_threshold: int = 20,
    port_scan_window_seconds: int = 10,
    brute_force_threshold: int = 10,
    brute_force_window_seconds: int = 10,
    brute_force_ports: list[int] | None = None,
    dos_threshold_pps: int = 100,
    dos_window_seconds: int = 10,
    dos_consecutive_intervals: int = 3,
):
    """Return a mock DetectionConfig with the given values."""
    cfg = MagicMock()
    cfg.port_scan_threshold = port_scan_threshold
    cfg.port_scan_window_seconds = port_scan_window_seconds
    cfg.brute_force_threshold = brute_force_threshold
    cfg.brute_force_window_seconds = brute_force_window_seconds
    cfg.brute_force_ports = brute_force_ports if brute_force_ports is not None else [22, 21, 3389, 5900]
    cfg.dos_threshold_pps = dos_threshold_pps
    cfg.dos_window_seconds = dos_window_seconds
    cfg.dos_consecutive_intervals = dos_consecutive_intervals
    return cfg


def _make_engine(config=None, packet_queue=None, stop_event=None, alert_manager=None):
    """Construct a DetectionEngine with sensible defaults for testing."""
    if config is None:
        config = _make_config()
    if packet_queue is None:
        packet_queue = queue.Queue()
    if stop_event is None:
        stop_event = threading.Event()
    if alert_manager is None:
        alert_manager = MagicMock()
    return DetectionEngine(
        alert_manager=alert_manager,
        config=config,
        packet_queue=packet_queue,
        stop_event=stop_event,
    )


class MockPacketWithSrc:
    """Minimal packet mock that exposes a ``src`` attribute (direct IP)."""

    def __init__(self, src: str, dport: int = 80) -> None:
        self.src = src
        self.dport = dport


class MockPacketNoSrc:
    """Packet mock with no src or IP layer — src_ip extraction should return None."""
    pass


class MockScapyPacket:
    """Simulates a Scapy-style packet with haslayer / __getitem__ support."""

    def __init__(self, src: str, dport: int = 80) -> None:
        self._src = src
        self._dport = dport

    def haslayer(self, layer: str) -> bool:
        return layer == "IP"

    def __getitem__(self, layer: str):
        if layer == "IP":
            ip = MagicMock()
            ip.src = self._src
            return ip
        raise KeyError(layer)


def _make_alert(src_ip: str = "1.2.3.4") -> Alert:
    return Alert(
        id="",
        timestamp="2024-01-01T00:00:00.000000Z",
        src_ip=src_ip,
        attack_type=AttackType.PORT_SCAN,
        severity=Severity.MEDIUM,
        metadata={"port_count": 5, "ports_sampled": []},
    )


# ---------------------------------------------------------------------------
# 1. DetectionEngine instantiates all three detectors
# ---------------------------------------------------------------------------

def test_engine_creates_port_scan_detector():
    """DetectionEngine must create a PortScanDetector with config values."""
    cfg = _make_config(port_scan_threshold=42, port_scan_window_seconds=15)
    engine = _make_engine(config=cfg)
    assert engine._port_scan.threshold == 42
    assert engine._port_scan.window_seconds == 15


def test_engine_creates_brute_force_detector():
    """DetectionEngine must create a BruteForceDetector with config values."""
    cfg = _make_config(
        brute_force_threshold=7,
        brute_force_window_seconds=20,
        brute_force_ports=[22, 3389],
    )
    engine = _make_engine(config=cfg)
    assert engine._brute_force.threshold == 7
    assert engine._brute_force.window_seconds == 20
    assert engine._brute_force.monitored_ports == [22, 3389]


def test_engine_creates_dos_detector():
    """DetectionEngine must create a DoSDetector with config values."""
    cfg = _make_config(
        dos_threshold_pps=200,
        dos_window_seconds=5,
        dos_consecutive_intervals=4,
    )
    engine = _make_engine(config=cfg)
    assert engine._dos.threshold_pps == 200
    assert engine._dos.window_seconds == 5
    assert engine._dos.consecutive_intervals == 4


# ---------------------------------------------------------------------------
# 2. src_ip extraction
# ---------------------------------------------------------------------------

def test_extract_src_ip_direct_attribute():
    """_extract_src_ip must return the src attribute from a mock packet."""
    engine = _make_engine()
    pkt = MockPacketWithSrc(src="10.0.0.1")
    assert engine._extract_src_ip(pkt) == "10.0.0.1"


def test_extract_src_ip_scapy_style():
    """_extract_src_ip must extract src from a Scapy-style IP layer."""
    engine = _make_engine()
    pkt = MockScapyPacket(src="192.168.1.5")
    assert engine._extract_src_ip(pkt) == "192.168.1.5"


def test_extract_src_ip_no_ip_returns_none():
    """_extract_src_ip must return None when no IP information is available."""
    engine = _make_engine()
    pkt = MockPacketNoSrc()
    assert engine._extract_src_ip(pkt) is None


def test_extract_src_ip_haslayer_returns_false():
    """_extract_src_ip must fall through to direct-attribute check when haslayer returns False."""
    engine = _make_engine()

    class NoIPLayer:
        def haslayer(self, layer):
            return False

    pkt = NoIPLayer()
    assert engine._extract_src_ip(pkt) is None


# ---------------------------------------------------------------------------
# 3. Packets are dequeued and processed by all three detectors
# ---------------------------------------------------------------------------

def test_run_processes_packet_through_all_detectors():
    """Each packet must be passed to all three detectors' process() methods."""
    pkt_queue = queue.Queue()
    stop_event = threading.Event()
    alert_manager = MagicMock()

    engine = _make_engine(
        packet_queue=pkt_queue,
        stop_event=stop_event,
        alert_manager=alert_manager,
    )

    # The last detector's process sets stop_event so run() exits after one packet
    def dos_process_and_stop(packet, src_ip, now):
        stop_event.set()
        return None

    engine._port_scan.process = MagicMock(return_value=None)
    engine._brute_force.process = MagicMock(return_value=None)
    engine._dos.process = MagicMock(side_effect=dos_process_and_stop)

    pkt = MockPacketWithSrc(src="10.0.0.1")
    pkt_queue.put(pkt)

    engine.run()

    engine._port_scan.process.assert_called_once()
    engine._brute_force.process.assert_called_once()
    engine._dos.process.assert_called_once()


def test_run_skips_packet_with_no_src_ip():
    """Packets from which no src_ip can be extracted must be silently skipped."""
    pkt_queue = queue.Queue()
    stop_event = threading.Event()
    alert_manager = MagicMock()

    engine = _make_engine(
        packet_queue=pkt_queue,
        stop_event=stop_event,
        alert_manager=alert_manager,
    )

    engine._port_scan.process = MagicMock(return_value=None)
    engine._brute_force.process = MagicMock(return_value=None)
    engine._dos.process = MagicMock(return_value=None)

    # Enqueue a packet with no src; stop_event is set so run() exits after the
    # queue drains (queue.Empty timeout triggers _do_tick then loop check)
    pkt_queue.put(MockPacketNoSrc())
    stop_event.set()

    engine.run()

    # No detector should have been called
    engine._port_scan.process.assert_not_called()
    engine._brute_force.process.assert_not_called()
    engine._dos.process.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Alerts from detectors are passed to alert_manager.receive
# ---------------------------------------------------------------------------

def test_run_forwards_alert_from_port_scan_detector():
    """Alerts returned by PortScanDetector.process must be forwarded to alert_manager.receive."""
    pkt_queue = queue.Queue()
    stop_event = threading.Event()
    alert_manager = MagicMock()

    engine = _make_engine(
        packet_queue=pkt_queue,
        stop_event=stop_event,
        alert_manager=alert_manager,
    )

    alert = _make_alert()

    def dos_process_and_stop(packet, src_ip, now):
        stop_event.set()
        return None

    engine._port_scan.process = MagicMock(return_value=alert)
    engine._brute_force.process = MagicMock(return_value=None)
    engine._dos.process = MagicMock(side_effect=dos_process_and_stop)

    pkt_queue.put(MockPacketWithSrc(src="10.0.0.1"))

    engine.run()

    alert_manager.receive.assert_called_once_with(alert)


def test_run_forwards_alert_from_brute_force_detector():
    """Alerts returned by BruteForceDetector.process must be forwarded to alert_manager.receive."""
    pkt_queue = queue.Queue()
    stop_event = threading.Event()
    alert_manager = MagicMock()

    engine = _make_engine(
        packet_queue=pkt_queue,
        stop_event=stop_event,
        alert_manager=alert_manager,
    )

    alert = _make_alert()

    def dos_process_and_stop(packet, src_ip, now):
        stop_event.set()
        return None

    engine._port_scan.process = MagicMock(return_value=None)
    engine._brute_force.process = MagicMock(return_value=alert)
    engine._dos.process = MagicMock(side_effect=dos_process_and_stop)

    pkt_queue.put(MockPacketWithSrc(src="10.0.0.1"))

    engine.run()

    alert_manager.receive.assert_called_once_with(alert)


def test_run_forwards_alert_from_dos_detector():
    """Alerts returned by DoSDetector.process must be forwarded to alert_manager.receive."""
    pkt_queue = queue.Queue()
    stop_event = threading.Event()
    alert_manager = MagicMock()

    engine = _make_engine(
        packet_queue=pkt_queue,
        stop_event=stop_event,
        alert_manager=alert_manager,
    )

    alert = _make_alert()

    def dos_process_and_stop(packet, src_ip, now):
        stop_event.set()
        return alert

    engine._port_scan.process = MagicMock(return_value=None)
    engine._brute_force.process = MagicMock(return_value=None)
    engine._dos.process = MagicMock(side_effect=dos_process_and_stop)

    pkt_queue.put(MockPacketWithSrc(src="10.0.0.1"))

    engine.run()

    alert_manager.receive.assert_called_once_with(alert)


def test_run_forwards_multiple_alerts_from_multiple_detectors():
    """When multiple detectors each return an alert, all must be forwarded."""
    pkt_queue = queue.Queue()
    stop_event = threading.Event()
    alert_manager = MagicMock()

    engine = _make_engine(
        packet_queue=pkt_queue,
        stop_event=stop_event,
        alert_manager=alert_manager,
    )

    alert_ps = _make_alert("1.1.1.1")
    alert_bf = _make_alert("2.2.2.2")
    alert_dos = _make_alert("3.3.3.3")

    def dos_process_and_stop(packet, src_ip, now):
        stop_event.set()
        return alert_dos

    engine._port_scan.process = MagicMock(return_value=alert_ps)
    engine._brute_force.process = MagicMock(return_value=alert_bf)
    engine._dos.process = MagicMock(side_effect=dos_process_and_stop)

    pkt_queue.put(MockPacketWithSrc(src="10.0.0.1"))

    engine.run()

    assert alert_manager.receive.call_count == 3
    alert_manager.receive.assert_any_call(alert_ps)
    alert_manager.receive.assert_any_call(alert_bf)
    alert_manager.receive.assert_any_call(alert_dos)


# ---------------------------------------------------------------------------
# 5. Engine stops when stop_event is set
# ---------------------------------------------------------------------------

def test_run_stops_when_stop_event_set_before_start():
    """If stop_event is already set, run() should return immediately."""
    pkt_queue = queue.Queue()
    stop_event = threading.Event()
    stop_event.set()  # set before run() is called

    engine = _make_engine(packet_queue=pkt_queue, stop_event=stop_event)

    # Should return quickly without blocking
    start = time.monotonic()
    engine.run()
    elapsed = time.monotonic() - start

    assert elapsed < 2.0, "run() should return quickly when stop_event is already set"


def test_run_stops_after_stop_event_set_from_another_thread():
    """run() must exit when stop_event is set from another thread."""
    pkt_queue = queue.Queue()
    stop_event = threading.Event()
    alert_manager = MagicMock()

    engine = _make_engine(
        packet_queue=pkt_queue,
        stop_event=stop_event,
        alert_manager=alert_manager,
    )

    # Start run() in a background thread
    t = threading.Thread(target=engine.run)
    t.start()

    # Give the engine a moment to start, then signal stop
    time.sleep(0.1)
    stop_event.set()

    t.join(timeout=5.0)
    assert not t.is_alive(), "DetectionEngine thread should have stopped after stop_event was set"


# ---------------------------------------------------------------------------
# 6. _do_tick forwards tick alerts to alert_manager
# ---------------------------------------------------------------------------

def test_do_tick_forwards_alerts_from_detectors():
    """_do_tick must forward any alerts returned by detector.tick() to alert_manager.receive."""
    alert_manager = MagicMock()
    engine = _make_engine(alert_manager=alert_manager)

    tick_alert = _make_alert()
    engine._port_scan.tick = MagicMock(return_value=[tick_alert])
    engine._brute_force.tick = MagicMock(return_value=[])
    engine._dos.tick = MagicMock(return_value=[])

    engine._do_tick()

    alert_manager.receive.assert_called_once_with(tick_alert)


def test_do_tick_no_alerts_when_detectors_return_empty():
    """_do_tick must not call alert_manager.receive when all detectors return empty lists."""
    alert_manager = MagicMock()
    engine = _make_engine(alert_manager=alert_manager)

    engine._port_scan.tick = MagicMock(return_value=[])
    engine._brute_force.tick = MagicMock(return_value=[])
    engine._dos.tick = MagicMock(return_value=[])

    engine._do_tick()

    alert_manager.receive.assert_not_called()
