"""tests/test_alert_manager.py — Unit tests for AlertManager.

Covers:
- UUID assignment (each alert gets a unique id)
- Alerts appear in get_recent_alerts after processing
- Ring buffer maxsize=50 (51st alert evicts the oldest)
- notify_callback is called for each successfully persisted alert
- Worker thread processes alerts asynchronously (threading.Event to wait)
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, call, patch

import pytest

from ids.alert_manager import AlertManager
from ids.models import Alert, AttackType, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(src_ip: str = "1.2.3.4") -> Alert:
    """Return a minimal Alert with an empty id (AlertManager assigns it)."""
    return Alert(
        id="",
        timestamp="2024-01-15T10:30:00.000000Z",
        src_ip=src_ip,
        attack_type=AttackType.PORT_SCAN,
        severity=Severity.MEDIUM,
        metadata={"port_count": 25},
    )


def _make_manager(log_store=None, callback=None):
    """Create an AlertManager with optional mock dependencies (retry_sleep=0 for speed)."""
    if log_store is None:
        log_store = MagicMock()
    if callback is None:
        callback = MagicMock()
    return AlertManager(log_store=log_store, notify_callback=callback, retry_sleep=0), log_store, callback


def _wait_for_processing(manager: AlertManager, timeout: float = 2.0) -> None:
    """Block until the worker queue is drained (all enqueued items processed)."""
    deadline = time.monotonic() + timeout
    while not manager._queue.empty():
        if time.monotonic() > deadline:
            raise TimeoutError("AlertManager worker did not drain queue in time")
        time.sleep(0.01)
    # Give the worker a moment to finish the last item it dequeued.
    time.sleep(0.05)


# ---------------------------------------------------------------------------
# UUID assignment
# ---------------------------------------------------------------------------

class TestUUIDAssignment:
    def test_receive_assigns_uuid(self):
        """receive() must assign a non-empty UUID4 string to alert.id."""
        manager, _, _ = _make_manager()
        alert = _make_alert()
        assert alert.id == ""
        manager.receive(alert)
        assert alert.id != ""
        assert len(alert.id) == 36  # UUID4 canonical form
        manager.stop()

    def test_each_alert_gets_unique_id(self):
        """Every alert processed by receive() must get a distinct UUID."""
        manager, _, _ = _make_manager()
        alerts = [_make_alert() for _ in range(20)]
        for a in alerts:
            manager.receive(a)
        _wait_for_processing(manager)
        ids = [a.id for a in alerts]
        assert len(ids) == len(set(ids)), "Duplicate UUIDs detected"
        manager.stop()

    def test_uuid_assigned_before_enqueue(self):
        """The UUID must be set on the alert object before it is enqueued."""
        manager, _, _ = _make_manager()
        alert = _make_alert()
        manager.receive(alert)
        # UUID is assigned synchronously inside receive(), before the worker picks it up.
        assert alert.id != ""
        manager.stop()


# ---------------------------------------------------------------------------
# get_recent_alerts
# ---------------------------------------------------------------------------

class TestGetRecentAlerts:
    def test_alerts_appear_after_processing(self):
        """Alerts should appear in get_recent_alerts once the worker persists them."""
        done = threading.Event()
        callback = lambda a: done.set()  # noqa: E731
        manager, _, _ = _make_manager(callback=callback)

        alert = _make_alert()
        manager.receive(alert)
        assert done.wait(timeout=2.0), "notify_callback was never called"

        recent = manager.get_recent_alerts()
        assert len(recent) == 1
        assert recent[0].id == alert.id
        manager.stop()

    def test_newest_first_ordering(self):
        """get_recent_alerts must return alerts newest-first."""
        received_order: list[str] = []
        lock = threading.Lock()
        count = threading.Semaphore(0)

        def callback(a: Alert):
            with lock:
                received_order.append(a.id)
            count.release()

        manager, _, _ = _make_manager(callback=callback)
        alerts = [_make_alert() for _ in range(5)]
        for a in alerts:
            manager.receive(a)

        # Wait for all 5 to be processed.
        for _ in range(5):
            assert count.acquire(timeout=2.0), "Timed out waiting for callback"

        recent = manager.get_recent_alerts()
        assert len(recent) == 5
        # The last alert received should be first in the result.
        assert recent[0].id == alerts[-1].id
        manager.stop()

    def test_limit_parameter(self):
        """get_recent_alerts(limit=N) must return at most N alerts."""
        done_count = [0]
        lock = threading.Lock()
        sem = threading.Semaphore(0)

        def callback(a):
            with lock:
                done_count[0] += 1
            sem.release()

        manager, _, _ = _make_manager(callback=callback)
        for _ in range(10):
            manager.receive(_make_alert())

        for _ in range(10):
            assert sem.acquire(timeout=2.0)

        assert len(manager.get_recent_alerts(limit=3)) == 3
        manager.stop()


# ---------------------------------------------------------------------------
# Ring buffer eviction
# ---------------------------------------------------------------------------

class TestRingBuffer:
    def test_ring_buffer_maxsize_50(self):
        """After 51 alerts, the oldest should be evicted (maxsize=50)."""
        sem = threading.Semaphore(0)

        def callback(a):
            sem.release()

        manager, _, _ = _make_manager(callback=callback)

        alerts = [_make_alert(src_ip=f"10.0.0.{i % 256}") for i in range(51)]
        for a in alerts:
            manager.receive(a)

        # Wait for all 51 to be processed.
        for _ in range(51):
            assert sem.acquire(timeout=5.0), "Timed out waiting for callback"

        recent = manager.get_recent_alerts(limit=50)
        assert len(recent) == 50

        # The first alert (index 0) should have been evicted.
        ids_in_buffer = {a.id for a in recent}
        assert alerts[0].id not in ids_in_buffer, "Oldest alert should have been evicted"
        # The last alert (index 50) should be present.
        assert alerts[50].id in ids_in_buffer, "Newest alert should be in buffer"
        manager.stop()


# ---------------------------------------------------------------------------
# notify_callback
# ---------------------------------------------------------------------------

class TestNotifyCallback:
    def test_callback_called_for_each_alert(self):
        """notify_callback must be called once per successfully persisted alert."""
        callback = MagicMock()
        manager, _, _ = _make_manager(callback=callback)

        n = 5
        alerts = [_make_alert() for _ in range(n)]
        for a in alerts:
            manager.receive(a)

        _wait_for_processing(manager)
        # Give the worker a bit more time to call the callback.
        time.sleep(0.1)

        assert callback.call_count == n
        manager.stop()

    def test_callback_receives_correct_alert(self):
        """notify_callback must be called with the exact alert that was persisted."""
        received: list[Alert] = []
        done = threading.Event()

        def callback(a: Alert):
            received.append(a)
            done.set()

        manager, _, _ = _make_manager(callback=callback)
        alert = _make_alert(src_ip="192.168.1.1")
        manager.receive(alert)

        assert done.wait(timeout=2.0)
        assert len(received) == 1
        assert received[0].src_ip == "192.168.1.1"
        assert received[0].id == alert.id
        manager.stop()


# ---------------------------------------------------------------------------
# Asynchronous processing
# ---------------------------------------------------------------------------

class TestAsyncProcessing:
    def test_worker_thread_processes_asynchronously(self):
        """receive() must return immediately; processing happens in background."""
        processing_started = threading.Event()
        processing_done = threading.Event()

        original_save = None

        def slow_save(a):
            processing_started.set()
            time.sleep(0.05)
            processing_done.set()

        log_store = MagicMock()
        log_store.save_alert.side_effect = slow_save

        manager = AlertManager(log_store=log_store, notify_callback=MagicMock(), retry_sleep=0)
        alert = _make_alert()

        start = time.monotonic()
        manager.receive(alert)
        elapsed = time.monotonic() - start

        # receive() should return well before the slow save completes.
        assert elapsed < 0.04, f"receive() blocked for {elapsed:.3f}s — expected non-blocking"

        # But the processing should eventually complete.
        assert processing_done.wait(timeout=2.0), "Worker thread never processed the alert"
        manager.stop()

    def test_threading_event_wait_for_callback(self):
        """Use threading.Event to confirm callback is invoked asynchronously."""
        callback_event = threading.Event()

        def callback(a: Alert):
            callback_event.set()

        manager, _, _ = _make_manager(callback=callback)
        manager.receive(_make_alert())

        # The callback should fire in the background worker thread.
        assert callback_event.wait(timeout=2.0), "Callback was not invoked by worker thread"
        manager.stop()


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------

class TestRetryLogic:
    def test_no_retry_on_success(self):
        """save_alert should be called exactly once when it succeeds."""
        log_store = MagicMock()
        done = threading.Event()
        callback = lambda a: done.set()  # noqa: E731

        manager = AlertManager(log_store=log_store, notify_callback=callback, retry_sleep=0)
        manager.receive(_make_alert())
        assert done.wait(timeout=2.0)

        assert log_store.save_alert.call_count == 1
        manager.stop()

    def test_retry_on_transient_failure(self):
        """save_alert should be retried up to 3 times on Exception."""
        log_store = MagicMock()
        # Fail twice, succeed on third attempt.
        log_store.save_alert.side_effect = [Exception("db error"), Exception("db error"), None]

        done = threading.Event()
        callback = lambda a: done.set()  # noqa: E731

        manager = AlertManager(log_store=log_store, notify_callback=callback, retry_sleep=0)
        manager.receive(_make_alert())
        assert done.wait(timeout=2.0), "Callback not called after successful retry"

        assert log_store.save_alert.call_count == 3
        manager.stop()

    def test_discard_after_3_failures(self):
        """After 3 consecutive failures, alert must be discarded (not in ring buffer)."""
        log_store = MagicMock()
        log_store.save_alert.side_effect = Exception("persistent db error")

        callback = MagicMock()

        manager = AlertManager(log_store=log_store, notify_callback=callback, retry_sleep=0)
        manager.receive(_make_alert())
        _wait_for_processing(manager)
        time.sleep(0.1)

        assert callback.call_count == 0, "Callback should not be called after 3 failures"
        assert len(manager.get_recent_alerts()) == 0, "Discarded alert should not be in ring buffer"
        manager.stop()

    def test_critical_log_on_exhaustion(self, caplog):
        """A CRITICAL log entry must be emitted when all retries are exhausted."""
        import logging as _logging
        log_store = MagicMock()
        log_store.save_alert.side_effect = Exception("persistent error")

        with caplog.at_level(_logging.CRITICAL, logger="ids.alert_manager"):
            manager = AlertManager(log_store=log_store, notify_callback=MagicMock(), retry_sleep=0)
            alert = _make_alert()
            manager.receive(alert)
            _wait_for_processing(manager)
            time.sleep(0.1)

        critical_records = [r for r in caplog.records if r.levelno == _logging.CRITICAL]
        assert len(critical_records) >= 1, "Expected at least one CRITICAL log record"
        # The UUID should appear in the critical log message.
        assert alert.id in critical_records[0].getMessage()
        manager.stop()
