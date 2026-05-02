"""ids/alert_manager.py — Alert management for the Network IDS.

Receives Alert objects from the Detection_Engine, assigns UUIDs, persists
them to the Log_Store with retry logic, maintains an in-memory ring buffer
of recent alerts, and notifies the Dashboard via a callback.
"""

from __future__ import annotations

import collections
import logging
import queue
import threading
import time
import uuid
from typing import Callable

from ids.models import Alert

logger = logging.getLogger("ids.alert_manager")

_SENTINEL = object()  # signals the worker thread to stop

# Retry sleep duration — exposed as a module-level constant so tests can patch it.
_RETRY_SLEEP_SECONDS = 0.5


class AlertManager:
    """Receives alerts, persists them, and notifies the dashboard.

    Parameters
    ----------
    log_store:
        A ``LogStore`` instance with ``save_alert`` and ``upsert_suspicious_ip``
        methods.
    notify_callback:
        Callable invoked with each successfully persisted ``Alert``.
    """

    def __init__(self, log_store, notify_callback: Callable[[Alert], None], retry_sleep: float = 0.5) -> None:
        self._log_store = log_store
        self._notify_callback = notify_callback
        self._retry_sleep = retry_sleep  # seconds to sleep between retry attempts

        # In-memory ring buffer — holds the 50 most recent alerts.
        self._ring_buffer: collections.deque[Alert] = collections.deque(maxlen=50)
        self._ring_lock = threading.Lock()

        # Worker queue and thread.
        self._queue: queue.Queue = queue.Queue()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True, name="alert-manager-worker")
        self._worker.start()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def receive(self, alert: Alert) -> None:
        """Assign a UUID to *alert* and enqueue it for async processing.

        Non-blocking — returns immediately after enqueueing.
        """
        alert.id = str(uuid.uuid4())
        self._queue.put_nowait(alert)

    def get_recent_alerts(self, limit: int = 50) -> list[Alert]:
        """Return the most recent *limit* alerts (newest first).

        Parameters
        ----------
        limit:
            Maximum number of alerts to return.  Capped at the ring buffer
            size (50).
        """
        with self._ring_lock:
            # deque stores oldest→newest; reverse for newest-first output.
            alerts = list(self._ring_buffer)
        alerts.reverse()
        return alerts[:limit]

    def stop(self) -> None:
        """Signal the worker thread to stop and wait for it to finish."""
        self._queue.put_nowait(_SENTINEL)
        self._worker.join()

    # ------------------------------------------------------------------
    # Worker thread
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        """Background thread: dequeue and persist alerts."""
        while True:
            try:
                item = self._queue.get(timeout=1)
            except queue.Empty:
                continue

            if item is _SENTINEL:
                break

            alert: Alert = item
            self._persist_with_retry(alert)

    def _persist_with_retry(self, alert: Alert) -> None:
        """Attempt to persist *alert*, retrying up to 3 times on failure."""
        max_attempts = 3
        last_exc: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            try:
                self._log_store.save_alert(alert)
                self._log_store.upsert_suspicious_ip(alert)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt < max_attempts:
                    logger.warning(
                        "Failed to persist alert %s (attempt %d/%d): %s — retrying in %.0f ms",
                        alert.id,
                        attempt,
                        max_attempts,
                        exc,
                        self._retry_sleep * 1000,
                    )
                    time.sleep(self._retry_sleep)
                    continue  # retry
                else:
                    logger.critical(
                        "Failed to persist alert %s after %d attempts — discarding. Error: %s",
                        alert.id,
                        max_attempts,
                        exc,
                    )
                    return  # discard — do not add to ring buffer or call callback
            else:
                # Persistence succeeded.
                with self._ring_lock:
                    self._ring_buffer.append(alert)
                try:
                    self._notify_callback(alert)
                except Exception as cb_exc:  # noqa: BLE001
                    logger.warning("notify_callback raised an exception: %s", cb_exc)
                return
