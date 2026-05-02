"""main.py — Entry point for the Network Intrusion Detection System.

Wires together all components:
  PacketCaptureEngine → Queue → DetectionEngine → AlertManager → LogStore
                                                                      ↓
                                                               Dashboard (Flask)

The Flask dashboard runs in a daemon thread on the configured port.
SIGINT/SIGTERM triggers graceful shutdown: stop capture, join threads,
flush log store, exit with code 0.
"""

import argparse
import collections
import logging
import queue
import signal
import sys
import threading

from ids.alert_manager import AlertManager
from ids.capture import PacketCaptureEngine
from ids.config import load_config
from ids.dashboard import create_app
from ids.detection import DetectionEngine
from ids.ip_blocker import IPBlocker
from ids.log_store import LogStore
from ids.logger import setup_logging


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        metavar="PATH",
        help="Path to the YAML configuration file",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    # Bootstrap basic logging until structured logger is ready
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    config = load_config(args.config)

    # Set up structured JSON logging
    logger = setup_logging(config.log_file_path, config.log_level)
    logger.info("IDS starting — config loaded from %s", args.config)

    # Shared stop event for graceful shutdown
    stop_event = threading.Event()

    # Shared packet queue (back-pressure buffer between capture and detection)
    packet_queue = queue.Queue(maxsize=10_000)

    # Shared stats deque — 60-point rolling window of per-second packet counts.
    # Updated by PacketCaptureEngine._on_packet; read by the Dashboard /api/stats.
    stats_provider: collections.deque = collections.deque(maxlen=60)

    # Initialise persistence layer
    log_store = LogStore(config.log_store_path)

    # Optional IP blocker (requires root/admin privileges)
    ip_blocker: IPBlocker | None = None
    if config.ip_blocker_enabled:
        ip_blocker = IPBlocker()
        logger.info("IPBlocker enabled")

    # Build the Flask dashboard app before wiring the notify_callback so the
    # app object is available in the closure.
    flask_app = create_app(
        alert_manager=None,  # will be replaced below after AlertManager is created
        log_store=log_store,
        stats_provider=stats_provider,
        ip_blocker=ip_blocker,
        ready=False,  # mark as not ready until all threads are started
    )

    # Alert manager — notify_callback pushes new alerts into the Flask app config
    # so the dashboard can serve them immediately without a DB round-trip.
    def _notify_callback(alert) -> None:
        # No-op for now; the dashboard reads from alert_manager.get_recent_alerts()
        # which is backed by the in-memory ring buffer.
        pass

    alert_manager = AlertManager(
        log_store=log_store,
        notify_callback=_notify_callback,
    )

    # Wire the alert_manager into the Flask app config now that it exists
    flask_app.config["ALERT_MANAGER"] = alert_manager

    # Detection engine
    detection_engine = DetectionEngine(
        alert_manager=alert_manager,
        config=config,
        packet_queue=packet_queue,
        stop_event=stop_event,
    )

    # Capture engine — pass stats_provider so it updates per-second counts
    capture_engine = PacketCaptureEngine(
        interface=config.interface,
        packet_queue=packet_queue,
        bpf_filter=config.bpf_filter,
        stop_event=stop_event,
        stats_provider=stats_provider,
    )

    # SIGINT/SIGTERM handler for graceful shutdown
    def _shutdown(signum, frame):
        logger.info("IDS stopping (signal %d)", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Start capture thread (daemon so it doesn't block process exit)
    capture_thread = threading.Thread(
        target=capture_engine.start,
        name="packet-capture",
        daemon=True,
    )
    capture_thread.start()

    # Start detection thread
    detection_thread = threading.Thread(
        target=detection_engine.run,
        name="detection-engine",
        daemon=True,
    )
    detection_thread.start()

    # Start Flask dashboard in a daemon thread
    def _run_dashboard() -> None:
        logger.info(
            "Dashboard starting on http://0.0.0.0:%d", config.dashboard_port
        )
        flask_app.run(
            host="0.0.0.0",
            port=config.dashboard_port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )

    dashboard_thread = threading.Thread(
        target=_run_dashboard,
        name="dashboard",
        daemon=True,
    )
    dashboard_thread.start()

    # Mark IDS as ready now that all threads are running
    flask_app.config["IDS_READY"] = True

    logger.info(
        "IDS started — capture, detection, and dashboard running "
        "(dashboard: http://localhost:%d)",
        config.dashboard_port,
    )

    # Block main thread until stop signal received
    stop_event.wait()

    # Graceful shutdown sequence
    logger.info("IDS shutting down…")
    flask_app.config["IDS_READY"] = False

    capture_engine.stop()
    capture_thread.join(timeout=5.0)
    detection_thread.join(timeout=5.0)
    alert_manager.stop()
    log_store.flush()

    logger.info("IDS stopped")
    sys.exit(0)


if __name__ == "__main__":
    main()
