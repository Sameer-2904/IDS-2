"""ids/dashboard/__init__.py — Flask application factory for the IDS dashboard."""

from __future__ import annotations

import collections
from typing import Callable

from flask import Flask


def create_app(
    alert_manager=None,
    log_store=None,
    stats_provider=None,
    ip_blocker=None,
    ready: bool = True,
) -> Flask:
    """Create and configure the Flask application.

    Parameters
    ----------
    alert_manager:
        AlertManager instance for recent alerts.
    log_store:
        LogStore instance for persistent alert queries.
    stats_provider:
        A collections.deque of per-second packet counts (60-point rolling window).
        Updated externally by the capture engine.
    ip_blocker:
        Optional IPBlocker instance. None if ip_blocker_enabled is False.
    ready:
        Set to False to return HTTP 503 from /api/health until components are ready.
    """
    app = Flask(__name__, template_folder="templates")

    # Store dependencies in app config
    app.config["ALERT_MANAGER"] = alert_manager
    app.config["LOG_STORE"] = log_store
    app.config["STATS_PROVIDER"] = stats_provider or collections.deque(maxlen=60)
    app.config["IP_BLOCKER"] = ip_blocker
    app.config["IDS_READY"] = ready

    from ids.dashboard.routes import register_routes
    register_routes(app)

    return app
