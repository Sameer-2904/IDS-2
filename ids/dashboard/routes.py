"""ids/dashboard/routes.py — Route handlers for the IDS dashboard Flask app."""

from __future__ import annotations

from flask import Flask, current_app, jsonify, render_template, request


def register_routes(app: Flask) -> None:
    """Register all URL routes on the given Flask application."""

    @app.route("/")
    def index():
        """Serve the main dashboard page."""
        ip_blocker = current_app.config.get("IP_BLOCKER")
        return render_template("index.html", ip_blocker_enabled=ip_blocker is not None)

    @app.route("/api/health")
    def health():
        """Liveness check endpoint."""
        if current_app.config.get("IDS_READY", True):
            return jsonify({"status": "ok"}), 200
        return jsonify({"status": "starting"}), 503

    @app.route("/api/stats")
    def stats():
        """Traffic statistics endpoint.

        Returns
        -------
        JSON with keys:
            total_packets: int — sum of all values in the rolling deque
            pps: float — last value in the deque (0.0 if empty)
            pps_history: list[float] — up to 60 per-second packet counts
        """
        stats_provider = current_app.config.get("STATS_PROVIDER")
        history = list(stats_provider) if stats_provider is not None else []
        total_packets = int(sum(history))
        pps = float(history[-1]) if history else 0.0
        return jsonify(
            {
                "total_packets": total_packets,
                "pps": pps,
                "pps_history": history,
            }
        )

    @app.route("/api/alerts")
    def alerts():
        """Paginated alert list.

        Query parameters
        ----------------
        page: int (default 1)
        size: int (default 25)
        q: str (optional) — filter by src_ip or attack_type (case-insensitive)
        """
        try:
            page = int(request.args.get("page", 1))
        except (ValueError, TypeError):
            page = 1
        try:
            size = int(request.args.get("size", 25))
        except (ValueError, TypeError):
            size = 25
        q = request.args.get("q", "").strip().lower()

        alert_manager = current_app.config.get("ALERT_MANAGER")
        if alert_manager is None:
            return jsonify({"alerts": [], "total": 0, "page": page, "size": size})

        # Fetch enough alerts to cover the requested page after filtering.
        raw_alerts = alert_manager.get_recent_alerts(limit=size * page)

        # Apply optional client-side filter.
        if q:
            raw_alerts = [
                a
                for a in raw_alerts
                if q in str(a.src_ip).lower() or q in str(a.attack_type).lower()
            ]

        total = len(raw_alerts)
        # Slice to the requested page.
        start = (page - 1) * size
        end = start + size
        page_alerts = raw_alerts[start:end]

        def _serialise_alert(a) -> dict:
            return {
                "id": str(a.id),
                "timestamp": str(a.timestamp),
                "src_ip": str(a.src_ip),
                "attack_type": str(a.attack_type.value) if hasattr(a.attack_type, "value") else str(a.attack_type),
                "severity": str(a.severity.value) if hasattr(a.severity, "value") else str(a.severity),
                "metadata": a.metadata if isinstance(a.metadata, dict) else {},
            }

        return jsonify(
            {
                "alerts": [_serialise_alert(a) for a in page_alerts],
                "total": total,
                "page": page,
                "size": size,
            }
        )

    @app.route("/api/suspicious-ips")
    def suspicious_ips():
        """Return the list of suspicious IPs from the log store."""
        log_store = current_app.config.get("LOG_STORE")
        if log_store is None:
            return jsonify([])

        ips = log_store.get_suspicious_ips()

        def _serialise_ip(s) -> dict:
            return {
                "ip_address": str(s.ip_address),
                "first_seen": str(s.first_seen),
                "last_seen": str(s.last_seen),
                "alert_count": int(s.alert_count),
                "attack_types": [
                    t.value if hasattr(t, "value") else str(t)
                    for t in s.attack_types
                ],
            }

        return jsonify([_serialise_ip(s) for s in ips])

    @app.route("/api/block/<ip>", methods=["POST"])
    def block_ip(ip: str):
        """Block an IP address via the IP blocker."""
        ip_blocker = current_app.config.get("IP_BLOCKER")
        if ip_blocker is None:
            return jsonify({"success": False, "error": "IP blocker not enabled"}), 400

        result = ip_blocker.block(ip)
        error = getattr(result, "error_message", None)
        return jsonify({"success": bool(result.success), "error": error})

    @app.route("/api/unblock/<ip>", methods=["POST"])
    def unblock_ip(ip: str):
        """Unblock an IP address via the IP blocker."""
        ip_blocker = current_app.config.get("IP_BLOCKER")
        if ip_blocker is None:
            return jsonify({"success": False, "error": "IP blocker not enabled"}), 400

        result = ip_blocker.unblock(ip)
        error = getattr(result, "error_message", None)
        return jsonify({"success": bool(result.success), "error": error})
