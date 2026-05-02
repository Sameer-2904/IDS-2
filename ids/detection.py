"""ids/detection.py — Detection Engine and detector sub-modules.

Implements rule-based detectors that analyse captured packets and emit Alert
objects when attack thresholds are crossed.
"""

from __future__ import annotations

import datetime
import logging
import queue
import threading
import time
from typing import TYPE_CHECKING

from ids.config import DetectionConfig
from ids.models import Alert, AttackType, severity_for_alert

if TYPE_CHECKING:
    pass


def _utc_iso(ts: float) -> str:
    """Convert a POSIX timestamp to an ISO 8601 UTC string."""
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _extract_dport(packet) -> int | None:
    """Extract the destination port from a packet using duck typing.

    Supports real Scapy packets (TCP/UDP layers) as well as simple mock
    objects used in tests.
    """
    # Direct attribute (mock objects or already-extracted layer)
    if hasattr(packet, "dport"):
        return packet.dport

    # One level of payload nesting (e.g. IP / TCP in Scapy)
    if hasattr(packet, "payload") and hasattr(packet.payload, "dport"):
        return packet.payload.dport

    return None


class PortScanDetector:
    """Detects port-scanning behaviour from a single source IP.

    A PORT_SCAN alert is raised when a source IP contacts more than
    *threshold* distinct destination ports within a *window_seconds*-wide
    sliding window.  Only one alert is emitted per window per source IP.

    Parameters
    ----------
    threshold:
        Number of distinct destination ports that must be exceeded before an
        alert is raised (i.e. alert fires when ``len(ports) > threshold``).
    window_seconds:
        Duration of the observation window in seconds.
    """

    def __init__(self, threshold: int, window_seconds: int) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds

        # Per-source-IP state
        self._ports: dict[str, set[int]] = {}
        self._window_start: dict[str, float] = {}
        self._alert_emitted: dict[str, bool] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def process(self, packet, src_ip: str, now: float) -> Alert | None:
        """Process a single packet and return an Alert if a scan is detected.

        Parameters
        ----------
        packet:
            A Scapy packet (or mock object) from which the destination port
            will be extracted.
        src_ip:
            Source IP address string of the packet sender.
        now:
            Current POSIX timestamp (seconds since epoch).

        Returns
        -------
        Alert | None
            A PORT_SCAN Alert if the threshold is exceeded for the first time
            in the current window; ``None`` otherwise.
        """
        dport = _extract_dport(packet)
        if dport is None:
            return None

        # Initialise window for new source IPs
        if src_ip not in self._window_start:
            self._window_start[src_ip] = now
            self._ports[src_ip] = set()
            self._alert_emitted[src_ip] = False

        self._ports[src_ip].add(dport)

        port_count = len(self._ports[src_ip])

        if port_count > self.threshold and not self._alert_emitted[src_ip]:
            self._alert_emitted[src_ip] = True
            severity = severity_for_alert(AttackType.PORT_SCAN, port_count=port_count)
            return Alert(
                id="",
                timestamp=_utc_iso(now),
                src_ip=src_ip,
                attack_type=AttackType.PORT_SCAN,
                severity=severity,
                metadata={
                    "port_count": port_count,
                    "ports_sampled": list(self._ports[src_ip])[:10],
                },
            )

        return None

    def tick(self, now: float) -> list[Alert]:
        """Expire windows that are older than *window_seconds*.

        Removes all per-IP state for expired windows so that the next packet
        from that IP starts a fresh window.

        Parameters
        ----------
        now:
            Current POSIX timestamp used to determine which windows have
            expired.

        Returns
        -------
        list[Alert]
            Always an empty list — tick does not generate new alerts for port
            scan detection.
        """
        expired = [
            ip
            for ip, start in self._window_start.items()
            if now - start >= self.window_seconds
        ]
        for ip in expired:
            del self._ports[ip]
            del self._window_start[ip]
            del self._alert_emitted[ip]

        return []


def _is_tcp_syn(packet) -> tuple[bool, int | None]:
    """Determine whether a packet is a TCP SYN and extract the destination port.

    Supports both real Scapy packets and lightweight mock objects used in tests.

    Returns
    -------
    (True, dport) if the packet is a TCP SYN directed at a known port.
    (False, None) otherwise.
    """
    # Try Scapy-style
    try:
        if packet.haslayer("TCP"):
            tcp = packet["TCP"]
            if tcp.flags & 0x02:
                return True, tcp.dport
    except (AttributeError, TypeError):
        pass
    # Try mock-style (direct attributes)
    if hasattr(packet, "flags") and hasattr(packet, "dport"):
        if packet.flags & 0x02:
            return True, packet.dport
    return False, None


class BruteForceDetector:
    """Detects brute-force login attempts against monitored ports.

    A BRUTE_FORCE alert is raised when a source IP sends more than *threshold*
    TCP SYN packets to a single monitored port within a *window_seconds*-wide
    sliding window.  Only one alert is emitted per (src_ip, port) pair per
    window.

    Parameters
    ----------
    threshold:
        Number of SYN packets that must be exceeded before an alert is raised
        (i.e. alert fires when ``count > threshold``).
    window_seconds:
        Duration of the observation window in seconds.
    monitored_ports:
        List of destination ports to watch for brute-force activity.
    """

    def __init__(
        self,
        threshold: int,
        window_seconds: int,
        monitored_ports: list[int],
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.monitored_ports = monitored_ports

        # Per-source-IP state
        self._syn_counts: dict[str, dict[int, int]] = {}
        self._window_start: dict[str, float] = {}
        self._alert_emitted: dict[str, dict[int, bool]] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def process(self, packet, src_ip: str, now: float) -> Alert | None:
        """Process a single packet and return an Alert if brute-force is detected.

        Parameters
        ----------
        packet:
            A Scapy packet (or mock object) to inspect for TCP SYN flags.
        src_ip:
            Source IP address string of the packet sender.
        now:
            Current POSIX timestamp (seconds since epoch).

        Returns
        -------
        Alert | None
            A BRUTE_FORCE Alert if the threshold is exceeded for the first time
            in the current window for the given (src_ip, port); ``None`` otherwise.
        """
        is_syn, dport = _is_tcp_syn(packet)
        if not is_syn:
            return None

        if dport not in self.monitored_ports:
            return None

        # Initialise window for new source IPs
        if src_ip not in self._window_start:
            self._window_start[src_ip] = now
            self._syn_counts[src_ip] = {}
            self._alert_emitted[src_ip] = {}

        # Increment SYN count for this (src_ip, port)
        self._syn_counts[src_ip][dport] = self._syn_counts[src_ip].get(dport, 0) + 1
        count = self._syn_counts[src_ip][dport]

        if count > self.threshold and not self._alert_emitted[src_ip].get(dport, False):
            self._alert_emitted[src_ip][dport] = True
            severity = severity_for_alert(AttackType.BRUTE_FORCE, attempt_count=count)
            return Alert(
                id="",
                timestamp=_utc_iso(now),
                src_ip=src_ip,
                attack_type=AttackType.BRUTE_FORCE,
                severity=severity,
                metadata={
                    "target_port": dport,
                    "attempt_count": count,
                },
            )

        return None

    def tick(self, now: float) -> list[Alert]:
        """Expire windows that are older than *window_seconds*.

        Removes all per-IP state for expired windows so that the next packet
        from that IP starts a fresh window.

        Parameters
        ----------
        now:
            Current POSIX timestamp used to determine which windows have
            expired.

        Returns
        -------
        list[Alert]
            Always an empty list — tick does not generate new alerts for
            brute-force detection.
        """
        expired = [
            ip
            for ip, start in self._window_start.items()
            if now - start >= self.window_seconds
        ]
        for ip in expired:
            del self._syn_counts[ip]
            del self._window_start[ip]
            del self._alert_emitted[ip]

        return []


class DoSDetector:
    """Detects Denial-of-Service attacks based on sustained high packet rates.

    A DOS alert is raised when a source IP exceeds *threshold_pps* packets per
    second for at least *consecutive_intervals* consecutive 1-second intervals.
    Only one alert is emitted per sustained burst per source IP.

    Parameters
    ----------
    threshold_pps:
        Packet rate (packets per second) that must be exceeded to count a
        1-second interval as "above threshold".
    window_seconds:
        Duration of the observation window in seconds (used by tick() to
        clean up stale buckets).
    consecutive_intervals:
        Number of consecutive 1-second intervals that must exceed
        *threshold_pps* before a DOS alert is raised.
    """

    def __init__(
        self,
        threshold_pps: int,
        window_seconds: int,
        consecutive_intervals: int,
    ) -> None:
        self.threshold_pps = threshold_pps
        self.window_seconds = window_seconds
        self.consecutive_intervals = consecutive_intervals

        # Per-source-IP state
        # _buckets[src_ip][second] = packet_count
        self._buckets: dict[str, dict[int, int]] = {}
        # _consecutive[src_ip] = number of consecutive completed seconds above threshold
        self._consecutive: dict[str, int] = {}
        # _alert_emitted[src_ip] = True once an alert has been emitted for the current burst
        self._alert_emitted: dict[str, bool] = {}
        # _last_second[src_ip] = the integer second we last processed for this IP
        self._last_second: dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def process(self, packet, src_ip: str, now: float) -> Alert | None:
        """Process a single packet and return an Alert if a DoS is detected.

        The method tracks per-second packet counts.  When the clock advances
        to a new second, the completed second's count is evaluated against
        *threshold_pps* and the consecutive-interval counter is updated.
        An alert is emitted the first time the consecutive counter reaches
        *consecutive_intervals* within a sustained burst.

        Parameters
        ----------
        packet:
            A Scapy packet (or mock object).  Not inspected beyond its
            presence — all that matters is the rate of arrival.
        src_ip:
            Source IP address string of the packet sender.
        now:
            Current POSIX timestamp (seconds since epoch).

        Returns
        -------
        Alert | None
            A DOS Alert if the sustained-rate condition is met for the first
            time in the current burst; ``None`` otherwise.
        """
        second = int(now)

        # Initialise state for new source IPs
        if src_ip not in self._buckets:
            self._buckets[src_ip] = {}
            self._consecutive[src_ip] = 0
            self._alert_emitted[src_ip] = False
            self._last_second[src_ip] = second

        last_sec = self._last_second[src_ip]

        # When the clock has advanced to a new second, evaluate the completed second
        if second != last_sec:
            prev_count = self._buckets[src_ip].get(last_sec, 0)
            if prev_count > self.threshold_pps:
                self._consecutive[src_ip] += 1
            else:
                self._consecutive[src_ip] = 0
                self._alert_emitted[src_ip] = False
            self._last_second[src_ip] = second

        # Increment the current second's bucket
        self._buckets[src_ip][second] = self._buckets[src_ip].get(second, 0) + 1

        # Fire alert if consecutive threshold reached and not yet emitted
        if (
            self._consecutive[src_ip] >= self.consecutive_intervals
            and not self._alert_emitted[src_ip]
        ):
            self._alert_emitted[src_ip] = True
            current_count = self._buckets[src_ip][second]
            severity = severity_for_alert(AttackType.DOS, packet_rate=current_count)
            return Alert(
                id="",
                timestamp=_utc_iso(now),
                src_ip=src_ip,
                attack_type=AttackType.DOS,
                severity=severity,
                metadata={
                    "packet_rate": float(current_count),
                    "window_seconds": self.window_seconds,
                },
            )

        return None

    def tick(self, now: float) -> list[Alert]:
        """Remove stale per-second buckets older than *window_seconds*.

        Parameters
        ----------
        now:
            Current POSIX timestamp used to determine which buckets have
            expired.

        Returns
        -------
        list[Alert]
            Always an empty list — tick does not generate new alerts for DoS
            detection.
        """
        cutoff = int(now) - self.window_seconds
        ips_to_remove = []
        for ip, buckets in self._buckets.items():
            stale = [sec for sec in list(buckets) if sec < cutoff]
            for sec in stale:
                del buckets[sec]
            if not buckets:
                ips_to_remove.append(ip)

        for ip in ips_to_remove:
            del self._buckets[ip]
            del self._consecutive[ip]
            del self._alert_emitted[ip]
            del self._last_second[ip]

        return []


class DetectionEngine:
    """Orchestrates all three detectors and drives the main detection loop.

    Parameters
    ----------
    alert_manager:
        An ``AlertManager`` instance whose ``receive(alert)`` method is called
        for every alert produced by the detectors.
    config:
        A ``DetectionConfig`` instance supplying all threshold and window
        parameters.
    packet_queue:
        The shared ``queue.Queue`` from which packets are dequeued.
    stop_event:
        A ``threading.Event`` that, when set, causes ``run()`` to return.
    """

    def __init__(
        self,
        alert_manager,
        config: DetectionConfig,
        packet_queue: queue.Queue,
        stop_event: threading.Event,
    ) -> None:
        # Instantiate all three detectors using config values
        self._port_scan = PortScanDetector(
            threshold=config.port_scan_threshold,
            window_seconds=config.port_scan_window_seconds,
        )
        self._brute_force = BruteForceDetector(
            threshold=config.brute_force_threshold,
            window_seconds=config.brute_force_window_seconds,
            monitored_ports=config.brute_force_ports,
        )
        self._dos = DoSDetector(
            threshold_pps=config.dos_threshold_pps,
            window_seconds=config.dos_window_seconds,
            consecutive_intervals=config.dos_consecutive_intervals,
        )
        self._alert_manager = alert_manager
        self._packet_queue = packet_queue
        self._stop_event = stop_event
        self._logger = logging.getLogger("ids.detection_engine")

    def run(self) -> None:
        """Main detection loop. Runs until stop_event is set."""
        self._logger.info("DetectionEngine started")
        last_tick = time.monotonic()

        while not self._stop_event.is_set():
            # Dequeue packet with 1-second timeout
            try:
                packet = self._packet_queue.get(timeout=1.0)
            except queue.Empty:
                # Still call tick even if no packets
                self._do_tick()
                last_tick = time.monotonic()
                continue

            # Extract source IP from packet
            src_ip = self._extract_src_ip(packet)
            if src_ip is None:
                continue

            now = time.time()

            # Run each detector
            for detector in (self._port_scan, self._brute_force, self._dos):
                alert = detector.process(packet, src_ip, now)
                if alert is not None:
                    self._alert_manager.receive(alert)

            # Call tick every second
            if time.monotonic() - last_tick >= 1.0:
                self._do_tick()
                last_tick = time.monotonic()

        self._logger.info("DetectionEngine stopped")

    def _do_tick(self) -> None:
        """Call tick() on all detectors and forward any resulting alerts."""
        now = time.time()
        for detector in (self._port_scan, self._brute_force, self._dos):
            alerts = detector.tick(now)
            for alert in alerts:
                self._alert_manager.receive(alert)

    def _extract_src_ip(self, packet) -> str | None:
        """Extract source IP from packet using duck typing.

        Supports Scapy-style packets (``packet['IP'].src``) as well as simple
        mock objects that expose a ``src`` attribute directly.
        """
        # Try Scapy-style IP layer
        try:
            if packet.haslayer("IP"):
                return packet["IP"].src
        except (AttributeError, TypeError):
            pass
        # Try direct attribute (mock objects)
        if hasattr(packet, "src"):
            return packet.src
        return None
