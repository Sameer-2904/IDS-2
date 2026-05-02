"""ids/capture.py — Packet capture engine for the Network IDS."""

from __future__ import annotations

import collections
import logging
import queue
import sys
import threading
import time

logger = logging.getLogger("ids.capture")


class PacketCaptureEngine:
    """Captures raw network packets using Scapy and enqueues them.

    Parameters
    ----------
    interface:
        Network interface name to capture on (e.g. "eth0", "en0").
    packet_queue:
        Thread-safe queue to enqueue captured packets.
    bpf_filter:
        Optional BPF filter string (e.g. "tcp port 80"). None means capture all.
    stop_event:
        Threading event; when set, the sniffer stops.
    stats_provider:
        Optional deque (maxlen=60) that receives per-second packet counts.
        Updated by the capture engine once per second.
    """

    def __init__(
        self,
        interface: str,
        packet_queue: queue.Queue,
        bpf_filter: str | None,
        stop_event: threading.Event,
        stats_provider: collections.deque | None = None,
    ) -> None:
        self._interface = interface
        self._packet_queue = packet_queue
        self._bpf_filter = bpf_filter
        self._stop_event = stop_event
        self._stats_provider = stats_provider
        self._drop_count = 0
        self._stop_flag = threading.Event()
        # Per-second packet counter for stats
        self._current_second: int = int(time.time())
        self._packets_this_second: int = 0

    def start(self) -> None:
        """Start sniffing in the current thread (blocking). Call from a dedicated thread."""
        logger.info("PacketCaptureEngine starting on interface %s", self._interface)
        try:
            from scapy.all import sniff
            sniff(
                iface=self._interface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set() or self._stop_flag.is_set(),
                filter=self._bpf_filter or "",
            )
        except OSError as exc:
            logger.error(
                "Failed to open interface '%s': %s", self._interface, exc
            )
            sys.exit(1)
        logger.info("PacketCaptureEngine stopped on interface %s", self._interface)

    def _on_packet(self, packet) -> None:
        """Callback invoked by Scapy for each captured packet."""
        try:
            self._packet_queue.put_nowait(packet)
        except queue.Full:
            # Queue is full — discard oldest packet to make room
            try:
                self._packet_queue.get_nowait()
            except queue.Empty:
                pass
            self._drop_count += 1
            logger.warning(
                "Packet queue full — dropped oldest packet (total drops: %d)",
                self._drop_count,
            )
            try:
                self._packet_queue.put_nowait(packet)
            except queue.Full:
                pass

        # Update per-second stats if a stats_provider deque is configured
        if self._stats_provider is not None:
            now_second = int(time.time())
            if now_second != self._current_second:
                # Flush the completed second's count into the deque
                self._stats_provider.append(self._packets_this_second)
                self._packets_this_second = 0
                self._current_second = now_second
            self._packets_this_second += 1

    def stop(self) -> None:
        """Signal the sniffer to stop."""
        self._stop_flag.set()
