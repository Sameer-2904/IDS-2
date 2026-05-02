"""tests/test_capture.py — Unit tests for ids/capture.py (PacketCaptureEngine).

Covers:
- _on_packet enqueues packets when queue has space
- _on_packet discards oldest packet and increments drop_count when queue is full
- stop() sets the internal stop flag
- start() calls sys.exit(1) on OSError (scapy.all.sniff mocked to raise OSError)
"""

from __future__ import annotations

import queue
import threading
from unittest.mock import MagicMock, patch

import pytest

from ids.capture import PacketCaptureEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(maxsize: int = 10) -> tuple[PacketCaptureEngine, queue.Queue, threading.Event]:
    """Return a PacketCaptureEngine with a fresh queue and stop_event."""
    pq = queue.Queue(maxsize=maxsize)
    stop_event = threading.Event()
    engine = PacketCaptureEngine(
        interface="eth0",
        packet_queue=pq,
        bpf_filter=None,
        stop_event=stop_event,
    )
    return engine, pq, stop_event


# ---------------------------------------------------------------------------
# _on_packet: normal enqueue
# ---------------------------------------------------------------------------

class TestOnPacketEnqueue:
    def test_packet_enqueued_when_queue_has_space(self):
        """_on_packet must put the packet onto the queue when space is available."""
        engine, pq, _ = _make_engine(maxsize=5)
        fake_packet = MagicMock()
        engine._on_packet(fake_packet)
        assert pq.qsize() == 1
        assert pq.get_nowait() is fake_packet

    def test_multiple_packets_enqueued_in_order(self):
        """Multiple packets should be enqueued in FIFO order."""
        engine, pq, _ = _make_engine(maxsize=10)
        packets = [MagicMock() for _ in range(5)]
        for pkt in packets:
            engine._on_packet(pkt)
        assert pq.qsize() == 5
        for expected in packets:
            assert pq.get_nowait() is expected

    def test_drop_count_not_incremented_on_normal_enqueue(self):
        """drop_count must remain 0 when packets are enqueued normally."""
        engine, pq, _ = _make_engine(maxsize=5)
        for _ in range(3):
            engine._on_packet(MagicMock())
        assert engine._drop_count == 0


# ---------------------------------------------------------------------------
# _on_packet: queue full — back-pressure / drop oldest
# ---------------------------------------------------------------------------

class TestOnPacketQueueFull:
    def test_oldest_packet_discarded_when_queue_full(self):
        """When the queue is full, the oldest packet must be discarded."""
        engine, pq, _ = _make_engine(maxsize=3)
        # Fill the queue
        old_packets = [MagicMock(name=f"old_{i}") for i in range(3)]
        for pkt in old_packets:
            pq.put_nowait(pkt)

        new_packet = MagicMock(name="new")
        engine._on_packet(new_packet)

        # Queue should still be at maxsize
        assert pq.qsize() == 3
        # The oldest packet (old_packets[0]) should have been evicted
        items = []
        while not pq.empty():
            items.append(pq.get_nowait())
        assert old_packets[0] not in items
        assert new_packet in items

    def test_drop_count_incremented_when_queue_full(self):
        """drop_count must be incremented each time a packet is dropped."""
        engine, pq, _ = _make_engine(maxsize=2)
        # Fill the queue
        pq.put_nowait(MagicMock())
        pq.put_nowait(MagicMock())

        # Trigger two drops
        engine._on_packet(MagicMock())
        engine._on_packet(MagicMock())

        assert engine._drop_count == 2

    def test_new_packet_present_in_queue_after_drop(self):
        """The new packet must be present in the queue after the oldest is dropped."""
        engine, pq, _ = _make_engine(maxsize=1)
        old_packet = MagicMock(name="old")
        new_packet = MagicMock(name="new")
        pq.put_nowait(old_packet)

        engine._on_packet(new_packet)

        assert pq.qsize() == 1
        assert pq.get_nowait() is new_packet

    def test_drop_count_zero_initially(self):
        """drop_count must start at 0."""
        engine, _, _ = _make_engine()
        assert engine._drop_count == 0


# ---------------------------------------------------------------------------
# stop()
# ---------------------------------------------------------------------------

class TestStop:
    def test_stop_sets_internal_stop_flag(self):
        """stop() must set the internal _stop_flag event."""
        engine, _, _ = _make_engine()
        assert not engine._stop_flag.is_set()
        engine.stop()
        assert engine._stop_flag.is_set()

    def test_stop_does_not_set_external_stop_event(self):
        """stop() must only set the internal flag, not the external stop_event."""
        engine, _, stop_event = _make_engine()
        engine.stop()
        assert not stop_event.is_set()

    def test_stop_idempotent(self):
        """Calling stop() multiple times must not raise."""
        engine, _, _ = _make_engine()
        engine.stop()
        engine.stop()  # should not raise
        assert engine._stop_flag.is_set()


# ---------------------------------------------------------------------------
# start(): OSError handling
# ---------------------------------------------------------------------------

class TestStartOSError:
    def test_start_calls_sys_exit_on_oserror(self):
        """start() must call sys.exit(1) when scapy.sniff raises OSError."""
        engine, _, _ = _make_engine()

        with patch("scapy.all.sniff", side_effect=OSError("No such device")):
            with pytest.raises(SystemExit) as exc_info:
                engine.start()

        assert exc_info.value.code == 1

    def test_start_logs_error_on_oserror(self, caplog):
        """start() must log an ERROR message identifying the interface when OSError occurs."""
        import logging
        engine, _, _ = _make_engine()

        with patch("scapy.all.sniff", side_effect=OSError("No such device")):
            with caplog.at_level(logging.ERROR, logger="ids.capture"):
                with pytest.raises(SystemExit):
                    engine.start()

        error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert len(error_records) >= 1
        # The interface name must appear in the error message
        assert "eth0" in error_records[0].getMessage()

    def test_start_calls_sniff_with_correct_interface(self):
        """start() must pass the configured interface to scapy.sniff."""
        pq = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        stop_event.set()  # stop immediately after first call
        engine = PacketCaptureEngine(
            interface="lo",
            packet_queue=pq,
            bpf_filter="tcp",
            stop_event=stop_event,
        )

        with patch("scapy.all.sniff") as mock_sniff:
            engine.start()

        mock_sniff.assert_called_once()
        call_kwargs = mock_sniff.call_args.kwargs
        assert call_kwargs["iface"] == "lo"
        assert call_kwargs["filter"] == "tcp"
        assert call_kwargs["store"] is False

    def test_start_uses_empty_string_filter_when_bpf_filter_is_none(self):
        """start() must pass an empty string to scapy.sniff when bpf_filter is None."""
        pq = queue.Queue(maxsize=10)
        stop_event = threading.Event()
        stop_event.set()
        engine = PacketCaptureEngine(
            interface="eth0",
            packet_queue=pq,
            bpf_filter=None,
            stop_event=stop_event,
        )

        with patch("scapy.all.sniff") as mock_sniff:
            engine.start()

        call_kwargs = mock_sniff.call_args.kwargs
        assert call_kwargs["filter"] == ""
