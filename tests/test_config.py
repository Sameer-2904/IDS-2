"""Unit tests for ids/config.py — DetectionConfig and load_config."""

import logging
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

from ids.config import DetectionConfig, load_config


# ---------------------------------------------------------------------------
# DetectionConfig — model-level tests
# ---------------------------------------------------------------------------


class TestDetectionConfigDefaults:
    def test_required_interface(self):
        cfg = DetectionConfig(interface="eth0")
        assert cfg.interface == "eth0"

    def test_defaults(self):
        cfg = DetectionConfig(interface="eth0")
        assert cfg.bpf_filter is None
        assert cfg.port_scan_threshold == 20
        assert cfg.port_scan_window_seconds == 10
        assert cfg.brute_force_threshold == 10
        assert cfg.brute_force_window_seconds == 10
        assert cfg.brute_force_ports == [22, 21, 3389, 5900]
        assert cfg.dos_threshold_pps == 100
        assert cfg.dos_window_seconds == 10
        assert cfg.dos_consecutive_intervals == 3
        assert cfg.dashboard_port == 5000
        assert cfg.log_store_path == "ids.db"
        assert cfg.log_file_path == "ids.log"
        assert cfg.log_level == "INFO"
        assert cfg.ip_blocker_enabled is False

    def test_interface_is_required(self):
        with pytest.raises(Exception):
            DetectionConfig()  # type: ignore[call-arg]

    def test_custom_values(self):
        cfg = DetectionConfig(
            interface="wlan0",
            bpf_filter="tcp",
            port_scan_threshold=50,
            port_scan_window_seconds=5,
            brute_force_threshold=20,
            brute_force_window_seconds=30,
            brute_force_ports=[22, 3306],
            dos_threshold_pps=500,
            dos_window_seconds=15,
            dos_consecutive_intervals=5,
            dashboard_port=8080,
            log_store_path="/tmp/ids.db",
            log_file_path="/tmp/ids.log",
            log_level="DEBUG",
            ip_blocker_enabled=True,
        )
        assert cfg.interface == "wlan0"
        assert cfg.bpf_filter == "tcp"
        assert cfg.port_scan_threshold == 50
        assert cfg.dashboard_port == 8080
        assert cfg.ip_blocker_enabled is True


class TestDetectionConfigValidation:
    """PositiveInt fields must reject zero and negative values."""

    @pytest.mark.parametrize(
        "field",
        [
            "port_scan_threshold",
            "port_scan_window_seconds",
            "brute_force_threshold",
            "brute_force_window_seconds",
            "dos_threshold_pps",
            "dos_window_seconds",
            "dos_consecutive_intervals",
            "dashboard_port",
        ],
    )
    def test_zero_rejected(self, field):
        with pytest.raises(Exception):
            DetectionConfig(interface="eth0", **{field: 0})

    @pytest.mark.parametrize(
        "field",
        [
            "port_scan_threshold",
            "port_scan_window_seconds",
            "brute_force_threshold",
            "brute_force_window_seconds",
            "dos_threshold_pps",
            "dos_window_seconds",
            "dos_consecutive_intervals",
            "dashboard_port",
        ],
    )
    def test_negative_rejected(self, field):
        with pytest.raises(Exception):
            DetectionConfig(interface="eth0", **{field: -5})


# ---------------------------------------------------------------------------
# load_config — file-based tests
# ---------------------------------------------------------------------------


def _write_yaml(tmp_path: Path, content: str) -> str:
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(p)


class TestLoadConfig:
    def test_minimal_valid_config(self, tmp_path):
        path = _write_yaml(tmp_path, "interface: eth0\n")
        cfg = load_config(path)
        assert cfg.interface == "eth0"
        assert cfg.port_scan_threshold == 20  # default

    def test_full_valid_config(self, tmp_path):
        content = """
            interface: wlan0
            bpf_filter: "tcp port 80"
            port_scan_threshold: 30
            port_scan_window_seconds: 15
            brute_force_threshold: 5
            brute_force_window_seconds: 20
            brute_force_ports: [22, 3389]
            dos_threshold_pps: 200
            dos_window_seconds: 5
            dos_consecutive_intervals: 4
            dashboard_port: 8080
            log_store_path: /tmp/ids.db
            log_file_path: /tmp/ids.log
            log_level: DEBUG
            ip_blocker_enabled: true
        """
        path = _write_yaml(tmp_path, content)
        cfg = load_config(path)
        assert cfg.interface == "wlan0"
        assert cfg.bpf_filter == "tcp port 80"
        assert cfg.port_scan_threshold == 30
        assert cfg.dashboard_port == 8080
        assert cfg.ip_blocker_enabled is True

    def test_missing_file_exits(self, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            load_config(str(tmp_path / "nonexistent.yaml"))
        assert exc_info.value.code == 1

    def test_missing_required_key_exits(self, tmp_path):
        # 'interface' is required — omitting it should cause sys.exit(1)
        path = _write_yaml(tmp_path, "port_scan_threshold: 10\n")
        with pytest.raises(SystemExit) as exc_info:
            load_config(path)
        assert exc_info.value.code == 1

    def test_invalid_yaml_exits(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("interface: [unclosed", encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            load_config(str(p))
        assert exc_info.value.code == 1

    def test_non_positive_threshold_exits(self, tmp_path):
        path = _write_yaml(tmp_path, "interface: eth0\nport_scan_threshold: 0\n")
        with pytest.raises(SystemExit) as exc_info:
            load_config(path)
        assert exc_info.value.code == 1

    def test_negative_threshold_exits(self, tmp_path):
        path = _write_yaml(tmp_path, "interface: eth0\ndos_threshold_pps: -1\n")
        with pytest.raises(SystemExit) as exc_info:
            load_config(path)
        assert exc_info.value.code == 1

    def test_error_message_identifies_field(self, tmp_path, caplog):
        """The error log should mention the offending key name."""
        path = _write_yaml(tmp_path, "interface: eth0\nport_scan_threshold: -5\n")
        with pytest.raises(SystemExit):
            with caplog.at_level(logging.ERROR, logger="ids.config"):
                load_config(path)
        assert any("port_scan_threshold" in record.message for record in caplog.records)

    def test_non_mapping_yaml_exits(self, tmp_path):
        p = tmp_path / "list.yaml"
        p.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            load_config(str(p))
        assert exc_info.value.code == 1
