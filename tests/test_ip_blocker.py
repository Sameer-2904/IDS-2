"""Unit tests for ids/ip_blocker.py."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from ids.ip_blocker import BlockResult, IPBlocker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_completed_process(returncode: int, stderr: str = "") -> MagicMock:
    """Return a mock CompletedProcess with the given returncode and stderr."""
    mock = MagicMock()
    mock.returncode = returncode
    mock.stderr = stderr
    return mock


# ---------------------------------------------------------------------------
# BlockResult dataclass
# ---------------------------------------------------------------------------

class TestBlockResult:
    def test_success_fields(self):
        result = BlockResult(success=True, ip="1.2.3.4")
        assert result.success is True
        assert result.ip == "1.2.3.4"
        assert result.error_message is None

    def test_failure_fields(self):
        result = BlockResult(success=False, ip="1.2.3.4", error_message="permission denied")
        assert result.success is False
        assert result.ip == "1.2.3.4"
        assert result.error_message == "permission denied"


# ---------------------------------------------------------------------------
# Linux path — block()
# ---------------------------------------------------------------------------

class TestIPBlockerLinux:
    """Tests for the Linux (iptables) command path."""

    @patch("ids.ip_blocker.platform.system", return_value="Linux")
    @patch("ids.ip_blocker.subprocess.run")
    def test_block_success(self, mock_run, _mock_system):
        mock_run.return_value = _make_completed_process(returncode=0)
        blocker = IPBlocker()
        result = blocker.block("192.168.1.1")

        assert result.success is True
        assert result.ip == "192.168.1.1"
        assert result.error_message is None

        # Verify the correct iptables command was used
        called_cmd = mock_run.call_args[0][0]
        assert called_cmd == ["iptables", "-I", "INPUT", "-s", "192.168.1.1", "-j", "DROP"]

    @patch("ids.ip_blocker.platform.system", return_value="Linux")
    @patch("ids.ip_blocker.subprocess.run")
    def test_block_failure_nonzero_exit(self, mock_run, _mock_system):
        mock_run.return_value = _make_completed_process(returncode=1, stderr="iptables: Permission denied")
        blocker = IPBlocker()
        result = blocker.block("192.168.1.1")

        assert result.success is False
        assert result.ip == "192.168.1.1"
        assert result.error_message == "iptables: Permission denied"

    @patch("ids.ip_blocker.platform.system", return_value="Linux")
    @patch("ids.ip_blocker.subprocess.run")
    def test_block_failure_nonzero_no_stderr(self, mock_run, _mock_system):
        """When stderr is empty, error_message should fall back to exit-code description."""
        mock_run.return_value = _make_completed_process(returncode=2, stderr="")
        blocker = IPBlocker()
        result = blocker.block("10.0.0.1")

        assert result.success is False
        assert "2" in result.error_message  # exit code mentioned

    @patch("ids.ip_blocker.platform.system", return_value="Linux")
    @patch("ids.ip_blocker.subprocess.run")
    def test_unblock_success(self, mock_run, _mock_system):
        mock_run.return_value = _make_completed_process(returncode=0)
        blocker = IPBlocker()
        result = blocker.unblock("192.168.1.1")

        assert result.success is True
        assert result.ip == "192.168.1.1"
        assert result.error_message is None

        called_cmd = mock_run.call_args[0][0]
        assert called_cmd == ["iptables", "-D", "INPUT", "-s", "192.168.1.1", "-j", "DROP"]

    @patch("ids.ip_blocker.platform.system", return_value="Linux")
    @patch("ids.ip_blocker.subprocess.run")
    def test_unblock_failure_nonzero_exit(self, mock_run, _mock_system):
        mock_run.return_value = _make_completed_process(returncode=1, stderr="Bad rule")
        blocker = IPBlocker()
        result = blocker.unblock("192.168.1.1")

        assert result.success is False
        assert result.error_message == "Bad rule"


# ---------------------------------------------------------------------------
# Windows path — block() / unblock()
# ---------------------------------------------------------------------------

class TestIPBlockerWindows:
    """Tests for the Windows (netsh) command path."""

    @patch("ids.ip_blocker.platform.system", return_value="Windows")
    @patch("ids.ip_blocker.subprocess.run")
    def test_block_success(self, mock_run, _mock_system):
        mock_run.return_value = _make_completed_process(returncode=0)
        blocker = IPBlocker()
        result = blocker.block("10.0.0.5")

        assert result.success is True
        assert result.ip == "10.0.0.5"
        assert result.error_message is None

        called_cmd = mock_run.call_args[0][0]
        assert called_cmd[0] == "netsh"
        assert "add" in called_cmd
        assert "IDS_BLOCK_10.0.0.5" in " ".join(called_cmd)
        assert "remoteip=10.0.0.5" in called_cmd

    @patch("ids.ip_blocker.platform.system", return_value="Windows")
    @patch("ids.ip_blocker.subprocess.run")
    def test_block_failure_nonzero_exit(self, mock_run, _mock_system):
        mock_run.return_value = _make_completed_process(returncode=1, stderr="Access denied")
        blocker = IPBlocker()
        result = blocker.block("10.0.0.5")

        assert result.success is False
        assert result.error_message == "Access denied"

    @patch("ids.ip_blocker.platform.system", return_value="Windows")
    @patch("ids.ip_blocker.subprocess.run")
    def test_unblock_success(self, mock_run, _mock_system):
        mock_run.return_value = _make_completed_process(returncode=0)
        blocker = IPBlocker()
        result = blocker.unblock("10.0.0.5")

        assert result.success is True
        assert result.ip == "10.0.0.5"
        assert result.error_message is None

        called_cmd = mock_run.call_args[0][0]
        assert called_cmd[0] == "netsh"
        assert "delete" in called_cmd
        assert "IDS_BLOCK_10.0.0.5" in " ".join(called_cmd)

    @patch("ids.ip_blocker.platform.system", return_value="Windows")
    @patch("ids.ip_blocker.subprocess.run")
    def test_unblock_failure_nonzero_exit(self, mock_run, _mock_system):
        mock_run.return_value = _make_completed_process(returncode=1, stderr="Rule not found")
        blocker = IPBlocker()
        result = blocker.unblock("10.0.0.5")

        assert result.success is False
        assert result.error_message == "Rule not found"


# ---------------------------------------------------------------------------
# Unsupported OS
# ---------------------------------------------------------------------------

class TestIPBlockerUnsupportedOS:
    @patch("ids.ip_blocker.platform.system", return_value="Darwin")
    def test_block_unsupported_os(self, _mock_system):
        blocker = IPBlocker()
        result = blocker.block("1.2.3.4")

        assert result.success is False
        assert "Darwin" in result.error_message

    @patch("ids.ip_blocker.platform.system", return_value="Darwin")
    def test_unblock_unsupported_os(self, _mock_system):
        blocker = IPBlocker()
        result = blocker.unblock("1.2.3.4")

        assert result.success is False
        assert "Darwin" in result.error_message


# ---------------------------------------------------------------------------
# Subprocess edge cases (timeout, unexpected exception)
# ---------------------------------------------------------------------------

class TestIPBlockerSubprocessEdgeCases:
    @patch("ids.ip_blocker.platform.system", return_value="Linux")
    @patch("ids.ip_blocker.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="iptables", timeout=10))
    def test_block_timeout(self, _mock_run, _mock_system):
        blocker = IPBlocker()
        result = blocker.block("1.2.3.4")

        assert result.success is False
        assert result.error_message == "Command timed out"

    @patch("ids.ip_blocker.platform.system", return_value="Linux")
    @patch("ids.ip_blocker.subprocess.run", side_effect=OSError("No such file or directory"))
    def test_block_unexpected_exception(self, _mock_run, _mock_system):
        blocker = IPBlocker()
        result = blocker.block("1.2.3.4")

        assert result.success is False
        assert "No such file or directory" in result.error_message

    @patch("ids.ip_blocker.platform.system", return_value="Linux")
    @patch("ids.ip_blocker.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="iptables", timeout=10))
    def test_unblock_timeout(self, _mock_run, _mock_system):
        blocker = IPBlocker()
        result = blocker.unblock("1.2.3.4")

        assert result.success is False
        assert result.error_message == "Command timed out"
