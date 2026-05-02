"""ids/ip_blocker.py — OS-level IP blocking for the Network IDS."""

from __future__ import annotations

import logging
import platform
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger("ids.ip_blocker")


@dataclass
class BlockResult:
    """Result of a block or unblock operation."""
    success: bool
    ip: str
    error_message: str | None = None


class IPBlocker:
    """Applies and removes OS-level firewall rules to block/unblock IPs.

    Supports:
    - Linux: iptables
    - Windows: netsh
    """

    def __init__(self) -> None:
        self._os = platform.system()
        logger.info("IPBlocker initialised for OS: %s", self._os)

    def block(self, ip: str) -> BlockResult:
        """Apply a firewall rule to drop all inbound traffic from *ip*."""
        logger.info("Blocking IP: %s", ip)
        if self._os == "Linux":
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        elif self._os == "Windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=IDS_BLOCK_{ip}", "dir=in", "action=block",
                f"remoteip={ip}"
            ]
        else:
            msg = f"Unsupported OS: {self._os}"
            logger.error(msg)
            return BlockResult(success=False, ip=ip, error_message=msg)

        return self._run(cmd, ip)

    def unblock(self, ip: str) -> BlockResult:
        """Remove the firewall rule blocking *ip*."""
        logger.info("Unblocking IP: %s", ip)
        if self._os == "Linux":
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        elif self._os == "Windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=IDS_BLOCK_{ip}"
            ]
        else:
            msg = f"Unsupported OS: {self._os}"
            logger.error(msg)
            return BlockResult(success=False, ip=ip, error_message=msg)

        return self._run(cmd, ip)

    def _run(self, cmd: list[str], ip: str) -> BlockResult:
        """Execute *cmd* as a subprocess and return a BlockResult."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.info("Command succeeded: %s", " ".join(cmd))
                return BlockResult(success=True, ip=ip)
            else:
                error = result.stderr.strip() or f"Command exited with code {result.returncode}"
                logger.error("Command failed for IP %s: %s", ip, error)
                return BlockResult(success=False, ip=ip, error_message=error)
        except subprocess.TimeoutExpired:
            msg = "Command timed out"
            logger.error("Command timed out for IP %s", ip)
            return BlockResult(success=False, ip=ip, error_message=msg)
        except Exception as exc:
            msg = str(exc)
            logger.error("Command raised exception for IP %s: %s", ip, msg)
            return BlockResult(success=False, ip=ip, error_message=msg)
