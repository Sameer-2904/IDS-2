"""ids/config.py — Configuration loading and validation for the Network IDS.

Reads a YAML file, validates it with pydantic v2, and returns a DetectionConfig.
Calls sys.exit(1) on any validation or parse failure.
"""

import logging
import sys
from typing import Optional

import yaml
from pydantic import BaseModel, PositiveInt, ValidationError

logger = logging.getLogger(__name__)


class DetectionConfig(BaseModel):
    """Validated configuration for the Network IDS.

    The `interface` field is required — the operator must specify which
    network interface to capture on.  All other fields have sensible defaults.
    """

    # --- Capture ---
    interface: str
    bpf_filter: Optional[str] = None

    # --- Port scan detection ---
    port_scan_threshold: PositiveInt = 20
    port_scan_window_seconds: PositiveInt = 10

    # --- Brute-force detection ---
    brute_force_threshold: PositiveInt = 10
    brute_force_window_seconds: PositiveInt = 10
    brute_force_ports: list[int] = [22, 21, 3389, 5900]

    # --- DoS detection ---
    dos_threshold_pps: PositiveInt = 100
    dos_window_seconds: PositiveInt = 10
    dos_consecutive_intervals: PositiveInt = 3

    # --- Dashboard ---
    dashboard_port: PositiveInt = 5000

    # --- Storage ---
    log_store_path: str = "ids.db"
    log_file_path: str = "ids.log"
    log_level: str = "INFO"

    # --- Optional features ---
    ip_blocker_enabled: bool = False


def load_config(path: str) -> DetectionConfig:
    """Read *path* (YAML), validate with pydantic, and return a DetectionConfig.

    On any error (file not found, YAML parse error, missing required key,
    invalid value) a descriptive message is logged and the process exits with
    status code 1.
    """
    # 1. Read the file
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        logger.error("Configuration file not found: %s", path)
        sys.exit(1)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse YAML configuration file '%s': %s", path, exc)
        sys.exit(1)

    if not isinstance(raw, dict):
        logger.error(
            "Configuration file '%s' must contain a YAML mapping, got %s",
            path,
            type(raw).__name__,
        )
        sys.exit(1)

    # 2. Validate with pydantic
    try:
        return DetectionConfig(**raw)
    except ValidationError as exc:
        # Report every offending field so the operator can fix them all at once.
        for error in exc.errors():
            field = ".".join(str(loc) for loc in error["loc"]) if error["loc"] else "<root>"
            msg = error["msg"]
            logger.error(
                "Configuration error for key '%s': %s (file: %s)", field, msg, path
            )
        sys.exit(1)
    except TypeError as exc:
        # Unexpected keyword arguments or other constructor issues.
        logger.error("Configuration error in '%s': %s", path, exc)
        sys.exit(1)
