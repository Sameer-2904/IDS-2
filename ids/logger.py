"""ids/logger.py — JSON structured logging for the Network IDS.

Provides a `setup_logging` function that configures a named "ids" logger
with a custom JSON formatter, writing to both a file and stdout.
"""

import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """Serialise each LogRecord to a single-line JSON object.

    The output always contains at minimum:
      - ``timestamp`` — ISO 8601 UTC with microseconds, e.g. "2024-01-15T10:30:00.123456Z"
      - ``level``     — e.g. "INFO", "ERROR"
      - ``message``   — the fully formatted log message
    """

    def format(self, record: logging.LogRecord) -> str:
        # Ensure exc_info / stack_info are rendered into record.message first.
        message = super().format(record)

        # Build UTC timestamp in ISO 8601 format with trailing "Z".
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        timestamp = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"

        entry: dict = {
            "timestamp": timestamp,
            "level": record.levelname,
            "message": message,
        }

        return json.dumps(entry, ensure_ascii=False)


def setup_logging(log_file_path: str, log_level: str) -> logging.Logger:
    """Configure and return the named "ids" logger.

    Attaches:
    - A ``FileHandler`` writing JSON lines to *log_file_path*.
    - A ``StreamHandler`` writing JSON lines to stdout.

    Both handlers use :class:`JsonFormatter`.

    Args:
        log_file_path: Path to the log file (created if it does not exist).
        log_level:     Standard Python log-level name, e.g. ``"INFO"``, ``"DEBUG"``.

    Returns:
        The configured ``logging.Logger`` instance named ``"ids"``.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    logger = logging.getLogger("ids")
    logger.setLevel(numeric_level)

    # Avoid adding duplicate handlers if setup_logging is called more than once.
    if logger.handlers:
        logger.handlers.clear()

    formatter = JsonFormatter()

    # File handler
    file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)

    # Stream handler (stdout)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(numeric_level)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    # Prevent log records from propagating to the root logger to avoid
    # duplicate output when basicConfig has also been called.
    logger.propagate = False

    return logger
