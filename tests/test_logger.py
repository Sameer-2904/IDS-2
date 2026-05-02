"""tests/test_logger.py — Unit tests for ids/logger.py.

Covers:
- JsonFormatter produces valid JSON for each log record.
- JSON output contains the required fields: timestamp, level, message.
- Timestamp is in ISO 8601 UTC format (ends with "Z").
- Different log levels are correctly serialised.
- setup_logging returns a configured Logger with file and stream handlers.
"""

import io
import json
import logging
import os
import re
import tempfile

import pytest

from ids.logger import JsonFormatter, setup_logging


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(
    msg: str = "test message",
    level: int = logging.INFO,
    name: str = "ids",
) -> logging.LogRecord:
    """Create a minimal LogRecord for formatter testing."""
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname=__file__,
        lineno=0,
        msg=msg,
        args=(),
        exc_info=None,
    )
    return record


# ---------------------------------------------------------------------------
# JsonFormatter tests
# ---------------------------------------------------------------------------

class TestJsonFormatter:
    def setup_method(self):
        self.formatter = JsonFormatter()

    def test_output_is_valid_json(self):
        record = _make_record("hello world")
        output = self.formatter.format(record)
        # Should not raise
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_contains_required_fields(self):
        record = _make_record("check fields")
        parsed = json.loads(self.formatter.format(record))
        assert "timestamp" in parsed
        assert "level" in parsed
        assert "message" in parsed

    def test_timestamp_is_iso8601_utc(self):
        record = _make_record("timestamp test")
        parsed = json.loads(self.formatter.format(record))
        ts = parsed["timestamp"]
        # Must end with "Z"
        assert ts.endswith("Z"), f"Timestamp does not end with 'Z': {ts!r}"
        # Must match ISO 8601 pattern: YYYY-MM-DDTHH:MM:SS.ffffffZ
        pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
        assert re.match(pattern, ts), f"Timestamp does not match ISO 8601 pattern: {ts!r}"

    def test_level_info(self):
        record = _make_record("info msg", level=logging.INFO)
        parsed = json.loads(self.formatter.format(record))
        assert parsed["level"] == "INFO"

    def test_level_error(self):
        record = _make_record("error msg", level=logging.ERROR)
        parsed = json.loads(self.formatter.format(record))
        assert parsed["level"] == "ERROR"

    def test_level_warning(self):
        record = _make_record("warn msg", level=logging.WARNING)
        parsed = json.loads(self.formatter.format(record))
        assert parsed["level"] == "WARNING"

    def test_level_debug(self):
        record = _make_record("debug msg", level=logging.DEBUG)
        parsed = json.loads(self.formatter.format(record))
        assert parsed["level"] == "DEBUG"

    def test_level_critical(self):
        record = _make_record("critical msg", level=logging.CRITICAL)
        parsed = json.loads(self.formatter.format(record))
        assert parsed["level"] == "CRITICAL"

    def test_message_content(self):
        record = _make_record("specific message content")
        parsed = json.loads(self.formatter.format(record))
        assert "specific message content" in parsed["message"]

    def test_message_with_format_args(self):
        record = logging.LogRecord(
            name="ids",
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg="value is %d",
            args=(42,),
            exc_info=None,
        )
        parsed = json.loads(self.formatter.format(record))
        assert "42" in parsed["message"]

    def test_output_is_single_line(self):
        record = _make_record("single line check")
        output = self.formatter.format(record)
        assert "\n" not in output

    def test_different_levels_produce_different_level_fields(self):
        levels = [
            (logging.DEBUG, "DEBUG"),
            (logging.INFO, "INFO"),
            (logging.WARNING, "WARNING"),
            (logging.ERROR, "ERROR"),
            (logging.CRITICAL, "CRITICAL"),
        ]
        for level_int, level_str in levels:
            record = _make_record("msg", level=level_int)
            parsed = json.loads(self.formatter.format(record))
            assert parsed["level"] == level_str


# ---------------------------------------------------------------------------
# setup_logging tests
# ---------------------------------------------------------------------------

class TestSetupLogging:
    def test_returns_logger_instance(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = setup_logging(log_file, "INFO")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "ids"

    def test_logger_has_file_and_stream_handlers(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = setup_logging(log_file, "INFO")
        handler_types = {type(h) for h in logger.handlers}
        assert logging.FileHandler in handler_types
        assert logging.StreamHandler in handler_types

    def test_log_file_is_created(self, tmp_path):
        log_file = str(tmp_path / "ids.log")
        setup_logging(log_file, "INFO")
        assert os.path.exists(log_file)

    def test_log_file_contains_valid_json(self, tmp_path):
        log_file = str(tmp_path / "ids.log")
        logger = setup_logging(log_file, "INFO")
        logger.info("file json test")
        # Flush handlers
        for h in logger.handlers:
            h.flush()
        with open(log_file, encoding="utf-8") as f:
            line = f.readline().strip()
        parsed = json.loads(line)
        assert parsed["level"] == "INFO"
        assert "file json test" in parsed["message"]

    def test_log_level_respected(self, tmp_path):
        log_file = str(tmp_path / "ids.log")
        logger = setup_logging(log_file, "WARNING")
        assert logger.level == logging.WARNING

    def test_debug_level_accepted(self, tmp_path):
        log_file = str(tmp_path / "ids.log")
        logger = setup_logging(log_file, "DEBUG")
        assert logger.level == logging.DEBUG

    def test_no_duplicate_handlers_on_repeated_calls(self, tmp_path):
        log_file = str(tmp_path / "ids.log")
        setup_logging(log_file, "INFO")
        logger = setup_logging(log_file, "INFO")
        # Should have exactly 2 handlers (file + stream), not 4
        assert len(logger.handlers) == 2

    def test_stream_handler_writes_json(self, tmp_path, capsys):
        log_file = str(tmp_path / "ids.log")
        logger = setup_logging(log_file, "INFO")
        logger.info("stdout json test")
        for h in logger.handlers:
            h.flush()
        captured = capsys.readouterr()
        line = captured.out.strip()
        parsed = json.loads(line)
        assert parsed["level"] == "INFO"
        assert "stdout json test" in parsed["message"]
        assert parsed["timestamp"].endswith("Z")
