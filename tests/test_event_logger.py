"""Tests for EventLogger."""

import json
import logging
from io import StringIO

from qise.core.event_logger import EventLogger
from qise.core.models import GuardResult, GuardVerdict, PipelineResult


class TestEventLogger:

    def test_log_guard_result(self) -> None:
        # Capture log output
        logger = EventLogger(level="INFO", output="stderr")
        result = GuardResult(
            guard_name="test",
            verdict=GuardVerdict.BLOCK,
            confidence=0.9,
            message="test message",
        )
        # Should not raise
        logger.log_guard_result("session-1", result)

    def test_log_pipeline_result(self) -> None:
        logger = EventLogger(level="INFO", output="stderr")
        result = PipelineResult(
            verdict=GuardVerdict.BLOCK,
            blocked_by="test",
            warnings=["warning1"],
        )
        logger.log_pipeline_result("session-1", result)

    def test_log_custom_event(self) -> None:
        logger = EventLogger(level="INFO", output="stderr")
        logger.log_event("custom_event", {"key": "value"})

    def test_json_format(self) -> None:
        # Use a StringIO handler to capture output
        log_capture = StringIO()
        handler = logging.StreamHandler(log_capture)
        handler.setFormatter(logging.Formatter("%(message)s"))

        test_logger = logging.getLogger("qise_test_json")
        test_logger.handlers.clear()
        test_logger.addHandler(handler)
        test_logger.setLevel(logging.INFO)

        event = {
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "test",
            "key": "value",
        }
        test_logger.info(json.dumps(event))
        output = log_capture.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["event_type"] == "test"
        assert parsed["key"] == "value"
