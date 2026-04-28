"""Tests for SessionTracker."""

import pytest

from qise.core.models import GuardResult, GuardVerdict
from qise.core.session_tracker import SessionTracker


@pytest.fixture
def tracker() -> SessionTracker:
    return SessionTracker()


class TestSessionTracker:

    def test_empty_session_risk_score(self, tracker: SessionTracker) -> None:
        assert tracker.get_risk_score("nonexistent") == 0.0

    def test_risk_score_with_block(self, tracker: SessionTracker) -> None:
        tracker.record_guard_result("s1", GuardResult(guard_name="test", verdict=GuardVerdict.BLOCK, confidence=0.9))
        score = tracker.get_risk_score("s1")
        assert score > 0.5

    def test_risk_score_with_pass(self, tracker: SessionTracker) -> None:
        tracker.record_guard_result("s1", GuardResult(guard_name="test", verdict=GuardVerdict.PASS))
        assert tracker.get_risk_score("s1") == 0.0

    def test_is_under_attack(self, tracker: SessionTracker) -> None:
        assert tracker.is_under_attack("s1") is False
        tracker.record_guard_result("s1", GuardResult(guard_name="test", verdict=GuardVerdict.BLOCK, confidence=0.9))
        assert tracker.is_under_attack("s1", threshold=0.6) is True

    def test_is_under_attack_below_threshold(self, tracker: SessionTracker) -> None:
        tracker.record_guard_result("s1", GuardResult(guard_name="test", verdict=GuardVerdict.WARN, confidence=0.3))
        assert tracker.is_under_attack("s1", threshold=0.8) is False

    def test_get_recent_verdicts(self, tracker: SessionTracker) -> None:
        for i in range(10):
            tracker.record_guard_result("s1", GuardResult(guard_name=f"guard_{i}", verdict=GuardVerdict.PASS))
        recent = tracker.get_recent_verdicts("s1", count=3)
        assert len(recent) == 3
        assert recent[-1].guard_name == "guard_9"

    def test_clear_session(self, tracker: SessionTracker) -> None:
        tracker.record_guard_result("s1", GuardResult(guard_name="test", verdict=GuardVerdict.BLOCK))
        tracker.clear_session("s1")
        assert tracker.get_risk_score("s1") == 0.0

    def test_decaying_weights(self, tracker: SessionTracker) -> None:
        """Recent BLOCK should weigh more than old PASS."""
        tracker.record_guard_result("s1", GuardResult(guard_name="g", verdict=GuardVerdict.PASS))
        tracker.record_guard_result("s1", GuardResult(guard_name="g", verdict=GuardVerdict.PASS))
        tracker.record_guard_result("s1", GuardResult(guard_name="g", verdict=GuardVerdict.BLOCK, confidence=0.9))
        # Even with 2 passes before, the recent block should push score high
        assert tracker.get_risk_score("s1") > 0.3
