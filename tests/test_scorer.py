"""
tests/test_scorer.py — Unit tests for RiskScorer.

Tests cover all boundary conditions for the Low / Medium / High thresholds.
"""

from scorer import RiskScorer


class TestRiskScorer:
    def setup_method(self) -> None:
        self.scorer = RiskScorer()

    def test_zero_indicators_is_low(self) -> None:
        assert self.scorer.score([]) == "Low"

    def test_one_indicator_is_medium(self) -> None:
        assert self.scorer.score(["Urgent or Threatening Language"]) == "Medium"

    def test_two_indicators_is_medium(self) -> None:
        assert self.scorer.score(["Urgent or Threatening Language", "Suspicious Link Detected"]) == "Medium"

    def test_three_indicators_is_high(self) -> None:
        assert self.scorer.score([
            "Urgent or Threatening Language",
            "Request for Sensitive Information",
            "Money or Payment Request",
        ]) == "High"

    def test_four_indicators_is_high(self) -> None:
        assert self.scorer.score([
            "Urgent or Threatening Language",
            "Request for Sensitive Information",
            "Money or Payment Request",
            "Suspicious Link Detected",
        ]) == "High"

    def test_five_indicators_is_high(self) -> None:
        indicators = [f"Indicator {i}" for i in range(5)]
        assert self.scorer.score(indicators) == "High"

    def test_score_returns_string(self) -> None:
        result = self.scorer.score([])
        assert isinstance(result, str)

    def test_known_level_strings(self) -> None:
        assert self.scorer.score([]) in ("Low", "Medium", "High")
        assert self.scorer.score(["x"]) in ("Low", "Medium", "High")
        assert self.scorer.score(["x", "y", "z"]) in ("Low", "Medium", "High")
