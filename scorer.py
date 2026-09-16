"""
scorer.py — Simple, transparent risk-level calculation.

RiskScorer converts a list of detected indicator names into a risk level string.
Thresholds are named constants so they are easy to understand and change.
"""


class RiskScorer:
    """
    Converts a count of detected phishing/scam indicators to a risk level.

    Thresholds (beginner-friendly, count-based):
        0 indicators  → Low Risk
        1–2 indicators → Medium Risk
        3+ indicators  → High Risk
    """

    # Adjust these constants to change the risk thresholds without touching logic.
    HIGH_THRESHOLD: int = 3   # 3 or more indicators → High Risk
    MEDIUM_THRESHOLD: int = 1  # 1 or more indicators → Medium Risk (up to HIGH_THRESHOLD)

    LEVEL_LOW: str = "Low"
    LEVEL_MEDIUM: str = "Medium"
    LEVEL_HIGH: str = "High"

    def score(self, indicators: list[str]) -> str:
        """
        Return a risk level string based on how many indicators were detected.

        Args:
            indicators: List of indicator category names that were found.

        Returns:
            One of "Low", "Medium", or "High".
        """
        count = len(indicators)
        if count >= self.HIGH_THRESHOLD:
            return self.LEVEL_HIGH
        if count >= self.MEDIUM_THRESHOLD:
            return self.LEVEL_MEDIUM
        return self.LEVEL_LOW
