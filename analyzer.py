"""
analyzer.py — Core rule-based message analysis engine.

MessageAnalyzer scans a user-submitted text for phishing and scam indicators,
calculates a risk level, and returns a structured AnalysisResult.
No network calls are made here — this module is fully offline and testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from exceptions import (
    EmptyMessageError,
    InvalidInputTypeError,
    MessageTooLongError,
    MessageTooShortError,
)
from indicators import (
    INDICATOR_CATEGORIES,
    IP_URL_PATTERN,
    LOOKALIKE_DOMAIN_FRAGMENTS,
    URL_EXTRACT_PATTERN,
    URL_SHORTENER_DOMAINS,
)
from scorer import RiskScorer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_LENGTH: int = 10
MAX_LENGTH: int = 5_000

DISCLAIMER: str = (
    "⚠️ This analysis is for educational awareness only. "
    "It cannot guarantee that a message, link, or sender is legitimate or malicious. "
    "Always apply your own judgment and consult official sources when in doubt."
)

# Explanation templates for each indicator category (beginner-friendly language)
INDICATOR_EXPLANATIONS: dict[str, str] = {
    "Urgent or Threatening Language": (
        "The message tries to pressure you into acting quickly or threatens negative "
        "consequences. Scammers use urgency so you don't have time to think carefully."
    ),
    "Request for Sensitive Information": (
        "The message asks for passwords, PINs, OTPs, card numbers, or other private details. "
        "Legitimate companies never ask for these through email, SMS, or chat."
    ),
    "Money or Payment Request": (
        "The message asks you to send money, buy gift cards, or make a payment. "
        "Requests for gift cards or wire transfers are a classic scam tactic."
    ),
    "Impersonation of Organization or Authority": (
        "The message mentions a well-known brand, bank, or government agency. "
        "Scammers often pretend to be trusted organizations to gain your confidence."
    ),
    "Suspicious Attachment Mention": (
        "The message asks you to open a file or enable document macros. "
        "Malicious files are a common way to infect your device with harmful software."
    ),
    "Request to Bypass Security": (
        "The message asks you to disable security software, keep things secret, or ignore warnings. "
        "Legitimate services never ask you to lower your guard."
    ),
    "Suspicious Link Detected": (
        "The message contains a shortened URL, an IP-address link, or a domain designed to look "
        "like a trusted website. These links may lead to fake login pages that steal your details."
    ),
    "Generic or Suspicious Greeting/Pattern": (
        "The message uses an unusually generic greeting or contains language patterns "
        "commonly found in mass-sent scam messages."
    ),
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    """
    Structured result of a message analysis.

    Attributes:
        risk_level:        "Low", "Medium", or "High".
        indicators_found:  Human-readable names of each detected indicator.
        explanations:      Plain-English explanation for each indicator found.
        ai_explanation:    AI-generated explanation (empty string if unavailable).
        advice:            Recommended next-step actions for the user.
        disclaimer:        Fixed educational disclaimer text.
        ai_available:      True if the AI explanation was successfully generated.
        original_text:     The original message that was analyzed (first 200 chars for history display).
    """

    risk_level: str
    indicators_found: list[str] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)
    ai_explanation: str = ""
    advice: list[str] = field(default_factory=list)
    disclaimer: str = DISCLAIMER
    ai_available: bool = False
    original_text: str = ""


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class MessageAnalyzer:
    """
    Scans a plain-text message for common phishing and scam indicators.

    Usage:
        analyzer = MessageAnalyzer("Click here to verify your PayPal account urgently!")
        result = analyzer.analyze()
        print(result.risk_level)   # "High"
    """

    def __init__(self, text: str) -> None:
        """
        Initialise the analyzer with the raw message text.

        Args:
            text: The plain-text message submitted by the user.

        Raises:
            InvalidInputTypeError: If text is not a string.
            EmptyMessageError:     If text is blank or whitespace-only.
            MessageTooShortError:  If text is shorter than MIN_LENGTH.
            MessageTooLongError:   If text is longer than MAX_LENGTH.
        """
        if not isinstance(text, str):
            raise InvalidInputTypeError()
        if not text.strip():
            raise EmptyMessageError()
        if len(text.strip()) < MIN_LENGTH:
            raise MessageTooShortError(MIN_LENGTH)
        if len(text) > MAX_LENGTH:
            raise MessageTooLongError(MAX_LENGTH)

        self._raw_text: str = text
        self._normalized: str = text.lower()
        self._scorer = RiskScorer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> AnalysisResult:
        """
        Run all checks and return a populated AnalysisResult.

        Returns:
            AnalysisResult with risk level, indicators, explanations, and disclaimer.
        """
        indicators: list[str] = []

        # Run all rule-based checks; each returns the indicator name or None.
        checks = [
            self._check_urgency(),
            self._check_sensitive_requests(),
            self._check_money_requests(),
            self._check_impersonation(),
            self._check_attachments(),
            self._check_bypass_security(),
            self._check_suspicious_links(),
            self._check_generic_patterns(),
        ]

        for result in checks:
            if result is not None:
                indicators.append(result)

        risk_level = self._scorer.score(indicators)
        explanations = [
            INDICATOR_EXPLANATIONS.get(ind, f"Suspicious pattern detected: {ind}")
            for ind in indicators
        ]

        return AnalysisResult(
            risk_level=risk_level,
            indicators_found=indicators,
            explanations=explanations,
            disclaimer=DISCLAIMER,
            original_text=self._raw_text[:200],
        )

    # ------------------------------------------------------------------
    # Private check methods — each returns the indicator name or None
    # ------------------------------------------------------------------

    def _check_urgency(self) -> str | None:
        """Detect urgent or threatening language."""
        keywords = INDICATOR_CATEGORIES["Urgent or Threatening Language"]
        if any(kw in self._normalized for kw in keywords):
            return "Urgent or Threatening Language"
        return None

    def _check_sensitive_requests(self) -> str | None:
        """Detect requests for passwords, OTPs, PINs, or other sensitive data."""
        keywords = INDICATOR_CATEGORIES["Request for Sensitive Information"]
        if any(kw in self._normalized for kw in keywords):
            return "Request for Sensitive Information"
        return None

    def _check_money_requests(self) -> str | None:
        """Detect requests for money, gift cards, or unusual payments."""
        keywords = INDICATOR_CATEGORIES["Money or Payment Request"]
        if any(kw in self._normalized for kw in keywords):
            return "Money or Payment Request"
        return None

    def _check_impersonation(self) -> str | None:
        """Detect impersonation of known organizations or authorities."""
        keywords = INDICATOR_CATEGORIES["Impersonation of Organization or Authority"]
        if any(kw in self._normalized for kw in keywords):
            return "Impersonation of Organization or Authority"
        return None

    def _check_attachments(self) -> str | None:
        """Detect references to file attachments or instructions to open files."""
        keywords = INDICATOR_CATEGORIES["Suspicious Attachment Mention"]
        if any(kw in self._normalized for kw in keywords):
            return "Suspicious Attachment Mention"
        return None

    def _check_bypass_security(self) -> str | None:
        """Detect requests to disable security measures or keep things secret."""
        keywords = INDICATOR_CATEGORIES["Request to Bypass Security"]
        if any(kw in self._normalized for kw in keywords):
            return "Request to Bypass Security"
        return None

    def _check_suspicious_links(self) -> str | None:
        """
        Detect suspicious URLs: IP-based, shortened, or lookalike domains.
        Strips spaces around dots to catch obfuscated URLs like 'bit . ly'.
        """
        # Collapse spaces around dots to catch obfuscated URLs (e.g. "bit . ly")
        cleaned = re.sub(r"\s*\.\s*", ".", self._normalized)

        # Check for IP-address-based URLs
        if re.search(IP_URL_PATTERN, cleaned):
            return "Suspicious Link Detected"

        # Extract all URLs and check each one
        urls = re.findall(URL_EXTRACT_PATTERN, cleaned)
        for url in urls:
            # Check for known URL shortener domains
            if any(shortener in url for shortener in URL_SHORTENER_DOMAINS):
                return "Suspicious Link Detected"
            # Check for lookalike domain fragments
            if any(fragment in url for fragment in LOOKALIKE_DOMAIN_FRAGMENTS):
                return "Suspicious Link Detected"

        # Also check for URL shortener domains mentioned without http (e.g. "bit.ly/abc")
        if any(shortener in cleaned for shortener in URL_SHORTENER_DOMAINS):
            return "Suspicious Link Detected"

        return None

    def _check_generic_patterns(self) -> str | None:
        """Detect generic greetings and mass-scam language patterns."""
        keywords = INDICATOR_CATEGORIES["Generic or Suspicious Greeting/Pattern"]
        if any(kw in self._normalized for kw in keywords):
            return "Generic or Suspicious Greeting/Pattern"
        return None
