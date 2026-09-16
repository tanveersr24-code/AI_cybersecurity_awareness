"""
password_checker.py — Educational password-strength awareness checker.

PasswordChecker evaluates a password string against common strength rules
and returns a PasswordResult with a strength label and improvement tips.

IMPORTANT: Passwords are evaluated entirely in local memory.
           They are never stored, logged, transmitted, or displayed in plain text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# A short list of the most common passwords — flagged explicitly
# ---------------------------------------------------------------------------
COMMON_PASSWORDS: set[str] = {
    "password", "password1", "password123", "123456", "12345678",
    "123456789", "1234567890", "qwerty", "qwerty123", "abc123",
    "letmein", "welcome", "monkey", "dragon", "master", "sunshine",
    "princess", "iloveyou", "admin", "login", "pass", "test",
    "superman", "batman", "football", "baseball", "shadow", "michael",
    "jessica", "charlie", "donald", "hello123", "welcome1",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PasswordResult:
    """
    Result of a password-strength evaluation.

    Attributes:
        strength:  "Weak", "Moderate", or "Strong".
        score:     Internal numeric score (0–5) used to derive strength.
        feedback:  List of improvement tips (empty if already Strong).
    """

    strength: str
    score: int
    feedback: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

class PasswordChecker:
    """
    Evaluates password strength using simple, transparent rules.

    Rules checked:
        1. Minimum length (8 characters)
        2. Longer length bonus (12+ characters)
        3. Contains uppercase letters
        4. Contains lowercase letters
        5. Contains digits
        6. Contains special characters
        7. Not a well-known common password

    Usage:
        checker = PasswordChecker("MySecure@Pass99")
        result = checker.check_strength()
        print(result.strength)   # "Strong"

    IMPORTANT: The password is never stored after check_strength() returns.
    """

    WEAK_THRESHOLD: int = 2     # score <= 2 → Weak
    MODERATE_THRESHOLD: int = 4  # score <= 4 → Moderate; above → Strong

    def __init__(self, password: str) -> None:
        """
        Initialise with the password string to evaluate.

        Args:
            password: The password string. Evaluated in memory only.
        """
        # Store only a reference for the duration of this check.
        # Do not log or persist.
        self._password: str = password

    def check_strength(self) -> PasswordResult:
        """
        Evaluate the password and return a PasswordResult.

        Returns:
            PasswordResult containing strength label, score, and feedback tips.
        """
        feedback: list[str] = []
        score: int = 0

        # Empty password — return immediately
        if not self._password:
            return PasswordResult(
                strength="Weak",
                score=0,
                feedback=["Please enter a password to check."],
            )

        # --- Rule 1: Common passwords ---
        if self._password.lower() in COMMON_PASSWORDS:
            return PasswordResult(
                strength="Weak",
                score=0,
                feedback=[
                    "This is one of the most commonly used passwords in the world. "
                    "It would be cracked almost instantly. Please choose something unique.",
                    "Avoid using common words, names, or number sequences.",
                ],
            )

        # --- Rule 2: Minimum length (8 characters) — REQUIRED for non-Weak ---
        # If the password is under 8 characters it is always Weak, regardless of other rules.
        if len(self._password) < 8:
            feedback.append("Use at least 8 characters. Longer is better.")
            feedback.append("Aim for 12 or more characters for a stronger password.")
            if not re.search(r"[A-Z]", self._password):
                feedback.append("Add at least one uppercase letter (A–Z).")
            if not re.search(r"[a-z]", self._password):
                feedback.append("Add at least one lowercase letter (a–z).")
            if not re.search(r"\d", self._password):
                feedback.append("Add at least one number (0–9).")
            if not re.search(r"[^A-Za-z0-9]", self._password):
                feedback.append("Add at least one special character (e.g. !, @, #, $, %).")
            return PasswordResult(strength="Weak", score=1, feedback=feedback)

        # Length >= 8: now score variety rules
        score += 1  # base point for meeting minimum length

        # --- Rule 3: Bonus for length >= 12 ---
        if len(self._password) >= 12:
            score += 1
        else:
            feedback.append("Aim for 12 or more characters for a stronger password.")

        # --- Rule 4: Uppercase letters ---
        if re.search(r"[A-Z]", self._password):
            score += 1
        else:
            feedback.append("Add at least one uppercase letter (A–Z).")

        # --- Rule 5: Lowercase letters ---
        if re.search(r"[a-z]", self._password):
            score += 1
        else:
            feedback.append("Add at least one lowercase letter (a–z).")

        # --- Rule 6: Digits ---
        if re.search(r"\d", self._password):
            score += 1
        else:
            feedback.append("Add at least one number (0–9).")

        # --- Rule 7: Special characters ---
        if re.search(r"[^A-Za-z0-9]", self._password):
            score += 1
        else:
            feedback.append("Add at least one special character (e.g. !, @, #, $, %).")

        # Derive strength label from score
        if score <= self.WEAK_THRESHOLD:
            strength = "Weak"
        elif score <= self.MODERATE_THRESHOLD:
            strength = "Moderate"
        else:
            strength = "Strong"
            feedback = []  # No tips needed for a strong password

        return PasswordResult(strength=strength, score=score, feedback=feedback)
