"""
tests/test_password.py — Unit tests for PasswordChecker and PasswordResult.

Tests cover:
- Empty password
- Too-short password
- Common/well-known password
- Weak password (only lowercase, short)
- Moderate password (meets some rules)
- Strong password (meets all rules)
- Feedback items present for weak/moderate passwords
- No feedback for strong passwords
- Password with only numbers
- Passphrase-style strong password
"""

from password_checker import PasswordChecker, PasswordResult


class TestPasswordChecker:

    def _check(self, password: str) -> PasswordResult:
        return PasswordChecker(password).check_strength()

    # --- Empty input ---

    def test_empty_password_is_weak(self) -> None:
        result = self._check("")
        assert result.strength == "Weak"

    def test_empty_password_has_feedback(self) -> None:
        result = self._check("")
        assert len(result.feedback) > 0

    # --- Common passwords ---

    def test_password123_is_weak(self) -> None:
        result = self._check("password123")
        assert result.strength == "Weak"

    def test_common_password_flagged_explicitly(self) -> None:
        result = self._check("password123")
        # Should include a message about being a well-known password
        assert any("common" in tip.lower() or "known" in tip.lower() for tip in result.feedback)

    def test_qwerty_is_weak(self) -> None:
        result = self._check("qwerty")
        assert result.strength == "Weak"

    def test_123456_is_weak(self) -> None:
        result = self._check("123456")
        assert result.strength == "Weak"

    # --- Short passwords ---

    def test_very_short_password_is_weak(self) -> None:
        result = self._check("Ab1!")
        assert result.strength == "Weak"

    def test_seven_char_password_is_weak_or_moderate(self) -> None:
        # 7 chars with variety — should still be at most Moderate
        result = self._check("Ab1!xyz")
        assert result.strength in ("Weak", "Moderate")

    # --- Moderate passwords ---

    def test_moderate_password_with_some_variety(self) -> None:
        # 9 chars, upper+lower+digit but no special char
        result = self._check("Hello1234")
        assert result.strength in ("Moderate", "Weak")

    def test_moderate_has_feedback(self) -> None:
        result = self._check("Hello1234")
        # Should suggest improvements
        assert len(result.feedback) > 0

    # --- Strong passwords ---

    def test_strong_password_all_criteria(self) -> None:
        # 14 chars, upper, lower, digit, special
        result = self._check("MySecure@Pass99")
        assert result.strength == "Strong"

    def test_strong_password_no_feedback(self) -> None:
        result = self._check("MySecure@Pass99")
        assert result.feedback == []

    def test_long_passphrase_is_strong(self) -> None:
        result = self._check("PurpleTreeBridge47!")
        assert result.strength == "Strong"

    def test_very_long_strong_password(self) -> None:
        result = self._check("C0mpl3x!P@ssw0rd#SecureL0ng")
        assert result.strength == "Strong"

    # --- Only numbers ---

    def test_only_numbers_is_weak_or_moderate(self) -> None:
        result = self._check("123456789012")
        assert result.strength in ("Weak", "Moderate")

    def test_only_lowercase_is_weak_or_moderate(self) -> None:
        result = self._check("simplelowercase")
        assert result.strength in ("Weak", "Moderate")

    # --- Result structure ---

    def test_result_is_password_result_instance(self) -> None:
        result = self._check("Test@12345678")
        assert isinstance(result, PasswordResult)

    def test_result_has_strength_field(self) -> None:
        result = self._check("Test@12345678")
        assert result.strength in ("Weak", "Moderate", "Strong")

    def test_result_has_score_field(self) -> None:
        result = self._check("Test@12345678")
        assert isinstance(result.score, int)

    def test_result_has_feedback_field(self) -> None:
        result = self._check("Test@12345678")
        assert isinstance(result.feedback, list)
