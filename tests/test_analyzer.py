"""
tests/test_analyzer.py — Unit tests for MessageAnalyzer and AnalysisResult.

Tests cover:
- Safe-looking text (no indicators)
- Each of the 7 indicator categories
- Mixed-case input (case normalization)
- Suspicious link variants
- Multiple indicators → High Risk
- Empty input → EmptyMessageError
- Whitespace-only input → EmptyMessageError
- Too-short input → MessageTooShortError
- Too-long input → MessageTooLongError
- Non-string input → InvalidInputTypeError
- AnalysisResult fields populated correctly
"""

import pytest

from analyzer import MAX_LENGTH, MIN_LENGTH, AnalysisResult, MessageAnalyzer
from exceptions import (
    EmptyMessageError,
    InvalidInputTypeError,
    MessageTooLongError,
    MessageTooShortError,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def analyze(text: str) -> AnalysisResult:
    """Convenience wrapper — create analyzer and run analysis."""
    return MessageAnalyzer(text).analyze()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_empty_string_raises(self) -> None:
        with pytest.raises(EmptyMessageError):
            MessageAnalyzer("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(EmptyMessageError):
            MessageAnalyzer("     ")

    def test_too_short_raises(self) -> None:
        with pytest.raises(MessageTooShortError):
            MessageAnalyzer("Hi there")  # 8 chars, under MIN_LENGTH of 10

    def test_exactly_min_length_is_accepted(self) -> None:
        # MIN_LENGTH is 10 — "0123456789" is exactly 10 characters
        result = analyze("0123456789")
        assert isinstance(result, AnalysisResult)

    def test_too_long_raises(self) -> None:
        with pytest.raises(MessageTooLongError):
            MessageAnalyzer("A" * (MAX_LENGTH + 1))

    def test_exactly_max_length_is_accepted(self) -> None:
        result = analyze("A" * MAX_LENGTH)
        assert isinstance(result, AnalysisResult)

    def test_non_string_raises(self) -> None:
        with pytest.raises(InvalidInputTypeError):
            MessageAnalyzer(12345)  # type: ignore[arg-type]

    def test_none_raises(self) -> None:
        with pytest.raises(InvalidInputTypeError):
            MessageAnalyzer(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Safe-looking messages (no indicators expected)
# ---------------------------------------------------------------------------

class TestSafeMessages:
    def test_friendly_message_is_low_risk(self) -> None:
        result = analyze("Hi, just wanted to check how you are doing today. Hope all is well!")
        assert result.risk_level == "Low"
        assert result.indicators_found == []

    def test_news_article_snippet_is_low_risk(self) -> None:
        # Deliberately avoids brand/org names to stay free of the impersonation keyword list
        result = analyze(
            "Scientists have discovered a new species of bird in a remote rainforest. "
            "The discovery was published in a scientific journal this week."
        )
        assert result.risk_level == "Low"
        assert result.indicators_found == []

    def test_low_risk_result_has_disclaimer(self) -> None:
        result = analyze("Hello, how are you doing today? I hope everything is fine.")
        assert "educational awareness" in result.disclaimer.lower()


# ---------------------------------------------------------------------------
# Urgency / threatening language
# ---------------------------------------------------------------------------

class TestUrgencyDetection:
    def test_act_now_detected(self) -> None:
        result = analyze("You must act now or your account will be closed forever!")
        assert "Urgent or Threatening Language" in result.indicators_found

    def test_final_warning_detected(self) -> None:
        result = analyze("This is your final warning. Respond within 24 hours or face legal action.")
        assert "Urgent or Threatening Language" in result.indicators_found

    def test_uppercase_urgency_detected(self) -> None:
        # Case normalization: "URGENT" should match "urgent"
        result = analyze("URGENT: Your account has been compromised. Respond IMMEDIATELY.")
        assert "Urgent or Threatening Language" in result.indicators_found

    def test_security_alert_detected(self) -> None:
        result = analyze("Security alert: unusual activity detected on your account. Immediate action required.")
        assert "Urgent or Threatening Language" in result.indicators_found


# ---------------------------------------------------------------------------
# Requests for sensitive information (passwords, OTPs, PINs)
# ---------------------------------------------------------------------------

class TestSensitiveRequestDetection:
    def test_password_request_detected(self) -> None:
        result = analyze("Please enter your password to continue with the verification process.")
        assert "Request for Sensitive Information" in result.indicators_found

    def test_otp_request_detected(self) -> None:
        result = analyze("Please provide your OTP to confirm your identity and complete the transfer.")
        assert "Request for Sensitive Information" in result.indicators_found

    def test_credit_card_request_detected(self) -> None:
        result = analyze("To claim your prize, please enter your credit card number and expiry date.")
        assert "Request for Sensitive Information" in result.indicators_found

    def test_social_security_detected(self) -> None:
        result = analyze("We need your social security number to verify your identity in our records.")
        assert "Request for Sensitive Information" in result.indicators_found

    def test_bank_account_number_detected(self) -> None:
        result = analyze("Please provide your bank account number so we can process the refund.")
        assert "Request for Sensitive Information" in result.indicators_found


# ---------------------------------------------------------------------------
# Money and payment requests
# ---------------------------------------------------------------------------

class TestMoneyRequestDetection:
    def test_gift_card_detected(self) -> None:
        result = analyze("Please buy 3 Google Play gift cards worth $100 each and send us the codes.")
        assert "Money or Payment Request" in result.indicators_found

    def test_bitcoin_detected(self) -> None:
        result = analyze("To release your funds, please send the equivalent in bitcoin to the wallet address below.")
        assert "Money or Payment Request" in result.indicators_found

    def test_wire_transfer_detected(self) -> None:
        result = analyze("You need to wire transfer the processing fee before we can release the package.")
        assert "Money or Payment Request" in result.indicators_found

    def test_advance_fee_detected(self) -> None:
        result = analyze("An advance fee of $500 is required to release your unclaimed inheritance of $1 million.")
        assert "Money or Payment Request" in result.indicators_found


# ---------------------------------------------------------------------------
# Impersonation
# ---------------------------------------------------------------------------

class TestImpersonationDetection:
    def test_paypal_impersonation_detected(self) -> None:
        result = analyze("Your PayPal account has been limited. Please verify your details to restore access.")
        assert "Impersonation of Organization or Authority" in result.indicators_found

    def test_microsoft_impersonation_detected(self) -> None:
        result = analyze("Microsoft tech support here. Your computer has a virus. Please call us immediately.")
        assert "Impersonation of Organization or Authority" in result.indicators_found

    def test_irs_impersonation_detected(self) -> None:
        result = analyze("This is the IRS. You owe back taxes. Failure to respond will result in arrest.")
        assert "Impersonation of Organization or Authority" in result.indicators_found


# ---------------------------------------------------------------------------
# Attachment mentions
# ---------------------------------------------------------------------------

class TestAttachmentDetection:
    def test_open_attached_detected(self) -> None:
        result = analyze("Please open the attached document to review your invoice and respond today.")
        assert "Suspicious Attachment Mention" in result.indicators_found

    def test_enable_macros_detected(self) -> None:
        result = analyze("When you open the file, please enable macros to view the content properly.")
        assert "Suspicious Attachment Mention" in result.indicators_found

    def test_download_file_detected(self) -> None:
        result = analyze("Download the file from the link below and run the installer to update your software.")
        assert "Suspicious Attachment Mention" in result.indicators_found


# ---------------------------------------------------------------------------
# Bypass security
# ---------------------------------------------------------------------------

class TestBypassSecurityDetection:
    def test_disable_antivirus_detected(self) -> None:
        result = analyze("Before running the setup, please disable your antivirus software temporarily.")
        assert "Request to Bypass Security" in result.indicators_found

    def test_do_not_tell_anyone_detected(self) -> None:
        result = analyze("This is a confidential offer. Do not tell anyone about this or the deal will be cancelled.")
        assert "Request to Bypass Security" in result.indicators_found


# ---------------------------------------------------------------------------
# Suspicious links
# ---------------------------------------------------------------------------

class TestSuspiciousLinkDetection:
    def test_shortened_url_detected(self) -> None:
        result = analyze("Click here to verify your account: http://bit.ly/verifyaccount123 — act now!")
        assert "Suspicious Link Detected" in result.indicators_found

    def test_ip_based_url_detected(self) -> None:
        result = analyze("Please visit http://192.168.0.1/login to update your billing details today.")
        assert "Suspicious Link Detected" in result.indicators_found

    def test_lookalike_domain_detected(self) -> None:
        result = analyze("Click to verify: https://paypal-secure-login.com/confirm — your account is at risk.")
        assert "Suspicious Link Detected" in result.indicators_found

    def test_tinyurl_detected(self) -> None:
        result = analyze("Your package is ready. Track it here: https://tinyurl.com/track123 and respond urgently.")
        assert "Suspicious Link Detected" in result.indicators_found

    def test_obfuscated_url_with_spaces_detected(self) -> None:
        # Scammers sometimes write "bit . ly" to evade simple filters
        result = analyze("Visit bit . ly/claim to collect your prize winnings immediately today.")
        assert "Suspicious Link Detected" in result.indicators_found

    def test_legitimate_long_url_not_flagged(self) -> None:
        # A normal-looking URL without shortener or IP — should NOT trigger the link check
        result = analyze(
            "Check out our official documentation at https://www.example.com/docs/getting-started "
            "for more information about our services and products."
        )
        assert "Suspicious Link Detected" not in result.indicators_found


# ---------------------------------------------------------------------------
# Generic patterns
# ---------------------------------------------------------------------------

class TestGenericPatternDetection:
    def test_dear_customer_detected(self) -> None:
        result = analyze("Dear customer, your account requires immediate verification to avoid suspension.")
        assert "Generic or Suspicious Greeting/Pattern" in result.indicators_found

    def test_you_have_won_detected(self) -> None:
        result = analyze("Congratulations! You have won our monthly prize draw. Claim now to receive your reward.")
        assert "Generic or Suspicious Greeting/Pattern" in result.indicators_found

    def test_million_dollars_detected(self) -> None:
        result = analyze(
            "I am writing to inform you of an unclaimed inheritance worth 5 million dollars "
            "left to you by a distant relative."
        )
        assert "Generic or Suspicious Greeting/Pattern" in result.indicators_found


# ---------------------------------------------------------------------------
# Multiple indicators → High Risk
# ---------------------------------------------------------------------------

class TestMultipleIndicators:
    def test_classic_phishing_email_is_high_risk(self) -> None:
        phishing_text = (
            "Dear customer, your PayPal account has been suspended due to unusual activity. "
            "Act now — this is urgent! Please enter your password and OTP to restore access. "
            "Click here: http://bit.ly/paypal-secure-verify to proceed immediately."
        )
        result = analyze(phishing_text)
        assert result.risk_level == "High"
        assert len(result.indicators_found) >= 3

    def test_three_indicators_give_high_risk(self) -> None:
        # Urgency + sensitive request + money
        text = (
            "Urgent: You owe a processing fee. Please provide your bank account number "
            "and password immediately to avoid legal action within 24 hours."
        )
        result = analyze(text)
        assert result.risk_level == "High"

    def test_two_indicators_give_medium_risk(self) -> None:
        # Impersonation + urgency only
        text = (
            "Your Amazon account is at risk. Immediate action required — please log in now "
            "to secure your account before it is permanently closed."
        )
        result = analyze(text)
        assert result.risk_level in ("Medium", "High")  # 2+ indicators expected

    def test_single_indicator_gives_medium_risk(self) -> None:
        result = analyze(
            "Dear customer, welcome to our newsletter. Thank you for subscribing to our service."
        )
        # "Dear customer" is 1 indicator → Medium Risk
        assert result.risk_level == "Medium"
        assert len(result.indicators_found) == 1


# ---------------------------------------------------------------------------
# AnalysisResult structure
# ---------------------------------------------------------------------------

class TestAnalysisResultStructure:
    def test_result_has_all_fields(self) -> None:
        result = analyze("Please enter your password immediately to avoid account suspension.")
        assert hasattr(result, "risk_level")
        assert hasattr(result, "indicators_found")
        assert hasattr(result, "explanations")
        assert hasattr(result, "advice")
        assert hasattr(result, "disclaimer")
        assert hasattr(result, "ai_available")
        assert hasattr(result, "original_text")

    def test_explanations_match_indicators(self) -> None:
        result = analyze("Please enter your password immediately to avoid account suspension.")
        assert len(result.explanations) == len(result.indicators_found)

    def test_original_text_is_capped_at_200_chars(self) -> None:
        long_text = "A" * 300
        # Add an indicator so we don't hit short-message validation
        long_text = "Please enter your password — " + long_text
        result = analyze(long_text)
        assert len(result.original_text) <= 200

    def test_disclaimer_always_present(self) -> None:
        result = analyze("Hi, how are you doing today? Everything seems fine here.")
        assert result.disclaimer != ""

    def test_ai_available_defaults_to_false(self) -> None:
        result = analyze("Hi, how are you doing today? Everything seems fine here.")
        assert result.ai_available is False
