"""
advice.py — Risk-level to recommended action lookup.

AdviceProvider maps a risk level (Low / Medium / High) to a list of plain-English
safety recommendations. All text is intentionally beginner-friendly.
"""


class AdviceProvider:
    """
    Returns a list of recommended safety actions for a given risk level.

    Usage:
        advice = AdviceProvider.get_advice("High")
    """

    _ADVICE: dict[str, list[str]] = {
        "Low": [
            "No obvious warning signs were detected in this message.",
            "Still, stay cautious — not all scams are easy to spot.",
            "If something feels off, trust your instincts and double-check with the sender through official channels.",
            "Never click links in unexpected messages, even if they look legitimate.",
        ],
        "Medium": [
            "This message contains one or two warning signs. Treat it with caution.",
            "Do NOT click any links in the message. If you need to visit a website, type the official address directly in your browser.",
            "Do NOT provide any personal information, passwords, or payment details.",
            "If the message claims to be from a company or bank, contact them directly using the phone number or website from their official website — not the one in the message.",
            "Consider reporting the message as spam or phishing to your email or messaging provider.",
        ],
        "High": [
            "This message shows multiple strong warning signs. It is very likely a phishing or scam attempt.",
            "Do NOT click any links, open any attachments, or respond to this message.",
            "Do NOT provide any personal information, passwords, OTPs, or payment details under any circumstances.",
            "Delete or report the message immediately as phishing or spam.",
            "If you have already clicked a link or provided information, change your passwords immediately and contact your bank if financial details were involved.",
            "Report the message to your country's cybercrime reporting authority (e.g. the FBI's IC3 in the US, Action Fraud in the UK, or your local police).",
        ],
    }

    @staticmethod
    def get_advice(risk_level: str) -> list[str]:
        """
        Return a list of recommended actions for the given risk level.

        Args:
            risk_level: "Low", "Medium", or "High".

        Returns:
            A list of advice strings. Returns Low-risk advice for unknown levels.
        """
        return AdviceProvider._ADVICE.get(risk_level, AdviceProvider._ADVICE["Low"])
