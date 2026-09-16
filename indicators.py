"""
indicators.py — Phishing and scam indicator pattern definitions.

Each entry maps a human-readable indicator name to a list of lowercase
keyword strings (or regex pattern strings) to match against the message.
Import INDICATOR_PATTERNS in MessageAnalyzer to keep patterns out of logic code.
"""

# ---------------------------------------------------------------------------
# Plain-keyword lists (matched with simple `in` check after lowercasing)
# ---------------------------------------------------------------------------

# 1. Urgent or threatening language
URGENCY_KEYWORDS: list[str] = [
    "act now",
    "act immediately",
    "urgent",
    "urgently",
    "immediately",
    "final warning",
    "last chance",
    "limited time",
    "expires soon",
    "account will be suspended",
    "account suspended",
    "account has been compromised",
    "will be closed",
    "will be terminated",
    "respond within 24 hours",
    "respond within 48 hours",
    "within 24 hours",
    "within 48 hours",
    "action required",
    "your account is at risk",
    "security alert",
    "immediate action",
    "failure to respond",
    "legal action",
    "you have been selected",
    "congratulations you",
    "you are a winner",
]

# 2. Requests for sensitive credentials or personal information
SENSITIVE_REQUEST_KEYWORDS: list[str] = [
    "enter your password",
    "confirm your password",
    "provide your password",
    "reset your password",
    "your otp",
    "enter otp",
    "provide otp",
    "verify otp",
    "one-time password",
    "one time password",
    "enter your pin",
    "provide your pin",
    "confirm your pin",
    "your cvv",
    "card number",
    "credit card",
    "debit card",
    "bank account number",
    "account number",
    "routing number",
    "social security",
    "ssn",
    "national id",
    "passport number",
    "driver's license",
    "drivers license",
    "date of birth",
    "mother's maiden name",
    "security question",
    "secret answer",
    "login credentials",
    "username and password",
]

# 3. Money or unusual payment requests
MONEY_REQUEST_KEYWORDS: list[str] = [
    "send money",
    "transfer money",
    "wire transfer",
    "bank transfer",
    "gift card",
    "itunes card",
    "google play card",
    "amazon gift card",
    "steam card",
    "buy gift cards",
    "western union",
    "moneygram",
    "bitcoin",
    "cryptocurrency",
    "crypto payment",
    "processing fee",
    "handling fee",
    "pay a small fee",
    "release your funds",
    "claim your prize",
    "pay to receive",
    "advance fee",
    "upfront payment",
    "refund has been issued",
    "overpayment",
]

# 4. Impersonation of organizations or authorities
IMPERSONATION_KEYWORDS: list[str] = [
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "google",
    "facebook",
    "instagram",
    "netflix",
    "irs",
    "internal revenue service",
    "social security administration",
    "ssa",
    "fbi",
    "interpol",
    "your bank",
    "your financial institution",
    "tech support",
    "customer support",
    "helpdesk",
    "it department",
    "hr department",
    "human resources",
    "ceo",
    "director",
]

# 5. Attachment or file-opening instructions
ATTACHMENT_KEYWORDS: list[str] = [
    "open the attached",
    "open attachment",
    "see attached",
    "download the document",
    "download the file",
    "click to view file",
    "view the attachment",
    "attached invoice",
    "attached document",
    "attached file",
    "unzip the file",
    "run the installer",
    "execute the file",
    "enable macros",
    "enable content",
]

# 6. Requests to bypass security procedures
BYPASS_SECURITY_KEYWORDS: list[str] = [
    "disable your antivirus",
    "turn off your firewall",
    "ignore the security warning",
    "bypass the verification",
    "do not tell anyone",
    "keep this confidential",
    "do not share this",
    "delete this message after",
    "this is not a scam",
    "trust me",
    "100% safe",
    "guaranteed safe",
    "no risk",
    "do not contact",
    "do not reply",
]

# 7. Generic or suspicious communication patterns
GENERIC_PATTERN_KEYWORDS: list[str] = [
    "dear customer",
    "dear user",
    "dear account holder",
    "dear valued customer",
    "dear member",
    "hello friend",
    "greetings of the day",
    "i am the prince",
    "i am a government official",
    "you have won",
    "you have been selected",
    "lucky winner",
    "unclaimed funds",
    "unclaimed inheritance",
    "million dollars",
    "million usd",
    "billion dollars",
]

# ---------------------------------------------------------------------------
# Regex patterns for suspicious links (compiled in analyzer.py)
# ---------------------------------------------------------------------------

# Known URL-shortening service domains
URL_SHORTENER_DOMAINS: list[str] = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "short.link",
    "rb.gy",
    "cutt.ly",
    "shorte.st",
    "clck.ru",
    "x.co",
]

# Regex pattern: URL containing a raw IP address instead of a domain name
# e.g.  http://192.168.1.1/login  or  https://203.0.113.5/verify
IP_URL_PATTERN: str = r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# Regex pattern: extract any URL-like token from text (http/https)
URL_EXTRACT_PATTERN: str = r"https?://[^\s\"'<>]+"

# Regex pattern: suspicious lookalike domain fragments (e.g. paypal-secure-login, amazon-update)
LOOKALIKE_DOMAIN_FRAGMENTS: list[str] = [
    "secure-login",
    "account-verify",
    "account-update",
    "login-secure",
    "verify-account",
    "update-billing",
    "confirm-identity",
    "password-reset",
    "-login.",
    "-secure.",
    "-verify.",
    "-update.",
    "-account.",
]

# ---------------------------------------------------------------------------
# Convenience mapping: category name → keyword list (used by MessageAnalyzer)
# ---------------------------------------------------------------------------

INDICATOR_CATEGORIES: dict[str, list[str]] = {
    "Urgent or Threatening Language": URGENCY_KEYWORDS,
    "Request for Sensitive Information": SENSITIVE_REQUEST_KEYWORDS,
    "Money or Payment Request": MONEY_REQUEST_KEYWORDS,
    "Impersonation of Organization or Authority": IMPERSONATION_KEYWORDS,
    "Suspicious Attachment Mention": ATTACHMENT_KEYWORDS,
    "Request to Bypass Security": BYPASS_SECURITY_KEYWORDS,
    "Generic or Suspicious Greeting/Pattern": GENERIC_PATTERN_KEYWORDS,
}
