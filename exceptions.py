"""
exceptions.py — Custom exception classes for the Cybersecurity Awareness app.

All exceptions are caught in app.py and displayed as friendly UI messages.
"""


class EmptyMessageError(ValueError):
    """Raised when the submitted message is blank or whitespace-only."""

    def __init__(self) -> None:
        super().__init__("Please enter a message to analyze.")


class MessageTooShortError(ValueError):
    """Raised when the submitted message is too short to be meaningful."""

    def __init__(self, min_length: int) -> None:
        super().__init__(
            f"Your message is too short. Please enter at least {min_length} characters."
        )


class MessageTooLongError(ValueError):
    """Raised when the submitted message exceeds the allowed maximum length."""

    def __init__(self, max_length: int) -> None:
        super().__init__(
            f"Your message is too long. Please keep it under {max_length} characters."
        )


class InvalidInputTypeError(TypeError):
    """Raised when the input is not a plain string."""

    def __init__(self) -> None:
        super().__init__("Input must be a plain text string.")


class WatsonxUnavailableError(RuntimeError):
    """Raised when watsonx credentials are missing or the API call fails."""

    def __init__(self, reason: str = "") -> None:
        msg = "IBM watsonx.ai is unavailable."
        if reason:
            msg += f" Reason: {reason}"
        super().__init__(msg)
