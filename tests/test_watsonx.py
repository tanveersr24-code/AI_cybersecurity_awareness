"""
tests/test_watsonx.py — Unit tests for WatsonxClient.

All IBM watsonx.ai SDK calls are mocked — no real API credentials needed.
Tests cover:
- is_available() returns False when env vars are missing
- generate_explanation() raises WatsonxUnavailableError when unavailable
- Successful mocked API call returns a string
- Failed SDK call raises WatsonxUnavailableError
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from exceptions import WatsonxUnavailableError
from watsonx_client import WatsonxClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client_with_no_env() -> WatsonxClient:
    """Return a WatsonxClient with no credentials in the environment."""
    with patch.dict(os.environ, {"WATSONX_API_KEY": "", "WATSONX_PROJECT_ID": ""}, clear=False):
        return WatsonxClient()


# ---------------------------------------------------------------------------
# Tests: is_available()
# ---------------------------------------------------------------------------

class TestWatsonxClientAvailability:

    def test_not_available_without_credentials(self) -> None:
        client = _make_client_with_no_env()
        assert client.is_available() is False

    def test_not_available_with_only_api_key(self) -> None:
        with patch.dict(
            os.environ,
            {"WATSONX_API_KEY": "fake_key", "WATSONX_PROJECT_ID": ""},
            clear=False,
        ):
            client = WatsonxClient()
        assert client.is_available() is False

    def test_not_available_with_only_project_id(self) -> None:
        with patch.dict(
            os.environ,
            {"WATSONX_API_KEY": "", "WATSONX_PROJECT_ID": "fake_project"},
            clear=False,
        ):
            client = WatsonxClient()
        assert client.is_available() is False

    def test_available_when_credentials_present_and_sdk_init_succeeds(self) -> None:
        mock_model = MagicMock()

        with patch.dict(
            os.environ,
            {"WATSONX_API_KEY": "fake_key", "WATSONX_PROJECT_ID": "fake_project"},
            clear=False,
        ):
            with patch("watsonx_client.WatsonxClient.__init__", return_value=None) as _:
                client = WatsonxClient.__new__(WatsonxClient)
                client._client = mock_model
                assert client.is_available() is True


# ---------------------------------------------------------------------------
# Tests: generate_explanation() when unavailable
# ---------------------------------------------------------------------------

class TestGenerateExplanationUnavailable:

    def test_raises_when_client_not_available(self) -> None:
        client = _make_client_with_no_env()
        with pytest.raises(WatsonxUnavailableError):
            client.generate_explanation(
                indicators=["Urgent or Threatening Language"],
                risk_level="High",
                snippet="Act now or your account will be closed.",
            )


# ---------------------------------------------------------------------------
# Tests: generate_explanation() with mocked SDK
# ---------------------------------------------------------------------------

class TestGenerateExplanationMocked:

    def _make_available_client(self, mock_response) -> WatsonxClient:
        """Create a WatsonxClient whose internal _client is fully mocked."""
        client = WatsonxClient.__new__(WatsonxClient)
        mock_model = MagicMock()
        mock_model.generate_text.return_value = mock_response
        client._client = mock_model
        return client

    def test_returns_string_from_model(self) -> None:
        client = self._make_available_client("This message appears to have phishing indicators.")
        result = client.generate_explanation(
            indicators=["Urgent or Threatening Language", "Suspicious Link Detected"],
            risk_level="High",
            snippet="Act now! Click http://bit.ly/verify to secure your account.",
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_returns_stripped_string(self) -> None:
        client = self._make_available_client("  Some explanation with whitespace.  ")
        result = client.generate_explanation(
            indicators=["Request for Sensitive Information"],
            risk_level="Medium",
            snippet="Please provide your password to continue.",
        )
        assert result == "Some explanation with whitespace."

    def test_sdk_exception_raises_watsonx_unavailable(self) -> None:
        client = WatsonxClient.__new__(WatsonxClient)
        mock_model = MagicMock()
        mock_model.generate_text.side_effect = Exception("Connection timeout")
        client._client = mock_model

        with pytest.raises(WatsonxUnavailableError):
            client.generate_explanation(
                indicators=["Urgent or Threatening Language"],
                risk_level="High",
                snippet="Act now!",
            )

    def test_empty_indicators_list_handled(self) -> None:
        client = self._make_available_client("No specific indicators were found in this message.")
        result = client.generate_explanation(
            indicators=[],
            risk_level="Low",
            snippet="Hi, how are you doing today?",
        )
        assert isinstance(result, str)

    def test_dict_response_format_handled(self) -> None:
        # Some SDK versions return a dict instead of a plain string
        dict_response = {"results": [{"generated_text": "Explanation from dict response."}]}
        client = self._make_available_client(dict_response)
        result = client.generate_explanation(
            indicators=["Suspicious Link Detected"],
            risk_level="Medium",
            snippet="Visit tinyurl.com/track for details.",
        )
        assert "Explanation from dict response." in result
