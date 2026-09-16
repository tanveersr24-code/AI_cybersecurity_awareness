"""
watsonx_client.py — IBM watsonx.ai integration (optional).

WatsonxClient wraps the IBM watsonx.ai Python SDK to generate beginner-friendly
explanations of detected phishing/scam indicators.

This component is entirely optional:
- If WATSONX_API_KEY and WATSONX_PROJECT_ID are not set in the .env file,
  is_available() returns False and the app falls back to rule-based explanations.
- The AI is only used to explain already-detected indicators.
  It cannot override the rule engine's findings.
- No user message content beyond a short snippet is sent to the API.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

from exceptions import WatsonxUnavailableError

# Load .env file if present (silently ignored if missing)
load_dotenv()

# Model and generation settings
_MODEL_ID: str = "ibm/granite-3-8b-instruct"
_MAX_NEW_TOKENS: int = 300
_TEMPERATURE: float = 0.3

# Prompt template — instructs Granite to explain risks in beginner-friendly language
_PROMPT_TEMPLATE: str = """You are a friendly cybersecurity educator helping a beginner understand why a message might be dangerous.

The following warning signs were detected in a suspicious message:
{indicators}

Overall risk level: {risk_level}

Message snippet (first 150 characters):
"{snippet}"

Please explain in 3–5 simple sentences why these warning signs are concerning and what the person should do. 
Use plain, non-technical language suitable for someone with no cybersecurity experience.
Do NOT claim with certainty that the message is definitely a scam — this is an educational awareness tool.
Do NOT reproduce any personal information, passwords, or credentials.
Keep your response under 150 words.
"""


class WatsonxClient:
    """
    Optional IBM watsonx.ai client for AI-generated explanations.

    Usage:
        client = WatsonxClient()
        if client.is_available():
            explanation = client.generate_explanation(indicators, risk_level, snippet)

    Raises:
        WatsonxUnavailableError: If credentials are missing or the API call fails.
    """

    def __init__(self) -> None:
        """
        Load credentials from environment variables and initialise the SDK client.
        Does not raise — unavailability is surfaced via is_available().
        """
        self._api_key: str = os.getenv("WATSONX_API_KEY", "").strip()
        self._project_id: str = os.getenv("WATSONX_PROJECT_ID", "").strip()
        self._url: str = os.getenv(
            "WATSONX_URL", "https://us-south.ml.cloud.ibm.com"
        ).strip()
        self._client = None

        if self._api_key and self._project_id:
            try:
                from ibm_watsonx_ai import Credentials
                from ibm_watsonx_ai.foundation_models import ModelInference

                credentials = Credentials(
                    url=self._url,
                    api_key=self._api_key,
                )
                self._client = ModelInference(
                    model_id=_MODEL_ID,
                    credentials=credentials,
                    project_id=self._project_id,
                    params={
                        "max_new_tokens": _MAX_NEW_TOKENS,
                        "temperature": _TEMPERATURE,
                    },
                )
            except Exception:
                # Credentials present but SDK init failed — mark as unavailable
                self._client = None

    def is_available(self) -> bool:
        """
        Return True if the watsonx client was successfully initialised.

        Returns:
            bool: True if ready to generate explanations, False otherwise.
        """
        return self._client is not None

    def generate_explanation(
        self,
        indicators: list[str],
        risk_level: str,
        snippet: str,
    ) -> str:
        """
        Call the Granite foundation model to generate a beginner-friendly explanation.

        Args:
            indicators: List of indicator category names detected in the message.
            risk_level: The calculated risk level ("Low", "Medium", or "High").
            snippet:    A short excerpt of the original message (max 150 chars).

        Returns:
            A plain-text explanation string from the AI model.

        Raises:
            WatsonxUnavailableError: If the client is not available or the API call fails.
        """
        if not self.is_available():
            raise WatsonxUnavailableError("No credentials configured.")

        indicators_text = "\n".join(f"- {ind}" for ind in indicators) if indicators else "- No specific indicators found"
        safe_snippet = snippet[:150].replace('"', "'")

        prompt = _PROMPT_TEMPLATE.format(
            indicators=indicators_text,
            risk_level=risk_level,
            snippet=safe_snippet,
        )

        try:
            response = self._client.generate_text(prompt=prompt)  # type: ignore[union-attr]
            if isinstance(response, str):
                return response.strip()
            # Some SDK versions return a dict
            if isinstance(response, dict):
                return str(response.get("results", [{}])[0].get("generated_text", "")).strip()
            return str(response).strip()
        except Exception as exc:
            raise WatsonxUnavailableError(str(exc)) from exc
