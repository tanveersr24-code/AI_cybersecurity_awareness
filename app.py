"""
app.py — Streamlit UI for the AI Cybersecurity Awareness Assistant.

Run with:
    streamlit run app.py

Two tabs:
    1. Message Analyzer — paste a suspicious message and get a risk assessment.
    2. Password Checker — check password strength (educational, nothing is stored).
"""

from __future__ import annotations

import sys
import os

# Allow imports from the project root when running via `streamlit run app.py`
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st

from advice import AdviceProvider
from analyzer import AnalysisResult, MessageAnalyzer
from exceptions import (
    EmptyMessageError,
    InvalidInputTypeError,
    MessageTooLongError,
    MessageTooShortError,
    WatsonxUnavailableError,
)
from password_checker import PasswordChecker
from watsonx_client import WatsonxClient

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="AI Cybersecurity Awareness Assistant",
    page_icon="🔐",
    layout="centered",
)

# ---------------------------------------------------------------------------
# Initialise session state
# ---------------------------------------------------------------------------

if "history" not in st.session_state:
    st.session_state["history"]: list[AnalysisResult] = []

if "watsonx" not in st.session_state:
    st.session_state["watsonx"] = WatsonxClient()

# ---------------------------------------------------------------------------
# Helper: risk-level badge styling
# ---------------------------------------------------------------------------

_RISK_COLORS: dict[str, str] = {
    "Low": "#2d7a2d",      # green
    "Medium": "#c47a00",   # amber
    "High": "#c0392b",     # red
}

_RISK_ICONS: dict[str, str] = {
    "Low": "🟢",
    "Medium": "🟡",
    "High": "🔴",
}

_STRENGTH_COLORS: dict[str, str] = {
    "Weak": "#c0392b",
    "Moderate": "#c47a00",
    "Strong": "#2d7a2d",
}

_STRENGTH_ICONS: dict[str, str] = {
    "Weak": "🔴",
    "Moderate": "🟡",
    "Strong": "🟢",
}


def _risk_badge(level: str) -> str:
    color = _RISK_COLORS.get(level, "#555")
    icon = _RISK_ICONS.get(level, "⚪")
    return (
        f'<span style="background:{color};color:white;padding:4px 14px;'
        f'border-radius:12px;font-weight:bold;font-size:1.05rem;">'
        f'{icon} {level.upper()} RISK</span>'
    )


def _strength_badge(level: str) -> str:
    color = _STRENGTH_COLORS.get(level, "#555")
    icon = _STRENGTH_ICONS.get(level, "⚪")
    return (
        f'<span style="background:{color};color:white;padding:4px 14px;'
        f'border-radius:12px;font-weight:bold;font-size:1.05rem;">'
        f'{icon} {level.upper()}</span>'
    )


# ---------------------------------------------------------------------------
# Helper: render a single AnalysisResult
# ---------------------------------------------------------------------------

def _render_result(result: AnalysisResult, expanded: bool = True) -> None:
    """Render a full analysis result card."""
    with st.container():
        # Risk badge
        st.markdown(_risk_badge(result.risk_level), unsafe_allow_html=True)
        st.write("")  # spacing

        # Indicators and explanations
        if result.indicators_found:
            st.markdown("#### 🚩 Warning Signs Detected")
            for indicator, explanation in zip(result.indicators_found, result.explanations):
                with st.expander(f"⚠️ {indicator}"):
                    st.write(explanation)
        else:
            st.info(
                "✅ No specific warning signs were detected. "
                "However, this does not mean the message is definitely safe."
            )

        # AI or fallback explanation
        st.markdown("#### 🤖 Explanation")
        if result.ai_available and result.ai_explanation:
            st.write(result.ai_explanation)
        else:
            if not result.ai_available:
                st.caption(
                    "ℹ️ AI-powered explanation is unavailable. "
                    "Showing a rule-based summary instead."
                )
            if result.indicators_found:
                st.write(
                    f"This message contains **{len(result.indicators_found)}** "
                    f"warning sign(s) commonly associated with phishing or scam attempts. "
                    f"Each warning sign is explained above."
                )
            else:
                st.write(
                    "No specific phishing patterns were detected in this message. "
                    "Always stay cautious with unexpected messages."
                )

        # Recommended actions
        st.markdown("#### ✅ Recommended Actions")
        for action in result.advice:
            st.markdown(f"- {action}")

        # Disclaimer
        st.warning(result.disclaimer)


# ---------------------------------------------------------------------------
# Tab 1 — Message Analyzer
# ---------------------------------------------------------------------------

def _tab_message_analyzer() -> None:
    st.markdown(
        "Paste or type a suspicious **email, SMS, chat message, or link** below "
        "and click **Analyze Message** to check it for common phishing and scam warning signs."
    )

    user_input = st.text_area(
        label="Suspicious message",
        placeholder="e.g. 'Dear customer, your account will be suspended. Click here urgently to verify...'",
        height=180,
        max_chars=5000,
        label_visibility="collapsed",
    )

    col1, col2 = st.columns([1, 4])
    with col1:
        analyze_btn = st.button("🔍 Analyze Message", type="primary", use_container_width=True)
    with col2:
        clear_btn = st.button("🗑️ Clear History", use_container_width=True)

    if clear_btn:
        st.session_state["history"] = []
        st.rerun()

    if analyze_btn:
        with st.spinner("Analyzing..."):
            try:
                analyzer = MessageAnalyzer(user_input)
                result = analyzer.analyze()
            except (EmptyMessageError, MessageTooShortError, MessageTooLongError) as exc:
                st.warning(str(exc))
                return
            except InvalidInputTypeError as exc:
                st.error(str(exc))
                return

            # Attach advice
            result.advice = AdviceProvider.get_advice(result.risk_level)

            # Attempt AI explanation
            watsonx: WatsonxClient = st.session_state["watsonx"]
            if watsonx.is_available():
                try:
                    result.ai_explanation = watsonx.generate_explanation(
                        indicators=result.indicators_found,
                        risk_level=result.risk_level,
                        snippet=result.original_text[:150],
                    )
                    result.ai_available = True
                except WatsonxUnavailableError:
                    result.ai_available = False
            else:
                result.ai_available = False

            # Prepend to session history
            st.session_state["history"].insert(0, result)

    # Show current (latest) result
    if st.session_state["history"]:
        latest = st.session_state["history"][0]
        st.markdown("---")
        st.markdown("### 📊 Analysis Result")
        _render_result(latest)

        # Session history (older entries)
        if len(st.session_state["history"]) > 1:
            st.markdown("---")
            with st.expander(
                f"📜 Session History ({len(st.session_state['history']) - 1} previous analysis/analyses)",
                expanded=False,
            ):
                for i, past_result in enumerate(st.session_state["history"][1:], start=2):
                    snippet = past_result.original_text[:80] + ("..." if len(past_result.original_text) > 80 else "")
                    icon = _RISK_ICONS.get(past_result.risk_level, "⚪")
                    with st.expander(f"#{i} {icon} {past_result.risk_level} Risk — \"{snippet}\""):
                        _render_result(past_result)


# ---------------------------------------------------------------------------
# Tab 2 — Password Checker
# ---------------------------------------------------------------------------

def _tab_password_checker() -> None:
    st.markdown(
        "Check how strong a password is. "
        "This is an **educational awareness tool** — your password is evaluated "
        "locally in your browser session and is **never stored, transmitted, or displayed**."
    )

    st.info(
        "🔒 **Do not enter real passwords you currently use.** "
        "This tool is for learning what makes a password strong, not for checking live credentials."
    )

    password_input = st.text_input(
        label="Password to check",
        type="password",
        placeholder="Type a sample password...",
        label_visibility="collapsed",
    )

    check_btn = st.button("🔍 Check Password Strength", type="primary")

    if check_btn:
        checker = PasswordChecker(password_input)
        result = checker.check_strength()

        st.markdown("---")
        st.markdown("### 🔐 Password Strength Result")
        st.markdown(_strength_badge(result.strength), unsafe_allow_html=True)
        st.write("")

        if result.feedback:
            st.markdown("#### 💡 How to Make It Stronger")
            for tip in result.feedback:
                st.markdown(f"- {tip}")
        else:
            st.success(
                "Great password! It meets all the strength criteria. "
                "Remember to use a unique password for every account."
            )

        st.markdown("#### 📚 Password Safety Tips")
        st.markdown(
            """
- Use a different password for **every** account — especially email and banking.
- Consider using a **passphrase**: three or four random words joined together (e.g. `PurpleTreeBridge47!`).
- Use a **password manager** (e.g. Bitwarden, 1Password) to store complex passwords safely.
- Enable **two-factor authentication (2FA)** wherever possible — it protects you even if your password is stolen.
- Never share your password with anyone, including tech support.
            """
        )

        st.caption(
            "🔒 Reminder: This password was evaluated in memory only and has not been stored or transmitted."
        )


# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------

def main() -> None:
    # App header
    st.title("🔐 AI Cybersecurity Awareness Assistant")
    st.markdown(
        "An educational tool to help you recognise common **phishing and scam warning signs** "
        "and develop safer digital habits."
    )

    # Always-visible disclaimer banner
    st.error(
        "⚠️ **Educational Tool Only** — This app helps you recognise common warning signs. "
        "It **cannot guarantee** that any message or sender is legitimate or malicious. "
        "Always apply your own judgment and consult official sources when in doubt."
    )

    # Tabs
    tab1, tab2 = st.tabs(["📨 Message Analyzer", "🔑 Password Checker"])

    with tab1:
        _tab_message_analyzer()

    with tab2:
        _tab_password_checker()

    # Footer
    st.markdown("---")
    st.caption(
        "🛡️ This tool is for cybersecurity **awareness and education** only. "
        "It does not perform penetration testing, malware analysis, or any offensive security activity. "
        "| Built with Python + Streamlit + IBM watsonx.ai (optional)"
    )


if __name__ == "__main__":
    main()
