# 🔐 AI Cybersecurity Awareness Assistant

A beginner-friendly Python + Streamlit application that helps you recognise common **phishing and scam warning signs** and develop safer digital habits.

> **Educational tool only.** This app cannot guarantee that any message or sender is legitimate. Always apply your own judgment.

---

## ✨ Features

- **Message Analyzer** — paste any suspicious email, SMS, chat message, or link description and get an instant risk assessment (Low / Medium / High)
- **7 indicator categories** detected: urgency, sensitive info requests, money requests, impersonation, suspicious links, attachment mentions, bypass-security requests
- **AI-powered explanations** via IBM watsonx.ai Granite model (optional — app works fully offline without it)
- **Recommended safety actions** tailored to each risk level
- **Password Strength Checker** — educational awareness tab (passwords are never stored or transmitted)
- **Session history** — scroll back through all analyses in the current session

---

## 📁 Project Structure

```
cybersecurity-awareness-app/
│
├── app.py                  Streamlit UI entry point
├── analyzer.py             MessageAnalyzer + AnalysisResult (core rule engine)
├── scorer.py               RiskScorer (indicator count → risk level)
├── password_checker.py     PasswordChecker + PasswordResult
├── watsonx_client.py       WatsonxClient (optional IBM watsonx.ai integration)
├── indicators.py           Keyword/pattern lists for all 7 indicator categories
├── advice.py               AdviceProvider (risk level → recommended actions)
├── exceptions.py           Custom exception classes
├── requirements.txt        Project dependencies
├── .env.example            Template for watsonx credentials
└── tests/
    ├── conftest.py         Adds project root to sys.path for pytest
    ├── test_analyzer.py    Tests for MessageAnalyzer (50 tests)
    ├── test_scorer.py      Tests for RiskScorer (8 tests)
    ├── test_password.py    Tests for PasswordChecker (20 tests)
    └── test_watsonx.py     Tests for WatsonxClient with mocked SDK (10 tests)
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or newer
- pip

### 1. Install dependencies

```bash
cd cybersecurity-awareness-app
pip install -r requirements.txt
```

### 2. Configure IBM watsonx.ai (optional)

The app works perfectly without watsonx credentials. If you want AI-generated explanations:

1. Copy the example env file:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and fill in your values:
   ```
   WATSONX_API_KEY=your_api_key_here
   WATSONX_PROJECT_ID=your_project_id_here
   WATSONX_URL=https://us-south.ml.cloud.ibm.com
   ```
3. Save the file. The app will detect the credentials automatically on startup.

> ⚠️ Never commit your `.env` file to git. It is already listed in `.gitignore`.

### 3. Run the application

```bash
streamlit run app.py
```

Your browser will open automatically at `http://localhost:8501`.

---

## 🧪 Running the Tests

```bash
cd cybersecurity-awareness-app
python -m pytest tests/ -v
```

Expected output: **88 passed** — no watsonx credentials required (SDK calls are mocked).

---

## 🔒 Safety and Privacy Notes

- **No credentials are collected.** The app never asks for real passwords, OTPs, or API keys.
- **Passwords entered in the Password Checker are evaluated in local memory only** — they are never stored, logged, or transmitted anywhere.
- **No links are opened or executed.** The app only reads text and looks for patterns.
- **No files are downloaded.** This is a text-only input application.
- **Results are educational awareness assessments**, not definitive verdicts. The app always displays this disclaimer prominently.

---

## ⚠️ Limitations

- **English-only** — the keyword patterns are in English. Non-English messages may not be fully analyzed.
- **Keyword-based detection** — the rule engine uses keyword matching, not machine learning. It can have false positives (e.g. a news article mentioning "Amazon") and false negatives (novel scam techniques not yet in the keyword lists).
- **No URL execution** — the app checks for suspicious URL patterns in text but does not visit links or check their actual content.
- **Session history is lost on browser refresh** — history is stored in Streamlit session state only.

---

## 🏗️ Architecture

```
User Input
    └─▶ MessageAnalyzer (rule engine)
            └─▶ 7 _check_* methods (indicators.py patterns)
            └─▶ RiskScorer (Low / Medium / High)
            └─▶ AnalysisResult (dataclass)
                    └─▶ WatsonxClient.generate_explanation() [optional]
                    └─▶ AdviceProvider.get_advice()
                    └─▶ Streamlit UI renders result + adds to session_state history
```

Business logic (`analyzer.py`, `scorer.py`, `advice.py`, `password_checker.py`, `watsonx_client.py`) is **fully independent of Streamlit** and can be used or tested without the UI.
