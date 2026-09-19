import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import requests
import summarizer


HIGH_RISK_SCAN = {
    "url": "http://192.0.2.10/login-verify-account",
    "level": "HIGH",
    "score": 85.0,
    "rule_score": 95,
    "ml_score": 100.0,
    "security_score": 20,
    "reasons": ["Hostname appears to be an IP address.", "URL is not using HTTPS."],
    "findings": [
        {"severity": "MEDIUM", "title": "HTTPS is not used", "detail": "Not HTTPS."},
        {"severity": "LOW", "title": "Missing header: Referrer-Policy", "detail": "Absent."},
    ],
}

CLEAN_SCAN = {
    "url": "https://example.com",
    "level": "LOW",
    "score": 3.0,
    "rule_score": 0,
    "ml_score": 0.5,
    "security_score": 20,
    "reasons": ["No strong suspicious URL pattern was found."],
    "findings": [
        {"severity": "INFO", "title": "HTTPS is enabled", "detail": "Used HTTPS."},
    ],
}


def test_prompt_contains_only_scan_data():
    prompt = summarizer.build_prompt(HIGH_RISK_SCAN)
    assert HIGH_RISK_SCAN["url"] in prompt
    assert "Hostname appears to be an IP address." in prompt
    assert "ONLY the scan data" in prompt


def test_prompt_states_the_verdict_in_words():
    # The model must not have to infer the risk band from the numeric score:
    # a 3B model misread 3.79/100 as "moderate risk" during testing.
    assert "high risk" in summarizer.build_prompt(HIGH_RISK_SCAN)
    assert "low risk" in summarizer.build_prompt(CLEAN_SCAN)


def test_contradiction_detection():
    assert summarizer.contradicts_verdict("This is a moderate risk link.", "LOW")
    assert summarizer.contradicts_verdict("This link is low risk.", "HIGH")
    assert not summarizer.contradicts_verdict("This link is low risk.", "LOW")
    assert not summarizer.contradicts_verdict("This link is high risk.", "HIGH")


@pytest.mark.parametrize(
    "text",
    [
        # Every one of these was actually produced by llama3.2:3b for a URL
        # the system scored as low risk.
        "This link, https://github.com, looks like it could be phishing because"
        " its URL pattern doesn't show any strong suspicious signs.",
        "This link might be phishing.",
        "This link may be a phishing site.",
        "It looks like a phishing site.",
        "The address appears to be phishing.",
        "It shows signs of phishing.",
        "This link has a high score.",
    ],
)
def test_low_risk_phishing_claims_are_rejected(text):
    assert summarizer.contradicts_verdict(text, "LOW")


@pytest.mark.parametrize(
    "text",
    [
        "This link does not appear to be a phishing site. Nothing stood out.",
        "Nothing in this address suggests phishing. Some headers were missing.",
        "This address shows no phishing indicators. Take normal care online.",
        "The address looks ordinary and no suspicious patterns were found.",
        "Nothing strongly indicates phishing, but take normal care.",
    ],
)
def test_valid_low_risk_wording_is_allowed(text):
    assert not summarizer.contradicts_verdict(text, "LOW")


def test_contradicting_llm_output_is_rejected(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "This link carries a moderate risk of phishing."}

    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse())
    result = summarizer.summarize(CLEAN_SCAN)

    assert result["source"] == "fallback"
    assert "contradicted" in result["reason"]


def test_llm_line_breaks_are_collapsed(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "First sentence.\n\nSecond   sentence."}

    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse())
    result = summarizer.summarize(HIGH_RISK_SCAN)

    assert result["summary"] == "First sentence. Second sentence."


def test_fallback_mentions_score_and_advice():
    text = summarizer.fallback_summary(HIGH_RISK_SCAN)
    assert "85.0" in text
    assert "Avoid this address" in text


def test_fallback_handles_clean_url():
    text = summarizer.fallback_summary(CLEAN_SCAN)
    assert "no suspicious patterns" in text
    assert "normal caution" in text


def test_fallback_is_used_when_ollama_is_down(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(requests, "post", fail)
    result = summarizer.summarize(HIGH_RISK_SCAN)

    assert result["source"] == "fallback"
    assert "reason" in result
    assert result["summary"]


def test_llm_response_is_used_when_available(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "  This link looks dangerous. Avoid it.  "}

    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse())
    result = summarizer.summarize(HIGH_RISK_SCAN)

    assert result["source"] == "llm"
    assert result["summary"] == "This link looks dangerous. Avoid it."


def test_empty_llm_response_falls_back(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "   "}

    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse())
    result = summarizer.summarize(HIGH_RISK_SCAN)

    assert result["source"] == "fallback"


def test_ollama_available_reports_false_when_unreachable(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(requests, "get", fail)
    status = summarizer.ollama_available()

    assert status["available"] is False
    assert status["model_ready"] is False
