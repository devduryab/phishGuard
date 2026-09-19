import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detector


def test_normalize_url_adds_https_when_missing():
    assert detector.normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_existing_scheme():
    assert detector.normalize_url("http://example.com") == "http://example.com"
    assert detector.normalize_url("https://example.com") == "https://example.com"


def test_make_features_ignores_www_prefix():
    # Regression test: an earlier trained model learned "no www. -> phishing"
    # because the training dataset had www. on ~100% of legitimate URLs but
    # only ~41% of phishing URLs. Features must be identical with/without
    # www. so the model can't use it as a shortcut.
    with_www = detector.make_features("https://www.example.com")
    without_www = detector.make_features("https://example.com")
    assert with_www == without_www


def test_make_features_detects_ip_host():
    features = detector.make_features("http://192.168.1.1/login")
    assert features["has_ip"] == 1


def test_make_features_detects_non_ip_host():
    features = detector.make_features("https://example.com/login")
    assert features["has_ip"] == 0


def test_make_features_counts_suspicious_words():
    features = detector.make_features("https://secure-login-verify.example.com")
    assert features["suspicious_words"] >= 2


def test_make_features_https_flag():
    assert detector.make_features("https://example.com")["https"] == 1
    assert detector.make_features("http://example.com")["https"] == 0


def test_rule_score_clean_url_is_zero():
    features = detector.make_features("https://example.com")
    score, reasons = detector.rule_score(features)
    assert score == 0
    assert "No strong suspicious URL pattern was found." in reasons


def test_rule_score_flags_long_url():
    long_url = "https://example.com/" + ("a" * 80)
    features = detector.make_features(long_url)
    score, reasons = detector.rule_score(features)
    assert score >= 15
    assert any("long" in r.lower() for r in reasons)


def test_rule_score_flags_at_symbol():
    features = detector.make_features("https://example.com/redirect?next=user@evil.com")
    score, reasons = detector.rule_score(features)
    assert score >= 20
    assert any("@" in r for r in reasons)


def test_rule_score_flags_ip_host():
    features = detector.make_features("http://192.168.1.1/login")
    score, reasons = detector.rule_score(features)
    assert score >= 20
    assert any("IP address" in r for r in reasons)


def test_rule_score_flags_multiple_hyphens():
    features = detector.make_features("https://a-b-c-d.example.com")
    score, reasons = detector.rule_score(features)
    assert score >= 10
    assert any("hyphens" in r.lower() for r in reasons)


def test_rule_score_flags_missing_https():
    features = detector.make_features("http://example.com")
    score, reasons = detector.rule_score(features)
    assert score >= 15
    assert any("HTTPS" in r for r in reasons)


def test_rule_score_caps_at_100():
    worst_url = "http://192.168.1.1/login-verify-account-signin-bonus-free-gift?user=test@x.com"
    features = detector.make_features(worst_url)
    score, _ = detector.rule_score(features)
    assert score <= 100


def test_analyze_url_without_model(monkeypatch):
    monkeypatch.setattr(detector, "MODEL_PATH", "nonexistent/model.joblib")
    result = detector.analyze_url("https://example.com")
    assert result["ml_score"] == 0.0
    assert result["normalized_url"] == "https://example.com"


def test_analyze_url_with_model_if_present():
    if not os.path.exists(detector.MODEL_PATH):
        import pytest
        pytest.skip("no trained model available")
    result = detector.analyze_url("https://example.com")
    assert 0.0 <= result["ml_score"] <= 100.0


def test_ml_score_stable_across_trailing_slash_and_path(monkeypatch):
    # Regression test: earlier trained models flagged any URL with a path
    # (even just a trailing "/") as ~100% phishing, because the training
    # dataset's legitimate class was 100% bare root domains. A clean
    # domain's ml_score should not swing wildly just because a harmless
    # path was added.
    if not os.path.exists(detector.MODEL_PATH):
        import pytest
        pytest.skip("no trained model available")

    root = detector.analyze_url("https://www.example-clean-site.com")["ml_score"]
    with_slash = detector.analyze_url("https://www.example-clean-site.com/")["ml_score"]
    with_path = detector.analyze_url("https://www.example-clean-site.com/about")["ml_score"]

    assert abs(root - with_slash) < 20
    assert abs(root - with_path) < 20
