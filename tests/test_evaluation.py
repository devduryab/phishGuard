import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import evaluation


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://192.0.2.10/login", "ip_host"),
        ("https://xn--pypal-4ve.com/signin", "punycode"),
        ("https://bit.ly/3xYz", "shortener"),
        ("https://paypal.com.secure-billing.tk/login", "brand_impersonation"),
        ("https://a.b.c.d.example.com/", "deep_subdomain"),
        ("http://verify-account-login.example.org/", "keyword_stuffed"),
        ("https://schtrekh.de/img/", "https_clean"),
        ("http://plainsite.de/", "http_plain"),
    ],
)
def test_categorise_url(url, expected):
    assert evaluation.categorise_url(url) == expected


def test_categories_are_mutually_exclusive():
    # Every URL must land in exactly one bucket, otherwise the per-category
    # detection rates would not add up to the totals.
    urls = [
        "http://192.0.2.10/login-verify-account",
        "https://paypal.com.evil.tk/",
        "https://bit.ly/abc",
        "https://clean-domain.com/",
    ]
    for url in urls:
        assert evaluation.categorise_url(url) in evaluation.CATEGORY_LABELS


def test_compute_metrics_perfect_classifier():
    metrics = evaluation.compute_metrics({"tp": 50, "fp": 0, "tn": 50, "fn": 0})
    assert metrics["precision"] == 100.0
    assert metrics["recall"] == 100.0
    assert metrics["f1"] == 100.0
    assert metrics["accuracy"] == 100.0


def test_compute_metrics_misses_everything():
    metrics = evaluation.compute_metrics({"tp": 0, "fp": 0, "tn": 50, "fn": 50})
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0
    assert metrics["accuracy"] == 50.0


def test_compute_metrics_handles_empty_counts():
    metrics = evaluation.compute_metrics({"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    assert metrics["precision"] == 0.0
    assert metrics["accuracy"] == 0.0


def test_weight_sensitivity_favours_ml_when_rules_are_blind():
    # A phishing set the rule engine cannot see (rule 0) but the classifier
    # scores highly, and a legitimate set both components score low. This is
    # the situation the live feed actually produced.
    scored = [(f"p{i}", 1, 0.0, 0, 95.0, False) for i in range(20)]
    scored += [(f"l{i}", 0, 0.0, 0, 5.0, False) for i in range(20)]

    results = evaluation.weight_sensitivity(scored, threshold=40.0)
    by_ml_weight = sorted(results, key=lambda item: item["ml_weight"])

    assert by_ml_weight[0]["recall"] < by_ml_weight[-1]["recall"]
    assert by_ml_weight[-1]["recall"] == 100.0
    assert next(item for item in results if item["is_best"])["recall"] == 100.0


def test_weight_sensitivity_marks_exactly_one_best():
    scored = [(f"p{i}", 1, 0.0, 10, 90.0, False) for i in range(10)]
    scored += [(f"l{i}", 0, 0.0, 0, 2.0, False) for i in range(10)]

    results = evaluation.weight_sensitivity(scored, threshold=40.0)
    assert sum(1 for item in results if item["is_best"]) == 1
    assert sum(1 for item in results if item["is_current"]) == 1


def test_escalated_urls_are_detected_under_every_weighting():
    # A URL both components score near zero on, but which carries a
    # high-confidence signal, must still be flagged regardless of weights.
    scored = [(f"p{i}", 1, 0.0, 0, 1.0, True) for i in range(10)]
    scored += [(f"l{i}", 0, 0.0, 0, 1.0, False) for i in range(10)]

    results = evaluation.weight_sensitivity(scored, threshold=40.0)
    assert all(item["recall"] == 100.0 for item in results)
    assert all(item["counts"]["fp"] == 0 for item in results)


def test_sweep_thresholds_recall_decreases_as_threshold_rises():
    scored = [(f"p{i}", 1, float(i), 0, 0.0, False) for i in range(0, 100, 5)]
    sweep = evaluation.sweep_thresholds(scored)
    recalls = [point["recall"] for point in sweep]
    assert recalls == sorted(recalls, reverse=True)


def test_load_phishing_urls_returns_only_absolute_urls():
    urls = evaluation.load_phishing_urls(20)
    if not urls:
        pytest.skip("phishing feed not downloaded")
    assert all(url.startswith(("http://", "https://")) for url in urls)


def test_legitimate_set_includes_urls_with_paths():
    # Guards the bias that broke the model: evaluating only on bare domains
    # would hide the detector's blindness to path content.
    urls = evaluation.load_legitimate_urls(60)
    with_paths = [url for url in urls if url.count("/") > 2]
    assert len(with_paths) >= 20
