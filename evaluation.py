"""Self-audit module: measures how well the detector performs on real data.

This deliberately does NOT make network requests. It evaluates the parts of
the system that judge a URL from its text - the rule engine and the machine
learning classifier - against real phishing URLs from a live feed and real
legitimate URLs. The passive security checks in vulnerability.py need a live
response and are therefore out of scope here; that limitation is reported
alongside the results.
"""

import ipaddress
import os
from urllib.parse import urlparse

from detector import (
    ESCALATION_FLOOR,
    SUSPICIOUS_WORDS,
    analyze_url,
    escalating_signal,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data", "evaluation")
PHISHING_FEED = os.path.join(DATA_DIR, "openphish.txt")

# The full Tranco list is 22 MB and excluded from git and from deployment.
# A committed 10,000-row extract is used when it is not present, which is
# ample since evaluations sample a few hundred domains.
TRANCO_CANDIDATES = [
    os.path.join(DATA_DIR, "top-1m.csv"),
    os.path.join(DATA_DIR, "tranco-top10k.csv"),
]
TRANCO_LIST = next(
    (path for path in TRANCO_CANDIDATES if os.path.exists(path)),
    TRANCO_CANDIDATES[-1],
)

# Weights mirror app.py, with the security component absent because no live
# request is made. A URL is treated as "flagged" at or above the threshold,
# which defaults to the app's MEDIUM boundary.
# Must mirror app.py so the "current" row in the weight analysis reflects what
# the live scanner actually uses.
RULE_WEIGHT = 0.35
ML_WEIGHT = 0.50
DEFAULT_THRESHOLD = 40.0

# Alternative weightings compared on every run. The rule engine currently
# carries most of the weight but only recognises older phishing patterns
# (IP hosts, "@" tricks, keyword stuffing), while the classifier is the
# component that actually reacts to current phishing domains.
WEIGHT_CANDIDATES = [
    (0.60, 0.25),
    (0.50, 0.35),
    (0.45, 0.40),
    (0.35, 0.50),
    (0.25, 0.60),
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "buff.ly", "shorturl.at", "rebrand.ly", "tiny.cc", "s.id",
    "lnkd.in", "t.ly", "shorturl.com",
}

IMPERSONATED_BRANDS = {
    "paypal", "apple", "microsoft", "netflix", "amazon", "google", "facebook",
    "instagram", "whatsapp", "outlook", "office365", "dhl", "fedex", "ups",
    "chase", "wellsfargo", "hsbc", "barclays", "coinbase", "binance", "steam",
    "linkedin", "dropbox", "adobe", "docusign", "meta", "icloud",
}

CATEGORY_LABELS = {
    "ip_host": "IP address as hostname",
    "punycode": "Punycode / homograph domain",
    "shortener": "URL shortener",
    "brand_impersonation": "Brand name in subdomain",
    "deep_subdomain": "Unusually deep subdomain",
    "keyword_stuffed": "Account/security keywords",
    "https_clean": "HTTPS with clean-looking domain",
    "http_plain": "Plain HTTP, no other signals",
    "unremarkable": "No obvious structural signal",
}


def _host_of(url):
    host = urlparse(url).netloc.lower()
    return host.split("@")[-1].split(":")[0]


def categorise_url(url):
    """Bucket a URL by the structural trait a detector could most plausibly use.

    Checked most-specific first, so each URL lands in exactly one bucket.
    """
    host = _host_of(url)
    lowered = url.lower()
    labels = [part for part in host.split(".") if part]

    try:
        ipaddress.ip_address(host)
        return "ip_host"
    except ValueError:
        pass

    if "xn--" in host:
        return "punycode"

    if host in SHORTENERS:
        return "shortener"

    # A brand name anywhere except the registrable domain is a strong
    # impersonation signal: paypal.com.secure-login.tk is not PayPal.
    if len(labels) > 2:
        for brand in IMPERSONATED_BRANDS:
            if any(brand in label for label in labels[:-2]):
                return "brand_impersonation"

    if len(labels) >= 5:
        return "deep_subdomain"

    if sum(word in lowered for word in SUSPICIOUS_WORDS) >= 2:
        return "keyword_stuffed"

    if lowered.startswith("https://"):
        return "https_clean"

    if lowered.startswith("http://"):
        return "http_plain"

    return "unremarkable"


def detection_score(url):
    """Score a URL using only the offline components, mirroring app weights."""
    analysis = analyze_url(url)
    score = round(
        analysis["rule_score"] * RULE_WEIGHT + analysis["ml_score"] * ML_WEIGHT, 2
    )

    if escalating_signal(analysis["features"]) and score < ESCALATION_FLOOR:
        score = ESCALATION_FLOOR

    return score, analysis


def load_phishing_urls(limit=250):
    if not os.path.exists(PHISHING_FEED):
        return []

    urls = []
    with open(PHISHING_FEED, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if line.startswith(("http://", "https://")):
                urls.append(line)
            if len(urls) >= limit:
                break
    return urls


def load_legitimate_urls(limit=250):
    """Real legitimate URLs: popular domains plus real deep links.

    The deep links matter. The training data contained only bare root domains
    for the legitimate class, so evaluating on bare domains alone would hide
    exactly the weakness that caused the worst bugs in this project.
    """
    urls = list(LEGITIMATE_DEEP_URLS)

    if os.path.exists(TRANCO_LIST):
        with open(TRANCO_LIST, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                parts = line.strip().split(",")
                if len(parts) == 2 and parts[1]:
                    urls.append(f"https://{parts[1]}")
                if len(urls) >= limit:
                    break

    return urls[:limit]


LEGITIMATE_DEEP_URLS = [
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://github.com/scikit-learn/scikit-learn",
    "https://github.com/pallets/flask/blob/main/README.md",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.bbc.co.uk/news/technology",
    "https://www.theguardian.com/international",
    "https://scikit-learn.org/stable/modules/ensemble.html",
    "https://pypi.org/project/requests/",
    "https://www.kaggle.com/datasets",
    "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
    "https://arxiv.org/abs/1706.03762",
    "https://www.nature.com/articles/s41586-021-03819-2",
    "https://news.ycombinator.com/newest",
    "https://www.reddit.com/r/learnpython/",
    "https://www.gov.uk/government/organisations/hm-revenue-customs",
    "https://support.google.com/accounts/answer/41078",
    "https://www.microsoft.com/en-us/security/blog/",
    "https://aws.amazon.com/s3/pricing/",
    "https://azure.microsoft.com/en-us/products/machine-learning",
    "https://www.paypal.com/uk/webapps/mpp/security/home",
    "https://accounts.google.com/signin/v2/identifier",
    "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://www.apple.com/uk/shop/buy-iphone",
    "https://www.netflix.com/browse/genre/34399",
    "https://www.amazon.co.uk/gp/help/customer/display.html",
    "https://www.linkedin.com/feed/",
    "https://www.dropbox.com/login",
    "https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go",
    "https://www.hsbc.co.uk/help/online-banking/",
    "https://www.dhl.com/gb-en/home/tracking.html",
    "https://www.royalmail.com/track-your-item",
    "https://www.ebay.co.uk/myb/PurchaseHistory",
    "https://www.gov.uk/log-in-register-hmrc-online-services",
    "https://mail.google.com/mail/u/0/",
    "https://outlook.live.com/mail/0/inbox",
    "https://www.icloud.com/mail",
    "https://www.office.com/login",
]


def evaluate(threshold=DEFAULT_THRESHOLD, phishing_limit=250, legit_limit=250):
    phishing_urls = load_phishing_urls(phishing_limit)
    legitimate_urls = load_legitimate_urls(legit_limit)

    if not phishing_urls:
        raise FileNotFoundError(
            "No phishing feed found. Expected data/evaluation/openphish.txt"
        )

    samples = [(url, 1) for url in phishing_urls] + [
        (url, 0) for url in legitimate_urls
    ]

    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    categories = {}
    false_negatives = []
    false_positives = []
    scored = []

    for url, label in samples:
        score, analysis = detection_score(url)
        predicted = 1 if score >= threshold else 0
        scored.append((
            url,
            label,
            score,
            analysis["rule_score"],
            analysis["ml_score"],
            bool(escalating_signal(analysis["features"])),
        ))

        if label == 1 and predicted == 1:
            outcome = "tp"
        elif label == 1:
            outcome = "fn"
        elif predicted == 1:
            outcome = "fp"
        else:
            outcome = "tn"
        counts[outcome] += 1

        if label == 1:
            category = categorise_url(url)
            bucket = categories.setdefault(
                category,
                {"category": category, "label": CATEGORY_LABELS.get(category, category),
                 "total": 0, "detected": 0},
            )
            bucket["total"] += 1
            if predicted == 1:
                bucket["detected"] += 1

        if outcome == "fn" and len(false_negatives) < 25:
            false_negatives.append({
                "url": url,
                "score": score,
                "rule_score": analysis["rule_score"],
                "ml_score": analysis["ml_score"],
                "category": categorise_url(url),
            })
        elif outcome == "fp" and len(false_positives) < 25:
            false_positives.append({
                "url": url,
                "score": score,
                "rule_score": analysis["rule_score"],
                "ml_score": analysis["ml_score"],
                "reasons": analysis["reasons"],
            })

    metrics = compute_metrics(counts)

    for bucket in categories.values():
        bucket["missed"] = bucket["total"] - bucket["detected"]
        bucket["detection_rate"] = (
            round(bucket["detected"] / bucket["total"] * 100, 1)
            if bucket["total"]
            else 0.0
        )

    return {
        "threshold": threshold,
        "counts": counts,
        "metrics": metrics,
        "totals": {
            "phishing": len(phishing_urls),
            "legitimate": len(legitimate_urls),
            "total": len(samples),
        },
        "categories": sorted(
            categories.values(), key=lambda item: item["detection_rate"]
        ),
        "false_negatives": sorted(false_negatives, key=lambda item: item["score"]),
        "false_positives": sorted(
            false_positives, key=lambda item: item["score"], reverse=True
        ),
        "sweep": sweep_thresholds(scored),
        "weight_analysis": weight_sensitivity(scored, threshold),
    }


def weight_sensitivity(scored, threshold):
    """Re-score every sample under alternative rule/ML weightings.

    This is the core self-audit output: it shows whether the detector is
    limited by its components or simply by how their scores are combined.
    """
    results = []

    for rule_weight, ml_weight in WEIGHT_CANDIDATES:
        counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

        for _, label, _, rule_score, ml_score, escalates in scored:
            combined = rule_score * rule_weight + ml_score * ml_weight
            # Escalation applies whatever the weights are, so it must be
            # included here too - otherwise the row marked "current" would
            # not match the headline metrics for the same configuration.
            if escalates and combined < ESCALATION_FLOOR:
                combined = ESCALATION_FLOOR
            predicted = 1 if combined >= threshold else 0

            if label == 1 and predicted == 1:
                counts["tp"] += 1
            elif label == 1:
                counts["fn"] += 1
            elif predicted == 1:
                counts["fp"] += 1
            else:
                counts["tn"] += 1

        metrics = compute_metrics(counts)
        results.append({
            "rule_weight": rule_weight,
            "ml_weight": ml_weight,
            "security_weight": round(1 - rule_weight - ml_weight, 2),
            "is_current": rule_weight == RULE_WEIGHT and ml_weight == ML_WEIGHT,
            "counts": counts,
            **metrics,
        })

    best = max(results, key=lambda item: item["f1"])
    for item in results:
        item["is_best"] = item is best

    return results


def compute_metrics(counts):
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    total = tp + fp + tn + fn

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    return {
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1 * 100, 1),
        "accuracy": round(accuracy * 100, 1),
    }


def sweep_thresholds(scored, steps=range(0, 101, 5)):
    """Show how the detection threshold trades recall against false positives."""
    sweep = []
    for threshold in steps:
        counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        for _, label, score, _, _, _ in scored:
            predicted = 1 if score >= threshold else 0
            if label == 1 and predicted == 1:
                counts["tp"] += 1
            elif label == 1:
                counts["fn"] += 1
            elif predicted == 1:
                counts["fp"] += 1
            else:
                counts["tn"] += 1

        metrics = compute_metrics(counts)
        sweep.append({
            "threshold": threshold,
            "recall": metrics["recall"],
            "precision": metrics["precision"],
            "f1": metrics["f1"],
            "false_positives": counts["fp"],
        })
    return sweep


def dataset_info():
    phishing = load_phishing_urls(10_000)
    return {
        "phishing_available": len(phishing),
        "phishing_feed_present": os.path.exists(PHISHING_FEED),
        "phishing_feed_updated": (
            os.path.getmtime(PHISHING_FEED) if os.path.exists(PHISHING_FEED) else None
        ),
        "tranco_present": os.path.exists(TRANCO_LIST),
        "curated_legitimate": len(LEGITIMATE_DEEP_URLS),
    }
