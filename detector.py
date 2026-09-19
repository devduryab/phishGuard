from urllib.parse import urlparse
import ipaddress
import os

try:
    import joblib
    import pandas as pd
except ImportError:
    joblib = None

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "phishing_model.joblib")

SUSPICIOUS_WORDS = [
    "login", "verify", "verification", "secure", "account",
    "update", "password", "bank", "wallet", "signin",
    "confirm", "bonus", "free", "gift", "docusign", "invoice",
    "billing", "payment", "suspended", "unlock", "recover",
]

# Top-level domains repeatedly reported as heavily abused for phishing,
# largely because registration is free or near-free. Used as a weak signal
# only: plenty of legitimate sites use these.
HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "cyou", "sbs",
    "cfd", "buzz", "rest", "bond", "quest", "click", "link", "work",
    "fit", "surf", "monster", "lol", "live", "shop", "autos",
}

# Brand name -> the domains that brand legitimately uses. A brand name in a
# hostname that is not one of these is impersonation.
BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "netflix": {"netflix.com", "nflximg.net"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com",
                  "office.com", "office365.com", "msn.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonaws.com", "primevideo.com"},
    "primevideo": {"primevideo.com", "amazon.com"},
    "google": {"google.com", "gmail.com", "googleapis.com", "youtube.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "chase": {"chase.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "santander": {"santander.co.uk", "santander.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "adobe": {"adobe.com"},
    "outlook": {"outlook.com", "live.com", "microsoft.com"},
}


# Minimum score for a URL carrying a high-confidence indicator. Set just
# above the MEDIUM boundary so such a URL can never be reported as low risk
# purely because a weighted average diluted the signal.
ESCALATION_FLOOR = 45.0


def escalating_signal(features):
    """Indicators specific enough to raise the verdict on their own.

    Brand *substring* matching was deliberately excluded after measurement:
    on a 500-URL evaluation it cost 7 points of precision (92.8% -> 85.5%)
    to gain 2 points of recall, because brands own many domains that contain
    their own name (googletagmanager.com, amazon-adsystem.com).
    """
    brand = features.get("brand_signal")

    if brand:
        return brand["detail"]

    if features.get("punycode"):
        return "the hostname uses punycode, which can disguise look-alike characters."

    return None


def edit_distance(left, right):
    """Levenshtein distance, iterative two-row version (no dependencies)."""
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (left_char != right_char),
            ))
        previous = current
    return previous[-1]


def registrable_domain(host):
    """Best-effort "example.co.uk" / "example.com" from a hostname.

    Not a public-suffix-list implementation - it treats a two-letter final
    label preceded by a short label (co.uk, com.au) as a compound suffix,
    which covers the common cases well enough for a scoring signal.
    """
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host

    if (
        len(labels) >= 3
        and len(labels[-1]) == 2
        and len(labels[-2]) <= 3
    ):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def brand_signals(host):
    """Detect brand impersonation and typosquatting in a hostname."""
    host = host.lower()
    domain = registrable_domain(host)
    labels = [label for label in host.split(".") if label]
    name = domain.split(".")[0]

    for brand, official in BRAND_DOMAINS.items():
        if domain in official:
            return None

        # The brand appears as a whole subdomain label while the registrable
        # domain belongs to someone else - the paypal.com.evil.tk pattern.
        #
        # Substring matching was tried and rejected: it flagged 20 legitimate
        # brand-owned domains (googletagmanager.com, whatsapp.net,
        # apple-dns.net, amazon-adsystem.com) because brands own far more
        # domains than any hand-maintained list can track. Measured effect was
        # precision 92.8% -> 85.5%, so only the exact-label form is kept.
        subdomain_labels = labels[:-len(domain.split("."))] if len(labels) > 1 else []
        if brand in subdomain_labels:
            return {
                "kind": "impersonation",
                "brand": brand,
                "detail": f"'{brand}' appears as a subdomain of {domain}, which is not an official {brand} domain.",
            }

        # A near-miss spelling of the brand: paypa1, prlmevldeo, arnazon.
        threshold = 2 if len(brand) >= 8 else 1
        if len(name) >= 4 and 0 < edit_distance(name, brand) <= threshold:
            return {
                "kind": "typosquat",
                "brand": brand,
                "detail": f"Domain name '{name}' is a near-miss spelling of '{brand}'.",
            }

    return None

# The training dataset's legitimate class is 100% bare root domains: no
# path, no query string, ever (0% contain "/", "?", "=" or "@" beyond the
# scheme). Any feature that can only be nonzero when a path/query is
# present has zero legitimate counterexamples to learn from, so the model
# treats it as "phishing" with near-certainty. That ruled out
# path_length, slash_count, url_length (reconstructable from
# url_length - host_length) and, for the same reason, at_count,
# question_count and equal_count. Those last three are still handled
# correctly by the hand-written rule engine in rule_score(), which isn't
# learned from this dataset and so isn't subject to the same bias.
# host_length, dot_count, hyphen_count, digit_count and suspicious_words
# vary naturally within both classes even when a path is present, and are
# safe to keep.
ML_FEATURE_COLUMNS = [
    "host_length", "dot_count", "hyphen_count",
    "digit_count", "has_ip", "https", "suspicious_words"
]

_model_cache = None
_model_mtime = None

def load_model():
    """Return the trained model, loading it at most once per file version.

    Keyed on the file's modification time so retraining is picked up without
    restarting the server, while a bulk evaluation run doesn't re-read 27MB
    from disk for every single URL.
    """
    global _model_cache, _model_mtime

    if not joblib or not os.path.exists(MODEL_PATH):
        return None

    mtime = os.path.getmtime(MODEL_PATH)
    if _model_cache is None or _model_mtime != mtime:
        _model_cache = joblib.load(MODEL_PATH)
        _model_mtime = mtime

    return _model_cache

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def make_features(url):
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()

    # Strip a leading "www." before counting anything, so the model can't
    # use "has www." as a shortcut for "is legitimate" (a bias found in
    # the training dataset, where ~100% of legitimate URLs had www. but
    # only ~41% of phishing URLs did).
    count_url = url
    if host.startswith("www."):
        host = host[4:]
        count_url = url.replace("www.", "", 1)

    try:
        ipaddress.ip_address(host.split(":")[0])
        has_ip = 1
    except ValueError:
        has_ip = 0

    suspicious_count = sum(word in url.lower() for word in SUSPICIOUS_WORDS)

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    brand = brand_signals(host)

    return {
        "tld": tld,
        "high_risk_tld": 1 if tld in HIGH_RISK_TLDS else 0,
        "punycode": 1 if "xn--" in host else 0,
        "brand_signal": brand,
        "url_length": len(count_url),
        "host_length": len(host),
        "path_length": len(path),
        "dot_count": count_url.count("."),
        "hyphen_count": count_url.count("-"),
        "at_count": count_url.count("@"),
        "question_count": count_url.count("?"),
        "equal_count": count_url.count("="),
        "slash_count": count_url.count("/"),
        "digit_count": sum(ch.isdigit() for ch in count_url),
        "has_ip": has_ip,
        "https": 1 if parsed.scheme == "https" else 0,
        "suspicious_words": suspicious_count,
    }

def rule_score(features):
    score = 0
    reasons = []

    if features["url_length"] > 75:
        score += 15
        reasons.append("URL is unusually long.")

    if features["at_count"] > 0:
        score += 20
        reasons.append("URL contains '@', which can be misleading.")

    if features["has_ip"]:
        score += 20
        reasons.append("Hostname appears to be an IP address.")

    if features["hyphen_count"] >= 3:
        score += 10
        reasons.append("URL contains several hyphens.")

    if features["suspicious_words"] >= 2:
        score += 15
        reasons.append("URL contains multiple security/account-related keywords.")

    if features["https"] == 0:
        score += 15
        reasons.append("URL is not using HTTPS.")

    if features.get("punycode"):
        score += 25
        reasons.append(
            "Hostname uses punycode, which can disguise look-alike characters."
        )

    if features.get("high_risk_tld"):
        score += 15
        reasons.append(
            f"Domain uses '.{features['tld']}', a top-level domain frequently abused for phishing."
        )

    brand = features.get("brand_signal")
    if brand:
        score += 30 if brand["kind"] == "typosquat" else 25
        reasons.append(brand["detail"])

    if score == 0:
        reasons.append("No strong suspicious URL pattern was found.")

    return min(score, 100), reasons

def analyze_url(url):
    normalized = normalize_url(url)
    features = make_features(normalized)
    score, reasons = rule_score(features)

    ml_score = 0.0

    # Optional ML model. The app still works without it.
    model = load_model()
    if model is not None:
        vector = pd.DataFrame([[features[c] for c in ML_FEATURE_COLUMNS]], columns=ML_FEATURE_COLUMNS)
        probability = model.predict_proba(vector)[0][1]
        ml_score = round(float(probability * 100), 2)

    return {
        "normalized_url": normalized,
        "features": features,
        "rule_score": score,
        "ml_score": ml_score,
        "reasons": reasons
    }
