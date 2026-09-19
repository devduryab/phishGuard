"""Inspects the HTML of a fetched page for phishing indicators.

vulnerability.py already downloads the page in order to read its headers.
This module reads the body as well, which is where the strongest signals
live: a login form that submits to somebody else's domain is far more
telling than anything in the URL string.
"""

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from detector import BRAND_DOMAINS, registrable_domain

MAX_CONTENT = 500_000


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.form_actions = []
        self.has_password_field = False
        self.input_count = 0
        self.hidden_iframes = 0
        self.iframes = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag == "title":
            self._in_title = True

        elif tag == "form":
            self.form_actions.append(attributes.get("action") or "")

        elif tag == "input":
            self.input_count += 1
            if (attributes.get("type") or "").lower() == "password":
                self.has_password_field = True

        elif tag == "iframe":
            self.iframes += 1
            style = (attributes.get("style") or "").replace(" ", "").lower()
            if (
                "display:none" in style
                or "visibility:hidden" in style
                or attributes.get("hidden") is not None
                or attributes.get("width") in {"0", "1"}
                or attributes.get("height") in {"0", "1"}
            ):
                self.hidden_iframes += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def analyse_page(html, final_url):
    """Return (score, findings) from the page body of an already-fetched URL."""
    findings = []
    score = 0

    if not html:
        return score, findings

    parser = PageParser()
    try:
        parser.feed(html[:MAX_CONTENT])
    except Exception:
        # Malformed markup is common on phishing pages; whatever was parsed
        # before the error is still usable.
        pass

    page_domain = registrable_domain(urlparse(final_url).netloc.lower())

    if parser.has_password_field:
        findings.append({
            "severity": "INFO",
            "title": "Page contains a password field",
            "detail": "The page asks for a password. This is normal for a genuine sign-in page.",
        })

        if not final_url.lower().startswith("https://"):
            score += 30
            findings.append({
                "severity": "HIGH",
                "title": "Password field on an unencrypted page",
                "detail": "Credentials entered here would be sent without encryption.",
            })

    external_targets = set()
    for action in parser.form_actions:
        if not action:
            continue
        target = urlparse(urljoin(final_url, action)).netloc.lower()
        if not target:
            continue
        target_domain = registrable_domain(target)
        if target_domain and target_domain != page_domain:
            external_targets.add(target_domain)

    if external_targets and parser.has_password_field:
        score += 35
        findings.append({
            "severity": "HIGH",
            "title": "Login form submits to a different domain",
            "detail": f"A form containing a password field posts to {', '.join(sorted(external_targets))}, not {page_domain}.",
        })
    elif external_targets:
        score += 10
        findings.append({
            "severity": "LOW",
            "title": "Form submits to a different domain",
            "detail": f"A form posts to {', '.join(sorted(external_targets))} rather than {page_domain}.",
        })

    # Only meaningful alongside a password field. A page that merely mentions
    # a brand is usually an article about it - "PayPal - Wikipedia" is not
    # impersonation, whereas a login page claiming to be PayPal on another
    # domain is.
    title = " ".join(parser.title.split())
    if title and parser.has_password_field:
        mismatched = [
            brand
            for brand, official in BRAND_DOMAINS.items()
            if brand in title.lower() and page_domain not in official
        ]
        if mismatched:
            score += 25
            findings.append({
                "severity": "HIGH",
                "title": "Sign-in page names a brand that does not match the domain",
                "detail": f"The page asks for a password and its title mentions '{mismatched[0]}', but it is served from {page_domain}.",
            })

    if parser.hidden_iframes:
        score += 15
        findings.append({
            "severity": "MEDIUM",
            "title": "Hidden iframe detected",
            "detail": f"{parser.hidden_iframes} iframe(s) are hidden from view, a technique used to disguise content.",
        })

    return score, findings
