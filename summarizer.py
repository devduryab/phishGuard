import re

import requests

OLLAMA_URL = "http://127.0.0.1:11434"
MODEL = "llama3.2:3b"
GENERATE_TIMEOUT = 60

SYSTEM_RULES = (
    "You explain phishing scan results to someone with no technical "
    "background.\n\n"
    "What the score means: a higher score means the web address itself looks "
    "like a phishing link - an address designed to impersonate a real site and "
    "trick people into giving away passwords or payment details. A high score "
    "does NOT mean the site has security vulnerabilities, and it does NOT mean "
    "the site has been hacked.\n\n"
    "Rules you must follow:\n"
    "1. Use ONLY the scan data provided. Never add outside knowledge about the "
    "website, its owner, or its reputation.\n"
    "2. Never claim certainty. Say a link 'looks like' or 'shows signs of' "
    "phishing. Never state that it definitely is a phishing site.\n"
    "3. Do not invent findings, scores or technical details.\n"
    "4. Write at most 3 sentences and stay under 60 words in total.\n"
    "5. Write plain prose only: no bullet points, headings, markdown or "
    "line breaks.\n"
    "6. Talk about 'this link' or 'this address'. Never write phrases like "
    "'the scan data shows' or 'the results indicate'.\n"
    "7. Finish with one short, natural instruction to the reader that matches "
    "the SUGGESTED ADVICE given below. Write it in your own words - do not "
    "copy the advice text literally.\n"
    "8. The verdict is already decided for you and is given below. Describe it "
    "using exactly that wording. Never upgrade or downgrade it, and never "
    "describe a low-risk link as moderate, medium or high risk.\n"
    "9. If the verdict is low risk, do not suggest the link might be phishing "
    "and do not describe it as having red flags. Say plainly that nothing in "
    "the address stood out as suspicious."
)

VERDICT_WORDING = {
    "LOW": "low risk (nothing in this address strongly suggests phishing)",
    "MEDIUM": "medium risk (some warning signs are present)",
    "HIGH": "high risk (several strong warning signs are present)",
}

# The closing advice has to match the verdict: warning a reader off a low-risk
# link is as unhelpful as being casual about a high-risk one.
ADVICE_HINT = {
    "LOW": (
        "nothing specific is required here, so suggest only the normal care "
        "anyone should take before entering personal details online"
    ),
    "MEDIUM": (
        "suggest checking the address carefully and not entering login or "
        "payment details unless they are certain the site is genuine"
    ),
    "HIGH": (
        "tell them to avoid this link entirely and not to enter any details "
        "or download anything from it"
    ),
}

# Words that would contradict the deterministic verdict. A small local model
# sometimes misreads the numeric score, and a summary that disagrees with the
# score shown beside it is worse than no summary at all.
CONTRADICTIONS = {
    # For LOW the model also tends to hedge towards "might be phishing", which
    # reads as a warning next to a 3/100 score. These phrases are only ever
    # wrong for a low-risk verdict; a correct one says "does not appear to be
    # a phishing site", which matches none of them.
    "LOW": ("high risk", "medium risk", "moderate risk", "high score",
            "highly suspicious", "trying to trick", "red flag"),
    "MEDIUM": ("low risk", "high risk"),
    "HIGH": ("low risk", "medium risk", "moderate risk", "safe to use"),
}

NEGATION = re.compile(r"\b(?:no|not|n't|nothing|never|none|nor)\b", re.IGNORECASE)
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def asserts_phishing(text):
    """True if any sentence claims the link is phishing without negating it.

    Listing banned phrases turned into whack-a-mole - the model produced
    "might be phishing", then "could be phishing", then "looks like it could
    be phishing". Instead, for each mention of "phish" we look at the words
    before it in that sentence: a negation there ("nothing suggests phishing",
    "does not appear to be a phishing site") makes it a valid low-risk
    statement, and its absence makes it an assertion.
    """
    for sentence in SENTENCE_SPLIT.split(text):
        for match in re.finditer(r"phish", sentence, re.IGNORECASE):
            if not NEGATION.search(sentence[: match.start()]):
                return True
    return False


def contradicts_verdict(text, level):
    lowered = text.lower()

    if any(phrase in lowered for phrase in CONTRADICTIONS[level]):
        return True

    return level == "LOW" and asserts_phishing(text)


def _describe(scan):
    reasons = "\n".join(f"- {reason}" for reason in scan["reasons"]) or "- none"
    findings = (
        "\n".join(
            f"- [{finding['severity']}] {finding['title']}: {finding['detail']}"
            for finding in scan["findings"]
        )
        or "- none"
    )

    # Numeric scores are deliberately withheld. llama3.2:3b repeatedly misread
    # "3.79 out of 100" as a high score and concluded a clean site was
    # phishing. The verdict is supplied in words instead, and the numbers are
    # already shown beside the summary in the interface.
    return (
        f"URL analysed: {scan['url']}\n"
        f"VERDICT (describe it exactly this way): "
        f"{VERDICT_WORDING[scan['level']]}\n"
        f"URL patterns matched by the rule engine:\n{reasons}\n"
        f"Security findings from the live response:\n{findings}\n"
        f"SUGGESTED ADVICE for your closing sentence: {ADVICE_HINT[scan['level']]}"
    )


def build_prompt(scan):
    return (
        f"{SYSTEM_RULES}\n\n"
        "Scan data:\n"
        f"{_describe(scan)}\n\n"
        "Write the summary now."
    )


def fallback_summary(scan):
    level = scan["level"]
    reasons = [r for r in scan["reasons"] if not r.startswith("No strong suspicious")]

    if reasons:
        joined = " ".join(reasons)
        opening = f"This address scored {scan['score']} out of 100. {joined}"
    else:
        opening = (
            f"This address scored {scan['score']} out of 100 and no suspicious "
            "patterns were found in the URL itself."
        )

    missing_headers = [
        finding for finding in scan["findings"] if "Missing header" in finding["title"]
    ]
    serious = [
        finding
        for finding in scan["findings"]
        if finding["severity"] in {"MEDIUM", "HIGH"}
    ]

    sentences = []
    if serious:
        sentences.append(f" The live check also flagged: {serious[0]['title'].lower()}.")
    if missing_headers:
        count = len(missing_headers)
        sentences.append(
            f" {count} common security header{'s were' if count != 1 else ' was'} missing."
        )

    middle = "".join(sentences)

    advice = {
        "LOW": (
            " Nothing strongly indicates phishing, but treat any request for "
            "passwords or payment details with normal caution."
        ),
        "MEDIUM": (
            " Treat this address with caution and avoid entering personal or "
            "login details unless you are certain it is genuine."
        ),
        "HIGH": (
            " Avoid this address. Do not enter login, payment or personal "
            "details, and do not download anything from it."
        ),
    }[level]

    return opening + middle + advice


def ollama_available():
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        response.raise_for_status()
        models = [model.get("name", "") for model in response.json().get("models", [])]
        return {
            "available": True,
            "model_ready": any(name.startswith(MODEL.split(":")[0]) for name in models),
            "models": models,
        }
    except requests.exceptions.RequestException:
        return {"available": False, "model_ready": False, "models": []}


def summarize(scan):
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": MODEL,
                "prompt": build_prompt(scan),
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": 150},
            },
            timeout=GENERATE_TIMEOUT,
        )
        response.raise_for_status()
        # The model occasionally emits line breaks despite being asked not to;
        # collapse them so the card always renders as one clean paragraph.
        text = " ".join((response.json().get("response") or "").split())

        if not text:
            return {
                "summary": fallback_summary(scan),
                "source": "fallback",
                "reason": "The model returned an empty response.",
            }

        if contradicts_verdict(text, scan["level"]):
            return {
                "summary": fallback_summary(scan),
                "source": "fallback",
                "reason": "The model's wording contradicted the calculated verdict.",
            }

        return {"summary": text, "source": "llm", "model": MODEL}

    except requests.exceptions.RequestException as exc:
        return {
            "summary": fallback_summary(scan),
            "source": "fallback",
            "reason": f"{type(exc).__name__}: local model unavailable.",
        }
