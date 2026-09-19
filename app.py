from flask import Flask, render_template, request, jsonify
from detector import ESCALATION_FLOOR, analyze_url, escalating_signal
from vulnerability import assess_url
from database import (
    init_db, save_scan, get_all_scans, get_scan,
    save_evaluation, get_evaluations, get_evaluation,
)
from summarizer import ollama_available, summarize
import evaluation as evaluation_module

app = Flask(__name__)
init_db()

# Rebalanced after the self-audit measured recall of 9.2% against a live
# phishing feed. The classifier separated the classes well (mean score 91 on
# phishing vs 21 on legitimate) but at 0.25 weight its signal could not reach
# the threshold on its own, while the rule engine only recognises older
# phishing patterns. See evaluation.py and the Self-Audit page.
RULE_WEIGHT = 0.35
ML_WEIGHT = 0.50
SECURITY_WEIGHT = 0.15


def run_scan(url):
    detection = analyze_url(url)
    assessment = assess_url(detection["normalized_url"])

    final_score = round(
        detection["rule_score"] * RULE_WEIGHT +
        detection["ml_score"] * ML_WEIGHT +
        assessment["security_score"] * SECURITY_WEIGHT,
        2
    )

    # A weighted average dilutes any single confident signal: a typosquatted
    # domain scores 30 on the rule engine, which is only 10.5 points once
    # weighted, so it could never raise an alert on its own. These indicators
    # are specific enough to warrant at least a medium verdict by themselves.
    escalation = escalating_signal(detection["features"])
    if escalation and final_score < ESCALATION_FLOOR:
        final_score = ESCALATION_FLOOR
        detection["reasons"] = detection["reasons"] + [
            f"Risk level raised: {escalation}"
        ]

    if final_score >= 70:
        level = "HIGH"
    elif final_score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    result = {
        "url": detection["normalized_url"],
        "level": level,
        "score": final_score,
        "rule_score": detection["rule_score"],
        "ml_score": detection["ml_score"],
        "security_score": assessment["security_score"],
        "reasons": detection["reasons"],
        "findings": assessment["findings"],
    }

    result["id"] = save_scan(result)
    return result

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if not url:
            error = "Please enter a website URL."
        else:
            try:
                result = run_scan(url)
            except Exception as exc:
                error = f"Analysis error: {type(exc).__name__}: {exc}"

    return render_template("index.html", result=result, error=error)

@app.route("/history")
def history():
    scans = get_all_scans()
    return render_template("history.html", scans=scans)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Please enter a website URL."}), 400

    try:
        return jsonify(run_scan(url))
    except Exception as exc:
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500

@app.route("/api/history")
def api_history():
    return jsonify(get_all_scans())

@app.route("/api/summarize", methods=["POST"])
def api_summarize():
    payload = request.get_json(silent=True) or {}
    scan_id = payload.get("scan_id")

    if not isinstance(scan_id, int):
        return jsonify({"error": "A numeric scan_id is required."}), 400

    scan = get_scan(scan_id)
    if scan is None:
        return jsonify({"error": f"No scan found with id {scan_id}."}), 404

    return jsonify(summarize({
        "url": scan["url"],
        "level": scan["risk_level"],
        "score": scan["final_score"],
        "rule_score": scan["rule_score"],
        "ml_score": scan["ml_score"],
        "security_score": scan["security_score"],
        "reasons": scan["reasons"],
        "findings": scan["findings"],
    }))

@app.route("/api/assessment/run", methods=["POST"])
def api_assessment_run():
    payload = request.get_json(silent=True) or {}
    threshold = float(payload.get("threshold", evaluation_module.DEFAULT_THRESHOLD))
    phishing_limit = int(payload.get("phishing_limit", 250))
    legit_limit = int(payload.get("legit_limit", 250))

    try:
        result = evaluation_module.evaluate(
            threshold=threshold,
            phishing_limit=phishing_limit,
            legit_limit=legit_limit,
        )
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 400

    result["id"] = save_evaluation(result, RULE_WEIGHT, ML_WEIGHT)
    result["current_weights"] = {"rule": RULE_WEIGHT, "ml": ML_WEIGHT,
                                 "security": SECURITY_WEIGHT}
    return jsonify(result)

@app.route("/api/assessment/runs")
def api_assessment_runs():
    return jsonify(get_evaluations())

@app.route("/api/assessment/runs/<int:evaluation_id>")
def api_assessment_run_detail(evaluation_id):
    record = get_evaluation(evaluation_id)
    if record is None:
        return jsonify({"error": f"No evaluation found with id {evaluation_id}."}), 404
    return jsonify(record)

@app.route("/api/assessment/dataset")
def api_assessment_dataset():
    return jsonify(evaluation_module.dataset_info())

@app.route("/api/ai-status")
def api_ai_status():
    return jsonify(ollama_available())

@app.route("/api/weights")
def api_weights():
    return jsonify({
        "rule": RULE_WEIGHT,
        "ml": ML_WEIGHT,
        "security": SECURITY_WEIGHT,
    })

if __name__ == "__main__":
    app.run(debug=True)
