import sqlite3
import json
import os

# DB_PATH lets a deployment point the database at a mounted volume. Without
# it the file sits next to the code, which on an ephemeral host means scan
# history resets on each redeploy.
DB_NAME = os.environ.get(
    "DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db"),
)

def init_db():
    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            final_score REAL NOT NULL,
            rule_score REAL NOT NULL,
            ml_score REAL NOT NULL,
            security_score REAL NOT NULL,
            reasons TEXT,
            findings TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS evaluations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threshold REAL NOT NULL,
            rule_weight REAL NOT NULL,
            ml_weight REAL NOT NULL,
            phishing_count INTEGER NOT NULL,
            legitimate_count INTEGER NOT NULL,
            tp INTEGER NOT NULL,
            fp INTEGER NOT NULL,
            tn INTEGER NOT NULL,
            fn INTEGER NOT NULL,
            precision_pct REAL NOT NULL,
            recall_pct REAL NOT NULL,
            f1_pct REAL NOT NULL,
            accuracy_pct REAL NOT NULL,
            payload TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    con.commit()
    con.close()

def save_evaluation(result, rule_weight, ml_weight):
    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()

    cur.execute("""
        INSERT INTO evaluations
        (threshold, rule_weight, ml_weight, phishing_count, legitimate_count,
         tp, fp, tn, fn, precision_pct, recall_pct, f1_pct, accuracy_pct, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result["threshold"],
        rule_weight,
        ml_weight,
        result["totals"]["phishing"],
        result["totals"]["legitimate"],
        result["counts"]["tp"],
        result["counts"]["fp"],
        result["counts"]["tn"],
        result["counts"]["fn"],
        result["metrics"]["precision"],
        result["metrics"]["recall"],
        result["metrics"]["f1"],
        result["metrics"]["accuracy"],
        json.dumps(result),
    ))

    evaluation_id = cur.lastrowid
    con.commit()
    con.close()
    return evaluation_id

def get_evaluations(limit=20):
    con = sqlite3.connect(DB_NAME)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute("""
        SELECT id, threshold, rule_weight, ml_weight, phishing_count,
               legitimate_count, tp, fp, tn, fn, precision_pct, recall_pct,
               f1_pct, accuracy_pct, created_at
        FROM evaluations
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cur.fetchall()]
    con.close()
    return rows

def get_evaluation(evaluation_id):
    con = sqlite3.connect(DB_NAME)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute("SELECT * FROM evaluations WHERE id = ?", (evaluation_id,))
    row = cur.fetchone()
    con.close()

    if row is None:
        return None

    record = dict(row)
    record["payload"] = json.loads(record["payload"])
    return record

def save_scan(result):
    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()

    cur.execute("""
        INSERT INTO scans
        (url, risk_level, final_score, rule_score, ml_score,
         security_score, reasons, findings)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result["url"],
        result["level"],
        result["score"],
        result["rule_score"],
        result["ml_score"],
        result["security_score"],
        json.dumps(result["reasons"]),
        json.dumps(result["findings"])
    ))

    scan_id = cur.lastrowid
    con.commit()
    con.close()
    return scan_id

def get_scan(scan_id):
    con = sqlite3.connect(DB_NAME)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute("""
        SELECT id, url, risk_level, final_score, rule_score, ml_score,
               security_score, reasons, findings, created_at
        FROM scans
        WHERE id = ?
    """, (scan_id,))
    row = cur.fetchone()
    con.close()

    if row is None:
        return None

    scan = dict(row)
    scan["reasons"] = json.loads(scan["reasons"]) if scan["reasons"] else []
    scan["findings"] = json.loads(scan["findings"]) if scan["findings"] else []
    return scan

def get_all_scans():
    con = sqlite3.connect(DB_NAME)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute("""
        SELECT id, url, risk_level, final_score, rule_score, ml_score,
               security_score, reasons, findings, created_at
        FROM scans
        ORDER BY id DESC
    """)
    rows = cur.fetchall()
    con.close()

    scans = []
    for row in rows:
        scan = dict(row)
        scan["reasons"] = json.loads(scan["reasons"]) if scan["reasons"] else []
        scan["findings"] = json.loads(scan["findings"]) if scan["findings"] else []
        scans.append(scan)

    return scans
