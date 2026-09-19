import sys
import os
import sqlite3
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database


def test_init_db_creates_scans_table(tmp_path, monkeypatch):
    db_file = tmp_path / "test_scans.db"
    monkeypatch.setattr(database, "DB_NAME", str(db_file))

    database.init_db()

    con = sqlite3.connect(str(db_file))
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
    assert cur.fetchone() is not None
    con.close()


def test_save_scan_persists_all_fields(tmp_path, monkeypatch):
    db_file = tmp_path / "test_scans.db"
    monkeypatch.setattr(database, "DB_NAME", str(db_file))
    database.init_db()

    result = {
        "url": "https://example.com/login",
        "level": "MEDIUM",
        "score": 45.0,
        "rule_score": 35,
        "ml_score": 10.5,
        "security_score": 20,
        "reasons": ["URL is not using HTTPS."],
        "findings": [{"severity": "LOW", "title": "Missing header", "detail": "test"}],
    }
    database.save_scan(result)

    con = sqlite3.connect(str(db_file))
    cur = con.cursor()
    cur.execute("SELECT url, risk_level, final_score, reasons, findings FROM scans")
    row = cur.fetchone()
    con.close()

    assert row[0] == "https://example.com/login"
    assert row[1] == "MEDIUM"
    assert row[2] == 45.0
    assert json.loads(row[3]) == ["URL is not using HTTPS."]
    assert json.loads(row[4])[0]["severity"] == "LOW"


def test_save_scan_appends_multiple_rows(tmp_path, monkeypatch):
    db_file = tmp_path / "test_scans.db"
    monkeypatch.setattr(database, "DB_NAME", str(db_file))
    database.init_db()

    base_result = {
        "url": "https://example.com",
        "level": "LOW",
        "score": 0.0,
        "rule_score": 0,
        "ml_score": 0.0,
        "security_score": 0,
        "reasons": [],
        "findings": [],
    }
    database.save_scan(base_result)
    database.save_scan(base_result)

    con = sqlite3.connect(str(db_file))
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM scans")
    count = cur.fetchone()[0]
    con.close()

    assert count == 2


def test_get_all_scans_empty(tmp_path, monkeypatch):
    db_file = tmp_path / "test_scans.db"
    monkeypatch.setattr(database, "DB_NAME", str(db_file))
    database.init_db()

    assert database.get_all_scans() == []


def test_get_all_scans_returns_newest_first(tmp_path, monkeypatch):
    db_file = tmp_path / "test_scans.db"
    monkeypatch.setattr(database, "DB_NAME", str(db_file))
    database.init_db()

    first = {
        "url": "https://first.example.com", "level": "LOW", "score": 1.0,
        "rule_score": 0, "ml_score": 0.0, "security_score": 0,
        "reasons": [], "findings": [],
    }
    second = {
        "url": "https://second.example.com", "level": "HIGH", "score": 90.0,
        "rule_score": 90, "ml_score": 90.0, "security_score": 90,
        "reasons": ["reason a"], "findings": [{"severity": "HIGH", "title": "t", "detail": "d"}],
    }
    database.save_scan(first)
    database.save_scan(second)

    scans = database.get_all_scans()
    assert len(scans) == 2
    assert scans[0]["url"] == "https://second.example.com"
    assert scans[1]["url"] == "https://first.example.com"
    assert scans[0]["reasons"] == ["reason a"]
    assert scans[0]["findings"][0]["title"] == "t"
