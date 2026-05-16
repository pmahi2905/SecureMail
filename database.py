import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("securemail.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            subject TEXT,
            score INTEGER,
            risk_level TEXT,
            scanned_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_scan(sender, subject, score, risk_level):
    init_db()

    conn = sqlite3.connect("securemail.db")
    conn.execute(
        "INSERT INTO scans (sender, subject, score, risk_level, scanned_at) VALUES (?, ?, ?, ?, ?)",
        (sender, subject, score, risk_level, datetime.now().strftime("%Y-%m-%d %H:%M"))
    )
    conn.commit()
    conn.close()

def get_history():
    init_db()

    conn = sqlite3.connect("securemail.db")
    rows = conn.execute(
        "SELECT sender, subject, score, risk_level, scanned_at FROM scans ORDER BY id DESC"
    ).fetchall()
    conn.close()

    return rows