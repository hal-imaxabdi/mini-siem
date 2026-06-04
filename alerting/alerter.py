import sqlite3
import time
from config import DB_PATH


def init_db():
    """
    Creates the alerts table if it doesn't exist.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule TEXT,
            severity TEXT,
            event_type TEXT,
            exe TEXT,
            uid TEXT,
            hostname TEXT,
            timestamp REAL,
            collected_at REAL,
            raw TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("[+] Database initialized")


def save_alerts(alerts):
    """
    Saves a list of alerts to the database.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    saved = 0
    for alert in alerts:
        details = alert["details"]
        cursor.execute('''
            INSERT INTO alerts 
            (rule, severity, event_type, exe, uid, hostname, timestamp, collected_at, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert["rule"],
            alert["severity"],
            details.get("type"),
            details.get("exe"),
            details.get("uid"),
            details.get("hostname"),
            details.get("timestamp"),
            details.get("collected_at"),
            details.get("raw")
        ))
        saved += 1

    conn.commit()
    conn.close()
    print(f"[+] Saved {saved} alerts to database")


def get_all_alerts():
    """
    Retrieves all alerts from the database.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC')
    rows = cursor.fetchall()

    conn.close()
    return rows
