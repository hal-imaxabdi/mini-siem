from flask import Flask, render_template_string
import sqlite3
from config import DB_PATH

app = Flask(__name__)


def get_alerts_from_db():
    """
    Reads all alerts from the database.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_stats(alerts):
    """
    Calculates summary statistics from alerts.
    """
    total = len(alerts)
    high = sum(1 for a in alerts if a[2] == "high")
    medium = sum(1 for a in alerts if a[2] == "medium")
    low = sum(1 for a in alerts if a[2] == "low")
    return {"total": total, "high": high, "medium": medium, "low": low}


@app.route("/")
def index():
    alerts = get_alerts_from_db()
    stats = get_stats(alerts)
    return render_template_string(TEMPLATE, alerts=alerts, stats=stats)


TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Mini SIEM Dashboard</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { font-family: monospace; background: #0d0d0d; color: #00ff00; padding: 20px; }
        h1 { color: #00ff00; }
        .stats { display: flex; gap: 20px; margin-bottom: 30px; }
        .stat-box { background: #1a1a1a; border: 1px solid #00ff00; padding: 15px 25px; border-radius: 5px; }
        .stat-box h2 { margin: 0; font-size: 2em; }
        .stat-box p { margin: 0; color: #888; }
        .high { color: #ff4444; }
        .medium { color: #ffaa00; }
        .low { color: #00ff00; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #1a1a1a; padding: 10px; text-align: left; border-bottom: 1px solid #00ff00; }
        td { padding: 8px 10px; border-bottom: 1px solid #1a1a1a; font-size: 0.85em; }
        tr:hover { background: #1a1a1a; }
    </style>
</head>
<body>
    <h1>Mini SIEM Dashboard</h1>
    <p>Auto refreshes every 30 seconds</p>

    <div class="stats">
        <div class="stat-box">
            <h2>{{ stats.total }}</h2>
            <p>Total Alerts</p>
        </div>
        <div class="stat-box">
            <h2 class="high">{{ stats.high }}</h2>
            <p>High</p>
        </div>
        <div class="stat-box">
            <h2 class="medium">{{ stats.medium }}</h2>
            <p>Medium</p>
        </div>
        <div class="stat-box">
            <h2 class="low">{{ stats.low }}</h2>
            <p>Low</p>
        </div>
    </div>

    <table>
        <tr>
            <th>#</th>
            <th>Rule</th>
            <th>Severity</th>
            <th>Type</th>
            <th>Exe</th>
            <th>UID</th>
            <th>Timestamp</th>
        </tr>
        {% for alert in alerts %}
        <tr>
            <td>{{ alert[0] }}</td>
            <td>{{ alert[1] }}</td>
            <td class="{{ alert[2] }}">{{ alert[2] }}</td>
            <td>{{ alert[3] }}</td>
            <td>{{ alert[4] }}</td>
            <td>{{ alert[5] }}</td>
            <td>{{ alert[7] }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
