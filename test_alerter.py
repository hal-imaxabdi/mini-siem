from collectors.linux_collector import collect_all_logs
from normalizer.normalizer import normalize_logs
from detection.rules import run_all_rules
from alerting.alerter import init_db, save_alerts, get_all_alerts

# Step 1 - collect
raw_logs = collect_all_logs()

# Step 2 - normalize
normalized = normalize_logs(raw_logs)

# Step 3 - detect
alerts = run_all_rules(normalized)
print(f"[+] Alerts fired: {len(alerts)}")

# Step 4 - save to database
init_db()
save_alerts(alerts)

# Step 5 - read back from database
rows = get_all_alerts()
print(f"\n[+] Alerts in database: {len(rows)}")
print("\n--- First 3 alerts from database ---")
for row in rows[:3]:
    print(row)
