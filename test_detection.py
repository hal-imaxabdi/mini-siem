from collectors.linux_collector import collect_all_logs
from normalizer.normalizer import normalize_logs
from detection.rules import run_all_rules

raw_logs = collect_all_logs()
normalized = normalize_logs(raw_logs)
alerts = run_all_rules(normalized)

print(f"\n[+] Total alerts fired: {len(alerts)}")
print("\n--- First 5 alerts ---")
for alert in alerts[:5]:
    print(f"Rule: {alert['rule']}")
    print(f"Severity: {alert['severity']}")
    print(f"Type: {alert['details'].get('type')}")
    print(f"Exe: {alert['details'].get('exe')}")
    print()
