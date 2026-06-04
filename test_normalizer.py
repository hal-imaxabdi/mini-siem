from collectors.linux_collector import collect_all_logs
from normalizer.normalizer import normalize_logs

raw_logs = collect_all_logs()
normalized = normalize_logs(raw_logs)

print("\n--- Sample normalized entries ---")
for entry in normalized[:3]:
    print(entry)
    print()
