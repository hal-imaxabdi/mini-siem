import os
import time


# Log files we want to read on Kali
LOG_SOURCES = {
    "audit": "/var/log/audit/audit.log",
}


def read_log_file(filepath):
    """
    Reads all lines from a log file.
    Returns a list of raw entries.
    """
    entries = []

    if not os.path.exists(filepath):
        print(f"[WARNING] File not found: {filepath}")
        return entries

    try:
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append({
                        "source": filepath,
                        "raw": line,
                        "collected_at": time.time()
                    })

    except PermissionError:
        print(f"[ERROR] Permission denied: {filepath}")
        print("[TIP] Run with sudo")

    return entries


def collect_all_logs():
    """
    Collects logs from all sources.
    """
    all_entries = []

    for name, path in LOG_SOURCES.items():
        print(f"[*] Collecting from {name}: {path}")
        entries = read_log_file(path)
        print(f"    -> {len(entries)} lines collected")
        all_entries.extend(entries)

    print(f"\n[+] Total entries collected: {len(all_entries)}")
    return all_entries


if __name__ == "__main__":
    logs = collect_all_logs()

    print("\n--- Sample (first 3 entries) ---")
    for entry in logs[:3]:
        print(entry)
