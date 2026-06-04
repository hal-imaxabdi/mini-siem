from collections import defaultdict


def detect_sudo_usage(entry):
    """
    Flags any sudo command execution.
    """
    if entry.get("type") == "USER_CMD":
        return {
            "alert": True,
            "rule": "Sudo command executed",
            "severity": "medium",
            "details": entry
        }
    return None


def detect_failed_auth(entry):
    """
    Flags any failed authentication attempt.
    """
    res = entry.get("res", "")
    event_type = entry.get("type", "")

    if "failed" in res.lower() and "USER" in event_type:
        return {
            "alert": True,
            "rule": "Failed authentication attempt",
            "severity": "high",
            "details": entry
        }
    return None


def detect_brute_force(normalized_entries):
    """
    Detects brute force by counting failed logins
    per uid within a 60 second window.
    Fires if 5 or more failures found.
    """
    alerts = []
    THRESHOLD = 5
    WINDOW = 60

    failures = defaultdict(list)

    for entry in normalized_entries:
        res = entry.get("res", "")
        event_type = entry.get("type", "")
        timestamp = entry.get("timestamp")

        if "failed" in res.lower() and "USER" in event_type and timestamp:
            uid = entry.get("uid", "unknown")
            failures[uid].append(timestamp)

    for uid, timestamps in failures.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window_events = [
                t for t in timestamps
                if timestamps[i] <= t <= timestamps[i] + WINDOW
            ]
            if len(window_events) >= THRESHOLD:
                alerts.append({
                    "alert": True,
                    "rule": "Brute force detected",
                    "severity": "critical",
                    "details": {
                        "uid": uid,
                        "failed_attempts": len(window_events),
                        "window_seconds": WINDOW,
                        "type": "BRUTE_FORCE",
                    }
                })
                break

    return alerts


def run_all_rules(normalized_entries):
    """
    Runs every detection rule against all log entries.
    Returns a list of alerts.
    """
    alerts = []

    # Single entry rules
    rules = [detect_sudo_usage, detect_failed_auth]
    for entry in normalized_entries:
        for rule in rules:
            result = rule(entry)
            if result:
                alerts.append(result)

    # Multi entry rules
    alerts.extend(detect_brute_force(normalized_entries))

    return alerts
