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


def run_all_rules(normalized_entries):
    """
    Runs every detection rule against all log entries.
    Returns a list of alerts.
    """
    alerts = []
    rules = [detect_sudo_usage, detect_failed_auth]

    for entry in normalized_entries:
        for rule in rules:
            result = rule(entry)
            if result:
                alerts.append(result)

    return alerts
