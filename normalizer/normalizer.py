import re


def parse_audit_line(raw_line):
    """
    Takes a raw audit log line and extracts fields into a dictionary.
    """
    result = {}

    # Extract the type
    type_match = re.match(r'type=(\S+)', raw_line)
    if type_match:
        result["type"] = type_match.group(1)

    # Extract the timestamp from msg=audit(1234567890.123:456)
    time_match = re.search(r'audit\((\d+\.\d+):\d+\)', raw_line)
    if time_match:
        result["timestamp"] = float(time_match.group(1))

    # Extract uid
    uid_match = re.search(r'\buid=(\d+)', raw_line)
    if uid_match:
        result["uid"] = uid_match.group(1)

    # Extract exe
    exe_match = re.search(r'exe="([^"]+)"', raw_line)
    if exe_match:
        result["exe"] = exe_match.group(1)

    # Extract hostname
    host_match = re.search(r'hostname=(\S+)', raw_line)
    if host_match:
        result["hostname"] = host_match.group(1)

    # Extract res (result - success or failed)
    res_match = re.search(r'res=(\S+)', raw_line)
    if res_match:
        result["res"] = res_match.group(1).strip("'")

    # Keep the raw line too
    result["raw"] = raw_line

    return result


def normalize_logs(raw_entries):
    """
    Takes a list of raw log entries from the collector
    and returns normalized structured entries.
    """
    normalized = []

    for entry in raw_entries:
        parsed = parse_audit_line(entry["raw"])
        parsed["source"] = entry["source"]
        parsed["collected_at"] = entry["collected_at"]
        normalized.append(parsed)

    return normalized
