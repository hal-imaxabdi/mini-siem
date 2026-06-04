# Mini SIEM System

A custom-built Security Information and Event Management system 
for centralized threat detection, built from scratch in Python.

## What it does
Collects real logs from a Kali Linux machine, normalizes them,
runs detection rules, stores alerts in a database, and displays 
everything on a live web dashboard.

## Architecture
collectors/   → reads raw logs from /var/log/audit/audit.log
normalizer/   → parses raw lines into structured fields
detection/    → runs threat detection rules against normalized logs
alerting/     → saves fired alerts to SQLite database
dashboard/    → Flask web UI showing live alerts

## Detection Rules
- Sudo command execution (medium severity)
- Failed authentication attempts (high severity)

## Tech Stack
Python, SQLite, Flask

## How to run

### 1. Collect logs and populate database
sudo python3 test_alerter.py

### 2. Start the dashboard
sudo python3 -m dashboard.app

### 3. Open in browser
http://localhost:5000

## Results
- 9000+ real audit log lines ingested
- 22 alerts fired on first run
- 3 high severity, 19 medium severity

## Next Steps
- Add Windows Event Log collection
- Add brute force detection rule
- Integrate with Splunk
