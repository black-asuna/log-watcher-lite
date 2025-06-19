# Log Watcher Lite

A Python-based security log parser that scans authentication logs for suspicious activity such as failed logins, brute force attempts, and known malicious IP access. This mini-project demonstrates log analysis fundamentals for SOC and cybersecurity analyst workflows.

##  Features
- Detects:
  - Repeated failed SSH login attempts
  - Logins from blacklisted IP addresses
  - Sudden privilege escalation (e.g., `sudo`)
- Outputs alerts to a CSV report
- Easy to customize with new log patterns

##  Requirements
- Python 3.x
- `logs/sample_auth.log` (provided)
- `blacklist.txt` with known bad IPs

##  How to Run
```bash
python parser.py
