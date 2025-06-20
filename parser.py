import re
import csv
from collections import defaultdict

# File paths
LOG_FILE = "logs/sample_auth.log"
BLACKLIST_FILE = "blacklist.txt"
ALERTS_FILE = "alerts.csv"

# Load blacklisted IPs into a set
with open(BLACKLIST_FILE, "r") as f:
    blacklist = set(line.strip() for line in f.readlines())

alerts = []  # List to store alert events
failed_logins = defaultdict(int)  # Dictionary to track failed logins by IP

# Open and read the log file line by line
with open(LOG_FILE, "r") as f:
    for line in f:
        # Detect failed login attempts
        if "Failed password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                failed_logins[ip] += 1
                alerts.append(("Failed Login", ip))

        # Detect privilege escalation attempts using sudo
        elif "sudo:" in line:
            alerts.append(("Privilege Escalation", "N/A"))

        # Detect access from blacklisted IPs
        elif any(ip in line for ip in blacklist):
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                alerts.append(("Blacklisted IP Access", ip_match.group(1)))

# Add brute-force alerts once per IP after all logs are parsed
for ip, count in failed_logins.items():
    if count >= 3:
        alerts.append(("Brute Force Suspected", ip))

# Write alerts to a CSV file
with open(ALERTS_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Event Type", "Source IP"])  # CSV header
    writer.writerows(alerts)

# Print summary
print(f"Detection complete. {len(alerts)} alert(s) written to {ALERTS_FILE}")
