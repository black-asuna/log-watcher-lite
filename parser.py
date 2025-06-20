import re
import csv

# File paths
LOG_FILE = "logs/sample_auth.log"
BLACKLIST_FILE = "blacklist.txt"
ALERTS_FILE = "alerts.csv"

# Load blacklisted IP addresses into a set for fast lookup
with open(BLACKLIST_FILE, "r") as f:
    blacklist = set(line.strip() for line in f.readlines())

alerts = []  # Store detected security events

# Open and read the log file line by line
with open(LOG_FILE, "r") as f:
    for line in f:
        # Detect failed login attempts
        if "Failed password" in line:
            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                alerts.append(("Failed Login", ip.group(1)))

        # Detect use of sudo (privilege escalation attempt)
        elif "sudo:" in line:
            alerts.append(("Privilege Escalation", "N/A"))

        # Detect log entries from blacklisted IP addresses
        elif any(ip in line for ip in blacklist):
            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                alerts.append(("Blacklisted IP Access", ip.group(1)))

# Write all detected alerts to a CSV file
with open(ALERTS_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Event Type", "Source IP"])  # Header row
    writer.writerows(alerts)  # Detected events

# Print confirmation
print(f"Detection complete. {len(alerts)} alert(s) written to {ALERTS_FILE}")
