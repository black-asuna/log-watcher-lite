import re
import csv

LOG_FILE = "logs/sample_auth.log"
BLACKLIST_FILE = "blacklist.txt"
ALERTS_FILE = "alerts.csv"

# Load blacklisted IPs
with open(BLACKLIST_FILE, "r") as f:
    blacklist = set(line.strip() for line in f.readlines())

alerts = []

with open(LOG_FILE, "r") as f:
    for line in f:
        if "Failed password" in line:
            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                alerts.append(("Failed Login", ip.group(1)))
        elif "sudo:" in line:
            alerts.append(("Privilege Escalation", "N/A"))
        elif any(ip in line for ip in blacklist):
            ip = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip:
                alerts.append(("Blacklisted IP Access", ip.group(1)))

# Write alerts to CSV
with open(ALERTS_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Event Type", "Source IP"])
    writer.writerows(alerts)

print(f"Detection complete. {len(alerts)} alert(s) written to {ALERTS_FILE}")
