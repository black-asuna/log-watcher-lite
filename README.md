# Log Watcher Lite 

**Log Watcher Lite** is a Python-based mini SOC tool that scans system authentication logs (`auth.log`) for signs of suspicious activity like failed logins, brute force attempts, and logins from blacklisted IP addresses.

This project simulates the early steps of log analysis, often performed in real-world Security Operations Centers (SOCs), and is built to reinforce key cybersecurity analyst skills.

---

##  Features
- Detects:
  -  Multiple failed SSH login attempts
  -  Logins from blacklisted IPs
  -  Privilege escalation via `sudo`
- Outputs alerts in a structured `.csv` file
- Clean and customizable Python code

---

##  Project Structure
|-----logs/

|  ----- sample_auth.log

|-----blacklist.txt

|-----parser.py

|-----alerts.csv (generated)

|-----README.md

---

##  How to Run
1. Clone the repository:
```bash
git clone https://github.com/black-asuna/log-watcher-lite.git
```

2. Run the script:
```bash
python parser.py
```

3. View alerts.csv for detection output.

---

##  Example Output
Event Type,Source IP

Failed Login,192.168.1.4

Failed Login,192.168.1.4

Failed Login,192.168.1.4

Blacklisted IP Access,45.67.89.123

Privilege Escalation,N/A

---

##  Learning Objectives
This project was created to demonstrate:

  -  Log parsing and pattern detection
  -  API-free cybersecurity scripting
  -  Realistic simulation of SOC alerting logic
  -  Command line automation and output handling

---

##  Author

Soeli Llinas Rosa
Aspiring Cybersecurity Analyst | Python & Threat Intelligence Enthusiast
 Gurabo, PR | 🌐 [LinkedIn](https://www.linkedin.com/in/sllinasrosa/)
 
##  Future Improvements

  -  Detect brute-force attempts by IP over time
  -  Flag privilege escalation from unusual accounts
  -  Extend support for real-time log monitoring

##  License

MIT License
