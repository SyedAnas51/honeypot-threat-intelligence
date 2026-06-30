# 🍯 Sky Bait — Live SSH Honeypot & Threat Intelligence Pipeline

A fully operational SSH honeypot deployed on Oracle Cloud Infrastructure, capturing real-world attack data from internet-facing threat actors and visualizing it through a live Grafana Cloud dashboard.

Built as a personal cybersecurity project to demonstrate SOC operations, threat intelligence collection, log engineering, and cloud infrastructure skills.

---
## 📊 Live Stats (as of July 2026)
- **1,320+ unique attacker IPs** captured from the open internet
- **50+ countries** identified as attack sources
- **Continuous monitoring** since June 16, 2026
- **Top targeted usernames:** sysadmin, ubuntu, root, admin
- **Notable:** Detected active botnet campaign targeting "sysadmin" with 28,000+ attempts
- Pipeline runs **24/7 autonomously** with zero manual intervention
---

## 🏗️ Architecture
Internet Attackers
↓
Cowrie SSH Honeypot (port 22)
Oracle Cloud VM — Ubuntu 22.04
↓
cowrie.json log file
↓
Python Enricher Script
(ip-api.com geolocation)
↓
Grafana Cloud Loki
↓
Live Grafana Dashboard
peacefulwalrus3385.grafana.net


---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Honeypot | Cowrie SSH Honeypot |
| Cloud Infrastructure | Oracle Cloud Free Tier (E2.1.Micro) |
| OS | Ubuntu 22.04 |
| Log Enrichment | Python 3, ip-api.com |
| Log Storage | Grafana Cloud Loki |
| Dashboard | Grafana Cloud |
| Process Management | systemd |

---

## 📈 Dashboard Panels

1. **Attacks Over Time** — Time series of attack frequency
2. **Top Attacking Countries** — Bar chart of attack origins by country code
3. **Top Attacked Usernames** — Most commonly targeted SSH usernames
4. **Event Type Breakdown** — Pie chart of login success vs failure vs connections
5. **Total Unique Attackers** — Running count of distinct attacker IPs
6. **Recent Attack Activity** — Live log feed with IP, credentials, and country

---

## ⚙️ How It Works

1. **Cowrie** listens on port 22 — real SSH moved to port 2223
2. Every attacker connection, login attempt, and credential tried is logged to `cowrie.json`
3. A **Python enricher script** runs as a systemd service, reading new log entries every 60 seconds
4. Each unique attacker IP is geolocated via ip-api.com (country, ISP)
5. Enriched events are pushed to **Grafana Cloud Loki** via HTTP API
6. **Grafana dashboard** queries Loki in real time to visualize attack patterns
7. Script auto-detects Cowrie log rotation and self-heals — no manual intervention needed

---

## 🚀 Setup & Deployment

### Prerequisites
- Oracle Cloud (or any Linux VPS) running Ubuntu 22.04
- Grafana Cloud free account (grafana.com)
- Python 3.8+

### 1. Install Cowrie
```bash
sudo adduser --disabled-password cowrie
sudo su - cowrie
git clone https://github.com/cowrie/cowrie
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -e .
cp src/cowrie/data/etc/cowrie.cfg.dist etc/cowrie.cfg
cowrie start
```

### 2. Redirect port 22 to Cowrie
```bash
# Move real SSH to port 2223 first
sudo nano /etc/ssh/sshd_config  # Set Port 2223
sudo systemctl restart sshd

# Redirect port 22 to Cowrie's 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

### 3. Clone this repo and configure
```bash
git clone https://github.com/SyedAnas51/honeypot-threat-intelligence.git
cd honeypot-threat-intelligence
pip3 install -r requirements.txt

# Set up your credentials
cp .env.example .env
nano .env  # Fill in your Grafana Cloud Loki details
```

### 4. Run as a systemd service
```bash
sudo nano /etc/systemd/system/honeypot-enricher.service
```

```ini
[Unit]
Description=Honeypot Log Enricher
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/path/to/honeypot-threat-intelligence
EnvironmentFile=/path/to/honeypot-threat-intelligence/.env
ExecStart=/usr/bin/python3 -u enricher.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable honeypot-enricher
sudo systemctl start honeypot-enricher
```

---

## 🔐 Security Notes

- Real SSH is on port 2223 — attackers only interact with Cowrie's fake shell
- Cowrie is a **low-interaction honeypot** — attackers cannot access the real system
- All secrets stored in `.env` file, never committed to version control
- VM firewall (UFW) configured to allow only necessary ports

---

## 📁 Repository Structure
honeypot-threat-intelligence/
├── enricher.py          # Main log enricher and Loki pusher
├── requirements.txt     # Python dependencies
├── .env.example         # Environment variable template
├── .gitignore           # Excludes secrets and cache files
└── README.md            # This file
---

## 🔑 Environment Variables

Copy `.env.example` to `.env` and fill in your values:
LOKI_URL=https://logs-prod-XXX.grafana.net/loki/api/v1/push
LOKI_USER=your_loki_user_id
LOKI_TOKEN=your_grafana_api_token
---

## 👤 Author

**Syed Muhammad Anas**
Final-year CS student at FAST NUCES Karachi
Cybersecurity | SOC Operations | Penetration Testing

[![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%204%25-red)](https://tryhackme.com/p/syedmohammadanas)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/syed-muhammad-anas)
[![GitHub](https://img.shields.io/badge/GitHub-SyedAnas51-black)](https://github.com/SyedAnas51)

