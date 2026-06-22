import os
import json
import time
import requests
from datetime import datetime, timezone

# ====== CONFIG ======
from dotenv import load_dotenv
load_dotenv()

LOKI_URL = os.environ.get("LOKI_URL")
LOKI_USER = os.environ.get("LOKI_USER")
LOKI_TOKEN = os.environ.get("LOKI_TOKEN")

COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
STATE_FILE = "/home/ubuntu/honeypot-enricher/last_position.txt"
SEEN_IPS_FILE = "/home/ubuntu/honeypot-enricher/seen_ips.json"

def load_seen_ips():
    if os.path.exists(SEEN_IPS_FILE):
        with open(SEEN_IPS_FILE) as f:
            return json.load(f)
    return {}

def save_seen_ips(seen):
    with open(SEEN_IPS_FILE, "w") as f:
        json.dump(seen, f)

def check_ip(ip, seen_ips):
    if ip in seen_ips:
        return seen_ips[ip]
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,countryCode,isp,org"},
            timeout=5
        )
        d = r.json()
        result = {
            "country": d.get("countryCode", "XX") if d.get("status") == "success" else "XX",
            "isp": d.get("isp", "Unknown")
        }
    except Exception:
        result = {"country": "XX", "isp": "Unknown"}
    seen_ips[ip] = result
    save_seen_ips(seen_ips)
    time.sleep(1.5)  # ip-api free tier: max 45 requests/minute
    return result

def get_last_position():
    current_size = os.path.getsize(COWRIE_LOG)
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            saved_pos = int(f.read().strip())
        if saved_pos > current_size:
            print(f"Log rotation detected! Resetting position from {saved_pos} to 0")
            return 0
        return saved_pos
    return 0


def save_position(pos):
    with open(STATE_FILE, "w") as f:
        f.write(str(pos))

def push_to_loki(entries):
    if not entries:
        return
    streams = {}
    for entry in entries:
        labels = entry["labels"]
        key = json.dumps(labels, sort_keys=True)
        if key not in streams:
            streams[key] = {"stream": labels, "values": []}
        streams[key]["values"].append([entry["ts"], entry["line"]])

    payload = {"streams": list(streams.values())}

    resp = requests.post(
        LOKI_URL,
        json=payload,
        auth=(LOKI_USER, LOKI_TOKEN),
        headers={"Content-Type": "application/json"},
        timeout=10
    )
    if resp.status_code not in (200, 204):
        print(f"Loki push failed: {resp.status_code} {resp.text}")
    else:
        print(f"Pushed {len(entries)} log entries to Loki")

def process_new_lines():
    seen_ips = load_seen_ips()
    last_pos = get_last_position()
    entries = []

    with open(COWRIE_LOG) as f:
        f.seek(last_pos)
        lines = f.readlines()
        new_pos = f.tell()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        etype = event.get("eventid", "")
        if etype not in (
            "cowrie.login.failed", "cowrie.login.success",
            "cowrie.session.connect", "cowrie.session.closed"
        ):
            continue

        ip = event.get("src_ip", "0.0.0.0")
        enrich = check_ip(ip, seen_ips)

        labels = {
            "job": "honeypot",
            "event_type": etype,
            "country": enrich["country"]
        }

        log_line = json.dumps({
            "src_ip": ip,
            "username": event.get("username", ""),
            "password": event.get("password", ""),
            "event_type": etype,
            "isp": enrich["isp"],
            "country": enrich["country"],
            "message": event.get("message", "")
        })

        ts_ns = str(int(time.time() * 1e9))
        entries.append({"labels": labels, "line": log_line, "ts": ts_ns})

    push_to_loki(entries)
    save_position(new_pos)
    print(f"Processed {len(entries)} new events at {datetime.now(timezone.utc)}")

if __name__ == "__main__":
    while True:
        try:
            process_new_lines()
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(60)
