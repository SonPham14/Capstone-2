#!/usr/bin/env python3
import time
import json
import requests
import os

ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"
ML_WEBATTACK_URL = "http://192.168.88.1:8000/detect-webattack"
REQUIRED_GROUPS = {"web", "accesslog", "attack"}

def follow(filepath):
    """Generator that yields new lines as they're added to the file."""
    with open(filepath, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line

def process_alert(alert):
    """Gửi nguyên bản alert tới ML API"""
    try:
        print("Alert: ", alert)
        headers = {"Content-Type": "application/json"}
        resp = requests.post(ML_WEBATTACK_URL, json=alert, headers=headers)
        print(f"[WebAttack] Alert sent: {resp.status_code}")
    except Exception as e:
        print(f"[Error] Failed to send alert: {str(e)}")

def main():
    print(f"[*] Monitoring {ALERT_FILE} for alerts")
    for line in follow(ALERT_FILE):
        line = line.strip()
        if not line:
            continue

        try:
            alert = json.loads(line)
            rule_section = alert.get('rule', {})
            print("rule_section: ", rule_section)
            alert_groups = set(rule_section.get('groups', []))  # Đọc groups từ phần rule

            # Kiểm tra groups
            if REQUIRED_GROUPS.issubset(alert_groups):
                print(f"[Debug] Processing alert with groups: {alert_groups}")
                process_alert(alert)
            else:
                print(f"[Debug] Skipping alert - Missing required groups. Alert groups: {alert_groups}")

        except json.JSONDecodeError:
            print("[Error] Failed to parse alert JSON")
        except KeyError as e:
            print(f"[Error] Missing key in alert data: {str(e)}")
        except Exception as e:
            print(f"[Error] General error processing alert: {str(e)}")

if __name__ == "__main__":
    main()
