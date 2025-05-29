#!/usr/bin/env python3
import sys, json, os, datetime
from pathlib import Path

# Ghi vào active-responses.log mặc định
LOG_FILE = Path(os.getenv('ProgramFiles(x86)', r'C:\Program Files (x86)')) \
           / 'ossec-agent' / 'active-response' / 'active-responses.log'

def log(msg):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now():%Y/%m/%d %H:%M:%S} {msg}\n")

def main():
    # 1) Đọc đúng một dòng JSON
    raw = sys.stdin.readline()
    try:
        data = json.loads(raw)
    except Exception as e:
        log(f"Invalid JSON: {e}")
        return

    log(f"Payload: {data}")

    # 2) Chỉ chạy khi action = add
    action = data.get("command")
    if action != "add":
        log(f"Non-add action '{action}', skipping")
        return

    # 3) Lấy file từ extra_args
    args = data.get("parameters", {}).get("extra_args", [])
    if not args:
        log("No target file in extra_args")
        return
    target = args[0]

    # 4) Xóa file
    if os.path.exists(target):
        try:
            os.remove(target)
            log(f"Deleted file: {target}")
        except Exception as e:
            log(f"Error deleting '{target}': {e}")
    else:
        log(f"File not found: {target}")

if __name__ == "__main__":
    main()
