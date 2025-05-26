#!/usr/bin/env python3
# delete_file.py – Active-response

import sys, json, pathlib, os, datetime

LOG = pathlib.Path(os.getenv('ProgramFiles(x86)', r'C:\Program Files')) \
      / 'ossec-agent' / 'active-response' / 'ar.log'

def log(msg):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.open("a").write(f"{datetime.datetime.now():%Y/%m/%d %H:%M:%S} {msg}\n")

def get_target(data):
    # 1) API → extra_args
    try:
        ea = data["parameters"]["extra_args"]
        if isinstance(ea, list) and ea:
            return ea[0]
    except Exception:
        pass
    # 2) API legacy → parameters.file
    return data.get("parameters", {}).get("file")

def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw or "{}")
    except Exception as e:
        log(f"Invalid JSON: {e}")
        sys.exit(1)

    if payload.get("command") != "add":
        log("Received non-add action, skipping")
        sys.exit(0)

    target = get_target(payload)
    if not target:
        log("No target file found in payload")
        sys.exit(1)

    p = pathlib.Path(target)
    if p.exists():
        try:
            os.chmod(p, 0o600)
            p.unlink()
            log(f"Deleted {p}")
        except Exception as e:
            log(f"Error deleting {p}: {e}")
    else:
        log(f"File not found: {p}")

if __name__ == "__main__":
    main()
