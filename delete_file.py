#!/usr/bin/env python
"""
delete_file.py – Wazuh active-response (Windows Agent)

• Đọc JSON từ STDIN.
• Tìm đường dẫn file cần xoá, ưu tiên:
    1. data["alert"]["data"]["file"]     (khi script được kích hoạt tự động)
    2. data["parameters"]["file"]        (khi gọi qua Wazuh API)

• Ghi log vào ar.log để dễ audit.
"""

import sys, json, os, pathlib, datetime

AR_DIR = pathlib.Path(os.getenv("ProgramFiles(x86)", r"C:\Program Files")) \
         / "ossec-agent" / "active-response"
LOG_FILE = AR_DIR / "ar.log"

def write_log(message: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{now}  {message}\n")

def get_target(path_dict: dict) -> str | None:
    # ① tự động qua rule
    try:
        return path_dict["alert"]["data"]["file"]
    except Exception:
        pass
    # ② gọi trực tiếp qua API
    return path_dict.get("parameters", {}).get("file")

def main() -> int:
    try:
        raw_json = sys.stdin.read()
        data     = json.loads(raw_json or "{}")
        target   = get_target(data)
        if not target:
            write_log("No 'file' field found in payload")
            return 1

        p = pathlib.Path(target)
        if p.exists():
            try:
                os.chmod(p, 0o600)  # gỡ Read-only nếu có
            except Exception:
                pass
            p.unlink()
            write_log(f"Deleted {p}")
            return 0
        else:
            write_log(f"File not found: {p}")
            return 1
    except Exception as err:
        write_log(f"Error: {err}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
