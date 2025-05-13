import os
from flask import request, jsonify
import joblib
import numpy as np
from requests.auth import HTTPBasicAuth
from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import pickle
from fastapi import FastAPI, HTTPException, logger
from pydantic import BaseModel
from typing import Any, Dict
import traceback
import requests

# Wazuh password == WvaW?9iLq*Xq4VHQEPuegAgMeSIEf8b*

# === FastAPI ===
app = FastAPI(title="Malware & Web attack Detection API")


# Load web attack detect model
vec_path   = ".\\web_attack_detect_model\\tfidf_vectorizer.joblib"
model_path = ".\\web_attack_detect_model\\wazuh_classifier.joblib"
vectorizer = joblib.load(vec_path)
model      = joblib.load(model_path)
print("Web attack model loaded successfully.")


def web_attack_predict(data):
    # Chọn cột full_log làm feature
    X = data.get("full_log","data_url")

    # Ensure X is a list (even if it's a single string)
    X_vec = vectorizer.transform([X])  # Wrap X in a list

    # Dự đoán nhãn
    prediction = model.predict(X_vec)
    probability = model.predict_proba(X_vec).max()
    return int(prediction[0]), probability


# === Web attack detection ===

# ⚡ Hàm kiểm tra IP nội bộ
def is_internal(ip):
    return 1 if ip.startswith("192.168.") or ip.startswith("10.") else 0

# ⚡ Hàm lấy danh tiếng IP
def get_ip_reputation(ip):
    bad_ips = {"203.0.113.5": 100, "192.168.1.10": 30}
    return bad_ips.get(ip, 10)

# ⚡ Hàm phân tích đe dọa
def analyze_threat(log_entry):
    log_entry["is_internal_ip"] = is_internal(log_entry.get("data", {}).get("src_ip", "0.0.0.0"))
    log_entry["src_ip_reputation"] = get_ip_reputation(log_entry.get("data", {}).get("src_ip", "0.0.0.0"))
    
    filtered_log = {key: log_entry[key] for key in FEATURE_COLUMNS if key in log_entry}
    df = pd.DataFrame([filtered_log])

    prediction = model.predict(df)  # Dự đoán nhãn
    is_threat, recommended_action = prediction[0]

    
    # Kết hợp với threat_score
    if log_entry["threat_score"] > 80:
        recommended_action = 1  # Chặn IP
    elif 50 <= log_entry["threat_score"] <= 80:
        recommended_action = 2  # Cách ly Endpoint
    else:
        recommended_action = 0  # Không có hành động nào
    
    actions = {0: "Khong co hanh dong", 1: "IP Blocked", 2: "Endpoint isolation"}
    return {"is_threat": bool(is_threat), "recommended_action": actions.get(recommended_action, "Khong co hanh dong")}

@app.post("/detect-webattack")
def detect_webattack(log: Dict[str, Any]):
    """
    Nhận log từ Wazuh về SQLi/XSS, dùng text-based ML để dự đoán.
    """
    try:
        # Lấy các thông tin cần thiết từ log
        data = {
            "timestamp": log.get("timestamp", ""),
            "data_id": log.get("data", {}).get("id", 0),
            "rule_level": log.get("rule", {}).get("level", 0),
            "MITRE_ID": log.get("rule", {}).get("mitre", {}).get("id", ""),
            "MITRE_Tactic": log.get("rule", {}).get("mitre", "").get("tactic", ""),
            "srcip": log.get("data", {}).get("srcip", ""),
            "dstip": log.get("agent", {}).get("ip", ""),
            "full_log": log.get("full_log", {}),
            "data_protocol": log.get("data", {}).get("protocol", ""),
            "data_url": log.get("data", {}).get("url", "")
        }

        # threat = analyze_threat(data)  # Phân tích đe dọa

        # Dự đoán nhãn
        label, probability = web_attack_predict(data)
        
        # Map label to attack type
        attack = {1: "XSS", 2: "SQLi"}.get(label, "Benign")
        print("Attack: ", attack)
        print("Probability: ", probability)
        from datetime import datetime
        date = datetime.utcnow().isoformat() + "Z"
        shuffle_web_attack(attack, probability, date)

        # Lưu log + kết quả
        # record = log.dict()
        # record.update(res)
        # df = pd.DataFrame([record])
        # df.to_csv("Log/webattack_logs.csv",
        #           mode="a", index=False,
        #           header=not os.path.exists("webattack_logs.csv"))
    except Exception as e:
        print("=== Exception in /detect-webattack ===")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal ML error: {e}")


def shuffle_web_attack(label: str, probability: float, date: str):
    url = "http://192.168.88.135:3001/api/v1/hooks/webhook_4c76f98f-7f5a-465b-93fc-079c41a54327"  # 🔁 URL webhook Shuffle
    headers = {"Content-Type": "application/json"}
    notification_content = {
        "label": label,
        "probability": probability,
        "is_threat": "true",
        "recommended_action": "IP Blocked",
        "date": date
    }

    try:
        response = requests.post(url, json=notification_content, headers=headers)
        response.raise_for_status()
        print("[+] Sent to Shuffle successfully.")
    except Exception as e:
        print(f"[!] Error sending to Shuffle: {e}")


# === Malware detection ===

# Feature list
class FeatureInput(BaseModel):
    features: list[float]

@app.post("/predict-features")
def predict_features(inp: FeatureInput):
    """
    Nhận trực tiếp features list dạng json, trả về prediction.
    """
    try:
        model = joblib.load('Classifier/classifier.pkl')
        prediction = model.predict([inp.features])[0]
        probability = model.predict_proba([inp.features])[0].max()
        label = ['malicious', 'legitimate'][prediction]

        # Ghi log + kết quả
        df = pd.DataFrame(inp.features, columns=["feature"])
        df["label"] = label
        df["probability"] = probability
        # df["timestamp"] = pd.Timestamp.now()
        # df.to_csv("malware_logs.csv",
        #           mode="a", index=False,
        #           header=not os.path.exists("/Log/malware_logs.csv"))
        shuffle_malware_attack(label, probability)
        print({"label": label, "probability": float(probability)})
        return {"label": label, "probability": float(probability)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=e)


def shuffle_malware_attack(label: str, probability: float):
    url = "http://192.168.88.135:3001/api/v1/hooks/webhook_397ad5f5-c18c-47da-ab6d-990688ff357d"  # 🔁 URL webhook Shuffle
    headers = {"Content-Type": "application/json"}
    payload = {
        "label": label,
        "probability": float(probability)
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        print("[+] Sent to Shuffle successfully.", response.status_code)
    except Exception as e:
        print(f"[!] Error sending to Shuffle: {e}")


# To run the FastAPI app, use the command:
# uvicorn app2:app --reload --host 192.168.88.1 --port 8000
