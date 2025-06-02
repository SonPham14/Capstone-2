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


# === FastAPI ===
app = FastAPI(title="Malware & Web attack Detection API")


# Load web attack detect model
vec_path   = ".\\web_attack_detect_model\\tfidf_vectorizer.joblib"
model_path = ".\\web_attack_detect_model\\wazuh_classifier.joblib"
vectorizer = joblib.load(vec_path)
model      = joblib.load(model_path)


# === Web attack detection ===

def web_attack_predict(data):
    X = data.get("full_log","data_url")

    # Ensure X is a list (even if it's a single string)
    X_vec = vectorizer.transform([X])  # Wrap X in a list

    # Predict
    prediction = model.predict(X_vec)
    probability = model.predict_proba(X_vec).max()
    return int(prediction[0]), probability

@app.post("/detect-webattack")
def detect_webattack(log: Dict[str, Any]):
    try:
        data = {
            "timestamp": log.get("timestamp", ""),
            "agent": log.get("agent", {}).get("name", ""),
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
        
        
        # Predict
        label, probability = web_attack_predict(data)
        
        # Map label to attack type
        attack = {1: "XSS", 2: "SQLi"}.get(label, "Benign")
        print("Attack: ", attack)
        print("Probability: ", probability)
        
        if attack != "Benign":
            shuffle_web_attack(attack, probability, data)

    except Exception as e:
        print("=== Exception in /detect-webattack ===")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal ML error: {e}")

# Send prediction to Shuffle
def shuffle_web_attack(label: str, probability: float, data: Dict[str, Any]):
    url = "http://192.168.88.135:3001/api/v1/hooks/webhook_4c76f98f-7f5a-465b-93fc-079c41a54327"  # 🔁 URL webhook Shuffle
    headers = {"Content-Type": "application/json"}
    notification_content = {
        "label": label,
        "probability": probability,
        "srcip": data.get("srcip", ""),
        "dstip": data.get("dstip", ""),
        "agent": data.get("agent", ""),
        "mitre_id": data.get("MITRE_ID", "")[0],
        "mitre_tactic": data.get("MITRE_Tactic", "")[0],
        "payload": data.get("data_url", ""),
        "recommended_action": "IP Blocked",
        "date": data.get("timestamp", "")
    }
    print("Payload: ", notification_content["payload"])
    try:
        response = requests.post(url, json=notification_content, headers=headers)
        response.raise_for_status()
        print("[+] Sent to Shuffle successfully.")
    except Exception as e:
        print(f"[!] Error sending to Shuffle: {e}")


# === Malware detection ===

# Feature list
class Input(BaseModel):
    features: list[float]
    path: str
    agent_name: str
    agent_ip: str

@app.post("/predict-features")
def predict_features(inp: Input):
    try:
        model = joblib.load('Classifier/classifier.pkl')
        prediction = model.predict([inp.features])[0]
        probability = model.predict_proba([inp.features])[0].max()
        label = ['malicious', 'legitimate'][prediction]

        # Log + Predict
        df = pd.DataFrame(inp.features, columns=["feature"])
        df["label"] = label
        df["probability"] = probability
        df["timestamp"] = pd.Timestamp.now()
        df.to_csv("malware_logs.csv",
                  mode="a", index=False,
                  header=not os.path.exists("/Log/malware_logs.csv"))
        
        if label == "malicious":
            print({"path": inp.path, "label": label, "probability": float(probability)})
            shuffle_malware_attack(inp.agent_name, inp.agent_ip, inp.path, label, probability)
        else:
            print("Legitimate file detected.")
            print({"path": inp.path, "label": label, "probability": float(probability)})
    except Exception as e:
        raise HTTPException(status_code=500, detail=e)

# Send prediction to Shuffle
def shuffle_malware_attack(agent_name: str, agent_ip: str, path: str, label: str, probability: float):
    url = "http://192.168.88.135:3001/api/v1/hooks/webhook_397ad5f5-c18c-47da-ab6d-990688ff357d"  # 🔁 URL webhook Shuffle
    headers = {"Content-Type": "application/json"}
    payload = {
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "path": path.replace("\\", "\\\\"),
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
