# ============================================================
# main.py - ITGATE Backend (Improved Stable Version)
# Focus: Consistency + Debug Safety + Reliable Stats
# ============================================================

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from schemas import NetworkData
from datetime import datetime
from typing import List, Dict, Any
import numpy as np
import pandas as pd
import joblib, json, os

app = FastAPI(
    title="ITGATE Anomaly Detection API",
    version="3.1-stable"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
FEATURE_MAP = {
    "packet_length_std":          "Packet Length Std",
    "packet_length_max":          "Packet Length Max",
    "rst_flag_count":             "RST Flag Count",
    "fwd_packet_length_max":      "Fwd Packet Length Max",
    "total_length_of_fwd_packet": "Total Length of Fwd Packet",
    "fwd_packet_length_mean":     "Fwd Packet Length Mean",
    "bwd_packet_length_std":      "Bwd Packet Length Std",
    "packet_length_mean":         "Packet Length Mean",
    "subflow_fwd_bytes":          "Subflow Fwd Bytes",
    "flow_iat_max":               "Flow IAT Max",
    "bwd_packet_length_mean":     "Bwd Packet Length Mean",
    "bwd_packet_length_max":      "Bwd Packet Length Max",
    "packet_length_variance":     "Packet Length Variance",
    "dst_port":                   "Dst Port",
    "bwd_segment_size_avg":       "Bwd Segment Size Avg",
    "bwd_psh_flags":              "Bwd PSH Flags",
    "flow_bytes_s":               "Flow Bytes/s",
    "flow_packets_s":             "Flow Packets/s",
    "average_packet_size":        "Average Packet Size",
    "fwd_segment_size_avg":       "Fwd Segment Size Avg",
}
# -------------------------
# GLOBAL STATE (STABLE)
# -------------------------
predictions: List[Dict[str, Any]] = []
alerts: List[Dict[str, Any]] = []

models: Dict[str, Any] = {}
scaler = None
feature_names: List[str] = []
label_mapping = {"0": "Benign", "1": "Malicious"}  # default safe mapping

# -------------------------
# LOAD MODELS + CONFIG
# -------------------------
def load_models():
    global models, scaler, feature_names, label_mapping

    # features
    with open(os.path.join(MODELS_DIR, "feature_names.json"), "r") as f:
        feature_names = json.load(f)

    # scaler
    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))

    # OPTIONAL: label mapping (IMPORTANT FIX)
    label_path = os.path.join(MODELS_DIR, "label_mapping.json")
    if os.path.exists(label_path):
        with open(label_path, "r") as f:
            label_mapping = json.load(f)

    model_files = {
        "random_forest": "rf_model.pkl",
        "xgboost": "xgb_model.pkl",
        "svm": "svm_model.pkl",
        "knn": "knn_model.pkl",
        "decision_tree": "dt_model.pkl",
        "isolation_forest": "iso_model.pkl",
    }

    for k, f in model_files.items():
        path = os.path.join(MODELS_DIR, f)
        if os.path.exists(path):
            models[k] = joblib.load(path)

load_models()

# -------------------------
# FEATURE PREPROCESSING
# -------------------------
def prepare_features(data: NetworkData) -> pd.DataFrame:
    row = {c: getattr(data, f, 0.0) for f, c in FEATURE_MAP.items()}

    df = pd.DataFrame([row])

    # force correct order
    df = df.reindex(columns=feature_names, fill_value=0.0)

    # safety cleanup
    df = df.replace([np.inf, -np.inf], 0.0).fillna(0.0)

    # normalization ONLY ONCE
    df = pd.DataFrame(scaler.transform(df), columns=feature_names)

    return df

# -------------------------
# ROOT
# -------------------------
@app.get("/")
def root():
    return {
        "status": "running",
        "models": list(models.keys()),
        "features": len(feature_names)
    }

# -------------------------
# STATUS
# -------------------------
@app.get("/status")
def status():
    return {
        "predictions": len(predictions),
        "alerts": len(alerts),
        "models_loaded": len(models),
        "timestamp": datetime.now().isoformat()
    }

# -------------------------
# PREDICT
# -------------------------
@app.post("/predict")
def predict(data: NetworkData):

    model_key = (data.model or "random_forest").lower()

    if model_key not in models:
        raise HTTPException(400, f"Model not found: {model_key}")

    try:
        X = prepare_features(data)
        model = models[model_key]

        # -------------------------
        # prediction logic
        # -------------------------
        if model_key == "isolation_forest":
            raw = model.predict(X)[0]
            prediction = 1 if raw == -1 else 0
            confidence = float(abs(model.score_samples(X)[0]) * 100)

        elif hasattr(model, "predict_proba"):
            probas = model.predict_proba(X)[0]
            prediction = int(np.argmax(probas))
            confidence = float(np.max(probas) * 100)

        else:
            prediction = int(model.predict(X)[0])
            confidence = 80.0  # fallback safe value

        # -------------------------
        # SAFE LABEL DECODING
        # -------------------------
        label = label_mapping.get(str(prediction), "Unknown")

        ts = datetime.now().isoformat()

        result = {
            "timestamp": ts,
            "label": label,
            "confidence": round(confidence, 2),
            "model": model_key
        }

        # store ALL predictions
        predictions.append(result)

        # store only attacks
        if label == "Malicious":
            alerts.append(result)

        return {
            "prediction": prediction,
            "label": label,
            "confidence": round(confidence, 2),
            "model": model_key,
            "timestamp": ts
        }

    except Exception as e:
        raise HTTPException(500, str(e))

# -------------------------
# ALERTS
# -------------------------
@app.get("/alerts")
def get_alerts():
    return {
        "alerts": alerts[-100:],
        "total": len(alerts)
    }

# -------------------------
# STATS (FIXED LOGIC)
# -------------------------
@app.get("/stats")
def stats():

    total = len(predictions)

    if total == 0:
        return {"total": 0, "malicious": 0, "benign": 0}

    mal = sum(1 for p in predictions if p["label"] == "Malicious")
    ben = sum(1 for p in predictions if p["label"] == "Benign")

    return {
        "total": total,
        "malicious": mal,
        "benign": ben,
        "malicious_pct": round(mal / total * 100, 2)
    }

# -------------------------
# CLEAR
# -------------------------
@app.delete("/reset")
def reset():
    predictions.clear()
    alerts.clear()
    return {"message": "state cleared"}