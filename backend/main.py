# ============================================================
# main.py - Backend FastAPI ITGATE v4.0
# Dataset  : CICIDS-2017
# Features : 20 features (Random Forest selection)
# sklearn  : 1.6.1
#
# ARCHITECTURE STATE :
#   predictions[] : ALL predictions (Benign + Malicious)
#   alerts[]      : Malicious ONLY
#   /stats        : uses predictions[] -> correct counters
#   /alerts       : uses alerts[]      -> attack table only
#   /history      : uses predictions[] -> full traffic table
# ============================================================

from fastapi                 import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from schemas                 import NetworkData
from datetime                import datetime
from typing                  import List, Dict, Any
import numpy  as np
import pandas as pd
import joblib, json, os

app = FastAPI(
    title       = "ITGATE Anomaly Detection API",
    description = "API de detection d'anomalies reseau - CICIDS-2017",
    version     = "4.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

# Mapping Pydantic field -> CICIDS-2017 column name
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

# Real model performance metrics from CICIDS-2017 training notebook
MODEL_METRICS = {
    "random_forest":    {"accuracy": 99.917, "precision": 99.917, "recall": 99.917, "f1_score": 99.917},
    "xgboost":          {"accuracy": 99.682, "precision": 99.683, "recall": 99.682, "f1_score": 99.682},
    "knn":              {"accuracy": 99.558, "precision": 99.559, "recall": 99.558, "f1_score": 99.558},
    "decision_tree":    {"accuracy": 99.678, "precision": 99.679, "recall": 99.678, "f1_score": 99.678},
    "svm":              {"accuracy": 96.135, "precision": 96.163, "recall": 96.135, "f1_score": 96.134},
    "isolation_forest": {"accuracy": 61.110, "precision": 61.111, "recall": 61.110, "f1_score": 61.109},
}

models:        Dict[str, Any]     = {}
scaler                            = None
feature_names: List[str]          = []
predictions:   List[Dict[str, Any]] = []   # ALL predictions
alerts:        List[Dict[str, Any]] = []   # Malicious ONLY


def load_models():
    global models, scaler, feature_names
    with open(os.path.join(MODELS_DIR, "feature_names.json")) as f:
        feature_names = json.load(f)
    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
    for key, fname in {
        "random_forest":    "rf_model.pkl",
        "xgboost":          "xgb_model.pkl",
        "svm":              "svm_model.pkl",
        "knn":              "knn_model.pkl",
        "decision_tree":    "dt_model.pkl",
        "isolation_forest": "iso_model.pkl",
    }.items():
        path = os.path.join(MODELS_DIR, fname)
        if os.path.exists(path):
            models[key] = joblib.load(path)
            print(f"Loaded: {key}")
    print(f"Models loaded: {len(models)} | Features: {len(feature_names)}")


load_models()


def preparer_features(data: NetworkData) -> pd.DataFrame:
    row = {cicids: getattr(data, field, 0.0)
           for field, cicids in FEATURE_MAP.items()}
    df = pd.DataFrame([row])[feature_names]
    df = df.replace([np.inf, -np.inf], 0.0).fillna(0.0)
    return pd.DataFrame(scaler.transform(df), columns=feature_names)


# ── ROUTES ───────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "ITGATE API v4.0", "dataset": "CICIDS-2017",
            "models": list(models.keys()), "features": len(feature_names)}


@app.get("/status")
def status():
    return {"api_status": "online", "dataset": "CICIDS-2017",
            "modeles": {k: "loaded" for k in models},
            "total_alertes": len(alerts),
            "timestamp": datetime.now().isoformat()}


@app.post("/predict")
def predict(data: NetworkData):
    model_key = (data.model or "random_forest").lower().replace(" ", "_")
    if model_key not in models:
        raise HTTPException(400,
            detail=f"Model '{model_key}' not found. Available: {list(models.keys())}")
    try:
        X     = preparer_features(data)
        model = models[model_key]

        if model_key == "isolation_forest":
            raw        = model.predict(X)[0]
            prediction = 1 if raw == -1 else 0
            score      = model.score_samples(X)[0]
            confidence = round(min(abs(float(score)) * 100, 99.9), 2)
        elif not hasattr(model, "predict_proba"):
            prediction = int(model.predict(X)[0])
            decision   = model.decision_function(X)[0]
            confidence = round(min(float(abs(decision)) * 20 + 50, 99.9), 2)
        else:
            prediction = int(model.predict(X)[0])
            probas     = model.predict_proba(X)[0]
            confidence = round(float(max(probas)) * 100, 2)

        label = "Malicious" if prediction == 1 else "Benign"
        ts    = datetime.now().isoformat()

        record = {
            "timestamp":  ts,
            "label":      label,
            "prediction": prediction,
            "confidence": confidence,
            "model":      model_key,
            "dst_port":   getattr(data, "dst_port", 0),
        }

        # Store in ALL predictions
        predictions.append(record)

        # Store in alerts ONLY if Malicious
        if prediction == 1:
            alerts.append(record)

        return {"label": label, "prediction": prediction,
                "confidence": confidence, "model": model_key,
                "timestamp": ts}

    except Exception as e:
        raise HTTPException(500, detail=f"Prediction error: {str(e)}")


@app.get("/alerts")
def get_alerts():
    # Returns Malicious ONLY — used by AlertsTable
    return {"alerts": list(reversed(alerts[-100:])), "total": len(alerts)}


@app.get("/history")
def get_history():
    # Returns ALL predictions — used by full traffic table
    return {"history": list(reversed(predictions[-200:])), "total": len(predictions)}


@app.delete("/alerts/clear")
def clear_alerts():
    alerts.clear()
    predictions.clear()
    return {"message": "Cleared", "total": 0}


@app.get("/stats")
def get_stats():
    # ALWAYS uses predictions[] — never alerts[]
    total = len(predictions)
    if total == 0:
        return {"total": 0, "malicious": 0, "benign": 0,
                "malicious_pct": 0.0, "avg_confidence": 0.0}
    mal = sum(1 for p in predictions if p["label"] == "Malicious")
    ben = total - mal
    avg = round(sum(p["confidence"] for p in predictions) / total, 2)
    return {
        "total":          total,
        "malicious":      mal,
        "benign":         ben,
        "malicious_pct":  round(mal / total * 100, 1),
        "avg_confidence": avg,
    }


@app.get("/models")
def get_models():
    result = []
    for key in models:
        metrics = MODEL_METRICS.get(key, {})
        result.append({
            "key":       key,
            "name":      key.replace("_", " ").title(),
            "type":      "non-supervise" if key == "isolation_forest" else "supervise",
            "accuracy":  metrics.get("accuracy",  0),
            "precision": metrics.get("precision", 0),
            "recall":    metrics.get("recall",    0),
            "f1_score":  metrics.get("f1_score",  0),
        })
    return {"available": result, "total": len(result),
            "dataset": "CICIDS-2017", "features": feature_names}
