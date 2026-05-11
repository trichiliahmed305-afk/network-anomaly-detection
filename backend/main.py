# ============================================================
# main.py - Backend FastAPI ITGATE
# Dataset : CICIDS-2017
# Features : 20 features selectionnees par Random Forest
# Compatible : scikit-learn 1.6.1
# ============================================================

from fastapi             import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from schemas             import NetworkData
from datetime            import datetime
from typing              import List, Dict, Any
import numpy  as np
import pandas as pd
import joblib, json, os

app = FastAPI(
    title       = "ITGATE Anomaly Detection API",
    description = "API de detection d'anomalies reseau - CICIDS-2017",
    version     = "3.0"
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

models:       Dict[str, Any] = {}
scaler        = None
feature_names: List[str]     = []

# DEUX listes separees :
# predictions = TOUTES les predictions (Benign + Malicious)
# alerts      = uniquement les Malicious (pour la table d'alertes)
predictions: List[Dict[str, Any]] = []
alerts:      List[Dict[str, Any]] = []


def load_models():
    global models, scaler, feature_names
    fn_path = os.path.join(MODELS_DIR, "feature_names.json")
    with open(fn_path, "r") as f:
        feature_names = json.load(f)
    print(f"Features chargees : {len(feature_names)}")

    scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
    print("Scaler charge")

    model_files = {
        "random_forest":    "rf_model.pkl",
        "xgboost":          "xgb_model.pkl",
        "svm":              "svm_model.pkl",
        "knn":              "knn_model.pkl",
        "decision_tree":    "dt_model.pkl",
        "isolation_forest": "iso_model.pkl",
    }
    for key, fname in model_files.items():
        path = os.path.join(MODELS_DIR, fname)
        if os.path.exists(path):
            models[key] = joblib.load(path)
            print(f"Modele charge : {key}")
    print(f"Total modeles : {len(models)}")

load_models()


def preparer_features(data: NetworkData) -> pd.DataFrame:
    row = {cicids: getattr(data, field, 0.0)
           for field, cicids in FEATURE_MAP.items()}
    df = pd.DataFrame([row])[feature_names]
    df = df.replace([np.inf, -np.inf], 0.0).fillna(0.0)
    return pd.DataFrame(scaler.transform(df), columns=feature_names)


@app.get("/")
def root():
    return {
        "message":  "ITGATE Anomaly Detection API",
        "dataset":  "CICIDS-2017",
        "version":  "3.0",
        "features": len(feature_names),
        "models":   list(models.keys())
    }


@app.get("/status")
def status():
    return {
        "api_status":    "online",
        "dataset":       "CICIDS-2017",
        "modeles":       {k: "loaded" for k in models},
        "total_alertes": len(alerts),
        "timestamp":     datetime.now().isoformat()
    }


@app.post("/predict")
def predict(data: NetworkData):
    model_key = (data.model or "random_forest").lower().replace(" ", "_")

    if model_key not in models:
        raise HTTPException(
            status_code=400,
            detail=f"Modele '{model_key}' introuvable. Disponibles : {list(models.keys())}"
        )

    try:
        X     = preparer_features(data)
        model = models[model_key]

        if model_key == "isolation_forest":
            raw_pred   = model.predict(X)[0]
            prediction = 1 if raw_pred == -1 else 0
            scores     = model.score_samples(X)
            confidence = round(min(abs(float(scores[0])) * 100, 99.9), 2)
        elif model_key == "svm" and not hasattr(model, "predict_proba"):
            prediction = int(model.predict(X)[0])
            decision   = model.decision_function(X)[0]
            confidence = round(min(float(abs(decision)) * 20 + 50, 99.9), 2)
        else:
            prediction = int(model.predict(X)[0])
            probas     = model.predict_proba(X)[0]
            confidence = round(float(max(probas)) * 100, 2)

        label = "Malicious" if prediction == 1 else "Benign"
        ts    = datetime.now().isoformat()

        # Enregistrer TOUTES les predictions pour les stats
        predictions.append({
            "timestamp":  ts,
            "label":      label,
            "confidence": confidence,
            "model":      model_key,
        })

        # Enregistrer uniquement les Malicious dans alerts
        if prediction == 1:
            alerts.append({
                "timestamp":  ts,
                "label":      label,
                "confidence": confidence,
                "model":      model_key,
            })

        return {
            "label":      label,
            "prediction": prediction,
            "confidence": confidence,
            "model":      model_key,
            "timestamp":  ts
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur : {str(e)}")


@app.get("/alerts")
def get_alerts():
    return {"alerts": alerts[-100:], "total": len(alerts)}


@app.delete("/alerts/clear")
def clear_alerts():
    alerts.clear()
    predictions.clear()
    return {"message": "Alertes effacees", "total": 0}


@app.get("/stats")
def get_stats():
    # Calcul base sur TOUTES les predictions
    total = len(predictions)
    if total == 0:
        return {
            "total": 0, "malicious": 0, "benign": 0,
            "malicious_pct": 0, "avg_confidence": 0
        }

    mal = sum(1 for p in predictions if p["label"] == "Malicious")
    ben = total - mal
    avg = round(sum(p["confidence"] for p in predictions) / total, 2)

    return {
        "total":          total,
        "malicious":      mal,
        "benign":         ben,
        "malicious_pct":  round(mal / total * 100, 1),
        "avg_confidence": avg
    }


@app.get("/models")
def get_models():
    model_info = {
        "random_forest":    {"name": "Random Forest",    "type": "supervise"},
        "xgboost":          {"name": "XGBoost",          "type": "supervise"},
        "svm":              {"name": "SVM",               "type": "supervise"},
        "knn":              {"name": "KNN",               "type": "supervise"},
        "decision_tree":    {"name": "Decision Tree",    "type": "supervise"},
        "isolation_forest": {"name": "Isolation Forest", "type": "non-supervise"},
    }
    return {
        "available": [
            {**model_info.get(k, {"name": k}), "key": k}
            for k in models
        ],
        "total":    len(models),
        "dataset":  "CICIDS-2017",
        "features": feature_names
    }