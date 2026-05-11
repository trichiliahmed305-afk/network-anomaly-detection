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
from typing              import List, Dict, Any, Optional
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

# ── Chemins des modeles ──────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR  = os.path.join(BASE_DIR, "models")

# ── Mapping features CICIDS-2017 ────────────────────────────
# Correspondance : champ Pydantic -> nom exact dans feature_names.json
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

# ── Chargement des modeles au demarrage ──────────────────────
models  = {}
scaler  = None
feature_names = []
alerts: List[Dict[str, Any]] = []

def load_models():
    global models, scaler, feature_names
    try:
        # Charger la liste des features
        fn_path = os.path.join(MODELS_DIR, "feature_names.json")
        with open(fn_path, "r") as f:
            feature_names = json.load(f)
        print(f"Features chargees : {len(feature_names)}")

        # Charger le scaler
        scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
        print("Scaler charge")

        # Charger tous les modeles
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
            else:
                print(f"ATTENTION : {fname} introuvable")

        print(f"\nTotal modeles charges : {len(models)}")
    except Exception as e:
        print(f"Erreur chargement modeles : {e}")
        raise

load_models()


def preparer_features(data: NetworkData) -> pd.DataFrame:
    """
    Construit le DataFrame de features a partir des donnees entrantes.
    Utilise FEATURE_MAP pour correspondre les champs Pydantic
    aux noms exacts des features CICIDS-2017.
    """
    row = {}
    for pydantic_field, cicids_name in FEATURE_MAP.items():
        row[cicids_name] = getattr(data, pydantic_field, 0.0)

    df = pd.DataFrame([row])

    # Reordonner selon l'ordre exact de feature_names.json
    df = df[feature_names]

    # Remplacer les valeurs infinies
    df = df.replace([np.inf, -np.inf], 0.0).fillna(0.0)

    # Appliquer le scaler
    df_scaled = pd.DataFrame(
        scaler.transform(df),
        columns=feature_names
    )

    return df_scaled


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
        "api_status":  "online",
        "dataset":     "CICIDS-2017",
        "modeles":     {k: "loaded" for k in models},
        "total_alertes": len(alerts),
        "timestamp":   datetime.now().isoformat()
    }


@app.post("/predict")
def predict(data: NetworkData):
    """
    Realise une prediction sur les donnees reseau entrantes.
    Retourne : label (Benign/Malicious), confidence, modele utilise.
    """
    model_key = (data.model or "random_forest").lower().replace(" ", "_")

    if model_key not in models:
        raise HTTPException(
            status_code = 400,
            detail      = f"Modele '{model_key}' introuvable. "
                          f"Disponibles : {list(models.keys())}"
        )

    try:
        # 1. Preparer les features
        X = preparer_features(data)

        # 2. Predire selon le type de modele
        model = models[model_key]

        if model_key == "isolation_forest":
            raw_pred   = model.predict(X)[0]
            prediction = 1 if raw_pred == -1 else 0
            scores     = model.score_samples(X)
            confidence = round(min(abs(float(scores[0])) * 100, 99.9), 2)

        elif model_key == "svm" and not hasattr(model, "predict_proba"):
            # LinearSVC sans calibration
            prediction = int(model.predict(X)[0])
            decision   = model.decision_function(X)[0]
            confidence = round(min(float(abs(decision)) * 20 + 50, 99.9), 2)

        else:
            prediction = int(model.predict(X)[0])
            probas     = model.predict_proba(X)[0]
            confidence = round(float(max(probas)) * 100, 2)

        label = "Malicious" if prediction == 1 else "Benign"

        # 3. Enregistrer l'alerte si malveillant
        if prediction == 1:
            alerts.append({
                "timestamp":  datetime.now().isoformat(),
                "label":      label,
                "confidence": confidence,
                "model":      model_key,
            })

        return {
            "label":      label,
            "prediction": prediction,
            "confidence": confidence,
            "model":      model_key,
            "timestamp":  datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur de prediction : {str(e)}")


@app.get("/alerts")
def get_alerts():
    return {"alerts": alerts[-100:], "total": len(alerts)}


@app.delete("/alerts/clear")
def clear_alerts():
    alerts.clear()
    return {"message": "Alertes effacees", "total": 0}


@app.get("/stats")
def get_stats():
    if not alerts:
        return {
            "total": 0, "malicious": 0, "benign": 0,
            "malicious_pct": 0, "avg_confidence": 0
        }
    mal  = sum(1 for a in alerts if a["label"] == "Malicious")
    ben  = len(alerts) - mal
    avg  = round(sum(a["confidence"] for a in alerts) / len(alerts), 2)
    return {
        "total":          len(alerts),
        "malicious":      mal,
        "benign":         ben,
        "malicious_pct":  round(mal / len(alerts) * 100, 1),
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
