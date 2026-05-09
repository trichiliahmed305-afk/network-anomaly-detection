# backend/main.py
from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from schemas import TrafficData, PredictionResult
import joblib
import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import List
import os
import io
from pdf_report import generer_rapport_pdf
from fastapi.responses import Response

app = FastAPI(
    title="API Detection d'Anomalies Reseau — ITGATE PFE 2026",
    description="Systeme ML de detection d'intrusions reseau en temps reel",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

def charger_modele(nom_fichier):
    chemin = os.path.join(MODELS_DIR, nom_fichier)
    return joblib.load(chemin)

MODELS = {}
scaler = None
feature_names = []

try:
    scaler = charger_modele('scaler.pkl')
    with open(os.path.join(MODELS_DIR, 'feature_names.json')) as f:
        feature_names = json.load(f)

    model_files = {
        'random_forest':    'rf_model.pkl',
        'xgboost':          'xgb_model.pkl',
        'svm':              'svm_model.pkl',
        'knn':              'knn_model.pkl',
        'decision_tree':    'dt_model.pkl',
        'isolation_forest': 'iso_model.pkl',
    }

    for key, filename in model_files.items():
        try:
            MODELS[key] = charger_modele(filename)
            print(f"OK {key} charge")
        except Exception as e:
            print(f"WARNING {key} non disponible: {e}")

    print(f"OK {len(MODELS)} modeles charges: {list(MODELS.keys())}")
    print(f"Feature names: {feature_names}")
    print(f"Scaler cols: {scaler.feature_names_in_ if hasattr(scaler, 'feature_names_in_') else 'N/A'}")

except Exception as e:
    print(f"ERREUR chargement: {e}")
    MODELS = {}
    scaler = None
    feature_names = []

rf_model  = MODELS.get('random_forest')
iso_model = MODELS.get('isolation_forest')

alert_history: List[dict] = []

SCALER_COLS = [
    'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts',
    'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes',
    'inter_arrival_time', 'pkt_ratio'
]

def determine_risk_level(confidence: float, prediction: int) -> str:
    if prediction == 0:
        return "LOW"
    if confidence >= 95:
        return "CRITICAL"
    elif confidence >= 80:
        return "HIGH"
    elif confidence >= 60:
        return "MEDIUM"
    else:
        return "LOW"

def preparer_features(data: TrafficData) -> pd.DataFrame:
    features = {
        'id.orig_p':          data.id_orig_p,
        'duration':           data.duration,
        'orig_bytes':         data.orig_bytes,
        'resp_bytes':         data.resp_bytes,
        'missed_bytes':       data.missed_bytes,
        'orig_pkts':          data.orig_pkts,
        'orig_ip_bytes':      data.orig_ip_bytes,
        'resp_pkts':          data.resp_pkts,
        'resp_ip_bytes':      data.resp_ip_bytes,
        'is_orig_local':      data.is_orig_local,
        'orig_h_count':       data.orig_h_count,
        'resp_h_count':       data.resp_h_count,
        'is_well_known_port': data.is_well_known_port,
        'hour':               data.hour,
        'minute':             data.minute,
        'day_of_week':        data.day_of_week,
        'inter_arrival_time': data.inter_arrival_time,
        'pkt_ratio':          data.pkt_ratio,
        'avg_orig_pkt_size':  data.avg_orig_pkt_size,
        'avg_resp_pkt_size':  data.avg_resp_pkt_size,
    }
    df = pd.DataFrame([features])
    df[SCALER_COLS] = scaler.transform(df[SCALER_COLS].values.reshape(1, -1))
    return df[feature_names]

@app.get("/", tags=["Status"])
def racine():
    return {
        "message": "API Detection Anomalies Reseau — ITGATE PFE 2026",
        "status": "operational",
        "modeles_charges": len(MODELS) > 0,
        "nb_modeles": len(MODELS),
        "feature_names": feature_names,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/status", tags=["Status"])
def statut():
    modeles_status = {key: "loaded" for key in MODELS.keys()}
    modeles_status["scaler"] = "loaded" if scaler else "error"
    return {
        "api_status": "online",
        "modeles": modeles_status,
        "total_alertes": len(alert_history),
        "timestamp": datetime.now().isoformat()
    }

@app.post("/predict", response_model=PredictionResult, tags=["Prediction"])
def predire(data: TrafficData):
    if not MODELS or scaler is None:
        raise HTTPException(status_code=503, detail="Modeles non disponibles")
    try:
        model_key = getattr(data, 'model', 'random_forest') or 'random_forest'
        if model_key not in MODELS:
            model_key = 'random_forest'
        model = MODELS[model_key]

        X = preparer_features(data)

        if model_key == 'isolation_forest':
            raw_pred   = model.predict(X)[0]
            prediction = 1 if raw_pred == -1 else 0
            scores     = model.score_samples(X)
            confidence = round(min(abs(float(scores[0])) * 100, 99.9), 2)
        else:
            prediction = int(model.predict(X)[0])
            probas     = model.predict_proba(X)[0]
            confidence = round(float(max(probas)) * 100, 2)

        risk_level = determine_risk_level(confidence, prediction)
        label      = "Malicious" if prediction == 1 else "Benign"
        alert_msg  = (
            f"Trafic malveillant detecte ! Confiance : {confidence}%"
            if prediction == 1
            else f"Trafic normal. Confiance : {confidence}%"
        )

        alert_entry = {
            "timestamp":  datetime.now().isoformat(),
            "prediction": prediction,
            "label":      label,
            "confidence": confidence,
            "risk_level": risk_level,
            "model":      model_key,
            "data":       data.dict()
        }
        alert_history.append(alert_entry)
        if len(alert_history) > 1000:
            alert_history.pop(0)

        return PredictionResult(
            prediction=prediction,
            label=label,
            confidence=confidence,
            risk_level=risk_level,
            model_used=model_key,
            alert_message=alert_msg
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur de prediction: {str(e)}")

@app.post("/predict/batch", tags=["Prediction"])
async def predire_batch(file: UploadFile = File(...)):
    """Analyser un fichier CSV ou Excel - normalisation automatique si necessaire."""
    if not MODELS or scaler is None:
        raise HTTPException(status_code=503, detail="Modeles non disponibles")
    try:
        contents = await file.read()
        filename = file.filename.lower()

        if filename.endswith('.csv'):
            df_input = pd.read_csv(io.BytesIO(contents))
        elif filename.endswith(('.xlsx', '.xls')):
            df_input = pd.read_excel(io.BytesIO(contents))
        else:
            raise HTTPException(
                status_code=400,
                detail="Format non supporte. Utilisez .csv, .xlsx ou .xls"
            )

        print(f"Batch recu: {len(df_input)} lignes")

        # Verifier les colonnes requises
        missing = [c for c in feature_names if c not in df_input.columns]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Colonnes manquantes: {missing}"
            )

        # Convertir toutes les colonnes en numerique
        for col in feature_names:
            df_input[col] = pd.to_numeric(
                df_input[col], errors='coerce').fillna(0.0)

        # Normalisation automatique si les donnees sont brutes
        scaler_vals = df_input[SCALER_COLS].values
        already_normalized = (
            float(scaler_vals.min()) >= 0.0 and
            float(scaler_vals.max()) <= 1.0
        )

        if not already_normalized:
            print("Donnees brutes detectees — normalisation automatique...")
            df_input[SCALER_COLS] = scaler.transform(df_input[SCALER_COLS])
        else:
            print("Donnees deja normalisees")

        results         = []
        malicious_count = 0
        benign_count    = 0
        errors          = 0

        for idx, row in df_input.iterrows():
            try:
                X          = pd.DataFrame([row[feature_names]])
                model      = MODELS.get('random_forest')
                prediction = int(model.predict(X)[0])
                probas     = model.predict_proba(X)[0]
                confidence = round(float(max(probas)) * 100, 2)
                risk_level = determine_risk_level(confidence, prediction)
                label      = "Malicious" if prediction == 1 else "Benign"

                if prediction == 1:
                    malicious_count += 1
                else:
                    benign_count += 1

                results.append({
                    "index":      int(idx),
                    "prediction": prediction,
                    "label":      label,
                    "confidence": confidence,
                    "risk_level": risk_level,
                })

                alert_history.append({
                    "timestamp":  datetime.now().isoformat(),
                    "prediction": prediction,
                    "label":      label,
                    "confidence": confidence,
                    "risk_level": risk_level,
                    "model":      "random_forest",
                    "data":       row[feature_names].to_dict()
                })

            except Exception as ex:
                print(f"Erreur ligne {idx}: {str(ex)}")
                errors += 1
                continue

        total = len(results)
        print(f"Batch termine: {total} OK, {errors} erreurs")

        return {
            "total":          total,
            "malicious":      malicious_count,
            "benign":         benign_count,
            "taux_detection": round(malicious_count / total * 100, 2) if total > 0 else 0,
            "results":        results
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur analyse batch: {str(e)}"
        )

@app.get("/alerts", tags=["Alertes"])
def obtenir_alertes(limit: int = 50):
    return {
        "total": len(alert_history),
        "alertes": alert_history[-limit:][::-1]
    }

@app.get("/stats", tags=["Statistiques"])
def statistiques():
    if not alert_history:
        return {"message": "Aucune analyse effectuee pour l'instant"}
    total        = len(alert_history)
    malveillants = sum(1 for a in alert_history if a['prediction'] == 1)
    benins       = total - malveillants
    return {
        "total_analyses":     total,
        "trafic_malveillant": malveillants,
        "trafic_benin":       benins,
        "taux_detection":     round((malveillants / total) * 100, 2) if total > 0 else 0,
        "derniere_alerte":    alert_history[-1]['timestamp'] if alert_history else None,
        "niveaux_risque": {
            level: sum(1 for a in alert_history if a['risk_level'] == level)
            for level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        }
    }

@app.get("/report", tags=["Rapport"])
def generer_rapport():
    if not alert_history:
        raise HTTPException(status_code=404, detail="Aucune alerte disponible")
    try:
        pdf_bytes   = generer_rapport_pdf(alert_history)
        nom_fichier = f"rapport_anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={nom_fichier}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur generation PDF: {str(e)}")

@app.delete("/alerts/clear", tags=["Alertes"])
def vider_alertes():
    alert_history.clear()
    return {"message": "Historique des alertes vide", "timestamp": datetime.now().isoformat()}