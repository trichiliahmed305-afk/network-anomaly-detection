# backend/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from schemas import TrafficData, PredictionResult
import joblib
import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import List
import os
from pdf_report import generer_rapport_pdf
from fastapi.responses import Response

app = FastAPI(
    title="API Détection d'Anomalies Réseau — ITGATE PFE 2026",
    description="Système ML de détection d'intrusions réseau en temps réel",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

def charger_modele(nom_fichier):
    chemin = os.path.join(MODELS_DIR, nom_fichier)
    return joblib.load(chemin)

try:
    rf_model = charger_modele('rf_model.pkl')
    scaler   = charger_modele('scaler.pkl')
    with open(os.path.join(MODELS_DIR, 'feature_names.json')) as f:
        feature_names = json.load(f)
    try:
        iso_model = charger_modele('iso_model.pkl')
        print("✅ iso_model.pkl chargé")
    except Exception:
        iso_model = None
        print("⚠️ iso_model.pkl absent — ignoré")
    print("✅ Modèles principaux chargés avec succès!")
except Exception as e:
    print(f"❌ Erreur chargement modèles: {e}")
    rf_model = iso_model = scaler = None
    feature_names = []

alert_history: List[dict] = []

# Colonnes que le scaler connaît (9 colonnes numériques)
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
    """Transforme les données en DataFrame avec les 21 features exactes du modèle"""
    features = {
        'id.orig_p':          data.id_orig_p,
        'id.resp_p':          data.id_resp_p,
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

    # Normaliser seulement les 9 colonnes que le scaler connaît
    df[SCALER_COLS] = scaler.transform(df[SCALER_COLS])

    # Retourner dans l'ordre exact du modèle RF
    return df[feature_names]

@app.get("/", tags=["Status"])
def racine():
    return {
        "message": "🛡️ API Détection Anomalies Réseau — ITGATE PFE 2026",
        "status": "operational",
        "modeles_charges": rf_model is not None,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/status", tags=["Status"])
def statut():
    return {
        "api_status": "online",
        "modeles": {
            "random_forest": "loaded" if rf_model else "error",
            "isolation_forest": "loaded" if iso_model else "absent",
            "scaler": "loaded" if scaler else "error",
        },
        "total_alertes": len(alert_history),
        "timestamp": datetime.now().isoformat()
    }

@app.post("/predict", response_model=PredictionResult, tags=["Prédiction"])
def predire(data: TrafficData):
    """🔮 Analyser une connexion réseau et détecter les anomalies."""
    if rf_model is None:
        raise HTTPException(status_code=503, detail="Modèles non disponibles")
    try:
        # 1. Préparer et normaliser les features
        X = preparer_features(data)

        # 2. Prédire directement (scaler déjà appliqué dans preparer_features)
        prediction = int(rf_model.predict(X)[0])
        probas = rf_model.predict_proba(X)[0]
        confidence = round(float(max(probas)) * 100, 2)

        # 3. Déterminer le niveau de risque
        risk_level = determine_risk_level(confidence, prediction)
        label = "Malicious" if prediction == 1 else "Benign"
        alert_msg = (
            f"🚨 ALERTE : Trafic malveillant détecté ! Confiance : {confidence}%"
            if prediction == 1
            else f"✅ Trafic normal. Confiance : {confidence}%"
        )

        # 4. Enregistrer dans l'historique
        alert_entry = {
            "timestamp": datetime.now().isoformat(),
            "prediction": prediction,
            "label": label,
            "confidence": confidence,
            "risk_level": risk_level,
            "data": data.dict()
        }
        alert_history.append(alert_entry)
        if len(alert_history) > 1000:
            alert_history.pop(0)

        return PredictionResult(
            prediction=prediction,
            label=label,
            confidence=confidence,
            risk_level=risk_level,
            model_used="Random Forest",
            alert_message=alert_msg
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur de prédiction: {str(e)}")

@app.get("/alerts", tags=["Alertes"])
def obtenir_alertes(limit: int = 50):
    """📋 Récupérer les dernières alertes générées"""
    return {
        "total": len(alert_history),
        "alertes": alert_history[-limit:][::-1]
    }

@app.get("/stats", tags=["Statistiques"])
def statistiques():
    """📊 Statistiques globales du système de détection"""
    if not alert_history:
        return {"message": "Aucune analyse effectuée pour l'instant"}
    total = len(alert_history)
    malveillants = sum(1 for a in alert_history if a['prediction'] == 1)
    benins = total - malveillants
    return {
        "total_analyses": total,
        "trafic_malveillant": malveillants,
        "trafic_benin": benins,
        "taux_detection": round((malveillants / total) * 100, 2) if total > 0 else 0,
        "derniere_alerte": alert_history[-1]['timestamp'] if alert_history else None,
        "niveaux_risque": {
            level: sum(1 for a in alert_history if a['risk_level'] == level)
            for level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        }
    }

@app.get("/report", tags=["Rapport"])
def generer_rapport():
    """
    📄 Générer un rapport PDF des incidents détectés.
    Télécharge automatiquement un fichier PDF.
    """
    if not alert_history:
        raise HTTPException(
            status_code=404,
            detail="Aucune alerte disponible pour générer un rapport"
        )
    try:
        pdf_bytes = generer_rapport_pdf(alert_history)
        nom_fichier = f"rapport_anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={nom_fichier}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur génération PDF: {str(e)}")

@app.delete("/alerts/clear", tags=["Alertes"])
def vider_alertes():
    """🗑️ Vider l'historique des alertes"""
    alert_history.clear()
    return {"message": "Historique des alertes vidé", "timestamp": datetime.now().isoformat()}