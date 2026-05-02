# backend/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from schemas import TrafficData, PredictionResult
import pickle
import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import List
import os

# ============================================================
# INITIALISATION DE L'APPLICATION
# ============================================================
app = FastAPI(
    title="API Détection d'Anomalies Réseau — ITGATE PFE 2026",
    description="Système ML de détection d'intrusions réseau en temps réel",
    version="1.0.0"
)

# Autoriser les requêtes depuis le frontend (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# CHARGEMENT DES MODÈLES AU DÉMARRAGE
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')  # ✅ CORRIGÉ : models/ est dans backend/

def charger_modele(nom_fichier):
    """Charge un modèle pickle depuis le dossier models/"""
    chemin = os.path.join(MODELS_DIR, nom_fichier)
    with open(chemin, 'rb') as f:
        return pickle.load(f)

try:
    rf_model = charger_modele('rf_model.pkl')
    scaler   = charger_modele('scaler.pkl')

    with open(os.path.join(MODELS_DIR, 'feature_names.json')) as f:
        feature_names = json.load(f)

    # iso_model est optionnel — pas d'erreur s'il est absent
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

# Historique des alertes (stocké en mémoire)
alert_history: List[dict] = []

# ============================================================
# FONCTIONS UTILITAIRES
# ============================================================
def determine_risk_level(confidence: float, prediction: int) -> str:
    """Détermine le niveau de risque selon la confiance du modèle"""
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

def preparer_features(data: TrafficData) -> np.ndarray:
    """Transforme les données d'entrée en vecteur de features pour le modèle"""
    features = {
        'duration': data.duration,
        'orig_bytes': data.orig_bytes,
        'resp_bytes': data.resp_bytes,
        'orig_pkts': data.orig_pkts,
        'resp_pkts': data.resp_pkts,
        'orig_ip_bytes': data.orig_ip_bytes,
        'resp_ip_bytes': data.resp_ip_bytes,
        'pkt_ratio': data.pkt_ratio,
        'avg_orig_pkt_size': data.avg_orig_pkt_size,
        'avg_resp_pkt_size': data.avg_resp_pkt_size,
        'is_orig_local': data.is_orig_local,
        'is_well_known_port': data.is_well_known_port,
        'hour': data.hour,
        'minute': data.minute,
        'day_of_week': data.day_of_week,
        'inter_arrival_time': data.inter_arrival_time,
    }
    df = pd.DataFrame([features])
    # Aligner avec les features attendues par le modèle
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0
    df = df[feature_names] if feature_names else df
    return df.values

# ============================================================
# ENDPOINTS DE L'API
# ============================================================

@app.get("/", tags=["Status"])
def racine():
    """Page d'accueil — vérifie que l'API fonctionne"""
    return {
        "message": "🛡️ API Détection Anomalies Réseau — ITGATE PFE 2026",
        "status": "operational",
        "modeles_charges": rf_model is not None,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/status", tags=["Status"])
def statut():
    """Statut détaillé de l'API et des modèles"""
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
    """
    🔮 Analyser une connexion réseau et détecter les anomalies.

    Envoie les caractéristiques d'une connexion réseau.
    Reçois une prédiction : Bénin (0) ou Malveillant (1).
    """
    if rf_model is None:
        raise HTTPException(status_code=503, detail="Modèles non disponibles")

    try:
        # 1. Préparer les features
        X = preparer_features(data)

        # 2. Normaliser (même scaler que pendant l'entraînement)
        X_scaled = scaler.transform(X)

        # 3. Prédire avec Random Forest (modèle principal)
        prediction = int(rf_model.predict(X_scaled)[0])
        probas = rf_model.predict_proba(X_scaled)[0]
        confidence = round(float(max(probas)) * 100, 2)

        # 4. Déterminer le niveau de risque
        risk_level = determine_risk_level(confidence, prediction)
        label = "Malicious" if prediction == 1 else "Benign"

        alert_msg = (
            f"🚨 ALERTE : Trafic malveillant détecté ! Confiance : {confidence}%"
            if prediction == 1
            else f"✅ Trafic normal. Confiance : {confidence}%"
        )

        # 5. Enregistrer dans l'historique
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

@app.delete("/alerts/clear", tags=["Alertes"])
def vider_alertes():
    """🗑️ Vider l'historique des alertes"""
    alert_history.clear()
    return {"message": "Historique des alertes vidé", "timestamp": datetime.now().isoformat()}