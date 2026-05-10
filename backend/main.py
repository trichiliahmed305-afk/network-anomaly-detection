# backend/main.py
from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from schemas import TrafficData, PredictionResult
import joblib
import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import List, Optional
import os
import io
from pdf_report import generer_rapport_pdf
from fastapi.responses import Response

app = FastAPI(
    title="API Detection d'Anomalies Reseau - ITGATE PFE 2026",
    description="Systeme ML de detection d'intrusions reseau en temps reel",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# CHARGEMENT DES MODELES
# ============================================================
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
            print(f"WARN {key} non disponible: {e}")

    print(f"OK {len(MODELS)} modeles charges: {list(MODELS.keys())}")

except Exception as e:
    print(f"ERR Erreur chargement: {e}")
    MODELS = {}
    scaler = None
    feature_names = []

# Compatibilite
rf_model  = MODELS.get('random_forest')
iso_model = MODELS.get('isolation_forest')

alert_history: List[dict] = []

# Colonnes sur lesquelles le scaler a ete entraine
SCALER_COLS = [
    'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts',
    'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes',
    'inter_arrival_time', 'pkt_ratio'
]

# Mapping flexible des noms de colonnes
# Cle = variantes possibles dans Excel/JSON, Valeur = nom interne attendu
COLUMN_ALIASES = {
    # id.orig_p
    'id.orig_p':   'id.orig_p',
    'id_orig_p':   'id.orig_p',
    'orig_port':   'id.orig_p',
    # id.resp_p
    'id.resp_p':   'id.resp_p',
    'id_resp_p':   'id.resp_p',
    'resp_port':   'id.resp_p',
    'dst_port':    'id.resp_p',
    # autres champs directs
    'duration':           'duration',
    'orig_bytes':         'orig_bytes',
    'resp_bytes':         'resp_bytes',
    'missed_bytes':       'missed_bytes',
    'orig_pkts':          'orig_pkts',
    'orig_ip_bytes':      'orig_ip_bytes',
    'resp_pkts':          'resp_pkts',
    'resp_ip_bytes':      'resp_ip_bytes',
    'is_orig_local':      'is_orig_local',
    'orig_h_count':       'orig_h_count',
    'resp_h_count':       'resp_h_count',
    'is_well_known_port': 'is_well_known_port',
    'hour':               'hour',
    'minute':             'minute',
    'day_of_week':        'day_of_week',
    'inter_arrival_time': 'inter_arrival_time',
    'pkt_ratio':          'pkt_ratio',
    'avg_orig_pkt_size':  'avg_orig_pkt_size',
    'avg_resp_pkt_size':  'avg_resp_pkt_size',
}

# ============================================================
# FONCTIONS UTILITAIRES
# ============================================================
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
    """
    Construit le DataFrame de features a partir d'un objet TrafficData.
    Applique le scaler sur SCALER_COLS puis retourne les colonnes dans
    l'ordre exact de feature_names.
    """
    features = {
        'id.orig_p':          float(data.id_orig_p),
        'id.resp_p':          float(data.id_resp_p),
        'duration':           float(data.duration),
        'orig_bytes':         float(data.orig_bytes),
        'resp_bytes':         float(data.resp_bytes),
        'missed_bytes':       float(data.missed_bytes),
        'orig_pkts':          float(data.orig_pkts),
        'orig_ip_bytes':      float(data.orig_ip_bytes),
        'resp_pkts':          float(data.resp_pkts),
        'resp_ip_bytes':      float(data.resp_ip_bytes),
        'is_orig_local':      float(data.is_orig_local),
        'orig_h_count':       float(data.orig_h_count),
        'resp_h_count':       float(data.resp_h_count),
        'is_well_known_port': float(data.is_well_known_port),
        'hour':               float(data.hour),
        'minute':             float(data.minute),
        'day_of_week':        float(data.day_of_week),
        'inter_arrival_time': float(data.inter_arrival_time),
        'pkt_ratio':          float(data.pkt_ratio),
        'avg_orig_pkt_size':  float(data.avg_orig_pkt_size),
        'avg_resp_pkt_size':  float(data.avg_resp_pkt_size),
    }
    df = pd.DataFrame([features])

    # Appliquer le scaler uniquement sur les colonnes concernees
    cols_to_scale = [c for c in SCALER_COLS if c in df.columns]
    if cols_to_scale:
        df[cols_to_scale] = scaler.transform(df[cols_to_scale])

    # Retourner dans l'ordre exact attendu par les modeles
    return df[feature_names]


def normaliser_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalise un DataFrame brut venant d'un upload Excel :
    1. Renomme les colonnes via COLUMN_ALIASES (insensible a la casse)
    2. Applique le scaler sur SCALER_COLS si les donnees semblent brutes
    3. Retourne le DataFrame dans l'ordre feature_names
    """
    # 1. Renommer les colonnes
    rename_map = {}
    for col in df.columns:
        col_clean = col.strip().lower().replace(' ', '_')
        if col_clean in COLUMN_ALIASES:
            rename_map[col] = COLUMN_ALIASES[col_clean]
        elif col.strip() in COLUMN_ALIASES:
            rename_map[col] = COLUMN_ALIASES[col.strip()]
    if rename_map:
        df = df.rename(columns=rename_map)

    # 2. Verifier que toutes les features sont presentes
    missing = [f for f in feature_names if f not in df.columns]
    if missing:
        raise ValueError(f"Colonnes manquantes dans le fichier : {missing}")

    # 3. Convertir en float
    for col in feature_names:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

    # 4. Detecter si les donnees sont brutes (non normalisees)
    #    Heuristique : si orig_bytes ou resp_bytes > 1, c'est brut
    cols_to_scale = [c for c in SCALER_COLS if c in df.columns]
    needs_scaling = False
    for check_col in ['orig_bytes', 'resp_bytes', 'duration']:
        if check_col in df.columns and df[check_col].max() > 1.0:
            needs_scaling = True
            break

    if needs_scaling and cols_to_scale:
        df[cols_to_scale] = scaler.transform(df[cols_to_scale])

    return df[feature_names]


def predire_depuis_row(row: pd.Series, model_key: str) -> dict:
    """
    Execute la prediction pour une ligne deja normalisee.
    Retourne un dict avec prediction, label, confidence, risk_level.
    """
    model = MODELS[model_key]
    X = pd.DataFrame([row])

    if model_key == 'isolation_forest':
        raw_pred = model.predict(X)[0]
        prediction = 1 if raw_pred == -1 else 0
        scores = model.score_samples(X)
        confidence = round(min(abs(float(scores[0])) * 100, 99.9), 2)
    else:
        prediction = int(model.predict(X)[0])
        probas = model.predict_proba(X)[0]
        confidence = round(float(max(probas)) * 100, 2)

    risk_level = determine_risk_level(confidence, prediction)
    label = "Malicious" if prediction == 1 else "Benign"
    return {
        "prediction": prediction,
        "label":      label,
        "confidence": confidence,
        "risk_level": risk_level,
    }


# ============================================================
# ENDPOINTS
# ============================================================
@app.get("/", tags=["Status"])
def racine():
    return {
        "message": "API Detection Anomalies Reseau - ITGATE PFE 2026",
        "status": "operational",
        "modeles_charges": len(MODELS) > 0,
        "nb_modeles": len(MODELS),
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
    """Analyser une connexion reseau et detecter les anomalies."""
    if not MODELS or scaler is None:
        raise HTTPException(status_code=503, detail="Modeles non disponibles")
    try:
        # 1. Choisir le modele demande
        model_key = (data.model or 'random_forest').strip().lower()
        if model_key not in MODELS:
            model_key = 'random_forest'

        # 2. Preparer les features
        X = preparer_features(data)

        # 3. Predire
        result = predire_depuis_row(X.iloc[0], model_key)

        # 4. Message
        alert_msg = (
            f"Trafic malveillant detecte ! Confiance : {result['confidence']}%"
            if result['prediction'] == 1
            else f"Trafic normal. Confiance : {result['confidence']}%"
        )

        alert_entry = {
            "timestamp":  datetime.now().isoformat(),
            "prediction": result['prediction'],
            "label":      result['label'],
            "confidence": result['confidence'],
            "risk_level": result['risk_level'],
            "model":      model_key,
            "data":       data.dict()
        }
        alert_history.append(alert_entry)
        if len(alert_history) > 1000:
            alert_history.pop(0)

        return PredictionResult(
            prediction=result['prediction'],
            label=result['label'],
            confidence=result['confidence'],
            risk_level=result['risk_level'],
            model_used=model_key,
            alert_message=alert_msg
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur de prediction: {str(e)}")


@app.post("/predict/batch", tags=["Prediction"])
async def predire_batch(
    file: UploadFile = File(...),
    model: Optional[str] = Query(default="random_forest")
):
    """
    Analyser un fichier Excel (.xlsx ou .xls) en masse.
    Chaque ligne = une connexion reseau a analyser.
    """
    if not MODELS or scaler is None:
        raise HTTPException(status_code=503, detail="Modeles non disponibles")

    # Validation extension
    filename = file.filename or ""
    if not (filename.endswith('.xlsx') or filename.endswith('.xls') or
            filename.endswith('.csv')):
        raise HTTPException(
            status_code=400,
            detail="Format non supporte. Utilisez .xlsx, .xls ou .csv"
        )

    try:
        content = await file.read()
        if len(content) == 0:
            raise HTTPException(status_code=400, detail="Fichier vide")

        # Lire le fichier
        if filename.endswith('.csv'):
            df_raw = pd.read_csv(io.BytesIO(content))
        else:
            # Essayer openpyxl d'abord, puis xlrd pour .xls
            try:
                df_raw = pd.read_excel(io.BytesIO(content), engine='openpyxl')
            except Exception:
                df_raw = pd.read_excel(io.BytesIO(content), engine='xlrd')

        if df_raw.empty:
            raise HTTPException(status_code=400, detail="Le fichier ne contient aucune donnee")

        # Supprimer les lignes entierement vides
        df_raw = df_raw.dropna(how='all').reset_index(drop=True)

        if len(df_raw) == 0:
            raise HTTPException(status_code=400, detail="Le fichier ne contient aucune ligne valide")

        # Normaliser
        df = normaliser_dataframe(df_raw.copy())

        # Choisir le modele
        model_key = (model or 'random_forest').strip().lower()
        if model_key not in MODELS:
            model_key = 'random_forest'

        # Analyser chaque ligne
        resultats = []
        for i, row in df.iterrows():
            try:
                result = predire_depuis_row(row, model_key)
                resultats.append({
                    "index":      int(i),
                    "prediction": result['prediction'],
                    "label":      result['label'],
                    "confidence": result['confidence'],
                    "risk_level": result['risk_level'],
                    "model":      model_key,
                })

                alert_entry = {
                    "timestamp":  datetime.now().isoformat(),
                    "prediction": result['prediction'],
                    "label":      result['label'],
                    "confidence": result['confidence'],
                    "risk_level": result['risk_level'],
                    "model":      model_key,
                }
                alert_history.append(alert_entry)
                if len(alert_history) > 1000:
                    alert_history.pop(0)

            except Exception as row_err:
                resultats.append({
                    "index": int(i),
                    "error": str(row_err),
                })

        total        = len(resultats)
        malveillants = sum(1 for r in resultats if r.get('prediction') == 1)
        benins       = total - malveillants

        return {
            "total":           total,
            "malveillants":    malveillants,
            "benins":          benins,
            "taux_detection":  round(malveillants / total * 100, 2) if total > 0 else 0,
            "model_used":      model_key,
            "resultats":       resultats,
        }

    except HTTPException:
        raise
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur traitement fichier: {str(e)}")


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