# backend/schemas.py
from pydantic import BaseModel
from typing import Optional

class TrafficData(BaseModel):
    """
    Données d'une connexion réseau à analyser.
    Chaque champ représente une caractéristique du flux réseau.
    """
    duration: float = 0.0           # Durée de la connexion (secondes)
    orig_bytes: float = 0.0         # Octets envoyés par la source
    resp_bytes: float = 0.0         # Octets envoyés par la destination
    orig_pkts: float = 1.0          # Nombre de paquets envoyés
    resp_pkts: float = 1.0          # Nombre de paquets reçus
    orig_ip_bytes: float = 0.0      # Octets IP envoyés
    resp_ip_bytes: float = 0.0      # Octets IP reçus
    pkt_ratio: float = 1.0          # Ratio paquets orig/réponse
    avg_orig_pkt_size: float = 0.0  # Taille moyenne paquets source
    avg_resp_pkt_size: float = 0.0  # Taille moyenne paquets destination
    is_orig_local: int = 1          # IP source locale (1) ou externe (0)
    is_well_known_port: int = 0     # Port connu < 1024 (1) ou non (0)
    hour: int = 12                  # Heure de la connexion
    minute: int = 0                 # Minute de la connexion
    day_of_week: int = 0            # Jour de la semaine (0=lundi)
    inter_arrival_time: float = 0.0 # Délai entre connexions successives

class PredictionResult(BaseModel):
    """Résultat de la prédiction du modèle ML"""
    prediction: int           # 0 = Bénin, 1 = Malveillant
    label: str                # "Benign" ou "Malicious"
    confidence: float         # Pourcentage de confiance (0-100)
    risk_level: str           # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    model_used: str           # Nom du modèle utilisé
    alert_message: str        # Message lisible pour l'analyste SOC