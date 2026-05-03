# backend/realtime_simulator.py
"""
Simulateur de détection d'anomalies réseau en temps réel.
Lit un fichier CSV et envoie chaque connexion à l'API /predict.
"""

import requests
import pandas as pd
import numpy as np
import time
import json
from datetime import datetime

API_URL = "https://itgate-anomaly-api.onrender.com"

# ============================================================
# DONNÉES DE TEST SIMULÉES
# ============================================================
CONNEXIONS_TEST = [
    # Connexions normales
    {
        "nom": "Trafic HTTP normal",
        "data": {
            "id_orig_p": 12345, "id_resp_p": 80,
            "duration": 1.5, "orig_bytes": 500.0, "resp_bytes": 200.0,
            "missed_bytes": 0.0, "orig_pkts": 5.0, "orig_ip_bytes": 600.0,
            "resp_pkts": 3.0, "resp_ip_bytes": 250.0,
            "is_orig_local": 1, "orig_h_count": 10.0, "resp_h_count": 5.0,
            "is_well_known_port": 1, "hour": 14, "minute": 30,
            "day_of_week": 1, "inter_arrival_time": 0.5,
            "pkt_ratio": 1.67, "avg_orig_pkt_size": 100.0, "avg_resp_pkt_size": 62.5
        }
    },
    {
        "nom": "Trafic DNS normal",
        "data": {
            "id_orig_p": 54321, "id_resp_p": 53,
            "duration": 0.1, "orig_bytes": 100.0, "resp_bytes": 150.0,
            "missed_bytes": 0.0, "orig_pkts": 2.0, "orig_ip_bytes": 120.0,
            "resp_pkts": 2.0, "resp_ip_bytes": 170.0,
            "is_orig_local": 1, "orig_h_count": 5.0, "resp_h_count": 2.0,
            "is_well_known_port": 1, "hour": 10, "minute": 15,
            "day_of_week": 2, "inter_arrival_time": 0.05,
            "pkt_ratio": 1.0, "avg_orig_pkt_size": 40.0, "avg_resp_pkt_size": 56.7
        }
    },
    # Connexions suspectes — IoT Malware
    {
        "nom": "SCAN PORT Telnet (Mirai)",
        "data": {
            "id_orig_p": 54321, "id_resp_p": 23,
            "duration": 0.001, "orig_bytes": 0.0, "resp_bytes": 0.0,
            "missed_bytes": 0.0, "orig_pkts": 1.0, "orig_ip_bytes": 40.0,
            "resp_pkts": 0.0, "resp_ip_bytes": 0.0,
            "is_orig_local": 0, "orig_h_count": 500.0, "resp_h_count": 1.0,
            "is_well_known_port": 1, "hour": 3, "minute": 0,
            "day_of_week": 6, "inter_arrival_time": 0.001,
            "pkt_ratio": 1.0, "avg_orig_pkt_size": 20.0, "avg_resp_pkt_size": 0.0
        }
    },
    {
        "nom": "ATTAQUE SSH Brute Force",
        "data": {
            "id_orig_p": 45678, "id_resp_p": 22,
            "duration": 0.5, "orig_bytes": 200.0, "resp_bytes": 50.0,
            "missed_bytes": 0.0, "orig_pkts": 10.0, "orig_ip_bytes": 300.0,
            "resp_pkts": 5.0, "resp_ip_bytes": 100.0,
            "is_orig_local": 0, "orig_h_count": 1000.0, "resp_h_count": 1.0,
            "is_well_known_port": 1, "hour": 2, "minute": 30,
            "day_of_week": 5, "inter_arrival_time": 0.05,
            "pkt_ratio": 2.0, "avg_orig_pkt_size": 27.3, "avg_resp_pkt_size": 16.7
        }
    },
    {
        "nom": "EXFILTRATION données",
        "data": {
            "id_orig_p": 11111, "id_resp_p": 443,
            "duration": 120.0, "orig_bytes": 50000.0, "resp_bytes": 100.0,
            "missed_bytes": 500.0, "orig_pkts": 500.0, "orig_ip_bytes": 51000.0,
            "resp_pkts": 10.0, "resp_ip_bytes": 200.0,
            "is_orig_local": 1, "orig_h_count": 2.0, "resp_h_count": 1.0,
            "is_well_known_port": 1, "hour": 4, "minute": 0,
            "day_of_week": 6, "inter_arrival_time": 0.24,
            "pkt_ratio": 50.0, "avg_orig_pkt_size": 101.6, "avg_resp_pkt_size": 18.2
        }
    },
    {
        "nom": "SCAN réseau interne",
        "data": {
            "id_orig_p": 33333, "id_resp_p": 445,
            "duration": 0.002, "orig_bytes": 0.0, "resp_bytes": 0.0,
            "missed_bytes": 0.0, "orig_pkts": 1.0, "orig_ip_bytes": 48.0,
            "resp_pkts": 0.0, "resp_ip_bytes": 0.0,
            "is_orig_local": 0, "orig_h_count": 800.0, "resp_h_count": 1.0,
            "is_well_known_port": 1, "hour": 1, "minute": 45,
            "day_of_week": 6, "inter_arrival_time": 0.002,
            "pkt_ratio": 1.0, "avg_orig_pkt_size": 24.0, "avg_resp_pkt_size": 0.0
        }
    },
    {
        "nom": "Trafic HTTPS normal",
        "data": {
            "id_orig_p": 55555, "id_resp_p": 443,
            "duration": 2.5, "orig_bytes": 1000.0, "resp_bytes": 5000.0,
            "missed_bytes": 0.0, "orig_pkts": 15.0, "orig_ip_bytes": 1200.0,
            "resp_pkts": 20.0, "resp_ip_bytes": 5500.0,
            "is_orig_local": 1, "orig_h_count": 8.0, "resp_h_count": 100.0,
            "is_well_known_port": 1, "hour": 16, "minute": 20,
            "day_of_week": 3, "inter_arrival_time": 0.15,
            "pkt_ratio": 0.71, "avg_orig_pkt_size": 75.0, "avg_resp_pkt_size": 257.1
        }
    },
    {
        "nom": "BOTNET C2 Communication",
        "data": {
            "id_orig_p": 22222, "id_resp_p": 6667,
            "duration": 300.0, "orig_bytes": 500.0, "resp_bytes": 500.0,
            "missed_bytes": 0.0, "orig_pkts": 50.0, "orig_ip_bytes": 600.0,
            "resp_pkts": 50.0, "resp_ip_bytes": 600.0,
            "is_orig_local": 1, "orig_h_count": 3.0, "resp_h_count": 1.0,
            "is_well_known_port": 0, "hour": 3, "minute": 30,
            "day_of_week": 6, "inter_arrival_time": 6.0,
            "pkt_ratio": 1.0, "avg_orig_pkt_size": 11.8, "avg_resp_pkt_size": 11.8
        }
    },
]


def analyser_connexion(nom: str, data: dict) -> dict:
    """Envoie une connexion à l'API et retourne le résultat"""
    try:
        response = requests.post(
            f"{API_URL}/predict",
            json=data,
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def afficher_resultat(nom: str, result: dict):
    """Affiche le résultat de manière lisible dans le terminal"""
    if "error" in result:
        print(f"  ❌ ERREUR : {result['error']}")
        return

    prediction = result.get("prediction", 0)
    label      = result.get("label", "?")
    confidence = result.get("confidence", 0)
    risk       = result.get("risk_level", "LOW")

    # Icônes et couleurs terminal
    icons = {
        "Benign":    "✅",
        "Malicious": "🚨"
    }
    risk_icons = {
        "LOW":      "🟢",
        "MEDIUM":   "🟡",
        "HIGH":     "🟠",
        "CRITICAL": "🔴"
    }

    icon      = icons.get(label, "⚪")
    risk_icon = risk_icons.get(risk, "⚪")

    print(f"  {icon} {label:<12} | Confiance: {confidence:>6.1f}% | Risque: {risk_icon} {risk:<8} | {nom}")


def lancer_simulation(intervalle: float = 1.5):
    """
    Lance la simulation en temps réel.
    intervalle = délai en secondes entre chaque analyse
    """
    print("\n" + "="*70)
    print("  🛡️  ITGATE — Simulation Détection Temps Réel")
    print(f"  📡  API : {API_URL}")
    print(f"  ⏱️   Intervalle : {intervalle}s entre chaque analyse")
    print("="*70)

    # Vérifier que l'API est en ligne
    print("\n🔌 Vérification de la connexion API...")
    try:
        r = requests.get(f"{API_URL}/status", timeout=5)
        status = r.json()
        if status.get("modeles", {}).get("random_forest") == "loaded":
            print("  ✅ API connectée — Modèles chargés\n")
        else:
            print("  ⚠️  API connectée mais modèles non chargés\n")
    except Exception:
        print("  ❌ API non disponible — Vérifiez la connexion\n")
        return

    print(f"{'─'*70}")
    print(f"  {'RÉSULTAT':<14} | {'CONFIANCE':>9} | {'RISQUE':<12} | CONNEXION")
    print(f"{'─'*70}")

    stats = {"total": 0, "malicious": 0, "benign": 0}

    for connexion in CONNEXIONS_TEST:
        nom  = connexion["nom"]
        data = connexion["data"]

        result = analyser_connexion(nom, data)
        afficher_resultat(nom, result)

        if "error" not in result:
            stats["total"] += 1
            if result.get("prediction") == 1:
                stats["malicious"] += 1
            else:
                stats["benign"] += 1

        time.sleep(intervalle)

    # Résumé final
    print(f"\n{'='*70}")
    print(f"  📊 RÉSUMÉ DE LA SESSION")
    print(f"{'─'*70}")
    print(f"  Total analysé  : {stats['total']}")
    print(f"  ✅ Bénins       : {stats['benign']}")
    print(f"  🚨 Malveillants : {stats['malicious']}")
    if stats['total'] > 0:
        taux = round(stats['malicious'] / stats['total'] * 100, 1)
        print(f"  📈 Taux menaces : {taux}%")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    lancer_simulation(intervalle=1.5)