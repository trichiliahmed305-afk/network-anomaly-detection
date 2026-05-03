# backend/pdf_report.py
from fpdf import FPDF
from datetime import datetime
from typing import List
import os

class RapportAnomalies(FPDF):
    """Générateur de rapport PDF pour les anomalies réseau détectées"""

    def header(self):
        """En-tête de chaque page"""
        # Logo / Titre
        self.set_font('Helvetica', 'B', 16)
        self.set_fill_color(13, 27, 42)      # Bleu nuit
        self.set_text_color(255, 255, 255)   # Blanc
        self.cell(0, 15, 'ITGATE — Rapport de Detection d Anomalies Reseau', 
                  fill=True, align='C', new_x='LMARGIN', new_y='NEXT')
        self.set_text_color(0, 0, 0)
        self.ln(5)

    def footer(self):
        """Pied de page"""
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, 
                  f'ITGATE PFE 2026 — Page {self.page_no()} — Confidentiel',
                  align='C')

    def titre_section(self, titre: str):
        """Titre de section avec fond coloré"""
        self.set_font('Helvetica', 'B', 12)
        self.set_fill_color(52, 152, 219)    # Bleu
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, titre, fill=True, 
                  new_x='LMARGIN', new_y='NEXT')
        self.set_text_color(0, 0, 0)
        self.ln(3)

    def ligne_info(self, label: str, valeur: str):
        """Ligne d'information label : valeur"""
        self.set_font('Helvetica', 'B', 10)
        self.cell(60, 8, f'{label} :', new_x='RIGHT', new_y='LAST')
        self.set_font('Helvetica', '', 10)
        self.cell(0, 8, str(valeur), new_x='LMARGIN', new_y='NEXT')


def generer_rapport_pdf(alert_history: List[dict]) -> bytes:
    """
    Génère un rapport PDF complet des incidents détectés.
    Retourne les bytes du PDF.
    """
    pdf = RapportAnomalies()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    now = datetime.now()
    total = len(alert_history)
    malveillants = sum(1 for a in alert_history if a['prediction'] == 1)
    benins = total - malveillants
    taux = round((malveillants / total * 100), 2) if total > 0 else 0

    # ============================================================
    # PAGE 1 — RÉSUMÉ EXÉCUTIF
    # ============================================================
    pdf.titre_section("1. INFORMATIONS DU RAPPORT")
    pdf.ligne_info("Date de generation", now.strftime("%d/%m/%Y a %H:%M:%S"))
    pdf.ligne_info("Systeme", "ITGATE Network Anomaly Detection v1.0")
    pdf.ligne_info("Modele ML utilise", "Random Forest (Accuracy: 99.49%)")
    pdf.ligne_info("Dataset", "CTU-IoT-Malware-Capture")
    pdf.ln(5)

    pdf.titre_section("2. RESUME EXECUTIF")
    pdf.ligne_info("Total connexions analysees", str(total))
    pdf.ligne_info("Connexions maleveilantes", f"{malveillants} ({taux}%)")
    pdf.ligne_info("Connexions benignes", f"{benins}")
    pdf.ligne_info("Periode analysee", 
                   f"{alert_history[0]['timestamp'][:10]} au {alert_history[-1]['timestamp'][:10]}"
                   if alert_history else "N/A")
    pdf.ln(5)

    # Niveaux de risque
    niveaux = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for a in alert_history:
        niveaux[a['risk_level']] = niveaux.get(a['risk_level'], 0) + 1

    pdf.titre_section("3. DISTRIBUTION DES NIVEAUX DE RISQUE")
    
    couleurs = {
        'LOW':      (46, 204, 113),   # Vert
        'MEDIUM':   (241, 196, 15),   # Jaune
        'HIGH':     (230, 126, 34),   # Orange
        'CRITICAL': (231, 76, 60),    # Rouge
    }
    icones = {'LOW': 'FAIBLE', 'MEDIUM': 'MOYEN', 'HIGH': 'ELEVE', 'CRITICAL': 'CRITIQUE'}

    for level, count in niveaux.items():
        r, g, b = couleurs[level]
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 10)
        pct = round(count / total * 100, 1) if total > 0 else 0
        pdf.cell(0, 9,
                 f"  {icones[level]} ({level}) : {count} alertes — {pct}%",
                 fill=True, new_x='LMARGIN', new_y='NEXT')
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)

    pdf.ln(5)

    # ============================================================
    # PAGE 2 — JOURNAL DES ALERTES
    # ============================================================
    pdf.add_page()
    pdf.titre_section("4. JOURNAL DES ALERTES (50 dernières)")

    # En-tête du tableau
    pdf.set_font('Helvetica', 'B', 9)
    pdf.set_fill_color(44, 62, 80)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(45, 8, 'Horodatage',     fill=True, border=1)
    pdf.cell(25, 8, 'Classification', fill=True, border=1)
    pdf.cell(25, 8, 'Confiance',      fill=True, border=1)
    pdf.cell(25, 8, 'Niveau Risque',  fill=True, border=1)
    pdf.cell(0,  8, 'Message',        fill=True, border=1,
             new_x='LMARGIN', new_y='NEXT')
    pdf.set_text_color(0, 0, 0)

    # Lignes du tableau
    alertes_recentes = list(reversed(alert_history))[:50]
    for i, alerte in enumerate(alertes_recentes):
        # Couleur alternée
        if i % 2 == 0:
            pdf.set_fill_color(236, 240, 241)
        else:
            pdf.set_fill_color(255, 255, 255)

        pdf.set_font('Helvetica', '', 8)
        ts = alerte['timestamp'][:19].replace('T', ' ')
        label = alerte['label']
        conf = f"{alerte['confidence']}%"
        risk = alerte['risk_level']

        # Couleur du niveau de risque
        if risk == 'CRITICAL':
            msg = "ALERTE CRITIQUE"
        elif risk == 'HIGH':
            msg = "Risque eleve"
        elif risk == 'MEDIUM':
            msg = "Risque moyen"
        else:
            msg = "Trafic normal"

        pdf.cell(45, 7, ts,    fill=True, border=1)
        pdf.cell(25, 7, label, fill=True, border=1)
        pdf.cell(25, 7, conf,  fill=True, border=1)
        pdf.cell(25, 7, risk,  fill=True, border=1)
        pdf.cell(0,  7, msg,   fill=True, border=1,
                 new_x='LMARGIN', new_y='NEXT')

    pdf.ln(5)

    # ============================================================
    # PAGE 3 — RECOMMANDATIONS
    # ============================================================
    pdf.add_page()
    pdf.titre_section("5. RECOMMANDATIONS DE SECURITE")

    recommandations = []
    if niveaux['CRITICAL'] > 0:
        recommandations.append(
            f"URGENT : {niveaux['CRITICAL']} alerte(s) CRITIQUE(S) detectee(s). "
            "Isoler immediatement les machines sources."
        )
    if niveaux['HIGH'] > 0:
        recommandations.append(
            f"PRIORITE HAUTE : {niveaux['HIGH']} connexion(s) a risque eleve. "
            "Analyser les logs reseau des IP sources."
        )
    if taux > 50:
        recommandations.append(
            f"ATTENTION : Taux de trafic malveillant eleve ({taux}%). "
            "Verifier la configuration du pare-feu."
        )
    if not recommandations:
        recommandations.append(
            "Aucune alerte critique detectee. Continuer la surveillance normale."
        )

    pdf.set_font('Helvetica', '', 10)
    for i, rec in enumerate(recommandations, 1):
        pdf.set_font('Helvetica', 'B', 10)
        pdf.cell(8, 8, f"{i}.")
        pdf.set_font('Helvetica', '', 10)
        pdf.multi_cell(0, 8, rec)
        pdf.ln(2)

    pdf.ln(5)
    pdf.titre_section("6. INFORMATIONS TECHNIQUES")
    pdf.ligne_info("Framework ML", "Scikit-learn 1.4.2")
    pdf.ligne_info("API Backend", "FastAPI + Uvicorn")
    pdf.ligne_info("Hebergement", "Render.com (Frankfurt EU)")
    pdf.ligne_info("Features utilisees", "21 features reseau extraites")
    pdf.ligne_info("Algorithme principal", "Random Forest (100 estimateurs)")

    # Signature
    pdf.ln(10)
    pdf.set_font('Helvetica', 'I', 9)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 8,
             f"Rapport genere automatiquement le {now.strftime('%d/%m/%Y a %H:%M:%S')} "
             f"par ITGATE Anomaly Detection System",
             align='C')

    return bytes(pdf.output())