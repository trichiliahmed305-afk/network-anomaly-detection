# backend/pdf_report.py
from fpdf import FPDF
from datetime import datetime
from typing import List


class RapportAnomalies(FPDF):

    def header(self):
        # Bande bleue en haut
        self.set_fill_color(13, 27, 42)
        self.rect(0, 0, 210, 18, 'F')
        self.set_font('Helvetica', 'B', 13)
        self.set_text_color(255, 255, 255)
        self.set_xy(0, 3)
        self.cell(0, 10, 'ITGATE - Network Anomaly Detection System', align='C')
        self.set_text_color(100, 160, 220)
        self.set_font('Helvetica', '', 7)
        self.set_xy(0, 11)
        self.cell(0, 5, 'PFE 2026 - Cybersecurity R&D - Sousse, Tunisie', align='C')
        self.set_text_color(0, 0, 0)
        self.ln(12)

    def footer(self):
        self.set_y(-12)
        self.set_fill_color(13, 27, 42)
        self.rect(0, self.get_y(), 210, 15, 'F')
        self.set_font('Helvetica', 'I', 7)
        self.set_text_color(150, 180, 210)
        self.cell(0, 8,
                  f'ITGATE PFE 2026 - Page {self.page_no()} - Confidentiel - '
                  f'Genere le {datetime.now().strftime("%d/%m/%Y")}',
                  align='C')
        self.set_text_color(0, 0, 0)

    def section_title(self, num: str, titre: str, color=(52, 120, 200)):
        self.ln(4)
        r, g, b = color
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 10)
        self.cell(8, 8, num, fill=True, border=0)
        self.set_fill_color(r + 30, g + 30, b + 30)
        self.cell(0, 8, f'  {titre}', fill=True, border=0,
                  new_x='LMARGIN', new_y='NEXT')
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def info_row(self, label: str, valeur: str, label_color=(60, 60, 60)):
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(*label_color)
        self.cell(55, 7, label + ' :', new_x='RIGHT', new_y='LAST')
        self.set_font('Helvetica', '', 9)
        self.set_text_color(30, 30, 30)
        self.cell(0, 7, str(valeur), new_x='LMARGIN', new_y='NEXT')

    def kpi_box(self, label: str, valeur: str, couleur_rgb, x, y, w=42, h=20):
        r, g, b = couleur_rgb
        self.set_xy(x, y)
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 14)
        self.cell(w, 10, valeur, fill=True, align='C', new_x='RIGHT', new_y='LAST')
        self.set_xy(x, y + 10)
        self.set_fill_color(r - 20, g - 20, b - 20)
        self.set_font('Helvetica', '', 7)
        self.cell(w, 7, label, fill=True, align='C', new_x='RIGHT', new_y='LAST')
        self.set_text_color(0, 0, 0)


def generer_rapport_pdf(alert_history: List[dict]) -> bytes:
    pdf = RapportAnomalies()
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    now   = datetime.now()
    total = len(alert_history)
    malveillants = sum(1 for a in alert_history if a['prediction'] == 1)
    benins       = total - malveillants
    taux         = round((malveillants / total * 100), 1) if total > 0 else 0

    niveaux = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for a in alert_history:
        niveaux[a.get('risk_level', 'LOW')] = niveaux.get(a.get('risk_level', 'LOW'), 0) + 1

    # Modeles utilises
    models_used = {}
    for a in alert_history:
        m = a.get('model', 'random_forest')
        models_used[m] = models_used.get(m, 0) + 1

    # ── PAGE 1 ──────────────────────────────────────────────

    # Infos rapport
    pdf.section_title('1', 'INFORMATIONS DU RAPPORT', (20, 60, 120))
    pdf.info_row('Date de generation', now.strftime('%d/%m/%Y a %H:%M:%S'))
    pdf.info_row('Systeme', 'ITGATE Network Anomaly Detection v1.0')
    pdf.info_row('Dataset', 'CTU-IoT-Malware-Capture (Stratosphere Lab)')
    pdf.info_row('Modeles utilises', ', '.join(models_used.keys()) or 'N/A')
    pdf.info_row('Periode analysee',
                 f"{alert_history[-1]['timestamp'][:10]} au {alert_history[0]['timestamp'][:10]}"
                 if alert_history else 'N/A')
    pdf.ln(4)

    # KPI boxes
    pdf.section_title('2', 'RESUME EXECUTIF', (20, 100, 160))
    pdf.ln(2)

    kpis = [
        ('Total Analyses', str(total),       (41, 128, 185)),
        ('Malveillants',   str(malveillants), (192, 57, 43)),
        ('Benins',         str(benins),       (39, 174, 96)),
        ('Taux Detection', f'{taux}%',        (142, 68, 173)),
    ]
    start_x = 14
    for i, (label, val, color) in enumerate(kpis):
        pdf.kpi_box(label, val, color, start_x + i * 46, pdf.get_y())

    pdf.ln(26)

    # Distribution niveaux de risque
    pdf.section_title('3', 'DISTRIBUTION DES NIVEAUX DE RISQUE', (150, 50, 50))

    risk_config = {
        'LOW':      ('FAIBLE',   (39, 174, 96)),
        'MEDIUM':   ('MOYEN',    (230, 126, 34)),
        'HIGH':     ('ELEVE',    (211, 84, 0)),
        'CRITICAL': ('CRITIQUE', (192, 57, 43)),
    }

    for level, (label_fr, (r, g, b)) in risk_config.items():
        count = niveaux.get(level, 0)
        pct   = round(count / total * 100, 1) if total > 0 else 0
        bar_w = int((pct / 100) * 130)

        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(r, g, b)
        pdf.cell(30, 7, f'{label_fr}', new_x='RIGHT', new_y='LAST')
        pdf.set_text_color(60, 60, 60)
        pdf.set_font('Helvetica', '', 9)
        pdf.cell(18, 7, f'{count} alerte(s)', new_x='RIGHT', new_y='LAST')

        # Barre de progression
        y_bar = pdf.get_y() + 2
        pdf.set_fill_color(220, 220, 220)
        pdf.rect(pdf.get_x() + 2, y_bar, 130, 4, 'F')
        if bar_w > 0:
            pdf.set_fill_color(r, g, b)
            pdf.rect(pdf.get_x() + 2, y_bar, bar_w, 4, 'F')

        pdf.set_text_color(60, 60, 60)
        pdf.cell(140, 7, f'  {pct}%', new_x='LMARGIN', new_y='NEXT')

    pdf.ln(2)

    # Modeles utilises
    if models_used:
        pdf.section_title('4', 'MODELES ML UTILISES', (60, 100, 60))
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_fill_color(230, 240, 255)
        pdf.cell(70, 7, 'Modele', fill=True, border=1)
        pdf.cell(30, 7, 'Utilisations', fill=True, border=1)
        pdf.cell(0,  7, 'Pourcentage', fill=True, border=1, new_x='LMARGIN', new_y='NEXT')

        for i, (model, count) in enumerate(models_used.items()):
            pct_m = round(count / total * 100, 1) if total > 0 else 0
            pdf.set_fill_color(245, 248, 255) if i % 2 == 0 else pdf.set_fill_color(255, 255, 255)
            pdf.set_font('Helvetica', '', 9)
            pdf.cell(70, 7, model.replace('_', ' ').title(), fill=True, border=1)
            pdf.cell(30, 7, str(count), fill=True, border=1, align='C')
            pdf.cell(0,  7, f'{pct_m}%', fill=True, border=1, align='C',
                     new_x='LMARGIN', new_y='NEXT')

    # ── PAGE 2 — JOURNAL DES ALERTES ────────────────────────
    pdf.add_page()
    pdf.section_title('5', 'JOURNAL DES ALERTES (50 dernieres)', (80, 40, 120))

    # En-tete tableau
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(20, 50, 100)
    pdf.set_text_color(255, 255, 255)
    cols = [
        ('Horodatage',      38),
        ('Classification',  28),
        ('Confiance',       22),
        ('Niveau Risque',   28),
        ('Modele',          32),
        ('Message',         42),
    ]
    for label, w in cols:
        pdf.cell(w, 8, label, fill=True, border=1)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    # Lignes tableau
    alertes = list(reversed(alert_history))[:50]
    for i, alerte in enumerate(alertes):
        bg = (245, 248, 252) if i % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_font('Helvetica', '', 7)

        ts    = alerte.get('timestamp', '')[:19].replace('T', ' ')
        label = alerte.get('label', '?')
        conf  = f"{alerte.get('confidence', 0)}%"
        risk  = alerte.get('risk_level', 'LOW')
        model = alerte.get('model', 'random_forest').replace('_', ' ').title()

        if risk == 'CRITICAL':
            msg = 'Critique - Action immediate'
        elif risk == 'HIGH':
            msg = 'Risque eleve'
        elif risk == 'MEDIUM':
            msg = 'Risque moyen'
        else:
            msg = 'Trafic normal'

        # Couleur label
        if label == 'Malicious':
            pdf.set_text_color(180, 30, 30)
        else:
            pdf.set_text_color(30, 130, 60)

        pdf.cell(38, 6, ts,    fill=True, border=1)
        pdf.cell(28, 6, label, fill=True, border=1)
        pdf.set_text_color(40, 40, 40)
        pdf.cell(22, 6, conf,  fill=True, border=1, align='C')

        # Couleur risque
        risk_colors = {
            'LOW': (39, 174, 96), 'MEDIUM': (230, 126, 34),
            'HIGH': (211, 84, 0), 'CRITICAL': (192, 57, 43)
        }
        rc = risk_colors.get(risk, (100, 100, 100))
        pdf.set_text_color(*rc)
        pdf.cell(28, 6, risk,  fill=True, border=1, align='C')
        pdf.set_text_color(60, 60, 180)
        pdf.cell(32, 6, model, fill=True, border=1)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(42, 6, msg,   fill=True, border=1, new_x='LMARGIN', new_y='NEXT')

    # ── PAGE 3 — RECOMMANDATIONS ─────────────────────────────
    pdf.add_page()
    pdf.section_title('6', 'RECOMMANDATIONS DE SECURITE', (150, 80, 20))

    recommandations = []
    if niveaux.get('CRITICAL', 0) > 0:
        recommandations.append(
            f"URGENT : {niveaux['CRITICAL']} alerte(s) CRITIQUE(S). "
            "Isoler immediatement les machines sources."
        )
    if niveaux.get('HIGH', 0) > 0:
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

    for i, rec in enumerate(recommandations, 1):
        pdf.set_fill_color(255, 248, 220)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(8, 8, str(i), fill=True, border=1, align='C')
        pdf.set_font('Helvetica', '', 9)
        pdf.multi_cell(0, 8, ' ' + rec, fill=True, border=1)
        pdf.ln(1)

    pdf.ln(4)
    pdf.section_title('7', 'INFORMATIONS TECHNIQUES', (40, 100, 80))
    pdf.info_row('Framework ML', 'Scikit-learn 1.4.2')
    pdf.info_row('API Backend', 'FastAPI + Uvicorn')
    pdf.info_row('Hebergement', 'Render.com (Frankfurt EU)')
    pdf.info_row('Features utilisees', '21 features reseau extraites')
    pdf.info_row('Modeles disponibles', 'RF, XGBoost, SVM, KNN, DT, Isolation Forest')
    pdf.info_row('Dataset', 'CTU-IoT-Malware-Capture (Stratosphere Lab)')

    pdf.ln(8)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6,
             f'Rapport genere le {now.strftime("%d/%m/%Y a %H:%M:%S")} '
             f'par ITGATE Anomaly Detection System v1.0',
             align='C')

    return bytes(pdf.output())