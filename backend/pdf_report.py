# backend/pdf_report.py - Version 3.0 - ITGATE PFE 2026
from fpdf import FPDF
from datetime import datetime
from typing import List
import tempfile, os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

C_NAVY    = (10,  25,  50)
C_BLUE    = (30,  80, 160)
C_ACCENT  = (0,  180, 200)
C_WHITE   = (255, 255, 255)
C_GRAY_L  = (245, 247, 250)
C_GRAY_M  = (200, 210, 220)
C_GRAY_D  = (90, 100, 110)
C_GREEN   = (39, 174,  96)
C_ORANGE  = (230, 126,  34)
C_RED     = (192,  57,  43)
C_CRIMSON = (150,  20,  20)
C_PURPLE  = (142,  68, 173)

RISK_FR = {'LOW': 'Faible', 'MEDIUM': 'Moyen', 'HIGH': 'Eleve', 'CRITICAL': 'Critique'}
RISK_COL = {'LOW': C_GREEN, 'MEDIUM': C_ORANGE, 'HIGH': C_RED, 'CRITICAL': C_CRIMSON}
MODEL_DISPLAY = {
    'random_forest': 'Random Forest', 'xgboost': 'XGBoost',
    'svm': 'SVM', 'knn': 'KNN',
    'decision_tree': 'Decision Tree', 'isolation_forest': 'Isolation Forest',
}

def _tmp():
    fd, p = tempfile.mkstemp(suffix='.png')
    os.close(fd)
    return p

def chart_donut(mal, ben):
    p = _tmp()
    fig, ax = plt.subplots(figsize=(2.6, 2.6), facecolor='none')
    sizes  = [mal, ben] if (mal + ben) > 0 else [1, 1]
    ax.pie(sizes, colors=['#C0392B', '#27AE60'], startangle=90,
           wedgeprops=dict(width=0.52, edgecolor='white', linewidth=1.5))
    total = mal + ben
    pct   = round(mal / total * 100, 1) if total else 0
    ax.text(0,  0.1, f'{pct}%', ha='center', fontsize=14,
            fontweight='bold', color='#C0392B')
    ax.text(0, -0.2, 'menaces', ha='center', fontsize=7, color='#555')
    ax.legend(
        handles=[mpatches.Patch(color='#C0392B', label=f'Malveillant ({mal})'),
                 mpatches.Patch(color='#27AE60', label=f'Benin ({ben})')],
        loc='lower center', bbox_to_anchor=(0.5, -0.18),
        ncol=2, fontsize=6.5, frameon=False
    )
    plt.tight_layout()
    plt.savefig(p, dpi=120, bbox_inches='tight', transparent=True)
    plt.close(fig)
    return p

def chart_risk(niveaux):
    p = _tmp()
    keys   = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    labels = ['Critique', 'Eleve', 'Moyen', 'Faible']
    vals   = [niveaux.get(k, 0) for k in keys]
    colors = ['#961414', '#C0392B', '#E67E22', '#27AE60']
    fig, ax = plt.subplots(figsize=(3.8, 2.2), facecolor='none')
    bars = ax.barh(labels, vals, color=colors, edgecolor='white',
                   linewidth=1, height=0.5)
    for bar, v in zip(bars, vals):
        if v:
            ax.text(bar.get_width() + 0.03, bar.get_y() + bar.get_height() / 2,
                    str(v), va='center', fontsize=8, fontweight='bold', color='#333')
    ax.set_xlim(0, max(vals + [1]) * 1.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.tick_params(labelsize=7, colors='#555')
    ax.set_xlabel('Alertes', fontsize=7, color='#555')
    plt.tight_layout()
    plt.savefig(p, dpi=120, bbox_inches='tight', transparent=True)
    plt.close(fig)
    return p

def chart_models(models_used):
    p = _tmp()
    if not models_used:
        fig, ax = plt.subplots(figsize=(3.0, 2.2), facecolor='none')
        ax.axis('off')
        plt.savefig(p, dpi=120, transparent=True)
        plt.close(fig)
        return p
    labels  = [MODEL_DISPLAY.get(k, k) for k in models_used]
    vals    = list(models_used.values())
    palette = ['#1E5FA0','#2980B9','#1ABC9C','#8E44AD','#E67E22','#C0392B']
    fig, ax = plt.subplots(figsize=(3.0, 2.6), facecolor='none')
    _, _, autos = ax.pie(vals, colors=palette[:len(vals)], startangle=140,
                         autopct='%1.0f%%', pctdistance=0.72,
                         wedgeprops=dict(edgecolor='white', linewidth=1.2))
    for a in autos:
        a.set_fontsize(6.5); a.set_color('white'); a.set_fontweight('bold')
    ax.legend(
        handles=[mpatches.Patch(color=palette[i % 6], label=f'{labels[i]}')
                 for i in range(len(labels))],
        loc='lower center', bbox_to_anchor=(0.5, -0.25),
        ncol=2, fontsize=6, frameon=False
    )
    plt.tight_layout()
    plt.savefig(p, dpi=120, bbox_inches='tight', transparent=True)
    plt.close(fig)
    return p


class RapportAnomalies(FPDF):

    def __init__(self, now_str):
        super().__init__()
        self.now_str = now_str
        self.set_margins(13, 20, 13)
        self.set_auto_page_break(auto=True, margin=16)

    def header(self):
        self.set_fill_color(*C_NAVY)
        self.rect(0, 0, 210, 14, 'F')
        self.set_fill_color(*C_ACCENT)
        self.rect(0, 14, 210, 1.2, 'F')
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(*C_WHITE)
        self.set_xy(12, 2.5)
        self.cell(120, 5, 'ITGATE - Network Anomaly Detection System', ln=0)
        self.set_font('Helvetica', '', 6.5)
        self.set_text_color(*C_ACCENT)
        self.set_xy(12, 8)
        self.cell(0, 4, 'PFE 2026  -  Cybersecurity R&D  -  Sousse, Tunisie', ln=0)
        self.set_font('Helvetica', '', 6.5)
        self.set_text_color(*C_GRAY_M)
        self.set_xy(150, 4)
        self.cell(47, 5, f'Page {self.page_no()}  -  CONFIDENTIEL', align='R')
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def footer(self):
        self.set_y(-11)
        self.set_fill_color(*C_NAVY)
        self.rect(0, self.get_y(), 210, 12, 'F')
        self.set_font('Helvetica', 'I', 6)
        self.set_text_color(*C_GRAY_M)
        self.cell(0, 7,
                  f'ITGATE Anomaly Detection v1.0  -  {self.now_str}'
                  f'  -  CTU-IoT-Malware-Capture (Stratosphere Lab)  -  Page {self.page_no()}',
                  align='C')
        self.set_text_color(0, 0, 0)

    def section_title(self, titre):
        self.ln(3)
        self.set_fill_color(*C_BLUE)
        self.rect(self.l_margin, self.get_y(), 2.5, 8, 'F')
        self.set_xy(self.l_margin + 4, self.get_y())
        self.set_font('Helvetica', 'B', 9.5)
        self.set_text_color(*C_NAVY)
        self.cell(0, 8, titre.upper(), ln=1)
        self.set_draw_color(*C_GRAY_M)
        self.set_line_width(0.25)
        self.line(self.l_margin, self.get_y(), 210 - self.r_margin, self.get_y())
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def kpi(self, label, val, col, x, y, w=28, h=19):
        r, g, b = col
        self.set_fill_color(max(r-25,0), max(g-25,0), max(b-25,0))
        self.rect(x+1, y+1, w, h, 'F')
        self.set_fill_color(r, g, b)
        self.rect(x, y, w, h, 'F')
        self.set_xy(x, y+2)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(*C_WHITE)
        self.cell(w, 8, val, align='C', ln=0)
        self.set_xy(x, y+11)
        self.set_font('Helvetica', '', 6)
        self.set_text_color(215, 230, 255)
        self.cell(w, 5, label, align='C', ln=0)
        self.set_text_color(0, 0, 0)


def generer_rapport_pdf(alert_history: List[dict]) -> bytes:
    now     = datetime.now()
    now_str = now.strftime('%d/%m/%Y a %H:%M:%S')
    total   = len(alert_history)
    mal     = sum(1 for a in alert_history if a.get('prediction') == 1)
    ben     = total - mal
    taux    = round(mal / total * 100, 1) if total else 0

    niveaux = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for a in alert_history:
        niveaux[a.get('risk_level', 'LOW')] = niveaux.get(a.get('risk_level','LOW'), 0) + 1

    models_used = {}
    for a in alert_history:
        m = a.get('model', 'random_forest')
        models_used[m] = models_used.get(m, 0) + 1

    conf_mal = [a.get('confidence', 0) for a in alert_history if a.get('prediction') == 1]
    conf_ben = [a.get('confidence', 0) for a in alert_history if a.get('prediction') == 0]
    avg_mal  = round(sum(conf_mal) / len(conf_mal), 1) if conf_mal else 0
    avg_ben  = round(sum(conf_ben) / len(conf_ben), 1) if conf_ben else 0

    periode_debut = alert_history[-1]['timestamp'][:10] if alert_history else 'N/A'
    periode_fin   = alert_history[0]['timestamp'][:10]  if alert_history else 'N/A'
    ref = f'ITGATE-RPT-{now.strftime("%Y%m%d-%H%M%S")}'

    tmp_files = []
    p_donut  = chart_donut(mal, ben);       tmp_files.append(p_donut)
    p_risk   = chart_risk(niveaux);         tmp_files.append(p_risk)
    p_models = chart_models(models_used);   tmp_files.append(p_models)

    pdf = RapportAnomalies(now_str)

    # ═══════════════════════════════════════════════════════════
    # PAGE 1 - EN-TETE + KPI + GRAPHIQUES + MODELES
    # ═══════════════════════════════════════════════════════════
    pdf.add_page()

    # Bloc titre
    pdf.set_fill_color(*C_NAVY)
    pdf.rect(0, 19, 210, 26, 'F')
    pdf.set_fill_color(*C_ACCENT)
    pdf.rect(0, 45, 210, 1.5, 'F')
    pdf.set_xy(0, 22)
    pdf.set_font('Helvetica', 'B', 17)
    pdf.set_text_color(*C_WHITE)
    pdf.cell(210, 9, "RAPPORT D'ANALYSE - DETECTION D'ANOMALIES RESEAU", align='C', ln=1)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(*C_ACCENT)
    pdf.cell(210, 6,
             f'Ref : {ref}  |  Periode : {periode_debut} -> {periode_fin}  |  '
             f'Dataset : CTU-IoT-Malware-Capture (Stratosphere Lab)',
             align='C', ln=1)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)

    # KPI row
    kpis = [
        ('Total analyses',   str(total),  (52, 120, 200)),
        ('Malveillants',     str(mal),    C_RED),
        ('Benins',           str(ben),    C_GREEN),
        ('Taux menaces',     f'{taux}%',  C_PURPLE),
        ('Conf. moy. mal.',  f'{avg_mal}%', C_ORANGE),
        ('Alertes critiques',str(niveaux['CRITICAL']), C_CRIMSON),
    ]
    kw   = (210 - 13 - 13 - 10) / 6
    y_k  = pdf.get_y()
    for i, (lbl, val, col) in enumerate(kpis):
        pdf.kpi(lbl, val, col, 13 + i * (kw + 2), y_k, w=kw)
    pdf.ln(24)

    # Graphiques : donut + risk + models
    pdf.section_title('Analyse de la session')
    y_g = pdf.get_y()
    pdf.image(p_donut,  x=13,    y=y_g, w=58)
    pdf.image(p_risk,   x=76,    y=y_g, w=72)
    pdf.image(p_models, x=152,   y=y_g, w=45)
    pdf.ln(58)

    # Legendes sous les graphiques
    pdf.set_font('Helvetica', 'I', 6.5)
    pdf.set_text_color(*C_GRAY_D)
    pdf.cell(58,  4, 'Repartition trafic',       align='C', ln=0)
    pdf.cell(72,  4, 'Distribution niveaux risque', align='C', ln=0)
    pdf.cell(0,   4, 'Modeles ML utilises',       align='C', ln=1)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)

    # Tableau modeles compact
    pdf.section_title('Modeles ML - Statistiques de session')

    pdf.set_font('Helvetica', 'B', 7.5)
    pdf.set_fill_color(*C_NAVY)
    pdf.set_text_color(*C_WHITE)
    col_w = [52, 28, 22, 22, 28, 28]
    hdrs  = ['Modele', 'Type', 'Pred.', 'Pct.', 'Conf. Mal.', 'Conf. Ben.']
    for h, w in zip(hdrs, col_w):
        pdf.cell(w, 6.5, h, fill=True, border=1)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    model_stats = {}
    for a in alert_history:
        m = a.get('model', 'random_forest')
        if m not in model_stats:
            model_stats[m] = {'mal': [], 'ben': []}
        if a.get('prediction') == 1:
            model_stats[m]['mal'].append(a.get('confidence', 0))
        else:
            model_stats[m]['ben'].append(a.get('confidence', 0))

    for i, (mk, cnt) in enumerate(models_used.items()):
        ms     = model_stats.get(mk, {'mal': [], 'ben': []})
        pct_m  = round(cnt / total * 100, 1) if total else 0
        cm     = round(sum(ms['mal']) / len(ms['mal']), 1) if ms['mal'] else '-'
        cb     = round(sum(ms['ben']) / len(ms['ben']), 1) if ms['ben'] else '-'
        mtype  = 'Non-sup.' if mk == 'isolation_forest' else 'Supervise'
        disp   = MODEL_DISPLAY.get(mk, mk.replace('_', ' ').title())
        bg     = C_GRAY_L if i % 2 == 0 else C_WHITE
        pdf.set_fill_color(*bg)
        pdf.set_font('Helvetica', '', 7.5)
        pdf.set_text_color(*C_NAVY)
        pdf.cell(col_w[0], 5.8, disp,        fill=True, border=1)
        pdf.cell(col_w[1], 5.8, mtype,       fill=True, border=1)
        pdf.cell(col_w[2], 5.8, str(cnt),    fill=True, border=1, align='C')
        pdf.cell(col_w[3], 5.8, f'{pct_m}%', fill=True, border=1, align='C')
        pdf.set_text_color(180, 30, 30)
        pdf.cell(col_w[4], 5.8, f'{cm}%' if cm != '-' else '-',
                 fill=True, border=1, align='C')
        pdf.set_text_color(30, 130, 60)
        pdf.cell(col_w[5], 5.8, f'{cb}%' if cb != '-' else '-',
                 fill=True, border=1, align='C', ln=1)
    pdf.set_text_color(0, 0, 0)

    # ═══════════════════════════════════════════════════════════
    # PAGE 2 - JOURNAL DES ALERTES
    # ═══════════════════════════════════════════════════════════
    pdf.add_page()
    nb = min(40, len(alert_history))
    pdf.section_title(f'Journal des alertes - {nb} derniere(s) connexion(s)')

    pdf.set_font('Helvetica', 'B', 7)
    pdf.set_fill_color(*C_NAVY)
    pdf.set_text_color(*C_WHITE)
    cw = [34, 22, 18, 24, 28, 58]
    hs = ['Horodatage', 'Statut', 'Confiance', 'Risque', 'Modele', 'Message']
    for h, w in zip(hs, cw):
        pdf.cell(w, 6.5, h, fill=True, border=1)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    for idx, a in enumerate(list(reversed(alert_history))[:nb]):
        pred  = a.get('prediction', 0)
        label = a.get('label', '?')
        conf  = a.get('confidence', 0)
        risk  = a.get('risk_level', 'LOW')
        mk    = a.get('model', 'random_forest')
        ts    = a.get('timestamp', '')[:19].replace('T', ' ')
        disp  = MODEL_DISPLAY.get(mk, mk.replace('_', ' ').title())

        if pred == 1:
            msg = 'Action immediate' if risk == 'CRITICAL' else \
                  'Risque eleve'     if risk == 'HIGH'     else 'Trafic malveillant'
        else:
            msg = 'Trafic normal'

        bg = C_GRAY_L if idx % 2 == 0 else C_WHITE
        pdf.set_fill_color(*bg)
        pdf.set_font('Helvetica', '', 6.5)

        pdf.set_text_color(*C_GRAY_D)
        pdf.cell(cw[0], 5.5, ts, fill=True, border=1)

        lc = (180, 30, 30) if label == 'Malicious' else (30, 130, 60)
        pdf.set_text_color(*lc)
        pdf.set_font('Helvetica', 'B', 6.5)
        pdf.cell(cw[1], 5.5, label, fill=True, border=1)

        pdf.set_font('Helvetica', '', 6.5)
        pdf.set_text_color(40, 40, 40)
        pdf.cell(cw[2], 5.5, f'{conf:.1f}%', fill=True, border=1, align='C')

        rc = RISK_COL.get(risk, C_GRAY_D)
        pdf.set_text_color(*rc)
        pdf.set_font('Helvetica', 'B', 6.5)
        pdf.cell(cw[3], 5.5, RISK_FR.get(risk, risk), fill=True, border=1, align='C')

        pdf.set_text_color(50, 50, 160)
        pdf.set_font('Helvetica', '', 6.5)
        pdf.cell(cw[4], 5.5, disp, fill=True, border=1)

        pdf.set_text_color(*C_GRAY_D)
        pdf.cell(cw[5], 5.5, msg, fill=True, border=1, ln=1)

    pdf.set_text_color(0, 0, 0)

    # ═══════════════════════════════════════════════════════════
    # PAGE 3 - RECOMMANDATIONS + INFOS TECHNIQUES
    # ═══════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.section_title('Recommandations de securite')

    recs = []
    if niveaux.get('CRITICAL', 0) > 0:
        recs.append((C_CRIMSON, 'CRITIQUE',
            f'{niveaux["CRITICAL"]} alerte(s) critique(s). '
            'Isoler les machines sources, notifier le SOC, archiver les logs (pcap), ouvrir ticket P1.'))
    if niveaux.get('HIGH', 0) > 0:
        recs.append((C_RED, 'PRIORITE HAUTE',
            f'{niveaux["HIGH"]} connexion(s) a risque eleve. '
            'Analyser les logs sources sous 2h, verifier les regles pare-feu, corroler avec le SIEM.'))
    if taux > 50:
        recs.append((C_ORANGE, 'TAUX ELEVE',
            f'Taux malveillant : {taux}%. '
            "Auditer les regles ACL, verifier la segmentation VLAN, controler l'integrite reseau."))
    if not recs:
        recs.append((C_GREEN, 'NORMAL',
            'Aucune anomalie critique. Maintenir la surveillance continue et conserver les logs.'))
    recs.append(((52,120,200), 'AMELIORATION',
        'Reentrainer les modeles mensuellement. '
        'Implementer la persistance des alertes (BDD). '
        'Integrer la classification MITRE ATT&CK.'))

    for r, g, b in [(x[0]) for x in recs]:
        pass  # just iterate

    for rec_col, rec_title, rec_text in recs:
        r2, g2, b2 = rec_col
        pdf.set_fill_color(r2, g2, b2)
        pdf.set_text_color(*C_WHITE)
        pdf.set_font('Helvetica', 'B', 8)
        pdf.cell(0, 6.5, f'  {rec_title}', fill=True, ln=1)
        pdf.set_fill_color(248, 249, 252)
        pdf.set_text_color(40, 40, 80)
        pdf.set_font('Helvetica', '', 7.8)
        w_avail = 210 - pdf.l_margin - pdf.r_margin
        pdf.multi_cell(w_avail, 5.2, '  ' + rec_text, fill=True, border=1)
        pdf.ln(1.5)
    pdf.set_text_color(0, 0, 0)

    pdf.ln(2)
    pdf.section_title('Informations techniques')

    left_w  = 52
    right_w = 210 - pdf.l_margin - pdf.r_margin - left_w

    tech = [
        ('Systeme',         'ITGATE Network Anomaly Detection v1.0'),
        ('Framework ML',    'Scikit-learn 1.4.2 . XGBoost 2.0.3 . FastAPI 0.115.0'),
        ('Dataset',         'CTU-IoT-Malware-Capture (Stratosphere Lab, CTU Prague)'),
        ('Features',        '20 features comportementales - id.resp_p exclu (biais port 23/Mirai)'),
        ('Modeles',         'Random Forest . XGBoost . SVM . KNN . Decision Tree . Isolation Forest'),
        ('Normalisation',   'MinMaxScaler - pipeline automatique'),
        ('Stockage',        'In-memory (max 1000 alertes, FIFO) - non persiste'),
        ('Hebergement',     'Render.com - Frankfurt EU'),
    ]
    for lbl, val in tech:
        pdf.set_font('Helvetica', 'B', 7.8)
        pdf.set_text_color(*C_GRAY_D)
        pdf.cell(left_w, 5.8, lbl + ' :', ln=0)
        pdf.set_font('Helvetica', '', 7.8)
        pdf.set_text_color(*C_NAVY)
        pdf.multi_cell(right_w, 5.8, val)
    pdf.set_text_color(0, 0, 0)

    # Signature finale
    pdf.ln(4)
    pdf.set_draw_color(*C_GRAY_M)
    pdf.set_line_width(0.25)
    pdf.line(pdf.l_margin, pdf.get_y(), 210 - pdf.r_margin, pdf.get_y())
    pdf.ln(2)
    pdf.set_font('Helvetica', 'I', 7)
    pdf.set_text_color(*C_GRAY_D)
    pdf.cell(0, 5,
             f'Rapport genere le {now_str}  -  Ref : {ref}  -  ITGATE PFE 2026',
             align='C')
    pdf.set_text_color(0, 0, 0)

    result = bytes(pdf.output())
    for tmp in tmp_files:
        try: os.remove(tmp)
        except: pass
    return result
