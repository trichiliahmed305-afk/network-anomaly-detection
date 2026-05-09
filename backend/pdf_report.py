# backend/pdf_report.py
# ============================================================
# ITGATE PFE 2026 - PDF Report Generator
# Generates a professional 3-page anomaly detection report.
# Dependencies: fpdf2 >= 2.7
# ============================================================

from fpdf import FPDF
from datetime import datetime
from typing import List, Dict, Tuple

# ── Constants ────────────────────────────────────────────────
MAX_ALERTS_IN_TABLE = 50
FEATURES_USED       = 20      # id.resp_p excluded (port bias)
DATASET_NAME        = "CTU-IoT-Malware-Capture (Stratosphere Lab, CTU Prague)"
SYSTEM_VERSION      = "ITGATE Network Anomaly Detection v1.0"
SKLEARN_VERSION     = "Scikit-learn 1.4.2"

RISK_CONFIG: Dict[str, Tuple[str, Tuple[int, int, int]]] = {
    "LOW":      ("FAIBLE",   (39,  174,  96)),
    "MEDIUM":   ("MOYEN",    (230, 126,  34)),
    "HIGH":     ("ELEVE",    (211,  84,   0)),
    "CRITICAL": ("CRITIQUE", (192,  57,  43)),
}

MODEL_DISPLAY: Dict[str, str] = {
    "random_forest":    "Random Forest",
    "xgboost":          "XGBoost",
    "svm":              "SVM",
    "knn":              "KNN",
    "decision_tree":    "Decision Tree",
    "isolation_forest": "Isolation Forest",
}


# ── Utility functions ────────────────────────────────────────


def _sanitize(s) -> str:
    """Strip non-latin1 characters unsupported by Helvetica PDF font."""
    return str(s).encode("latin-1", errors="replace").decode("latin-1")

def _safe_rgb(r: int, g: int, b: int) -> Tuple[int, int, int]:
    """Clamp RGB values to [0, 255] to prevent fpdf color errors."""
    return (max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b)))


def _format_timestamp(ts: str) -> str:
    """Safely format ISO timestamp to readable format."""
    try:
        return ts[:19].replace("T", " ")
    except (TypeError, IndexError):
        return "N/A"


def _get_period(alert_history: List[dict]) -> str:
    """Return analysis period string safely."""
    if not alert_history:
        return "N/A"
    try:
        start = alert_history[0]["timestamp"][:10]
        end   = alert_history[-1]["timestamp"][:10]
        return f"{start} au {end}"
    except (KeyError, IndexError, TypeError):
        return "N/A"


def _compute_stats(alert_history: List[dict]) -> Dict:
    """
    Compute all report statistics from alert_history.
    Single-pass loop for efficiency.
    Returns: total, malveillants, benins, taux, niveaux, models_used.
    """
    total        = len(alert_history)
    malveillants = 0
    niveaux      = {k: 0 for k in RISK_CONFIG}
    models_used: Dict[str, int] = {}

    for alert in alert_history:
        if alert.get("prediction") == 1:
            malveillants += 1

        level = alert.get("risk_level", "LOW")
        if level in niveaux:
            niveaux[level] += 1

        model = alert.get("model", "random_forest")
        models_used[model] = models_used.get(model, 0) + 1

    taux = round((malveillants / total * 100), 1) if total > 0 else 0.0

    return {
        "total":        total,
        "malveillants": malveillants,
        "benins":       total - malveillants,
        "taux":         taux,
        "niveaux":      niveaux,
        "models_used":  models_used,
    }


# ── PDF Class ────────────────────────────────────────────────

class RapportAnomalies(FPDF):
    """
    Custom FPDF subclass for the ITGATE anomaly detection report.
    Reusable layout helpers: section_title, info_row, kpi_box, progress_bar.
    """

    def header(self) -> None:
        """Dark top banner with system title and subtitle."""
        self.set_fill_color(*_safe_rgb(13, 27, 42))
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(255, 255, 255)
        self.set_xy(0, 3)
        self.cell(0, 10, _sanitize("ITGATE - Network Anomaly Detection System"), align="C")
        self.set_text_color(100, 160, 220)
        self.set_font("Helvetica", "", 7)
        self.set_xy(0, 11)
        self.cell(0, 5, _sanitize("PFE 2026 - Cybersecurity R&D - Sousse, Tunisie"), align="C")
        self.set_text_color(0, 0, 0)
        self.ln(12)

    def footer(self) -> None:
        """Dark bottom banner with page number and generation date."""
        self.set_y(-12)
        self.set_fill_color(*_safe_rgb(13, 27, 42))
        self.rect(0, self.get_y(), 210, 15, "F")
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(150, 180, 210)
        self.cell(
            0, 8,
            f"ITGATE PFE 2026 - Page {self.page_no()} - Confidentiel - "
            f"Genere le {datetime.now().strftime('%d/%m/%Y a %H:%M')}",
            align="C",
        )
        self.set_text_color(0, 0, 0)

    def section_title(
        self,
        num: str,
        titre: str,
        color: Tuple[int, int, int] = (52, 120, 200),
    ) -> None:
        """Numbered section header with two-tone background."""
        r, g, b = _safe_rgb(*color)
        self.ln(4)
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 10)
        self.cell(8, 8, num, fill=True, border=0)
        self.set_fill_color(*_safe_rgb(r + 30, g + 30, b + 30))
        self.cell(0, 8, f"  {titre}", fill=True, border=0, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def info_row(self, label: str, valeur: str) -> None:
        """Key-value row: bold label left, normal value right."""
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(60, 60, 60)
        self.cell(65, 7, f"{label} :", new_x="RIGHT", new_y="LAST")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 7, _sanitize(str(valeur)), new_x="LMARGIN", new_y="NEXT")

    def kpi_box(
        self,
        label: str,
        valeur: str,
        couleur_rgb: Tuple[int, int, int],
        x: float,
        y: float,
        w: float = 42,
    ) -> None:
        """Colored KPI tile: large value on top, label caption below."""
        r, g, b = _safe_rgb(*couleur_rgb)
        self.set_xy(x, y)
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 14)
        self.cell(w, 10, valeur, fill=True, align="C", new_x="RIGHT", new_y="LAST")
        self.set_xy(x, y + 10)
        self.set_fill_color(*_safe_rgb(r - 20, g - 20, b - 20))
        self.set_font("Helvetica", "", 7)
        self.cell(w, 7, label, fill=True, align="C", new_x="RIGHT", new_y="LAST")
        self.set_text_color(0, 0, 0)

    def progress_bar(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        pct: float,
        color: Tuple[int, int, int],
    ) -> None:
        """Grey background + colored fill proportional to pct [0-100]."""
        self.set_fill_color(220, 220, 220)
        self.rect(x, y, width, height, "F")
        if pct > 0:
            fill_w = max(1, int((pct / 100) * width))
            self.set_fill_color(*_safe_rgb(*color))
            self.rect(x, y, fill_w, height, "F")


# ── Public API ───────────────────────────────────────────────

def generer_rapport_pdf(alert_history: List[dict]) -> bytes:
    """
    Generate a professional 3-page PDF anomaly detection report.

    Args:
        alert_history: List of alert dicts. Each must contain:
            timestamp (ISO str), prediction (int 0/1), label (str),
            confidence (float), risk_level (str), model (str).

    Returns:
        PDF content as bytes for HTTP response streaming.

    Raises:
        ValueError: if alert_history is empty.
    """
    if not alert_history:
        raise ValueError("alert_history is empty - cannot generate report.")

    stats = _compute_stats(alert_history)
    now   = datetime.now()
    total = stats["total"]

    pdf = RapportAnomalies()
    pdf.set_auto_page_break(auto=True, margin=16)

    # ── PAGE 1 - Executive summary ───────────────────────────
    pdf.add_page()

    # 1. Report metadata
    pdf.section_title("1", "INFORMATIONS DU RAPPORT", (20, 60, 120))
    pdf.info_row("Date de generation", # sanitized below
    #  now.strftime("%d/%m/%Y a %H:%M:%S"))
    pdf.info_row("Systeme",             SYSTEM_VERSION)
    pdf.info_row("Dataset",             DATASET_NAME)
    pdf.info_row("Features du modele",  f"{FEATURES_USED} features (id.resp_p exclu - biais port 23)")
    pdf.info_row("Framework ML",        SKLEARN_VERSION)
    pdf.info_row("Modeles disponibles", ", ".join(MODEL_DISPLAY.values()))
    pdf.info_row("Periode analysee",    _get_period(alert_history))
    pdf.ln(4)

    # 2. KPI tiles
    pdf.section_title("2", "RESUME EXECUTIF", (20, 100, 160))
    pdf.ln(2)
    kpis = [
        ("Total Analyses", str(total),               (41,  128, 185)),
        ("Malveillants",   str(stats["malveillants"]), (192,  57,  43)),
        ("Benins",         str(stats["benins"]),       (39,  174,  96)),
        ("Taux Detection", f"{stats['taux']}%",        (142,  68, 173)),
    ]
    y_kpi = pdf.get_y()
    for i, (label, val, color) in enumerate(kpis):
        pdf.kpi_box(label, val, color, 14.0 + i * 46, y_kpi)
    pdf.ln(26)

    # 3. Risk level distribution
    pdf.section_title("3", "DISTRIBUTION DES NIVEAUX DE RISQUE", (150, 50, 50))
    for level, (label_fr, rgb) in RISK_CONFIG.items():
        count = stats["niveaux"].get(level, 0)
        pct   = round(count / total * 100, 1) if total > 0 else 0.0

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*_safe_rgb(*rgb))
        pdf.cell(30, 7, label_fr, new_x="RIGHT", new_y="LAST")
        pdf.set_text_color(60, 60, 60)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(22, 7, f"{count} alerte(s)", new_x="RIGHT", new_y="LAST")

        bar_x = pdf.get_x() + 2
        bar_y = pdf.get_y() + 1.5
        pdf.progress_bar(bar_x, bar_y, 118, 4, pct, rgb)
        pdf.cell(130, 7, f"   {pct}%", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # 4. Models used table
    if stats["models_used"]:
        pdf.section_title("4", "MODELES ML UTILISES", (60, 100, 60))
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(210, 225, 255)
        pdf.cell(75, 7, "Modele",       fill=True, border=1)
        pdf.cell(30, 7, "Utilisations", fill=True, border=1, align="C")
        pdf.cell(0,  7, "Pourcentage",  fill=True, border=1, align="C",
                 new_x="LMARGIN", new_y="NEXT")

        for i, (model_key, count) in enumerate(stats["models_used"].items()):
            pct_m   = round(count / total * 100, 1) if total > 0 else 0.0
            fill_bg = (245, 248, 255) if i % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*fill_bg)
            pdf.set_font("Helvetica", "", 9)
            display = MODEL_DISPLAY.get(model_key, model_key.replace("_", " ").title())
            pdf.cell(75, 7, _sanitize(display),     fill=True, border=1)
            pdf.cell(30, 7, str(count),  fill=True, border=1, align="C")
            pdf.cell(0,  7, f"{pct_m}%", fill=True, border=1, align="C",
                     new_x="LMARGIN", new_y="NEXT")

    # ── PAGE 2 - Alert journal ───────────────────────────────
    pdf.add_page()
    pdf.section_title(
        "5",
        f"JOURNAL DES ALERTES ({min(MAX_ALERTS_IN_TABLE, total)} dernieres)",
        (80, 40, 120),
    )

    cols = [
        ("Horodatage",     38),
        ("Classification", 28),
        ("Confiance",      22),
        ("Risque",         24),
        ("Modele",         34),
        ("Message",        44),
    ]
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(*_safe_rgb(20, 50, 100))
    pdf.set_text_color(255, 255, 255)
    for label, w in cols:
        pdf.cell(w, 8, label, fill=True, border=1)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    risk_messages = {
        "CRITICAL": "Critique - Action immediate",
        "HIGH":     "Risque eleve",
        "MEDIUM":   "Risque moyen",
        "LOW":      "Trafic normal",
    }

    alertes = list(reversed(alert_history))[:MAX_ALERTS_IN_TABLE]
    for i, alerte in enumerate(alertes):
        try:
            ts          = _format_timestamp(alerte.get("timestamp", ""))
            label_txt   = str(alerte.get("label", "?"))
            confidence  = alerte.get("confidence", 0)
            risk        = alerte.get("risk_level", "LOW")
            model_key   = alerte.get("model", "random_forest")
            display_mdl = MODEL_DISPLAY.get(model_key, model_key[:12])
            message     = risk_messages.get(risk, "N/A")

            fill_bg = (245, 248, 252) if i % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*fill_bg)
            pdf.set_font("Helvetica", "", 7)

            # Timestamp
            pdf.set_text_color(60, 60, 60)
            pdf.cell(38, 6, _sanitize(ts), fill=True, border=1)

            # Label (color-coded)
            pdf.set_text_color(180, 30, 30) if label_txt == "Malicious" else pdf.set_text_color(30, 130, 60)
            pdf.cell(28, 6, _sanitize(label_txt), fill=True, border=1)

            # Confidence
            pdf.set_text_color(40, 40, 40)
            pdf.cell(22, 6, f"{confidence}%", fill=True, border=1, align="C")

            # Risk (color-coded)
            rgb_risk = RISK_CONFIG.get(risk, ("?", (100, 100, 100)))[1]
            pdf.set_text_color(*_safe_rgb(*rgb_risk))
            pdf.cell(24, 6, _sanitize(risk), fill=True, border=1, align="C")

            # Model
            pdf.set_text_color(60, 60, 180)
            pdf.cell(34, 6, _sanitize(display_mdl), fill=True, border=1)

            # Message
            pdf.set_text_color(60, 60, 60)
            pdf.cell(44, 6, _sanitize(message), fill=True, border=1, new_x="LMARGIN", new_y="NEXT")

        except (KeyError, TypeError):
            continue  # Skip malformed entries gracefully

    # ── PAGE 3 - Recommendations + technical info ────────────
    pdf.add_page()
    pdf.section_title("6", "RECOMMANDATIONS DE SECURITE", (150, 80, 20))

    recommendations = []
    if stats["niveaux"].get("CRITICAL", 0) > 0:
        recommendations.append(
            f"URGENT : {stats['niveaux']['CRITICAL']} alerte(s) CRITIQUE(S). "
            "Isoler immediatement les machines sources et alerter le SOC."
        )
    if stats["niveaux"].get("HIGH", 0) > 0:
        recommendations.append(
            f"PRIORITE HAUTE : {stats['niveaux']['HIGH']} connexion(s) a risque eleve. "
            "Analyser les logs reseau des IP sources dans les 24 heures."
        )
    if stats["taux"] > 80:
        recommendations.append(
            f"CRITIQUE : {stats['taux']}% du trafic est malveillant. "
            "Envisager une coupure reseau et une investigation forensique."
        )
    elif stats["taux"] > 50:
        recommendations.append(
            f"ALERTE : Taux de trafic malveillant eleve ({stats['taux']}%). "
            "Verifier la configuration pare-feu et les regles IDS."
        )
    if not recommendations:
        recommendations.append(
            "Aucune alerte critique. Systeme nominal. "
            "Continuer la surveillance reguliere."
        )

    for i, rec in enumerate(recommendations, 1):
        pdf.set_fill_color(255, 248, 220)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(150, 80, 0)
        pdf.cell(8, 8, str(i), fill=True, border=1, align="C")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 8, _sanitize(f" {rec}"), fill=True, border=1)
        pdf.ln(1)

    pdf.ln(4)

    # Section 7 - Technical info
    pdf.section_title("7", "INFORMATIONS TECHNIQUES DU SYSTEME", (40, 100, 80))
    pdf.info_row("Framework ML",       SKLEARN_VERSION)
    pdf.info_row("API Backend",        "FastAPI 0.136 + Uvicorn")
    pdf.info_row("Hebergement",        "Render.com (Free Tier)")
    pdf.info_row("Features modele",    f"{FEATURES_USED} features - id.resp_p exclu (biais port 23 Mirai)")
    pdf.info_row("Modeles deployes",   ", ".join(MODEL_DISPLAY.values()))
    pdf.info_row("Dataset",            DATASET_NAME)
    pdf.info_row("Normalisation",      "MinMaxScaler - detection auto si donnees brutes")
    pdf.info_row("Stockage alertes",   "In-memory (max 1000 - FIFO) - perdu au redemarrage Render")

    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(
        0, 6,
        f"Rapport genere le {now.strftime('%d/%m/%Y a %H:%M:%S')} "
        f"par {SYSTEM_VERSION}",
        align="C",
    )

    return bytes(pdf.output())
