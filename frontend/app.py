"""
ITGATE — Network Anomaly Detection System
PFE 2026 — Advanced SOC Dashboard
Themes: Dark / Light / Amber
"""

import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ============================================================
# CONSTANTS
# ============================================================
API_URL = "https://itgate-anomaly-api.onrender.com"

RISK_COLORS = {
    "LOW":      {"dark": "#22c55e", "light": "#16a34a", "amber": "#4ade80"},
    "MEDIUM":   {"dark": "#f59e0b", "light": "#d97706", "amber": "#fbbf24"},
    "HIGH":     {"dark": "#f97316", "light": "#ea580c", "amber": "#fb923c"},
    "CRITICAL": {"dark": "#ef4444", "light": "#dc2626", "amber": "#f87171"},
}

RISK_LABELS = {
    "LOW":      "Faible",
    "MEDIUM":   "Moyen",
    "HIGH":     "Elevé",
    "CRITICAL": "Critique",
}

THEMES = {
    "dark": {
        "label": "Sombre",
        "bg":          "#0b0f1a",
        "bg_secondary":"#111827",
        "card":        "#161d2e",
        "card2":       "#1e2740",
        "border":      "#1f2d47",
        "border2":     "#2a3a57",
        "accent":      "#3b82f6",
        "accent2":     "#60a5fa",
        "success":     "#22c55e",
        "danger":      "#ef4444",
        "warning":     "#f59e0b",
        "text":        "#f1f5f9",
        "text_muted":  "#64748b",
        "text_sub":    "#94a3b8",
        "nav_active":  "#1e3a5f",
        "nav_hover":   "#162033",
        "metric_bg":   "#0f1929",
        "scrollbar":   "#1f2d47",
        "plot_bg":     "rgba(0,0,0,0)",
        "grid_color":  "#1f2d47",
        "font":        "JetBrains Mono",
        "font_body":   "IBM Plex Sans",
        "badge_text":  "#ffffff",
    },
    "light": {
        "label": "Clair",
        "bg":          "#f8fafc",
        "bg_secondary":"#f1f5f9",
        "card":        "#ffffff",
        "card2":       "#f8fafc",
        "border":      "#e2e8f0",
        "border2":     "#cbd5e1",
        "accent":      "#2563eb",
        "accent2":     "#3b82f6",
        "success":     "#16a34a",
        "danger":      "#dc2626",
        "warning":     "#d97706",
        "text":        "#0f172a",
        "text_muted":  "#64748b",
        "text_sub":    "#475569",
        "nav_active":  "#dbeafe",
        "nav_hover":   "#f1f5f9",
        "metric_bg":   "#f0f9ff",
        "scrollbar":   "#cbd5e1",
        "plot_bg":     "rgba(0,0,0,0)",
        "grid_color":  "#e2e8f0",
        "font":        "JetBrains Mono",
        "font_body":   "IBM Plex Sans",
        "badge_text":  "#ffffff",
    },
    "amber": {
        "label": "Ambre",
        "bg":          "#0f0a00",
        "bg_secondary":"#150d00",
        "card":        "#1a1000",
        "card2":       "#221500",
        "border":      "#2d1f00",
        "border2":     "#3d2a00",
        "accent":      "#f59e0b",
        "accent2":     "#fbbf24",
        "success":     "#4ade80",
        "danger":      "#f87171",
        "warning":     "#fb923c",
        "text":        "#fef3c7",
        "text_muted":  "#92400e",
        "text_sub":    "#d97706",
        "nav_active":  "#2d1f00",
        "nav_hover":   "#1f1500",
        "metric_bg":   "#150d00",
        "scrollbar":   "#2d1f00",
        "plot_bg":     "rgba(0,0,0,0)",
        "grid_color":  "#2d1f00",
        "font":        "JetBrains Mono",
        "font_body":   "IBM Plex Sans",
        "badge_text":  "#0f0a00",
    },
}

PAGES = [
    "System Status",
    "Analyze Connection",
    "Alert Log",
    "Statistics",
    "PDF Report",
]

# ============================================================
# SESSION STATE INIT
# ============================================================
if "theme" not in st.session_state:
    st.session_state.theme = "dark"

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="ITGATE — SOC Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# THEME INJECTION
# ============================================================
T = THEMES[st.session_state.theme]

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

*, *::before, *::after {{ box-sizing: border-box; }}

:root {{
    --bg:           {T['bg']};
    --bg2:          {T['bg_secondary']};
    --card:         {T['card']};
    --card2:        {T['card2']};
    --border:       {T['border']};
    --border2:      {T['border2']};
    --accent:       {T['accent']};
    --accent2:      {T['accent2']};
    --success:      {T['success']};
    --danger:       {T['danger']};
    --warning:      {T['warning']};
    --text:         {T['text']};
    --muted:        {T['text_muted']};
    --sub:          {T['text_sub']};
    --nav-active:   {T['nav_active']};
    --nav-hover:    {T['nav_hover']};
    --metric-bg:    {T['metric_bg']};
    --scroll:       {T['scrollbar']};
    --font:         '{T['font']}', monospace;
    --font-body:    '{T['font_body']}', sans-serif;
}}

html, body, [class*="css"] {{
    font-family: var(--font-body) !important;
    color: var(--text) !important;
    background-color: var(--bg) !important;
}}

.stApp {{ background-color: var(--bg) !important; }}

header[data-testid="stHeader"], footer, #MainMenu {{ display: none !important; }}
[data-testid="stToolbar"] {{ display: none !important; }}

section[data-testid="stSidebar"] {{
    background-color: var(--card) !important;
    border-right: 1px solid var(--border) !important;
    min-width: 260px !important;
}}
section[data-testid="stSidebar"] * {{ color: var(--text) !important; }}

[data-testid="stMainBlockContainer"],
[data-testid="block-container"] {{
    background-color: var(--bg) !important;
    padding-top: 2rem !important;
    padding-bottom: 3rem !important;
}}

h1 {{
    font-family: var(--font) !important;
    font-size: 1.65rem !important;
    font-weight: 700 !important;
    letter-spacing: -0.5px !important;
    color: var(--text) !important;
    margin-bottom: 2px !important;
}}

h2 {{
    font-family: var(--font) !important;
    font-size: 1.15rem !important;
    font-weight: 600 !important;
    color: var(--text) !important;
    margin-top: 1.5rem !important;
}}

h3 {{
    font-family: var(--font-body) !important;
    font-size: 0.95rem !important;
    font-weight: 600 !important;
    color: var(--sub) !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
}}

p, li, span, div {{ color: var(--text) !important; }}

[data-testid="stCaptionContainer"] p {{
    color: var(--muted) !important;
    font-size: 0.82rem !important;
}}

hr {{
    border: none !important;
    border-top: 1px solid var(--border) !important;
    margin: 1.2rem 0 !important;
}}

[data-testid="stMetric"] {{
    background: var(--metric-bg) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    padding: 18px 20px !important;
    transition: border-color 0.2s, box-shadow 0.2s;
}}

[data-testid="stMetric"]:hover {{
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 1px var(--accent), 0 4px 20px rgba(59,130,246,0.08) !important;
}}

[data-testid="stMetricLabel"] p {{
    font-family: var(--font-body) !important;
    font-size: 0.75rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.07em !important;
    color: var(--muted) !important;
}}

[data-testid="stMetricValue"] {{
    font-family: var(--font) !important;
    font-size: 1.8rem !important;
    font-weight: 700 !important;
    color: var(--text) !important;
}}

div.stButton > button {{
    background-color: var(--accent) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 7px !important;
    font-family: var(--font-body) !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
    padding: 0.55rem 1.6rem !important;
    transition: opacity 0.2s, transform 0.1s !important;
}}

div.stButton > button:hover {{
    opacity: 0.88 !important;
    transform: translateY(-1px) !important;
}}

div[data-testid="stFormSubmitButton"] > button {{
    background: linear-gradient(135deg, var(--accent), var(--accent2)) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 8px !important;
    font-family: var(--font) !important;
    font-weight: 700 !important;
    font-size: 0.9rem !important;
    padding: 0.65rem 2rem !important;
    width: 100% !important;
}}

div[data-testid="stNumberInput"] input,
div[data-testid="stTextInput"] input,
div[data-baseweb="select"] {{
    background-color: var(--card2) !important;
    border: 1px solid var(--border2) !important;
    border-radius: 7px !important;
    color: var(--text) !important;
    font-family: var(--font-body) !important;
    font-size: 0.88rem !important;
}}

[data-testid="stForm"] {{
    background: var(--card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    padding: 24px !important;
}}

[data-testid="stAlert"] {{
    border-radius: 9px !important;
    border-left-width: 3px !important;
    font-family: var(--font-body) !important;
    font-size: 0.88rem !important;
}}

[data-testid="stDataFrame"] {{
    border-radius: 10px !important;
    overflow: hidden !important;
    border: 1px solid var(--border) !important;
}}

.section-label {{
    font-family: var(--font-body);
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--muted);
    margin-bottom: 12px;
    margin-top: 4px;
}}

.result-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 24px;
    margin-top: 16px;
}}

.result-card.malicious {{
    border-left: 4px solid var(--danger);
    background: rgba(239,68,68,0.05);
}}

.result-card.benign {{
    border-left: 4px solid var(--success);
    background: rgba(34,197,94,0.05);
}}

.status-dot {{
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
    margin-right: 7px;
    vertical-align: middle;
    animation: pulse 2s infinite;
}}

@keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.45; }}
}}

.info-block {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
    font-family: var(--font-body);
    font-size: 0.87rem;
    line-height: 1.7;
    color: var(--sub);
}}

.info-block strong {{ color: var(--text); font-weight: 600; }}
.info-block code {{
    font-family: var(--font);
    background: var(--card2);
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 0.82rem;
    color: var(--accent2);
}}

.pdf-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 16px;
}}

.pdf-stat {{
    background: var(--metric-bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    text-align: center;
}}

.sidebar-logo {{
    font-family: var(--font);
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--text);
    letter-spacing: -0.3px;
}}

.sidebar-logo span {{ color: var(--accent); }}

.sidebar-version {{
    font-family: var(--font-body);
    font-size: 0.72rem;
    color: var(--muted);
    margin-top: 2px;
}}

::-webkit-scrollbar {{ width: 5px; height: 5px; }}
::-webkit-scrollbar-track {{ background: var(--bg); }}
::-webkit-scrollbar-thumb {{ background: var(--scroll); border-radius: 10px; }}
</style>
""", unsafe_allow_html=True)


# ============================================================
# UTILITIES
# ============================================================
def api_call(endpoint: str, method: str = "GET", payload: dict = None) -> dict:
    try:
        url = f"{API_URL}{endpoint}"
        if method == "POST":
            response = requests.post(url, json=payload, timeout=5)
        else:
            response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        return {"error": "connection", "message": "Connexion refusee. Verifiez que l'API est demarree."}
    except requests.exceptions.Timeout:
        return {"error": "timeout", "message": "L'API ne repond pas. Reessayez dans quelques instants."}
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response else "?"
        return {"error": "http", "message": f"Erreur HTTP {code} renvoyee par l'API."}
    except Exception as exc:
        return {"error": "unknown", "message": str(exc)}


def api_call_raw(endpoint: str) -> bytes:
    """Appel API qui retourne les bytes bruts (pour PDF)"""
    try:
        url = f"{API_URL}{endpoint}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.content
    except Exception as e:
        return None


def render_risk_badge(level: str) -> str:
    color = RISK_COLORS.get(level, {}).get(st.session_state.theme, "#888")
    label = RISK_LABELS.get(level, level)
    return (
        f'<span style="background:{color};color:#fff;padding:2px 10px;'
        f'border-radius:20px;font-size:0.72rem;font-weight:700;">'
        f'{label}</span>'
    )


def format_timestamp(ts: str) -> str:
    return ts[:19].replace("T", " ") if ts else "-"


def show_api_error(error_dict: dict):
    msg = error_dict.get("message", "Erreur inconnue.")
    err_type = error_dict.get("error", "unknown")
    if err_type == "connection":
        st.error(f"**Connexion echouee** - {msg}")
    elif err_type == "timeout":
        st.warning(f"**Delai depasse** - {msg}")
    elif err_type == "http":
        st.error(f"**Erreur API** - {msg}")
    else:
        st.error(f"**Erreur** - {msg}")


# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown(
        f'<div class="sidebar-logo">IT<span>GATE</span></div>'
        f'<div class="sidebar-version">SOC Dashboard · PFE 2026</div>',
        unsafe_allow_html=True,
    )
    st.divider()

    st.markdown('<div class="section-label">Theme d\'affichage</div>', unsafe_allow_html=True)
    theme_cols = st.columns(3)
    for i, (key, meta) in enumerate(THEMES.items()):
        with theme_cols[i]:
            if st.button(meta["label"], key=f"theme_{key}", use_container_width=True):
                st.session_state.theme = key
                st.rerun()

    st.divider()

    st.markdown('<div class="section-label">Navigation</div>', unsafe_allow_html=True)
    page = st.radio("Navigation", options=PAGES, label_visibility="collapsed")

    st.divider()
    st.markdown(
        f'<p style="font-size:0.73rem;color:{T["text_muted"]};line-height:1.6">'
        f'Modeles actifs<br>'
        f'<strong style="color:{T["text_sub"]}">Random Forest · Isolation Forest · XGBoost</strong>'
        f'</p>',
        unsafe_allow_html=True,
    )

T = THEMES[st.session_state.theme]

# ============================================================
# PAGE 1 — SYSTEM STATUS
# ============================================================
if page == "System Status":
    st.title("System Status")
    st.caption("Etat en temps reel de l'API, des modeles et des composants actifs.")
    st.divider()

    status = api_call("/status")

    if "error" in status:
        show_api_error(status)
        st.stop()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("API", "En ligne")
    col2.metric("Modele principal", status.get("modeles", {}).get("random_forest", "N/A"))
    col3.metric("Alertes totales", status.get("total_alertes", 0))
    col4.metric("Latence cible", "< 2 s")

    st.markdown(
        f'<span class="status-dot" style="background:{T["success"]}"></span>'
        f'<span style="font-size:0.85rem;color:{T["success"]};font-weight:600">Tous les composants sont operationnels</span>',
        unsafe_allow_html=True,
    )

    st.divider()
    st.subheader("A propos du projet")
    st.markdown(
        f"""
        <div class="info-block">
        Ce systeme utilise le <strong>Machine Learning</strong> pour detecter automatiquement
        les comportements anormaux dans le trafic reseau en temps reel.<br><br>
        <strong>Modeles implementes</strong><br>
        · <code>Random Forest</code> - Classification supervisee (modele principal)<br>
        · <code>Isolation Forest</code> - Detection non-supervisee de menaces zero-day<br>
        · <code>XGBoost / SVM / KNN</code> - Modeles de comparaison<br><br>
        <strong>Jeux de donnees</strong><br>
        · CTU-IoT-Malware-Capture (Stratosphere Lab)<br>
        · CICIDS 2017 / 2018 - DoS, DDoS, Brute Force, Web Attacks
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# PAGE 2 — ANALYZE CONNECTION
# ============================================================
elif page == "Analyze Connection":
    st.title("Analyze Connection")
    st.caption("Saisissez les caracteristiques d'un flux reseau pour obtenir une classification ML.")
    st.divider()

    with st.form("connection_analysis_form"):
        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown('<div class="section-label">Volume de donnees</div>', unsafe_allow_html=True)
            orig_bytes = st.number_input("Octets envoyes (source)", min_value=0.0, value=500.0)
            resp_bytes = st.number_input("Octets recus (destination)", min_value=0.0, value=200.0)
            orig_pkts  = st.number_input("Paquets envoyes", min_value=1.0, value=5.0)
            resp_pkts  = st.number_input("Paquets recus", min_value=1.0, value=3.0)

        with col2:
            st.markdown('<div class="section-label">Temps et port</div>', unsafe_allow_html=True)
            duration           = st.number_input("Duree (secondes)", min_value=0.0, value=1.5)
            is_well_known_port = st.selectbox(
                "Port source < 1024",
                [0, 1],
                format_func=lambda x: "Oui - port systeme" if x else "Non - port dynamique",
            )
            is_orig_local = st.selectbox(
                "IP source locale",
                [1, 0],
                format_func=lambda x: "Oui - reseau interne" if x else "Non - adresse externe",
            )
            hour = st.slider("Heure de connexion", 0, 23, 14)

        with col3:
            st.markdown('<div class="section-label">Metriques avancees</div>', unsafe_allow_html=True)
            orig_ip_bytes = st.number_input("Octets IP source", min_value=0.0, value=600.0)
            resp_ip_bytes = st.number_input("Octets IP destination", min_value=0.0, value=250.0)
            inter_arrival = st.number_input("Inter-arrivee (secondes)", min_value=0.0, value=0.5)
            day_of_week   = st.slider("Jour de la semaine (0 = Lundi)", 0, 6, 1)

        submitted = st.form_submit_button("Lancer l'analyse", use_container_width=True)

    if submitted:
        pkt_ratio         = orig_pkts / (resp_pkts + 1)
        avg_orig_pkt_size = orig_ip_bytes / (orig_pkts + 1)
        avg_resp_pkt_size = resp_ip_bytes / (resp_pkts + 1)

        payload = {
            "duration":           duration,
            "orig_bytes":         orig_bytes,
            "resp_bytes":         resp_bytes,
            "orig_pkts":          orig_pkts,
            "resp_pkts":          resp_pkts,
            "orig_ip_bytes":      orig_ip_bytes,
            "resp_ip_bytes":      resp_ip_bytes,
            "pkt_ratio":          pkt_ratio,
            "avg_orig_pkt_size":  avg_orig_pkt_size,
            "avg_resp_pkt_size":  avg_resp_pkt_size,
            "is_orig_local":      is_orig_local,
            "is_well_known_port": is_well_known_port,
            "hour":               hour,
            "minute":             0,
            "day_of_week":        day_of_week,
            "inter_arrival_time": inter_arrival,
        }

        with st.spinner("Classifying traffic..."):
            result = api_call("/predict", method="POST", payload=payload)

        if "error" in result:
            show_api_error(result)
            st.stop()

        prediction = result.get("prediction")
        risk       = result.get("risk_level", "LOW")
        confidence = result.get("confidence", 0)
        label      = result.get("label", "-")
        message    = result.get("alert_message", "")

        card_class = "malicious" if prediction == 1 else "benign"
        icon_color = T["danger"] if prediction == 1 else T["success"]
        icon = "■" if prediction == 1 else "●"

        st.markdown(
            f'<div class="result-card {card_class}">'
            f'<span style="color:{icon_color};font-size:0.85rem;margin-right:8px">{icon}</span>'
            f'<strong style="font-size:0.95rem">{message}</strong>'
            f'</div>',
            unsafe_allow_html=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        c1.metric("Classification", label)
        c2.metric("Confiance", f"{confidence} %")
        c3.metric("Niveau de risque", RISK_LABELS.get(risk, risk))


# ============================================================
# PAGE 3 — ALERT LOG
# ============================================================
elif page == "Alert Log":
    st.title("Alert Log")
    st.caption("Journal horodate de toutes les connexions analysees et alertes generees.")
    st.divider()

    col_btn, _ = st.columns([1, 6])
    with col_btn:
        if st.button("Rafraichir"):
            st.rerun()

    with st.spinner("Chargement du journal..."):
        data = api_call("/alerts?limit=100")

    if "error" in data:
        show_api_error(data)
        st.stop()

    alerts = data.get("alertes", [])

    if not alerts:
        st.info("Aucune alerte enregistree. Utilisez 'Analyze Connection' pour analyser des flux reseau.")
        st.stop()

    st.metric("Entrees dans le journal", data.get("total", len(alerts)))
    st.divider()

    rows = [
        {
            "Horodatage":       format_timestamp(a["timestamp"]),
            "Classification":   a["label"],
            "Confiance (%)":    a["confidence"],
            "Niveau de risque": RISK_LABELS.get(a["risk_level"], a["risk_level"]),
        }
        for a in alerts
    ]

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    malicious = sum(1 for a in alerts if a["prediction"] == 1)
    benign    = len(alerts) - malicious

    c1, c2 = st.columns(2)

    with c1:
        fig_pie = px.pie(
            values=[benign, malicious],
            names=["Benin", "Malveillant"],
            color_discrete_sequence=[T["success"], T["danger"]],
            title="Repartition du trafic analyse",
            hole=0.45,
        )
        fig_pie.update_layout(
            paper_bgcolor=T["plot_bg"],
            plot_bgcolor=T["plot_bg"],
            font_color=T["text"],
            font_family=T["font_body"],
            title_font_size=14,
            margin=dict(t=40, b=40, l=20, r=20),
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with c2:
        risk_counts = {}
        for a in alerts:
            lvl = a.get("risk_level", "LOW")
            risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

        if risk_counts:
            fig_risk = px.bar(
                x=[RISK_LABELS.get(k, k) for k in risk_counts],
                y=list(risk_counts.values()),
                color=list(risk_counts.keys()),
                color_discrete_map={
                    k: RISK_COLORS[k].get(st.session_state.theme, "#888")
                    for k in RISK_COLORS
                },
                title="Distribution des niveaux de risque",
                labels={"x": "Niveau", "y": "Occurrences"},
            )
            fig_risk.update_layout(
                paper_bgcolor=T["plot_bg"],
                plot_bgcolor=T["plot_bg"],
                font_color=T["text"],
                font_family=T["font_body"],
                title_font_size=14,
                showlegend=False,
                xaxis=dict(gridcolor=T["grid_color"]),
                yaxis=dict(gridcolor=T["grid_color"]),
                margin=dict(t=40, b=20, l=20, r=20),
            )
            st.plotly_chart(fig_risk, use_container_width=True)


# ============================================================
# PAGE 4 — STATISTICS
# ============================================================
elif page == "Statistics":
    st.title("Statistics")
    st.caption("Vue agregee des performances du systeme de detection et distribution des menaces.")
    st.divider()

    with st.spinner("Chargement des statistiques..."):
        stats = api_call("/stats")

    if "message" in stats and "error" not in stats:
        st.info(stats["message"])
        st.stop()

    if "error" in stats:
        show_api_error(stats)
        st.stop()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total analyses",     stats.get("total_analyses", 0))
    c2.metric("Trafic malveillant", stats.get("trafic_malveillant", 0))
    c3.metric("Trafic benin",       stats.get("trafic_benin", 0))
    c4.metric("Taux de detection",  f"{stats.get('taux_detection', 0)} %")

    st.divider()

    risk_levels = stats.get("niveaux_risque", {})
    if risk_levels:
        fig_bar = px.bar(
            x=[RISK_LABELS.get(k, k) for k in risk_levels],
            y=list(risk_levels.values()),
            color=list(risk_levels.keys()),
            color_discrete_map={
                k: RISK_COLORS[k].get(st.session_state.theme, "#888")
                for k in RISK_COLORS
            },
            title="Distribution des niveaux de risque",
            labels={"x": "Niveau de risque", "y": "Nombre de detections"},
        )
        fig_bar.update_layout(
            paper_bgcolor=T["plot_bg"],
            plot_bgcolor=T["plot_bg"],
            font_color=T["text"],
            font_family=T["font_body"],
            title_font_size=14,
            showlegend=False,
            xaxis=dict(gridcolor=T["grid_color"]),
            yaxis=dict(gridcolor=T["grid_color"]),
            margin=dict(t=40, b=20, l=20, r=20),
        )
        st.plotly_chart(fig_bar, use_container_width=True)


# ============================================================
# PAGE 5 — PDF REPORT  ← NOUVELLE PAGE
# ============================================================
elif page == "PDF Report":
    st.title("PDF Report")
    st.caption("Generez et telechargez un rapport PDF complet des incidents detectes.")
    st.divider()

    # --- Apercu des stats avant generation ---
    with st.spinner("Chargement des donnees..."):
        stats = api_call("/stats")
        alerts_data = api_call("/alerts?limit=100")

    if "error" in stats or "error" in alerts_data:
        st.warning("Impossible de charger les donnees. Verifiez que l'API est en ligne.")
        st.stop()

    # Si pas d'alertes
    if "message" in stats:
        st.info("Aucune analyse effectuee. Allez dans 'Analyze Connection' pour analyser des connexions reseau d'abord.")
        st.stop()

    # --- Statistiques resumees ---
    st.subheader("Apercu du rapport")
    st.markdown('<div class="section-label">Contenu qui sera inclus dans le PDF</div>',
                unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total analyses",     stats.get("total_analyses", 0))
    c2.metric("Malveillants",       stats.get("trafic_malveillant", 0))
    c3.metric("Benins",             stats.get("trafic_benin", 0))
    c4.metric("Taux detection",     f"{stats.get('taux_detection', 0)} %")

    st.divider()

    # --- Contenu du rapport ---
    st.subheader("Contenu du rapport PDF")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            f"""
            <div class="info-block">
            <strong>Page 1 - Resume executif</strong><br>
            · Informations du systeme<br>
            · Total connexions analysees<br>
            · Connexions malveillantes vs benignes<br>
            · Periode analysee<br>
            · Distribution des niveaux de risque<br><br>

            <strong>Page 2 - Journal des alertes</strong><br>
            · 50 dernieres alertes horodatees<br>
            · Classification + confiance + niveau de risque<br>
            · Message de chaque alerte
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="info-block">
            <strong>Page 3 - Recommandations</strong><br>
            · Recommandations de securite automatiques<br>
            · Basees sur les alertes detectees<br>
            · Actions prioritaires pour l'equipe SOC<br><br>

            <strong>Informations techniques</strong><br>
            · Framework ML utilise<br>
            · Version et hebergement<br>
            · Signature et date de generation<br>
            · Marque Confidentiel
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # --- Distribution des risques ---
    risk_levels = stats.get("niveaux_risque", {})
    if risk_levels:
        fig = px.pie(
            values=list(risk_levels.values()),
            names=[RISK_LABELS.get(k, k) for k in risk_levels],
            color=list(risk_levels.keys()),
            color_discrete_map={
                RISK_LABELS.get(k, k): RISK_COLORS[k].get(st.session_state.theme, "#888")
                for k in RISK_COLORS
            },
            title="Distribution des risques (apercu)",
            hole=0.4,
        )
        fig.update_layout(
            paper_bgcolor=T["plot_bg"],
            plot_bgcolor=T["plot_bg"],
            font_color=T["text"],
            font_family=T["font_body"],
            title_font_size=14,
            margin=dict(t=40, b=20, l=20, r=20),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # --- BOUTON DE TELECHARGEMENT ---
    st.subheader("Telecharger le rapport")

    col_btn, col_info = st.columns([1, 2])

    with col_btn:
        if st.button("Generer et telecharger le PDF", use_container_width=True):
            with st.spinner("Generation du rapport PDF en cours..."):
                pdf_bytes = api_call_raw("/report")

            if pdf_bytes is None:
                st.error("Erreur lors de la generation du PDF. Verifiez que l'API est en ligne.")
            else:
                from datetime import datetime
                nom_fichier = f"rapport_itgate_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

                st.success("Rapport PDF genere avec succes !")
                st.download_button(
                    label="Cliquez ici pour telecharger le PDF",
                    data=pdf_bytes,
                    file_name=nom_fichier,
                    mime="application/pdf",
                    use_container_width=True,
                )

    with col_info:
        st.markdown(
            f"""
            <div class="info-block">
            <strong>Format :</strong> PDF 3 pages<br>
            <strong>Langue :</strong> Francais<br>
            <strong>Modele :</strong> Random Forest (99.49% accuracy)<br>
            <strong>Mise a jour :</strong> En temps reel<br>
            <strong>Confidentialite :</strong> Marque Confidentiel ITGATE
            </div>
            """,
            unsafe_allow_html=True,
        )