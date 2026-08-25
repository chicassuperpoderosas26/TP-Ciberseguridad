import os
import time
import json
import random
import requests
from datetime import datetime, timezone, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import psycopg2
import streamlit as st

# ── Configuración de Entorno & BD ─────────────────────────────────────────────
# Zona Horaria de Argentina (ART = UTC-3)
TZ_ARG = timezone(timedelta(hours=-3))

DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     int(os.getenv("DB_PORT", 5432)),
    "dbname":   os.getenv("DB_NAME", "siem"),
    "user":     os.getenv("DB_USER", "siem"),
    "password": os.getenv("DB_PASSWORD", "siem123"),
}

IS_DOCKER = (DB_CONFIG["host"] == "postgres")
DEFAULT_WEBHOOK = "http://n8n:5678/webhook/alert/siem" if IS_DOCKER else "http://localhost:5678/webhook/alert/siem"
N8N_WEBHOOK_URL = os.getenv("SIEM_WEBHOOK_URL", DEFAULT_WEBHOOK)
SIEM_KEY = os.getenv("SIEM_API_KEY", "superpoderosas26")
RAMA_TEST_IP = "45.33.32.156"

# Paleta Chicas Superpoderosas (PPG Theme)
PPG_PINK   = "#FF6B9D"
PPG_BLUE   = "#5BC8F5"
PPG_GREEN  = "#7ED4A0"
PPG_PURPLE = "#C39BD3"
PPG_DARK   = "#1a0e2e"

SEVERITY_COLORS = {
    "critical": PPG_PINK,
    "high":     "#FF9A6C",
    "medium":   PPG_BLUE,
    "low":      PPG_GREEN,
    "normal":   PPG_PURPLE,
}

REFRESH_SECONDS = 30

# ── Datos de Atacantes & Payloads (Igual a attack_simulator.py) ────────────────
ATTACKER_IPS = [
    "185.156.73.233", "80.94.95.116", "196.251.83.100",
    "45.33.32.156", "185.220.101.42", "89.234.157.254", "178.128.95.10",
]
TARGET_USERS = ["root", "admin", "ubuntu", "deploy", "postgres", "www-data", "siem"]
FIM_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
    "/var/www/html/index.php", "/etc/crontab", "/usr/local/bin/backup.sh",
]
SQLI_PAYLOADS = [
    "' OR 1=1 --", "'; DROP TABLE users; --",
    "' UNION SELECT * FROM credentials --",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --", "admin'--",
]
WEBSHELL_PATHS = [
    "/var/www/html/uploads/cmd.php", "/var/www/html/.hidden/shell.php",
    "/tmp/backdoor.py", "/var/www/html/wp-content/plugins/hack.php",
]
SUSPICIOUS_COUNTRIES = [
    ("Russia", "RU"), ("China", "CN"), ("North Korea", "KP"),
    ("Iran", "IR"), ("Nigeria", "NG"),
]
MALWARE_SIGNATURES = [
    {"name": "Trojan.GenericKD.46789", "type": "trojan", "path": "/tmp/.cache/svchost.exe"},
    {"name": "Backdoor.Linux.Mirai.b", "type": "botnet", "path": "/var/tmp/.x11"},
    {"name": "Ransom.WannaCry.S", "type": "ransomware", "path": "/home/user/Documents/important.docx.encrypted"},
    {"name": "CoinMiner.Linux.XMRIG.a", "type": "cryptominer", "path": "/opt/.xmrig/config.json"},
]

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOC Dashboard & Security Operations — UTN",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS — Custom Properties ───────────────────────────────────────────────────
_css_vars = (
    "<style>:root{"
    "--ppg-pink:" + PPG_PINK + ";"
    "--ppg-blue:" + PPG_BLUE + ";"
    "--ppg-green:" + PPG_GREEN + ";"
    "--ppg-purple:" + PPG_PURPLE + ";"
    "--ppg-dark:" + PPG_DARK + ";"
    "}</style>"
)
st.markdown(_css_vars, unsafe_allow_html=True)

st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');

  .stApp {
    background-color: var(--ppg-dark);
    color: #e8d5f0;
    font-family: 'Inter', sans-serif;
  }

  /* Estilos de Sidebar */
  [data-testid="stSidebar"] {
    background-color: #150926;
    border-right: 1px solid color-mix(in srgb, var(--ppg-purple) 20%, transparent);
  }
  .sidebar-nav-title {
    font-size: 0.72rem;
    font-weight: 700;
    color: var(--ppg-purple);
    letter-spacing: 0.08em;
    margin-bottom: 10px;
    padding-left: 4px;
  }

  /* Botones del menú lateral: Primario (Activo = Borde y Letra Oro) vs Secundario */
  [data-testid="stSidebar"] button[kind="primary"] {
    background-color: rgba(255, 215, 0, 0.12) !important;
    color: #FFD700 !important;
    border: 2px solid #FFD700 !important;
    box-shadow: 0 0 14px rgba(255, 215, 0, 0.35) !important;
    font-weight: 700 !important;
    border-radius: 8px !important;
    text-align: left !important;
  }
  [data-testid="stSidebar"] button[kind="secondary"] {
    background-color: rgba(34, 14, 56, 0.6) !important;
    color: #e8d5f0 !important;
    border: 1px solid rgba(195, 155, 211, 0.25) !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
    text-align: left !important;
    transition: all 0.2s ease !important;
  }
  [data-testid="stSidebar"] button:hover {
    border-color: var(--ppg-blue) !important;
    color: var(--ppg-blue) !important;
    box-shadow: 0 0 10px rgba(91, 200, 245, 0.3) !important;
  }

  /* Botones del contenido principal: Fondo blanco con letras en negro nítido */
  .main .stButton > button, [data-testid="stMain"] .stButton > button, .stButton > button:not([data-testid="stSidebar"] *) {
    color: #0a0a0a !important;
    background-color: #ffffff !important;
    border: 1px solid #d4d4d8 !important;
    font-weight: 700 !important;
    border-radius: 8px !important;
    box-shadow: 0 2px 6px rgba(0,0,0,0.18) !important;
    transition: all 0.15s ease-in-out !important;
  }
  .main .stButton > button:hover, [data-testid="stMain"] .stButton > button:hover, .stButton > button:not([data-testid="stSidebar"] *):hover {
    background-color: #f4f4f5 !important;
    border-color: var(--ppg-blue) !important;
    color: #000000 !important;
    box-shadow: 0 0 12px rgba(91, 200, 245, 0.4) !important;
  }
  .main .stButton > button p, [data-testid="stMain"] .stButton > button p,
  .main .stButton > button span, [data-testid="stMain"] .stButton > button span,
  .main .stButton > button div, [data-testid="stMain"] .stButton > button div {
    color: #0a0a0a !important;
    font-weight: 700 !important;
  }

  /* Header SOC */
  .soc-header {
    background: linear-gradient(135deg, #2a1040 0%, #1a1a3e 50%, #0e2a1a 100%);
    border: 1px solid color-mix(in srgb, var(--ppg-purple) 33%, transparent);
    border-radius: 14px; padding: 22px 30px; margin-bottom: 22px;
    display: flex; align-items: center; justify-content: space-between;
    box-shadow: 0 0 30px color-mix(in srgb, var(--ppg-pink) 13%, transparent);
  }
  .soc-title {
    font-size: 1.75rem; font-weight: 800;
    background: linear-gradient(90deg, var(--ppg-pink), var(--ppg-blue), var(--ppg-green));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0;
  }
  .soc-subtitle { font-size: 0.85rem; color: var(--ppg-purple); margin: 4px 0 0; font-weight: 600; }
  .ppg-badge { display: flex; gap: 6px; align-items: center; font-size: 0.8rem; font-weight: 700; color: #fff; }
  .dot-pink  { width:10px; height:10px; border-radius:50%; background:var(--ppg-pink);  box-shadow: 0 0 8px var(--ppg-pink); }
  .dot-blue  { width:10px; height:10px; border-radius:50%; background:var(--ppg-blue);  box-shadow: 0 0 8px var(--ppg-blue); }
  .dot-green { width:10px; height:10px; border-radius:50%; background:var(--ppg-green); box-shadow: 0 0 8px var(--ppg-green); }

  /* Tarjetas KPI */
  .kpi-card {
    background: linear-gradient(145deg, #220e38, #1a1a2e);
    border: 1px solid color-mix(in srgb, var(--ppg-purple) 27%, transparent);
    border-radius: 12px; padding: 18px 16px; text-align: center;
    height: 110px; display: flex; flex-direction: column; justify-content: center;
    transition: box-shadow .2s;
  }
  .kpi-card:hover { box-shadow: 0 0 16px color-mix(in srgb, var(--ppg-purple) 33%, transparent); }
  .kpi-label { font-size: 0.72rem; color: var(--ppg-purple); text-transform: uppercase; letter-spacing: .07em; }
  .kpi-value { font-size: 1.9rem; font-weight: 700; margin: 5px 0 0; }
  .kpi-critical { color: var(--ppg-pink);  text-shadow: 0 0 12px color-mix(in srgb, var(--ppg-pink) 53%, transparent); }
  .kpi-warning  { color: #FF9A6C;          text-shadow: 0 0 12px rgba(255,154,108,0.53); }
  .kpi-ok       { color: var(--ppg-green); text-shadow: 0 0 12px color-mix(in srgb, var(--ppg-green) 53%, transparent); }
  .kpi-info     { color: var(--ppg-blue);  text-shadow: 0 0 12px color-mix(in srgb, var(--ppg-blue) 53%, transparent); }

  /* Secciones y alertas */
  .section-title {
    font-size: 0.85rem; font-weight: 700; text-transform: uppercase; letter-spacing: .1em;
    margin: 22px 0 12px; padding-bottom: 6px;
    background: linear-gradient(90deg, var(--ppg-pink), var(--ppg-blue));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    border-bottom: 1px solid color-mix(in srgb, var(--ppg-purple) 27%, transparent);
  }

  .alert-row {
    display: flex; align-items: center; gap: 10px;
    padding: 8px 14px; border-radius: 8px; margin-bottom: 4px;
    background: rgba(34,14,56,0.67);
    border: 1px solid color-mix(in srgb, var(--ppg-purple) 20%, transparent);
    font-size: 0.82rem;
  }
  .badge { border-radius: 5px; padding: 2px 9px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; min-width: 65px; text-align: center; }
  .badge-critical { background: color-mix(in srgb, var(--ppg-pink) 13%, transparent);   color: var(--ppg-pink);   border: 1px solid color-mix(in srgb, var(--ppg-pink) 40%, transparent); }
  .badge-high     { background: rgba(255,154,108,0.13);  color: #FF9A6C;  border: 1px solid rgba(255,154,108,0.40); }
  .badge-medium   { background: color-mix(in srgb, var(--ppg-blue) 13%, transparent);   color: var(--ppg-blue);   border: 1px solid color-mix(in srgb, var(--ppg-blue) 40%, transparent); }
  .badge-low      { background: color-mix(in srgb, var(--ppg-green) 13%, transparent);  color: var(--ppg-green);  border: 1px solid color-mix(in srgb, var(--ppg-green) 40%, transparent); }
  .badge-normal   { background: color-mix(in srgb, var(--ppg-purple) 13%, transparent); color: var(--ppg-purple); border: 1px solid color-mix(in srgb, var(--ppg-purple) 40%, transparent); }

  /* Health cards */
  .health-card {
    background: linear-gradient(145deg, #1d0b30, #15152a);
    border: 1px solid color-mix(in srgb, var(--ppg-purple) 27%, transparent);
    border-radius: 12px; padding: 16px; margin-bottom: 14px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .health-name { font-weight: 700; font-size: 1rem; color: #ffffff; }
  .health-desc { font-size: 0.78rem; color: var(--ppg-purple); }
  .status-online {
    background: color-mix(in srgb, var(--ppg-green) 13%, transparent);
    color: var(--ppg-green); border: 1px solid color-mix(in srgb, var(--ppg-green) 40%, transparent);
    padding: 4px 12px; border-radius: 6px; font-weight: 700; font-size: 0.8rem;
  }
  .status-offline {
    background: color-mix(in srgb, var(--ppg-pink) 13%, transparent);
    color: var(--ppg-pink); border: 1px solid color-mix(in srgb, var(--ppg-pink) 40%, transparent);
    padding: 4px 12px; border-radius: 6px; font-weight: 700; font-size: 0.8rem;
  }

  /* Landing Page */
  .landing-hero {
    background: linear-gradient(135deg, #220e38 0%, #15152e 100%);
    border: 1px solid color-mix(in srgb, var(--ppg-purple) 27%, transparent);
    border-radius: 14px; padding: 28px; margin-bottom: 24px;
    box-shadow: 0 4px 25px rgba(0,0,0,0.4);
  }
  .landing-title {
    font-size: 2.2rem; font-weight: 800;
    background: linear-gradient(90deg, var(--ppg-pink), var(--ppg-blue), var(--ppg-green));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px;
  }
  .landing-subtitle { font-size: 1.1rem; color: var(--ppg-blue); font-weight: 600; margin-bottom: 16px; }
  .tech-tag {
    display: inline-block;
    background: color-mix(in srgb, var(--ppg-purple) 13%, transparent);
    border: 1px solid color-mix(in srgb, var(--ppg-purple) 40%, transparent);
    color: var(--ppg-blue); border-radius: 6px; padding: 4px 12px;
    font-size: 0.8rem; font-weight: 600; margin-right: 8px; margin-bottom: 8px;
  }
  .feature-card {
    background: linear-gradient(145deg, #220e38, #1a1a2e);
    border: 1px solid color-mix(in srgb, var(--ppg-purple) 20%, transparent);
    border-radius: 12px; padding: 20px; height: 100%; margin-bottom: 16px;
  }
  .feature-icon { font-size: 2rem; margin-bottom: 10px; }
  .feature-title { font-size: 1.1rem; font-weight: 700; color: #ffffff; margin-bottom: 6px; }
  .feature-text { font-size: 0.88rem; color: var(--ppg-purple); line-height: 1.5; }

  #MainMenu, footer { visibility: hidden; }
  .block-container { padding-top: 1.2rem; }
</style>
""", unsafe_allow_html=True)

# ── Estado global en memoria ──────────────────────────────────────────────────
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "🌐 Landing Page & Arquitectura"

if "attack_logs" not in st.session_state:
    st.session_state["attack_logs"] = []

# ── DB Helpers (Consultas directas a PostgreSQL en tiempo real) ───────────────
_db_conn = None


def get_connection():
    global _db_conn
    if _db_conn is None or _db_conn.closed:
        _db_conn = psycopg2.connect(**DB_CONFIG)
    return _db_conn


def query(sql):
    global _db_conn
    try:
        conn = get_connection()
        return pd.read_sql_query(sql, conn)
    except Exception:
        _db_conn = None
        try:
            conn = get_connection()
            return pd.read_sql_query(sql, conn)
        except Exception:
            return pd.DataFrame()


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Consultas SQL para Dashboard SOC ──────────────────────────────────────────
_SQL_KPIS = (
    "SELECT"
    " (SELECT COUNT(*) FROM alerts WHERE ts >= NOW() - INTERVAL '24 hours') AS alerts_24h,"
    " (SELECT COUNT(*) FROM alerts WHERE ts >= NOW() - INTERVAL '1 hour') AS alerts_1h,"
    " (SELECT COUNT(*) FROM incidents WHERE status = 'open') AS open_incidents,"
    " (SELECT COALESCE(ROUND(AVG(EXTRACT(EPOCH FROM (p.executed_at - a.ts)))::numeric, 1), 0)"
    "  FROM alerts a JOIN playbook_runs p ON p.alert_id = a.id) AS mttr_sec,"
    " (SELECT COALESCE(automation_percentage, 0) FROM automation_rate_operational) AS auto_pct,"
    " (SELECT COUNT(*) FROM failed_alerts WHERE resolved = false) AS failed,"
    " (SELECT COUNT(*) FROM ip_blacklist WHERE active = true AND (expires_at IS NULL OR expires_at > NOW())) AS ips_bloqueadas,"
    " (SELECT ROUND(avg_mtta_seconds::numeric, 1) FROM mtta_stats) AS mtta_sec,"
    " (SELECT acknowledged_count FROM mtta_stats) AS mtta_n"
)

_SQL_TIMELINE = (
    "SELECT DATE_TRUNC('hour', ts AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires') AS hora, severity, COUNT(*) AS total"
    " FROM alerts WHERE ts >= NOW() - INTERVAL '24 hours'"
    " GROUP BY hora, severity ORDER BY hora"
)

_SQL_GEO = (
    "SELECT country_code, COUNT(*) AS ataques FROM alerts"
    " WHERE country_code IS NOT NULL AND country_code != ''"
    " GROUP BY country_code ORDER BY ataques DESC"
)

_SQL_TOP_IPS = (
    "SELECT src_ip, COUNT(*) AS alertas FROM alerts"
    " WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY alertas DESC LIMIT 8"
)

_SQL_RECENT = (
    "SELECT TO_CHAR(ts AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires', 'HH24:MI:SS') AS hora, rule_id, src_ip, username, severity, status"
    " FROM alerts ORDER BY ts DESC LIMIT 20"
)

_SQL_PLAYBOOKS = (
    "SELECT workflow, outcome, COUNT(*) AS ejecuciones"
    " FROM playbook_runs GROUP BY workflow, outcome ORDER BY ejecuciones DESC"
)

_SQL_TOP_RULES = (
    "SELECT rule_id AS regla, COUNT(*) AS disparos,"
    " COUNT(*) FILTER (WHERE severity = 'critical') AS criticas,"
    " COUNT(*) FILTER (WHERE severity = 'high') AS altas,"
    " MAX(ts AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires') AS ultima_vez"
    " FROM alerts WHERE ts >= NOW() - INTERVAL '24 hours'"
    " GROUP BY rule_id ORDER BY disparos DESC LIMIT 8"
)

_SQL_SEV_DIST = (
    "SELECT severity, COUNT(*) AS total FROM alerts WHERE severity IS NOT NULL GROUP BY severity ORDER BY total DESC"
)

_SQL_BLACKLIST = (
    "SELECT ip, reason AS razón,"
    " TO_CHAR(blocked_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires', 'DD/MM HH24:MI') AS bloqueada,"
    " TO_CHAR(expires_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires', 'DD/MM HH24:MI') AS vence,"
    " enforced, enforcement_message"
    " FROM ip_blacklist"
    " WHERE active = true AND (expires_at IS NULL OR expires_at > NOW())"
    " ORDER BY blocked_at DESC LIMIT 10"
)

_SQL_INCIDENTS = (
    "SELECT id, type AS tipo, src_ip AS ip_origen, username AS usuario,"
    " attempts AS intentos, severity,"
    " TO_CHAR(created_at AT TIME ZONE 'UTC' AT TIME ZONE 'America/Argentina/Buenos_Aires', 'DD/MM HH24:MI') AS creado"
    " FROM incidents WHERE status = 'open'"
    " ORDER BY created_at DESC LIMIT 10"
)


def get_kpis():
    return query(_SQL_KPIS)


def get_timeline():
    return query(_SQL_TIMELINE)


def get_sev_dist():
    return query(_SQL_SEV_DIST)


def get_geo_attacks():
    return query(_SQL_GEO)


def get_top_ips():
    return query(_SQL_TOP_IPS)


def get_recent_alerts():
    return query(_SQL_RECENT)


def get_playbook_summary():
    return query(_SQL_PLAYBOOKS)


def get_top_rules():
    return query(_SQL_TOP_RULES)


def get_blacklist():
    return query(_SQL_BLACKLIST)


def get_open_incidents():
    return query(_SQL_INCIDENTS)


# ── Render Helpers ────────────────────────────────────────────────────────────
def kpi_card(label, value, css_class="kpi-info"):
    st.markdown(
        '<div class="kpi-card"><div class="kpi-label">'
        + str(label)
        + '</div><div class="kpi-value '
        + css_class
        + '">'
        + str(value)
        + "</div></div>",
        unsafe_allow_html=True,
    )


def severity_badge(sev):
    cls = "badge-" + sev.lower() if sev.lower() in SEVERITY_COLORS else "badge-normal"
    return '<span class="badge ' + cls + '">' + sev.upper() + "</span>"


def plotly_ppg(fig):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e8d5f0",
        font_family="Inter, sans-serif",
        margin=dict(l=0, r=0, t=34, b=0),
        legend=dict(bgcolor="rgba(0,0,0,0)", font_color="#c39bd3"),
        title_font_color=PPG_PURPLE,
    )
    fig.update_xaxes(gridcolor="rgba(61,31,85,0.27)", zerolinecolor="rgba(61,31,85,0.27)")
    fig.update_yaxes(gridcolor="rgba(61,31,85,0.27)", zerolinecolor="rgba(61,31,85,0.27)")
    return fig


def render_header(title, subtitle):
    now_str = datetime.now(TZ_ARG).strftime("%d/%m/%Y %H:%M:%S")
    st.markdown(
        '<div class="soc-header"><div>'
        '<p class="soc-title">' + title + "</p>"
        '<p class="soc-subtitle">' + subtitle + " &nbsp;·&nbsp; UTN FRM &nbsp;·&nbsp; " + now_str + "</p>"
        "</div>"
        '<div class="ppg-badge">'
        '<div class="dot-pink"></div><div class="dot-blue"></div><div class="dot-green"></div>'
        "&nbsp;LIVE SOC</div></div>",
        unsafe_allow_html=True,
    )


def send_alert_to_n8n(webhook_url, payload):
    headers = {"Content-Type": "application/json", "x-siem-key": SIEM_KEY}
    
    # Probar primero el host interno de Docker (n8n:5678), luego localhost:5678
    candidates = [
        "http://n8n:5678/webhook/alert/siem",
        "http://localhost:5678/webhook/alert/siem",
    ]
    if webhook_url and webhook_url not in candidates:
        if "n8n" in webhook_url:
            candidates.insert(0, webhook_url)
        else:
            candidates.append(webhook_url)

    last_err = ""
    for url in candidates:
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=6)
            if resp.status_code == 200:
                return True, "200 OK — Alerta entregada a n8n y registrada en PostgreSQL"
            elif resp.status_code == 403:
                return False, "HTTP 403 en n8n: En n8n abrí el nodo Webhook y poné Authentication: None (o configurá la credencial Header Auth con Name: x-siem-key y Value: superpoderosas26)."
            elif resp.status_code == 404:
                return False, "HTTP 404: El workflow en n8n no está ACTIVO (switch verde arriba a la derecha en n8n)."
            else:
                last_err = "HTTP " + str(resp.status_code) + " — " + resp.text
        except Exception as e:
            last_err = str(e)
            continue

    return False, "Error de conexión (" + last_err + ")"


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 1: Dashboard SOC (Métricas & Alertas)
# ══════════════════════════════════════════════════════════════════════════════
def render_dashboard_soc():
    render_header("🛡️ Panel de Operaciones de Seguridad", "SOC Dashboard & Real-Time Monitoring")

    kpis_df = get_kpis()
    if not kpis_df.empty:
        k = kpis_df.iloc[0]
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        with col1:
            alerts_1h = int(k["alerts_1h"]) if pd.notnull(k["alerts_1h"]) else 0
            css = "kpi-critical" if alerts_1h > 10 else "kpi-ok"
            kpi_card("Alertas última hora", alerts_1h, css)
        with col2:
            alerts_24h = int(k["alerts_24h"]) if pd.notnull(k["alerts_24h"]) else 0
            css = "kpi-warning" if alerts_24h > 50 else "kpi-info"
            kpi_card("Alertas 24 h", alerts_24h, css)
        with col3:
            inc_open = int(k["open_incidents"]) if pd.notnull(k["open_incidents"]) else 0
            css = "kpi-critical" if inc_open > 0 else "kpi-ok"
            kpi_card("Incidentes abiertos", inc_open, css)
        with col4:
            bloq = int(k["ips_bloqueadas"]) if pd.notnull(k["ips_bloqueadas"]) else 0
            css = "kpi-critical" if bloq > 0 else "kpi-ok"
            kpi_card("IPs bloqueadas (SOAR)", bloq, css)
        with col5:
            auto = float(k["auto_pct"]) if pd.notnull(k["auto_pct"]) else 0.0
            css = "kpi-ok" if auto >= 80 else ("kpi-warning" if auto >= 50 else "kpi-critical")
            kpi_card("Tasa autom. (op.)", str(round(auto, 1)) + "%", css)
        with col6:
            failed_n = int(k["failed"]) if pd.notnull(k["failed"]) else 0
            css = "kpi-critical" if failed_n > 0 else "kpi-ok"
            kpi_card("Alertas fallidas", failed_n, css)

    st.markdown('<div class="section-title">Análisis de Alertas & Distribución de Amenazas</div>', unsafe_allow_html=True)
    col_left, col_right = st.columns([1.6, 1.1])

    with col_left:
        timeline_df = get_timeline()
        if not timeline_df.empty:
            fig = px.bar(
                timeline_df, x="hora", y="total", color="severity",
                color_discrete_map=SEVERITY_COLORS,
                title="Volumen de Alertas por Hora (últimas 24 h)", barmode="stack",
            )
            st.plotly_chart(plotly_ppg(fig), use_container_width=True)
        else:
            st.info("Sin datos de timeline aún.")

    with col_right:
        sev_df = get_sev_dist()
        if not sev_df.empty:
            fig_pie = px.pie(
                sev_df, values="total", names="severity",
                color="severity", color_discrete_map=SEVERITY_COLORS,
                title="Distribución por Severidad", hole=0.45,
            )
            fig_pie.update_traces(textposition="inside", textinfo="percent+label")
            st.plotly_chart(plotly_ppg(fig_pie), use_container_width=True)
        else:
            top_df = get_top_ips()
            if not top_df.empty:
                fig = px.bar(
                    top_df, x="alertas", y="src_ip", orientation="h",
                    title="Top IPs sospechosas", color="alertas",
                    color_continuous_scale=[PPG_GREEN, PPG_BLUE, PPG_PINK],
                )
                fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False)
                st.plotly_chart(plotly_ppg(fig), use_container_width=True)
            else:
                st.info("Sin datos de severidad.")

    st.markdown('<div class="section-title">🚫 Lista Negra de IPs Bloqueadas (Firewall SOAR) & Incidentes Abiertos</div>', unsafe_allow_html=True)
    col_black, col_inc = st.columns([1.1, 1.1])

    with col_black:
        bl_df = get_blacklist()
        if not bl_df.empty:
            rows_html = ""
            for _, r in bl_df.iterrows():
                rows_html += (
                    '<div class="alert-row" style="border-left:3px solid ' + PPG_PINK + ';">'
                    '<span style="color:' + PPG_PURPLE + ';min-width:65px;font-size:0.75rem;">' + str(r.get("bloqueada")) + "</span>"
                    '<span style="color:' + PPG_PINK + ';font-weight:700;min-width:125px;">' + str(r.get("ip")) + "</span>"
                    '<span style="flex:1;color:#e8d5f0;font-size:0.78rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + str(r.get("razón", "Bloqueo SOAR")) + "</span>"
                    '<span style="background:rgba(255,107,157,0.2);color:' + PPG_PINK + ';border:1px solid ' + PPG_PINK + ';padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;">BLOQUEADA</span>'
                    "</div>"
                )
            st.markdown(rows_html, unsafe_allow_html=True)
        else:
            st.markdown(
                '<div style="text-align:center;padding:20px;color:' + PPG_GREEN + ';">✅ Sin IPs bloqueadas activas actualmente</div>',
                unsafe_allow_html=True,
            )

    with col_inc:
        inc_df = get_open_incidents()
        if not inc_df.empty:
            rows_html = ""
            for _, r in inc_df.iterrows():
                sev = str(r.get("severity", "normal")).lower()
                badge = severity_badge(sev)
                rows_html += (
                    '<div class="alert-row" style="border-left:3px solid ' + PPG_BLUE + ';">'
                    '<span style="color:' + PPG_PURPLE + ';font-size:0.72rem;min-width:75px">' + str(r.get("creado")) + "</span>"
                    + badge
                    + '<span style="flex:1;color:#e8d5f0;font-weight:600;font-size:0.8rem;">' + str(r.get("tipo")) + "</span>"
                    '<span style="color:' + PPG_BLUE + ';min-width:95px;font-size:0.8rem;">' + str(r.get("ip_origen")) + "</span>"
                    '<span style="color:' + PPG_PURPLE + ';min-width:35px;text-align:right;">' + str(r.get("intentos")) + "x</span>"
                    "</div>"
                )
            st.markdown(rows_html, unsafe_allow_html=True)
        else:
            st.markdown(
                '<div style="text-align:center;padding:20px;color:' + PPG_GREEN + ';">✅ Sin incidentes abiertos actualmente</div>',
                unsafe_allow_html=True,
            )

    st.markdown('<div class="section-title">Respuesta Automatizada (SOAR) & Reglas más Disparadas</div>', unsafe_allow_html=True)
    col_rules, col_pb = st.columns([1, 1])

    with col_rules:
        rules_df = get_top_rules()
        if not rules_df.empty:
            rows_html = ""
            for _, r in rules_df.iterrows():
                ultima = str(r.get("ultima_vez", ""))[:16]
                rows_html += (
                    '<div class="alert-row">'
                    '<span style="flex:1.5;color:#e8d5f0;font-weight:600">' + str(r["regla"]) + "</span>"
                    '<span style="color:' + PPG_PINK + ';min-width:60px;text-align:center">' + str(int(r["disparos"])) + " total</span>"
                    '<span style="color:' + PPG_PINK + ';min-width:55px;text-align:center">' + str(int(r["criticas"])) + " crit</span>"
                    '<span style="color:#FF9A6C;min-width:50px;text-align:center">' + str(int(r["altas"])) + " alta</span>"
                    '<span style="color:' + PPG_PURPLE + ';font-size:0.75rem;min-width:90px;text-align:right">' + ultima + "</span>"
                    "</div>"
                )
            st.markdown(rows_html, unsafe_allow_html=True)
        else:
            st.info("Sin reglas disparadas en las últimas 24 h.")

    with col_pb:
        pb_df = get_playbook_summary()
        if not pb_df.empty:
            fig = px.bar(
                pb_df, x="ejecuciones", y="workflow", color="outcome", orientation="h",
                title="Playbooks ejecutados por resultado",
                color_discrete_map={"success": PPG_GREEN, "error": PPG_PINK, "warning": "#FF9A6C"},
            )
            fig.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(plotly_ppg(fig), use_container_width=True)
        else:
            st.info("Sin ejecuciones de playbooks registradas.")

    st.markdown('<div class="section-title">Últimas Alertas Registradas</div>', unsafe_allow_html=True)
    alerts_df = get_recent_alerts()
    if not alerts_df.empty:
        rows_html = ""
        for _, row in alerts_df.iterrows():
            sev = str(row.get("severity", "normal")).lower()
            badge = severity_badge(sev)
            status_icon = "✅" if row.get("status") == "acknowledged" else "🔴"
            rows_html += (
                '<div class="alert-row">'
                '<span style="color:' + PPG_PURPLE + ';min-width:70px">' + str(row["hora"]) + "</span>"
                + badge
                + '<span style="flex:1;color:#e8d5f0">' + str(row["rule_id"]) + "</span>"
                '<span style="color:' + PPG_BLUE + ';min-width:110px">' + str(row.get("src_ip") or "—") + "</span>"
                '<span style="color:' + PPG_GREEN + ';min-width:100px">' + str(row.get("username") or "—") + "</span>"
                "<span>" + status_icon + "</span>"
                "</div>"
            )
        st.markdown(rows_html, unsafe_allow_html=True)
    else:
        st.info("No hay alertas registradas aún en la base de datos.")


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 2: Lanzador & Simulador de Ataques (Layout en 2 Columnas)
# ══════════════════════════════════════════════════════════════════════════════
def dispatch_attack_event(rule_id, src_ip, username, severity, message, **extra_fields):
    payload = {
        "rule_id": rule_id,
        "src_ip": src_ip,
        "username": username,
        "severity": severity,
        "timestamp": utc_now_iso(),
        "message": message,
    }
    payload.update(extra_fields)
    ok, status_msg = send_alert_to_n8n(DEFAULT_WEBHOOK, payload)
    st.session_state["attack_logs"].insert(0, {
        "timestamp": datetime.now(TZ_ARG).strftime("%H:%M:%S"),
        "rule_id": rule_id,
        "src_ip": src_ip,
        "username": username,
        "severity": severity,
        "status": "OK (200)" if ok else "ERROR",
        "message": message,
        "response": status_msg,
        "payload": payload,
    })
    return ok, status_msg, payload


def render_attack_launcher():
    render_header("🚀 Lanzador & Simulador de Ataques SIEM", "Generación y Despacho de Eventos Adversarios")

    col_btn_col, col_feed_col = st.columns([1.1, 1.3])

    # ── COLUMNA IZQUIERDA: PANEL DE BOTONES ────────────────────────────────────
    with col_btn_col:
        st.markdown('<div class="section-title">🎮 Ataques de Consola (1 Click)</div>', unsafe_allow_html=True)

        if st.button("🔴 1. SSH Brute Force (7 ráfagas)", use_container_width=True):
            ip = random.choice(ATTACKER_IPS)
            user = random.choice(TARGET_USERS)
            sent = 0
            for attempt in range(1, 8):
                sev = "high" if attempt < 6 else "critical"
                ok, msg, p = dispatch_attack_event(
                    "ssh_bruteforce", ip, user, sev,
                    "Failed password for " + user + " from " + ip + " port 22 ssh2",
                    attempt=attempt, attempts=7
                )
                if ok: sent += 1
            st.success("✅ SSH Brute Force: " + str(sent) + "/7 alertas entregadas para " + user + "@" + ip)

        if st.button("🟣 2. File Integrity Monitoring (FIM)", use_container_width=True):
            f = random.choice(FIM_FILES)
            ip = "192.168.1." + str(random.randint(10, 50))
            sev = "high" if "www" in f else "critical"
            ok, msg, _ = dispatch_attack_event(
                "file_integrity", ip, "system", sev,
                "ossec: integrity checksum changed: " + f,
                file_path=f
            )
            if ok: st.success("✅ Alerta FIM enviada para " + f)
            else: st.error("❌ " + msg)

        if st.button("🔵 3. Port Scan (150+ puertos)", use_container_width=True):
            ip = random.choice(ATTACKER_IPS)
            ports = random.randint(100, 500)
            ok, msg, _ = dispatch_attack_event(
                "port_scan_detected", ip, "unknown", "high",
                "Multiple connection attempts from " + ip + " to various ports detected",
                ports_scanned=ports
            )
            if ok: st.success("✅ Port Scan enviado (" + str(ports) + " puertos) desde " + ip)
            else: st.error("❌ " + msg)

        if st.button("🔴 4. Escalación de Privilegios", use_container_width=True):
            ip = "192.168.1." + str(random.randint(10, 50))
            user = random.choice(["www-data", "deploy", "ubuntu"])
            ok, msg, _ = dispatch_attack_event(
                "privilege_escalation", ip, user, "critical",
                "Suspicious sudo usage by " + user + ": attempting to access /etc/shadow"
            )
            if ok: st.success("✅ Escalación enviada para " + user + "@" + ip)
            else: st.error("❌ " + msg)

        if st.button("🟡 5. SQL Injection", use_container_width=True):
            ip = random.choice(ATTACKER_IPS)
            sqli = random.choice(SQLI_PAYLOADS)
            ok, msg, _ = dispatch_attack_event(
                "sql_injection", ip, "web_app", "critical",
                "SQL injection attempt detected on /api/v1/login: " + sqli,
                payload_detected=sqli, target_url="/api/v1/login"
            )
            if ok: st.success("✅ SQL Injection enviado desde " + ip)
            else: st.error("❌ " + msg)

        if st.button("🔴 6. Web Shell Upload", use_container_width=True):
            ip = "192.168.1." + str(random.randint(10, 50))
            sh = random.choice(WEBSHELL_PATHS)
            ok, msg, _ = dispatch_attack_event(
                "web_shell_detected", ip, "www-data", "critical",
                "Suspicious web shell detected: " + sh,
                file_path=sh, detection_method="file_signature_analysis"
            )
            if ok: st.success("✅ Web Shell enviado para " + sh)
            else: st.error("❌ " + msg)

        if st.button("🔴 7. Malware Detectado", use_container_width=True):
            ip = "192.168.1." + str(random.randint(10, 50))
            mal = random.choice(MALWARE_SIGNATURES)
            ok, msg, _ = dispatch_attack_event(
                "malware_detected", ip, "system", "critical",
                "Malware detected: " + mal["name"] + " (" + mal["type"] + ") at " + mal["path"],
                malware_name=mal["name"], malware_type=mal["type"], file_path=mal["path"]
            )
            if ok: st.success("✅ Alerta de Malware enviada: " + mal["name"])
            else: st.error("❌ " + msg)

        if st.button("🟡 8. Login Sospechoso (Geo)", use_container_width=True):
            ip = random.choice(ATTACKER_IPS)
            user = random.choice(["admin", "root", "ceo", "finance"])
            country_name, country_code = random.choice(SUSPICIOUS_COUNTRIES)
            ok, msg, _ = dispatch_attack_event(
                "suspicious_login", ip, user, "high",
                "Login from suspicious location: " + user + " from " + country_name + " (" + country_code + ")",
                country=country_name, country_code=country_code
            )
            if ok: st.success("✅ Login sospechoso (" + country_name + ") para " + user)
            else: st.error("❌ " + msg)

        st.markdown('<div class="section-title">⚡ Ramas del Workflow SOAR & Demos</div>', unsafe_allow_html=True)

        if st.button("🟡 R1. Rama 1 — Alerta HIGH (Solo Telegram)", use_container_width=True):
            ok, msg, _ = dispatch_attack_event(
                "file_integrity", "91.189.114.8", "admin", "high",
                "Archivo crítico modificado — test rama 1", attempt_count=1
            )
            if ok: st.success("✅ Rama 1: Alerta HIGH enviada (notificación sin incidente).")
            else: st.error("❌ " + msg)

        if st.button("🔵 R2. Rama 2 — Alerta LOW (Solo DB)", use_container_width=True):
            ok, msg, _ = dispatch_attack_event(
                "sql_injection", "10.10.10.2", "user", "low",
                "SQL injection detectado — test rama 2", attempt_count=1
            )
            if ok: st.success("✅ Rama 2: Alerta LOW enviada (registrada en DB sin notificación).")
            else: st.error("❌ " + msg)

        if st.button("🔴 R3. Rama 3 — Incidente + Bloqueo (6 alertas)", use_container_width=True):
            sent = 0
            for attempt in range(1, 7):
                ok, _, _ = dispatch_attack_event(
                    "ssh_bruteforce", RAMA_TEST_IP, "root", "critical",
                    "Failed password for root from " + RAMA_TEST_IP + " port 22 ssh2",
                    attempt_count=attempt
                )
                if ok: sent += 1
            st.success("✅ Rama 3: 6 alertas críticas enviadas desde " + RAMA_TEST_IP + ". Disparó incidente y bloqueo.")

        if st.button("🟡 R4. Rama 4 — IP Reincidente", use_container_width=True):
            ok, msg, _ = dispatch_attack_event(
                "ssh_bruteforce", RAMA_TEST_IP, "root", "critical",
                "Ataque de IP reincidente post-bloqueo: " + RAMA_TEST_IP
            )
            if ok: st.success("✅ Rama 4: Alerta de reincidencia enviada para " + RAMA_TEST_IP)
            else: st.error("❌ " + msg)

        if st.button("🟣 R5. Rama 5 — Password Spraying (6 IPs)", use_container_width=True):
            user = "admin"
            spraying_ips = random.sample(ATTACKER_IPS, min(6, len(ATTACKER_IPS)))
            sent = 0
            for s_ip in spraying_ips:
                ok, _, _ = dispatch_attack_event(
                    "ssh_bruteforce", s_ip, user, "high",
                    "Failed password for " + user + " from " + s_ip + " port 22 ssh2 [spraying]"
                )
                if ok: sent += 1
            st.success("✅ Password Spraying: " + str(sent) + " IPs atacaron a '" + user + "'")

        if st.button("🌟 10. Simulación Completa Demo (Multi-Fase)", use_container_width=True):
            demo_events = [
                ("ssh_bruteforce", "185.156.73.233", "root", "critical", "Fase 1: SSH Brute Force"),
                ("file_integrity", "192.168.1.50", "system", "high", "Fase 2: FIM Checksum /etc/shadow"),
                ("sql_injection", "80.94.95.116", "web_app", "critical", "Fase 3: SQL Injection en /login"),
                ("malware_detected", "192.168.1.10", "system", "critical", "Fase 4: Ransomware detectado"),
                ("suspicious_login", "185.220.101.42", "admin", "high", "Fase 5: Geo Login sospechoso"),
                ("port_scan_detected", "89.234.157.254", "unknown", "high", "Fase 6: Port Scan 250 puertos"),
            ]
            sent = 0
            for r_id, r_ip, r_u, r_s, r_m in demo_events:
                ok, _, _ = dispatch_attack_event(r_id, r_ip, r_u, r_s, r_m)
                if ok: sent += 1
            st.success("🌟 Simulación completa finalizada: " + str(sent) + "/6 fases ejecutadas.")

        if st.button("🧹 Limpiar DB de Pruebas (IP " + RAMA_TEST_IP + ")", use_container_width=True):
            try:
                conn = get_connection()
                cur = conn.cursor()
                cur.execute("DELETE FROM playbook_runs WHERE alert_id IN (SELECT id FROM alerts WHERE src_ip = %s);", (RAMA_TEST_IP,))
                cur.execute("DELETE FROM ip_blacklist WHERE ip = %s;", (RAMA_TEST_IP,))
                cur.execute("DELETE FROM alerts WHERE src_ip = %s;", (RAMA_TEST_IP,))
                cur.execute("DELETE FROM incidents WHERE src_ip = %s;", (RAMA_TEST_IP,))
                conn.commit()
                cur.close()
                st.success("🧹 Registros de prueba de " + RAMA_TEST_IP + " eliminados de la BD.")
            except Exception as e:
                st.error("Error al limpiar DB: " + str(e))

        with st.expander("⚙️ Ataque Parametrizado Personalizado"):
            custom_rule = st.selectbox(
                "Regla de Detección",
                options=[
                    "ssh_bruteforce", "file_integrity", "sql_injection",
                    "web_shell_detected", "malware_detected", "suspicious_login", "port_scan_detected"
                ]
            )
            col_u1, col_u2 = st.columns(2)
            with col_u1:
                custom_ip = st.selectbox("IP Atacante", options=ATTACKER_IPS + ["198.51.100.42", "10.0.0.99"])
            with col_u2:
                custom_user = st.selectbox("Usuario Target", options=TARGET_USERS)

            col_u3, col_u4 = st.columns(2)
            with col_u3:
                custom_sev = st.selectbox("Severidad", options=["critical", "high", "medium", "low"])
            with col_u4:
                custom_attempts = st.slider("Cantidad de Ráfagas", min_value=1, max_value=30, value=5)

            if st.button("🚀 Disparar Ataque Personalizado", use_container_width=True):
                sent = 0
                for a in range(1, custom_attempts + 1):
                    ok, msg, p = dispatch_attack_event(
                        custom_rule, custom_ip, custom_user, custom_sev,
                        "Ataque custom " + custom_rule + " intento " + str(a) + "/" + str(custom_attempts),
                        attempt=a, attempts=custom_attempts
                    )
                    if ok: sent += 1
                if sent > 0:
                    st.success("✅ " + str(sent) + " alertas personalizadas enviadas.")
                else:
                    st.error("❌ Falló el envío: " + msg)

    # ── COLUMNA DERECHA: MENSAJES EN VIVO, PAYLOAD E HISTORIAL ────────────────
    with col_feed_col:
        st.markdown('<div class="section-title">📡 Mensaje del Ataque & Estado de Salida</div>', unsafe_allow_html=True)

        if st.session_state["attack_logs"]:
            latest = st.session_state["attack_logs"][0]
            status_badge = '<span class="status-online">✅ 200 OK — PROCESADO POR N8N</span>' if "OK" in latest["status"] else '<span class="status-offline">🔴 ERROR DE CONEXIÓN</span>'
            sev_color = SEVERITY_COLORS.get(str(latest.get("severity", "")).lower(), PPG_PINK)

            st.markdown(
                '<div style="background:linear-gradient(145deg, #220e38, #18102a);border:1px solid rgba(195,155,211,0.3);border-radius:12px;padding:16px;margin-bottom:16px;box-shadow:0 4px 15px rgba(0,0,0,0.3);">'
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">'
                '<span style="font-weight:800;font-size:1.1rem;color:' + sev_color + ';">' + str(latest["rule_id"]) + "</span>"
                + status_badge +
                "</div>"
                '<div style="font-size:0.88rem;color:#ffffff;margin-bottom:10px;line-height:1.4;">'
                '<b>Mensaje:</b> <span style="color:' + PPG_BLUE + ';">' + str(latest["message"]) + '</span>'
                '</div>'
                '<div style="font-size:0.8rem;color:' + PPG_PURPLE + ';display:flex;flex-wrap:wrap;gap:14px;border-top:1px solid rgba(195,155,211,0.15);padding-top:8px;">'
                "<span>🌐 IP Origen: <b style='color:#ffffff;'>" + str(latest["src_ip"]) + "</b></span>"
                "<span>👤 Usuario: <b style='color:#ffffff;'>" + str(latest["username"]) + "</b></span>"
                "<span>🔴 Severidad: <b style='color:" + sev_color + ";'>" + str(latest["severity"]).upper() + "</b></span>"
                "<span>⏰ Hora: <b style='color:#ffffff;'>" + str(latest["timestamp"]) + "</b></span>"
                "</div>"
                "</div>",
                unsafe_allow_html=True,
            )

            st.markdown('<div class="section-title">📦 Payload JSON Despachado a n8n</div>', unsafe_allow_html=True)
            st.code(json.dumps(latest["payload"], indent=2), language="json")

            st.markdown('<div class="section-title">📋 Historial de Despachos Recientes</div>', unsafe_allow_html=True)
            for item in st.session_state["attack_logs"][:12]:
                status_color = PPG_GREEN if "OK" in item["status"] else PPG_PINK
                item_sev_color = SEVERITY_COLORS.get(str(item.get("severity", "")).lower(), PPG_BLUE)
                st.markdown(
                    '<div class="alert-row">'
                    '<span style="color:' + PPG_PURPLE + ';min-width:65px;font-weight:600;">' + item["timestamp"] + "</span>"
                    '<span style="color:' + item_sev_color + ';font-weight:700;min-width:150px;">' + item["rule_id"] + "</span>"
                    '<span style="color:' + PPG_BLUE + ';min-width:120px;">' + item["src_ip"] + "</span>"
                    '<span style="color:#ffffff;font-size:0.78rem;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + str(item.get("username", "system")) + "</span>"
                    '<span style="color:' + status_color + ';font-weight:700;min-width:70px;text-align:right;">' + item["status"] + "</span>"
                    "</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.info("💡 Hacé click en cualquiera de los ataques de la columna izquierda para disparar eventos y ver el mensaje y payload aquí.")


# ══════════════════════════════════════════════════════════════════════════════
# MÓDULO 3: Landing Page & Arquitectura de la Tesis (UTN FRM)
# ══════════════════════════════════════════════════════════════════════════════
def render_landing_page():
    # ── HERO ACADÉMICO ────────────────────────────────────────────────────────
    st.markdown(
        '<div class="landing-hero">'
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;">'
        '<span style="background:rgba(91,200,245,0.15);border:1px solid ' + PPG_BLUE + ';color:' + PPG_BLUE + ';font-size:0.75rem;padding:3px 10px;border-radius:6px;font-weight:700;">UNIVERSIDAD TECNOLÓGICA NACIONAL — FRM</span>'
        '<span style="background:rgba(255,107,157,0.15);border:1px solid ' + PPG_PINK + ';color:' + PPG_PINK + ';font-size:0.75rem;padding:3px 10px;border-radius:6px;font-weight:700;">TRABAJO FINAL DE CARRERA 2026</span>'
        '</div>'
        '<p class="landing-title">Implementación de un SIEM Básico Orquestado con n8n</p>'
        '<p class="landing-subtitle">Para Recolección Centralizada de Logs y Respuesta Automatizada en Tiempo Real</p>'
        '<p class="feature-text" style="font-size:0.95rem;color:#e8d5f0;line-height:1.6;margin-bottom:18px;">'
        "Trabajo de graduación de la <b>Tecnicatura Universitaria en Programación</b>. "
        "Propone una solución de seguridad perimetral y detección de incidentes 100% <i>open source</i> para organizaciones académicas y PyMEs, "
        "integrando recolección desacoplada de telemetría, correlación de amenazas por severidad y mitigación automatizada mediante flujos SOAR."
        "</p>"
        '<div style="display:flex;flex-wrap:wrap;gap:6px;">'
        '<span class="tech-tag">🐍 Python 3.11</span>'
        '<span class="tech-tag">⚙️ n8n SOAR 2.1.5</span>'
        '<span class="tech-tag">🐘 PostgreSQL 16</span>'
        '<span class="tech-tag">⚡ Elasticsearch 8.15</span>'
        '<span class="tech-tag">📊 Logstash 8.15</span>'
        '<span class="tech-tag">📦 Syslog-ng 4.8</span>'
        '<span class="tech-tag">📈 Grafana 11.1</span>'
        '<span class="tech-tag">🛡️ AbuseIPDB API</span>'
        '<span class="tech-tag">🐳 Docker Compose</span>'
        "</div></div>",
        unsafe_allow_html=True,
    )

    # ── ARQUITECTURA DE 5 CAPAS (CAPÍTULO 5 DE LA TESIS) ──────────────────────
    st.markdown('<div class="section-title">🏛️ Pipeline Arquitectónico de 5 Capas (Capítulo 5)</div>', unsafe_allow_html=True)
    
    col_c1, col_c2, col_c3, col_c4, col_c5 = st.columns(5)

    with col_c1:
        st.markdown(
            '<div class="feature-card">'
            '<div style="font-size:1.6rem;margin-bottom:6px;">📦</div>'
            '<div style="font-size:0.75rem;color:' + PPG_PINK + ';font-weight:700;text-transform:uppercase;">Capa 1</div>'
            '<div style="font-weight:700;font-size:0.95rem;color:#ffffff;margin-bottom:4px;">Ingesta Centralizada</div>'
            '<div class="feature-text" style="font-size:0.78rem;">'
            '<b>Syslog-ng (UDP:514)</b> recibe telemetría de servidores y atacantes sin bloquear el host emisor.'
            '</div></div>',
            unsafe_allow_html=True,
        )

    with col_c2:
        st.markdown(
            '<div class="feature-card">'
            '<div style="font-size:1.6rem;margin-bottom:6px;">🔄</div>'
            '<div style="font-size:0.75rem;color:' + PPG_BLUE + ';font-weight:700;text-transform:uppercase;">Capa 2</div>'
            '<div style="font-weight:700;font-size:0.95rem;color:#ffffff;margin-bottom:4px;">Normalización Grok</div>'
            '<div class="feature-text" style="font-size:0.78rem;">'
            '<b>Logstash (UDP:5140)</b> parsea los logs con filtros Grok, extrayendo <code>src_ip</code>, <code>user</code> y <code>timestamp</code>.'
            '</div></div>',
            unsafe_allow_html=True,
        )

    with col_c3:
        st.markdown(
            '<div class="feature-card">'
            '<div style="font-size:1.6rem;margin-bottom:6px;">🗄️</div>'
            '<div style="font-size:0.75rem;color:' + PPG_PURPLE + ';font-weight:700;text-transform:uppercase;">Capa 3</div>'
            '<div style="font-weight:700;font-size:0.95rem;color:#ffffff;margin-bottom:4px;">Almacenamiento Dual</div>'
            '<div class="feature-text" style="font-size:0.78rem;">'
            '<b>Elasticsearch</b> para búsqueda masiva no estructurada y <b>PostgreSQL</b> para auditoría relacional.'
            '</div></div>',
            unsafe_allow_html=True,
        )

    with col_c4:
        st.markdown(
            '<div class="feature-card">'
            '<div style="font-size:1.6rem;margin-bottom:6px;">⚡</div>'
            '<div style="font-size:0.75rem;color:' + PPG_GREEN + ';font-weight:700;text-transform:uppercase;">Capa 4</div>'
            '<div style="font-weight:700;font-size:0.95rem;color:#ffffff;margin-bottom:4px;">Detección & SOAR</div>'
            '<div class="feature-text" style="font-size:0.78rem;">'
            'Reglas en <b>Python</b> detectan SSH/FIM y <b>n8n</b> ejecuta playbooks de mitigación y scoring.'
            '</div></div>',
            unsafe_allow_html=True,
        )

    with col_c5:
        st.markdown(
            '<div class="feature-card">'
            '<div style="font-size:1.6rem;margin-bottom:6px;">📈</div>'
            '<div style="font-size:0.75rem;color:#FFD700;font-weight:700;text-transform:uppercase;">Capa 5</div>'
            '<div style="font-weight:700;font-size:0.95rem;color:#ffffff;margin-bottom:4px;">Visualización SOC</div>'
            '<div class="feature-text" style="font-size:0.78rem;">'
            '<b>Grafana</b> + <b>Streamlit SOC</b> para monitoreo analítico en vivo y simulación de ataques.'
            '</div></div>',
            unsafe_allow_html=True,
        )

    # ── RESULTADOS CUANTITATIVOS & HALLAZGOS (CAPÍTULO 6) ─────────────────────
    st.markdown('<div class="section-title">📊 Resultados Cuantitativos & Aporte de la Investigación (Capítulo 6)</div>', unsafe_allow_html=True)
    
    col_k1, col_k2, col_k3, col_k4 = st.columns(4)
    with col_k1:
        st.markdown(
            '<div class="feature-card" style="text-align:center;">'
            '<div style="font-size:2rem;font-weight:800;color:' + PPG_PINK + ';">~1 seg</div>'
            '<div style="font-weight:700;font-size:0.88rem;color:#ffffff;margin:4px 0;">MTTR Automatizado</div>'
            '<div class="feature-text" style="font-size:0.78rem;">Reducción drástica del tiempo medio de respuesta frente al orden de minutos de la línea base manual.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col_k2:
        st.markdown(
            '<div class="feature-card" style="text-align:center;">'
            '<div style="font-size:2rem;font-weight:800;color:' + PPG_GREEN + ';">>85%</div>'
            '<div style="font-weight:700;font-size:0.88rem;color:#ffffff;margin:4px 0;">Tasa de Automatización</div>'
            '<div class="feature-text" style="font-size:0.78rem;">Resolución y mitigación automática de alertas operacionales sin requerir intervención humana directa.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col_k3:
        st.markdown(
            '<div class="feature-card" style="text-align:center;">'
            '<div style="font-size:2rem;font-weight:800;color:' + PPG_BLUE + ';">100%</div>'
            '<div style="font-weight:700;font-size:0.88rem;color:#ffffff;margin:4px 0;">Reproducibilidad Docker</div>'
            '<div class="feature-text" style="font-size:0.78rem;">Despliegue unificado de los 8 microservicios con un único comando estándar <code>docker compose up -d</code>.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
    with col_k4:
        st.markdown(
            '<div class="feature-card" style="text-align:center;">'
            '<div style="font-size:2rem;font-weight:800;color:#FFD700;">$0 USD</div>'
            '<div style="font-weight:700;font-size:0.88rem;color:#ffffff;margin:4px 0;">Cero Costo en Licencias</div>'
            '<div class="feature-text" style="font-size:0.78rem;">Arquitectura construida exclusivamente con software libre para accesibilidad en entornos PyME y académicos.</div>'
            '</div>',
            unsafe_allow_html=True,
        )

    # ── ESCENARIOS DE VALIDACIÓN EVALUADOS ────────────────────────────────────
    st.markdown('<div class="section-title">🎯 Escenarios de Validación & Detección Implementados</div>', unsafe_allow_html=True)
    
    col_sc1, col_sc2 = st.columns(2)
    with col_sc1:
        st.markdown(
            '<div class="alert-row" style="margin-bottom:8px;padding:12px 16px;">'
            '<span style="font-size:1.2rem;">🔴</span>'
            '<div style="flex:1;">'
            '<span style="font-weight:700;color:#ffffff;">Detección Volumétrica SSH Brute Force</span><br>'
            '<span style="font-size:0.8rem;color:' + PPG_PURPLE + ';">Correlación por ventana de tiempo: ante más de 5 intentos fallidos se eleva la severidad a CRITICAL y se genera incidente.</span>'
            '</div></div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="alert-row" style="margin-bottom:8px;padding:12px 16px;">'
            '<span style="font-size:1.2rem;">🟣</span>'
            '<div style="flex:1;">'
            '<span style="font-weight:700;color:#ffffff;">Monitoreo de Integridad de Archivos (FIM)</span><br>'
            '<span style="font-size:0.8rem;color:' + PPG_PURPLE + ';">Verificación de firmas criptográficas (SHA256) sobre archivos críticos como <code>/etc/shadow</code> y <code>/etc/passwd</code>.</span>'
            '</div></div>',
            unsafe_allow_html=True,
        )

    with col_sc2:
        st.markdown(
            '<div class="alert-row" style="margin-bottom:8px;padding:12px 16px;">'
            '<span style="font-size:1.2rem;">🌐</span>'
            '<div style="flex:1;">'
            '<span style="font-weight:700;color:#ffffff;">Threat Intelligence con AbuseIPDB</span><br>'
            '<span style="font-size:0.8rem;color:' + PPG_PURPLE + ';">Consulta automática a bases de reputación global para enriquecer la IP con país, score de abuso y reportes previos.</span>'
            '</div></div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="alert-row" style="margin-bottom:8px;padding:12px 16px;">'
            '<span style="font-size:1.2rem;">🚫</span>'
            '<div style="flex:1;">'
            '<span style="font-weight:700;color:#ffffff;">Mitigación Activa Perimetral (Blocker API)</span><br>'
            '<span style="font-size:0.8rem;color:' + PPG_PURPLE + ';">Aislamiento en lista negra con aplicación de reglas de firewall host reales (<code>netsh</code> en Windows / <code>iptables</code> en Linux).</span>'
            '</div></div>',
            unsafe_allow_html=True,
        )

    # ── FICHA TÉCNICA OFICIAL (AL FINAL) ──────────────────────────────────────
    st.markdown('<div class="section-title">📋 Ficha Técnica Oficial del Proyecto de Tesis</div>', unsafe_allow_html=True)
    
    col_meta1, col_meta2 = st.columns(2)
    with col_meta1:
        st.markdown(
            '<div style="background:rgba(34,14,56,0.6);border:1px solid rgba(195,155,211,0.25);border-radius:12px;padding:18px;">'
            '<div style="font-weight:700;font-size:0.95rem;color:' + PPG_PINK + ';margin-bottom:10px;">👥 Equipo del Proyecto & Autoridades</div>'
            '<div style="font-size:0.85rem;color:#e8d5f0;line-height:1.8;">'
            '<b>🎓 Institución:</b> Universidad Tecnológica Nacional (UTN FRM)<br>'
            '<b>📚 Carrera:</b> Tecnicatura Universitaria en Programación<br>'
            '<b>👩‍💻 Autoras (Tesistas):</b><br>'
            '&nbsp;&nbsp;• 🌺 <b>Azul Castroviejo</b><br>'
            '&nbsp;&nbsp;• 💧 <b>Clara Mitre</b><br>'
            '&nbsp;&nbsp;• 🌿 <b>Micaela Paco</b><br>'
            '<b>👨‍🏫 Directores de Tesis (Docentes):</b><br>'
            '&nbsp;&nbsp;• Prof. <b>Alberto Cortez</b><br>'
            '&nbsp;&nbsp;• Prof. <b>Ariel Enferrel</b>'
            '</div></div>',
            unsafe_allow_html=True,
        )

    with col_meta2:
        st.markdown(
            '<div style="background:rgba(34,14,56,0.6);border:1px solid rgba(195,155,211,0.25);border-radius:12px;padding:18px;">'
            '<div style="font-weight:700;font-size:0.95rem;color:' + PPG_BLUE + ';margin-bottom:10px;">⚙️ Especificaciones del Despliegue</div>'
            '<div style="font-size:0.85rem;color:#e8d5f0;line-height:1.8;">'
            '<b>📄 Documento:</b> Tesis Versión 13 — Revisión Académica Final (2026)<br>'
            '<b>📍 Ubicación:</b> Mendoza, Argentina<br>'
            '<b>⚖️ Licencia:</b> Código Abierto (Open Source / MIT)<br>'
            '<b>🌐 Red Docker:</b> Bridge aislado <code>siem-net</code> con 8 microservicios<br>'
            '<b>🔑 Seguridad API:</b> Token autenticado vía Header <code>x-siem-key</code><br>'
            '<b>⚡ Estado Operativo:</b> Monitoreo y automatización 24/7'
            '</div></div>',
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# NAVEGACIÓN PRINCIPAL (Sidebar con Botones y Resaltado Dorado)
# ══════════════════════════════════════════════════════════════════════════════
st.sidebar.markdown(
    '<div style="text-align:center;padding:10px 0 20px;">'
    '<span style="font-size:2rem;">🛡️</span>'
    '<div style="font-weight:800;font-size:1.15rem;color:' + PPG_PINK + ';margin-top:4px;">SIEM & SOAR SOC</div>'
    '<div style="font-size:0.78rem;color:' + PPG_PURPLE + ';">UTN Ciberseguridad</div>'
    "</div>",
    unsafe_allow_html=True,
)

st.sidebar.markdown('<div class="sidebar-nav-title">MÓDULOS DEL SISTEMA</div>', unsafe_allow_html=True)

PAGES = [
    ("🌐 Landing Page & Arquitectura", "🌐 Landing Page & Arquitectura"),
    ("📊 Dashboard SOC (Métricas & Alertas)", "📊 Dashboard SOC (Métricas & Alertas)"),
    ("🚀 Lanzador de Ataques (Simulador Web)", "🚀 Lanzador de Ataques (Simulador Web)"),
]

for label, page_key in PAGES:
    is_active = (st.session_state["current_page"] == page_key)
    btn_type = "primary" if is_active else "secondary"
    if st.sidebar.button(label, key="nav_" + page_key, type=btn_type, use_container_width=True):
        st.session_state["current_page"] = page_key
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown(
    '<div style="font-size:0.75rem;color:' + PPG_PURPLE + ';padding:8px 12px;background:rgba(34,14,56,0.5);border-radius:8px;border:1px solid rgba(195,155,211,0.2);">'
    "<b>Estado de Conexión:</b><br>"
    "• DB Host: <code>" + DB_CONFIG["host"] + "</code><br>"
    "• Webhook: <code>" + ("n8n:5678" if IS_DOCKER else "localhost:5678") + "</code><br>"
    "• Refresco auto: <code>" + str(REFRESH_SECONDS) + "s</code>"
    "</div>",
    unsafe_allow_html=True,
)

# ── Router de Vistas ──────────────────────────────────────────────────────────
current = st.session_state["current_page"]
if "Landing Page" in current:
    render_landing_page()
elif "Dashboard SOC" in current:
    render_dashboard_soc()
elif "Lanzador de Ataques" in current:
    render_attack_launcher()
else:
    render_landing_page()

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown(
    '<div style="text-align:right;font-size:0.75rem;color:rgba(195,155,211,0.53);margin-top:30px;padding-top:10px;'
    'border-top:1px solid rgba(195,155,211,0.13);">'
    "🛡️ Panel de Operaciones de Seguridad (SOC) &nbsp;·&nbsp; UTN FRM &nbsp;·&nbsp; Refresco cada " + str(REFRESH_SECONDS) + "s"
    "</div>",
    unsafe_allow_html=True,
)
