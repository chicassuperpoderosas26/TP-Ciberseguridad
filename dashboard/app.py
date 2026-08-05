import os
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import psycopg2
import streamlit as st

# ── Configuración ─────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     int(os.getenv("DB_PORT", 5432)),
    "dbname":   os.getenv("DB_NAME", "siem"),
    "user":     os.getenv("DB_USER", "siem"),
    "password": os.getenv("DB_PASSWORD", "siem123"),
}

# Paleta Chicas Superpoderosas
# Blossom → rosa  | Bubbles → celeste  | Buttercup → verde
PPG_PINK   = "#FF6B9D"   # Blossom
PPG_BLUE   = "#5BC8F5"   # Bubbles
PPG_GREEN  = "#7ED4A0"   # Buttercup
PPG_PURPLE = "#C39BD3"   # Panel de Operaciones de Seguridad / fondo
PPG_DARK   = "#1a0e2e"   # fondo oscuro con tinte violeta

SEVERITY_COLORS = {
    "critical": PPG_PINK,    # Blossom al frente
    "high":     "#FF9A6C",   # naranja cálido
    "medium":   PPG_BLUE,    # Bubbles
    "low":      PPG_GREEN,   # Buttercup
    "normal":   PPG_PURPLE,  # Panel de Operaciones de Seguridad
}

REFRESH_SECONDS = 30

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Panel de Operaciones de Seguridad — SOC Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── CSS custom ────────────────────────────────────────────────────────────────
st.markdown(f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

  /* fondo con tinte PPG */
  .stApp {{
    background-color: {PPG_DARK};
    color: #e8d5f0;
    font-family: 'Inter', sans-serif;
  }}

  /* header */
  .soc-header {{
    background: linear-gradient(135deg, #2a1040 0%, #1a1a3e 50%, #0e2a1a 100%);
    border: 1px solid {PPG_PURPLE}55;
    border-radius: 14px;
    padding: 22px 30px;
    margin-bottom: 22px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 0 30px {PPG_PINK}22;
  }}
  .soc-title {{
    font-size: 1.75rem;
    font-weight: 700;
    background: linear-gradient(90deg, {PPG_PINK}, {PPG_BLUE}, {PPG_GREEN});
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0;
  }}
  .soc-subtitle {{ font-size: 0.83rem; color: {PPG_PURPLE}; margin: 4px 0 0; }}
  .ppg-badge {{
    display: flex;
    gap: 6px;
    align-items: center;
    font-size: 0.8rem;
    font-weight: 700;
    color: #fff;
  }}
  .dot-pink  {{ width:10px; height:10px; border-radius:50%; background:{PPG_PINK};  box-shadow: 0 0 8px {PPG_PINK}; }}
  .dot-blue  {{ width:10px; height:10px; border-radius:50%; background:{PPG_BLUE};  box-shadow: 0 0 8px {PPG_BLUE}; }}
  .dot-green {{ width:10px; height:10px; border-radius:50%; background:{PPG_GREEN}; box-shadow: 0 0 8px {PPG_GREEN}; }}

  /* tarjetas KPI */
  .kpi-card {{
    background: linear-gradient(145deg, #220e38, #1a1a2e);
    border: 1px solid {PPG_PURPLE}44;
    border-radius: 12px;
    padding: 18px 16px;
    text-align: center;
    height: 110px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    transition: box-shadow .2s;
  }}
  .kpi-card:hover {{ box-shadow: 0 0 16px {PPG_PURPLE}55; }}
  .kpi-label {{
    font-size: 0.72rem;
    color: {PPG_PURPLE};
    text-transform: uppercase;
    letter-spacing: .07em;
  }}
  .kpi-value {{ font-size: 1.9rem; font-weight: 700; margin: 5px 0 0; }}
  .kpi-critical {{ color: {PPG_PINK};  text-shadow: 0 0 12px {PPG_PINK}88; }}
  .kpi-warning  {{ color: #FF9A6C;     text-shadow: 0 0 12px #FF9A6C88; }}
  .kpi-ok       {{ color: {PPG_GREEN}; text-shadow: 0 0 12px {PPG_GREEN}88; }}
  .kpi-info     {{ color: {PPG_BLUE};  text-shadow: 0 0 12px {PPG_BLUE}88; }}

  /* section titles */
  .section-title {{
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .1em;
    margin: 20px 0 10px;
    padding-bottom: 6px;
    background: linear-gradient(90deg, {PPG_PINK}, {PPG_BLUE});
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    border-bottom: 1px solid {PPG_PURPLE}44;
  }}

  /* tabla alertas */
  .alert-row {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 14px;
    border-radius: 8px;
    margin-bottom: 4px;
    background: #220e38aa;
    border: 1px solid {PPG_PURPLE}33;
    font-size: 0.82rem;
  }}
  .badge {{
    border-radius: 5px;
    padding: 2px 9px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    min-width: 65px;
    text-align: center;
  }}
  .badge-critical {{ background:{PPG_PINK}22;   color:{PPG_PINK};   border:1px solid {PPG_PINK}66; }}
  .badge-high     {{ background:#FF9A6C22;       color:#FF9A6C;      border:1px solid #FF9A6C66; }}
  .badge-medium   {{ background:{PPG_BLUE}22;    color:{PPG_BLUE};   border:1px solid {PPG_BLUE}66; }}
  .badge-low      {{ background:{PPG_GREEN}22;   color:{PPG_GREEN};  border:1px solid {PPG_GREEN}66; }}
  .badge-normal   {{ background:{PPG_PURPLE}22;  color:{PPG_PURPLE}; border:1px solid {PPG_PURPLE}66; }}

  /* ocultar branding Streamlit */
  #MainMenu, footer {{ visibility: hidden; }}
  .block-container {{ padding-top: 1rem; }}
</style>
""", unsafe_allow_html=True)


# ── DB helpers ────────────────────────────────────────────────────────────────
@st.cache_resource
def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def query(sql: str) -> pd.DataFrame:
    try:
        conn = get_connection()
        return pd.read_sql_query(sql, conn)
    except Exception:
        get_connection.clear()
        try:
            conn = get_connection()
            return pd.read_sql_query(sql, conn)
        except Exception as e:
            st.error(f"Error de base de datos: {e}")
            return pd.DataFrame()


# ── Queries ───────────────────────────────────────────────────────────────────
@st.cache_data(ttl=REFRESH_SECONDS)
def get_kpis():
    return query("""
        SELECT
          (SELECT COUNT(*) FROM alerts WHERE ts >= NOW() - INTERVAL '24 hours')  AS alerts_24h,
          (SELECT COUNT(*) FROM alerts WHERE ts >= NOW() - INTERVAL '1 hour')    AS alerts_1h,
          (SELECT COUNT(*) FROM incidents WHERE status = 'open')                  AS open_incidents,
          (SELECT COALESCE(ROUND(AVG(
              EXTRACT(EPOCH FROM (p.executed_at - a.ts))
           )::numeric, 1), 0)
           FROM alerts a JOIN playbook_runs p ON p.alert_id = a.id)               AS mttr_sec,
          (SELECT COALESCE(automation_percentage, 0) FROM automation_rate_operational) AS auto_pct,
          (SELECT COUNT(*) FROM failed_alerts WHERE resolved = false)              AS failed,
          (SELECT COUNT(*) FROM ip_blacklist WHERE active = true AND (expires_at IS NULL OR expires_at > NOW())) AS ips_bloqueadas,
          (SELECT ROUND(avg_mtta_seconds::numeric, 1) FROM mtta_stats)              AS mtta_sec,
          (SELECT acknowledged_count FROM mtta_stats)                              AS mtta_n
    """)


@st.cache_data(ttl=REFRESH_SECONDS)
def get_severity_dist():
    return query("""
        SELECT severity, COUNT(*) AS total
        FROM alerts
        GROUP BY severity
        ORDER BY total DESC
    """)


@st.cache_data(ttl=REFRESH_SECONDS)
def get_timeline():
    return query("""
        SELECT
          DATE_TRUNC('hour', ts) AS hora,
          severity,
          COUNT(*) AS total
        FROM alerts
        WHERE ts >= NOW() - INTERVAL '24 hours'
        GROUP BY hora, severity
        ORDER BY hora
    """)


@st.cache_data(ttl=REFRESH_SECONDS)
def get_geo_attacks():
    return query("""
        SELECT country_code, COUNT(*) AS ataques
        FROM alerts
        WHERE country_code IS NOT NULL AND country_code != ''
        GROUP BY country_code
        ORDER BY ataques DESC
    """)


@st.cache_data(ttl=REFRESH_SECONDS)
def get_top_ips():
    return query("""
        SELECT src_ip, COUNT(*) AS alertas
        FROM alerts
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY alertas DESC
        LIMIT 8
    """)


@st.cache_data(ttl=REFRESH_SECONDS)
def get_recent_alerts():
    return query("""
        SELECT
          TO_CHAR(ts, 'HH24:MI:SS') AS hora,
          rule_id,
          src_ip,
          username,
          severity,
          status
        FROM alerts
        ORDER BY ts DESC
        LIMIT 20
    """)


@st.cache_data(ttl=REFRESH_SECONDS)
def get_playbook_summary():
    return query("""
        SELECT workflow, outcome, COUNT(*) AS ejecuciones
        FROM playbook_runs
        GROUP BY workflow, outcome
        ORDER BY ejecuciones DESC
    """)


@st.cache_data(ttl=REFRESH_SECONDS)
def get_top_rules():
    return query("""
        SELECT
          rule_id AS regla,
          COUNT(*) AS disparos,
          COUNT(*) FILTER (WHERE severity = 'critical') AS criticas,
          COUNT(*) FILTER (WHERE severity = 'high')     AS altas,
          MAX(ts) AS ultima_vez
        FROM alerts
        WHERE ts >= NOW() - INTERVAL '24 hours'
        GROUP BY rule_id
        ORDER BY disparos DESC
        LIMIT 8
    """)


@st.cache_data(ttl=REFRESH_SECONDS)
def get_blacklist():
    return query("""
        SELECT ip, reason AS razón,
          TO_CHAR(blocked_at, 'DD/MM HH24:MI') AS bloqueada,
          TO_CHAR(expires_at, 'DD/MM HH24:MI') AS vence,
          enforced,
          enforcement_message
        FROM ip_blacklist
        WHERE active = true AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY blocked_at DESC
        LIMIT 10
    """)


@st.cache_data(ttl=REFRESH_SECONDS)
def get_open_incidents():
    return query("""
        SELECT
          id,
          type AS tipo,
          src_ip AS ip_origen,
          username AS usuario,
          attempts AS intentos,
          severity,
          TO_CHAR(created_at, 'DD/MM HH24:MI') AS creado
        FROM incidents
        WHERE status = 'open'
        ORDER BY created_at DESC
        LIMIT 10
    """)


# ── Render helpers ────────────────────────────────────────────────────────────
def kpi_card(label: str, value, css_class: str = "kpi-info"):
    st.markdown(f"""
    <div class="kpi-card">
      <div class="kpi-label">{label}</div>
      <div class="kpi-value {css_class}">{value}</div>
    </div>
    """, unsafe_allow_html=True)


def severity_badge(sev: str) -> str:
    cls = f"badge-{sev.lower()}" if sev.lower() in SEVERITY_COLORS else "badge-normal"
    return f'<span class="badge {cls}">{sev.upper()}</span>'


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


# ── Layout principal ──────────────────────────────────────────────────────────
now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

st.markdown(f"""
<div class="soc-header">
  <div>
    <p class="soc-title">🛡️ Panel de Operaciones de Seguridad</p>
    <p class="soc-subtitle">SOC Dashboard &nbsp;·&nbsp; UTN &nbsp;·&nbsp; {now_str}</p>
  </div>
  <div class="ppg-badge">
    <div class="dot-pink"></div>
    <div class="dot-blue"></div>
    <div class="dot-green"></div>
    &nbsp;LIVE
  </div>
</div>
""", unsafe_allow_html=True)

# ── KPIs ──────────────────────────────────────────────────────────────────────
kpis_df = get_kpis()

if not kpis_df.empty:
    k = kpis_df.iloc[0]
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        css = "kpi-critical" if k["alerts_1h"] > 10 else "kpi-ok"
        kpi_card("Alertas última hora", int(k["alerts_1h"]), css)
    with col2:
        css = "kpi-warning" if k["alerts_24h"] > 50 else "kpi-info"
        kpi_card("Alertas 24 h", int(k["alerts_24h"]), css)
    with col3:
        css = "kpi-critical" if k["open_incidents"] > 0 else "kpi-ok"
        kpi_card("Incidentes abiertos", int(k["open_incidents"]), css)
    with col4:
        mttr = float(k["mttr_sec"])
        css = "kpi-critical" if mttr > 300 else ("kpi-warning" if mttr > 60 else "kpi-ok")
        kpi_card("MTTR histórico (seg)", f"{mttr:.1f}s", css)
    with col5:
        auto = float(k["auto_pct"])
        css = "kpi-ok" if auto >= 80 else ("kpi-warning" if auto >= 50 else "kpi-critical")
        kpi_card("Tasa autom. histórica (op.)", f"{auto:.1f}%", css)
    with col6:
        css = "kpi-critical" if k["failed"] > 0 else "kpi-ok"
        kpi_card("Alertas fallidas", int(k["failed"]), css)

# ── KPI fila 2: SOAR ──────────────────────────────────────────────────────────
if not kpis_df.empty:
    k = kpis_df.iloc[0]
    col_b1, col_b2, col_b3 = st.columns([1, 1, 4])
    with col_b1:
        bloq = int(k["ips_bloqueadas"])
        css  = "kpi-critical" if bloq > 0 else "kpi-ok"
        kpi_card("IPs bloqueadas (SOAR)", bloq, css)
    with col_b2:
        mtta_n = int(k["mtta_n"]) if k["mtta_n"] is not None else 0
        if mtta_n > 0:
            mtta = float(k["mtta_sec"])
            css = "kpi-critical" if mtta > 120 else ("kpi-warning" if mtta > 60 else "kpi-ok")
            kpi_card(f"MTTA real (n={mtta_n})", f"{mtta:.1f}s", css)
        else:
            kpi_card("MTTA real", "Sin datos", "kpi-info")

# ── Gráficos principales ──────────────────────────────────────────────────────
st.markdown('<div class="section-title">Análisis de alertas</div>', unsafe_allow_html=True)
col_left, col_right = st.columns([2, 1])

with col_left:
    timeline_df = get_timeline()
    if not timeline_df.empty:
        fig = px.bar(
            timeline_df,
            x="hora", y="total", color="severity",
            color_discrete_map=SEVERITY_COLORS,
            title="Alertas por hora (últimas 24 h)",
            barmode="stack",
        )
        st.plotly_chart(plotly_ppg(fig), use_container_width=True)
    else:
        st.info("Sin datos de timeline aún.")

with col_right:
    sev_df = get_severity_dist()
    if not sev_df.empty:
        colors = [SEVERITY_COLORS.get(s, PPG_PURPLE) for s in sev_df["severity"]]
        fig = go.Figure(go.Pie(
            labels=sev_df["severity"],
            values=sev_df["total"],
            marker_colors=colors,
            marker=dict(line=dict(color=PPG_DARK, width=2)),
            hole=0.48,
            textinfo="label+percent",
            textfont_color="#e8d5f0",
        ))
        fig.update_layout(title="Distribución por severidad (histórico)")
        st.plotly_chart(plotly_ppg(fig), use_container_width=True)
    else:
        st.info("Sin datos de severidad aún.")

# ── Mapa geográfico ───────────────────────────────────────────────────────────
ISO2_TO_ISO3 = {
    "AF":"AFG","AL":"ALB","DZ":"DZA","AR":"ARG","AU":"AUS","AT":"AUT","AZ":"AZE",
    "BD":"BGD","BE":"BEL","BR":"BRA","BG":"BGR","CA":"CAN","CL":"CHL","CN":"CHN",
    "CO":"COL","HR":"HRV","CZ":"CZE","DK":"DNK","EG":"EGY","FI":"FIN","FR":"FRA",
    "DE":"DEU","GH":"GHA","GR":"GRC","HK":"HKG","HU":"HUN","IN":"IND","ID":"IDN",
    "IR":"IRN","IQ":"IRQ","IE":"IRL","IL":"ISR","IT":"ITA","JP":"JPN","JO":"JOR",
    "KZ":"KAZ","KE":"KEN","KP":"PRK","KR":"KOR","LT":"LTU","MY":"MYS","MX":"MEX",
    "MA":"MAR","NL":"NLD","NZ":"NZL","NG":"NGA","NO":"NOR","PK":"PAK","PH":"PHL",
    "PL":"POL","PT":"PRT","RO":"ROU","RU":"RUS","SA":"SAU","SG":"SGP","ZA":"ZAF",
    "ES":"ESP","SE":"SWE","CH":"CHE","TW":"TWN","TH":"THA","TR":"TUR","UA":"UKR",
    "GB":"GBR","US":"USA","VN":"VNM","VE":"VEN","AE":"ARE","UZ":"UZB","BY":"BLR",
    "RS":"SRB","SK":"SVK","SI":"SVN","MK":"MKD","LV":"LVA","EE":"EST","LU":"LUX",
    "IS":"ISL","CY":"CYP","MD":"MDA","GE":"GEO","AM":"ARM","TN":"TUN","LY":"LBY",
    "SD":"SDN","ET":"ETH","TZ":"TZA","UG":"UGA","ZW":"ZWE","MZ":"MOZ","AO":"AGO",
}

st.markdown('<div class="section-title">Distribución geográfica de ataques (histórico)</div>', unsafe_allow_html=True)
geo_df = get_geo_attacks()
if not geo_df.empty:
    geo_df["iso3"] = geo_df["country_code"].map(ISO2_TO_ISO3)
    geo_plot = geo_df.dropna(subset=["iso3"])
    col_map, col_bar = st.columns([2, 1])
    with col_map:
        fig = px.choropleth(
            geo_plot,
            locations="iso3",
            color="ataques",
            color_continuous_scale=[[0, PPG_BLUE], [1, PPG_PINK]],
            title="Ataques por país",
            locationmode="ISO-3",
        )
        fig.update_layout(
            geo=dict(
                bgcolor="rgba(0,0,0,0)",
                showframe=False,
                showcoastlines=True,
                coastlinecolor="#5a3070",
                showland=True,
                landcolor="#0d0820",
                showocean=True,
                oceancolor="#06101a",
                showcountries=True,
                countrycolor="#5a3070",
            ),
            coloraxis_colorbar=dict(title="ataques", tickfont_color="#e8d5f0", title_font_color="#e8d5f0"),
        )
        st.plotly_chart(plotly_ppg(fig), use_container_width=True)
    with col_bar:
        geo_bar = geo_df.head(10).copy()
        geo_bar = geo_bar.rename(columns={"country_code": "País"})
        fig = px.bar(
            geo_bar,
            x="ataques", y="País",
            orientation="h",
            title="Top países atacantes",
            color="ataques",
            color_continuous_scale=[[0, PPG_BLUE], [1, PPG_PINK]],
        )
        fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False)
        st.plotly_chart(plotly_ppg(fig), use_container_width=True)
else:
    st.info("Sin datos geográficos aún. Se poblarán con las próximas alertas procesadas por AbuseIPDB.")

# ── Top IPs + Playbooks ───────────────────────────────────────────────────────
st.markdown('<div class="section-title">Inteligencia de amenazas</div>', unsafe_allow_html=True)
col_ips, col_pb = st.columns([1, 1])

with col_ips:
    ips_df = get_top_ips()
    if not ips_df.empty:
        fig = px.bar(
            ips_df,
            x="alertas", y="src_ip",
            orientation="h",
            title="Top IPs sospechosas (histórico)",
            color="alertas",
            color_continuous_scale=[PPG_GREEN, PPG_BLUE, PPG_PINK],
        )
        fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False)
        st.plotly_chart(plotly_ppg(fig), use_container_width=True)
    else:
        st.info("Sin IPs registradas aún.")

with col_pb:
    pb_df = get_playbook_summary()
    if not pb_df.empty:
        fig = px.bar(
            pb_df,
            x="ejecuciones", y="workflow",
            orientation="h",
            color="outcome",
            title="Ejecuciones de playbooks (histórico)",
            color_discrete_map={
                "success": PPG_GREEN,
                "error":   PPG_PINK,
                "warning": "#FF9A6C",
            },
        )
        fig.update_layout(yaxis=dict(autorange="reversed"))
        st.plotly_chart(plotly_ppg(fig), use_container_width=True)
    else:
        st.info("Sin ejecuciones de playbooks aún.")

# ── Reglas más disparadas + Incidentes destacados ────────────────────────────
st.markdown('<div class="section-title">Reglas e incidentes</div>', unsafe_allow_html=True)
col_rules, col_inc = st.columns([1, 1])

with col_rules:
    rules_df = get_top_rules()
    if not rules_df.empty:
        fig = px.bar(
            rules_df,
            x="disparos", y="regla",
            orientation="h",
            title="Reglas más disparadas (24 h)",
            color="disparos",
            color_continuous_scale=[PPG_BLUE, PPG_PURPLE, PPG_PINK],
        )
        fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False)
        st.plotly_chart(plotly_ppg(fig), use_container_width=True)

        # detalle por regla
        rows_html = ""
        for _, r in rules_df.iterrows():
            ultima = str(r.get("ultima_vez", ""))[:16]
            rows_html += f"""
            <div class="alert-row">
              <span style="flex:1.5;color:#e8d5f0;font-weight:600">{r['regla']}</span>
              <span style="color:{PPG_PINK};min-width:60px;text-align:center">{int(r['disparos'])} total</span>
              <span style="color:{PPG_PINK};min-width:55px;text-align:center">{int(r['criticas'])} crit</span>
              <span style="color:#FF9A6C;min-width:50px;text-align:center">{int(r['altas'])} alta</span>
              <span style="color:{PPG_PURPLE};font-size:0.75rem;min-width:90px;text-align:right">{ultima}</span>
            </div>
            """
        st.markdown(rows_html, unsafe_allow_html=True)
    else:
        st.info("Sin reglas disparadas en las últimas 24 h.")

with col_inc:
    inc_df = get_open_incidents()
    st.markdown(f"<div style='color:{PPG_PINK};font-weight:700;font-size:0.9rem;margin-bottom:8px'>🚨 Incidentes abiertos</div>", unsafe_allow_html=True)
    if not inc_df.empty:
        rows_html = ""
        for _, r in inc_df.iterrows():
            sev = str(r.get("severity", "normal")).lower()
            badge = severity_badge(sev)
            tipo = str(r.get("tipo") or "—")
            ip   = str(r.get("ip_origen") or "—")
            user = str(r.get("usuario") or "—")
            intentos = r.get("intentos") or "—"
            creado = str(r.get("creado") or "")
            rows_html += f"""
            <div class="alert-row" style="border-left:3px solid {PPG_PINK};">
              <span style="color:{PPG_PURPLE};font-size:0.72rem;min-width:85px">{creado}</span>
              {badge}
              <span style="flex:1;color:#e8d5f0;font-weight:600">{tipo}</span>
              <span style="color:{PPG_BLUE};min-width:100px">{ip}</span>
              <span style="color:{PPG_GREEN};min-width:70px">{user}</span>
              <span style="color:{PPG_PURPLE};min-width:40px;text-align:right">{intentos}x</span>
            </div>
            """
        st.markdown(rows_html, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="text-align:center;padding:30px;color:{PPG_GREEN};font-size:1.1rem;">
          ✅ Sin incidentes abiertos
        </div>
        """, unsafe_allow_html=True)

# ── Blacklist SOAR ────────────────────────────────────────────────────────────
st.markdown('<div class="section-title">Respuesta automatizada — IPs bloqueadas (SOAR)</div>', unsafe_allow_html=True)
bl_df = get_blacklist()
if not bl_df.empty:
    rows_html = ""
    for _, r in bl_df.iterrows():
        enforced = r.get("enforced", False)
        if enforced:
            enforcement_badge = f'<span style="background:#e74c3c22;color:#e74c3c;border:1px solid #e74c3c66;border-radius:4px;padding:1px 7px;font-size:0.68rem;font-weight:700">🔥 APLICADO</span>'
        else:
            enforcement_badge = f'<span style="background:{PPG_PURPLE}22;color:{PPG_PURPLE};border:1px solid {PPG_PURPLE}66;border-radius:4px;padding:1px 7px;font-size:0.68rem;font-weight:700">⚠ LÓGICO</span>'
        enf_msg = str(r.get("enforcement_message") or "")
        enf_title = f' title="{enf_msg}"' if enf_msg else ""
        rows_html += f"""
        <div class="alert-row" style="border-left:3px solid {'#e74c3c' if enforced else PPG_PURPLE};">
          <span style="color:{PPG_PINK};font-weight:700;min-width:120px">🚫 {r['ip']}</span>
          <span style="flex:1;color:#e8d5f0;font-size:0.85rem">{r['razón']}</span>
          <span style="color:{PPG_PURPLE};font-size:0.75rem;min-width:95px">desde {r['bloqueada']}</span>
          <span style="color:{PPG_BLUE};font-size:0.75rem;min-width:95px">vence {r['vence']}</span>
          <span{enf_title}>{enforcement_badge}</span>
        </div>
        """
    st.markdown(rows_html, unsafe_allow_html=True)
else:
    st.markdown(f"""
    <div style="text-align:center;padding:20px;color:{PPG_GREEN};font-size:1rem;">
      ✅ Sin IPs bloqueadas actualmente
    </div>
    """, unsafe_allow_html=True)

# ── Tabla últimas alertas ─────────────────────────────────────────────────────
st.markdown('<div class="section-title">Últimas alertas</div>', unsafe_allow_html=True)

alerts_df = get_recent_alerts()
if not alerts_df.empty:
    rows_html = ""
    for _, row in alerts_df.iterrows():
        sev = str(row.get("severity", "normal")).lower()
        badge = severity_badge(sev)
        status_icon = "✅" if row.get("status") == "acknowledged" else "🔴"
        rows_html += f"""
        <div class="alert-row">
          <span style="color:{PPG_PURPLE};min-width:70px">{row['hora']}</span>
          {badge}
          <span style="flex:1;color:#e8d5f0">{row['rule_id']}</span>
          <span style="color:{PPG_BLUE};min-width:110px">{row.get('src_ip') or '—'}</span>
          <span style="color:{PPG_GREEN};min-width:100px">{row.get('username') or '—'}</span>
          <span>{status_icon}</span>
        </div>
        """
    st.markdown(rows_html, unsafe_allow_html=True)
else:
    st.info("No hay alertas registradas aún. Iniciá el detector o el simulador de ataques.")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div style="text-align:right;font-size:0.72rem;color:{PPG_PURPLE}88;margin-top:20px;">
  🛡️ Panel de Operaciones de Seguridad &nbsp;·&nbsp; UTN &nbsp;·&nbsp;
  Refresco automático cada {REFRESH_SECONDS}s
</div>
""", unsafe_allow_html=True)

time.sleep(REFRESH_SECONDS)
st.rerun()
