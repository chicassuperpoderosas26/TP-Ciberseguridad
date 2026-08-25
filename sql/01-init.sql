-- ============================================
-- SIEM Database Schema
-- ============================================

-- Tabla de eventos crudos (auditoría completa). Reservada para ingesta directa de
-- eventos; no poblada en la implementación actual, en la que Logstash escribe
-- únicamente a Elasticsearch (ver §5.2 de la tesis).
CREATE TABLE IF NOT EXISTS events_raw (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMP NOT NULL DEFAULT NOW(),
    host VARCHAR(120),
    source VARCHAR(120),
    severity VARCHAR(20),
    message TEXT,
    json_raw JSONB
);

CREATE INDEX IF NOT EXISTS idx_events_raw_ts ON events_raw(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_raw_host ON events_raw(host);

-- Tabla de alertas procesadas
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMP DEFAULT NOW(),
    rule_id VARCHAR(120) NOT NULL,
    src_ip VARCHAR(60),
    username VARCHAR(120),
    severity VARCHAR(20),
    raw JSONB,
    status VARCHAR(30) DEFAULT 'new',
    acknowledged_at TIMESTAMPTZ,  -- Reservada para futuro módulo de gestión de casos (ver §7.4)
    acknowledged_by TEXT,
    country_code VARCHAR(100),
    event_occurred_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

-- Tabla de ejecuciones de playbooks
CREATE TABLE IF NOT EXISTS playbook_runs (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id),
    workflow VARCHAR(120),
    outcome VARCHAR(60),
    evidence JSONB,
    executed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbook_runs_alert_id ON playbook_runs(alert_id);
CREATE INDEX IF NOT EXISTS idx_playbook_runs_executed_at ON playbook_runs(executed_at DESC);

-- ============================================
-- VISTAS PARA MÉTRICAS
-- ============================================

-- Vista para cálculo de MTTR (Mean Time To Respond)
CREATE OR REPLACE VIEW mttr_stats AS
SELECT
    AVG(EXTRACT(EPOCH FROM (p.executed_at - a.ts))) AS avg_mttr_seconds,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (p.executed_at - a.ts))) AS median_mttr_seconds,
    COUNT(*) AS total_responses
FROM alerts a
JOIN playbook_runs p ON p.alert_id = a.id;

-- Vista para cálculo de MTTA (Mean Time To Acknowledge)
-- MTTA = tiempo entre que el evento ocurre en el mundo real (event_occurred_at,
-- ej. timestamp de un log syslog) y el momento en que el sistema lo detecta e
-- inserta la alerta (ts). Solo aplica a detectores por sondeo periodico que
-- reportan el timestamp real del evento (ej. ssh_bruteforce_detector.py);
-- las alertas sinteticas del simulador no tienen event_occurred_at y quedan
-- fuera del calculo (NULL).
CREATE OR REPLACE VIEW mtta_stats AS
SELECT
    AVG(EXTRACT(EPOCH FROM (ts - event_occurred_at))) FILTER (WHERE event_occurred_at IS NOT NULL) AS avg_mtta_seconds,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (ts - event_occurred_at))) FILTER (WHERE event_occurred_at IS NOT NULL) AS median_mtta_seconds,
    COUNT(*) FILTER (WHERE event_occurred_at IS NOT NULL) AS acknowledged_count,
    COUNT(*) AS total_alerts
FROM alerts;

-- Vista para alertas por severidad
CREATE OR REPLACE VIEW alerts_by_severity AS
SELECT
    DATE(ts) AS alert_date,
    severity,
    COUNT(*) AS count
FROM alerts
GROUP BY DATE(ts), severity
ORDER BY alert_date DESC, severity;

-- Vista para distribucion de alertas por regla de deteccion (cobertura del catalogo)
CREATE OR REPLACE VIEW alerts_by_rule AS
SELECT
    rule_id,
    COUNT(*) AS alert_count,
    MIN(ts) AS primera_vez,
    MAX(ts) AS ultima_vez
FROM alerts
GROUP BY rule_id
ORDER BY alert_count DESC;

-- Vista para tasa de automatización (cobertura + éxito separados)
CREATE OR REPLACE VIEW automation_rate AS
SELECT
    -- Cobertura: alertas con al menos un playbook registrado / total alertas
    COUNT(DISTINCT p.alert_id)                                                        AS automated_alerts,
    (SELECT COUNT(*) FROM alerts)                                                     AS total_alerts,
    ROUND(COUNT(DISTINCT p.alert_id)::numeric
          / NULLIF((SELECT COUNT(*) FROM alerts), 0) * 100, 2)                       AS automation_percentage,

    -- Éxito: playbooks con outcome exitoso / total playbooks registrados
    COUNT(*) FILTER (WHERE p.outcome IN (
        'success', 'incident_created', 'incident_reused', 'blocked', 'partial_success', 'logged_low'
    ))                                                                                AS successful_runs,
    COUNT(*)                                                                          AS total_runs,
    ROUND(COUNT(*) FILTER (WHERE p.outcome IN (
        'success', 'incident_created', 'incident_reused', 'blocked', 'partial_success', 'logged_low'
    ))::numeric / NULLIF(COUNT(*), 0) * 100, 2)                                      AS success_rate,

    -- Distribución de outcomes
    COUNT(*) FILTER (WHERE p.outcome = 'success')           AS outcome_success,
    COUNT(*) FILTER (WHERE p.outcome = 'incident_created')  AS outcome_incident_created,
    COUNT(*) FILTER (WHERE p.outcome = 'incident_reused')   AS outcome_incident_reused,
    COUNT(*) FILTER (WHERE p.outcome = 'blocked')           AS outcome_blocked,
    COUNT(*) FILTER (WHERE p.outcome = 'partial_success')   AS outcome_partial,
    COUNT(*) FILTER (WHERE p.outcome = 'logged_low')        AS outcome_logged_low,
    COUNT(*) FILTER (WHERE p.outcome = 'failed')            AS outcome_failed
FROM playbook_runs p;

-- Vista de automatización OPERATIVA (excluye alertas de prueba/construcción)
-- Las alertas de test no deben sesgar los KPI operativos del SOC
CREATE OR REPLACE VIEW automation_rate_operational AS
SELECT
    COUNT(DISTINCT p.alert_id)                                                        AS automated_alerts,
    COUNT(DISTINCT a.id)                                                              AS total_alerts,
    ROUND(COUNT(DISTINCT p.alert_id)::numeric
          / NULLIF(COUNT(DISTINCT a.id), 0) * 100, 2)                                AS automation_percentage,
    COUNT(*) FILTER (WHERE p.outcome IN (
        'success', 'incident_created', 'incident_reused', 'blocked', 'partial_success', 'logged_low'
    ))                                                                                AS successful_runs,
    COUNT(p.id)                                                                       AS total_runs,
    ROUND(COUNT(*) FILTER (WHERE p.outcome IN (
        'success', 'incident_created', 'incident_reused', 'blocked', 'partial_success', 'logged_low'
    ))::numeric / NULLIF(COUNT(p.id), 0) * 100, 2)                                   AS success_rate,
    COUNT(*) FILTER (WHERE p.outcome = 'success')           AS outcome_success,
    COUNT(*) FILTER (WHERE p.outcome = 'incident_created')  AS outcome_incident_created,
    COUNT(*) FILTER (WHERE p.outcome = 'incident_reused')   AS outcome_incident_reused,
    COUNT(*) FILTER (WHERE p.outcome = 'blocked')           AS outcome_blocked,
    COUNT(*) FILTER (WHERE p.outcome = 'partial_success')   AS outcome_partial,
    COUNT(*) FILTER (WHERE p.outcome = 'logged_low')        AS outcome_logged_low,
    COUNT(*) FILTER (WHERE p.outcome = 'failed')            AS outcome_failed
FROM alerts a
LEFT JOIN playbook_runs p ON p.alert_id = a.id
WHERE a.rule_id NOT IN ('test_fix', 'test_playbook', 'test_mejorado', 'test_telegram')
  AND a.rule_id NOT LIKE 'test%';

-- Vista para top IPs sospechosas
CREATE OR REPLACE VIEW top_suspicious_ips AS
SELECT
    src_ip,
    COUNT(*) AS alert_count
FROM alerts
WHERE src_ip IS NOT NULL
GROUP BY src_ip
ORDER BY alert_count DESC
LIMIT 10;

-- ============================================
-- TABLAS ADICIONALES
-- ============================================

-- Tabla de incidentes (gestión de ataques detectados)
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    type TEXT,
    src_ip TEXT,
    username TEXT,
    attempts INTEGER,
    rule_id TEXT,
    severity TEXT,
    status TEXT DEFAULT 'open',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents(src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

-- Tabla de alertas fallidas (manejo de errores)
CREATE TABLE IF NOT EXISTS failed_alerts (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMP DEFAULT NOW(),
    error_node TEXT,
    error_message TEXT,
    alert_data JSONB,
    retry_count INTEGER DEFAULT 0,
    resolved BOOLEAN DEFAULT false,
    resolved_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_failed_alerts_ts ON failed_alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_failed_alerts_resolved ON failed_alerts(resolved);

-- Tabla de blacklist de IPs (respuesta automatizada SOAR)
CREATE TABLE IF NOT EXISTS ip_blacklist (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(60) NOT NULL,
    reason TEXT,
    incident_id INTEGER REFERENCES incidents(id),
    blocked_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    active BOOLEAN DEFAULT true,
    -- Enforcement: distingue "intención de bloqueo" de "bloqueo aplicado realmente"
    enforced            BOOLEAN DEFAULT false,
    enforcement_message TEXT,
    enforced_at         TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ip_blacklist_ip ON ip_blacklist(ip);
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_active ON ip_blacklist(active);