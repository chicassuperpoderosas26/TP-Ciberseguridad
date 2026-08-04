"""
==============================================
  SIMULADOR DE ATAQUES PARA SIEM
  Envia alertas automaticas al webhook de n8n
==============================================
Uso:
  python attack_simulator.py              -> Menu interactivo
  python attack_simulator.py --auto       -> Simulacion automatica completa
  python attack_simulator.py --brute      -> Solo SSH brute force
  python attack_simulator.py --fim        -> Solo integridad de archivos
  python attack_simulator.py --mixed      -> Ataques variados aleatorios
"""

import argparse
import logging
import os
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone

import requests


# ============================================
# COLORES ANSI
# ============================================
class C:
    """Colores ANSI para la terminal."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"

    # Mapeo severidad -> color
    SEV = {
        "critical": "\033[91m",  # rojo
        "high":     "\033[93m",  # amarillo
        "medium":   "\033[94m",  # azul
        "low":      "\033[92m",  # verde
    }

    @classmethod
    def sev(cls, severity):
        return cls.SEV.get(severity, cls.WHITE)


# ============================================
# CONFIGURACION
# ============================================
N8N_WEBHOOK_URL = os.getenv("SIEM_WEBHOOK_URL", "http://localhost:5678/webhook/alert/siem")
SIEM_KEY = os.getenv("SIEM_API_KEY", "superpoderosas26")
REQUEST_TIMEOUT = int(os.getenv("SIEM_REQUEST_TIMEOUT", "10"))
LOG_FILE = os.getenv("SIEM_LOG_FILE", "attack_simulator.log")

HEADERS = {
    "Content-Type": "application/json",
    "x-siem-key": SIEM_KEY,
}

# ============================================
# LOGGING
# ============================================
logger = logging.getLogger("attack_simulator")
logger.setLevel(logging.INFO)

_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
logger.addHandler(_file_handler)


# ============================================
# DATOS SIMULADOS
# ============================================

# IPs simuladas de atacantes (publicas, con pais real via AbuseIPDB para el mapa)
ATTACKER_IPS = [
    "103.140.187.60",
    "80.94.95.116",
    "196.251.83.100",
    "45.33.32.156",
    "185.220.101.42",
    "91.240.118.172",
    "178.128.95.10",
]

# Usuarios objetivo
TARGET_USERS = ["root", "admin", "ubuntu", "deploy", "postgres", "www-data", "siem"]

# Archivos para FIM
FIM_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/var/www/html/index.php",
    "/etc/crontab",
    "/usr/local/bin/backup.sh",
]

# Payloads SQL Injection
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM credentials --",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    "admin'--",
]

# Rutas de Web Shell
WEBSHELL_PATHS = [
    "/var/www/html/uploads/cmd.php",
    "/var/www/html/.hidden/shell.php",
    "/tmp/backdoor.py",
    "/var/www/html/wp-content/plugins/hack.php",
]

# Paises sospechosos para login
SUSPICIOUS_COUNTRIES = [
    ("Russia", "RU"),
    ("China", "CN"),
    ("North Korea", "KP"),
    ("Iran", "IR"),
    ("Nigeria", "NG"),
]

# Firmas de malware
MALWARE_SIGNATURES = [
    {"name": "Trojan.GenericKD.46789", "type": "trojan", "path": "/tmp/.cache/svchost.exe"},
    {"name": "Backdoor.Linux.Mirai.b", "type": "botnet", "path": "/var/tmp/.x11"},
    {"name": "Ransom.WannaCry.S", "type": "ransomware", "path": "/home/user/Documents/important.docx.encrypted"},
    {"name": "CoinMiner.Linux.XMRIG.a", "type": "cryptominer", "path": "/opt/.xmrig/config.json"},
]


def jittered_delay(base_delay):
    """Retorna un delay variable: base +/- 40% aleatorio."""
    jitter = base_delay * random.uniform(-0.4, 0.4)
    return max(0.3, base_delay + jitter)


def utc_now():
    """Retorna timestamp UTC real en formato ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_payload(rule_id, src_ip, username, severity, message, **extra_fields):
    """Crea payloads consistentes para todos los tipos de alerta."""
    payload = {
        "rule_id": rule_id,
        "src_ip": src_ip,
        "username": username,
        "severity": severity,
        "timestamp": utc_now(),
        "message": message,
    }
    payload.update(extra_fields)
    return payload


def init_run_stats(seed=None):
    """Inicializa metricas de la ejecucion."""
    return {
        "seed": seed,
        "started_at": utc_now(),
        "total_sent": 0,
        "total_ok": 0,
        "total_failed": 0,
        "by_rule": Counter(),
        "by_severity": Counter(),
    }


def print_summary(stats):
    """Muestra un resumen util para testing y demos."""
    print(f"\n{C.BOLD}{'=' * 65}")
    print(f"  RESUMEN DE EJECUCION")
    print(f"{'=' * 65}{C.RESET}")
    print(f"  Seed: {stats['seed'] if stats['seed'] is not None else 'aleatoria'}")
    print(f"  Inicio: {stats['started_at']}")
    print(f"  Fin:    {utc_now()}")
    print(f"  Enviadas: {C.CYAN}{stats['total_sent']}{C.RESET}")
    print(f"  OK:       {C.GREEN}{stats['total_ok']}{C.RESET}")
    print(f"  Fallidas: {C.RED}{stats['total_failed']}{C.RESET}")

    print(f"\n  {C.BOLD}Por regla:{C.RESET}")
    if stats["by_rule"]:
        for rule_id, count in sorted(stats["by_rule"].items()):
            print(f"    {C.GRAY}-{C.RESET} {rule_id}: {C.CYAN}{count}{C.RESET}")
    else:
        print(f"    {C.GRAY}- Sin datos{C.RESET}")

    print(f"\n  {C.BOLD}Por severidad:{C.RESET}")
    if stats["by_severity"]:
        for severity, count in sorted(stats["by_severity"].items()):
            color = C.sev(severity)
            print(f"    {C.GRAY}-{C.RESET} {color}{severity}: {count}{C.RESET}")
    else:
        print(f"    {C.GRAY}- Sin datos{C.RESET}")
    print(f"{C.BOLD}{'=' * 65}{C.RESET}")

    # Log summary to file
    logger.info(
        "Resumen | Enviadas: %d | OK: %d | Fallidas: %d | Reglas: %s | Severidades: %s",
        stats["total_sent"], stats["total_ok"], stats["total_failed"],
        dict(stats["by_rule"]), dict(stats["by_severity"]),
    )


def send_alert(payload, stats=None):
    """Envia una alerta al webhook de n8n y acumula metricas."""
    if stats is not None:
        stats["total_sent"] += 1
        stats["by_rule"][payload["rule_id"]] += 1
        stats["by_severity"][payload["severity"]] += 1

    sev_color = C.sev(payload["severity"])

    try:
        response = requests.post(
            N8N_WEBHOOK_URL,
            json=payload,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        ok = response.status_code == 200
        if ok:
            status_str = f"{C.GREEN}{'OK':12s}{C.RESET}"
        else:
            status_str = f"{C.RED}{'ERROR (' + str(response.status_code) + ')':12s}{C.RESET}"

        print(
            f"  {status_str} [{sev_color}{payload['severity'].upper():8s}{C.RESET}] "
            f"{C.BOLD}{payload['rule_id']:22s}{C.RESET} {C.GRAY}|{C.RESET} "
            f"IP: {C.YELLOW}{payload['src_ip']:16s}{C.RESET} {C.GRAY}|{C.RESET} "
            f"User: {C.CYAN}{payload.get('username', 'N/A')}{C.RESET}"
        )

        logger.info(
            "%s | [%s] %s | IP: %s | User: %s",
            "OK" if ok else f"ERROR({response.status_code})",
            payload["severity"].upper(), payload["rule_id"],
            payload["src_ip"], payload.get("username", "N/A"),
        )

        if stats is not None:
            if ok:
                stats["total_ok"] += 1
            else:
                stats["total_failed"] += 1
        return ok
    except requests.exceptions.ConnectionError:
        print(f"  {C.RED}ERROR{C.RESET}        No se pudo conectar a n8n en {N8N_WEBHOOK_URL}")
        print(f"               {C.YELLOW}Verifica que el contenedor de n8n este corriendo.{C.RESET}")
        logger.error("ConnectionError: No se pudo conectar a %s", N8N_WEBHOOK_URL)
    except Exception as exc:
        print(f"  {C.RED}ERROR{C.RESET}        {exc}")
        logger.error("Exception: %s", exc)

    if stats is not None:
        stats["total_failed"] += 1
    return False


# ============================================
# TIPOS DE ATAQUE
# ============================================

def ssh_bruteforce(ip=None, user=None, count=7, delay=2.0, stats=None):
    """Simula un ataque de fuerza bruta SSH."""
    ip = ip or random.choice(ATTACKER_IPS)
    user = user or random.choice(TARGET_USERS)

    print(f"\n{C.BOLD}{C.RED}[SSH BRUTE FORCE]{C.RESET} {ip} -> {user} ({count} intentos)")
    print(f"{C.GRAY}Delay entre intentos: ~{delay}s{C.RESET}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    all_ok = True
    for attempt in range(1, count + 1):
        payload = build_payload(
            "ssh_bruteforce",
            ip,
            user,
            "high" if attempt < count - 1 else "critical",
            f"Failed password for {user} from {ip} port 22 ssh2",
            attempt=attempt,
        )
        if not send_alert(payload, stats=stats):
            all_ok = False
        if attempt < count:
            time.sleep(jittered_delay(delay))

    print(f"\n{C.GREEN}Brute force completado: {count} alertas enviadas{C.RESET}")
    return all_ok


def file_integrity(file_path=None, ip=None, stats=None):
    """Simula una alerta de integridad de archivos."""
    file_path = file_path or random.choice(FIM_FILES)
    ip = ip or f"192.168.1.{random.randint(10, 50)}"

    print(f"\n{C.BOLD}{C.MAGENTA}[FILE INTEGRITY]{C.RESET} {file_path}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    payload = build_payload(
        "file_integrity",
        ip,
        "system",
        "high" if "www" in file_path else "critical",
        f"ossec: integrity checksum changed: {file_path}",
        file_path=file_path,
    )
    ok = send_alert(payload, stats=stats)
    if ok:
        print(f"{C.GREEN}Alerta FIM enviada{C.RESET}")
    return ok


def port_scan(ip=None, stats=None):
    """Simula deteccion de escaneo de puertos."""
    ip = ip or random.choice(ATTACKER_IPS)
    ports = random.randint(50, 500)

    print(f"\n{C.BOLD}{C.BLUE}[PORT SCAN]{C.RESET} {ip} ({ports} puertos)")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    payload = build_payload(
        "port_scan_detected",
        ip,
        "unknown",
        "high",
        f"Multiple connection attempts from {ip} to various ports detected",
        ports_scanned=ports,
    )
    return send_alert(payload, stats=stats)


def privilege_escalation(ip=None, user=None, stats=None):
    """Simula intento de escalacion de privilegios."""
    ip = ip or f"192.168.1.{random.randint(10, 50)}"
    user = user or random.choice(["www-data", "deploy", "ubuntu"])

    print(f"\n{C.BOLD}{C.RED}[PRIVILEGE ESCALATION]{C.RESET} {user}@{ip}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    payload = build_payload(
        "privilege_escalation",
        ip,
        user,
        "critical",
        f"Suspicious sudo usage by {user}: attempting to access /etc/shadow",
    )
    return send_alert(payload, stats=stats)


def sql_injection(ip=None, stats=None):
    """Simula intento de SQL Injection en aplicacion web."""
    ip = ip or random.choice(ATTACKER_IPS)
    sqli = random.choice(SQLI_PAYLOADS)
    target_url = random.choice(["/login", "/api/users", "/search", "/admin/query"])

    print(f"\n{C.BOLD}{C.YELLOW}[SQL INJECTION]{C.RESET} {ip} -> {target_url}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    payload = build_payload(
        "sql_injection",
        ip,
        "web_app",
        "critical",
        f"SQL injection attempt detected on {target_url}: {sqli}",
        target_url=target_url,
        payload_detected=sqli,
    )
    return send_alert(payload, stats=stats)


def web_shell(ip=None, stats=None):
    """Simula deteccion de web shell en el servidor."""
    ip = ip or f"192.168.1.{random.randint(10, 50)}"
    shell = random.choice(WEBSHELL_PATHS)

    print(f"\n{C.BOLD}{C.RED}[WEB SHELL]{C.RESET} {shell}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    payload = build_payload(
        "web_shell_detected",
        ip,
        "www-data",
        "critical",
        f"Suspicious web shell detected: {shell}",
        file_path=shell,
        detection_method="file_signature_analysis",
    )
    return send_alert(payload, stats=stats)


def malware_detected(ip=None, stats=None):
    """Simula deteccion de malware en el sistema."""
    ip = ip or f"192.168.1.{random.randint(10, 50)}"
    mal = random.choice(MALWARE_SIGNATURES)

    print(f"\n{C.BOLD}{C.BG_RED}{C.WHITE}[MALWARE]{C.RESET} {mal['name']}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    payload = build_payload(
        "malware_detected",
        ip,
        "system",
        "critical",
        f"Malware detected: {mal['name']} ({mal['type']}) at {mal['path']}",
        malware_name=mal["name"],
        malware_type=mal["type"],
        file_path=mal["path"],
    )
    return send_alert(payload, stats=stats)


def password_spraying(user=None, ip_count=6, delay=0.5, stats=None):
    """Simula un ataque de password spraying: múltiples IPs -> mismo usuario."""
    user = user or random.choice(["admin", "root", "ceo", "finance", "siem"])
    ips = random.sample(ATTACKER_IPS + [
        "77.88.55.66", "104.21.14.101", "172.67.68.212",
        "45.155.205.233", "194.165.16.11",
    ], k=min(ip_count, 12))

    print(f"\n{C.BOLD}{C.RED}[PASSWORD SPRAYING]{C.RESET} {len(ips)} IPs -> usuario: {C.CYAN}{user}{C.RESET}")
    print(f"{C.GRAY}Delay entre intentos: ~{delay}s{C.RESET}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    all_ok = True
    for ip in ips:
        payload = build_payload(
            "ssh_bruteforce",
            ip,
            user,
            "high",
            f"Failed password for {user} from {ip} port 22 ssh2 [spraying]",
        )
        if not send_alert(payload, stats=stats):
            all_ok = False
        time.sleep(jittered_delay(delay))

    print(f"\n{C.GREEN}Password spraying completado: {len(ips)} IPs enviadas{C.RESET}")
    return all_ok


def suspicious_login(ip=None, user=None, stats=None):
    """Simula login desde ubicacion geografica sospechosa."""
    ip = ip or random.choice(ATTACKER_IPS)
    user = user or random.choice(["admin", "root", "ceo", "finance"])
    country_name, country_code = random.choice(SUSPICIOUS_COUNTRIES)

    print(f"\n{C.BOLD}{C.YELLOW}[SUSPICIOUS LOGIN]{C.RESET} {user} desde {country_name} ({ip})")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    payload = build_payload(
        "suspicious_login",
        ip,
        user,
        "high",
        f"Login from suspicious location: {user} from {country_name} ({country_code})",
        country=country_name,
        country_code=country_code,
    )
    return send_alert(payload, stats=stats)


# ============================================
# ESCENARIOS COMPUESTOS
# ============================================

def scenario_ssh_campaign(stats, delay=1.5):
    """Escenario realista de brute force para disparar deteccion por volumen."""
    return ssh_bruteforce(
        ip=random.choice(ATTACKER_IPS),
        user=random.choice(["root", "admin", "ubuntu"]),
        count=random.randint(5, 8),
        delay=delay,
        stats=stats,
    )


def scenario_fim_cluster(stats, delay=1.5):
    """Escenario con multiples cambios sensibles de integridad."""
    ok = True
    ip = f"192.168.1.{random.randint(10, 50)}"
    files = random.sample(FIM_FILES, k=min(2, len(FIM_FILES)))
    for file_path in files:
        if not file_integrity(file_path=file_path, ip=ip, stats=stats):
            ok = False
        time.sleep(jittered_delay(delay))
    return ok


def scenario_recon(stats, delay=1.5):
    """Escenario de reconocimiento seguido de escalacion."""
    ip = random.choice(ATTACKER_IPS)
    ok = port_scan(ip=ip, stats=stats)
    time.sleep(jittered_delay(delay))
    if not privilege_escalation(ip=f"192.168.1.{random.randint(10, 50)}", stats=stats):
        ok = False
    return ok


def scenario_web_attack(stats, delay=1.5):
    """Escenario de ataque web: SQL Injection seguido de Web Shell."""
    ip = random.choice(ATTACKER_IPS)
    ok = sql_injection(ip=ip, stats=stats)
    time.sleep(jittered_delay(delay))
    if not web_shell(stats=stats):
        ok = False
    return ok


def scenario_intrusion(stats, delay=1.5):
    """Escenario de intrusion completa: login sospechoso + malware."""
    ip = random.choice(ATTACKER_IPS)
    ok = suspicious_login(ip=ip, stats=stats)
    time.sleep(jittered_delay(delay))
    if not malware_detected(stats=stats):
        ok = False
    return ok


def mixed_attacks(count=10, delay=3, stats=None):
    """Envia escenarios aleatorios en lugar de eventos sueltos."""
    scenarios = [
        ("Campana SSH",         lambda: scenario_ssh_campaign(stats, delay=max(1, delay / 2))),
        ("Cluster FIM",         lambda: scenario_fim_cluster(stats, delay=max(1, delay / 2))),
        ("Recon + Escalacion",  lambda: scenario_recon(stats, delay=max(1, delay / 2))),
        ("Ataque Web",          lambda: scenario_web_attack(stats, delay=max(1, delay / 2))),
        ("Intrusion Completa",  lambda: scenario_intrusion(stats, delay=max(1, delay / 2))),
    ]

    print(f"\n{C.BOLD}Simulacion mixta: {count} escenarios aleatorios{C.RESET}")
    print(f"{C.GRAY}Delay entre escenarios: ~{delay}s{C.RESET}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")

    overall_ok = True
    for index in range(1, count + 1):
        name, scenario_fn = random.choice(scenarios)
        print(f"\n  {C.CYAN}[{index}/{count}]{C.RESET} {C.BOLD}{name}{C.RESET}")
        if not scenario_fn():
            overall_ok = False
        if index < count:
            time.sleep(jittered_delay(delay))

    print(f"\n{C.GREEN}Simulacion mixta completada: {count} escenarios ejecutados{C.RESET}")
    return overall_ok


def full_auto_simulation(stats=None):
    """Ejecuta una simulacion automatica completa para demo."""
    print(f"{C.BOLD}{'=' * 65}")
    print(f"  SIMULACION AUTOMATICA COMPLETA")
    print(f"  Esto va a enviar multiples ataques al SIEM")
    print(f"{'=' * 65}{C.RESET}")

    logger.info("=== SIMULACION AUTOMATICA COMPLETA INICIADA ===")
    results = []

    print(f"\n{C.BOLD}{C.CYAN}FASE 1: Ataque SSH Brute Force{C.RESET}")
    results.append(ssh_bruteforce(ip="103.140.187.60", user="root", count=6, delay=1.5, stats=stats))
    time.sleep(3)

    print(f"\n{C.BOLD}{C.CYAN}FASE 2: Cambios de integridad detectados{C.RESET}")
    results.append(scenario_fim_cluster(stats or init_run_stats(), delay=2))
    time.sleep(3)

    print(f"\n{C.BOLD}{C.CYAN}FASE 3: SQL Injection + Web Shell{C.RESET}")
    results.append(scenario_web_attack(stats or init_run_stats(), delay=2))
    time.sleep(3)

    print(f"\n{C.BOLD}{C.CYAN}FASE 4: Segundo ataque brute force{C.RESET}")
    results.append(ssh_bruteforce(ip="80.94.95.116", user="admin", count=5, delay=1.5, stats=stats))
    time.sleep(3)

    print(f"\n{C.BOLD}{C.CYAN}FASE 5: Login sospechoso + Malware{C.RESET}")
    results.append(scenario_intrusion(stats or init_run_stats(), delay=2))
    time.sleep(3)

    print(f"\n{C.BOLD}{C.CYAN}FASE 6: Reconocimiento y escalacion{C.RESET}")
    results.append(scenario_recon(stats or init_run_stats(), delay=2))

    print(f"\n{C.BOLD}{'=' * 65}")
    print(f"  SIMULACION COMPLETA FINALIZADA")
    print(f"  Revisa n8n, Telegram y Grafana para ver los resultados")
    print(f"{'=' * 65}{C.RESET}")

    logger.info("=== SIMULACION AUTOMATICA COMPLETA FINALIZADA ===")
    return all(results)


# ============================================
# PRUEBA DE RAMAS DEL WORKFLOW
# ============================================

RAMA_TEST_IP = "45.33.32.156"


def rama1_alerta_high(stats=None):
    """Rama 1: alerta HIGH — notificacion Telegram sin crear incidente."""
    print(f"\n{C.BOLD}{C.YELLOW}[RAMA 1] Alerta HIGH — solo notificacion{C.RESET}")
    print(f"{C.GRAY}Espera: Telegram con alerta HIGH, sin incidente nuevo{C.RESET}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")
    payload = build_payload(
        "file_integrity", "91.189.114.8", "admin", "high",
        "Archivo critico modificado — test rama 1",
        attempt_count=1,
    )
    return send_alert(payload, stats=stats)


def rama2_alerta_descartada(stats=None):
    """Rama 2: alerta LOW — se registra en DB pero no genera notificación."""
    print(f"\n{C.BOLD}{C.BLUE}[RAMA 2] Alerta LOW — registrada sin notificacion{C.RESET}")
    print(f"{C.GRAY}Espera: webhook responde 200, se guarda en DB pero NO llega nada a Telegram{C.RESET}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")
    payload = build_payload(
        "sql_injection", "10.10.10.2", "user", "low",
        "SQL injection detectado — test rama 2",
        attempt_count=1,
    )
    ok = send_alert(payload, stats=stats)
    if ok:
        print(f"  {C.YELLOW}-> Verificar que NO llegue notificacion a Telegram{C.RESET}")
    return ok


def rama3_nuevo_incidente(stats=None):
    """Rama 3: 6 alertas CRITICAL del mismo IP — crea incidente + enforce block."""
    print(f"\n{C.BOLD}{C.RED}[RAMA 3] Nuevo incidente + Enforce Block{C.RESET}")
    print(f"{C.GRAY}IP de prueba: {RAMA_TEST_IP} (6 alertas criticas){C.RESET}")
    print(f"{C.GRAY}Espera: incidente creado, IP bloqueada, notificacion de bloqueo{C.RESET}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")
    all_ok = True
    for attempt in range(1, 7):
        payload = build_payload(
            "ssh_bruteforce", RAMA_TEST_IP, "root", "critical",
            f"Failed password for root from {RAMA_TEST_IP} port 22 ssh2",
            attempt_count=attempt,
        )
        if not send_alert(payload, stats=stats):
            all_ok = False
        time.sleep(1)
    print(f"\n{C.GREEN}6 alertas enviadas — revisar Telegram e ip_blacklist{C.RESET}")
    return all_ok


def rama4_reincidencia(stats=None):
    """Rama 4: alerta del mismo IP con incidente ya abierto — alerta de reincidencia."""
    print(f"\n{C.BOLD}{C.YELLOW}[RAMA 4] IP Reincidente{C.RESET}")
    print(f"{C.GRAY}IP de prueba: {RAMA_TEST_IP} (debe tener incidente abierto de Rama 3){C.RESET}")
    print(f"{C.GRAY}Espera: alerta de reincidencia en Telegram, sin crear nuevo incidente{C.RESET}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")
    payload = build_payload(
        "ssh_bruteforce", RAMA_TEST_IP, "root", "critical",
        f"Reincidencia detectada desde {RAMA_TEST_IP}",
        attempt_count=9,
    )
    return send_alert(payload, stats=stats)


def rama5_password_spraying_workflow(stats=None):
    """Rama 5: 6 IPs distintas atacando el mismo usuario — detecta password spraying."""
    user = "admin"
    ips = ["103.140.187.60", "80.94.95.116", "185.220.101.42", "91.240.118.172", "178.128.95.10", "45.33.32.156"]
    print(f"\n{C.BOLD}{C.RED}[RAMA 5] Password Spraying{C.RESET}")
    print(f"{C.GRAY}6 IPs distintas -> usuario: {user}{C.RESET}")
    print(f"{C.GRAY}Espera: alertas individuales + mensaje PASSWORD SPRAYING DETECTADO{C.RESET}")
    print(f"{C.GRAY}{'-' * 65}{C.RESET}")
    all_ok = True
    for ip in ips:
        payload = build_payload(
            "password_spraying", ip, user, "critical",
            f"Failed password for {user} from {ip} — spraying test",
            attempt_count=2,
        )
        if not send_alert(payload, stats=stats):
            all_ok = False
        time.sleep(1)
    print(f"\n{C.GREEN}Password spraying completado — revisar Telegram{C.RESET}")
    return all_ok


def rama3_limpiar():
    """Limpia los datos de prueba de la Rama 3 en la DB."""
    import subprocess
    cmd = (
        "docker exec siem_postgres psql -U siem -d siem -c \""
        f"DELETE FROM playbook_runs WHERE alert_id IN (SELECT id FROM alerts WHERE src_ip='{RAMA_TEST_IP}');"
        f"DELETE FROM ip_blacklist WHERE ip='{RAMA_TEST_IP}';"
        f"DELETE FROM alerts WHERE src_ip='{RAMA_TEST_IP}';"
        f"DELETE FROM incidents WHERE src_ip='{RAMA_TEST_IP}';\""
    )
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"  {C.GREEN}DB limpiada para IP {RAMA_TEST_IP}{C.RESET}")
    else:
        print(f"  {C.RED}Error limpiando DB: {result.stderr}{C.RESET}")


# ============================================
# MENU INTERACTIVO
# ============================================

def interactive_menu(stats):
    """Menu interactivo para elegir el tipo de ataque."""
    while True:
        print(f"\n{C.BOLD}{'=' * 55}")
        print(f"  SIMULADOR DE ATAQUES SIEM")
        print(f"{'=' * 55}{C.RESET}")
        print(f"  {C.RED}1.{C.RESET} SSH Brute Force (7 intentos)")
        print(f"  {C.MAGENTA}2.{C.RESET} File Integrity (FIM)")
        print(f"  {C.BLUE}3.{C.RESET} Port Scan")
        print(f"  {C.RED}4.{C.RESET} Escalacion de privilegios")
        print(f"  {C.YELLOW}5.{C.RESET} SQL Injection")
        print(f"  {C.RED}6.{C.RESET} Web Shell")
        print(f"  {C.RED}7.{C.RESET} Malware detectado")
        print(f"  {C.YELLOW}8.{C.RESET} Login sospechoso")
        print(f"  {C.CYAN}9.{C.RESET} Ataques mixtos aleatorios")
        print(f"  {C.GREEN}10.{C.RESET} Simulacion COMPLETA automatica")
        print(f"\n{C.BOLD}  --- PROBAR RAMAS DEL WORKFLOW ---{C.RESET}")
        print(f"  {C.YELLOW}R1.{C.RESET} Rama 1 — Alerta HIGH (notificacion sin incidente)")
        print(f"  {C.BLUE}R2.{C.RESET} Rama 2 — Alerta LOW (registrada sin notificacion)")
        print(f"  {C.RED}R3.{C.RESET} Rama 3 — Nuevo incidente + Enforce Block")
        print(f"  {C.YELLOW}R4.{C.RESET} Rama 4 — IP Reincidente (requiere correr R3 antes)")
        print(f"  {C.MAGENTA}R5.{C.RESET} Rama 5 — Password Spraying (6 IPs -> admin)")
        print(f"  {C.GRAY}RC.  Limpiar DB de pruebas (IP {RAMA_TEST_IP}){C.RESET}")
        print(f"  {C.GRAY}0.   Salir{C.RESET}")
        print(f"{C.BOLD}{'=' * 55}{C.RESET}")

        choice = input(f"\n  {C.BOLD}Elige una opcion:{C.RESET} ").strip().lower()

        if choice == "1":
            ssh_bruteforce(stats=stats)
        elif choice == "2":
            file_integrity(stats=stats)
        elif choice == "3":
            port_scan(stats=stats)
        elif choice == "4":
            privilege_escalation(stats=stats)
        elif choice == "5":
            sql_injection(stats=stats)
        elif choice == "6":
            web_shell(stats=stats)
        elif choice == "7":
            malware_detected(stats=stats)
        elif choice == "8":
            suspicious_login(stats=stats)
        elif choice == "9":
            amount = input("  Cuantos escenarios? (default 10): ").strip()
            mixed_attacks(count=int(amount) if amount else 10, stats=stats)
        elif choice == "10":
            full_auto_simulation(stats=stats)
        elif choice == "r1":
            rama1_alerta_high(stats=stats)
        elif choice == "r2":
            rama2_alerta_descartada(stats=stats)
        elif choice == "r3":
            rama3_nuevo_incidente(stats=stats)
        elif choice == "r4":
            rama4_reincidencia(stats=stats)
        elif choice == "r5":
            rama5_password_spraying_workflow(stats=stats)
        elif choice == "rc":
            rama3_limpiar()
        elif choice == "0":
            print(f"\n  {C.GREEN}Chau{C.RESET}")
            break
        else:
            print(f"  {C.RED}Opcion no valida{C.RESET}")


# ============================================
# CLI
# ============================================

def parse_args():
    parser = argparse.ArgumentParser(description="Simulador de ataques para SIEM")
    parser.add_argument("--auto", action="store_true", help="Simulacion automatica completa")
    parser.add_argument("--brute", action="store_true", help="Solo SSH brute force")
    parser.add_argument("--fim", action="store_true", help="Solo alerta FIM")
    parser.add_argument("--mixed", action="store_true", help="Ataques mixtos aleatorios")
    parser.add_argument("--spray", action="store_true", help="Password spraying (6 IPs -> 1 usuario)")
    parser.add_argument("--count", type=int, default=10, help="Cantidad de escenarios para --mixed")
    parser.add_argument("--seed", type=int, help="Semilla para reproducir una corrida aleatoria")
    return parser.parse_args()


def main():
    # Habilitar colores ANSI en Windows
    if sys.platform == "win32":
        os.system("")

    args = parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    stats = init_run_stats(seed=args.seed)
    logger.info("--- Sesion iniciada | Modo: %s ---",
                "auto" if args.auto else "brute" if args.brute
                else "fim" if args.fim else "mixed" if args.mixed else "menu")

    if args.auto:
        full_auto_simulation(stats=stats)
    elif args.brute:
        ssh_bruteforce(stats=stats)
    elif args.fim:
        file_integrity(stats=stats)
    elif args.mixed:
        mixed_attacks(count=args.count, stats=stats)
    elif args.spray:
        password_spraying(stats=stats)
    else:
        interactive_menu(stats)

    print_summary(stats)


if __name__ == "__main__":
    main()
