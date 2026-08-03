# -*- coding: utf-8 -*-
"""
==============================================
  MONITOR DE INTEGRIDAD DE ARCHIVOS (FIM)
  Vigila una carpeta, calcula hashes MD5/SHA256
  y escribe eventos en formato tipo Wazuh syscheck
==============================================
Uso:
  python fim_monitor.py

Genera eventos en FIM_ALERTS_LOG cada vez que un archivo dentro de
FIM_WATCH_DIR se crea, se modifica o se elimina. fim_to_n8n.py
lee ese mismo archivo y reenvía las alertas a n8n.
"""

import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone

# Evita UnicodeEncodeError con los emojis de los prints cuando la consola
# de Windows no está en UTF-8 (por ejemplo, al redirigir la salida a un archivo).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ============================================
# CONFIGURACION
# ============================================
WATCH_DIR = os.getenv("FIM_WATCH_DIR", os.path.join(tempfile.gettempdir(), "test_fim"))
ALERTS_LOG = os.getenv("FIM_ALERTS_LOG", os.path.join(os.path.dirname(__file__), "fim_alerts.json"))
CHECK_INTERVAL = int(os.getenv("FIM_CHECK_INTERVAL", "10"))  # segundos
AGENT_IP = os.getenv("FIM_AGENT_IP", "127.0.0.1")


def utc_now():
    """Timestamp UTC real en formato ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_file(path):
    """Calcula MD5 y SHA256 de un archivo."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def scan_dir():
    """Devuelve {ruta_absoluta: (md5, sha256)} para cada archivo en WATCH_DIR."""
    state = {}
    for entry in os.listdir(WATCH_DIR):
        path = os.path.join(WATCH_DIR, entry)
        if os.path.isfile(path):
            try:
                state[path] = hash_file(path)
            except OSError:
                # Archivo en uso o borrado justo durante el escaneo
                continue
    return state


def write_alert(path, event, md5_after=""):
    """Escribe una línea de alerta en formato tipo Wazuh syscheck en ALERTS_LOG."""
    alert = {
        "timestamp": utc_now(),
        "agent": {"ip": AGENT_IP},
        "data": {
            "syscheck": {
                "path": path,
                "event": event,
                "uname_after": os.getenv("USERNAME", os.getenv("USER", "system")),
                "md5_after": md5_after,
            }
        },
    }
    with open(ALERTS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")


def monitor_loop():
    """Bucle principal: compara el estado de la carpeta entre ciclos."""
    os.makedirs(WATCH_DIR, exist_ok=True)
    # Reinicia el log de alertas al arrancar para no reprocesar eventos viejos
    open(ALERTS_LOG, "w", encoding="utf-8").close()

    print("🔍 Monitor de integridad de archivos (FIM) iniciado")
    print(f"📁 Carpeta vigilada: {WATCH_DIR}")
    print(f"📝 Log de alertas:   {ALERTS_LOG}")
    print(f"⏱️  Intervalo: {CHECK_INTERVAL} segundos")
    print("-" * 60)

    previous_state = scan_dir()

    while True:
        time.sleep(CHECK_INTERVAL)
        current_state = scan_dir()

        for path, (md5, _sha256) in current_state.items():
            if path not in previous_state:
                print(f"🆕 Archivo creado: {path}")
                write_alert(path, "added", md5_after=md5)
            elif previous_state[path][0] != md5:
                print(f"✏️  Archivo modificado: {path}")
                write_alert(path, "modified", md5_after=md5)

        for path in previous_state:
            if path not in current_state:
                print(f"🗑️  Archivo eliminado: {path}")
                write_alert(path, "deleted")

        previous_state = current_state


if __name__ == "__main__":
    try:
        monitor_loop()
    except KeyboardInterrupt:
        print("\n⏹️  Monitor detenido")
