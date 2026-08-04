import json
import os
import sys
import requests
import time
from datetime import datetime

# Evita UnicodeEncodeError con los emojis de los prints cuando la consola
# de Windows no está en UTF-8 (por ejemplo, al redirigir la salida a un archivo).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

N8N_WEBHOOK = "http://localhost:5678/webhook/alert/siem"
API_KEY = "superpoderosas26"

# Wazuh fue excluido del núcleo del sistema (ver tesis, sección 5.11: incompatibilidad
# Elasticsearch/OpenSearch). fim_monitor.py mimetiza el formato de alerta de Wazuh
# (evento syscheck) en un archivo local, y este script lo sigue como si fuera el log
# real de un agente Wazuh, sin depender de ningún contenedor.
ALERTS_LOG = os.getenv("FIM_ALERTS_LOG", os.path.join(os.path.dirname(__file__), "fim_alerts.json"))


def tail_f(path, poll_interval=1.0):
    """Sigue un archivo de texto a medida que crece, como `tail -f` pero portable."""
    while not os.path.exists(path):
        time.sleep(poll_interval)

    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(poll_interval)


def monitor_wazuh_fim():
    """Monitorea alertas FIM (generadas por fim_monitor.py) y las envía a n8n"""

    print("🔍 Monitoreando alertas FIM en tiempo real...")
    print(f"📝 Leyendo: {ALERTS_LOG}")
    print("-" * 60)

    for line in tail_f(ALERTS_LOG):
        try:
            if not line.strip():
                continue

            alert = json.loads(line.strip())
            
            # Solo procesar alertas de syscheck (FIM)
            if 'syscheck' in alert.get('data', {}):
                fim = alert['data']['syscheck']
                
                # Determinar severidad según evento
                event_type = fim.get('event', 'unknown')
                severity = 'critical' if event_type == 'deleted' else 'high'
                
                # Crear payload para n8n
                payload = {
                    "rule_id": "file_integrity",
                    "src_ip": alert.get('agent', {}).get('ip', 'localhost'),
                    "username": fim.get('uname_after', 'unknown'),
                    "severity": severity,
                    "timestamp": alert.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
                    "filepath": fim.get('path', ''),
                    "change_type": event_type,
                    "md5_after": fim.get('md5_after', ''),
                    "detection_method": "wazuh_fim"
                }
                
                # Enviar a n8n
                headers = {
                    "x-siem-key": API_KEY,
                    "Content-Type": "application/json"
                }
                
                response = requests.post(N8N_WEBHOOK, json=payload, headers=headers)
                
                if response.status_code == 200:
                    print(f"✅ FIM Alert: {fim.get('path')} - {event_type} [{severity}]")
                else:
                    print(f"❌ Error enviando alerta: {response.status_code}")
                    
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    try:
        monitor_wazuh_fim()
    except KeyboardInterrupt:
        print("\n⏹️  Monitor detenido")
