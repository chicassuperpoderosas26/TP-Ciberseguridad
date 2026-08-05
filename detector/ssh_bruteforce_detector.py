import sys
import requests
import time
from datetime import datetime, timedelta
import json

# Evita UnicodeEncodeError con los emojis de los prints cuando la consola
# de Windows no esta en UTF-8 (mismo fix ya aplicado en fim_monitor.py y
# attack_simulator.py).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Configuración
ELASTICSEARCH_URL = "http://localhost:9200"
N8N_WEBHOOK_URL = "http://localhost:5678/webhook/alert/siem"
N8N_API_KEY = "superpoderosas26"
CHECK_INTERVAL = 120  # 2 minutos en segundos
THRESHOLD = 5  # Número mínimo de intentos fallidos

def buscar_ssh_bruteforce():
    """Busca patrones de SSH brute force en Elasticsearch"""
    
    # Query para buscar intentos fallidos SSH en últimos 2 minutos
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"match": {"program": "sshd"}},
                    {"match": {"message": "Failed password"}}
                ],
                "filter": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-2m"
                        }
                    }
                }
            }
        },
        "aggs": {
            "ips_atacantes": {
                "terms": {
                    "field": "src_ip.keyword",
                    "min_doc_count": THRESHOLD
                },
                "aggs": {
                    "primer_evento": {
                        "min": {
                            "field": "@timestamp"
                        }
                    }
                }
            }
        }
    }
    
    try:
        # Consultar Elasticsearch
        response = requests.post(
            f"{ELASTICSEARCH_URL}/siem-events-*/_search",
            json=query,
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            buckets = data.get("aggregations", {}).get("ips_atacantes", {}).get("buckets", [])
            
            # Para cada IP que supere el umbral
            for bucket in buckets:
                ip = bucket["key"]
                count = bucket["doc_count"]
                primer_evento = bucket.get("primer_evento", {}).get("value_as_string")

                print(f"🚨 ALERTA: SSH Brute Force detectado desde {ip} - {count} intentos fallidos "
                      f"(primer evento real: {primer_evento})")
                enviar_alerta_n8n(ip, count, primer_evento)
        else:
            print(f"❌ Error consultando Elasticsearch: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def enviar_alerta_n8n(src_ip, event_count, event_time=None):
    """Envía alerta a n8n"""

    alerta = {
        "rule_id": "ssh_bruteforce_auto",
        "src_ip": src_ip,
        "username": "detected_automatically",
        "severity": "high",
        "event_count": event_count,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "detection_method": "automated_script",
        # Timestamp real del primer evento detectado en Elasticsearch (no el
        # momento de deteccion) - permite calcular MTTA real en n8n/Postgres.
        "event_time": event_time,
    }
    
    headers = {
        "x-siem-key": N8N_API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(N8N_WEBHOOK_URL, json=alerta, headers=headers)
        
        if response.status_code == 200:
            print(f"✅ Alerta enviada a n8n para IP {src_ip}")
        else:
            print(f"❌ Error enviando a n8n: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error enviando a n8n: {e}")

def main():
    """Loop principal"""
    print("🔍 Detector SSH Brute Force iniciado")
    print(f"📊 Umbral: {THRESHOLD} intentos fallidos")
    print(f"⏱️  Intervalo: {CHECK_INTERVAL} segundos")
    print("-" * 50)
    
    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] Ejecutando detección...")
        
        buscar_ssh_bruteforce()
        
        print(f"⏳ Esperando {CHECK_INTERVAL} segundos hasta próxima ejecución...")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()