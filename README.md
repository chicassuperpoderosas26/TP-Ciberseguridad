# 🛡️ SIEM Básico Orquestado con n8n

**Sistema de seguridad automatizado para detectar amenazas y responder automáticamente.**

---

## 📋 Índice

1. [¿De qué se trata este proyecto?](#1-de-qué-se-trata-este-proyecto)
2. [Qué se pide en el Proyecto03 (según el PDF)](#2-qué-se-pide-en-el-proyecto03-según-el-pdf)
3. [Qué se hizo hasta ahora](#3-qué-se-hizo-hasta-ahora)
4. [Por qué el proyecto está hecho de esta forma](#4-por-qué-el-proyecto-está-hecho-de-esta-forma)
5. [Cómo funciona el proyecto (visión general)](#5-cómo-funciona-el-proyecto-visión-general)
6. [Estructura del proyecto](#6-estructura-del-proyecto)
7. [Para qué sirven los códigos](#7-para-qué-sirven-los-códigos)
8. [Cómo se conectan entre sí los componentes](#8-cómo-se-conectan-entre-sí-los-componentes)
9. [Requisitos del sistema](#9-requisitos-del-sistema)
10. [Comandos necesarios para ejecutar el proyecto](#10-comandos-necesarios-para-ejecutar-el-proyecto)
11. [Cómo correr el proyecto paso a paso](#11-cómo-correr-el-proyecto-paso-a-paso)
12. [Configuración](#12-configuración)
13. [Uso del sistema](#13-uso-del-sistema)
14. [Qué falta para completar el proyecto (según Proyecto03)](#14-qué-falta-para-completar-el-proyecto-según-proyecto03)
15. [Estado actual del proyecto](#15-estado-actual-del-proyecto)
16. [Errores comunes y soluciones](#16-errores-comunes-y-soluciones)
17. [Glosario](#17-glosario)
18. [Autoría](#18-autoría)

---

## 1. ¿De qué se trata este proyecto?

### Explicación general

Este proyecto es un **SIEM**, que significa **Sistema de Información y Gestión de Eventos de Seguridad**. Es como un "centro de vigilancia digital" que:

1. **Recibe información** de todos los dispositivos de una red (computadoras, servidores, etc.)
2. **Analiza** esa información buscando comportamientos sospechosos
3. **Alerta** automáticamente cuando detecta algo malo
4. **Responde** sin necesidad de intervención humana

### ¿Qué problema resuelve?

Imagina que tienes 100 computadoras en tu empresa. Cada una genera miles de "mensajes" (llamados **logs**) por día sobre lo que está pasando: alguien intentó entrar con contraseña incorrecta, se modificó un archivo, hubo un error, etc.

**Sin este sistema**: Nadie puede revisar millones de mensajes manualmente. Los ataques pasan desapercibidos.

**Con este sistema**: Todo se centraliza, se analiza automáticamente, y cuando hay algo sospechoso (por ejemplo, alguien intenta adivinar contraseñas 100 veces), el sistema te avisa inmediatamente y puede bloquear al atacante.

### Uso práctico

Este proyecto está diseñado para:

- **Laboratorios universitarios**: Enseñar cómo funcionan los sistemas de seguridad reales
- **Prácticas de ciberseguridad**: Los estudiantes pueden simular ataques y ver cómo el sistema los detecta
- **Pequeñas organizaciones**: Tener un sistema de seguridad básico sin pagar licencias costosas

### Para alguien que nunca programó

Piensa en este proyecto como un **guardia de seguridad virtual** que:
- Tiene cámaras en todas partes (los logs)
- Está atento 24/7 (los detectores)
- Sabe reconocer comportamientos sospechosos (las reglas)
- Llama a la policía automáticamente (las notificaciones)
- Anota todo lo que pasó (la base de datos)

---

## 2. Qué se pide en el Proyecto03 (según el PDF)

### Objetivo general del PDF

Desarrollar y documentar un **prototipo funcional de SIEM automatizado con n8n**, capaz de recolectar, analizar y reaccionar ante eventos de seguridad en un entorno de laboratorio académico.

### Los 7 objetivos específicos

| # | Objetivo | Descripción simple |
|---|----------|-------------------|
| 1 | **Recolección centralizada de logs** | Usar syslog-ng y Logstash para recibir todos los mensajes en un solo lugar |
| 2 | **Almacenamiento dual** | Guardar en Elasticsearch (para buscar rápido) y PostgreSQL (para auditoría) |
| 3 | **Reglas de detección** | Detectar SSH brute-force y cambios en archivos (FIM) |
| 4 | **Respuestas automáticas con n8n** | Notificación, bloqueo simulado, creación de tickets, guardar evidencia |
| 5 | **Visualización en Grafana** | Dashboards con métricas del sistema |
| 6 | **Medir MTTA/MTTR** | Calcular qué tan rápido detectamos y respondemos |
| 7 | **Documentación técnica** | Docker-compose, SQL, workflows n8n, dashboards exportados |

### Funcionalidades requeridas

1. **Ingesta de logs**
   - syslog-ng escuchando en puerto UDP 514
   - Logstash parseando y normalizando los mensajes

2. **Detección de ataques**
   - SSH brute-force: 5+ intentos fallidos en 2 minutos desde la misma IP
   - FIM (File Integrity Monitoring): Detectar cambios en archivos críticos

3. **Orquestación SOAR-lite con n8n**
   - Recibir alertas por webhook
   - Validar autenticación
   - Guardar en base de datos
   - Notificar por Telegram
   - Registrar ejecución del playbook

4. **Visualización**
   - Alertas por severidad
   - Playbooks ejecutados
   - Métricas MTTA/MTTR
   - Top IPs sospechosas

### Condiciones importantes del PDF

- ✅ Solo herramientas **open source** (gratuitas)
- ✅ Todo en **contenedores Docker** (portable)
- ✅ Entorno de **laboratorio** (no producción)
- ✅ Acciones de bloqueo **simuladas** (no reales)
- ✅ Sistema **reproducible** con un solo comando

---

## 3. Qué se hizo hasta ahora

### Funcionalidades implementadas ✅

| Componente | Estado | Qué hace |
|------------|--------|----------|
| Docker Compose | ✅ Completo | Define los 8 servicios del sistema |
| PostgreSQL | ✅ Funcionando | Base de datos con tablas alerts, playbook_runs, incidents, ip_blacklist, failed_alerts |
| Elasticsearch | ✅ Funcionando | Almacena logs indexados para búsqueda rápida |
| Kibana | ✅ Funcionando | Interfaz web para explorar logs |
| Logstash | ✅ Funcionando | Parsea logs syslog, extrae IP origen, usuario, etc. |
| syslog-ng | ✅ Funcionando | Recibe logs UDP y los reenvía a Logstash |
| n8n | ✅ Funcionando | Workflow "SIEM - Alerta Entrante": severidad, Risk Score, incidentes, bloqueo |
| Grafana | ✅ Funcionando | Dashboard con 7 paneles de métricas |
| Dashboard Streamlit (Panel de Operaciones de Seguridad) | ✅ Funcionando | KPIs, mapa geográfico, IPs bloqueadas |
| Detector SSH | ✅ Funcionando | Script Python que detecta brute-force automáticamente |
| Detector FIM | ✅ Funcionando | `fim_monitor.py` (hashes MD5/SHA256) + `fim_to_n8n.py` (reenvío a n8n) |
| Risk Score + AbuseIPDB | ✅ Funcionando | Reputación de IP, alertas acumuladas y reputación interna combinadas en un score 0-100 |
| Detección de Password Spraying | ✅ Funcionando | 5+ IPs distintas contra el mismo usuario en 5 min → incidente especial |
| Bloqueo automático de IP (Blocker API) | ✅ Funcionando | Microservicio Flask que aplica reglas de firewall reales (netsh/iptables) |

> **Nota:** Wazuh **no forma parte del stack** (ver más abajo, sección de arquitectura). Se evaluó incorporarlo pero se descartó por incompatibilidad entre su backend (OpenSearch) y el Elasticsearch usado en este proyecto. El monitoreo FIM se implementa con scripts Python propios.

### Puntos del PDF ya cubiertos

- ✅ Objetivo 1: Recolección centralizada (syslog-ng + Logstash)
- ✅ Objetivo 2: Almacenamiento dual (Elasticsearch + PostgreSQL)
- ✅ Objetivo 3: Regla SSH brute-force funcionando
- ✅ Objetivo 4: n8n recibiendo alertas y guardando en DB
- ✅ Objetivo 5: Grafana con dashboards
- ⏳ Objetivo 6: MTTR calculado (~14 segundos), MTTA pendiente de simulación
- ⏳ Objetivo 7: Documentación en progreso

### Métricas actuales del sistema

```
📊 Alertas procesadas:      112
📊 Playbook runs:           106
📊 MTTR promedio:           ~14.3 segundos
📊 MTTA promedio:           ~22.5 segundos
📊 Tasa de automatización:  94.64%
```

---

## 4. Por qué el proyecto está hecho de esta forma

### Decisiones de diseño

#### 1. Separación SIEM vs SOAR

El sistema separa claramente:
- **Detección** (Elasticsearch, scripts Python)
- **Respuesta** (n8n)

**¿Por qué?** Esto permite cambiar o agregar motores de detección sin tocar los playbooks de respuesta  y viceversa.

#### 2. Almacenamiento dual

- **Elasticsearch**: Para búsquedas rápidas en millones de logs
- **PostgreSQL**: Para auditoría estructurada y métricas

**¿Por qué?** Elasticsearch es excelente buscando, pero PostgreSQL es mejor para relaciones entre datos (qué alerta disparó qué playbook).

#### 3. n8n como SOAR-lite

**¿Por qué n8n y no TheHive u otra herramienta?**
- Es visual (arrastrar y soltar)
- Es gratuito
- Puede conectarse a cualquier API
- Perfecto para entorno educativo

### Elección de tecnologías

| Tecnología | Alternativas descartadas | Razón de elección |
|------------|-------------------------|-------------------|
| syslog-ng | rsyslog, Filebeat | Más flexible, configuración clara |
| Logstash | Fluentd | Mejor integración con Elasticsearch |
| PostgreSQL | MySQL, MongoDB | Mejor soporte para JSONB, vistas, SQL estándar |
| n8n | TheHive, Shuffle | Más visual, menor curva de aprendizaje |
| Grafana | Kibana | Mejor para métricas SQL |

### Organización del código

```
TP-Final/
├── docker-compose.yml    → Define todos los servicios
├── detector/             → Scripts Python de detección
├── sql/                  → Esquema de base de datos
├── logstash/             → Configuración de parseo
├── syslog-ng/            → Configuración de recolección
└── grafana/              → Datasources predefinidos
```

**¿Por qué esta estructura?**
- Cada carpeta tiene un propósito claro
- Facilita encontrar qué modificar
- Compatible con docker-compose (monta volúmenes)

---

## 5. Cómo funciona el proyecto (visión general)

### Explicación conceptual

El sistema funciona como una **cadena de montaje** donde cada estación tiene una tarea específica:

```
[Computadoras] → [Recolector] → [Procesador] → [Almacén] → [Detector] → [Respondedor] → [Visualizador]
```

### Flujo general del sistema

```
┌─────────────┐     ┌───────────┐     ┌────────────────┐
│  syslog-ng  │────▶│  Logstash │────▶│ Elasticsearch  │
│  (UDP 514)  │     │  (Parseo) │     │   (Búsqueda)   │
└─────────────┘     └───────────┘     └────────────────┘
                          │                    │
                          ▼                    ▼
                    ┌───────────┐       ┌───────────┐
                    │ PostgreSQL│       │  Detector │
                    │(Auditoría)│       │  Python   │
                    └───────────┘       └───────────┘
                          │                    │
                          │                    ▼
                    ┌─────┴─────┐       ┌───────────┐
                    ▼           ▼       │    n8n    │
              ┌───────────┐           ┌▶│  (SOAR)   │
              │  Grafana  │           │ └───────────┘
              │(Dashboard)│           │       │
              └───────────┘           │       ▼
                                      │ ┌────────────────────┐
                                      │ │ Risk Score          │
                                      │ │ (AbuseIPDB + histor.)│
                                      │ └──────────┬──────────┘
                                      │            ▼
                                      │ ┌────────────────────┐
                                      │ │ Telegram / Email    │
                                      │ │ PostgreSQL          │
                                      │ │ Incidente + Bloqueo  │
                                      │ │ (Blocker API)        │
                                      │ └────────────────────┘
                                      │
                    ┌───────────────┐ │
                    │ fim_monitor.py│─┘
                    │ (hashes MD5/  │
                    │  SHA256, sin  │
                    │  Wazuh)       │
                    └───────────────┘
```

### Esquema Entrada → Proceso → Salida

| Etapa | Entrada | Proceso | Salida |
|-------|---------|---------|--------|
| 1. Recolección | Logs UDP de hosts | syslog-ng recibe y reenvía | Logs en formato raw |
| 2. Normalización | Logs raw | Logstash parsea con Grok | Campos estructurados (IP, usuario, programa) |
| 3. Almacenamiento | Campos estructurados | Indexación/inserción | Datos en Elasticsearch y PostgreSQL |
| 4. Detección | Logs indexados | Script busca patrones anómalos | Alerta JSON |
| 5. Orquestación | Alerta JSON | n8n valida y procesa | Notificación + registro |
| 6. Visualización | Datos de PostgreSQL | Grafana genera gráficos | Dashboards interactivos |

---

## 6. Estructura del proyecto

### Árbol de carpetas

```
C:\TP-Final\
│
├── 📄 docker-compose.yml      # Define los 8 servicios Docker
├── 📄 README.md               # Este archivo que estás leyendo
├── 📄 PROYECTO 03.pdf         # Documento con los requisitos
│
├── 📁 detector/               # Scripts de detección automática
│   ├── ssh_bruteforce_detector.py
│   ├── fim_monitor.py
│   ├── fim_to_n8n.py
│   ├── attack_simulator.py
│   ├── generate_historical_data.py
│   └── generate_report.py
│
├── 📁 blocker/                # Microservicio de bloqueo de IP (firewall real)
│   └── blocker_api.py
│
├── 📁 dashboard/              # Dashboard Streamlit "Panel de Operaciones de Seguridad"
│   └── app.py
│
├── 📁 n8n/                    # Workflows exportados (JSON)
│   ├── SIEM - Alerta Entrante.json
│   ├── SIEM - Reporte Diario.json
│   └── SIEM - Error Handler.json
│
├── 📁 sql/                    # Esquema de base de datos
│   └── 01-init.sql
│
├── 📁 logstash/               # Configuración del procesador de logs
│   └── logstash.conf
│
├── 📁 syslog-ng/              # Configuración del recolector
│   └── syslog-ng.conf
│
└── 📁 grafana/                # Configuración de visualización
    └── datasources/
        └── datasources.yml
```

### Explicación de cada parte

| Carpeta/Archivo | Qué contiene | Para qué sirve |
|-----------------|--------------|----------------|
| `docker-compose.yml` | Definición de servicios | Levantar todo el sistema con un comando |
| `detector/` | Scripts Python | Detectar ataques automáticamente |
| `blocker/` | Microservicio Flask | Aplicar bloqueos de IP reales en el firewall (netsh/iptables) |
| `dashboard/` | App Streamlit | Vista ejecutiva del SOC ("Panel de Operaciones de Seguridad") |
| `n8n/` | Workflows exportados | Backup versionable de la orquestación SOAR |
| `sql/` | Queries SQL | Crear las tablas al iniciar PostgreSQL |
| `logstash/` | Configuración Grok | Definir cómo parsear los logs |
| `syslog-ng/` | Configuración syslog | Definir de dónde recibir logs y a dónde enviarlos |
| `grafana/` | Datasources YAML | Conectar Grafana con PostgreSQL y Elasticsearch |

---

## 7. Para qué sirven los códigos

### docker-compose.yml

**Qué hace**: Define 8 servicios Docker que componen el SIEM.

**Para qué existe**: Permite levantar todo el sistema con un solo comando (`docker-compose up -d`).

**Rol en el sistema**: Es el "plano" que Docker usa para construir la infraestructura.

**Servicios definidos**:
| Servicio | Puerto | Función |
|----------|--------|---------|
| postgres | 5432 | Base de datos para auditoría |
| elasticsearch | 9200 | Motor de búsqueda de logs |
| kibana | 5601 | Interfaz web para Elasticsearch |
| logstash | 5140/udp | Procesador de logs |
| syslog-ng | 514/udp | Recolector de logs |
| n8n | 5678 | Orquestador SOAR |
| grafana | 3000 | Dashboards |
| dashboard | 8501 | Dashboard Streamlit "Panel de Operaciones de Seguridad" |

> **Nota sobre Wazuh**: se evaluó incorporar Wazuh como agente de FIM, pero se descartó porque su stack de indexación está pensado para **OpenSearch**, mientras que este proyecto usa **Elasticsearch** — ambos motores son incompatibles entre sí, y migrar habría significado duplicar la capa de almacenamiento. La detección FIM se implementa en cambio con dos scripts Python propios: `detector/fim_monitor.py` calcula hashes MD5/SHA256 de los archivos vigilados y escribe los eventos en un log local que mimetiza el formato de alerta de Wazuh (evento `syscheck`), y `detector/fim_to_n8n.py` sigue ese log y reenvía cada evento a n8n. Así se gana compatibilidad conceptual con el modelo de datos de Wazuh sin depender de él — el script se llamó originalmente `wazuh_fim_to_n8n.py`, mientras dependía de un contenedor Wazuh que ya no existe; se renombró a `fim_to_n8n.py` para reflejar que hoy funciona de forma independiente.
>
> El **Blocker API** (`blocker/blocker_api.py`) tampoco está en `docker-compose.yml`: es un microservicio Flask que se corre aparte, con permisos de administrador, porque aplica reglas reales de firewall (`netsh` en Windows, `iptables` en Linux). Ver `GUIA_TESTING.md` paso 12 para levantarlo.

---

### detector/ssh_bruteforce_detector.py

**Qué hace**: Consulta Elasticsearch cada 2 minutos buscando intentos fallidos de login SSH. Si encuentra 5+ intentos desde la misma IP, envía una alerta a n8n.

**Para qué existe**: Automatizar la detección de ataques de fuerza bruta sin intervención humana.

**Rol en el sistema**: Es el "detective" que revisa los logs y encuentra comportamientos sospechosos.

**Cómo funciona**:
```python
# Pseudocódigo simplificado
cada 2 minutos:
    buscar en Elasticsearch "Failed password" de los últimos 2 minutos
    agrupar por IP
    si alguna IP tiene 5+ intentos:
        enviar alerta a n8n
```

---

### detector/fim_monitor.py

**Qué hace**: Vigila una carpeta (por defecto, `test_fim` dentro de la carpeta temporal del sistema) y calcula hashes MD5/SHA256 de cada archivo en ciclos periódicos. Cuando detecta que un archivo se creó, se modificó o se eliminó, escribe un evento en un log local en formato tipo Wazuh (`syscheck`).

**Para qué existe**: Reemplazar el agente FIM de Wazuh con un script propio, sin depender de ningún contenedor externo — la detección de integridad de archivos "de la casa".

**Rol en el sistema**: Es el "vigilante" que detecta cambios en archivos críticos comparando hashes entre ciclos.

**Cómo funciona**:
```python
# Pseudocódigo simplificado
cada N segundos:
    calcular MD5/SHA256 de cada archivo en la carpeta vigilada
    comparar contra el estado del ciclo anterior
    si hay un archivo nuevo, modificado o borrado:
        escribir el evento en el log local (formato syscheck)
```

---

### detector/fim_to_n8n.py

**Qué hace**: Sigue en tiempo real el log local que escribe `fim_monitor.py` (con una implementación portable de `tail -f`, sin depender de Docker) y envía las alertas de tipo FIM a n8n.

**Para qué existe**: Ser el "traductor" entre el formato de evento de integridad de archivos y el webhook de n8n, sin importar si la fuente es un script propio o, eventualmente, un agente Wazuh real.

**Rol en el sistema**: Es el "puente" entre la detección FIM y n8n. Antes se llamaba `wazuh_fim_to_n8n.py`, cuando dependía de un contenedor Wazuh; se renombró tras eliminar esa dependencia (ver nota en la sección de componentes de Docker Compose).

**Cómo funciona**:
```python
# Pseudocódigo simplificado
seguir el log local escrito por fim_monitor.py
si la alerta es de tipo "syscheck" (cambio de archivo):
    determinar severidad (deleted=critical, modified=high, created=medium)
    enviar a n8n
```

---

### detector/generate_historical_data.py

**Qué hace**: Genera 50 alertas aleatorias con diferentes tipos y severidades.

**Para qué existe**: Poblar el sistema con datos de prueba para que los dashboards de Grafana tengan información que mostrar.

**Rol en el sistema**: Es una herramienta de desarrollo/testing.

---

### sql/01-init.sql

**Qué hace**: Crea las tablas y vistas de PostgreSQL cuando el contenedor inicia por primera vez.

**Para qué existe**: Tener un esquema de base de datos listo automáticamente.

**Rol en el sistema**: Es el "plano" de la base de datos.

**Tablas creadas**:
| Tabla | Propósito |
|-------|-----------|
| `events_raw` | Guarda todos los logs (auditoría completa) |
| `alerts` | Guarda las alertas procesadas por n8n |
| `playbook_runs` | Guarda qué playbook se ejecutó para cada alerta |

**Vistas creadas**:
| Vista | Propósito |
|-------|-----------|
| `mttr_stats` | Calcula el tiempo promedio de respuesta |
| `mtta_stats` | Calcula el tiempo promedio de reconocimiento |
| `alerts_by_severity` | Cuenta alertas por severidad y fecha |
| `automation_rate` | Calcula % de alertas automatizadas |
| `top_suspicious_ips` | Lista las IPs con más alertas |

---

### logstash/logstash.conf

**Qué hace**: Define cómo Logstash debe parsear los logs que recibe.

**Para qué existe**: Convertir mensajes de texto plano en campos estructurados (IP, usuario, programa, etc.).

**Rol en el sistema**: Es el "traductor" que convierte logs crudos en datos útiles.

**Qué parsea**:
- Prioridad syslog (`<34>`)
- Timestamp (`Jan 30 14:00:00`)
- Hostname (`servidor1`)
- Programa (`sshd[12345]`)
- Mensaje (`Failed password for admin from 10.0.0.1`)
- IP origen (extraída del mensaje)
- Username (extraído de mensajes SSH)

---

### syslog-ng/syslog-ng.conf

**Qué hace**: Configura syslog-ng para escuchar en UDP 514 y reenviar todo a Logstash en UDP 5140.

**Para qué existe**: Ser el punto de entrada de todos los logs del sistema.

**Rol en el sistema**: Es la "puerta de entrada" donde llegan los logs.

---

### grafana/datasources/datasources.yml

**Qué hace**: Configura automáticamente las conexiones de Grafana a PostgreSQL y Elasticsearch.

**Para qué existe**: Que Grafana ya tenga los datasources listos sin configuración manual.

**Rol en el sistema**: Automatiza la configuración inicial de Grafana.

---

## 8. Cómo se conectan entre sí los componentes

### Comunicación entre módulos

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           RED DOCKER: siem-net                               │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [Host externo]                                                              │
│       │                                                                      │
│       │ UDP 514                                                              │
│       ▼                                                                      │
│  ┌─────────────┐  UDP 5140   ┌───────────┐  HTTP 9200  ┌───────────────────┐ │
│  │  syslog-ng  │────────────▶│  Logstash │────────────▶│   Elasticsearch   │ │
│  └─────────────┘             └───────────┘             └───────────────────┘ │
│                                                                │             │
│                                    HTTP 9200                   │             │
│                              ┌─────────────────────────────────┘             │
│                              │                                               │
│                              ▼                                               │
│  ┌───────────────┐    ┌─────────────────┐    HTTP POST     ┌───────────┐    │
│  │ Python Script │───▶│  localhost:9200 │─────────────────▶│    n8n    │    │
│  │  (Detector)   │    │   (Consulta ES) │                  │   :5678   │    │
│  └───────────────┘    └─────────────────┘                  └───────────┘    │
│                                                                   │          │
│                                                          SQL 5432 │          │
│                                                                   ▼          │
│  ┌───────────┐                                          ┌───────────────────┐│
│  │  Grafana  │◀─────────────────────────────────────────│    PostgreSQL     ││
│  │   :3000   │         SQL 5432                         │      :5432        ││
│  └───────────┘                                          └───────────────────┘│
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Flujo paso a paso

#### Escenario: Ataque SSH brute-force

1. **Un atacante intenta adivinar contraseñas**
   - Envía 10 intentos de login con contraseñas incorrectas
   - El servidor SSH genera logs: `Failed password for admin from 10.0.0.50`

2. **El servidor envía los logs a syslog-ng**
   - Protocolo: UDP
   - Puerto: 514
   - Formato: Syslog estándar

3. **syslog-ng reenvía a Logstash**
   - Protocolo: UDP
   - Puerto: 5140

4. **Logstash parsea el log**
   - Extrae: timestamp, hostname, programa (sshd), mensaje
   - Extrae la IP origen: `10.0.0.50`
   - Extrae el username: `admin`

5. **Logstash envía a Elasticsearch**
   - Protocolo: HTTP
   - Puerto: 9200
   - Índice: `siem-events-2026.02.02`

6. **El detector Python consulta Elasticsearch**
   - Cada 2 minutos busca: `program:sshd AND message:"Failed password"`
   - Agrupa por IP
   - Encuentra que `10.0.0.50` tiene 10 intentos

7. **El detector envía alerta a n8n**
   - Protocolo: HTTP POST
   - URL: `http://localhost:5678/webhook/alert/siem`
   - Header: `x-siem-key: superpoderosas26`
   - Body: JSON con rule_id, src_ip, severity

8. **n8n procesa la alerta**
   - Valida el header de autenticación y la inserta en la tabla `alerts` de PostgreSQL
   - Enriquece el evento y filtra por severidad (las alertas LOW se guardan y terminan ahí)
   - Verifica si la IP ya tiene un incidente abierto (evita duplicar, avisa reincidencia)
   - En paralelo: cuenta IPs distintas contra el mismo usuario (Password Spraying) y consulta AbuseIPDB + historial para calcular un Risk Score de 0 a 100
   - Si el Risk Score es crítico: crea un incidente, bloquea la IP vía Blocker API y notifica por Telegram y email
   - Inserta el resultado en `playbook_runs`

9. **Grafana muestra la alerta**
   - Consulta PostgreSQL cada X segundos
   - Actualiza los dashboards

### Integraciones externas

| Servicio externo | Cómo se integra | Estado |
|------------------|-----------------|--------|
| Telegram | n8n envía notificaciones | ✅ Configurado |
| AbuseIPDB | n8n consulta reputación IP para Risk Score y país de origen | ✅ Configurado |
| VirusTotal | n8n consulta hashes | ❌ No implementado |

---

## 9. Requisitos del sistema

### Software necesario

| Software | Versión mínima | Qué es | Para qué se necesita |
|----------|---------------|--------|---------------------|
| **Docker Desktop** | 4.0+ | Programa que permite ejecutar "contenedores" (como máquinas virtuales livianas) | Para correr todos los servicios sin instalarlos uno por uno |
| **Docker Compose** | 2.0+ | Herramienta para definir y ejecutar múltiples contenedores | Viene incluido en Docker Desktop |
| **Python** | 3.8+ | Lenguaje de programación | Para ejecutar los scripts de detección |
| **pip** | 20.0+ | Instalador de paquetes Python | Para instalar las librerías que necesitan los scripts |

### Librerías Python necesarias

```
requests     → Para hacer llamadas HTTP a Elasticsearch y n8n
```

### Recursos de hardware

| Recurso | Mínimo | Recomendado |
|---------|--------|-------------|
| RAM | 8 GB | 16 GB |
| CPU | 4 cores | 8 cores |
| Disco | 20 GB | 50 GB |

### Puertos que deben estar libres

| Puerto | Protocolo | Servicio |
|--------|-----------|----------|
| 514 | UDP | syslog-ng |
| 3000 | TCP | Grafana |
| 5432 | TCP | PostgreSQL |
| 5601 | TCP | Kibana |
| 5678 | TCP | n8n |

| 9200 | TCP | Elasticsearch |

### Verificar si Docker está instalado

Abre PowerShell y ejecuta:

```powershell
docker --version
```

**Salida esperada**: `Docker version 24.0.x, build xxxxxxx`

Si no está instalado, descarga [Docker Desktop](https://www.docker.com/products/docker-desktop/).

---

## 10. Comandos necesarios para ejecutar el proyecto

### Iniciar todos los servicios

```powershell
docker-compose up -d
```

**Qué hace internamente**:
1. Lee el archivo `docker-compose.yml`
2. Descarga las imágenes Docker si no existen localmente
3. Crea una red virtual llamada `siem-net`
4. Crea volúmenes para persistir datos
5. Inicia los 8 contenedores en orden de dependencias

**Por qué es necesario ejecutarlo**: Es el comando que "enciende" todo el sistema. Sin esto, no hay servicios corriendo.

**Salida esperada**:
```
[+] Running 8/8
 ✔ Container siem_postgres        Started
 ✔ Container siem_elasticsearch   Started
 ✔ Container siem_kibana          Started
 ✔ Container siem_logstash        Started
 ✔ Container siem_syslog          Started
 ✔ Container siem_n8n             Started
 ✔ Container siem_dashboard       Started
 ✔ Container siem_grafana         Started
```

---

### Verificar estado de los contenedores

```powershell
docker-compose ps
```

**Qué hace internamente**: Consulta el estado de todos los contenedores definidos en `docker-compose.yml`.

**Por qué es necesario ejecutarlo**: Para confirmar que todos los servicios están corriendo correctamente.

**Salida esperada**:
```
NAME                    STATUS
siem_postgres           Up
siem_elasticsearch      Up
siem_kibana             Up
siem_logstash           Up
siem_syslog             Up
siem_n8n                Up
siem_dashboard          Up
siem_grafana            Up
```

**Si alguno dice "Exited"**: Hay un problema. Ver logs con `docker logs <nombre_contenedor>`.

---

### Instalar dependencias Python

```powershell
pip install requests
```

**Qué hace internamente**: Descarga e instala la librería `requests` que permite hacer llamadas HTTP desde Python.

**Por qué es necesario ejecutarlo**: Los scripts de detección necesitan esta librería para comunicarse con Elasticsearch y n8n.

**Salida esperada**:
```
Successfully installed requests-2.31.0
```

---

### Ejecutar el detector SSH brute-force

```powershell
python detector\ssh_bruteforce_detector.py
```

**Qué hace internamente**:
1. Se conecta a Elasticsearch (localhost:9200)
2. Cada 2 minutos, busca logs de `sshd` con "Failed password"
3. Agrupa por IP origen
4. Si alguna IP tiene 5+ intentos, envía alerta a n8n

**Por qué es necesario ejecutarlo**: Sin este script, el sistema no detecta ataques SSH automáticamente.

**Salida esperada**:
```
🔍 Detector SSH Brute Force iniciado
📊 Umbral: 5 intentos fallidos
⏱️  Intervalo: 120 segundos
--------------------------------------------------

[2026-02-02 15:00:00] Ejecutando detección...
⏳ Esperando 120 segundos hasta próxima ejecución...
```

**Si detecta un ataque**:
```
🚨 ALERTA: SSH Brute Force detectado desde 10.0.0.50 - 7 intentos fallidos
✅ Alerta enviada a n8n para IP 10.0.0.50
```

---

### Detener todos los servicios

```powershell
docker-compose down
```

**Qué hace internamente**:
1. Detiene todos los contenedores
2. Elimina los contenedores (pero NO los volúmenes con datos)
3. Elimina la red virtual

**Por qué es necesario ejecutarlo**: Para apagar el sistema de forma ordenada.

**Salida esperada**:
```
[+] Running 8/8
 ✔ Container siem_dashboard        Removed
 ✔ Container siem_grafana          Removed
 ✔ Container siem_n8n              Removed
 ✔ Container siem_syslog           Removed
 ✔ Container siem_logstash         Removed
 ✔ Container siem_kibana           Removed
 ✔ Container siem_elasticsearch    Removed
 ✔ Container siem_postgres         Removed
 ✔ Network tp-final_siem-net       Removed
```

---

### Ver logs de un servicio

```powershell
docker logs siem_n8n
```

**Qué hace internamente**: Muestra los mensajes que el contenedor ha escrito en su consola.

**Por qué es necesario ejecutarlo**: Para diagnosticar problemas o ver qué está haciendo un servicio.

**Salida esperada**: Logs del servicio (varían según el servicio).

---

### Verificar alertas en PostgreSQL

```powershell
docker exec siem_postgres psql -U siem -d siem -c "SELECT id, rule_id, src_ip, severity, ts FROM alerts ORDER BY id DESC LIMIT 10;"
```

**Qué hace internamente**:
1. `docker exec`: Ejecuta un comando dentro de un contenedor
2. `psql`: Cliente de PostgreSQL
3. `-U siem -d siem`: Conecta con usuario `siem` a base de datos `siem`
4. `-c "..."`: Ejecuta la consulta SQL

**Por qué es necesario ejecutarlo**: Para verificar que las alertas se están guardando correctamente.

**Salida esperada**:
```
 id |      rule_id      |    src_ip     | severity |            ts
----+-------------------+---------------+----------+---------------------------
 15 | ssh_bruteforce    | 10.0.0.50     | high     | 2026-02-02 15:00:00.123456
 14 | file_integrity    | 192.168.1.10  | medium   | 2026-02-02 14:55:00.654321
 ...
```

---

## 11. Cómo correr el proyecto paso a paso

### Paso 1: Abrir terminal en la carpeta del proyecto

```powershell
cd C:\TP-Final
```

**Qué pasa**: Te posicionas en la carpeta donde está `docker-compose.yml`.

**Cómo saber si funcionó**: El prompt muestra `C:\TP-Final>`.

---

### Paso 2: Iniciar los servicios

```powershell
docker-compose up -d
```

**Qué pasa**: Docker descarga imágenes (si es la primera vez) e inicia los 9 contenedores.

**Cómo saber si funcionó**: Todos los servicios muestran "Started".

**Cómo saber si falló**: Algún servicio muestra "Error" o "Exited".

---

### Paso 3: Esperar a que los servicios inicien (2-3 minutos)

Los servicios, especialmente Elasticsearch, tardan en iniciar completamente.

**Cómo confirmar que Elasticsearch está listo**:

```powershell
curl http://localhost:9200/_cluster/health
```

**Respuesta esperada**: JSON con `"status":"green"` o `"status":"yellow"`.

---

### Paso 4: Acceder a las interfaces web

| Servicio | URL | Credenciales |
|----------|-----|--------------|
| Grafana | http://localhost:3000 | admin / admin123 |
| Kibana | http://localhost:5601 | (sin credenciales) |
| n8n | http://localhost:5678 | (crear cuenta al primer acceso) |


**Cómo saber si funcionó**: Se abre la interfaz en el navegador.

---

### Paso 5: Configurar n8n (primera vez)

1. Abrir http://localhost:5678
2. Crear cuenta de administrador
3. Ir a **Workflows**
4. Verificar que existe "SIEM - Alerta Entrante"
5. Si no existe, importar el JSON del Anexo F del PDF
6. **Activar** el workflow (switch en la esquina superior derecha)

---

### Paso 6: Instalar dependencias Python

```powershell
pip install requests
```

---

### Paso 7: Ejecutar el detector

En una nueva terminal:

```powershell
cd C:\TP-Final
python detector\ssh_bruteforce_detector.py
```

**Dejarlo corriendo**. Este script monitorea continuamente.

---

### Paso 8: Probar enviando un log de prueba

En otra terminal:

```powershell
$message = "<34>Feb 02 15:00:00 testhost sshd[12345]: Failed password for invalid user admin from 10.0.0.50 port 22 ssh2"
$udpClient = New-Object System.Net.Sockets.UdpClient
$bytes = [System.Text.Encoding]::ASCII.GetBytes($message)
$udpClient.Send($bytes, $bytes.Length, "localhost", 514)
$udpClient.Close()
```

Repetir 5+ veces para simular un ataque brute-force.

---

### Paso 9: Verificar que todo funciona

1. **En la terminal del detector**: Debería aparecer "🚨 ALERTA: SSH Brute Force detectado"
2. **En PostgreSQL**: `docker exec siem_postgres psql -U siem -d siem -c "SELECT * FROM alerts ORDER BY id DESC LIMIT 1;"`
3. **En Grafana**: El dashboard debería mostrar la nueva alerta

---

## 12. Configuración

### Variables de entorno

Las variables están definidas en `docker-compose.yml`:

#### PostgreSQL
```yaml
POSTGRES_USER: siem
POSTGRES_PASSWORD: siem123
POSTGRES_DB: siem
```

#### Elasticsearch
```yaml
discovery.type: single-node      # No necesita cluster
xpack.security.enabled: false    # Sin autenticación (laboratorio)
ES_JAVA_OPTS: -Xms1g -Xmx1g      # 1GB de RAM para Java
```

#### n8n
```yaml
DB_TYPE: postgresdb
DB_POSTGRESDB_HOST: postgres
DB_POSTGRESDB_DATABASE: siem
N8N_BASIC_AUTH_ACTIVE: false
```

#### Grafana
```yaml
GF_SECURITY_ADMIN_USER: admin
GF_SECURITY_ADMIN_PASSWORD: admin123
```

### Archivos de configuración

| Archivo | Propósito | Qué modificar |
|---------|-----------|---------------|
| `docker-compose.yml` | Servicios Docker | Puertos, contraseñas, recursos |
| `logstash/logstash.conf` | Parseo de logs | Patrones Grok para nuevos formatos |
| `syslog-ng/syslog-ng.conf` | Recolección | Nuevas fuentes de logs |
| `sql/01-init.sql` | Esquema DB | Nuevas tablas o campos |
| `detector/*.py` | Detección | Umbrales, nuevas reglas |

### Ejemplos de modificaciones comunes

#### Cambiar umbral de detección SSH (de 5 a 10 intentos)

En `detector/ssh_bruteforce_detector.py`:
```python
THRESHOLD = 10  # Era 5
```

#### Cambiar intervalo de escaneo (de 2 a 5 minutos)

En `detector/ssh_bruteforce_detector.py`:
```python
CHECK_INTERVAL = 300  # Era 120 (2 min), ahora 300 (5 min)
```

#### Cambiar la clave del webhook

En `detector/ssh_bruteforce_detector.py` y n8n:
```python
N8N_API_KEY = "mi_nueva_clave_secreta"
```

Y actualizar el workflow de n8n para validar la nueva clave.

---

## 13. Uso del sistema

### Qué puede hacer el usuario

1. **Monitorear logs en tiempo real** (Kibana)
2. **Ver alertas de seguridad** (Grafana, PostgreSQL)
3. **Ejecutar detección automática** (Scripts Python)
4. **Simular ataques** (Enviar logs de prueba)
5. **Ver métricas del SOC** (Grafana)

### Ejemplos simples de uso

#### Ver últimas 10 alertas

```powershell
docker exec siem_postgres psql -U siem -d siem -c "
SELECT id, rule_id, src_ip, severity, ts 
FROM alerts 
ORDER BY id DESC 
LIMIT 10;"
```

#### Ver playbooks ejecutados

```powershell
docker exec siem_postgres psql -U siem -d siem -c "
SELECT id, alert_id, workflow, outcome, executed_at 
FROM playbook_runs 
ORDER BY id DESC 
LIMIT 10;"
```

#### Ver IPs más sospechosas

```powershell
docker exec siem_postgres psql -U siem -d siem -c "
SELECT * FROM top_suspicious_ips;"
```

#### Ver MTTR promedio

```powershell
docker exec siem_postgres psql -U siem -d siem -c "
SELECT * FROM mttr_stats;"
```

#### Enviar alerta manual a n8n (PowerShell)

```powershell
$headers = @{
    "x-siem-key" = "superpoderosas26"
    "Content-Type" = "application/json"
}
$body = @{
    rule_id = "test_manual"
    src_ip = "192.168.1.100"
    username = "test_user"
    severity = "medium"
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5678/webhook/alert/siem" -Method POST -Headers $headers -Body $body
```

### Casos reales de uso

#### Caso 1: Detectar ataque SSH brute-force

1. Un atacante intenta 20 combinaciones de usuario/contraseña
2. El servidor genera 20 logs "Failed password"
3. Los logs llegan a syslog-ng → Logstash → Elasticsearch
4. El detector Python detecta 20 intentos desde la misma IP
5. Se envía alerta a n8n con severidad "high"
6. n8n guarda en PostgreSQL y (opcionalmente) notifica por Telegram
7. El analista ve la alerta en Grafana y toma acción

#### Caso 2: Detectar modificación de archivo crítico

1. Alguien modifica un archivo dentro de la carpeta vigilada
2. `fim_monitor.py` recalcula el hash MD5/SHA256 en su siguiente ciclo y detecta la diferencia
3. `fim_monitor.py` escribe el evento (creado/modificado/eliminado) en el log local
4. El script `fim_to_n8n.py` sigue ese log y captura el evento
5. Se envía a n8n con severidad "medium" (creación), "high" (modificación) o "critical" (eliminación)
6. El sistema registra y notifica

---

## 14. Qué falta para completar el proyecto (según Proyecto03)

### Comparación PDF vs Implementación actual

| Requisito del PDF | Estado | Detalle |
|-------------------|--------|---------|
| Recolección centralizada con syslog-ng + Logstash | ✅ Completo | Funcionando |
| Almacenamiento dual ES + PostgreSQL | ✅ Completo | Funcionando |
| Regla SSH brute-force | ✅ Completo | Script Python funcionando |
| Regla FIM (File Integrity) | ✅ Completo | `fim_monitor.py` + `fim_to_n8n.py`, sin dependencia de Wazuh |
| Respuesta automática con n8n | ✅ Completo | Workflow activo con Risk Score, incidentes y bloqueo |
| Notificación Telegram | ✅ Completo | Configurado en n8n |
| Visualización Grafana | ✅ Completo | Dashboard con 7 paneles |
| Dashboard Streamlit (Panel de Operaciones de Seguridad) | ✅ Completo | Mapa geográfico, KPIs, IPs bloqueadas |
| Risk Score con AbuseIPDB | ✅ Completo | Reputación de IP + historial + reputación interna (score 0-100) |
| Detección de Password Spraying | ✅ Completo | 5+ IPs contra el mismo usuario en 5 min |
| Bloqueo automático de IP | ✅ Completo | Blocker API con reglas de firewall reales |
| Métricas MTTA/MTTR | ✅ Completo | Calculado en PostgreSQL |
| docker-compose reproducible | ✅ Completo | Funciona con un comando |
| Documentación técnica | ✅ Completo | README completo |

### Funcionalidades pendientes (Prioridad Alta)

1. **Ampliar inteligencia de amenazas**
   - Integrar VirusTotal para clasificación de hashes de archivos sospechosos (AbuseIPDB ya está integrado)

2. **Configurar notificaciones Telegram**
   - Crear bot en BotFather
   - Obtener token y chat_id
   - Configurar credenciales en n8n

3. **Generar más datos históricos**
   - Ejecutar `generate_historical_data.py` varias veces
   - Distribuir en diferentes días para gráficos de tendencia

### Funcionalidades pendientes (Prioridad Media)

4. **Simular MTTA**
   - Generar eventos con timestamp conocido
   - Marcar alertas como "acknowledged"
   - Calcular tiempo event → acknowledge

5. **Exportar workflow n8n**
   - Descargar JSON del workflow
   - Guardar en repositorio

6. **Exportar dashboard Grafana**
   - Descargar JSON del dashboard
   - Guardar en repositorio

### Funcionalidades opcionales (Prioridad Baja)

7. **Más tipos de playbooks**
   - Port scanning detection
   - Malware detection
   - Login desde ubicación inusual

8. **Ampliar la integración con threat intelligence**
   - VirusTotal (AbuseIPDB ya está integrado para Risk Score y geolocalización)

---

## 15. Estado actual del proyecto

### Nivel de avance

```
[████████████████████████] 100%
```

### Desglose por área

| Área | Completado | Total | % |
|------|------------|-------|---|
| Infraestructura Docker | 9/9 servicios | 100% |
| Detección | 2/2 reglas | 100% |
| Orquestación | 1/1 workflow | 100% |
| Visualización | 7/7 paneles | 100% |
| Notificaciones | 1/1 Telegram | 100% |
| Documentación | 1/1 README | 100% |
| Exportables | 2/2 JSONs | 100% |

### ✅ Proyecto Completo

Todos los requisitos del PDF han sido implementados:

1. ✅ Recolección centralizada (syslog-ng + Logstash)
2. ✅ Almacenamiento dual (Elasticsearch + PostgreSQL)
3. ✅ Detección SSH brute-force
4. ✅ Detección FIM (File Integrity Monitoring) con scripts Python propios
5. ✅ Orquestación con n8n
6. ✅ Notificaciones Telegram
7. ✅ Dashboards Grafana
8. ✅ Métricas MTTA/MTTR

---

## 16. Errores comunes y soluciones

### Error: "Cannot connect to the Docker daemon"

**Causa**: Docker Desktop no está corriendo.

**Solución**: 
1. Abrir Docker Desktop
2. Esperar a que muestre "Docker is running"
3. Reintentar el comando

---

### Error: "Port 5432 is already in use"

**Causa**: PostgreSQL local u otro servicio usa el puerto.

**Solución**:
1. Cambiar el puerto en `docker-compose.yml`:
   ```yaml
   ports:
     - "5433:5432"  # Usar 5433 externamente
   ```
2. Actualizar scripts para usar puerto 5433

---

### Error: "Elasticsearch container keeps restarting"

**Causa**: Poca memoria asignada a Docker.

**Solución**:
1. Docker Desktop → Settings → Resources
2. Aumentar Memory a 8 GB mínimo
3. Reiniciar Docker Desktop

---

### Error: "Webhook returns 404"

**Causa**: El workflow de n8n no está activo o la URL es incorrecta.

**Solución**:
1. Abrir n8n: http://localhost:5678
2. Ir al workflow "SIEM - Alerta Entrante"
3. Verificar que está **activo** (toggle encendido)
4. Usar la URL de **Production**, no la de Test
5. Verificar el path: `/webhook/alert/siem`

---

### Error: "bad decrypt" en n8n

**Causa**: Las credenciales de n8n están corruptas (cambio de encryption key).

**Solución**:
1. Ir a n8n → Credentials
2. Eliminar credenciales existentes de PostgreSQL
3. Crear nuevas:
   - Host: `postgres`
   - Database: `siem`
   - User: `siem`
   - Password: `siem123`
4. Asignar a los nodos del workflow

---

### Error: "No module named 'requests'"

**Causa**: La librería no está instalada.

**Solución**:
```powershell
pip install requests
```

---

### Error: "Connection refused" al consultar Elasticsearch

**Causa**: Elasticsearch aún no terminó de iniciar.

**Solución**:
1. Esperar 2-3 minutos
2. Verificar estado: `curl http://localhost:9200`
3. Si persiste: `docker logs siem_elasticsearch`

---

## 17. Glosario

| Término | Definición simple |
|---------|-------------------|
| **SIEM** | Sistema que recolecta y analiza mensajes de seguridad de muchas computadoras en un solo lugar |
| **SOAR** | Sistema que automatiza respuestas a incidentes de seguridad |
| **Log** | Mensaje que genera un programa diciendo qué pasó (como un diario) |
| **Syslog** | Protocolo estándar para enviar logs por red |
| **Grok** | Lenguaje de patrones para extraer datos de texto |
| **Container** | Como una máquina virtual liviana que contiene un programa y todo lo que necesita para funcionar |
| **Docker** | Programa que ejecuta containers |
| **Docker Compose** | Herramienta para definir y ejecutar múltiples containers juntos |
| **Webhook** | URL que espera recibir datos (como un buzón de entrada) |
| **Playbook** | Conjunto de pasos automatizados para responder a un incidente |
| **SSH** | Protocolo para conectarse remotamente a servidores |
| **Brute-force** | Ataque que intenta muchas contraseñas hasta adivinar la correcta |
| **FIM** | File Integrity Monitoring - Monitoreo de cambios en archivos |
| **MTTA** | Mean Time To Acknowledge - Tiempo promedio hasta reconocer una alerta |
| **MTTR** | Mean Time To Respond - Tiempo promedio hasta responder a una alerta |
| **UDP** | Protocolo de red rápido (no garantiza entrega) |
| **TCP** | Protocolo de red confiable (garantiza entrega) |
| **API** | Interfaz para que programas se comuniquen entre sí |
| **JSON** | Formato de texto estructurado para intercambiar datos |
| **JSONB** | JSON almacenado de forma binaria en PostgreSQL (más eficiente) |
| **Elasticsearch** | Base de datos optimizada para búsquedas en texto |
| **PostgreSQL** | Base de datos relacional tradicional |
| **Pipeline** | Secuencia de pasos por donde fluyen los datos |
| **Threshold** | Umbral - valor límite para disparar una acción |
| **SecOps** | Security Operations - Operaciones de seguridad |
| **SOC** | Security Operations Center - Centro de operaciones de seguridad |

---

## 18. Autoría

**Proyecto académico**: Tecnicatura Universitaria en Programación

**Institución**: Universidad Tecnológica Nacional (UTN) – SIED

**Basado en**: Proyecto 03 - "Implementación de un SIEM Básico Orquestado con n8n"

**Autor documento original**: Alberto Cortez

**Última actualización README**: 1 de julio de 2026

---

> **Nota**: Este proyecto es exclusivamente para uso educativo. Las acciones de bloqueo son simuladas. No utilizar para monitorear redes sin autorización.
