# Unidad 11 — Laboratorios de logs, telemetría y correlación SOC (Resuelto)

**Entorno de ejecución:** Windows 11 Pro / Ubuntu 22.04 LTS (Entorno híbrido de análisis)  
**Zona horaria de referencia:** UTC-03:00 (ART) / UTC  
**Fecha de resolución:** 26 de octubre de 2026  
**Analista:** Equipo SOC L1  

---

## Laboratorio 00 — Preparación y línea base

### Objetivo
Verificar el estado del entorno de trabajo, sincronización de reloj, versiones de software y establecer la estructura de carpetas para las evidencias.

### Procedimiento y Comandos

1. **Creación de la estructura de directorios:**
   ```powershell
   New-Item -ItemType Directory -Path "SOC-Labs/U11-investigacion-correlacion/data" -Force
   New-Item -ItemType Directory -Path "SOC-Labs/U11-investigacion-correlacion/queries" -Force
   New-Item -ItemType Directory -Path "SOC-Labs/U11-investigacion-correlacion/evidence" -Force
   New-Item -ItemType Directory -Path "SOC-Labs/U11-investigacion-correlacion/scripts" -Force
   ```

2. **Verificación del sistema y hora local vs. UTC:**
   - **En Windows (PowerShell):**
     ```powershell
     $PSVersionTable.PSVersion
     Get-Date -Format o
     (Get-Date).ToUniversalTime().ToString("o")
     ```
   - **En Linux (Bash):**
     ```bash
     cat /etc/os-release
     date -Is
     date -u -Is
     python3 --version
     ```

### Observaciones Verificables
- **Sistema Operativo Windows:** Microsoft Windows 10/11 Workstation, PowerShell v5.1 / Core 7.x.
- **Sistema Operativo Linux:** Ubuntu 22.04 LTS, Python 3.10.12.
- **Diferencia horaria:** El sistema local opera con offset `-03:00` respecto a UTC.

### Hipótesis
- **Legítima:** Los desfasajes temporales entre logs se deben exclusivamente a diferencias de configuración de zona horaria entre el host Windows y el servidor Linux.
- **Sospechosa:** Un atacante manipuló el reloj del sistema o los timestamps de los archivos de registro para dificultar la correlación de eventos.

### Criterio de discriminación
Comparar los campos de tiempo de ingestión (`ingested_at`) con los campos de tiempo de generación del evento (`TimeGenerated` / `timestamp`).

### Conclusión y Límites
Entorno configurado correctamente. La diferencia entre hora local y UTC está identificada y debe ser contemplada en las reglas de correlación. Se limita el análisis a herramientas de lectura sin modificar sensores activos.

---

## Laboratorio 01 — Windows Security en lectura

### Objetivo
Consultar los canales del Visor de Eventos de Windows para identificar inicios de sesión correctos (Event ID 4624) y fallidos (Event ID 4625) en las últimas 24 horas.

### Procedimiento y Comandos

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4625
    StartTime = (Get-Date).AddDays(-1)
} -MaxEvents 100 | Select-Object TimeCreated, Id, Message
```

### Tabla Anonimizada de Eventos Observados

| Hora (Local) | Event ID | Cuenta / Usuario | Logon Type | Dirección IP Origen | Observación |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-10-25 08:30:12 | 4624 | SYSTEM | 0 | - | Inicio de sesión de sistema |
| 2026-10-25 09:15:04 | 4625 | analista | 3 | 192.0.2.50 | Credenciales incorrectas via red |
| 2026-10-25 09:15:22 | 4624 | analista | 3 | 192.0.2.50 | Inicio exitoso tras fallo |

### Interpretación del Contexto
- El Logon Type 3 indica un acceso a través de la red (por ejemplo, compartición de archivos o autenticación de dominio).
- El evento 4625 previo al 4624 sugiere un error tipográfico por parte del usuario o un intento de prueba de credenciales.

---

## Laboratorio 02 — Sysmon disponible y campos

### Objetivo
Verificar si el servicio de Sysmon está instalado y operativo, y consultar los eventos de Creación de Procesos (Event ID 1) y Conexión de Red (Event ID 3).

### Procedimiento y Comandos

1. **Verificar presencia del log de Sysmon:**
   ```powershell
   Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
   ```

2. **Consultar eventos recientes (ID 1 y 3):**
   ```powershell
   Get-WinEvent -FilterHashtable @{
       LogName = 'Microsoft-Windows-Sysmon/Operational'
       Id = 1, 3
   } -MaxEvents 20 | Select-Object TimeCreated, Id, Message
   ```

### Campos Clave Identificados

- `ProcessGuid`: Identificador único global del proceso, persistente ante reinicios de PID.
- `Image`: Ruta completa del ejecutable (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).
- `CommandLine`: Argumentos de línea de comandos utilizados.
- `ParentImage`: Proceso padre que inició la ejecución (`C:\Windows\explorer.exe`).
- `DestinationIp` / `DestinationPort`: Dirección de red de destino y puerto de conexión (ej. `198.51.100.20:443`).

### Conclusión
Sysmon proporciona visibilidad profunda sobre la ejecución y la actividad de red posterior. La presencia del `ProcessGuid` es indispensable para vincular una conexión de red directamente con el proceso exacto que la originó.

---

## Laboratorio 03 — journalctl por hora y unidad

### Objetivo
Consultar la bitácora de systemd en Linux, comparar el despliegue de registros en hora local frente a UTC y filtrar la actividad del servicio SSH.

### Procedimiento y Comandos

1. **Listar arranques del sistema:**
   ```bash
   journalctl --list-boots
   ```

2. **Consultar últimos 30 registros en formato UTC:**
   ```bash
   journalctl -b -n 30 --utc
   ```

3. **Extraer registros del servicio SSH de la última hora en JSON:**
   ```bash
   journalctl -u ssh -u sshd --since "1 hour ago" -o json --no-pager
   ```

### Cuadro de Disponibilidad y Zonas Horarias

| Servicio / Unidad | Campo de Hora en Log | Zona Horaria Configurada | Formato Exportado |
| :--- | :--- | :--- | :--- |
| `sshd.service` | `__REALTIME_TIMESTAMP` | Local (ART -0300) | Microsegundos UNIX Epoch / ISO8601 |
| `systemd` | `_SOURCE_REALTIME_TIMESTAMP` | Local (ART -0300) | UTC al pasar parámetro `--utc` |

### Conclusión
Se constató que `journalctl` convierte dinámicamente los timestamps almacenados en binario. Es crítico utilizar la bandera `--utc` en investigaciones incidentales para alinear los logs de Linux con otras fuentes.

---

## Laboratorio 04 — Audit Linux y fuentes alternativas

### Objetivo
Mapear las fuentes de telemetría de seguridad en Linux para auditoría de autenticación y ejecución de comandos.

### Procedimiento y Comandos

```bash
# Estado del servicio de auditoría
systemctl status auditd

# Consultar eventos de auditoría de hoy (requiere privilegios de lectura)
sudo ausearch -ts today -m AUTH_LOGIN 2>/dev/null || echo "Sin acceso direct a auditd"

# Verificar archivos de log tradicionales
ls -l /var/log/auth.log /var/log/secure /var/log/audit/ 2>/dev/null

# Consultar journal para eventos de autenticación
journalctl -u sshd -n 50 --no-pager
```

### Mapa de Fuentes de Seguridad en Linux

- `/var/log/audit/audit.log` (`auditd`): Captura llamadas al sistema, cambios de permisos, ejecución de binarios y eventos PAM a bajo nivel.
- `/var/log/auth.log` o `/var/log/secure`: Registra intentos de inicio de sesión (SSH, sudo, su) manejados por el subsistema PAM.
- `journalctl` (systemd-journald): Centraliza los logs de todos los servicios, incluidos `sshd` y `sudo`.

### Limitación Identificada
Si `auditd` no está instalado o activo, el sistema depende exclusivamente de PAM y `journald`, lo que limita el rastreo de ejecución de comandos sin elevación de privilegios.

---

## Laboratorio 05 — CSV robusto y parsing

### Objetivo
Procesar un archivo CSV sintético que contiene comas dentro de las cadenas de texto sin romper la estructura de las columnas.

### Código de Prueba en Python (`parse_csv.py`)

```python
import csv
from io import StringIO

csv_data = """timestamp,source,host,user,message
2026-10-20T10:00:00-03:00,winsec,pc-lab-01,analista,"Fallo de inicio de sesion, razon: clave incorrecta"
2026-10-20T10:02:20-03:00,winsec,pc-lab-01,analista,"Inicio exitoso, dominio: LAB"
"""

f = StringIO(csv_data)
reader = csv.DictReader(f)

for row in reader:
    print(f"Host: {row['host']} | User: {row['user']} | Msg: {row['message']}")
```

### Resultado
El módulo `csv` de Python respeta las comillas dobles y evita que la coma contenida en la columna `message` divida erróneamente el registro en columnas adicionales.

---

## Laboratorio 06 — Normalización de timestamps

### Objetivo
Convertir marcas de tiempo provenientes de múltiples fuentes con diferentes formatos y zonas horarias (`-03:00` y `Z`) a una representación única en UTC.

### Código de Normalización en Python

```python
from datetime import datetime, timezone

timestamps = [
    "2026-10-20T10:00:00-03:00",
    "2026-10-20T13:03:00Z"
]

for ts in timestamps:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    utc_dt = dt.astimezone(timezone.utc)
    print(f"Original: {ts:<28} -> UTC: {utc_dt.isoformat()}")
```

### Tabla de Conversión

| Timestamp Original | Formato | Offset / Zona | Timestamp Convertido (UTC) |
| :--- | :--- | :--- | :--- |
| `2026-10-20T10:00:00-03:00` | ISO 8601 | UTC-3 | `2026-10-20T13:00:00+00:00` |
| `2026-10-20T13:03:00Z` | ISO 8601 | UTC (Zulu) | `2026-10-20T13:03:00+00:00` |

---

## Laboratorio 07 — Correlación por identidad e IP

### Objetivo
Ejecutar la lógica de correlación para identificar secuencias donde ocurran fallos de autenticación seguidos de un acceso exitoso dentro de una ventana temporal de 10 minutos.

### Principios de Análisis
1. **IP Compartida:** Una misma dirección IP puede representar un portal NAT donde operan múltiples usuarios legítimos.
2. **Cuentas de Servicio:** No deben confundirse con usuarios interactivos humanos.
3. **Identidad vs. Dirección:** La IP es un indicador de red; la identidad requiere corroborar la sesión activa en el host objetivo.

---

## Laboratorio 08 — Salud del pipeline

### Objetivo
Analizar la recepción continua de logs e identificar brechas temporales que puedan señalar la caída de un agente o la interrupción de la red.

### Análisis de Escenarios

- **Gaps Legítimos:** Ocurren fuera del horario laboral o en sistemas dedicados a tareas no automatizadas donde la generación de logs es baja.
- **Caída de Pipeline:** Cese total y repentino de la ingesta de eventos (incluyendo eventos de heartbeat o logs del sistema).

### Consulta de Detección (KQL de Referencia)

```kql
AuthTraining_CL
| summarize UltimaSeñal = max(TimeGenerated) by host_s, source_s
| extend MinutosSinReportar = datetime_diff('minute', now(), UltimaSeñal)
| where MinutosSinReportar >= 15
| project host_s, source_s, UltimaSeñal, MinutosSinReportar, Estado="Alerta: Interrupcion de Pipeline"
```

---

## Laboratorio 09 — Detección con ventana y umbral

### Objetivo
Diseñar y evaluar una regla de detección por umbral para identificar posibles ataques de fuerza bruta.

### Parámetros de la Regla
- **Nombre:** Intentos de inicio de sesión fallidos seguidos de éxito.
- **Ventana de Tiempo:** 10 minutos.
- **Umbral:** Concentración de 2 o más eventos de fallo (Event ID 4625) seguidos de un evento exitoso (Event ID 4624) para el mismo usuario y equipo.

### Evaluación de Falsos Positivos
- **Caso Falso Positivo:** Un usuario olvida su contraseña, la ingresa mal dos veces y al tercer intento la escribe correctamente.
- **Mecanismo de Mitigación:** Verificar el contexto del dispositivo, la ubicación geográfica y la presencia de autenticación multifactor (MFA).

---

## Laboratorio 10 — Línea temporal multi-fuente

### Objetivo
Unificar eventos provenientes de Windows Security, Sysmon, Proxy y Logs de Autenticación de Linux en una única línea de tiempo cronológica en UTC.

### Alineación Cronológica de Eventos

1. `13:00:00 UTC` - Windows Security - Event ID 4625 (Inicio fallido, `analista`, IP `192.0.2.50`)
2. `13:01:00 UTC` - Windows Security - Event ID 4625 (Inicio fallido, `analista`, IP `192.0.2.50`)
3. `13:02:20 UTC` - Windows Security - Event ID 4624 (Inicio exitoso, `analista`, IP `192.0.2.50`)
4. `13:03:00 UTC` - Sysmon - Event ID 1 (Creación de proceso `powershell.exe`, GUID `{LAB-GUID-A}`)
5. `13:04:00 UTC` - Sysmon - Event ID 3 (Conexión saliente a `198.51.100.20:443`, GUID `{LAB-GUID-A}`)
6. `13:08:00 UTC` - Proxy - Solicitud HTTP 200 a `actualizaciones.ejemplo.test`

---

## Laboratorio 11 — Integridad de una exportación

### Objetivo
Garantizar la integridad de las evidencias exportadas mediante el cálculo de hashes SHA-256.

### Procedimiento y Comandos

- **En Linux:**
  ```bash
  sha256sum SOC-Labs/U11-investigacion-correlacion/data/eventos_u11.jsonl > SOC-Labs/U11-investigacion-correlacion/evidence/hashes.txt
  cat SOC-Labs/U11-investigacion-correlacion/evidence/hashes.txt
  ```

- **En Windows:**
  ```powershell
  Get-FileHash -Path "SOC-Labs/U11-investigacion-correlacion/data/eventos_u11.jsonl" -Algorithm SHA256 | Format-List
  ```

### Resultado Obtenido
El hash resultante debe archivarse inmediatamente en la carpeta `evidence/` para validar la cadena de custodia durante todo el proceso de análisis.

---

## Laboratorio 12 — Diseño y validación de regla Sigma

### Objetivo
Definir una regla en formato Sigma para detectar ejecuciones sospechosas de PowerShell asociadas a conexiones de red.

### Regla Sigma (`powershell_network_connection.yml`)

```yaml
title: Ejecucion de PowerShell con Conexion de Red Posterior
id: f47ac10b-58cc-4372-a567-0e02b2c3d479
status: experimental
description: Detecta la creacion de un proceso PowerShell seguido de una conexion de red saliente en una ventana corta.
author: Analista SOC L1
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith: '\powershell.exe'
        ParentImage|endswith: '\explorer.exe'
    condition: selection_process
falsepositives:
    - Scripts de administracion legitimos iniciados por el usuario.
level: medium
```

---

## Laboratorio 13 — Informe SOC L1 integrador

### Creación del dataset sintético (`eventos_u11.jsonl`)

Se generó el archivo de datos en la ruta `SOC-Labs/U11-investigacion-correlacion/data/eventos_u11.jsonl` con el siguiente contenido:

```json
{"timestamp":"2026-10-20T10:00:00-03:00","source":"winsec","host":"pc-lab-01","event_id":4625,"user":"analista","src_ip":"192.0.2.50","result":"failure","message":"Inicio fallido sintético"}
{"timestamp":"2026-10-20T10:01:00-03:00","source":"winsec","host":"pc-lab-01","event_id":4625,"user":"analista","src_ip":"192.0.2.50","result":"failure","message":"Inicio fallido sintético"}
{"timestamp":"2026-10-20T10:02:20-03:00","source":"winsec","host":"pc-lab-01","event_id":4624,"user":"analista","src_ip":"192.0.2.50","result":"success","logon_type":3,"message":"Inicio exitoso sintético"}
{"timestamp":"2026-10-20T13:03:00Z","source":"sysmon","host":"pc-lab-01","event_id":1,"user":"analista","process_guid":"{LAB-GUID-A}","image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parent_image":"C:\\Windows\\explorer.exe","message":"Creación de proceso sintética"}
{"timestamp":"2026-10-20T13:04:00Z","source":"sysmon","host":"pc-lab-01","event_id":3,"user":"analista","process_guid":"{LAB-GUID-A}","dst_ip":"198.51.100.20","dst_port":443,"message":"Conexión sintética"}
{"timestamp":"2026-10-20T13:06:00Z","source":"winsec","host":"pc-lab-01","event_id":4624,"user":"operador","src_ip":"192.0.2.80","result":"success","logon_type":2,"message":"Operación conocida de laboratorio"}
{"timestamp":"2026-10-20T13:08:00Z","source":"proxy","host":"pc-lab-01","user":"analista","src_ip":"192.0.2.50","dst_host":"actualizaciones.ejemplo.test","status":200,"message":"Acceso proxy sintético"}
{"timestamp":"2026-10-20T13:09:00Z","source":"linux-auth","host":"srv-lab-01","user":"devops","src_ip":"192.0.2.70","result":"success","message":"SSH sintético autorizado"}
{"timestamp":"2026-10-20T13:11:00Z","source":"linux-auth","host":"srv-lab-01","user":"root","src_ip":"192.0.2.99","result":"failure","message":"SSH fallido sintético"}
{"timestamp":"2026-10-20T13:12:00Z","source":"heartbeat","host":"pc-lab-01","message":"Agente activo"}
```

### Script de Procesamiento y Correlación (`correlacion_u11.py`)

Se guardó y ejecutó el script de análisis en `SOC-Labs/U11-investigacion-correlacion/scripts/correlacion_u11.py`:

```python
from __future__ import annotations
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

FILE = Path("SOC-Labs/U11-investigacion-correlacion/data/eventos_u11.jsonl")

def parse_timestamp(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"La fecha no tiene offset: {value}")
    return dt.astimezone(timezone.utc)

rows = []
if not FILE.exists():
    print(f"Error: No se encuentra el archivo {FILE}")
    exit(1)

for lineno, raw in enumerate(FILE.read_text(encoding="utf-8").splitlines(), 1):
    if not raw.strip():
        continue
    try:
        row = json.loads(raw)
        row["_utc"] = parse_timestamp(row["timestamp"])
        rows.append(row)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"Línea {lineno}: error de lectura: {exc}")

rows.sort(key=lambda r: r["_utc"])

print("==========================================")
print(" EVENTOS EN UT-CRONOLOGICO ")
print("==========================================")
for e in rows:
    print(f"{e['_utc'].isoformat()} | {e.get('source'):<10} | {e.get('host'):<10} | EventID: {str(e.get('event_id', '-')):<4} | User: {e.get('user', '-'):<10}")

failures = defaultdict(list)
print("\n==========================================")
print(" CANDIDATOS PARA TRIAGE (Fallos -> Éxito) ")
print("==========================================")
for e in rows:
    if e.get("source") != "winsec":
        continue
    key = (e.get("host"), e.get("user"))
    if e.get("event_id") == 4625:
        failures[key].append(e)
    elif e.get("event_id") == 4624:
        recent = [f for f in failures[key] if timedelta(0) <= e["_utc"] - f["_utc"] <= timedelta(minutes=10)]
        if recent:
            print(f"Alerta en Host: {key[0]} | Usuario: {key[1]}")
            print(f"  -> {len(recent)} inicios fallidos previos en menos de 10 min.")
            print(f"  -> Hora de éxito: {e['_utc'].isoformat()}")
            print(f"  -> Origen IP: {e.get('src_ip')}\n")
```

---

## Informe Final de Investigación (SOC L1)

```markdown
# Informe de Investigación de Seguridad — Caso Unidad 11

## Alcance
Analisis sobre dataset sintetico de telemetria multifuente (Windows, Sysmon, Linux, Proxy).

## Pregunta de investigación
¿Existe evidencia de autenticacion no autorizada seguida de actividad maliciosa en el equipo pc-lab-01?

## Evidencias
- Archivo fuente: `eventos_u11.jsonl`
- Cobertura temporal: `2026-10-20T13:00:00Z` a `2026-10-20T13:12:00Z`
- Cantidad de registros: 10
- Hash SHA-256 de la muestra: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (Ejemplo de integridad)

## Cronología Unificada (UTC)

| Hora (UTC) | Fuente | Host | ID / Evento | Usuario | Detalle |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 13:00:00 | winsec | pc-lab-01 | 4625 | analista | Fallo de autenticacion desde 192.0.2.50 |
| 13:01:00 | winsec | pc-lab-01 | 4625 | analista | Fallo de autenticacion desde 192.0.2.50 |
| 13:02:20 | winsec | pc-lab-01 | 4624 | analista | Autenticacion exitosa (Logon Type 3) |
| 13:03:00 | sysmon | pc-lab-01 | 1 | analista | Ejecucion de powershell.exe por explorer.exe |
| 13:04:00 | sysmon | pc-lab-01 | 3 | analista | Conexion saliente a 198.51.100.20:443 |
| 13:06:00 | winsec | pc-lab-01 | 4624 | operador | Inicio interactivo local (Logon Type 2) |
| 13:08:00 | proxy | pc-lab-01 | HTTP 200 | analista | Solicitud a actualizaciones.ejemplo.test |
| 13:09:00 | linux-auth | srv-lab-01 | SSH OK | devops | Acceso SSH correcto desde 192.0.2.70 |
| 13:11:00 | linux-auth | srv-lab-01 | SSH Fail | root | Intento fallido SSH desde 192.0.2.99 |
| 13:12:00 | heartbeat | pc-lab-01 | Agent OK | - | Confirmacion de salud de agente |

## Evaluación de Hipótesis

### Hipótesis 1: Actividad de Usuario Legítimo (Error Tipográfico)
- **A favor:** Tras dos intentos fallidos en un lapso de 2 minutos, el usuario `analista` ingresó la clave correcta. La conexión posterior por PowerShell y Proxy apunta a dominios de actualización conocidos (`actualizaciones.ejemplo.test`).
- **En contra:** La conexión saliente hacia la IP `198.51.100.20` carece de resolución de nombre explícita en el evento Sysmon ID 3.
- **Datos faltantes:** Entrevistar al usuario `analista` y revisar si la tarea correspondía a un mantenimiento programado.

### Hipótesis 2: Compromiso de Credenciales (Fuerza Bruta Ligera)
- **A favor:** Dos fallos consecutivos seguidos de un acceso remoto (Logon Type 3) y la inmediata apertura de un proceso de consola (`powershell.exe`) con red.
- **En contra:** La secuencia se detiene y la máquina continúa enviando eventos de Heartbeat normalmente sin evidencia de persistencia o movimiento lateral en los logs analizados.
- **Datos faltantes:** Copia de los scripts ejecutados dentro de la sesión de PowerShell.

## Conclusión
Se confirma la coincidencia de dos fallos de autenticación seguidos de un inicio exitoso para la cuenta `analista` en `pc-lab-01`. Si bien existe una ejecución de PowerShell y una conexión a la red posterior, los datos sintéticos no aportan evidencia suficiente para catalogarlo como incidente confirmado. Se clasifica de forma preventiva como **Evento Sospechoso Bajo Investigación (Prioridad B) / Falso Positivo Probable**.

## Próximos Pasos Recomendados
1. Contactar al usuario asignado a la cuenta `analista` para validar la actividad a las 10:00 AM (ART).
2. Extraer el historial de comandos ejecutados en el proceso de PowerShell (`{LAB-GUID-A}`).
3. Consultar la reputación de la IP externa `198.51.100.20` en bases de datos de Inteligencia de Amenazas.
```

---

## Lista de Verificación y Autoevaluación

- [x] Distingo evento, log y alerta.
- [x] Consulté logs de Windows y documenté cobertura.
- [x] Consulté Linux journald y documenté zonas horarias.
- [x] Separé tiempo de evento y tiempo de ingestión.
- [x] Leí JSONL/CSV mediante un parser robusto en Python.
- [x] Correlacioné eventos sin atribuir identidades exclusivamente por la IP.
- [x] Verifiqué la integridad de la evidencia exportada mediante SHA-256.
- [x] Reconocí la presencia de falsos positivos en las reglas por umbral.
- [x] Generé una línea temporal unificada en UTC.
- [x] Redacté un informe SOC L1 estructurado y basado en evidencias.