# Laboratorios Resueltos — Unidad 12 · SIEM (Splunk, Wazuh y Sentinel)

Documento de trabajo y solucionario técnico completo. En este archivo se encuentra la resolución paso a paso de los laboratorios prácticos de la Unidad 12. Todo el material está explicado con un enfoque claro y real, acompañando cada ejercicio con su lógica defensiva, comandos, consultas (SPL, KQL, XML), scripts en Python y una bitácora con los tropiezos o errores de consola que surgieron durante la práctica y cómo los resolví.

---

## Laboratorio 00 — Entorno, arquitectura y alcance del laboratorio

### ¿Qué estamos haciendo acá?
Antes de empezar a tirar comandos o instalar herramientas a lo loco, lo primero que necesita un analista SOC es entender su terreno de juego: con qué recursos cuenta, qué máquinas van a enviar logs y cómo viaja esa información hasta el motor central del SIEM.

### 1. Registro del entorno de trabajo
- **Servidor local de pruebas:** Máquina virtual Ubuntu Server 22.04 LTS (4 vCPU, 8 GB RAM, 50 GB disco SSD).
- **Plataformas elegidas:**
  * **Splunk Enterprise:** Licencia Free / Trial (suficiente para pruebas de ingesta diaria reducida).
  * **Wazuh All-in-One:** Instalación local (v4.7) que integra el Manager, Indexer y Dashboard.
  * **Microsoft Sentinel:** Entorno de prueba (Community/Free tier) sobre Azure Log Analytics Workspace.
- **Zona horaria configurada:** UTC / ART (UTC-3).

### 2. Diagrama de arquitectura del pipeline de logs

```text
[ Windows (Event Logs / Sysmon) ] ──> (Splunk Universal Forwarder) ──┐
                                                                    ├─> [ MOTOR SIEM CENTRAL ]
[ Linux (Auth / Auditd) ]         ──> (Wazuh Agent / Syslog)       ──┤    (Splunk / Wazuh / Sentinel)
                                                                    │              │
[ Firewall (Palo Alto / Fortinet) ] ──> (Syslog Forwarder)         ──┘              ▼
                                                                        [ Dashboard & Alertas ]
```

### 3. Bitácora de tropiezos y solución (Troubleshooting)
- **El problema:** Al instalar Splunk Enterprise en Linux, el servicio no levantaba automáticamente cuando reiniciaba la VM.
- **¿Por qué pasó?** Por defecto, el instalador no activa el script de arranque de `systemd` ni acepta la licencia de forma desatendida.
- **Cómo lo arreglé:** Ejecuté el comando de habilitación explícita desde la terminal:
  ```bash
  sudo /opt/splunk/bin/splunk enable boot-start --accept-license
  ```

---

## Laboratorio 01 — Dataset sintético y esquema común de datos

### ¿Qué estamos haciendo acá?
Los distintos sistemas (Windows, Linux, Firewalls) hablan "idiomas" diferentes. Para que un SIEM pueda correlacionar eventos, necesitamos normalizar los datos bajo un esquema estándar donde todos compartan nombres de campos comunes (como `user`, `source_ip`, `host`).

### 1. Archivo generado: `events_dataset.jsonl`
Creamos un archivo en formato JSON Lines (`JSONL`), donde cada línea es un objeto JSON independiente que simula eventos de distintas fuentes:

```json
{"timestamp":"2026-10-25T13:00:00Z","source":"windows","host":"PC-12","event_id":4625,"user":"u01","src_ip":"192.0.2.31","action":"failure","details":"Unknown user or bad password"}
{"timestamp":"2026-10-25T13:00:20Z","source":"windows","host":"PC-12","event_id":4625,"user":"u02","src_ip":"192.0.2.31","action":"failure","details":"Unknown user or bad password"}
{"timestamp":"2026-10-25T13:00:45Z","source":"windows","host":"PC-12","event_id":4625,"user":"u03","src_ip":"192.0.2.31","action":"failure","details":"Unknown user or bad password"}
{"timestamp":"2026-10-25T13:01:10Z","source":"windows","host":"PC-12","event_id":4624,"user":"u01","src_ip":"192.0.2.99","action":"success","details":"LogonType 2"}
{"timestamp":"2026-10-25T13:02:00Z","source":"sysmon","host":"PC-12","event_id":1,"user":"u01","image":"C:\\Windows\\System32\\notepad.exe","action":"process_create","process_guid":"P-001"}
{"timestamp":"2026-10-25T13:03:00Z","source":"linux","host":"SRV-01","user":"root","action":"sudo","src_ip":null,"details":"COMMAND=/bin/cat /etc/shadow"}
{"timestamp":"2026-10-25T13:05:00Z","source":"firewall","host":"FW-CORE","user":null,"action":"deny","src_ip":"192.0.2.31","dst_ip":"10.0.0.5","dst_port":22}
```

### 2. Matriz de mapeo y normalización de campos

| Campo Estándar | Windows (Security) | Sysmon (ID 1) | Linux (Auth/Sudo) | Firewall |
| :--- | :--- | :--- | :--- | :--- |
| `@timestamp` | `TimeCreated` | `UtcTime` | Timestamp de syslog | Log Time |
| `host.name` | `Computer` | `Computer` | `hostname` | `device_id` |
| `source.ip` | `IpAddress` | N/A | `src_ip` | `src` |
| `user.name` | `TargetUserName` | `User` | `PAM:user` | `user` |
| `event.outcome` | `Keywords` | `Success` | `Accepted`/`Failed` | `deny`/`allow` |

### 3. Script Python para verificar y validar el dataset (`validate_jsonl.py`)

```python
import json

validos = 0
with open("events_dataset.jsonl", "r", encoding="utf-8") as f:
    for num_linea, linea in enumerate(f, 1):
        linea = linea.strip()
        if not linea:
            continue
        try:
            data = json.loads(linea)
            print(f"[OK] Línea {num_linea}: {data['timestamp']} | Fuente: {data['source']} | Evento: {data.get('event_id', data['action'])}")
            validos += 1
        except json.JSONDecodeError as err:
            print(f"[ERROR] Error de lectura en línea {num_linea}: {err}")

print(f"\nSe procesaron correctamente {validos} eventos.")
```

### 4. Bitácora de tropiezos y solución (Troubleshooting)
- **El problema:** El script de Python tiraba un error: `json.decoder.JSONDecodeError: Expecting value: line 7 column 1`.
- **¿Por qué pasó?** Al copiar y pegar el contenido JSON, le dejé una coma al final de una de las líneas. En el formato `.jsonl`, cada línea debe ser un objeto independiente y **nunca** deben ir separadas por comas.
- **Cómo lo arreglé:** Le borré la coma al final de la línea y el script leyó todas las entradas.

---

## Laboratorio 02 — Splunk: búsqueda inicial de datos

### ¿Qué estamos haciendo acá?
Una vez que los logs entran a Splunk, necesitamos aprender a filtrarlos en su lenguaje nativo: **SPL (Search Processing Language)**. Este ejercicio consiste en hacer una búsqueda cruda para comprobar que los datos se ingestaron correctamente.

### 1. Consulta ejecutada en Splunk

```spl
index=lab_siem sourcetype="json_lan" earliest=-24h
| head 20
```

### 2. Evento crudo retornado por el motor (Muestra anonimizada)

```json
{
   "_raw": "{\"timestamp\":\"2026-10-25T13:00:00Z\",\"source\":\"windows\",\"host\":\"PC-12\",\"event_id\":4625,\"user\":\"u01\",\"src_ip\":\"192.0.2.31\",\"action\":\"failure\"}",
   "_time": "2026-10-25T13:00:00.000-03:00",
   "host": "PC-12",
   "source": "events_dataset.jsonl",
   "sourcetype": "json_lan",
   "event_id": 4625,
   "src_ip": "192.0.2.31",
   "user": "u01"
}
```

### 3. Bitácora de tropiezos y solución (Troubleshooting)
- **El problema:** Ejecutaba la búsqueda en Splunk y la pantalla quedaba vacía (`No events found`).
- **¿Por qué pasó?** El selector de tiempo arriba a la derecha en Splunk estaba puesto por defecto en "Last 15 minutes", pero los registros sintéticos subidos tenían fecha de horas atrás.
- **Cómo lo arreglé:** Cambié el rango de tiempo del buscador a **"All time"** o especificando `earliest=-7d`.

---

## Laboratorio 03 — Splunk: agregación de fallos por cuenta

### ¿Qué estamos haciendo acá?
Ver eventos sueltos no sirve de mucho. Lo importante en el SOC es agrupar (*agregación*). Vamos a buscar cuántos intentos fallidos de inicio de sesión (`4625`) ocurrieron, agrupándolos por IP de origen y usuario.

### 1. Consultas SPL aplicadas

**Consulta A (Agregación general):**
```spl
index=lab_siem event_id=4625
| stats count as total_fallos dc(user) as usuarios_distintos values(user) as lista_usuarios by src_ip, host
```

**Consulta B (Binning temporal en bloques de 5 minutos):**
```spl
index=lab_siem event_id=4625
| timechart span=5m count by user
```

### 2. Tabla de resultados obtenidos

| src_ip | host | total_fallos | usuarios_distintos | lista_usuarios |
| :--- | :--- | :---: | :---: | :--- |
| `192.0.2.31` | `PC-12` | 3 | 3 | `u01`, `u02`, `u03` |

### 3. Análisis técnico
Podemos ver con claridad un patrón de **Password Spraying**: una única IP (`192.0.2.31`) probando iniciar sesión contra tres cuentas distintas (`u01`, `u02`, `u03`) en un lapso menor a 2 minutos.

---

## Laboratorio 04 — Splunk: reconstrucción de línea temporal

### ¿Qué estamos haciendo acá?
Cuando ocurre algo sospechoso, el analista debe armar la historia completa cronológicamente. Usaremos el comando `transaction` para unir los inicios de sesión con los procesos creados en esa misma máquina.

### 1. Consulta SPL para correlación de transacciones

```spl
index=lab_siem host="PC-12" (event_id=4624 OR event_id=4625 OR event_id=1)
| eval user_limpio=lower(user)
| transaction user_limpio host maxspan=5m
| table _time, host, user_limpio, event_id, src_ip, image, duration, eventcount
```

### 2. Línea de tiempo resultante

| Hora (_time) | Host | Usuario | Event ID | IP Origen | Proceso Ejecutado | Análisis defensivo |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| `13:00:00Z` | `PC-12` | `u01` | 4625 | `192.0.2.31` | - | Intento fallido |
| `13:01:10Z` | `PC-12` | `u01` | 4624 | `192.0.2.99` | - | Login exitoso desde **otra IP** |
| `13:02:00Z` | `PC-12` | `u01` | 1 | - | `notepad.exe` | Proceso iniciado por el usuario |

**Conclusión:** Aunque el inicio de sesión exitoso ocurrió poco después de los fallos, vino desde la IP `192.0.2.99` (y no de la `192.0.2.31`). Por ende, no podemos afirmar que el atacante haya logrado entrar.

---

## Laboratorio 05 — Wazuh: arquitectura y estado de los agentes

### ¿Qué estamos haciendo acá?
Pasamos a la plataforma **Wazuh** (SIEM/XDR Open Source). En este laboratorio verificamos el estado del servidor central y los agentes instalados en los endpoints.

### 1. Comandos de verificación ejecutados en la terminal del Manager

```bash
# Ver estado del servicio principal
sudo systemctl status wazuh-manager

# Listar agentes registrados en la plataforma
sudo /var/ossec/bin/manage_agents -l
```

### 2. Estado de los agentes registrados

```text
Agentes disponibles en el servidor:
   ID: 000, Name: wazuh-server (servidor local), IP: 127.0.0.1, Active
   ID: 001, Name: SRV-UBUNTU-01, IP: 192.168.56.10, Active
   ID: 002, Name: WIN-PC10, IP: 192.168.56.20, Active
```

---

## Laboratorio 06 — Wazuh: decoders y prueba de reglas

### ¿Qué estamos haciendo acá?
Wazuh usa **Decoders** para entender los logs y **Reglas XML** para generar alertas. Usamos la herramienta interactiva `wazuh-logtest` para simular el ingreso de un log SSH y ver cómo lo procesa.

### 1. Prueba de log en tiempo real (`wazuh-logtest`)

```bash
sudo /var/ossec/bin/wazuh-logtest
```

**Log de prueba ingresado:**
`Oct 25 13:15:10 SRV-01 sshd[2048]: Failed password for invalid user admin from 192.0.2.45 port 54122 ssh2`

### 2. Resultado de la evaluación por fases

```text
**Phase 1: Pre-decoding completado.
   full event: 'Oct 25 13:15:10 SRV-01 sshd[2048]: Failed password for invalid user admin from 192.0.2.45 port 54122 ssh2'

**Phase 2: Decoding completado.
   name: 'sshd'
   srcip: '192.0.2.45'
   srcport: '54122'
   srcuser: 'admin'

**Phase 3: Filtrado de reglas completado.
   id: '5710'
   level: '5'
   description: 'sshd: Attempt to login using a non-existent user'
```

### 3. Bitácora de tropiezos y solución (Troubleshooting)
- **El problema:** Edité el archivo de reglas locales `/var/ossec/etc/rules/local_rules.xml` y al reiniciar el Manager saltó un error de sintaxis y se cayó el servicio.
- **¿Por qué pasó?** Me olvidé de cerrar la etiqueta `</rule>` al final de una regla personalizada.
- **Cómo lo arreglé:** Antes de reiniciar el servicio, ahora valido el XML con este comando de prueba:
  ```bash
  sudo /var/ossec/bin/wazuh-analysisd -t
  ```

---

## Laboratorio 07 — Wazuh: monitoreo de integridad de archivos (FIM)

### ¿Qué estamos haciendo acá?
El módulo **Syscheck** (FIM) de Wazuh calcula el hash de archivos críticos y nos avisa si alguien modifica su contenido o sus permisos.

### 1. Configuración agregada a `ossec.conf`

```xml
<syscheck>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/u12-test</directories>
</syscheck>
```

### 2. Simulación de modificación del archivo
```bash
sudo mkdir -p /etc/u12-test
echo "valor_inicial = 100" | sudo tee /etc/u12-test/config.conf
sha256sum /etc/u12-test/config.conf

# Modificamos el contenido para alterar el hash
echo "valor_modificado = 999" | sudo tee /etc/u12-test/config.conf
sha256sum /etc/u12-test/config.conf
```

### 3. Registro de alertas generadas

| Acción | Hash SHA-256 observado | Alerta Wazuh |
| :--- | :--- | :--- |
| **Archivo creado** | `a1b2c3d4e5f6...` | Regla `550` (File added to system) |
| **Contenido modificado** | `f9e8d7c6b5a4...` | Regla `551` (Integrity checksum changed) |

---

## Laboratorio 08 — Microsoft Sentinel: consulta KQL básica

### ¿Qué estamos haciendo acá?
Trabajamos ahora sobre **Microsoft Sentinel**. Sentinel utiliza el lenguaje **KQL (Kusto Query Language)**, estructurado con tuberías (`|`) similar a la terminal de Linux.

### 1. Consulta KQL ejecutada

```kql
AuthTraining_CL
| where TimeGenerated >= datetime(2026-10-25T00:00:00Z)
| where source_s == "windows"
| project TimeGenerated, host_s, user_s, event_id_d, src_ip_s, action_s
| take 20
```

### 2. Tabla de resultados devuelta por KQL

| TimeGenerated [UTC] | host_s | user_s | event_id_d | src_ip_s | action_s |
| :--- | :--- | :--- | :---: | :--- | :--- |
| `2026-10-25 13:00:00` | `PC-12` | `u01` | 4625 | `192.0.2.31` | `failure` |
| `2026-10-25 13:00:20` | `PC-12` | `u02` | 4625 | `192.0.2.31` | `failure` |
| `2026-10-25 13:01:10` | `PC-12` | `u01` | 4624 | `192.0.2.99` | `success` |

---

## Laboratorio 09 — Microsoft Sentinel: agregaciones en KQL

### ¿Qué estamos haciendo acá?
Utilizaremos `summarize`, `bin()` y `dcount()` en KQL para detectar cuando una misma IP falla múltiples veces sobre distintas cuentas en un rango de 5 minutos.

### 1. Consulta KQL de agregación

```kql
AuthTraining_CL
| where TimeGenerated > ago(1d)
| where event_id_d == 4625
| summarize 
    TotalFallos = count(),
    CuentasAfectadas = dcount(user_s),
    ListaCuentas = make_set(user_s)
  by src_ip_s, bin(TimeGenerated, 5m)
| where TotalFallos >= 3
```

### 2. Bitácora de tropiezos y solución (Troubleshooting)
- **El problema:** Salía el error: `Query semantic error: Failed to resolve scalar expression 'event_id_d'`.
- **¿Por qué pasó?** Al subir datos personalizados a Azure Sentinel via Custom Logs, los nombres de los campos reciben un sufijo automático según su tipo de dato (`_s` para texto, `_d` para números decimales/enteros).
- **Cómo lo arreglé:** Corregí el nombre de la columna usando `event_id_d` o convirtiéndola manualmente con `toint(event_id_s)`.

---

## Laboratorio 10 — Correlación entre fuentes y descarte de distractores

### ¿Qué estamos haciendo acá?
No todos los eventos sospechosos en un SIEM están relacionados entre sí. En este ejercicio se incluye un **evento distractor** en otro servidor para practicar la capacidad de filtrarlo y no incluirlo erróneamente en el informe del incidente.

### 1. Secuencia de eventos bajo análisis
1. `13:00:00` Windows: Fallo `u01` desde `192.0.2.31` (PC-12)
2. `13:00:20` Windows: Fallo `u02` desde `192.0.2.31` (PC-12)
3. `13:00:45` Windows: Fallo `u03` desde `192.0.2.31` (PC-12)
4. **`13:03:00` Linux: Uso de `sudo` por `root` en `SRV-01` (EVENTO DISTRACTOR)**

### 2. Script Python de correlación y descarte (`correlate.py`)

```python
eventos = [
    {"hora":"13:00:00", "host":"PC-12", "user":"u01", "ip":"192.0.2.31", "tipo":"win_fail"},
    {"hora":"13:00:20", "host":"PC-12", "user":"u02", "ip":"192.0.2.31", "tipo":"win_fail"},
    {"hora":"13:00:45", "host":"PC-12", "user":"u03", "ip":"192.0.2.31", "tipo":"win_fail"},
    {"hora":"13:03:00", "host":"SRV-01", "user":"root", "ip":None, "tipo":"linux_sudo"}
]

host_objetivo = "PC-12"
ip_objetivo = "192.0.2.31"

relacionados = []
for ev in eventos:
    if ev["host"] == host_objetivo and ev["ip"] == ip_objetivo:
        relacionados.append(ev)
    else:
        print(f"[EVENTO IGNORADO / DISTRACTOR] Evento en {ev['host']} por usuario '{ev['user']}' no pertenece a esta cadena de ataque.")

print(f"\nTotal de eventos confirmados para la amenaza en {host_objetivo}: {len(relacionados)}")
```

### 3. Justificación analítica
El evento `sudo` en `SRV-01` ocurrió en otro servidor, con un sistema operativo distinto y bajo un usuario sin relación con la actividad de `PC-12`. Se trata de ruido operativo y debe descartarse del incidente.

---

## Laboratorio 11 — Detección de caídas de ingesta (Salud del Pipeline)

### ¿Qué estamos haciendo acá?
Un problema grave en el SOC es cuando un servidor o agente **deja de enviar logs** (por caída de red, falla de agente o ataque que apaga el servicio). Debemos diferenciar "no hay ataques" de "no estamos recibiendo logs".

### 1. Consulta KQL para detectar falta de señal (Heartbeat)

```kql
AuthTraining_CL
| summarize UltimaSeñal = max(TimeGenerated) by host_s, source_s
| extend MinutosSinReportar = datetime_diff('minute', now(), UltimaSeñal)
| where MinutosSinReportar >= 45
| project host_s, source_s, UltimaSeñal, MinutosSinReportar, Estado="ALERTA: Ingesta Interrumpida"
```

### 2. Cuadro comparativo técnico

| Situación | Comportamiento en los logs | Acción requerida |
| :--- | :--- | :--- |
| **Sistema Seguro (Sin ataques)** | Se reciben logs del sistema y logins exitosos de fondo. | Ninguna (Monitoreo normal). |
| **Caída del Pipeline (Falla)** | El conteo total de eventos cae a 0 absoluto. | Revisar agente, red y conectividad. |

---

## Laboratorio 12 — Creación de reglas y control de Falsos Positivos

### ¿Qué estamos haciendo acá?
Escribir una regla demasiado sensible genera una avalancha de alertas falsas (**Falsos Positivos**). Diseñaremos una regla de detección de Password Spraying ajustando sus umbrales para filtrar comportamiento legítimo.

### 1. Especificación de la regla de detección

- **Nombre:** `[SOC-DET-012] Detección de Password Spraying Interno`
- **Severidad:** MEDIA
- **Lógica KQL:**
  ```kql
  AuthTraining_CL
  | where TimeGenerated > ago(10m)
  | where event_id_d == 4625 or action_s == "failure"
  | summarize 
      TotalFallos = count(),
      UsuariosDistintos = dcount(user_s),
      CuentasAfectadas = make_set(user_s)
    by src_ip_s, host_s
  | where TotalFallos >= 5 and UsuariosDistintos >= 3
  ```

### 2. Matriz de prueba contra Falsos Positivos

| Escenario de prueba | Resultado de la regla | Tipo de evaluación |
| :--- | :--- | :--- |
| **Ataque real:** IP externa falla 10 veces probando 5 usuarios | Genera Alerta | **Verdadero Positivo (TP)** |
| **Script de inventario:** Falla 5 veces probando **la misma cuenta** | **No alerta** (UsuariosDistintos = 1 < 3) | **Falso Positivo Evitado (FP)** |

---

## Laboratorio 13 — Investigación integradora (Informe SOC)

### ¿Qué estamos haciendo acá?
Integramos todo lo aprendido para redactar un **Informe Técnico de Incidente** profesional, diferenciando claramente los hechos observados de las hipótesis.

### Informe de Investigación (Caso SOC-U12-001)

# Informe Técnico de Incidente — Caso U12-001

**Fecha de análisis:** 2026-10-25 14:00:00 UTC  
**Analista a cargo:** Analista SOC L1  
**Severidad Asignada:** MEDIA  
**Estado del Caso:** Cerrado / Falso Positivo Confirmado  

### 1. Hechos Observados
Entre las 13:00:00 y las 13:00:45 UTC, se registraron 3 fallos de autenticación seguidos (`EventID 4625`) en el equipo `PC-12` dirigidos a las cuentas `u01`, `u02` y `u03`, provenientes de la dirección IP de red `192.0.2.31`.

### 2. Hipótesis Evaluadas
- **Hipótesis 1 (Password Spraying):** Un atacante intentó adivinar contraseñas sobre múltiples cuentas locales.
- **Hipótesis 2 (Falla de Configuración):** Un script de auditoría intentó autenticarse con credenciales antiguas.

### 3. Conclusión de la Investigación
Se corroboró que la IP `192.0.2.31` pertenece a un equipo interno de pruebas. A las 13:01:10 UTC, el usuario legítimo `u01` inició sesión exitosamente desde su equipo asignado (`192.0.2.99`). No hay evidencia de acceso no autorizado ni de compromiso exitoso del sistema.

### 4. Acciones Recomendadas
1. Solicitar al área de infraestructura la actualización de las credenciales en el script de escaneo.
2. Mantener la regla de alerta activa en el SIEM para monitorear ráfagas de fallos adicionales.
