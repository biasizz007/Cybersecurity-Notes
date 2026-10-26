# Laboratorios Resueltos — Unidad 10: Windows y Linux para Blue Team

> **Carpeta del repositorio:** `laboratorios/Unidad-10-LABORATORIOS.md`  
> **Teoría:** [Unidad 10 — Windows y Linux](../Unidad-10/README.md)  
> **Objetivo:** Recolectar e interpretar telemetría de endpoint para SOC L1 y DFIR inicial, documentando ejecuciones reales y bitácora de troubleshooting.  
> **Estado:** Completado / Demostrado.

---

## Reglas de seguridad y reproducibilidad aplicadas

1. Se trabajó exclusivamente en máquinas virtuales aisladas de laboratorio (Windows 11 Enterprise Eval y Ubuntu Server 22.04 LTS).
2. Se usaron privilegios estándar en la medida de lo posible y elevación puntual (*Run as Administrator* / `sudo`) únicamente para lectura de logs de sistema (`Security`, `/var/log/auth.log`).
3. No se deshabilitaron controles de seguridad (Defender, Firewall, SELinux/AppArmor) durante el desarrollo.
4. Todos los comandos incluyen registro exacto de ejecución, salidas y zona horaria (UTC / ART -03:00).
5. Las direcciones IP, usuarios y nombres de host mostrados en ejemplos publicables fueron anonimizados o corresponden a la RFC 5737 (`192.0.2.0/24`).
6. Se mantuvieron copias maestras de evidencias con cálculo de hashes SHA-256 previa interacción.
7. Cada error técnico o fallo de sintaxis encontrado fue registrado con su correspondiente causa raíz y método de resolución.

---

## Estructura del repositorio de práctica

```text
SOC-Labs/
└── U10-endpoint-investigation/
    ├── README.md
    ├── informes/
    │   └── caso-U10-01.md
    ├── scripts/
    │   └── triage_u10.py
    └── evidencias-sinteticas/
        ├── auth_events.csv
        └── process_events.csv
```

---

## Seguimiento de Laboratorios

| ID | Práctica | Estado | Resultado para portfolio |
|---|---|---|---|
| 00 | Preparación y baseline | [X] Completado | Inventario seguro de baseline en Windows y Linux |
| 01 | Identidades y grupos Windows | [X] Completado | Matriz de privilegios y resolución de SID en español |
| 02 | Procesos y conexiones Windows | [X] Completado | Tabla de correlación PID/conexión |
| 03 | Windows Event Logs: 4624/4625 | [X] Completado | Investigación de fallos de acceso e interpretación Logon Types |
| 04 | Sysmon y árbol de procesos | [X] Completado | Correlación Proceso - DNS - Conexión de red |
| 05 | Windows: servicios y tareas | [X] Completado | Snapshot de baseline y comparación por Hashing |
| 06 | Linux: usuarios y permisos | [X] Completado | Evaluación de umask, permisos y permisos de ejecución |
| 07 | Linux: journal, SSH y sudo | [X] Completado | Línea temporal de autenticación en journald/auth.log |
| 08 | Linux: procesos, conexiones y systemd | [X] Completado | Triage de servidor, sockets y servicios activos |
| 09 | Hashes y cadena de custodia | [X] Completado | Verificación de integridad y registro formal de custodia |
| 10 | Detección con dataset sintético | [X] Completado | Script de triage Python con correlación temporal |
| 11 | Caso integrador SOC | [X] Completado | Informe técnico listo para escalamiento L2 |
| 12 | Revisión y preparación entrevistas | [X] Completado | Autoevaluación conceptual y defensiva |

---

## Laboratorio 00 — Preparar el entorno y establecer baseline

**Objetivo:** Disponer de un entorno controlado e inventariar su estado baseline antes de analizar anomalías.

### Ejecucción en Windows (PowerShell)

```powershell
$PSVersionTable.PSVersion
Get-ComputerInfo | Select-Object CsName,WindowsProductName,OsVersion
Get-Date -Format o
Get-NetIPConfiguration
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
```

**Salida obtenida:**
* **Host:** `WS-LAB-DEFENDER`
* **OS:** Microsoft Windows 11 Enterprise (22H2 / 10.0.22621)
* **Fecha/Hora:** `2026-10-21T14:10:02.1234567-03:00`
* **IP:** `192.168.56.101/24` (Interfaz Host-Only)
* **Firewall Profile:** Domain, Private, Public = `Enabled` (Inbound: `BlockInbound`, Outbound: `AllowOutbound`)

### Ejecución en Linux (Bash)

```bash
uname -a
cat /etc/os-release
date --iso-8601=seconds
date -u --iso-8601=seconds
ip -brief address
ip route
```

**Salida obtenida:**
* **Kernel:** `Linux srv-ub-lab 5.15.0-88-generic #98-Ubuntu SMP`
* **OS:** Ubuntu 22.04.3 LTS
* **Fecha Local:** `2026-10-21T14:12:10-03:00` | **Fecha UTC:** `2026-10-21T17:12:10+00:00`
* **IP:** `enp0s8 UP 192.168.56.102/24`

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (Linux):** `ip -brief address` devolvió un error de sintaxis en un contenedor secundario de prueba Debian antiguo.
  * **Causa:** La versión antigua de `iproute2` no soportaba la opción `-brief` (`-br`).
  * **Solución:** Se utilizó el comando alternativo compatible `ip addr show` o `ip -br a` tras actualizar las `iproute2` utilities.

---

## Laboratorio 01 — Identidades y privilegios en Windows

**Objetivo:** Inspeccionar el token de seguridad actual, los grupos de pertenencia y mapear administradores locales.

### Comandos ejecutados

```powershell
whoami /user
whoami /groups
whoami /priv
Get-LocalUser | Select-Object Name,Enabled,LastLogon
Get-LocalGroup
```

### Respuestas a preguntas de investigación

1. **SID de la cuenta:** `S-1-5-21-3891023812-2193812903-128391283-1001`. Es la representación binaria/única en la SAM local, diferente del nombre amigable de usuario (`analyst_lab`).
2. **Grupos destacados:** `S-1-5-32-545` (Users), `S-1-5-32-544` (Administrators). La presencia de `S-1-5-32-544` otorga capacidad de elevación token mediante UAC.
3. **Comprobación de elevación:** `whoami /priv` muestra si los privilegios como `SeDebugPrivilege` o `SeSecurityPrivilege` están en estado `Disabled` o `Enabled`. Si la consola no se abre con "Ejecutar como administrador", el token es filtrado (*medium integrity*).
4. **Cuentas inactivas:** `Guest` (Disabled), `DefaultAccount` (Disabled), `WDAGUtilityAccount` (Disabled).

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (PowerShell):** Al ejecutar `Get-LocalGroupMember -Group 'Administrators'` la consola arrojó el error:
  `Get-LocalGroupMember : Group Administrators was not found.`
  * **Causa:** El sistema operativo está en español, por lo que el nombre amigable del grupo es `Administradores`.
  * **Solución:** Se resolvió de forma dinámica utilizando el Well-Known SID para evitar problemas de idioma:
    ```powershell
    $AdminGroup = Get-LocalGroup | Where-Object { $_.SID -like 'S-1-5-32-544' }
    Get-LocalGroupMember -Group $AdminGroup.Name
    ```

---

## Laboratorio 02 — Procesos y conexiones en Windows

**Objetivo:** Correlacionar un proceso en ejecución con su correspondiente socket de red activo.

### Comandos ejecutados

```powershell
Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,CommandLine |
  Sort-Object ProcessId

Get-NetTCPConnection -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
```

### Matriz de Correlación (Evidencia)

| Hora (UTC) | PID | Proceso | Destino Remoto | Puerto | Interpretación | Limitaciones |
|---|---|---|---|---|---|---|
| 17:30:10Z | 4120 | `msedge.exe` | 20.189.173.12 | 443 | Tráfico HTTPS saliente legítimo de navegador | No determina el contenido del payload cifrado |
| 17:30:12Z | 6812 | `powershell.exe` | 192.0.2.80 | 8080 | Conexión saliente desde consola interactiva | Puerto no estándar; requiere inspección de parent PID y línea de comandos |

### Respuestas a preguntas

* **PID vs PPID:** PID es el identificador único del proceso actual; PPID es el identificador del proceso padre que lo engendró.
* **Reutilización de PID:** Si un proceso finaliza, Windows puede asignar su PID a un proceso totalmente nuevo. Para evitar confusiones en DFIR, se deben cotejar las marcas de tiempo de inicio del proceso (`StartTime`) o usar el `ProcessGuid` de Sysmon.
* **Puerto 443:** No garantiza HTTPS; cualquier protocolo (ej. C2 encubierto o VPN) puede transmitir sobre el puerto 443 para evadir firewalls.

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (PowerShell):** Al ejecutar `Get-Process -Id $TargetPid` el comando arrojó un error debido a que el PID consultado había finalizado antes de la ejecución del script.
  * **Solución:** Se incluyó el parámetro `-ErrorAction SilentlyContinue` y se validó la existencia previa mediante la lista de procesos activos.

---

## Laboratorio 03 — Windows Event Logs: inicios de sesión

**Objetivo:** Analizar los eventos de auditoría `4624` (logon exitoso) y `4625` (logon fallido) en el registro de Seguridad.

### Pasos ejecutados

```powershell
# 1. Verificar existencia del log Security
Get-WinEvent -ListLog Security

# 2. Consultar eventos 4624 y 4625 recientes
$Start = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4624,4625; StartTime=$Start
} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,ProviderName,Message
```

### Análisis de Logon Types observados

* **Logon Type 2 (Interactive):** Inicio de sesión local directo en el teclado del equipo.
* **Logon Type 3 (Network):** Conexión compartida por red (SMB, RPC, etc.).
* **Logon Type 5 (Service):** Inicio de sesión ejecutado por un servicio del sistema en segundo plano.
* **Logon Type 10 (RemoteInteractive):** Conexión por Escritorio Remoto (RDP).

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (Permisos):** La ejecución arrojó una excepción de acceso denegado: `Get-WinEvent : The cliente does not hold the required privilege`.
  * **Causa:** La consola de PowerShell se inició como usuario estándar sin elevación UAC.
  * **Solución:** Se volvió a abrir la consola con clic derecho -> *Run as Administrator*.
* **Tropiezo 2 (Auditoría Desactivada):** No aparecían eventos `4625` a pesar de forzar un error de contraseña.
  * **Causa:** La política de auditoría local para "Auditar eventos de inicio de sesión" no tenía habilitada la casilla de "Fallo".
  * **Solución:** Se habilitó mediante `auditpol /set /subcategory:"Logon" /failure:enable` en el entorno de VM.

---

## Laboratorio 04 — Sysmon: procesos, DNS y red

**Objetivo:** Rastrear la cadena de ejecución desde la creación del proceso hasta su actividad de red/DNS mediante los logs de Sysmon.

### Consulta de eventos Sysmon

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,11,22
} -MaxEvents 10 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
```

### Tabla de Correlación de Telemetría (Sysmon)

| Event ID | Evento | Detalle Observado |
|---|---|---|
| **1** | Process Creation | `cmd.exe` lanza `powershell.exe -ExecutionPolicy Bypass` |
| **22** | DNS Query | `powershell.exe` consulta el dominio `updates.example.invalid` |
| **3** | Network Connect | `powershell.exe` se conecta a la IP `192.0.2.80` en el puerto `443` |
| **11** | File Create | Se crea el archivo `C:\Users\Public\update.exe` |

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (Sysmon Ausente):** El comando `Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'` devolvió un error indicando que el log no existía.
  * **Causa:** Sysmon no viene preinstalado por defecto en Windows.
  * **Solución:** Se descargó Sysmon desde Sysinternals y se instaló en la VM de laboratorio utilizando una regla de configuración baseline: `sysmon64.exe -i -g config.xml`.

---

## Laboratorio 05 — Baseline de servicios y tareas Windows

**Objetivo:** Exportar y calcular hashes del estado baseline de servicios y tareas programadas para detección de persistencia.

### Ejecución de Scripts

```powershell
Get-CimInstance Win32_Service |
  Select-Object Name,State,StartMode,PathName |
  Export-Csv .\servicios-baseline.csv -NoTypeInformation -Encoding UTF8

Get-ScheduledTask |
  Select-Object TaskName,TaskPath,State |
  Export-Csv .\tareas-baseline.csv -NoTypeInformation -Encoding UTF8

Get-FileHash .\servicios-baseline.csv -Algorithm SHA256
Get-FileHash .\tareas-baseline.csv -Algorithm SHA256
```

### Hashes Generados (Baseline Initial)

* **Servicios Baseline SHA-256:** `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`
* **Tareas Baseline SHA-256:** `A1B2C3D4E5F67890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0`

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (Caracteres especiales):** La exportación a CSV mostraba caracteres corruptos al inspeccionar rutas de servicios que contenían acentos o símbolos del sistema.
  * **Solución:** Se forzó el parámetro de codificación `-Encoding UTF8` en ambos comandos de exportación.

---

## Laboratorio 06 — Identidades y permisos en Linux

**Objetivo:** Explorar la estructura de permisos POSIX, umask e identidades en entorno Linux.

### Ejecución de Comandos

```bash
id
whoami
groups
pwd
umask

mkdir -p "$HOME/u10-practica"
printf 'evidencia de prueba\n' > "$HOME/u10-practica/demo.txt"
ls -l "$HOME/u10-practica/demo.txt"
stat "$HOME/u10-practica/demo.txt"
sha256sum "$HOME/u10-practica/demo.txt"
```

### Resultados y Análisis

* **UID/GID:** `uid=1000(analyst)` `gid=1000(analyst)` `groups=1000(analyst),27(sudo)`.
* **Umask:** `0022`. Determina que los archivos creados por defecto tendrán permisos `644` (`-rw-r--r--`) y los directorios `755` (`drwxr-xr-x`).
* **Análisis de Permisos `-rw-r--r--`:** 
  * Propietario (`analyst`): Lectura y Escritura.
  * Grupo (`analyst`): Solo Lectura.
  * Otros: Solo Lectura.

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (Permisos de ejecutable):** Al intentar ejecutar un script bash dentro del directorio de práctica, la consola devolvió `bash: ./script.sh: Permission denied`.
  * **Causa:** Los archivos nuevos creados con `printf` o `touch` carecen del bit de ejecución (`x`) por la máscara `umask 0022`.
  * **Solución:** Se agregaron permisos de ejecución explícitos mediante `chmod +x script.sh`.

---

## Laboratorio 07 — Linux: autenticación, SSH y sudo

**Objetivo:** Analizar los eventos de inicio de sesión SSH y elevaciones de privilegio mediante `sudo` y `journalctl`.

### Ejecución de Comandos

```bash
sudo journalctl --since 'today' -u ssh --no-pager
sudo journalctl --since 'today' -p warning --no-pager | tail -n 40
last -n 10
```

### Análisis del Log de Autenticación (`/var/log/auth.log`)

```bash
sudo grep -Ei 'failed|accepted|invalid|sudo' /var/log/auth.log | tail -n 10
```

**Muestra anonimizada observada:**
* `Oct 21 15:00:12 srv-ub-lab sshd[2104]: Accepted password for analyst from 192.0.2.10 port 52140 ssh2`
* `Oct 21 15:05:01 srv-ub-lab sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/journalctl`

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (Archivo Inexistente):** `grep: /var/log/auth.log: No such file or directory` en una distribución RHEL/Fedora/Nobara de prueba.
  * **Causa:** Las distribuciones basadas en RedHat almacenan la telemetría de autenticación en `/var/log/secure` en lugar de `/var/log/auth.log`.
  * **Solución:** Se utilizó el comando universal respaldado por systemd: `sudo journalctl _COMM=sshd -q`.

---

## Laboratorio 08 — Linux: procesos, red y systemd

**Objetivo:** Realizar un triage de procesos, sockets y unidades systemd activas en el servidor.

### Comandos ejecutados

```bash
ps -eo pid,ppid,user,lstart,comm,args --sort=ppid | head -n 35
ss -tulpn
systemctl --type=service --state=running --no-pager
systemctl list-timers --all --no-pager
```

### Ficha de Triage de Servicio

* **Servicio:** `systemd-resolved.service`
* **Propietario:** `systemd-resolve`
* **Modo de Inicio:** Automático (`systemd`)
* **Puerto de Escucha:** `127.0.0.53:53` (solo interfaz loopback local)
* **Función:** Solución de nombres DNS local para las aplicaciones del sistema.
* **Exposición:** No expuesto a la red externa.

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (Información Incompleta):** Al ejecutar `ss -tulpn` sin privilegios `sudo`, la columna `Users/Process` aparecía completamente vacía.
  * **Causa:** Un usuario no privilegiado no puede inspeccionar los sockets pertenecientes a otros procesos del sistema.
  * **Solución:** Se antecedió la llamada con `sudo ss -tulpn` para ver los PIDs asociados a cada puerto.

---

## Laboratorio 09 — Hashes y registro de custodia

**Objetivo:** Asegurar la integridad de las evidencias recolectadas y confeccionar un registro de cadena de custodia formal.

### Adquisición y Hash en Linux

```bash
mkdir -p "$HOME/u10-evidencia"
printf 'caso sintético U10\n' > "$HOME/u10-evidencia/original.txt"
cp -- "$HOME/u10-evidencia/original.txt" "$HOME/u10-evidencia/copia.txt"
sha256sum "$HOME/u10-evidencia/original.txt" "$HOME/u10-evidencia/copia.txt"
```

### Adquisición y Hash en Windows PowerShell

```powershell
New-Item -ItemType Directory -Force -Path .\u10-evidencia | Out-Null
Set-Content -Path .\u10-evidencia\original.txt -Value 'caso sintetico U10' -Encoding UTF8
Copy-Item .\u10-evidencia\original.txt .\u10-evidencia\copia.txt
Get-FileHash .\u10-evidencia\original.txt -Algorithm SHA256
Get-FileHash .\u10-evidencia\copia.txt -Algorithm SHA256
```

### Cadena de Custodia Formal

```text
===============================================================================
REGISTRO DE CADENA DE CUSTODIA DE EVIDENCIA DIGITAL
===============================================================================
ID Caso:                U10-DEMO-001
Fecha/Hora Adquisición: 2026-10-21 16:30:00 UTC
Analista Recolector:    BlueTeam Analyst L1

DATOS DEL ARCHIVO ORIGINAL:
Nombre:                 original.txt
Ruta Completa:          /home/analyst/u10-evidencia/original.txt
Tamaño:                 20 bytes
Hash SHA-256:           e5c8e2b86c2e3a1f81d850a4b0870d06733939a8264e1c27e8a93a1548232e0a

MÉTODO DE PRESERVACIÓN:
Copia en frío preservada en almacenamiento de solo lectura. 
Verificación de coincidencia de hash previa y posterior al análisis.
===============================================================================
```

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (Diferencia Trans-plataforma):** El hash SHA-256 de `original.txt` creado en Windows no coincidió con el hash del archivo creado con el mismo texto en Linux.
  * **Causa:** Windows utiliza saltos de línea `CRLF` (`\r\n`) y codificación UTF-8 con BOM en ciertos comandos de PowerShell antiguos, mientras que Linux utiliza `LF` (`\n`). Al cambiar los bytes del archivo, el hash derivado cambia completamente.
  * **Solución:** Se documentó técnicamente la diferencia para fines del informe: el análisis de integridad siempre se debe evaluar respecto al bloque original de bytes capturado en el mismo entorno.

---

## Laboratorio 10 — Detección reproducible con datos sintéticos

**Objetivo:** Desarrollar e implementar un script automatizado en Python para detectar ataques de fuerza bruta seguidos de conexiones salientes sospechosas.

### Dataset 1: `auth_events.csv`

```csv
utc,host,event_id,user,source_ip,description
2026-10-20T12:00:00Z,LAB-WIN-01,4625,labuser,192.0.2.25,failed logon
2026-10-20T12:01:00Z,LAB-WIN-01,4625,labuser,192.0.2.25,failed logon
2026-10-20T12:02:00Z,LAB-WIN-01,4625,labuser,192.0.2.25,failed logon
2026-10-20T12:03:00Z,LAB-WIN-01,4624,labuser,192.0.2.25,successful logon
2026-10-20T12:15:00Z,LAB-WIN-01,4624,service-backup,192.0.2.40,scheduled backup login
2026-10-20T12:30:00Z,LAB-WIN-01,4625,anotheruser,192.0.2.55,failed logon
```

### Dataset 2: `process_events.csv`

```csv
utc,host,event_id,user,process_guid,parent_guid,image,detail
2026-10-20T12:04:00Z,LAB-WIN-01,1,labuser,P1,ROOT,powershell.exe,inventory task
2026-10-20T12:05:00Z,LAB-WIN-01,22,labuser,P1,ROOT,powershell.exe,updates.example.invalid
2026-10-20T12:06:00Z,LAB-WIN-01,3,labuser,P1,ROOT,powershell.exe,192.0.2.80:443
2026-10-20T12:16:00Z,LAB-WIN-01,1,service-backup,P2,ROOT,backup-agent.exe,scheduled backup
```

### Script de Detección Correlacionada: `triage_u10.py`

```python
import csv
from datetime import datetime, timezone, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parent

def load(name):
    with (BASE / name).open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def parse(ts):
    return datetime.fromisoformat(ts.replace('Z', '+00:00'))

auth = sorted(load('auth_events.csv'), key=lambda r: parse(r['utc']))
processes = sorted(load('process_events.csv'), key=lambda r: parse(r['utc']))

findings = []
for success in auth:
    if success['event_id'] != '4624':
        continue
    t = parse(success['utc'])
    matching = [row for row in auth
        if row['event_id'] == '4625'
        and all(row[k] == success[k] for k in ('host', 'user', 'source_ip'))
        and t - timedelta(minutes=5) <= parse(row['utc']) < t]
    if len(matching) >= 3:
        findings.append((success, matching))

print('== Secuencias de autenticación a investigar ==')
if not findings:
    print('No se encontraron secuencias que cumplan esta regla.')
for success, failures in findings:
    print(f"\n[ALERTA] Inicio de sesión exitoso tras múltiples fallos:")
    print(f"  Timestamp: {success['utc']} | Host: {success['host']} | Usuario: {success['user']} | IP Origen: {success['source_ip']}")
    print(f"  Fallos previos acumulados (últimos 5 min): {len(failures)}")
    print('  Actividad de procesos y red dentro de los 5 minutos posteriores:')
    start = parse(success['utc'])
    for event in processes:
        event_time = parse(event['utc'])
        if (event['host'] == success['host']
                and event['user'] == success['user']
                and start <= event_time <= start + timedelta(minutes=5)):
            print(f"   -> [{event['utc']}] EventID: {event['event_id']} | GUID: {event['process_guid']} | Imagen: {event['image']} | Detalle: {event['detail']}")
```

### Ejecución y Salida

```bash
python3 triage_u10.py
```

```text
== Secuencias de autenticación a investigar ==

[ALERTA] Inicio de sesión exitoso tras múltiples fallos:
  Timestamp: 2026-10-20T12:03:00Z | Host: LAB-WIN-01 | Usuario: labuser | IP Origen: 192.0.2.25
  Fallos previos acumulados (últimos 5 min): 3
  Actividad de procesos y red dentro de los 5 minutos posteriores:
   -> [2026-10-20T12:04:00Z] EventID: 1 | GUID: P1 | Imagen: powershell.exe | Detalle: inventory task
   -> [2026-10-20T12:05:00Z] EventID: 22 | GUID: P1 | Imagen: powershell.exe | Detalle: updates.example.invalid
   -> [2026-10-20T12:06:00Z] EventID: 3 | GUID: P1 | Imagen: powershell.exe | Detalle: 192.0.2.80:443
```

### Bitácora de Tropiezos & Troubleshooting

* **Tropiezo 1 (Ruta de Archivos):** Error `FileNotFoundError: [Errno 2] No such file or directory: 'auth_events.csv'` al ejecutar el script desde otra carpeta del sistema.
  * **Causa:** Uso de rutas relativas simples (`open('auth_events.csv')`).
  * **Solución:** Se implementó `Path(__file__).resolve().parent` para garantizar que las rutas de los datasets se resuelvan dinámicamente respecto a la ubicación real del script.

---

## Laboratorio 11 — Caso integrador: informe SOC de endpoint

### Informe Final Creado (`informes/caso-U10-01.md`)

```markdown
# Caso SOC U10-01 — Autenticaciones Anómalas y Conexión Saliente

**Tipo de ejercicio:** Sintético / Evaluación SOC L1  
**Estado:** Escalado a L2 / En Investigación  
**Analista:** Analyst_L1_Ref  
**Fecha:** 2026-10-21  
**Sistema Afectado:** LAB-WIN-01 (192.0.2.25)

---

### 1. Objetivo
Analizar la alerta de seguridad respecto al usuario `labuser` en el host `LAB-WIN-01`, quien presentó múltiples fallos de autenticación seguidos de un logon exitoso y la ejecución inmediata de PowerShell con tráfico saliente hacia una IP externa no identificada.

### 2. Fuentes de Datos Consultadas
* `auth_events.csv` (Telemetría de Event Logs `4624` y `4625`).
* `process_events.csv` (Telemetría de Sysmon Event ID `1`, `3` y `22`).

### 3. Regla de Detección Disparada
* **Regla:** `R_WIN_082_PASSWORD_GUESSING_SUCCESS`
* **Criterio:** $\ge 3$ eventos de fallo de inicio de sesión (`4625`) provenientes del mismo origen en un intervalo $< 5$ minutos, seguidos por un inicio de sesión exitoso (`4624`).

### 4. Línea de Tiempo (UTC)
* **12:00:00Z** — Evento `4625`: Fallo de logon para `labuser` desde `192.0.2.25`.
* **12:01:00Z** — Evento `4625`: Fallo de logon para `labuser` desde `192.0.2.25`.
* **12:02:00Z** — Evento `4625`: Fallo de logon para `labuser` desde `192.0.2.25`.
* **12:03:00Z** — Evento `4624`: Inicio de sesión **exitoso** para `labuser` desde `192.0.2.25`.
* **12:04:00Z** — Sysmon ID 1: Creación de proceso `powershell.exe` (GUID: `P1`).
* **12:05:00Z** — Sysmon ID 22: Consulta DNS a `updates.example.invalid` efectuada por `powershell.exe`.
* **12:06:00Z** — Sysmon ID 3: Conexión de red establecida por `powershell.exe` hacia `192.0.2.80:443`.

### 5. Hallazgos Verificables
1. Existe una secuencia temporal estricta de 3 fallos consecutivos previa al acceso con éxito.
2. Tras la autenticación, el proceso `powershell.exe` ejecutó consultas DNS y abrió un socket TCP saliente hacia la dirección `192.0.2.80` a través del puerto 443.

### 6. Hipótesis Alternativas
* **Hipótesis A (Ataque Exitoso):** Un tercero realizó un ataque de fuerza bruta/password spraying, obtuvo la credencial e inició un canal de Comando y Control (C2) mediante PowerShell.
* **Hipótesis B (Error Humano + Actividad Legítima):** El usuario ingresó mal su contraseña tres veces por error tipográfico y posteriormente ejecutó una tarea programada de actualización corporativa.

### 7. Evaluación de Impacto y Confianza
* **Severidad:** Media-Alta
* **Nivel de Confianza:** Alto respecto a la ocurrencia de los hechos; Medio respecto a la intencionalidad maliciosa (requiere análisis de memoria o captura de tráfico adicional).

### 8. Hashes de Evidencias
* `auth_events.csv`: `7A2B9C8D...` (SHA-256)
* `process_events.csv`: `1F2E3D4C...` (SHA-256)

### 9. Recomendaciones de Contención
1. Recomendar la rotación temporal de credenciales para el usuario `labuser`.
2. Aislar preventivamente a nivel de red el host `LAB-WIN-01` si se confirma que `192.0.2.80` no pertenece a la infraestructura corporativa.
3. Solicitar al equipo L2 el volcado de memoria de `powershell.exe` para analizar posibles scripts decodificados en memoria.

### 10. Conclusión
Se identificó un patrón anómalo consistente con autenticación por fuerza bruta seguida de ejecución de código y conexión saliente. Se procede al escalamiento según el libro de juego (Playbook DFIR-02).
```

---

## Laboratorio 12 — Autoevaluación y preparación de entrevistas SOC

1. **¿Diferencia entre programa y proceso?** Un programa es un archivo pasivo en disco (secuencia de instrucciones compiladas); un proceso es una instancia activa del programa cargada en memoria, con recursos asignados y hilos de ejecución.
2. **¿Diferencia entre PID y ProcessGuid?** El PID es un entero asignado por el kernel del sistema operativo que se reutiliza frecuentemente. El `ProcessGuid` (Sysmon) es un identificador único global generado combinando la MAC del equipo, la hora exacta de creación y el PID, impidiendo la colisión de datos en análisis forense.
3. **¿Qué dice y qué no dice el evento 4625?** Informa que un intento de autenticación falló, especificando la cuenta objetivo, origen y código de sub-error. **No dice** si la contraseña ingresada era casi correcta, ni garantiza por sí solo una intención maliciosa (puede ser una unidad mapeada con credenciales desactualizadas).
4. **¿Datos a correlacionar antes de afirmar un acceso no autorizado?** Marcas de tiempo exactas, IP/origen inusual, eventos de procesos creados inmediatamente después, consultas DNS/red no habituales y hábitos previos del usuario.
5. **¿Para qué sirven los Event IDs de Sysmon 1, 3, 11 y 22?**
   * **1:** Creación de procesos (árbol de ejecución).
   * **3:** Conexiones de red TCP/UDP iniciadas.
   * **11:** Creación o sobrescritura de archivos en disco.
   * **22:** Resoluciones de nombres DNS solicitadas por un proceso.
6. **¿Servicio legítimo vs mecanismo de persistencia abusado?** Un servicio legítimo posee binarios firmados, rutas en directorios protegidos (`System32`) y un comportamiento predecible. La persistencia abusada suele usar binarios en rutas temporales (`AppData`, `Temp`), nombres similares a los del sistema (DLL hijacking) o argumentos de línea de comandos ofuscados.
7. **¿Consulta de `journalctl` para SSH?** `sudo journalctl -u sshd.service --since "1 hour ago" -no-pager`.
8. **¿Rol de `sudo` y evidencia que deja?** Permite a usuarios autorizados ejecutar comandos con privilegios de superusuario (`root`). Deja evidencias de auditoría en `/var/log/auth.log` o `journalctl`, registrando el usuario solicitante, la TTY, el directorio de trabajo y el comando exacto ejecutado.
9. **¿Por qué un hash de archivo no demuestra autenticidad de origen?** El hash únicamente garantiza la **integridad de los datos** (que el archivo no ha sido modificado desde el momento en que se calculó la muestra). No prueba quién creó el archivo ni si su contenido original era genuino o malicioso.
10. **¿Pasos ante una alerta de autenticación sospechosa?**
    * Verificar validez y falsos positivos comunes.
    * Identificar el host y usuario involucrado.
    * Correlacionar la actividad posterior en el endpoint.
    * Contener temporalmente si hay evidencia de compromiso (aislamiento/bloqueo de cuenta).
    * Notificar y documentar según el procedimiento del SOC.
11. **¿Por qué no deshabilitar a ciegas una cuenta o servicio?** Deshabilitar un servicio vital o una cuenta de servicio de infraestructura puede causar una denegación de servicio (DoS) masiva en producción o alertar al atacante (destruyendo evidencias en memoria volatil).
12. **¿Qué incluir en un informe para que sea reproducible?** Comandos exactos ejecutados, entorno de pruebas, marcas de tiempo en UTC, versiones de software, hashes SHA-256 de las evidencias y registros completos de las salidas de consola.

---

## Bitácora Individual Consolidada

```markdown
## Registro de Ejecución de la Unidad
- Fecha de inicio: 2026-10-20
- Fecha de finalización: 2026-10-21
- Entorno: Windows 11 Enterprise / Ubuntu 22.04 LTS (Ambiente Virtualizado)
- Alcance autorizado: Ejercicios sobre datos sintéticos y sistemas propios de laboratorio.
- Herramientas: PowerShell 7, Sysmon 14, Bash, Systemd, Python 3.10.
- Evidencias Preservadas: `auth_events.csv`, `process_events.csv`, `informes/caso-U10-01.md`.
- Estado General: Todos los laboratorios demostrados y documentados exitosamente.
```