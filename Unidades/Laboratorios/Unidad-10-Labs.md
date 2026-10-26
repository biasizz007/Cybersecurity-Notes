# Laboratorios — Unidad 10: Windows y Linux para Blue Team

> **Carpeta del repositorio:** `laboratorios/Unidad-10-LABORATORIOS.md`  
> **Teoría:** [Unidad 10 — Windows y Linux](../Unidad-10/README.md)  
> **Objetivo:** aprender a recolectar e interpretar telemetría de endpoint para SOC L1 y DFIR inicial.  
> **Estado inicial:** todos los laboratorios **pendientes**; los escenarios y datasets son **sintéticos**.

## Reglas de seguridad y reproducibilidad que tendrias que tener en cuenta

1. Practicá únicamente en equipos propios o expresamente autorizados. No escanees ni alteres equipos ajenos.
2. Empezá en máquinas virtuales o equipos de laboratorio. Algunos ejercicios requieren acceso administrador **solo de lectura**.
3. No deshabilites antivirus, firewall, auditoría ni políticas de un sistema de trabajo. No realices cambios de cuentas o servicios fuera del entorno de laboratorio.
4. Registrá **fecha/hora, zona horaria, sistema operativo, versión, comando y salida observada**. No reemplaces resultados reales por ejemplos.
5. Antes de subir capturas, XML/EVTX, logs, PCAP o CSV a GitHub, anonimizá usuarios, IP privadas, tokens, secretos, dominios internos y datos personales. Si no estás seguro, publicá únicamente una muestra sintética.
6. Preservá los datos recolectados en una carpeta de evidencias y calculá SHA-256. Evitá editar la copia que querés conservar como original.
7. Si un comando no funciona, documentá el error y la causa probable: es parte del aprendizaje.

## Estructura de práctica recomendada

```text
SOC-Labs/
└── U10-endpoint-investigation/
    ├── README.md
    ├── informes/
    │   └── caso-U10-01.md
    ├── scripts/
    └── evidencias-sinteticas/
        ├── auth_events.csv
        └── process_events.csv
```

No publiques datos reales sensibles. Guardá las evidencias completas en un directorio privado y referenciá en el informe únicamente su hash y una versión redactada.

## Seguimiento

| ID | Práctica | Estado | Resultado para portfolio |
|---|---|---|---|
| 00 | Preparación y baseline | [ ] | Inventario seguro |
| 01 | Identidades y grupos Windows | [ ] | Matriz de privilegios |
| 02 | Procesos y conexiones Windows | [ ] | Tabla PID/conexión |
| 03 | Windows Event Logs: 4624/4625 | [ ] | Investigación de acceso |
| 04 | Sysmon y árbol de procesos | [ ] | Correlación proceso/DNS/red |
| 05 | Windows: servicios y tareas | [ ] | Comparación de baseline |
| 06 | Linux: usuarios y permisos | [ ] | Evaluación de acceso |
| 07 | Linux: journal, SSH y sudo | [ ] | Línea temporal |
| 08 | Linux: procesos, conexiones y systemd | [ ] | Triage de servidor |
| 09 | Hashes y cadena de custodia | [ ] | Registro de integridad |
| 10 | Detección con dataset sintético | [ ] | Script y hallazgos |
| 11 | Caso integrador SOC | [ ] | Informe profesional |
| 12 | Revisión y preparación entrevistas | [ ] | Autoevaluación técnica |

---

## Laboratorio 00 — Preparar el entorno y establecer baseline

**Objetivo:** disponer de un entorno controlado e inventariar su estado antes de investigar anomalías. **Tiempo orientativo:** 45–75 minutos.

**Requisitos:** Windows 10/11 o Windows Server de laboratorio y/o Linux con systemd; terminal y cuenta de usuario estándar. Una VM por SO es suficiente para comenzar. No es obligatorio tener ambas VMs para la primera semana.

### Windows (PowerShell)

```powershell
$PSVersionTable.PSVersion
Get-ComputerInfo | Select-Object CsName,WindowsProductName,OsVersion
Get-Date -Format o
Get-NetIPConfiguration
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
```

### Linux

```bash
uname -a
cat /etc/os-release
date --iso-8601=seconds
date -u --iso-8601=seconds
ip -brief address
ip route
```

### Evidencia a registrar

- SO, versión y fecha/hora; zona horaria.
- Usuario utilizado y permisos de ejecución.
- Interfaces y rutas (anonimizadas si se publican).
- Estado del firewall sin modificarlo.
- Qué componentes no están instalados (por ejemplo Sysmon o auditd).

**Resultado esperado:** inventario mínimo y baseline documentado. **Criterio de éxito:** poder repetir los comandos y comparar la nueva salida con la inicial.

---

## Laboratorio 01 — Identidades y privilegios en Windows

**Objetivo:** distinguir cuenta, grupo, SID, token y privilegios. **Tiempo:** 45–60 minutos.

```powershell
whoami /user
whoami /groups
whoami /priv
Get-LocalUser | Select-Object Name,Enabled,LastLogon
Get-LocalGroup
```

Para inspeccionar miembros de un grupo administrativo, identificá el nombre real del grupo local; puede estar traducido:

```powershell
Get-LocalGroup | Where-Object { $_.SID -like 'S-1-5-32-544' }
```

Si existe, inspeccionar con el nombre devuelto:

```powershell
# Reemplazar NOMBRE_GRUPO por el nombre observado
Get-LocalGroupMember -Group 'NOMBRE_GRUPO'
```

### Preguntas de investigación

1. ¿Cuál es el SID de tu cuenta? ¿Es distinto del nombre visible?
2. ¿Qué grupos aparecen? ¿Cuáles implican privilegios adicionales?
3. ¿La consola está elevada? ¿Cómo lo comprobaste?
4. ¿Qué cuentas están habilitadas pero no se utilizan? No cambies su estado en este ejercicio.

**Resultado esperado:** mapa básico de cuentas y grupos del equipo. **Precaución:** `Get-LocalUser` puede no funcionar en un controlador de dominio u otros entornos; documentar la limitación.

---

## Laboratorio 02 — Procesos y conexiones en Windows

**Objetivo:** correlacionar procesos con puertos y destinos sin concluir prematuramente que son maliciosos. **Tiempo:** 60–90 minutos.

```powershell
Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,CommandLine |
  Sort-Object ProcessId
```

```powershell
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
```

Para un PID existente que hayas observado:

```powershell
$TargetPid = 1234     # Reemplazar por un PID real de tu equipo
Get-Process -Id $TargetPid -ErrorAction SilentlyContinue |
  Select-Object Name,Id,Path,StartTime
```

### Preguntas

- ¿Cuál es la diferencia entre PID y PPID?
- ¿Cómo asociarías una conexión con un proceso sin confundir PID reutilizados?
- ¿Una conexión a `443` prueba que está usando HTTPS? No; el puerto es una pista, no una garantía.
- ¿Por qué un comando puede devolver conexiones que desaparecen inmediatamente?

**Evidencia:** tabla redactada `hora_utc | pid | proceso | destino | puerto | interpretación | limitaciones`.

---

## Laboratorio 03 — Windows Event Logs: inicios de sesión

**Objetivo:** aprender a consultar `4624` y `4625`, y distinguir observación de interpretación. **Tiempo:** 90 minutos.

### Paso 1. Verificar que existe el canal

```powershell
Get-WinEvent -ListLog Security
```

### Paso 2. Consultar eventos recientes

```powershell
$Start = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4624,4625; StartTime=$Start
} -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,ProviderName,Message
```

**Nota:** leer Security puede requerir permisos; 4625 debe estar cubierto por política de auditoría. Un resultado vacío no prueba ausencia de fallos.

### Paso 3. Interpretar

En eventos que realmente estén presentes, documentá: usuario, `Logon Type`, origen si se conoce, hora y resultado. Evitá copiar campos de cuentas de terceros al repositorio.

| Tipo de logon | Significado frecuente |
|---|---|
| 2 | Interactivo |
| 3 | Red |
| 5 | Servicio |
| 10 | Interactivo remoto |

### Paso 4. Hipótesis

Explicá cómo diferenciarías: usuario que se equivocó de contraseña, servicio con credencial desactualizada, intentos automatizados y ataque dirigido. Indicá qué eventos adicionales buscarías y qué información te falta.

**Criterio de éxito:** informe breve con al menos una observación real o, si no hay eventos, documentación del motivo y análisis sobre un caso sintético del Lab 10.

---

## Laboratorio 04 — Sysmon: procesos, DNS y red

**Objetivo:** entender la telemetría de Sysmon y correlacionar eventos. **Tiempo:** 90–120 minutos.

**Prerequisito:** Sysmon instalado en una VM propia y configurado según una política conocida. No es obligatorio instalarlo para completar el ejercicio conceptual: si no está disponible, utilizá el dataset sintético del laboratorio 10.

### Consulta de existencia

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
```

### Eventos disponibles

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,11,22
} -MaxEvents 40 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,Id,Message
```

**Nota:** Sysmon Event ID 3 requiere activación según configuración y puede generar mucho volumen. No habilitar captura indiscriminada en producción.

### Investigación

Para un proceso de prueba propio (por ejemplo abrir un editor de texto), intentá identificar:

1. Evento de creación de proceso (`1`).
2. `ProcessGuid`, `ParentProcessGuid`, imagen y command line.
3. Si corresponde, consulta DNS (`22`).
4. Si corresponde, conexión (`3`).
5. Evidencia de archivo creado (`11`).

**Resultado esperado:** una tabla con eventos correlacionados. Es perfectamente válido que no haya DNS ni red si la aplicación no los usa. **Nunca inventar un evento para completar la secuencia.**

---

## Laboratorio 05 — Baseline de servicios y tareas Windows

**Objetivo:** reconocer mecanismos de inicio automático sin alterarlos. **Tiempo:** 60 minutos.

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

**Preguntas:** ¿por qué un servicio automático no es persistencia maliciosa por sí solo? ¿Qué campos harían sospechoso un cambio? ¿Qué autorización necesitarías para deshabilitarlo? **No deshabilitar ningún servicio o tarea.**

**Opcional:** repetir después de instalar un programa legítimo en una VM y comparar los archivos, teniendo en cuenta que un CSV puede cambiar por orden, software de fondo o actualización.

---

## Laboratorio 06 — Identidades y permisos en Linux

**Objetivo:** reconocer UID, GID, permisos y privilegios. **Tiempo:** 60 minutos.

```bash
id
whoami
groups
pwd
umask
```

Crear material de prueba en el HOME, nunca sobre archivos de sistema:

```bash
mkdir -p "$HOME/u10-practica"
printf 'evidencia de prueba\n' > "$HOME/u10-practica/demo.txt"
ls -l "$HOME/u10-practica/demo.txt"
stat "$HOME/u10-practica/demo.txt"
sha256sum "$HOME/u10-practica/demo.txt"
```

### Actividad

1. Interpretar `-rw-r--r--` u otro modo efectivo que aparezca.
2. Explicar propietario, grupo y otros.
3. Identificar por qué `umask` afecta permisos iniciales.
4. Explicar la diferencia entre leer un archivo y atravesar un directorio.

**Éxito:** tabla de permisos observados y explicación del riesgo de permisos excesivos.

---

## Laboratorio 07 — Linux: autenticación, SSH y sudo

**Objetivo:** construir una línea temporal de autenticaciones. **Tiempo:** 75–90 minutos.

```bash
sudo journalctl --since 'today' -u ssh --no-pager
sudo journalctl --since 'today' -u sshd --no-pager
sudo journalctl --since 'today' -p warning --no-pager | tail -n 40
last -n 10
```

Unidades `ssh` / `sshd`, archivos y herramientas disponibles dependen de la distribución. Los logs pueden no existir si el sistema no tiene servidor SSH.

Si hay un archivo de autenticación disponible:

```bash
sudo grep -Ei 'failed|accepted|invalid|sudo' /var/log/auth.log | tail -n 40
```

En algunas distribuciones corresponde `/var/log/secure`. No modificar configuraciones para fabricar fallos de autenticación en un servidor ajeno. Podés limitarte a revisar un inicio de sesión exitoso propio en tu VM.

**Documentar:** fuente, zona horaria, usuario anonimizado, IP anonimizada, resultado, ambigüedades y eventos faltantes.

---

## Laboratorio 08 — Linux: procesos, red y systemd

**Objetivo:** relacionar procesos, sockets y servicios. **Tiempo:** 60–90 minutos.

```bash
ps -eo pid,ppid,user,lstart,comm,args --sort=ppid | head -n 35
ss -tulpn
systemctl --type=service --state=running --no-pager
systemctl list-timers --all --no-pager
ip route
```

### Tareas

1. Seleccionar un servicio del sistema y explicar su función.
2. Averiguar si escucha en una interfaz de red o solo localmente.
3. Consultar sus logs con `journalctl -u nombre-servicio`.
4. Compararlo con la baseline del Lab 00.

**Criterio de éxito:** una ficha por servicio: nombre, propietario, modo de inicio, puerto, función y exposición observable. No inventar un puerto si el servicio no escucha.

---

## Laboratorio 09 — Hashes y registro de custodia

**Objetivo:** preservar y verificar integridad de archivos de investigación. **Tiempo:** 60 minutos.

### Linux

```bash
mkdir -p "$HOME/u10-evidencia"
printf 'caso sintético U10\n' > "$HOME/u10-evidencia/original.txt"
cp -- "$HOME/u10-evidencia/original.txt" "$HOME/u10-evidencia/copia.txt"
sha256sum "$HOME/u10-evidencia/original.txt" "$HOME/u10-evidencia/copia.txt"
```

### Windows PowerShell (alternativa)

```powershell
New-Item -ItemType Directory -Force -Path .\u10-evidencia | Out-Null
Set-Content -Path .\u10-evidencia\original.txt -Value 'caso sintetico U10' -Encoding UTF8
Copy-Item .\u10-evidencia\original.txt .\u10-evidencia\copia.txt
Get-FileHash .\u10-evidencia\original.txt -Algorithm SHA256
Get-FileHash .\u10-evidencia\copia.txt -Algorithm SHA256
```

No esperes que el hash del archivo Windows coincida necesariamente con el del archivo Linux: codificación y finales de línea pueden cambiar. La comparación correcta aquí es original contra copia **en el mismo entorno**.

### Prueba de integridad

Modificar **solo la copia** y recalcular el hash. Explicar por qué cambia. Verificar que el hash del original permanezca igual.

### Cadena de custodia

```text
ID caso: U10-DEMO-001
Adquisición: archivo creado intencionalmente en laboratorio
Origen y ruta:
Equipo / SO / versión:
Recolector:
Hora local y zona:
Hora UTC:
Método:
Herramienta y versión:
Hash SHA-256 original:
Hash SHA-256 copia:
Accesos/transferencias:
Limitaciones: evidencia sintética, no adquirida de incidente real
```

**Criterio de éxito:** igualdad inicial original-copia, diferencia posterior al modificar copia y registro verificable de cómo se obtuvo la evidencia.

---

## Laboratorio 10 — Detección reproducible con datos sintéticos

**Objetivo:** encontrar una secuencia sospechosa sin atribuir automáticamente un ataque. **Tiempo:** 90–120 minutos. **Requisito:** Python 3.9+ (solo biblioteca estándar).

**Como lo resolvi ?**

### Dataset 1: `auth_events.csv`

Cree el archivo con este contenido:

```csv
utc,host,event_id,user,source_ip,description
2026-10-20T12:00:00Z,LAB-WIN-01,4625,labuser,192.0.2.25,failed logon
2026-10-20T12:01:00Z,LAB-WIN-01,4625,labuser,192.0.2.25,failed logon
2026-10-20T12:02:00Z,LAB-WIN-01,4625,labuser,192.0.2.25,failed logon
2026-10-20T12:03:00Z,LAB-WIN-01,4624,labuser,192.0.2.25,successful logon
2026-10-20T12:15:00Z,LAB-WIN-01,4624,service-backup,192.0.2.40,scheduled backup login
2026-10-20T12:30:00Z,LAB-WIN-01,4625,anotheruser,192.0.2.55,failed logon
```

Las IP que use en este caso (`192.0.2.0/24`) son usadas de ejemplo que use para documentación. Este dataset no viene de personas ni sistemas reales.

### Dataset 2: `process_events.csv`

```csv
utc,host,event_id,user,process_guid,parent_guid,image,detail
2026-10-20T12:04:00Z,LAB-WIN-01,1,labuser,P1,ROOT,powershell.exe,inventory task
2026-10-20T12:05:00Z,LAB-WIN-01,22,labuser,P1,ROOT,powershell.exe,updates.example.invalid
2026-10-20T12:06:00Z,LAB-WIN-01,3,labuser,P1,ROOT,powershell.exe,192.0.2.80:443
2026-10-20T12:16:00Z,LAB-WIN-01,1,service-backup,P2,ROOT,backup-agent.exe,scheduled backup
```

El dominio `.invalid`(#3) es deliberadamente no resoluble. Los nombres de imágenes y GUID aca son simplificaciones de ejemplo, **no exportaciones nativas de Sysmon**.

### Script `triage_u10.py`

```python
import csv
from collections import defaultdict
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

# Regla didáctica: >= 3 fallos mismo host/usuario/IP en 5 min,
# seguidos de un éxito dentro de los siguientes 5 min.
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
    print(f"{success['utc']} host={success['host']} "
          f"user={success['user']} ip={success['source_ip']} "
          f"fallos_previos={len(failures)}")
    print('  Eventos de proceso y red en los siguientes 5 minutos:')
    start = parse(success['utc'])
    for event in processes:
        event_time = parse(event['utc'])
        if (event['host'] == success['host']
                and event['user'] == success['user']
                and start <= event_time <= start + timedelta(minutes=5)):
            print('  ', event['utc'], event['event_id'],
                  event['process_guid'], event['image'], event['detail'])
```

### Despues ejecute

```bash
python3 triage_u10.py
```

en linux o en caso de Windows podes usar:

```powershell
py .\triage_u10.py
```

**Salida esperada:** una secuencia al `labuser` desde `192.0.2.25` con tres fallos previos y un éxito, junto con los eventos de PowerShell asociados temporalmente. La regla no valida el tipo de logon, dispositivo, causa ni legitimidad de las acciones: es un **hallazgo para investigar** y no una confirmación de intrusión.

### Mejoras propuestas

- Exigir mismo `LogonId` donde tenga sentido y esté disponible; advertir si no existe.
- Incorporar tipo de logon, `ProcessGuid`, baseline, ticket de cambio.
- Agregar un dataset con un falso positivo (usuario que olvidó contraseña).
- Evaluar el impacto de retrasos en eventos, fuentes faltantes y zonas horarias.
- Reemplazar datasets simulados por exportaciones **anonimizadas** de un laboratorio propio.

### Preguntas que me gustaron y pueden analizar mejor el problema

1. ¿Por qué tres fallos y un éxito no prueban fuerza bruta?
2. ¿Qué evidencia necesitarías para atribuir la ejecución posterior al mismo inicio de sesión?
3. ¿Qué aporta `ProcessGuid` que no aporta solo PID?
4. ¿Qué pasaría si el SIEM recibe eventos con 15 minutos de retraso?

---

## Laboratorio 11 — Caso integrador: informe SOC de endpoint

**Objetivo:** producir una investigación técnica presentable sin inventar un incidente. **Tiempo:** 2–3 horas.

### Consigna

Utilizá los datasets sintéticos del Lab 10 y, si ya ejecutaste los anteriores, anexá de forma separada observaciones reales anonimizadas de tus VMs. No mezcles ambas fuentes como si fueran un mismo evento.

### Contexto del caso

En `LAB-WIN-01` se observan tres fallos de autenticación, luego un éxito y actividad de un proceso con consultas DNS y tráfico saliente. Existe una tarea de backup habitual cercana en el tiempo. El caso es ambiguo por diseño.

### Procedimiento de investigación

1. Clasificar la alerta inicial: nombre, período y regla de detección.
2. Construir una línea de tiempo en UTC de ambos CSV.
3. Distinguir `labuser` de `service-backup`.
4. Describir qué evidencia vincula o no vincula proceso, red y autenticación.
5. Elaborar **al menos dos hipótesis**: actividad legítima; posible abuso de credenciales.
6. Definir qué evidencia adicional se solicitaría: logs de identidad, proceso padre, comando completo, hash, destino, tickets de cambio, firewall, proxy.
7. Valorar severidad **provisional** y nivel de confianza; justificar ambos.
8. Sugerir acciones **condicionadas a confirmación y autorización**, evitando bloquear equipos automáticamente.
9. Crear informe y explicar limitaciones.

### Formato para `SOC-Labs/U10-endpoint-investigation/informes/caso-U10-01.md`

```markdown
# Caso SOC U10-01 — Autenticaciones y actividad del endpoint

**Tipo de ejercicio:** sintético / aprendizaje
**Estado:** En análisis
**Analista:** [alias]
**Fecha:** [AAAA-MM-DD]
**Sistema:** LAB-WIN-01 (simulado)

## 1. Objetivo
## 2. Fuentes de datos y limitaciones
## 3. Regla que generó el hallazgo
## 4. Línea de tiempo UTC
## 5. Hallazgos verificables
## 6. Hipótesis alternativas
## 7. Evaluación de impacto y confianza
## 8. Evidencia y hashes de archivos
## 9. Recomendaciones y escalamiento propuesto
## 10. Conclusión (sin atribuir ataque sin pruebas)
## 11. Qué aprendí y qué mejoraré
```

### Rúbrica de evaluación (20 puntos)

| Criterio | Puntos |
|---|---:|
| Línea temporal correcta y fuentes identificadas | 4 |
| Diferencia hechos de hipótesis | 4 |
| Correlación identidad/proceso/red | 4 |
| Evidencia, integridad y privacidad | 4 |
| Informe claro, límites y acciones justificadas | 4 |

**Objetivo de dominio:** 16/20 o más y revisión de todos los errores.

---

## Laboratorio 12 — Autoevaluación y preparación de entrevista SOC

**Objetivo:** poder explicar lo que hiciste. **Tiempo:** 45 minutos.

Respondé por escrito, con ejemplos de tu laboratorio:

1. ¿Cuál es la diferencia entre programa y proceso?
2. ¿Qué diferencia existe entre PID y ProcessGuid?
3. ¿Qué te dice y qué no te dice el evento 4625?
4. ¿Qué datos correlacionarías antes de afirmar que hubo acceso no autorizado?
5. ¿Para qué sirven Sysmon Event ID 1, 3, 11 y 22?
6. ¿Qué diferencia existe entre servicio legítimo y mecanismo de persistencia abusado?
7. ¿Qué consulta de `journalctl` usarías para revisar SSH?
8. ¿Qué rol cumple `sudo`? ¿Qué evidencia puede dejar?
9. ¿Por qué un hash de archivo no demuestra autenticidad de origen?
10. ¿Qué pasos seguirías ante una alerta de autenticación sospechosa?
11. ¿Por qué no hay que deshabilitar a ciegas una cuenta o servicio?
12. ¿Qué pondrías en un informe para que otro analista reproduzca tu investigación?

### Cierre de progreso

Marcar cada competencia como **estudiada**, **practicada** o **demostrada** solamente después de cumplirla. Agregar enlaces a evidencias sanitizadas e informe en el README principal de tu repositorio.

---

## Bitácora individual de laboratorio

Copiar esta plantilla para **cada** práctica:

```markdown
## Lab [ID] — [Título]
- Fecha, hora y zona horaria:
- Objetivo:
- SO / versión / entorno:
- Alcance autorizado:
- Herramientas y versiones:
- Comandos utilizados:
- Resultado esperado:
- Resultado real observado:
- Evidencias y SHA-256:
- Interpretación defensiva:
- Qué no puedo concluir:
- Errores y solución:
- Referencias:
- Estado: pendiente / ejecutado / demostrado
```

## Referencias

- [Guía teórica — Unidad 10](../Unidad-10/README.md)
- [Microsoft — Windows Security Events](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference)
- [Microsoft — Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft — Sysmon Events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [systemd — journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
- [MITRE ATT&CK](https://attack.mitre.org/)

**Nota final:** los resultados esperados no sustituyen capturas ni observaciones reales. No se han ejecutado los ejercicios en el equipo del estudiante. La honestidad documental es un componente central del trabajo SOC y DFIR.


