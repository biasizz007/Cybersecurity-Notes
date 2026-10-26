# Unidad 7 — Laboratorios Blue Team: autenticación, sesiones e investigación SOC

> **Perfil objetivo:** SOC Analyst Junior / L1, primeros pasos en Incident Response y DFIR.  
> **Regla de trabajo:** ejecutar únicamente en equipos propios, cuentas creadas para práctica o entornos expresamente autorizados.

## Cómo utilizar este manual

Cada laboratorio incluye **objetivo, requisitos, procedimiento, observaciones esperadas, interpretación, evidencias y criterios de finalización**. Los resultados esperados son hipótesis didácticas: no afirmes que los obtuviste hasta ejecutarlos. Si una edición de Windows carece de determinados logs, documentá esa limitación y utilizá el laboratorio sintético.

**Seguridad/privacidad:** jamás publiques contraseñas, cookies, tokens, claves privadas, datos personales o capturas completas de producción. Editá datos sensibles en copias de presentación; conservá las evidencias originales bajo acceso controlado. No modifiques registros originales; trabajá sobre copias y documentá cada acción.

## Índice

1. [Preparación del laboratorio y estructura de evidencias](#laboratorio-0--preparación)
2. [Windows: logons exitosos, fallidos y tipos](#laboratorio-1--windows-logons)
3. [Linux: autenticaciones SSH y sudo](#laboratorio-2--linux-ssh-y-sudo)
4. [Detectar un posible password spraying con datos sintéticos](#laboratorio-3--spraying-sintético)
5. [Correlación SOC: fallos, éxito y privilegios](#laboratorio-4--correlación-de-eventos)
6. [Sesiones web y atributos de cookies](#laboratorio-5--sesiones-y-cookies)
7. [JWT: estructura y límites de confianza](#laboratorio-6--jwt-sintético)
8. [MFA: inventario, recuperación y amenazas](#laboratorio-7--evaluación-de-mfa)
9. [Integridad y cadena de custodia de exportaciones](#laboratorio-8--integridad-forense)
10. [Control de acceso y mínimo privilegio](#laboratorio-9--matriz-rbac)
11. [Escribir una regla de detección y probar falsos positivos](#laboratorio-10--ingeniería-de-detección)
12. [Investigación final de identidad comprometida](#laboratorio-11--caso-integrador)
13. [Plantillas, criterios de calidad y roadmap](#plantillas-de-entrega-y-evaluación)

---

## Laboratorio 0 — Preparación

**Objetivo:** crear un entorno controlado para registrar resultados defendibles.

**Herramientas gratuitas recomendadas:** Windows 10/11 o Windows Server de laboratorio (según licencias disponibles), Linux VM (Ubuntu/Debian), Python 3, PowerShell, terminal, Wireshark opcional, editor Markdown. No es necesario instalar un SIEM para comenzar.

**Estructura propuesta** (crear dentro de un repositorio de práctica o una carpeta privada):

```text
Unidad-07/
├── README.md
├── LABORATORIOS.md
└── evidencias/                # No subir datos sensibles
    ├── lab-01/
    │   ├── registro.md
    │   ├── export-redactado.csv
    │   └── sha256.txt
    └── lab-11/
        ├── timeline.md
        ├── informe.md
        └── hashes.txt
```

**Preparación paso a paso**

1. Anotá sistema operativo, versión, zona horaria, hostname de laboratorio y herramientas.
2. Confirmá que es un sistema propio y que tenés permisos para revisar sus logs.
3. Creá una carpeta para resultados y otra para copias de evidencia.
4. Registrá fecha/hora de cada acción. Preferí UTC en tablas de correlación.
5. Creá un diario de laboratorio (`registro.md`) donde separes **comando**, **salida**, **interpretación** y **limitación**.

**Criterio de finalización:** el entorno y la metodología de evidencia están documentados.

## Laboratorio 1 — Windows logons

**Objetivo:** distinguir inicios de sesión exitosos y fallidos, identificar tipo y fuente y reconocer límites de visibilidad.

**Requisitos:** Windows propio, PowerShell, permisos suficientes. La generación/retención de eventos depende de política de auditoría.

### Procedimiento

1. Abrí **Visor de eventos → Registros de Windows → Seguridad**.
2. Buscá eventos `4624` y `4625`. También podés consultar sin modificar configuraciones:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddDays(-3)} -MaxEvents 50 |
  Select-Object TimeCreated, Id, MachineName, Message |
  Format-List
```

3. **Solo si tenés una cuenta de prueba**: cerrá sesión en ella e intentá una única autenticación errónea; después iniciá sesión con la credencial correcta. No generes intentos masivos ni afectes cuentas de otras personas.
4. Consultá nuevamente los eventos. El orden y disponibilidad dependen de Windows, credenciales locales/dominio y auditoría.
5. Anotá al menos:
   - `TimeCreated`
   - `Event ID`
   - Nombre de cuenta
   - `LogonType`
   - Dirección o equipo de origen, **si está presente**
   - `Status/SubStatus` para errores, **si está presente**.

### Interpretación

- `4624`: autenticación o inicio de sesión registrado correctamente en el contexto de Windows; no implica que se haya utilizado una aplicación web.
- `4625`: intento fallido; no prueba intención maliciosa.
- `LogonType=2`: interactivo; `3`: red; `10`: remoto interactivo. Algunos campos de red pueden aparecer vacíos.

### Evidencia y entregable

Guardá una tabla redactada con dos eventos o, si no aparecen, un registro de la limitación. Prepará tres hipótesis posibles para un `4625` (error humano, credencial obsoleta, abuso de acceso) y anotá una comprobación para cada una.

**Resultado esperado:** identificar diferencias observables sin inventar eventos ausentes.

## Laboratorio 2 — Linux SSH y sudo

**Objetivo:** identificar fuentes de autenticación en Linux y correlacionar eventos con un servicio.

**Requisitos:** VM Linux propia. No es necesario exponer SSH a Internet.

### Procedimiento

1. Verificá sistema y servicio:

```bash
cat /etc/os-release
systemctl status ssh --no-pager 2>/dev/null || systemctl status sshd --no-pager
```

2. Revisá eventos con `journalctl` si aplica:

```bash
sudo journalctl --since '24 hours ago' --no-pager | grep -Ei 'sshd|sudo|authentication|failed password|accepted'
```

3. Según distribución, también podés comprobar **sin asumir que existen**:

```bash
sudo test -f /var/log/auth.log && sudo tail -n 80 /var/log/auth.log
sudo test -f /var/log/secure && sudo tail -n 80 /var/log/secure
```

4. Generá un evento **legítimo y controlado** ejecutando una acción administrativa propia, por ejemplo:

```bash
sudo -v
```

5. Localizá el registro correspondiente y anotá zona horaria, cuenta, comando (si figura), método y resultado.

### Análisis

La salida de `sudo` no es equivalente a un login SSH. Si no existe servicio SSH no inventes logs de conexión. Una línea de log no confirma todas las acciones posteriores del proceso.

**Entregable:** captura redactada de un evento real de laboratorio, explicación de su origen y dos limitaciones.

## Laboratorio 3 — Spraying sintético

**Objetivo:** detectar el patrón de una IP con múltiples cuentas afectadas, evitando realizar ataques a servicios reales.

**Requisitos:** Python 3 estándar; funciona sin red.

### Paso 1 — Crear datos ficticios

Guardá como `analisis_login.py`:

```python
import csv
from io import StringIO
from collections import defaultdict
from datetime import datetime, timezone

DATA = '''timestamp,user,source_ip,result
2026-10-20T09:00:00Z,ana,192.0.2.10,failed
2026-10-20T09:01:00Z,luis,192.0.2.10,failed
2026-10-20T09:02:00Z,sofia,192.0.2.10,failed
2026-10-20T09:03:00Z,pedro,192.0.2.10,failed
2026-10-20T09:04:00Z,maria,192.0.2.10,failed
2026-10-20T09:05:00Z,ana,198.51.100.22,success
2026-10-20T09:06:00Z,backup,192.0.2.30,failed
2026-10-20T09:07:00Z,backup,192.0.2.30,failed
'''
rows = list(csv.DictReader(StringIO(DATA)))
start = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
end = datetime(2026, 10, 20, 9, 15, tzinfo=timezone.utc)
by_ip = defaultdict(lambda: {'events': 0, 'users': set()})
for r in rows:
    at = datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00'))
    if start <= at < end and r['result'] == 'failed':
        x = by_ip[r['source_ip']]
        x['events'] += 1
        x['users'].add(r['user'])
for ip, d in sorted(by_ip.items()):
    print(f'{ip}: fallos={d["events"]}, usuarios_distintos={len(d["users"])}')
    if len(d['users']) >= 5:
        print('  -> CANDIDATO DE INVESTIGACIÓN: múltiples usuarios')
```

### Paso 2 — Ejecutar

```bash
python3 analisis_login.py
```

En Windows también puede utilizarse `py analisis_login.py` si Python está instalado.

### Resultado esperado

```text
192.0.2.10: fallos=5, usuarios_distintos=5
  -> CANDIDATO DE INVESTIGACIÓN: múltiples usuarios
192.0.2.30: fallos=2, usuarios_distintos=1
```

### Interpretación Blue Team

- La primera IP presenta un patrón **compatible** con spraying.
- La segunda presenta repetición sobre una sola cuenta, no el mismo patrón.
- El éxito desde otra IP no demuestra automáticamente relación con los fallos.
- Umbral de 5 usuarios/15 minutos es **solo didáctico**, no una regla lista para producción.

**Entregable:** salida real, hipótesis de falsos positivos (NAT/proxy, sistema mal configurado) y propuesta para enriquecer con dispositivo y tipo de aplicación.

## Laboratorio 4 — Correlación de eventos

**Objetivo:** construir una línea de tiempo y separar hechos de hipótesis.

### Dataset sintético

```csv
utc,event_id,user,source_ip,host,detail
2026-10-20T10:01:00Z,4625,operador1,192.0.2.5,SRV-01,fallo
2026-10-20T10:02:00Z,4625,operador2,192.0.2.5,SRV-01,fallo
2026-10-20T10:03:00Z,4625,operador3,192.0.2.5,SRV-01,fallo
2026-10-20T10:06:00Z,4624,operador2,198.51.100.10,SRV-01,LogonType=10
2026-10-20T10:09:00Z,4732,operador2,,SRV-01,alta a grupo sensible (simulada)
```

### Procedimiento

1. Copiá el dataset en `eventos_sinteticos.csv`.
2. Ordená por hora UTC y generá `timeline.md`.
3. Marcá para cada evento **fuente**, **hecho**, **hipótesis** y **dato faltante**.
4. Contesta: ¿qué vincula o separa los orígenes? ¿qué evidencia necesitás de VPN/IdP? ¿quién aprobó el cambio de grupo?
5. Proponé una severidad provisional y justificá impacto/incertidumbre.

**Advertencia:** el CSV es inventado y no reproduce todos los campos de Windows. No debe etiquetarse como exportación nativa.

**Entregable:** timeline más un párrafo de conclusión: «sospecha no confirmada / incidente confirmado», fundamentado.

## Laboratorio 5 — Sesiones y cookies

**Objetivo:** diferenciar estado HTTP, cookies y protecciones del navegador sin recolectar sesiones ajenas.

**Requisitos:** navegador moderno; aplicación propia o ejemplos locales. No copiar cookies autenticadas reales a GitHub.

### Parte A — Clasificación teórica

Analizá estas cabeceras **ficticias**:

```http
Set-Cookie: demo_session=EJEMPLO_NO_REAL; Path=/; HttpOnly; Secure; SameSite=Lax
Set-Cookie: theme=dark; Path=/; SameSite=Lax
```

Responder:

1. ¿Cuál es un identificador de sesión ilustrativo y cuál una preferencia?
2. ¿Qué reduce `Secure`?
3. ¿Qué reduce `HttpOnly` y qué **no** soluciona?
4. ¿Qué limitación conserva `SameSite=Lax`?
5. ¿Quién debe invalidar una sesión al cerrar sesión?

### Parte B — Inspección local opcional

1. Abrí las herramientas de desarrollo del navegador en una web **propia** o local.
2. Entrá a Application/Storage → Cookies (nomenclatura según navegador).
3. Registrá solamente **nombres y atributos**, nunca valores reales.
4. Si observás una cookie sin `HttpOnly`, no concluyas automáticamente vulnerabilidad: puede ser una preferencia no sensible.

**Entregable:** matriz `cookie / finalidad / atributos / riesgo / recomendación` sin secretos.

## Laboratorio 6 — JWT sintético

**Objetivo:** demostrar que un JWT con estructura de tres partes no necesariamente oculta su contenido.

**Requisitos:** Python 3. No se realizan firmas criptográficas reales; el ejemplo es deliberadamente **no válido** para autenticar.

```python
import json, base64

def b64url(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).rstrip(b'=').decode()

header = {'alg': 'none', 'typ': 'JWT'}
payload = {'sub': 'usuario-demo', 'role': 'reader', 'iss': 'lab-local'}
fake = b64url(header) + '.' + b64url(payload) + '.'
print('JWT ILUSTRATIVO, SIN FIRMA, NO CONFIABLE:')
print(fake)
for name, part in zip(('header', 'payload'), fake.split('.')[:2]):
    raw = base64.urlsafe_b64decode(part + '=' * (-len(part) % 4))
    print(name, json.loads(raw))
```

### Preguntas

- ¿Se puede leer `role` sin una clave?
- ¿Se puede confiar en `role=reader` si el token carece de firma válida?
- ¿Qué habría que validar para un token firmado real? (firma, algoritmo permitido, `iss`, `aud`, vencimiento, contexto).
- ¿Por qué no se debe almacenar un access token real en repositorios públicos?

**Resultado esperado:** header y payload legibles; **ninguna autenticación válida**. El algoritmo `none` se utiliza aquí exclusivamente como ejemplo de dato no confiable.

## Laboratorio 7 — Evaluación de MFA

**Objetivo:** seleccionar factores según riesgo y diseñar monitoreo, sin necesidad de inscribir un dispositivo real.

### Escenario

Una empresa utiliza contraseña + push y recibe quejas por notificaciones inesperadas.

### Tareas

1. Enumerá tres explicaciones posibles: accesos legítimos erróneos, automatizaciones, ataque de fatiga MFA, etc.
2. Definí campos necesarios: usuario, timestamp, resultado, dispositivo, IP, cantidad de notificaciones, cambio de autenticador.
3. Compará alternativas: TOTP, push con number matching, FIDO2/passkeys.
4. Diseñá un proceso seguro de recuperación de cuenta.
5. Redactá un mensaje breve para usuario afectado sin pedirle revelar contraseñas/códigos.

### Criterios de cierre

Propuesta de control preventivo + detección + procedimiento de respuesta, con limitaciones expresas.

## Laboratorio 8 — Integridad forense

**Objetivo:** preservar una copia de evidencia y verificar su integridad con SHA-256.

**Requisitos:** archivo de ejemplo propio. No utilizar contenido sensible.

### Crear evidencia de prueba (Python multiplataforma)

```python
from pathlib import Path
p = Path('evento-demo.txt')
p.write_text('2026-10-20T10:00:00Z login_failed demo-user\n', encoding='utf-8')
print('Archivo:', p.resolve())
```

### Calcular hash

Linux:

```bash
sha256sum evento-demo.txt
```

PowerShell:

```powershell
Get-FileHash .\evento-demo.txt -Algorithm SHA256
```

### Copia y verificación

1. Copiá el archivo a otra carpeta **sin modificarlo**.
2. Calculá SHA-256 en origen y copia.
3. Registrá tamaño, hora de adquisición, herramienta, operador y hashes.
4. Modificá **otra copia de prueba** y comprobá que su SHA-256 cambia.
5. Conservá el original inalterado.

**Interpretación:** hashes iguales respaldan que los bytes comparados coinciden con una probabilidad criptográficamente alta; **no prueban origen, cronología real, autoría ni adquisición lícita**.

### Registro de custodia

```text
ID:
Descripción:
Sistema de origen:
Responsable:
Fecha/hora y zona:
Método de exportación:
Ubicación original:
Ubicación copia:
Tamaño:
SHA-256:
Transferencias:
Observaciones / limitaciones:
```

## Laboratorio 9 — Matriz RBAC

**Objetivo:** practicar autorización y mínimo privilegio.

### Escenario

Roles: `SOC-L1`, `SOC-L2`, `Administrador IAM`, `Auditor`.

Acciones: leer alertas, cerrar caso, modificar detección, revocar sesión, crear cuenta, exportar evidencia.

### Procedimiento

1. Construí matriz de roles vs acciones.
2. Justificá cada permiso como necesario o excesivo.
3. Marcá acciones que requieren segundo aprobador.
4. Proponé registro de auditoría para cambios críticos.
5. Analizá el caso: un L1 puede ver alertas, pero intenta crear una cuenta. ¿Qué debe ocurrir?

**Entregable:** tabla RBAC, justificación y ejemplo de evento de denegación **sintético**.

## Laboratorio 10 — Ingeniería de detección

**Objetivo:** convertir una hipótesis en una regla explicable y medir sus límites.

### Hipótesis

Una IP que genera fallos en cinco cuentas distintas dentro de 15 minutos merece triage.

### Pseudorregla (no ejecutar en un SIEM sin adaptar)

```text
DATASET = eventos_de_autenticacion
FILTER outcome == 'failure'
GROUP BY source.ip, ventana_15_min
COUNT distinct(user.name) AS usuarios
ALERT IF usuarios >= 5
```

### Pruebas

1. Probá contra los datos del laboratorio 3.
2. Cambiá el umbral a 3 y compará alertas.
3. Añadí un ejemplo de IP NAT corporativa y evaluá falsos positivos.
4. Diseñá un caso en que el patrón se distribuya entre varias IP.
5. Definí `severidad`, `campos faltantes`, `pasos de triage`, `exclusiones` y `métrica de calidad`.

**Entregable:** ficha de detección, evidencia sintética y una propuesta de mejora. Una regla probada solo con datos inventados **no está validada para producción**.

## Laboratorio 11 — Caso integrador

**Objetivo:** simular el trabajo de un analista SOC L1 con un incidente de identidad sin ejecutar acciones ofensivas.

### Caso sintético

```text
10:00Z - 12 fallos sobre 8 usuarios desde IP A (documentación)
10:08Z - Inicio exitoso de usuario B desde IP B
10:10Z - Nuevo autenticador MFA agregado para usuario B
10:12Z - Usuario B accede a aplicación con datos sensibles
10:15Z - Usuario B agrega miembro a grupo privilegiado
```

### Procedimiento paso a paso

1. **Triage:** ¿qué partes son más urgentes y por qué?
2. **Alcance:** ¿qué cuentas, aplicaciones, privilegios y datos podrían estar implicados?
3. **Evidencias requeridas:** logs IdP, Windows, aplicación, MFA, dispositivos, tickets de cambio.
4. **Hipótesis alternativas:** cambio autorizado, recuperación legítima, abuso de credenciales, sesiones independientes.
5. **Clasificación:** diferenciar observaciones de inferencias; asignar severidad provisional.
6. **Contención propuesta:** revocación de sesiones, bloqueo temporal o revisión de MFA solo bajo autorización y tras ponderar impacto.
7. **Preservación:** exportación, hashes, custodia y control de acceso a evidencia.
8. **Recuperación:** validación de identidad, restablecimiento seguro y monitoreo posterior.
9. **Lecciones aprendidas:** cobertura de eventos, mejores alertas, mejora de recuperación de cuentas.

### Plantilla de informe SOC

```markdown
# Caso SOC: investigación de identidad

- Caso: SOC-007-LAB
- Clasificación: ejercicio sintético
- Fecha/hora de análisis (UTC):
- Analista:
- Fuentes utilizadas:
- Activos/identidades:
- Severidad provisional y justificación:

## Resumen ejecutivo

## Línea de tiempo

| Hora UTC | Fuente | Hecho observado | Confianza |
|---|---|---|---|

## Evidencias

| ID | Origen | Archivo / registro | SHA-256 si corresponde | Custodio |
|---|---|---|---|---|

## Hipótesis

## Validaciones realizadas

## Limitaciones / datos faltantes

## Acciones propuestas o ejecutadas

## Resultado / estado

## Recomendaciones y mejoras
```

### Rúbrica de evaluación

| Criterio | 0 | 1 | 2 |
|---|---|---|---|
| Hechos vs hipótesis | Mezclados | Parcial | Separados |
| Timeline | Ausente | Incompleto | Cronológico con UTC |
| Correlación | Sin contexto | Parcial | Contexto + alternativas |
| Evidencias | Sin fuente | Parcial | Fuente, integridad y límites |
| Respuesta | Improvisada | General | Proporcional y autorizada |
| Informe | Confuso | Aceptable | Claro y reproducible |

**Meta:** 10–12 puntos y ninguna exposición de credenciales reales.

---

## Plantillas de entrega y evaluación

### Registro mínimo para cada práctica

```markdown
# Lab XX — Título

- Fecha/hora y zona:
- Entorno propio/autorizado:
- Sistema y versión:
- Herramientas y versiones:
- Objetivo:

## Procedimiento ejecutado

## Salidas relevantes (redactadas)

## Evidencia y hashes

## Interpretación Blue Team

## Hipótesis alternativas / falsos positivos

## Limitaciones

## Conclusiones

## Próximos pasos
```

### Checklist de publicación de GitHub

- [ ] No aparecen contraseñas, cookies, tokens ni claves privadas reales.
- [ ] Logs propios o sintéticos claramente etiquetados.
- [ ] Fechas y zonas horarias explícitas.
- [ ] Comandos copiados exactamente como se ejecutaron.
- [ ] Resultado real diferenciado de resultado esperado.
- [ ] Capturas ocultaron información personal sin alterar originales preservados.
- [ ] Hipótesis diferenciadas de hechos.
- [ ] Evidencias con SHA-256 cuando corresponde.
- [ ] Limitaciones y falsos positivos documentados.
- [ ] Próxima mejora técnica identificada.

### Orden recomendado para tu roadmap (10–15 h semanales)

- **Semana 1:** labs 0, 1 y 2 → logs en Windows/Linux.
- **Semana 2:** labs 3 y 4 → correlación y spraying con datos inventados.
- **Semana 3:** labs 5, 6 y 7 → sesiones, JWT y MFA.
- **Semana 4:** labs 8, 9, 10 y 11 → preservación, acceso, detección e informe final.

Si una práctica requiere tecnología que no tenés, documentá la carencia y ejecutá su equivalente sintético; no afirmes que generaste logs reales que no existen.

### Fuentes técnicas

- NIST SP 800-63-4: https://csrc.nist.gov/pubs/sp/800/63/4/final
- NIST SP 800-63B-4: https://pages.nist.gov/800-63-4/sp800-63b.html
- OWASP Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- Microsoft Event 4624: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
- Microsoft Event 4625: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
- MITRE ATT&CK: https://attack.mitre.org/

---

**Regla final:** en Blue Team el valor del laboratorio no es afirmar «detecté un ataque» por ver un evento. Es demostrar **qué observaste, qué inferiste, qué comprobaste, qué te falta y cuál sería una respuesta proporcionada**.
