# Laboratorios Blue Team — Unidad 9: Seguridad web, TLS y sesiones

> **Ubicación GitHub:** `laboratorios/Unidad-09-LABORATORIOS.md`  
> **Relación:** [`../Unidad-09/README.md`](../Unidad-09/README.md)  
> **Objetivo:** interpretar HTTP, verificar TLS/certificados, revisar cookies, correlacionar eventos de autenticación, documentar incidentes web y conservar evidencia.  
> **Alcance:** servicios de prueba públicos para solicitudes normales **sin carga**, datos sintéticos y aplicaciones propias/autorizadas.

## Reglas de seguridad y evidencia

- No probar inyecciones, bypasses, cargas ni enumeraciones sobre servicios ajenos.
- Los comandos contra `example.com` hacen una **solicitud normal** o conexión TLS de diagnóstico; si no existe conectividad, documentarlo como limitación.
- Para cookies/sesiones, utilizar un proyecto local propio o interpretar valores **ficticios**; no copiar cookies activas al repositorio.
- No deshabilitar validación TLS como solución a errores.
- No publicar tokens, cabeceras `Authorization`, identificadores de sesión, claves privadas o logs con datos personales.
- Los resultados esperados son ejemplos; hay que registrar los resultados de tu entorno real.

## Estructura de portfolio

```text
laboratorios/
  Unidad-09-LABORATORIOS.md
SOC-Labs/
  U09-web-security/
    README.md
    datasets/
    scripts/
    evidencia/
    informes/
```

Se necesita Python 3; `curl` y `openssl` son recomendables. En Windows PowerShell, verificar si `curl.exe` y `openssl` están instalados. No depender del alias `curl` de versiones antiguas de PowerShell.

---

## Lab 0 — Preparación y modelo de amenazas web

**Objetivo:** identificar componentes y puntos de confianza.

Dibujar:

```text
Navegador → DNS → CDN/WAF → Reverse Proxy → Aplicación → Datos
                            ↘ proveedor de identidad
```

Responder:

1. ¿Dónde se establece TLS? ¿Dónde podría terminar?
2. ¿Qué logs existen por capa y quién los administra?
3. ¿Qué campos permiten correlacionar una solicitud con un usuario sin exponer secretos?
4. ¿Qué ocurriría si el proxy confiara en una cabecera `X-Forwarded-For` enviada por un cliente desconocido?
5. ¿Cuál sería el impacto CIA de una cookie de sesión robada?

**Entregable:** `informes/00-threat-model.md` con diagrama y al menos tres controles.

---

## Lab 1 — Leer una respuesta HTTP normal

**Objetivo:** reconocer estado, encabezados y redirecciones de un servicio público de documentación.

```bash
curl -I https://example.com
```

En Windows:

```powershell
curl.exe -I https://example.com
```

Si se desea ver solo los encabezados y estado, no agregar opciones que omitan verificación. Anotar:

| Campo | Observación real |
|---|---|
| Fecha UTC | ... |
| Código HTTP | ... |
| Content-Type | ... |
| Cache-Control | ... |
| HSTS presente | ... |
| Servidor/proxy (si se anuncia) | ... |

**Importante:** ausencia de HSTS en un único host no permite juzgar toda la seguridad del proveedor; algunos encabezados aparecen solo en dominios concretos.

**Preguntas:** ¿qué demuestra 200? ¿Qué no demuestra? ¿Qué indica 301/302? ¿Por qué 401 y 403 no son idénticos?

---

## Lab 2 — Inspeccionar TLS y certificados

**Objetivo:** identificar versión, certificado, nombre y validación.

Linux/macOS (con OpenSSL):

```bash
openssl s_client -connect example.com:443 -servername example.com \
  -verify_hostname example.com -verify_return_error </dev/null
```

Anotar:

- Protocolo TLS negociado.
- Suite de cifrado negociada.
- Subject, Issuer, SAN, fechas (si aparecen o se obtienen del certificado).
- Resultado de validación.
- Evidencia de cadena.

Para extraer y leer certificado sin almacenar una clave privada:

```bash
openssl s_client -connect example.com:443 -servername example.com \
  -showcerts </dev/null 2>/dev/null |
  openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

En Windows, ejecutar en un shell con OpenSSL instalado. Si falla por no tener OpenSSL, documentarlo y usar las herramientas del navegador para revisar el certificado; no inventar salida.

**Limitaciones:** un handshake válido no prueba que la aplicación sea legítima ni que su backend esté protegido.

**Entregable:** tabla de campos reales y explicación de qué propiedad de seguridad verifica cada uno.

---

## Lab 3 — Interpretar TLS 1.3 en captura autorizada

**Objetivo:** diferenciar handshake de datos de aplicación cifrados.

1. Capturar **tu propia** navegación HTTPS en Wireshark.
2. Filtrar:

```text
tls
```

3. Buscar `Client Hello`, `Server Hello` y registros posteriores cuando sean visibles.  
4. Intentar correlacionar la IP y puerto de tu navegador con el servidor.  
5. Explicar por qué no se puede leer la ruta HTTP de una sesión protegida sin información adicional de descifrado.

**Atención:** si tu navegador utiliza HTTP/3/QUIC, el flujo puede aparecer bajo QUIC y no como TLS sobre TCP. Algunas partes del handshake están cifradas o no serán visibles con la misma claridad. No forzar configuraciones inseguras.

**Preguntas:** ¿qué identifica SNI en un caso donde es visible? ¿Qué protege TLS y qué no protege? ¿El certificado valida el nombre o garantiza que el contenido sea benigno?

---

## Lab 4 — Cookies y cabeceras: análisis seguro de datos ficticios

**Objetivo:** reconocer atributos sin tocar cuentas reales.

Ejemplos:

```http
Set-Cookie: session=SIMULADO123; Path=/; Secure; HttpOnly; SameSite=Lax
Set-Cookie: pref=es; Path=/; Max-Age=3600; SameSite=Strict
Set-Cookie: legacy=ABC; Path=/
```

Completar:

| Cookie | Riesgo/revisión | Recomendación |
|---|---|---|
| session | analizar atributos y expiración server-side | validar revocación y rotación |
| pref | configuración de preferencias, no necesariamente credencial | limitar alcance |
| legacy | sin Secure/HttpOnly/SameSite explícitos | verificar necesidad y riesgos |

**Aclaraciones:** `HttpOnly` no impide que la aplicación cliente ejecute acciones autenticadas en caso de XSS; `SameSite` no garantiza protección absoluta frente a CSRF; el valor `SIMULADO123` no tiene entropía suficiente para una sesión real y **no debe usarse en producción**.

**Entregable:** matriz de control por cookie y tres pruebas que solicitarías al equipo de desarrollo **en un entorno autorizado**.

---

## Lab 5 — Correlación SOC de logs web sintéticos

**Objetivo:** reconocer patrones de autenticación y uso de recursos sin afirmar compromiso automático.

Crear `datasets/web_events.csv`:

```csv
timestamp_utc,request_id,user,ip,method,path,status,latency_ms,action
2026-10-20T10:00:00Z,r1,ana,192.0.2.10,POST,/login,401,110,login_failed
2026-10-20T10:00:10Z,r2,ana,192.0.2.10,POST,/login,401,95,login_failed
2026-10-20T10:00:20Z,r3,ana,192.0.2.10,POST,/login,401,98,login_failed
2026-10-20T10:01:00Z,r4,ana,192.0.2.10,POST,/login,200,130,login_success
2026-10-20T10:02:00Z,r5,ana,192.0.2.10,GET,/dashboard,200,90,view
2026-10-20T10:03:00Z,r6,ana,192.0.2.10,GET,/exports,200,120,export
2026-10-20T10:04:00Z,r7,bob,198.51.100.5,GET,/dashboard,403,80,denied
2026-10-20T10:05:00Z,r8,svc,203.0.113.9,GET,/health,200,15,healthcheck
```

Son direcciones reservadas para documentación y usuarios inventados.

Crear `scripts/analyze_web.py`:

```python
import csv
from collections import Counter, defaultdict
from pathlib import Path

rows = list(csv.DictReader(Path('datasets/web_events.csv').open(newline='', encoding='utf-8')))
failed = Counter(r['user'] for r in rows if r['action'] == 'login_failed')
print('Fallos por usuario:', dict(failed))

by_user = defaultdict(list)
for r in rows:
    by_user[r['user']].append(r)

for user, events in by_user.items():
    events = sorted(events, key=lambda r: r['timestamp_utc'])
    print('\nCuenta', user)
    for e in events:
        print(e['timestamp_utc'], e['action'], e['status'], e['request_id'])
```

Ejecutar:

```bash
python3 scripts/analyze_web.py
```

**Resultado esperado:** `ana` presenta tres fallos, luego éxito, vista y exportación. Esto **no prueba** abuso: podría ser una contraseña mal escrita seguida de actividad autorizada. Se necesitan MFA, dispositivo, sesión, auditoría de exportación y contexto.

**Entregable:** tabla de eventos, dos hipótesis alternativas, severidad preliminar justificada y solicitud de evidencias adicionales.

---

## Lab 6 — SQL-like queries sobre logs con SQLite (solo lectura de dataset)

**Objetivo:** practicar un tipo de consulta similar a las tareas básicas de un SIEM, sin instalar infraestructura pesada.

Guardar como `scripts/sqlite_web.py`:

```python
import csv
import sqlite3
from pathlib import Path

con = sqlite3.connect(':memory:')
con.execute('CREATE TABLE events (timestamp_utc TEXT, request_id TEXT, user TEXT, ip TEXT, method TEXT, path TEXT, status INTEGER, latency_ms INTEGER, action TEXT)')
with Path('datasets/web_events.csv').open(newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    con.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)', [
        (r['timestamp_utc'], r['request_id'], r['user'], r['ip'], r['method'], r['path'],
         int(r['status']), int(r['latency_ms']), r['action']) for r in reader
    ])
for row in con.execute("SELECT user, COUNT(*) AS n FROM events WHERE status=401 GROUP BY user ORDER BY n DESC"):
    print('Fallos:', row)
for row in con.execute("SELECT timestamp_utc, user, action, path FROM events WHERE user='ana' ORDER BY timestamp_utc"):
    print('Secuencia:', row)
```

**Preguntas:** ¿qué condiciones agregarías para disminuir falsos positivos? ¿Por qué un `200` no demuestra que una acción fue correctamente autorizada? ¿Qué sucede si el proxy no valida su encabezado de IP de origen?

---

## Lab 7 — Cabeceras y redirecciones seguras

**Objetivo:** diseñar una revisión de configuración, no explotar un sitio.

Usar respuesta ficticia:

```http
HTTP/1.1 302 Found
Location: https://portal.example.com/login
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
```

Analizar:

1. ¿Qué aporta `Content-Security-Policy`? ¿Qué no aporta?
2. ¿Cuál sería el beneficio de HSTS y cuándo es seguro habilitarlo?
3. ¿CORS sustituye autorización? (No).
4. ¿Qué información puede divulgar una URL con token de sesión en query string?
5. ¿Cómo verificarías que un proxy interno vuelve a cifrar tráfico hacia backend?

**Entregable:** checklist de seguridad con prioridad y dueño propuesto por control.

---

## Lab 8 — Integridad forense de logs

**Objetivo:** conservar el dataset de investigación antes de modificar consultas o informes.

Linux/macOS:

```bash
sha256sum datasets/web_events.csv
```

Windows:

```powershell
Get-FileHash datasets\web_events.csv -Algorithm SHA256
```

Crear `evidencia/cadena-custodia.md`:

```text
ID:
Fuente: dataset sintético
Fecha/hora UTC de adquisición:
Herramienta y versión:
Ruta del archivo original:
SHA-256 real:
Responsable:
Copia de análisis:
Accesos/cambios:
```

Recalcular al finalizar. Explicar por qué **una comparación de hash no prueba por sí sola quién produjo originalmente los datos**.

---

## Lab 9 — Caso integrador: acceso web bajo investigación

**Escenario simulado:** tres fallos seguidos de login exitoso y una exportación de datos; otros eventos incluyen un 403 y un healthcheck. No hay registro de MFA, dispositivo ni validación de autorización.

### Tareas

1. Reconstruir una línea temporal UTC de `ana`.
2. Diferenciar `401`, `403` y `200`, considerando lógica de negocio.
3. Evaluar **al menos tres hipótesis:** error de usuario, actividad automatizada, credenciales comprometidas.
4. Precisar la evidencia faltante (IdP, MFA, agente, sesión, auditoría de exportación, datos alcanzados).
5. Definir acciones de respuesta **condicionadas a confirmación y autorización**.
6. Redactar informe y presentar hashes.

### Plantilla de informe final

```markdown
# U09-SOC-001 — Triage web y autenticación (SIMULADO)

## Resumen ejecutivo
## Alcance y evidencias
## Contexto de la aplicación
## Línea de tiempo UTC
## Hallazgos comprobados
## Hipótesis alternativas y validaciones pendientes
## Impacto potencial / confirmado
## Controles web/TLS/sesiones relevantes
## Acciones autorizadas o recomendaciones
## Evidencias y SHA-256
## Aprendizajes / limitaciones
```

### Rúbrica (0–2 por criterio, máximo 12)

| Criterio | 0 | 1 | 2 |
|---|---|---|---|
| Interpretación HTTP | incorrecta | parcial | contextualizada |
| TLS/sesiones | confundidos | definidos | aplicados al caso |
| Correlación | inexistente | parcial | cronología clara |
| Hipótesis | conclusiones precipitadas | una alternativa | ≥3 hipótesis contrastables |
| Evidencias | ausentes | incompletas | documentadas y hasheadas |
| Informe | poco reproducible | aceptable | claro, ético y verificable |

**Meta:** ≥10/12 antes de publicar como caso destacado de portfolio.

---

## Progreso

- [ ] Lab 0 — Modelo de amenazas
- [ ] Lab 1 — HTTP
- [ ] Lab 2 — TLS/certificados
- [ ] Lab 3 — Handshake y captura
- [ ] Lab 4 — Cookies
- [ ] Lab 5 — Correlación Python
- [ ] Lab 6 — Consultas SQLite
- [ ] Lab 7 — Cabeceras
- [ ] Lab 8 — Integridad forense
- [ ] Lab 9 — Caso integrador

## Referencias

- [Unidad 9 — Teoría](../Unidad-09/README.md)
- [RFC 9846 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc9846)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

**Integridad del portfolio:** publicar resultados reales cuando ejecutes los ejercicios, diferenciando claramente los eventos simulados, las observaciones medidas y las conclusiones.
