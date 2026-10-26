# Unidad 9 — Seguridad de aplicaciones y servicios web | Blue Team

> **Ruta:** SOC Analyst L1 → Incident Response / DFIR  
> **Nivel:** fundamentos a intermedio  
> **Estado:** guía de estudio lista virtualizada para organizacion general; las prácticas las documente por separado.  
> **Objetivo:** comprender HTTP/HTTPS, TLS, identidad de servidores, sesiones y controles de protección; investigar incidentes web con evidencias de logs y tráfico.

## Índice

1. [Arquitectura y superficie web](#1-arquitectura-y-superficie-web)
2. [HTTP: solicitudes, respuestas y estado](#2-http-solicitudes-respuestas-y-estado)
3. [HTTPS y seguridad en tránsito](#3-https-y-seguridad-en-tránsito)
4. [SSL, TLS 1.2 y TLS 1.3](#4-ssl-tls-12-y-tls-13)
5. [Handshake TLS 1.3 a detalle](#5-handshake-tls-13-a-detalle)
6. [Certificados digitales y PKI](#6-certificados-digitales-y-pki)
7. [Sesiones, cookies y tokens](#7-sesiones-cookies-y-tokens)
8. [Autenticación y autorización web](#8-autenticación-y-autorización-web)
9. [Riesgos frecuentes de aplicaciones](#9-riesgos-frecuentes-de-aplicaciones)
10. [Controles: navegador, servidor y perímetro](#10-controles-navegador-servidor-y-perímetro)
11. [Telemetría y detección SOC](#11-telemetría-y-detección-soc)
12. [Respuesta e investigación forense](#12-respuesta-e-investigación-forense)
13. [Casos de estudio](#13-casos-de-estudio)
14. [Competencias, glosario y referencias](#14-competencias-glosario-y-referencias)

---

## 1. Arquitectura y superficie web

Una aplicación web puede involucrar navegador, DNS, CDN, proxy inverso, WAF, balanceador, servidor de aplicación, API, base de datos, proveedor de identidad y servicios externos. **Una conexión cifrada no vuelve segura la aplicación por sí sola**.

```text
Navegador ──DNS──> Resolver
    │
    └──HTTPS──> CDN / WAF ──> Proxy / Balanceador ──> Aplicación ──> Base de datos
                                     │
                                     └──> Proveedor de identidad
```

**Frontera de confianza:** lugar donde cambian los supuestos de seguridad o el control administrativo. Ejemplo: el usuario no controla el backend; el proxy no debe confiar automáticamente en cabeceras enviadas por Internet; el backend debe validar permisos aunque la interfaz oculte un botón.

**Activos:** credenciales, sesiones, datos personales, claves, certificados, logs, APIs, secretos de infraestructura y disponibilidad.

### 1.1. Modelo de amenazas para SOC

- ¿Qué recursos están expuestos por Internet?
- ¿Cómo se identifica al usuario?
- ¿Dónde termina TLS?
- ¿Quién establece cabeceras de IP real y cómo se validan?
- ¿Qué logs vinculan usuario, sesión, request ID, recurso y resultado?
- ¿Qué controles evitan o detectan abuso?

---

## 2. HTTP: solicitudes, respuestas y estado

### 2.1. Esquema HTTP/1.1

```http
GET /recurso HTTP/1.1
Host: example.com
Accept: text/html
User-Agent: ClienteDeEjemplo
```

La respuesta contiene línea de estado, cabeceras y posiblemente cuerpo:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: no-store

<html>Ejemplo</html>
```

### 2.2. Métodos y semántica

| Método | Función habitual | Observación defensiva |
|---|---|---|
| GET | consultar representación | no debería modificar estado por diseño |
| HEAD | obtener encabezados | diagnóstico/caché |
| POST | enviar datos para procesar | controles de autenticación, CSRF y validación |
| PUT | crear/reemplazar representación | autorización de escritura |
| PATCH | cambios parciales | validar campos permitidos |
| DELETE | solicitar eliminación | permisos y auditoría |
| OPTIONS | describir opciones | configuración CORS |

**Seguro** (safe), **idempotente** y **sin riesgo** no son sinónimos. GET es semánticamente seguro, pero una implementación defectuosa puede tener efectos secundarios. PUT y DELETE son idempotentes en la semántica de HTTP, no necesariamente inocuos.

### 2.3. Códigos de estado

- **2xx:** éxito, por ejemplo `200`, `201`, `204`.
- **3xx:** redirección, por ejemplo `301`, `302`, `307`, `308`.
- **4xx:** errores de cliente, por ejemplo `400`, `401`, `403`, `404`, `429`.
- **5xx:** error del servidor, por ejemplo `500`, `502`, `503`, `504`.

`401` suele indicar que se requiere autenticación válida; `403` indica denegación según la política. No se deben inferir causas exactas solo desde el número de estado.

### 2.4. Encabezados importantes

- `Host`: autoridad solicitada en HTTP/1.1.
- `Content-Type`: tipo de representación.
- `Authorization`: material de autorización; **no registrar valores secretos**.
- `Cookie` y `Set-Cookie`: intercambio de cookies.
- `Location`: ubicación de redirección.
- `Cache-Control`: controles de caché.
- `Origin`: origen de ciertas solicitudes web.
- `X-Forwarded-For` / `Forwarded`: datos de proxies **solo confiables** cuando los establece infraestructura autorizada.

### 2.5. Versiones

- **HTTP/1.1:** protocolo textual con mensajes serializados.
- **HTTP/2:** framing binario y multiplexación de flujos sobre una conexión.
- **HTTP/3:** usa QUIC sobre UDP; integra TLS 1.3 en QUIC, no una conexión TCP tradicional.

**Visibilidad SOC:** el analizador de red puede ver destinos y metadatos, pero no necesariamente rutas, cookies ni cuerpos dentro de TLS. Los logs de proxy/servidor y aplicación suelen ser cruciales.

---

## 3. HTTPS y seguridad en tránsito

**HTTPS = HTTP protegido por TLS** en los transportes compatibles. Reduce riesgos de observación y modificación del contenido **en el segmento protegido** y permite autenticar criptográficamente al servidor si el cliente valida su identidad.

| Aspecto | HTTP sin TLS | HTTPS |
|---|---|---|
| Contenido en red | normalmente legible | cifrado en el canal |
| Integridad criptográfica del canal | no | sí |
| Autenticación del servidor vía certificado | no | sí, si validación correcta |
| Protege contra phishing o malware del propio sitio | no | tampoco |
| Puerto común | TCP 80 | TCP 443; HTTP/3 suele UDP 443 |

### 3.1. ¿Qué queda visible?

Depende de TLS, DNS, ECH, QUIC, proxies y punto de observación. Es frecuente que direcciones IP, volúmenes, tiempos y algunos mensajes iniciales sean visibles; rutas y contenido HTTP protegidos no. **SNI** puede ser observable sin ECH; no debe asumirse visibilidad universal.

### 3.2. TLS termination y cifrado entre saltos

Si el TLS termina en un proxy, ese proxy ve HTTP descifrado y puede aplicar controles. La conexión proxy→backend puede usar otra sesión TLS o un canal sin cifrar según diseño. **El candado del navegador no garantiza cifrado hasta la base de datos ni en cada salto interno.**

### 3.3. Mixed content y downgrade

Contenido activo cargado mediante HTTP desde una página HTTPS implica un riesgo significativo; los navegadores aplican bloqueos/actualizaciones según reglas. Redirecciones HTTP→HTTPS no protegen la primera petición de HTTP por sí solas; HSTS y configuraciones seguras reducen riesgo.

---

## 4. SSL, TLS 1.2 y TLS 1.3

### 4.1. Terminología

**SSL** es la familia histórica predecesora de TLS; sus versiones antiguas son inseguras/obsoletas. En lenguaje comercial todavía se habla de “certificados SSL”, aunque se utilicen con TLS.

**TLS 1.3** es la versión moderna desarrollada en esta unidad; **no existe una versión estándar llamada «TLS 3.1»**. La especificación publicada en 2026 es **RFC 9846**, que sustituye RFC 8446 sin cambiar el número de versión TLS 1.3.

### 4.2. Propiedades

- Autenticación del extremo servidor con certificados y validación de nombre/cadena, en el modo habitual web.
- Acuerdo de secretos y derivación de claves de tráfico.
- Confidencialidad y autenticidad de registros mediante cifrado autenticado (AEAD).
- Protección frente a cambios en tránsito dentro del canal TLS.
- Forward secrecy en el establecimiento habitual basado en (EC)DHE.

### 4.3. Límites

TLS no resuelve por sí solo: XSS, SQL injection, control de acceso roto, robo de sesión desde el endpoint, servidor comprometido o filtración por logs. Tampoco garantiza disponibilidad.

---

## 5. Handshake TLS 1.3 a detalle

### 5.1. Vista didáctica de un handshake completo

```text
CLIENTE                                     SERVIDOR
   | -------- ClientHello --------------------> |
   |   versiones, cipher suites, key_share     |
   | <------- ServerHello -------------------- |
   |   selección, key_share                    |
   | <------- {EncryptedExtensions} ---------- |
   | <------- {Certificate} ------------------ |
   | <------- {CertificateVerify} ------------ |
   | <------- {Finished} --------------------- |
   | -------- {Finished} --------------------> |
   | <========== Application Data ===========> |
```

Las llaves `{}` indican mensajes protegidos según el estado del handshake. Puede existir `HelloRetryRequest`, autenticación de cliente y reanudación PSK, por lo que el flujo no es único.

### 5.2. Pasos explicados

1. **ClientHello:** cliente anuncia capacidades y normalmente aporta un `key_share` efímero.
2. **ServerHello:** selecciona versión TLS 1.3, suite y parámetros compatibles; participa en acuerdo de claves.
3. **Derivación de secretos:** usando HKDF y el material negociado se derivan secretos de handshake y de aplicación. El hash de la transcripción liga decisiones previas.
4. **EncryptedExtensions:** extensiones protegidas relevantes a la conexión.
5. **Certificate:** servidor envía certificado/cadena cuando corresponde.
6. **CertificateVerify:** demuestra posesión de clave privada asociada mediante firma del contenido especificado del handshake.
7. **Finished:** verifica criptográficamente el estado acumulado del handshake.
8. **Validación del cliente:** cadena, propósito, nombre DNS, período de validez y política de confianza/revocación aplicables.
9. **Application Data:** datos de HTTP protegidos con claves derivadas.

El acuerdo efímero protege sesiones previas ante ciertos compromisos posteriores de claves de largo plazo, **si las condiciones del protocolo y del entorno se cumplen**.

### 5.3. Suites TLS 1.3

Ejemplos: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`.

Una suite de TLS 1.3 determina principalmente algoritmo AEAD y hash de HKDF; el intercambio de claves y firma se negocian por separado. **SHA-256 en el nombre no significa que los datos se “cifren con SHA-256”**.

### 5.4. Reanudación y 0-RTT

La reanudación puede reducir costo de nuevos handshakes. El envío temprano de datos **0-RTT** tiene consideraciones importantes de **replay**: no debe usarse despreocupadamente con operaciones que producen efectos irreversibles. La política del servidor importa.

### 5.5. Qué buscar desde SOC

- Desajustes de versión/cifrado respecto de la política.
- Certificados expirados, nombre incorrecto, emisores inesperados.
- Errores frecuentes de handshake y cambios tras despliegues.
- Tráfico inesperado hacia servicios sin TLS.
- Terminaciones de TLS no documentadas.

No clasificar tráfico TLS desconocido como malicioso sin contexto.

---

## 6. Certificados digitales y PKI

### 6.1. Certificado X.509

Asocia una **clave pública** con información de identidad y extensiones firmadas por un emisor. Los campos relevantes incluyen `Subject`, `Issuer`, `Subject Alternative Name (SAN)`, fechas `Not Before/After`, uso de clave, clave pública, firma y cadena.

### 6.2. Jerarquía de confianza

```text
Raíz confiable (trust store del cliente)
             |
      CA intermedia
             |
    Certificado servidor
             |
       Nombre esperado
```

**Validación no equivale a comprobar que “la página es honesta”.** Un sitio malicioso también puede presentar HTTPS válido para un dominio que controla.

### 6.3. Criterios de validación

- Cadena criptográfica hasta ancla de confianza permitida.
- Nombre DNS solicitado presente en SAN pertinente.
- Fecha/hora válidas y uso adecuado.
- Restricciones de emisión y políticas aplicables.
- Tratamiento de revocación según cliente/entorno; OCSP/CRL no tienen comportamiento idéntico universal.

### 6.4. Revocación, renovación y rotación

- **CRL:** lista de certificados revocados.
- **OCSP:** consulta sobre estado de certificado.
- **Renovación:** obtiene nuevo certificado antes del vencimiento.
- **Rotación de clave:** reemplaza material criptográfico; distinta de renovar un certificado reutilizando la misma clave.

### 6.5. Riesgos de operación

- Clave privada filtrada o almacenada sin protección.
- Certificados expirados o mal emitidos.
- Confianza excesiva en CAs internas instaladas sin control.
- Validación deshabilitada en aplicaciones.
- Secretos incluidos en repositorios Git o logs.

### 6.6. OpenSSL, comandos de lectura

```bash
openssl s_client -connect example.com:443 -servername example.com -verify_return_error </dev/null
```

La salida incluye información de la negociación/certificados; revisar estado de verificación, hostname (la comprobación exacta depende de parámetros) y errores. Para comprobar hostname explícitamente:

```bash
openssl s_client -connect example.com:443 -servername example.com -verify_hostname example.com -verify_return_error </dev/null
```

No usar `-k` de curl ni desactivar la verificación como “solución” en producción.

---

## 7. Sesiones, cookies y tokens

### 7.1. HTTP y estado

HTTP no exige que el servidor conserve por sí mismo el contexto entre solicitudes. Una sesión web vincula solicitudes con un contexto de usuario o dispositivo.

### 7.2. Cookie segura

```http
Set-Cookie: __Host-session=<valor_aleatorio>; Path=/; Secure; HttpOnly; SameSite=Lax
```

El ejemplo es conceptual; el prefijo `__Host-` requiere restricciones específicas (incluido `Secure`, `Path=/` y no incluir `Domain`). El valor debe ser generado criptográficamente y tratado como secreto.

- **Secure:** enviar la cookie únicamente en contextos de transporte seguro compatibles.
- **HttpOnly:** restringe acceso desde JavaScript mediante interfaces comunes; no elimina XSS.
- **SameSite:** regula determinados envíos entre sitios y contribuye a mitigar CSRF; no sustituye tokens/otras defensas donde corresponda.
- **Expires/Max-Age:** persistencia en el navegador, **no** sustituyen expiración del lado servidor.
- **Domain/Path:** delimitan alcance; no constituyen por sí solos un aislamiento completo de seguridad.

### 7.3. Ciclo de sesión

1. Identidad/credenciales válidas.
2. Generación de identificador impredecible.
3. Envío mediante canal protegido.
4. Validación de cada acceso y autorización por recurso.
5. Renovación de ID al iniciar sesión o elevar privilegios.
6. Expiración por inactividad y absoluta, según riesgo.
7. Revocación al cerrar sesión o ante incidentes.

### 7.4. Riesgos

- **Session hijacking:** uso no autorizado de una sesión válida.
- **Session fixation:** el sistema acepta/reutiliza identificador controlado antes de autenticar.
- **CSRF:** navegador autenticado inducido a realizar acción no deseada.
- **XSS:** ejecución de contenido no confiable en contexto web; puede actuar sobre sesiones aunque la cookie sea HttpOnly.
- **Replay:** reutilización de un mensaje válido, dependiendo del mecanismo.

### 7.5. Tokens JWT

JWT es un formato compacto que puede contener claims y estar firmado o cifrado según su perfil. No todos los JWT están cifrados; un JWS firmado se puede decodificar sin conocer la clave de firma. **Firma válida ≠ autorización suficiente**. Verificar algoritmo permitido, emisor, audiencia, expiración, claves, contexto y políticas; evitar logging de tokens completos.

### 7.6. Cookies vs tokens

Una cookie es un mecanismo del navegador para almacenar y enviar datos. Un token es un valor de credencial o autorización. Una cookie **puede contener** un token o identificador de sesión: no son tecnologías mutuamente excluyentes.

---

## 8. Autenticación y autorización web

### 8.1. AAA: conceptos distintos

- **Identificación:** declarar identidad.
- **Autenticación:** verificarla (por ejemplo contraseña + factor adicional).
- **Autorización:** decidir si la identidad puede realizar una acción sobre un recurso.
- **Auditoría/accounting:** conservar eventos útiles para trazabilidad.

### 8.2. MFA y passkeys

MFA combina factores distintos. Passkeys basadas en FIDO2/WebAuthn ofrecen propiedades resistentes al phishing cuando se usan correctamente, vinculando la operación al origen del servicio. **MFA no elimina robo de sesiones**, por lo que se necesita detección y revocación.

### 8.3. SSO, OAuth 2.0 y OpenID Connect

- **SSO:** experiencia de inicio de sesión compartido entre servicios.
- **OAuth 2.0:** marco de delegación de autorización.
- **OpenID Connect:** capa de identidad/autenticación construida sobre OAuth 2.0.

No considerar OAuth 2.0 por sí solo un protocolo de autenticación. Validar redirect URIs, estado, nonce donde proceda, scopes y claims.

### 8.4. Autorización rota (Broken Access Control)

Una sesión autenticada puede carecer de permiso para un objeto o acción. El backend debe verificar autorización **en cada solicitud**, no confiar en botones ocultos ni IDs proporcionados por cliente. La exposición horizontal de objetos entre usuarios se conoce habitualmente como IDOR/BOLA en casos pertinentes.

---

## 9. Riesgos frecuentes de aplicaciones

| Riesgo | Idea central | Defensa/telemetría |
|---|---|---|
| SQL Injection | entradas alteran consultas SQL | parametrización, permisos mínimos, logs de errores |
| XSS | contenido no confiable ejecutado en contexto web | codificación salida, CSP, saneamiento apropiado |
| CSRF | acción inducida al navegador autenticado | tokens CSRF, SameSite, verificación Origin según caso |
| Broken Access Control | se opera sin permiso sobre recurso | autorización server-side, pruebas, auditoría |
| SSRF | servidor inducido a acceder a destinos indebidos | allowlists, aislamiento, control egreso |
| Path Traversal | acceso a rutas fuera del ámbito permitido | canonizar y restringir rutas, permisos |
| Exposición de secretos | claves/tokens en código/logs | gestores de secretos, rotación, escaneo |
| Configuración TLS débil | validación/cifrado/versión inapropiados | política TLS, escaneo autorizado, monitoreo |
| Dependencias vulnerables | bibliotecas desactualizadas | inventario SBOM, parches y priorización |

No todas las entradas sospechosas suponen explotación exitosa. Correlacionar petición, respuesta, aplicación, integridad y procesos.

---

## 10. Controles: navegador, servidor y perímetro

### 10.1. Cabeceras relevantes

- `Strict-Transport-Security`: indica política de uso HTTPS futuro para navegadores compatibles. Se debe desplegar con precaución y tras asegurar soporte TLS.
- `Content-Security-Policy`: restringe fuentes y comportamientos de contenido; ayuda a reducir determinadas consecuencias de XSS, no lo reemplaza.
- `X-Content-Type-Options: nosniff`: reduce determinados problemas de interpretación de tipos MIME.
- `Referrer-Policy`: controla cuánto origen se divulga en encabezado Referer.
- `Permissions-Policy`: restringe ciertas funciones del navegador.
- `Access-Control-Allow-Origin`: política CORS para lectura de respuestas cross-origin; **CORS no es control de autenticación o autorización**.

### 10.2. Defensa de sesiones

Cookies `Secure`, `HttpOnly`, `SameSite`; rotación al autenticar; expiraciones y revocación del lado servidor; protección CSRF; MFA; monitoreo de reutilización sospechosa y eventos de cambio de credenciales.

### 10.3. WAF y reverse proxy

WAF observa tráfico HTTP que pasa por él. Puede detectar/bloquear patrones conocidos y aplicar límites, pero no reemplaza validaciones internas. Proxy inverso puede terminar TLS y reenviar al backend: documentar **dónde** se descifra y **qué** direcciones IP representan usuarios reales.

### 10.4. Secretos y registros

Nunca enviar a GitHub contraseñas, cookies reales, claves privadas, bearer tokens ni PCAP con datos ajenos. Configurar redacción, retención y protección de logs. El logging excesivo puede generar un nuevo incidente de confidencialidad.

---

## 11. Telemetría y detección SOC

### 11.1. Campos útiles en un log web

```text
@timestamp, request_id, src_ip_validated, method, path_normalized,
status, bytes_out, duration_ms, user_id_pseudonym,
session_id_hash_truncated, user_agent, upstream_status,
tls_version, tls_cipher, host, rule_id
```

No registrar identificadores reales de sesión ni credenciales. Una representación seudonimizada consistente puede ser útil bajo una política aprobada y diseñada correctamente.

### 11.2. Detecciones conceptuales

**Intentos fallidos de login:** crecimiento anómalo de 401/403 o eventos de identidad por cuenta/origen, seguido o no de autenticación exitosa; considerar fallas de integración y bots benignos.

**Acceso a recursos denegados:** muchos 403 sobre múltiples identificadores; comprobar si se trata de exploración legítima de una API o error de cliente.

**Error de TLS:** aumento de alertas de handshake coincidente con rotación de certificado; corroborar despliegues.

**Secuencia crítica:** sesión iniciada → factor de autenticación modificado → descarga masiva; elevar prioridad según activo/identidad.

**Abuso L7:** RPS elevado + aumento de 5xx/latencia sobre una ruta concreta; distinguir campañas legítimas.

### 11.3. Tabla de triage

| Pregunta | Evidencia útil |
|---|---|
| ¿Quién inició la sesión? | proveedor de identidad + correlación de requests |
| ¿Qué acción se realizó? | logs de aplicación y auditoría |
| ¿Se bloqueó o tuvo éxito? | estado HTTP **más** resultado de negocio |
| ¿Hubo cifrado? | metadatos TLS del proxy/servidor |
| ¿Afectó datos sensibles? | auditoría de objetos / DLP / backend |
| ¿Persistió el acceso? | revocaciones, refresh tokens, nuevas sesiones |

### 11.4. Cuidado con la atribución

Una misma IP puede corresponder a múltiples usuarios detrás de NAT. Un user-agent puede falsificarse. Una IP de proxy puede representar cientos de clientes. Correlacionar señales y definir confianza en datos de forwarding.

---

## 12. Respuesta e investigación forense

### 12.1. Pasos mínimos

1. Preservar datos volátiles y logs según procedimiento.
2. Establecer ventana UTC y eventos de cambio.
3. Identificar cuentas, sesiones y recursos relacionados.
4. Correlacionar IdP, WAF, reverse proxy, aplicación, base de datos y endpoint.
5. Determinar impacto CIA real frente a hipótesis.
6. Revocar sesiones/rotar credenciales y aislar componentes **solo con autorización**.
7. Corregir causa, validar recuperación y actualizar detecciones.

### 12.2. Evidencia digital

- Conservar archivos originales con metadatos y acceso restringido.
- Calcular SHA-256 y documentar procedimiento.
- Registrar fuente, UTC, versión de herramientas y responsables.
- Trabajar con copias, no alterar producción sin autorización.
- Una traza HTTP puede contener secretos; anonimizar antes de compartir.

### 12.3. Informe SOC (plantilla)

```text
Caso / fecha:
Servicio, entorno y responsable:
Fuente de alerta:
Impacto y criticidad:
Hechos comprobados (con fuentes):
Hipótesis pendientes:
Cronología UTC:
Sesiones/cuentas afectadas:
Objetos o datos expuestos:
Acciones autorizadas y validación:
Evidencias + hashes:
Falsos positivos considerados:
Recomendaciones y seguimiento:
```

---

## 13. Casos de estudio

### Caso A: certificado vencido

Una plataforma falla en distintos navegadores tras un despliegue. Revisar vencimiento, cadena, nombre y configuración; comparar errores del reverse proxy y cronología. **No solucionar desactivando validación TLS.**

### Caso B: HTTP 200 no significa operación autorizada

Una API devuelve `200` y datos del usuario distinto al autenticado. La evidencia relevante está en auditoría de autorización, objeto solicitado, identidad y respuesta; posible control de acceso roto. Evitar compartir datos reales de usuarios en GitHub.

### Caso C: muchos 401 seguidos de sesión válida

La secuencia puede ser credenciales olvidadas, un cliente defectuoso o ataque a credenciales. Investigar origen, MFA, identidad, dispositivo, nuevas sesiones y acciones posteriores.

### Caso D: sesión reutilizada desde origen anómalo

Correlacionar IdP, rotación de tokens, eventos de red, cambios de dispositivo y riesgo de proxy/VPN legítimo; no concluir secuestro de sesión por geolocalización aislada.

---

## 14. Competencias, glosario y referencias

### Checklist de progreso

- [ ] Identifico métodos, códigos y encabezados HTTP relevantes.
- [ ] Explico diferencias HTTP/1.1, HTTP/2 y HTTP/3.
- [ ] Describo el handshake TLS 1.3 y validación X.509.
- [ ] Identifico riesgos de TLS termination y certificados.
- [ ] Diferencio cookies, sesiones, JWT, SSO, OAuth/OIDC y MFA.
- [ ] Distingo autenticación de autorización en una API.
- [ ] Evalúo atributos de cookies e interpretación defensiva.
- [ ] Correlaciono logs de aplicación, WAF e identidad.
- [ ] Documento incidente web separando hechos e hipótesis.
- [ ] Preservo y anonimizo evidencias para portfolio.

### Glosario breve

**HTTPS:** HTTP protegido por TLS. **TLS:** seguridad criptográfica de transporte. **AEAD:** cifrado autenticado con datos asociados. **HKDF:** derivación de claves a partir de material secreto. **PKI:** infraestructura de clave pública. **SAN:** nombres del certificado. **SNI:** indicación del nombre de servidor en negociación TLS. **HSTS:** política de HTTPS del navegador. **CSP:** política de seguridad del contenido. **JWT:** formato compacto de token. **SSO:** inicio de sesión único. **IdP:** proveedor de identidad. **WAF:** firewall de aplicación web. **CSRF:** falsificación de solicitud entre sitios. **XSS:** scripting entre sitios. **CORS:** mecanismo navegador para controles cross-origin.

### Fuentes técnicas

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 9846 — TLS 1.3 (2026; reemplaza RFC 8446)](https://www.rfc-editor.org/rfc/rfc9846)
- [RFC 9525 — Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

**Laboratorios:** [`../laboratorios/Unidad-09-LABORATORIOS.md`](../laboratorios/Unidad-09-LABORATORIOS.md)

---

**Nota de portfolio:** las secciones describen competencias de estudio. No deben presentarse los casos ficticios como incidentes atendidos ni como experiencia laboral.
