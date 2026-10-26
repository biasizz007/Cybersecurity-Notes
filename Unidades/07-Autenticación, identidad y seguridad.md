# Unidad 7 — Autenticación, identidad y seguridad de accesos

> **Ruta:** Blue Team → SOC Analyst L1 → Incident Response / DFIR  
> **Propósito:** entender cómo se demuestra una identidad, cómo se conceden permisos, cómo se protegen sesiones y cómo un analista defensivo investiga accesos anómalos.  

## Índice

- [Unidad 7 — Autenticación, identidad y seguridad de accesos](#unidad-7--autenticación-identidad-y-seguridad-de-accesos)
  - [Índice](#índice)
  - [1. Modelo mental: identidad, autenticación, autorización y auditoría](#1-modelo-mental-identidad-autenticación-autorización-y-auditoría)
  - [2. Identidad digital y ciclo de vida](#2-identidad-digital-y-ciclo-de-vida)
  - [3. Factores y métodos de autenticación](#3-factores-y-métodos-de-autenticación)
    - [Seguridad de autenticación: niveles de garantía](#seguridad-de-autenticación-niveles-de-garantía)
  - [4. Contraseñas y credenciales](#4-contraseñas-y-credenciales)
    - [Amenazas a contraseñas](#amenazas-a-contraseñas)
    - [Política defensiva](#política-defensiva)
    - [Ejemplo de almacenamiento conceptual](#ejemplo-de-almacenamiento-conceptual)
  - [5. MFA y autenticación resistente al phishing](#5-mfa-y-autenticación-resistente-al-phishing)
  - [6. Claves públicas, certificados, SSH y Kerberos](#6-claves-públicas-certificados-ssh-y-kerberos)
    - [Autenticación con clave pública](#autenticación-con-clave-pública)
    - [SSH](#ssh)
    - [Certificados y PKI](#certificados-y-pki)
    - [Kerberos (contexto Windows/Active Directory)](#kerberos-contexto-windowsactive-directory)
  - [7. SSO, federación, OAuth 2.0, OpenID Connect y SAML](#7-sso-federación-oauth-20-openid-connect-y-saml)
    - [OAuth y OIDC: roles](#oauth-y-oidc-roles)
  - [8. Sesiones, cookies y tokens](#8-sesiones-cookies-y-tokens)
    - [Sesión con identificador opaco](#sesión-con-identificador-opaco)
    - [Atributos de cookies](#atributos-de-cookies)
    - [Riesgos de sesión](#riesgos-de-sesión)
    - [JWT](#jwt)
  - [9. Autorización y modelos de control de acceso](#9-autorización-y-modelos-de-control-de-acceso)
    - [Fallos comunes de autorización](#fallos-comunes-de-autorización)
  - [10. Protección de accesos y arquitectura defensiva](#10-protección-de-accesos-y-arquitectura-defensiva)
  - [11. Amenazas y patrones de abuso](#11-amenazas-y-patrones-de-abuso)
    - [Password spraying frente a fuerza bruta](#password-spraying-frente-a-fuerza-bruta)
    - [Robo de sesiones](#robo-de-sesiones)
    - [Compromiso de identidad federada](#compromiso-de-identidad-federada)
    - [Ataques a MFA](#ataques-a-mfa)
  - [12. Telemetría para SOC](#12-telemetría-para-soc)
    - [Fuentes](#fuentes)
    - [Eventos Windows útiles (no todos están habilitados normalmente)](#eventos-windows-útiles-no-todos-están-habilitados-normalmente)
    - [Tipo de inicio de sesión (`LogonType`)](#tipo-de-inicio-de-sesión-logontype)
    - [Campos normalizados mínimos](#campos-normalizados-mínimos)
  - [13. Investigaciones y casos de uso de detección](#13-investigaciones-y-casos-de-uso-de-detección)
    - [Caso A — Password spraying](#caso-a--password-spraying)
    - [Caso B — Cuenta bloqueada repetidamente](#caso-b--cuenta-bloqueada-repetidamente)
    - [Caso C — Acceso remoto inusual](#caso-c--acceso-remoto-inusual)
    - [Caso D — Escalada de privilegio](#caso-d--escalada-de-privilegio)
    - [Caso E — MFA push anómalo](#caso-e--mfa-push-anómalo)
    - [Caso F — Uso de sesión sin nuevo login](#caso-f--uso-de-sesión-sin-nuevo-login)
    - [Mi ficha reusable de detección](#mi-ficha-reusable-de-detección)
  - [14. Respuesta a incidentes de identidad y preservación forense](#14-respuesta-a-incidentes-de-identidad-y-preservación-forense)
  - [15. Ejemplo completo: investigar accesos sospechosos](#15-ejemplo-completo-investigar-accesos-sospechosos)
  - [16. Lista de competencias y errores comunes](#16-lista-de-competencias-y-errores-comunes)
  - [17. Glosario y referencias](#17-glosario-y-referencias)
    - [Referencias primarias](#referencias-primarias)

---

## 1. Modelo mental: identidad, autenticación, autorización y auditoría

La autenticación es una **comprobación**, no un permiso. Una identidad puede demostrar quién es y aun así no estar autorizada para acceder a un recurso.

| Concepto | Pregunta | Ejemplo |
|---|---|---|
| Identificación | ¿Quién afirma ser? | `analista01` |
| Verificación de identidad (*identity proofing*) | ¿Se comprobó la identidad real durante el alta? | Validación de identidad según el nivel de riesgo |
| Autenticación (*authentication*) | ¿Puede demostrar que controla esa identidad? | Passkey, contraseña, certificado |
| Autorización (*authorization*) | ¿Qué acciones puede ejecutar? | Consultar alertas, no administrar usuarios |
| Auditoría / *accounting* | ¿Qué ocurrió y qué evidencia quedó? | Inicio de sesión, recurso, hora, origen, resultado |

**AAA** agrupa autenticación, autorización y contabilidad/registro. No equivale a la tríada CIA, aunque contribuye a ella.

```text
[Usuario o servicio] -> [Identificador] -> [Autenticación]
                                            |
                                     [Sesión / token]
                                            |
                                   [Decisión de acceso]
                                            |
                                     [Recurso protegido]
                                            |
                                      [Logs / SIEM]
```

**Perspectiva SOC:** en una investigación separá: (a) intento de autenticación, (b) autenticación exitosa, (c) emisión de sesión/token, (d) acción autorizada o denegada y (e) actividad posterior. Un `login_success` por sí solo no demuestra que se haya accedido a datos críticos.

## 2. Identidad digital y ciclo de vida

Una identidad digital es el conjunto de atributos y credenciales usados para representar a un sujeto en un sistema. Puede corresponder a una persona, servicio, dispositivo o carga de trabajo.

**Ciclo de vida:** solicitud → comprobación de identidad cuando corresponda → alta → asignación de acceso → uso → cambios de rol → revisión periódica → suspensión/revocación → baja. En organizaciones, el proceso *joiner–mover–leaver* controla altas, movimientos y bajas.

Distinguí:

- **Cuenta humana:** persona que accede a aplicaciones o sistemas.
- **Cuenta de servicio:** identidad para tareas automatizadas; no debería compartirse entre procesos sin justificación.
- **Identidad de máquina/workload:** certificado, identidad gestionada o token vinculado a un servicio.
- **Cuenta privilegiada:** permite cambios sensibles; merece monitoreo reforzado.
- **Cuenta de emergencia (*break glass*):** acceso excepcional, fuertemente controlado y auditado.

Riesgos del ciclo de vida: cuentas huérfanas, exempleados activos, secretos sin rotar, permisos acumulados, credenciales compartidas y cuentas de servicio con privilegios excesivos.

**Evidencia defensiva:** inventario de identidades, propietario, fecha de alta, última actividad, método de autenticación, roles, cambios y fecha de revisión.

## 3. Factores y métodos de autenticación

Los factores clásicos son:

1. **Conocimiento:** algo que sabés (contraseña, PIN).
2. **Posesión:** algo que tenés (llave FIDO2, dispositivo autenticador, token).
3. **Inherencia:** algo que sos (característica biométrica).

Una contraseña y un PIN son dos secretos, pero pertenecen a la misma categoría: **no constituyen por sí solos MFA**.

| Método | Mecanismo | Riesgos / notas defensivas |
|---|---|---|
| Contraseña | Secreto memorizado | Reutilización, phishing, robo de base de credenciales |
| TOTP | Código temporal generado desde secreto compartido | Puede ser robado en phishing en tiempo real; requiere reloj sincronizado |
| HOTP | Código basado en contador | Sincronización de contador y protección del secreto |
| SMS OTP | Código por telefonía | SIM swapping, interceptación, phishing; no es resistente al phishing |
| Push | Aprobación desde autenticador | Fatiga de notificaciones; mejorar con coincidencia de números/contexto |
| Llave FIDO2 / passkey | Desafío–respuesta con clave asimétrica ligada al sitio | Resistente al phishing; proteger recuperación y dispositivo |
| Certificado cliente | Prueba criptográfica de clave privada | Gestión de certificados, revocación y claves |
| Biometría | Verificación local de rasgo físico | Privacidad, tasas de error, presentación y recuperación |

**Biometría no es una contraseña secreta:** una huella puede utilizarse para desbloquear localmente una clave protegida. No implica que el sitio reciba la huella.

### Seguridad de autenticación: niveles de garantía

NIST SP 800-63-4 distingue la comprobación inicial de identidad (*IAL*), la garantía de autenticación (*AAL*) y la federación (*FAL*). El nivel requerido depende del riesgo. No deduzcas que una cuenta está en un nivel formal NIST solo porque utiliza MFA.

## 4. Contraseñas y credenciales

Una **credencial** es la información o mecanismo con el que se autentica una identidad. Puede ser una contraseña, una clave privada, un certificado o un secreto asociado a un autenticador.

### Amenazas a contraseñas

- **Password spraying:** pocas contraseñas frecuentes probadas contra muchas cuentas.
- **Credential stuffing:** prueba de combinaciones usuario/contraseña obtenidas de filtraciones previas.
- **Fuerza bruta online:** múltiples intentos contra un servicio; debe limitarse.
- **Ataque offline:** pruebas contra hashes obtenidos tras una exposición; requiere protección robusta del almacenamiento.
- **Phishing:** engaño para entregar el secreto; una contraseña larga no lo elimina.
- **Reutilización:** una filtración externa compromete cuentas de otros servicios.

### Política defensiva

- Favorecer contraseñas **largas, únicas y memorables**; permitir gestores de contraseñas y pegar contraseñas.
- Aplicar bloqueo o limitación de intentos, controles basados en riesgo y alertas.
- Comparar secretos nuevos con listas de contraseñas comprometidas, según política.
- Exigir cambio ante evidencia de compromiso; evitar rotaciones periódicas arbitrarias sin motivo.
- No almacenar contraseñas reversibles ni con SHA-256 simple. Emplear derivación específica para contraseñas, como **Argon2id** o alternativas adecuadas, con *salt* único y parámetros calibrados.
- Proteger secretos de servicio en gestores de secretos; registrar accesos sin registrar el valor secreto.

### Ejemplo de almacenamiento conceptual

```text
contraseña --[KDF para contraseñas + salt único]--> verificador almacenado
                           |
             comparación de un nuevo intento
```

El salt puede ser público; un *pepper*, si se usa, debe guardarse por separado como secreto. Las políticas concretas deben ajustarse a normas y riesgos, no copiarse sin evaluación.

## 5. MFA y autenticación resistente al phishing

**MFA** combina factores distintos; no todas las opciones son igualmente resistentes al phishing.

```text
[Usuario] -> [Contraseña] -> [Segundo factor] -> [Sesión]

[Usuario] -> [Passkey / WebAuthn] -> [Desafío firmado ligado al origen]
```

**TOTP/push/SMS** pueden ser interceptados o inducidos mediante ingeniería social. **FIDO2/WebAuthn** verifica desafíos con criptografía asimétrica y vincula la autenticación al origen/servicio; eso dificulta que un sitio falso reutilice la respuesta. Las passkeys pueden ser sincronizadas o ligadas a un dispositivo.

**Aspectos operativos que suelen olvidarse:**

- Inscripción de autenticadores: ¿quién autoriza agregar uno nuevo?
- Recuperación de cuenta: ¿se puede degradar MFA a un canal débil?
- Revocación: ¿qué pasa si se pierde un dispositivo?
- Acceso de emergencia: ¿cómo se controla sin crear una puerta trasera cotidiana?
- MFA fatigue: ¿se registran solicitudes rechazadas/repetidas?
- Acceso condicional: ¿se evalúan identidad, dispositivo, ubicación y riesgo?

**Señal SOC:** múltiples desafíos MFA seguidos de una aprobación inusual, especialmente con nuevo dispositivo o cambio posterior de credenciales, justifican correlación y validación.

## 6. Claves públicas, certificados, SSH y Kerberos

### Autenticación con clave pública

El usuario o dispositivo guarda la **clave privada** y registra la **clave pública** ante el servicio. En un protocolo de desafío–respuesta, el servicio verifica una prueba criptográfica sin necesitar la clave privada.

- La clave privada **no se comparte**.
- La pública no es una contraseña.
- Es importante autenticar al servidor y proteger el dispositivo/clave.
- Una firma válida demuestra posesión de clave, no necesariamente identidad real sin un vínculo confiable.

### SSH

SSH admite autenticación mediante claves. El cliente debe validar la **clave de host** del servidor: ignorar avisos de cambios de clave puede permitir conexiones al destino equivocado. Las claves del usuario pueden almacenarse con protección local; es recomendable gestionar altas, bajas y rotación.

### Certificados y PKI

Una PKI incluye certificados, autoridades certificadoras, cadenas de confianza y procedimientos de emisión/revocación. **TLS de servidor** y **TLS mutuo (mTLS)** tienen objetivos relacionados, pero mTLS agrega autenticación de cliente con certificado.

### Kerberos (contexto Windows/Active Directory)

Kerberos es un protocolo de autenticación basado en tickets y una autoridad confiable (*KDC*). En términos didácticos:

1. El cliente se autentica ante el servicio de autenticación del KDC.
2. Obtiene un **TGT** (*Ticket Granting Ticket*).
3. Solicita un ticket para un servicio específico.
4. Presenta el ticket de servicio al recurso.

La implementación real incorpora cifrado, claves, autenticadores, tiempos de validez y protecciones contra repetición.

**Riesgos a estudiar defensivamente:** abuso de cuentas de servicio, privilegios excesivos, tickets anómalos, problemas de sincronización horaria y actividad irregular de autenticación. En Active Directory la telemetría útil incluye eventos de Kerberos, inicios de sesión y cambios de grupos.

## 7. SSO, federación, OAuth 2.0, OpenID Connect y SAML

**SSO (Single Sign-On)** facilita reutilizar una autenticación para acceder a aplicaciones. **Federación** permite confiar en un proveedor de identidad externo.

| Tecnología | Función principal | Error frecuente |
|---|---|---|
| SAML 2.0 | Aserciones de identidad, típicamente SSO empresarial | Confundir una aserción con contraseña |
| OAuth 2.0 | Delegar **autorización** para acceder a recursos | Considerarlo por sí solo un protocolo de login |
| OpenID Connect (OIDC) | Capa de **autenticación** sobre OAuth 2.0 | Confundir ID token con access token |
| SCIM | Aprovisionamiento de identidades y grupos | Confundir provisión con autenticación |

### OAuth y OIDC: roles

- **Resource Owner:** entidad propietaria/autorizante del recurso.
- **Client:** aplicación que solicita acceso.
- **Authorization Server:** emite tokens tras aplicar políticas.
- **Resource Server:** API que recibe y valida access tokens.
- **Identity Provider (IdP):** servicio de identidad en escenarios de autenticación.

Un **access token** autoriza acceso a un recurso; un **ID token** informa de la autenticación al cliente OIDC; un **refresh token** puede permitir obtener nuevos access tokens, sujeto a controles. No son intercambiables.

**Buenas prácticas modernas:** authorization code con PKCE para aplicaciones públicas; validar `issuer`, `audience`, firma, expiración y otras condiciones apropiadas; restringir scopes; proteger refresh tokens y evitar secretos en URLs/logs.

## 8. Sesiones, cookies y tokens

HTTP no exige mantener estado entre solicitudes, pero las aplicaciones necesitan saber si un usuario sigue autenticado. Para eso existen sesiones.

### Sesión con identificador opaco

```text
1. Login validado
2. Servidor crea un ID impredecible y un estado de sesión
3. Navegador recibe cookie
4. Petición siguiente envía cookie
5. Servidor identifica sesión y verifica autorización
```

Un **token bearer** da acceso a quien lo presente válidamente; su robo puede permitir suplantación hasta su expiración/revocación según la arquitectura.

### Atributos de cookies

| Atributo | Función |
|---|---|
| `Secure` | Envía cookie solo por canal HTTPS apropiado |
| `HttpOnly` | Impide acceso directo desde JavaScript del navegador; no elimina CSRF |
| `SameSite=Strict/Lax` | Restringe envío en algunos contextos cross-site; defensa en profundidad contra CSRF |
| `Max-Age` / `Expires` | Controlan persistencia en navegador; el servidor debe manejar vencimiento |
| `Path`, `Domain` | Alcance de la cookie; no son mecanismos suficientes de aislamiento por sí solos |
| `__Host-` | Prefijo que exige condiciones fuertes de ámbito y canal en navegadores compatibles |

Ejemplo ilustrativo de cabecera **sin secreto real**:

```http
Set-Cookie: __Host-session=<valor-aleatorio>; Path=/; Secure; HttpOnly; SameSite=Strict
```

### Riesgos de sesión

- **Session hijacking:** uso no autorizado de una sesión.
- **Session fixation:** el atacante intenta fijar un identificador antes del login; mitigar regenerando ID al autenticarse.
- **CSRF:** acciones no deseadas usando una sesión del navegador; tokens anti-CSRF y controles de origen según aplicación.
- **XSS:** puede ejecutar código en origen; `HttpOnly` ayuda con robo directo de cookie, no resuelve XSS.
- **Sesiones persistentes:** riesgo si no vencen o no pueden revocarse.

**Defensas:** TLS en toda la sesión; identificadores aleatorios; rotación en autenticación/cambio de privilegio; expiraciones por inactividad y absolutas; cierre de sesión que invalida estado de servidor; reautenticación para cambios sensibles; detección de sesiones inusuales.

### JWT

Un JWT suele tener la forma `header.payload.signature` cuando es firmado con JWS. **Codificar en Base64url no significa cifrar**. Nunca incluyas secretos en claims legibles. Validá firma y algoritmo permitido, emisor, audiencia, tiempo y tipo esperado; no aceptes algoritmos elegidos de manera insegura por un token no confiable.

## 9. Autorización y modelos de control de acceso

Autenticar al usuario no le concede automáticamente todos los privilegios.

- **DAC:** el propietario controla determinados accesos.
- **MAC:** políticas obligatorias centralizadas.
- **RBAC:** permisos asignados a roles.
- **ABAC:** políticas basadas en atributos de sujeto, recurso, acción y entorno.
- **ReBAC:** decisiones basadas en relaciones (por ejemplo, miembro de proyecto).

**Principios:** mínimo privilegio; denegación por defecto; separación de funciones; revisión periódica; eliminación inmediata o programada de accesos al cambiar roles; control de privilegios administrativos mediante PAM/JIT/JEA cuando aplique.

### Fallos comunes de autorización

- **IDOR / BOLA:** un usuario autenticado accede a un objeto ajeno porque faltan verificaciones sobre el recurso.
- **Escalada vertical:** acción reservada a un rol superior.
- **Escalada horizontal:** acceso a datos de otro usuario con el mismo rol.
- **Confused deputy:** un servicio con privilegios actúa de forma indebida por solicitud de otro actor.

La verificación debe ocurrir **en el servidor y para cada operación sensible**, no solo ocultar un botón en la interfaz.

## 10. Protección de accesos y arquitectura defensiva

Una arquitectura de identidad segura combina controles **preventivos, detectivos y correctivos**.

| Riesgo | Prevención | Detección | Respuesta |
|---|---|---|---|
| Reutilización de contraseña | Passkeys/MFA, gestores, bloqueo de secretos expuestos | Intentos anómalos, accesos nuevos | Revocar sesiones, resetear credencial |
| Abuso de privilegios | RBAC, PAM, JIT | Cambios de grupos/roles, acciones administrativas | Revocar privilegios, investigar cambios |
| Token robado | Protección de sesiones, vida limitada, revocación | Uso desde dispositivos/redes inesperadas | Invalidar token/sesión |
| MFA fatigue | FIDO2, controles de contexto, number matching | Muchas solicitudes push/rechazos | Validar usuario, revocar credenciales si procede |
| Cuentas huérfanas | Proceso joiner–mover–leaver | Cuentas activas sin propietario o inactivas | Deshabilitar según procedimiento |

**Zero Trust aplicado a identidad:** verificar explícitamente, usar mínimo privilegio y evaluar contexto y señales continuas; no asumir que pertenecer a una LAN equivale a confianza.

## 11. Amenazas y patrones de abuso

### Password spraying frente a fuerza bruta

- **Spraying:** pocos secretos frecuentes contra muchas identidades; suele producir numerosos usuarios con uno o pocos fallos.
- **Fuerza bruta focalizada:** muchos intentos contra una cuenta.
- **Credential stuffing:** combinaciones previamente filtradas; puede producir éxitos tempranos.

### Robo de sesiones

Puede ocurrir por malware, exposición de token, vulnerabilidades web o acceso a dispositivos. Un éxito de login no siempre aparece inmediatamente antes del uso de una sesión robada.

### Compromiso de identidad federada

Un atacante puede intentar obtener acceso mediante permisos de una aplicación OAuth, cambios de métodos MFA o sesiones existentes. El Blue Team debe correlacionar cambios de consentimiento, inscripciones y acceso a aplicaciones.

### Ataques a MFA

Phishing de OTP, robo de códigos de recuperación, abuso de notificaciones, suplantación de soporte y recuperación de cuenta débil. **MFA es una defensa importante, no una garantía absoluta.**

## 12. Telemetría para SOC

Necesitamos saber **qué datos existen y qué datos faltan** antes de diseñar detecciones.

### Fuentes

- **Windows Security Log:** logons, fallos, cambios de grupos, cuentas y políticas.
- **Sysmon:** procesos, conexiones y otros eventos según configuración; no sustituye Security Log.
- **Linux:** `journald`, `auth.log` o `secure`, `sshd`, `sudo`, PAM, auditd (según distribución/configuración).
- **IdP/cloud:** inicios de sesión, MFA, cambios de métodos, consentimiento, emisión/revocación de sesiones si existe esa telemetría.
- **VPN, proxy, firewall, EDR:** contexto de dispositivo, red, sesión y proceso.

### Eventos Windows útiles (no todos están habilitados normalmente)

| ID | Significado principal | Nota |
|---|---|---|
| 4624 | Inicio de sesión exitoso | Analizar `LogonType`; un inicio local, de red o remoto difiere |
| 4625 | Inicio de sesión fallido | Revisar `Status`, `SubStatus`, usuario, origen y tipo |
| 4634 | Sesión de logon finalizada | No siempre equivale a logout web |
| 4648 | Uso de credenciales explícitas | Puede ser legítimo en administración |
| 4672 | Privilegios especiales asignados al logon | No demuestra ataque |
| 4720 / 4726 | Cuenta creada / eliminada | Correlacionar con solicitud aprobada |
| 4728 / 4732 / 4756 | Miembro agregado a grupos de seguridad de diferentes ámbitos | Analizar criticidad del grupo |
| 4740 | Cuenta bloqueada | Puede ser error de usuario o actividad maliciosa |
| 4768 / 4769 | Solicitudes Kerberos TGT / ticket de servicio | Relevante especialmente en controladores de dominio |
| 4771 | Error de preautenticación Kerberos | No confundir con todos los 4625 |
| 4776 | Validación de credenciales NTLM | Contextualizar origen y protocolo |

### Tipo de inicio de sesión (`LogonType`)

- `2`: interactivo local.
- `3`: acceso de red.
- `4`: procesamiento batch.
- `5`: servicio.
- `7`: desbloqueo.
- `10`: remoto interactivo, como RDP.
- `11`: interactivo con credenciales en caché.

**No deduzcas automáticamente RDP de cualquier 4624**: verificá tipo, origen y otros eventos.

### Campos normalizados mínimos

```text
@timestamp | event.provider | event.code | event.outcome
user.name | host.name | source.ip | source.port
logon.type | device.id | session.id | correlation.id
```

Los nombres de campos son un modelo normalizado, no un formato nativo universal.

**Preservación forense:** mantener hora original y UTC, zona horaria, fuente, método de adquisición, hash de exportación, herramientas y acciones realizadas. Registrar explícitamente ausencias o limitaciones de telemetría.

## 13. Investigaciones y casos de uso de detección

Una detección combina **hipótesis + fuentes + lógica + exclusiones + procedimiento de validación**.

### Caso A — Password spraying

**Hipótesis:** una dirección de origen registra fallos para múltiples cuentas en una ventana breve.

```text
Agrupar fallos por source.ip en 15 minutos.
Medir: eventos, usuarios distintos, proporción de éxitos posteriores.
Enriquecer: IP corporativa, NAT, VPN, proxy, dispositivos conocidos.
```

**Falsos positivos:** proxy compartido, contraseñas caducadas, aplicaciones con configuración rota. **Límite:** un atacante distribuido puede evitar umbrales por IP.

### Caso B — Cuenta bloqueada repetidamente

Correlacionar evento 4740 con 4625/4771 y solicitudes de asistencia. Preguntar si un dispositivo o servicio conserva contraseña vieja.

### Caso C — Acceso remoto inusual

Correlacionar 4624 `LogonType=10`, origen, usuario, tiempo, host y cambios posteriores. No marcar como amenaza únicamente por horario nocturno.

### Caso D — Escalada de privilegio

Detectar modificación de membresía a grupos críticos y comparar con ticket de cambio; seguir inicio de sesión y uso de privilegios posteriores.

### Caso E — MFA push anómalo

Varias solicitudes de autenticación rechazadas → aprobación → nuevo dispositivo o sesión → cambio sensible. Requiere eventos del proveedor de identidad.

### Caso F — Uso de sesión sin nuevo login

Analizar `session.id`, dispositivo, IP, user-agent y cambios de contexto. Una IP distinta puede deberse a redes móviles/VPN; buscar más evidencia antes de atribuir robo.

### Mi ficha reusable de detección

```text
Nombre:
Hipótesis:
Activo y riesgo:
Fuentes / campos:
Condición lógica:
Ventana temporal:
Exclusiones:
Enriquecimiento:
Severidad inicial:
Falsos positivos previsibles:
Validación en laboratorio:
Acción del analista:
Limitaciones:
```

## 14. Respuesta a incidentes de identidad y preservación forense

1. **Clasificar y contener:** confirmar el alcance y el riesgo; según autorización, revocar sesiones/tokens, deshabilitar cuenta o exigir nueva autenticación.
2. **Preservar:** exportar logs, configuraciones relevantes y registros de auditoría siguiendo el procedimiento. Calcular hash de los archivos exportados, registrar origen, custodio y hora.
3. **Determinar alcance:** aplicaciones accedidas, recursos afectados, nuevos dispositivos, cambios de permisos y posible movimiento lateral.
4. **Erradicar:** corregir acceso indebido, rotar secretos comprometidos, retirar métodos MFA desconocidos, revisar consentimientos y persistencia.
5. **Recuperar:** restablecer identidad de forma segura, reactivar accesos necesarios y monitorear recurrencia.
6. **Lecciones aprendidas:** mejorar reglas, cobertura, inscripción MFA, soporte y procesos de alta/baja.

**Cadena de custodia:** registrar quién tomó cada evidencia, cuándo, dónde, cómo fue copiada, su huella y las transferencias. Una coincidencia SHA-256 respalda integridad entre dos versiones comparadas; **no prueba por sí sola procedencia, autenticidad de origen ni licitud de la adquisición**.

**No publiques:** credenciales, tokens, cookies reales, direcciones personales, información de usuarios ni logs sensibles en GitHub.

## 15. Ejemplo completo: investigar accesos sospechosos

> Escenario **sintético** de entrenamiento. Las IP `192.0.2.0/24` y `198.51.100.0/24` se reservan para documentación.

```text
09:01Z | 4625 | user=operador1 | source=192.0.2.44    | host=SRV-A
09:02Z | 4625 | user=operador2 | source=192.0.2.44    | host=SRV-A
09:03Z | 4625 | user=operador3 | source=192.0.2.44    | host=SRV-A
09:06Z | 4624 | user=operador2 | source=198.51.100.15 | host=SRV-A | type=10
09:09Z | 4732 | actor=operador2 | member=operador2    | group=Administrators
```

**Hechos:** hay tres fallos de identidades diferentes desde un origen, un éxito remoto para una cuenta desde otro origen y un cambio de membresía. **Hipótesis:** spraying y eventual abuso de cuenta, pero falta demostrar relación causal entre orígenes y acciones. **Preguntas:** ¿IP 192.0.2.44 es un proxy? ¿El evento de grupo ocurrió realmente en ese host? ¿Quién autorizó la elevación? ¿Hay sesiones federadas o VPN? **Siguiente paso:** recoger eventos originales completos y verificar correspondencia de usuarios, identificadores, hosts y tiempos. **Estado inicial:** *sospechoso, no confirmado*.

## 16. Lista de competencias y errores comunes

Al terminar la unidad poder:

- Explicar autenticación, autorización, identidad, sesión y auditoría sin confundirlas.
- Comparar contraseña, TOTP, push, FIDO2 y certificados considerando riesgos reales.
- Interpretar una cookie segura y distinguir un JWT firmado de información cifrada.
- Identificar un `4625`, `4624`, `4740` y cambios de grupo; explicar limitaciones de cada uno.
- Distinguir un falso positivo por contraseña caducada de una secuencia más compatible con spraying.
- Formular hipótesis SOC que incluyan evidencia a favor/en contra.
- Elaborar un informe de incidente con horas normalizadas, integridad y cadena de custodia.

**Errores frecuentes:** «MFA = imposible de comprometer»; «OAuth 2.0 = login»; «JWT = cifrado»; «IP distinta = atacante»; «muchos 4625 = ataque confirmado»; «hash igual = archivo legítimo»; «estar autenticado = tener autorización»; «cerrar navegador = sesión revocada».

## 17. Glosario y referencias

**IAM:** gestión de identidades y accesos. **IdP:** proveedor de identidad. **MFA:** autenticación multifactor. **FIDO2/WebAuthn:** autenticación criptográfica orientada a resistencia al phishing. **SSO:** inicio de sesión único. **PAM:** acceso privilegiado. **TOTP:** contraseña temporal basada en tiempo. **OIDC:** capa de identidad sobre OAuth 2.0. **JWT:** formato de claims; no implica confidencialidad. **RBAC/ABAC:** autorización por roles/atributos. **SOC:** centro de operaciones de seguridad. **DFIR:** análisis forense digital y respuesta a incidentes. **Triage:** evaluación y priorización inicial. **Cadena de custodia:** registro de posesión y manejo de evidencia.

### Referencias primarias

- NIST SP 800-63-4 — Digital Identity Guidelines: https://csrc.nist.gov/pubs/sp/800/63/4/final
- NIST SP 800-63B-4 — Authentication and Lifecycle Management: https://pages.nist.gov/800-63-4/sp800-63b.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- FIDO Alliance — Passkeys: https://fidoalliance.org/passkeys-2/
- Microsoft — Windows Security Auditing: https://learn.microsoft.com/windows/security/threat-protection/auditing/basic-audit-logon-events
- Microsoft — Event 4625: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
- MITRE ATT&CK — Credential Access: https://attack.mitre.org/tactics/TA0006/
- MITRE ATT&CK — Valid Accounts: https://attack.mitre.org/techniques/T1078/
- RFC 6749 — OAuth 2.0: https://www.rfc-editor.org/rfc/rfc6749
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7519 — JWT: https://www.rfc-editor.org/rfc/rfc7519

