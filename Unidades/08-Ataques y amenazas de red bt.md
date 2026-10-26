# Unidad 8 — Ataques y amenazas de red | Blue Team

> **Ruta:** SOC Analyst L1 → Incident Response / DFIR  
> **Propósito:** Documentacion propia para identificar amenazas de red, distinguir fallas de ataques, seleccionar telemetría, investigar eventos y proponer mitigaciones proporcionadas.

## Índice

1. [Modelo mental de defensa de redes](#1-modelo-mental-de-defensa-de-redes)
2. [Disponibilidad, DoS y DDoS](#2-disponibilidad-dos-y-ddos)
3. [Técnicas y síntomas de denegación de servicio](#3-técnicas-y-síntomas-de-denegación-de-servicio)
4. [Suplantación y manipulación de comunicaciones](#4-suplantación-y-manipulación-de-comunicaciones)
5. [Riesgos de protocolos de red](#5-riesgos-de-protocolos-de-red)
6. [Visibilidad y fuentes de evidencia](#6-visibilidad-y-fuentes-de-evidencia)
7. [Detección y triage en un SOC](#7-detección-y-triage-en-un-soc)
8. [Mitigación y arquitectura defensiva](#8-mitigación-y-arquitectura-defensiva)
9. [Respuesta a incidentes y evidencia forense](#9-respuesta-a-incidentes-y-evidencia-forense)
10. [Casos de análisis](#10-casos-de-análisis)
11. [Mapa de competencias y progreso](#11-mapa-de-competencias-y-progreso)
12. [Glosario y referencias](#12-glosario-y-referencias)

---

## 1. Modelo mental de defensa de redes

### 1.1. Qué es un ataque de red

Es una acción destinada a alterar el funcionamiento, la confidencialidad, integridad o disponibilidad de sistemas comunicados por una red. No todo error, pico de tráfico ni paquete extraño es un ataque: la clasificación necesita contexto y evidencias.

**Activos protegidos:** enlaces, routers, switches, DNS, gateways, VPN, firewalls, aplicaciones, endpoints y servicios de identidad.  
**Superficies:** interfaces expuestas, protocolos habilitados, puertos, reglas, configuraciones y dependencias de terceros.  
**Controles:** prevención, detección, contención, recuperación y mejora.

### 1.2. Preguntas de un analista SOC

1. **Qué falla:** ¿latencia, errores de aplicación, pérdida de paquetes, interrupción total, tráfico desviado?
2. **Dónde:** ¿en el enlace, router, firewall, servidor, DNS o aplicación?
3. **Desde cuándo:** ¿cuál es la línea base y cuándo comenzó el cambio?
4. **A quién afecta:** ¿todos los usuarios, una subred, un servicio o una ruta?
5. **Qué evidencia lo demuestra:** ¿contadores, logs, PCAP, NetFlow, métricas de aplicación?
6. **Qué otras explicaciones existen:** ¿mantenimiento, campaña legítima, actualización, fallo del proveedor?
7. **Cuál es el siguiente paso autorizado:** ¿escalamiento, filtrado temporal, contacto con ISP, activación de protección?

### 1.3. Los indicadores no son pruebas

Un origen con muchas conexiones podría ser un escáner, un balanceador, un cliente defectuoso o una actividad maliciosa. **IOC** (indicador de compromiso) y **IOA** (indicador de comportamiento de ataque) orientan la investigación; no sustituyen la validación.

---

## 2. Disponibilidad, DoS y DDoS

### 2.1. La disponibilidad de la tríada CIA

Disponibilidad significa que personas y procesos autorizados puedan usar recursos cuando los necesiten. Depende de red, DNS, cómputo, almacenamiento, autenticación, aplicaciones y proveedores.

### 2.2. DoS

**Denial of Service:** degradación o interrupción deliberada de un servicio. Puede ocurrir por saturación de ancho de banda, agotamiento de conexiones, consumo de CPU/memoria o solicitudes costosas de procesar. Un DoS no requiere necesariamente cientos de máquinas.

### 2.3. DDoS

**Distributed Denial of Service:** denegación de servicio producida desde múltiples fuentes. Esa distribución dificulta distinguir el tráfico malicioso del legítimo y aplicar bloqueos sencillos por dirección.

| Aspecto | DoS | DDoS |
|---|---|---|
| Orígenes | Puede ser uno | Múltiples |
| Impacto | Depende del vector y capacidad | Depende del vector y capacidad |
| Mitigación | Puede requerir controles locales | Puede requerir capacidad aguas arriba/CDN/ISP |
| Identificación | No basta una IP | No basta contar IP distintas |

### 2.4. Capacidad y cuello de botella

Una infraestructura tiene capacidades finitas de **bits/s**, **paquetes/s**, **conexiones/s**, **consultas/s** y **trabajo por solicitud**. Son métricas diferentes: un caudal moderado en Mbps puede agotar CPU si cada solicitud es costosa.

```text
Tráfico legítimo ──────┐
Tráfico anómalo A ─────┼──> Firewall / enlace / aplicación ──> Usuarios
Tráfico anómalo B ─────┘       (capacidad limitada)
```

Si el enlace de entrada se satura, bloquear en el servidor puede llegar demasiado tarde: los paquetes ya ocuparon el enlace. Esto explica el valor de la mitigación del proveedor o de una red de distribución.

### 2.5. Cómo cuantificar una degradación

- **bps:** bits por segundo; mide caudal.
- **pps:** paquetes por segundo; revela presión en procesamiento de paquetes.
- **RPS/QPS:** solicitudes/consultas por segundo en aplicación o DNS.
- **Conexiones concurrentes:** presión sobre sockets/tablas de estado.
- **Latencia p50/p95/p99:** respuesta típica y de cola; elegir percentiles evita ocultar degradaciones.
- **Tasa de errores:** 5xx, timeouts, resets, consultas fallidas.
- **Saturación:** CPU, memoria, colas, sesiones de firewall y ancho de banda.

Una comparación válida necesita misma ventana temporal, zona horaria y criterio de medición.

---

## 3. Técnicas y síntomas de denegación de servicio

Estudiamos estos patrones **para reconocerlos y mitigarlos**, no para reproducirlos contra servicios ajenos.

### 3.1. Volumétricos

Buscan ocupar capacidad de transporte: alto bps/pps, congestión, pérdida de paquetes, colas y rendimiento bajo. Los orígenes observados pueden no corresponder a los atacantes reales si existe suplantación IP.

**Telemetría:** contadores de interfaces, NetFlow/IPFIX, métricas ISP, firewall, gráficos de ancho de banda.  
**Mitigación:** proveedor, filtrado upstream, scrubbing, CDN/Anycast según servicio.

### 3.2. Agotamiento de estado o protocolo

Presionan recursos de conexión o procesamiento de protocolos. Un ejemplo conocido es el **SYN flood**, relacionado con estados de establecimiento TCP.

**Señales:** SYN elevados frente a conexiones completas, backlog lleno, aumento de conexiones semiestablecidas; comprobar también pérdida de paquetes, firewalls y fallos de clientes.  
**Controles:** SYN cookies, ajuste de recursos, rate limits y mitigación especializada. Ninguna técnica es universal.

### 3.3. Capa 7 o aplicación

Solicitudes aparentemente válidas pueden consumir muchos recursos de aplicación, backend, autenticación o bases de datos. El volumen puede ser bajo en Mbps y muy alto en costo de cómputo.

**Telemetría:** rutas HTTP, códigos, tiempos, IP/ASN, agentes de usuario, sesiones, caché hit rate, métricas de backend.  
**Controles:** WAF, CDN, caché, límites adaptativos, optimización de endpoints y protección de origen.

### 3.4. Reflexión y amplificación

La **reflexión** utiliza un servicio intermedio para dirigir respuestas hacia otro destino, generalmente cuando el origen puede ser falsificado. La **amplificación** ocurre si las respuestas son más grandes que las solicitudes que las originan. Pueden coexistir; no son sinónimos.

Protocolos históricamente afectados incluyen DNS y NTP en configuraciones vulnerables o expuestas. En defensa, revisar servicios UDP innecesarios, límites de respuesta, política recursiva y filtrado de origen del proveedor (**BCP 38 / RFC 2827**).

### 3.5. Flash crowd versus DDoS

Una campaña comercial o una noticia puede generar tráfico legítimo inesperado. Diferenciadores útiles: distribución de rutas, sesiones completas, conversión de usuarios, comportamiento temporal, orígenes y métricas de negocio. Ninguno es concluyente por sí solo.

### 3.6. Matriz de síntomas

| Observación | Posible explicación | Dato para contrastar |
|---|---|---|
| Mbps al máximo, drops | Congestión / ataque volumétrico | Métricas ISP y baseline |
| SYN altos, pocas sesiones completas | Problema TCP / ataque de estado | Retransmisiones, backend, pérdida |
| RPS alto y CPU alta | Carga legítima o abuso L7 | URLs, tiempos, caché |
| DNS SERVFAIL elevado | Fallo DNS o abuso de infraestructura | Resolvedor y upstream |
| 5xx altos con tráfico normal | Fallo backend / dependencia | APM, logs, cambios recientes |

---

## 4. Suplantación y manipulación de comunicaciones

### 4.1. Spoofing de IP

Se falsifica la dirección IP de origen en paquetes. No permite por sí solo recibir respuestas destinadas a otra IP ni mantener cualquier conexión TCP arbitraria. Puede utilizarse en tráfico no orientado a conexión y ataques de reflexión.

**Detección/mitigación:** controles anti-spoofing en bordes, uRPF cuando proceda, filtrado de salida/entrada y coordinación con operador. Cuidado: rutas asimétricas complican algunas configuraciones uRPF.

### 4.2. ARP spoofing / poisoning

ARP traduce direcciones IPv4 a direcciones de enlace dentro de un dominio local. Si una asociación IP→MAC se manipula, el tráfico puede desviarse o perderse.

**Observables:** cambios repetidos de MAC para una IP crítica, duplicidades, variaciones del gateway, alertas de switch. **Controles:** DHCP snooping y Dynamic ARP Inspection en diseños compatibles, segmentación, controles físicos y cifrado extremo a extremo.

### 4.3. DNS spoofing / poisoning / hijacking

- **Spoofing:** información DNS falsificada.
- **Cache poisoning:** contaminación de caché de un resolvedor.
- **Hijacking:** alteración del camino o configuración de resolución.

**Señales:** respuestas distintas respecto de referencias confiables, resoluciones hacia infraestructura inusual, alteraciones de configuración DNS. **Protecciones:** DNSSEC para validar datos firmados, gestión de cambios, seguridad del registrador, MFA, monitoreo de zonas y resolvedores.

### 4.4. Intermediario (MITM / adversary-in-the-middle)

Un tercero obtiene capacidad de observar o alterar una comunicación. Puede surgir por red local comprometida, proxy no autorizado u otro punto intermedio. **TLS correctamente validado** protege la confidencialidad e integridad del canal frente a muchos de estos escenarios, pero no corrige aplicaciones comprometidas o confianza mal configurada.

### 4.5. DHCP spoofing y rogue DHCP

Un servidor DHCP no autorizado puede ofrecer configuraciones indebidas (gateway, DNS). **Evidencias:** ofertas desde MAC/puertos no autorizados, cambios de gateway o DNS, inventario de switches. **Defensas:** DHCP snooping, control de puertos, segmentación y monitoreo.

### 4.6. MAC spoofing

La MAC de un equipo puede modificarse o falsificarse. Por ello no constituye una identidad fuerte por sí sola. Controles de acceso a red, 802.1X y políticas de identidad ofrecen garantías diferentes.

### 4.7. Riesgos de IPv6

IPv6 utiliza Neighbor Discovery (ICMPv6), no ARP. Riesgos de configuración incluyen anuncios de routers no autorizados y descubrimiento de vecinos manipulado. **Controles:** RA Guard cuando sea apropiado, controles de acceso, monitoreo ICMPv6 y diseño consciente de IPv6. **No bloquear ICMPv6 indiscriminadamente**: es indispensable para operaciones normales.

---

## 5. Riesgos de protocolos de red

| Protocolo/servicio | Riesgo relevante | Controles y señales defensivas |
|---|---|---|
| TCP | abuso de estado, exposición de servicios | políticas stateful, SYN cookies, contadores |
| UDP | spoofing/reflexión en servicios expuestos | limitar servicios, controles upstream, anti-spoofing |
| ICMP/ICMPv6 | abuso o diagnósticos indiscriminadamente bloqueados | tipos permitidos necesarios, rate control selectivo |
| ARP | envenenamiento local | DAI, DHCP snooping, monitoreo |
| DNS | desvío, poisoning, tunneling, amplificación | DNSSEC, logs, recursión restringida, alertas |
| DHCP | gateway/DNS malicioso | DHCP snooping, inventario |
| SNMP v1/v2c | comunidades débiles y exposición | preferir v3, segmentación, cuentas mínimas |
| Telnet/FTP tradicional | credenciales/contenido sin protección nativa | SSH/SFTP/FTPS según caso, deshabilitar legado |
| BGP | anuncios erróneos o secuestro de rutas | filtrado, RPKI/ROV, coordinación ISP |
| HTTP sin TLS | lectura/manipulación en tránsito | HTTPS y validación TLS |
| SMB/RDP/SSH | exposición administrativa y abuso de credenciales | segmentación, MFA donde proceda, monitoreo |

**RPKI/ROV:** herramientas para validar autorizaciones de origen de rutas BGP; no garantizan por sí solas toda la seguridad del encaminamiento.

---

## 6. Visibilidad y fuentes de evidencia

### 6.1. Qué aporta cada fuente

| Fuente | Qué permite observar | Limitación |
|---|---|---|
| PCAP | encabezados y contenido visible del tráfico capturado | punto de captura; cifrado; volumen |
| NetFlow/IPFIX | metadatos de flujos y volúmenes | generalmente sin carga útil |
| Logs de firewall | decisiones, sesiones, reglas, NAT | visibilidad condicionada por reglas/configuración |
| DNS logs | nombres consultados y códigos | DoH/DoT fuera de visibilidad, cachés |
| Proxy/WAF | solicitudes de aplicaciones y resultados | tráfico no inspeccionado |
| CDN/ISP | ataques y saturación aguas arriba | acceso a datos depende de proveedor |
| EDR | procesos, sockets, identidad, conexiones | cobertura del agente |
| Métricas de sistema | CPU, memoria, sockets y latencia | no atribuyen causa por sí solas |

### 6.2. Cinco campos base de un flujo

**IP origen, IP destino, puerto origen, puerto destino y protocolo**; también registrar timestamp, volumen, interfaz y estado cuando existan. Con NAT, distinguir direcciones antes/después de traducción y conservar logs de mapeo respetando políticas.

### 6.3. Baselines

La línea base es el comportamiento esperado según horario, día, servicio y estacionalidad. Un aumento del 200 % no significa nada sin conocer valores absolutos, horarios y actividad empresarial.

### 6.4. Herramientas de análisis

- Wireshark: lectura detallada de PCAP.
- `tcpdump`: captura limitada a interfaces propias/autorizadas.
- `ss`, `ip`, `netstat`: estados locales.
- SIEM (Elastic, Splunk, Sentinel): correlación y alertas.
- Zeek/Suricata: telemetría y detección de red.
- Métricas de CDN/WAF: análisis de solicitudes y mitigación L7.

Comandos de **observación local**:

```bash
ip -br addr
ip route
ss -s
ss -tuna
```

En Windows PowerShell:

```powershell
Get-NetTCPConnection | Group-Object State | Select-Object Name,Count
Get-NetIPConfiguration
```

### 6.5. PCAP no equivale a verdad completa

Puede faltar parte del tráfico por pérdida de captura, enlaces distintos, offloading, asimetría o cifrado. La ausencia de paquetes en un PCAP no prueba ausencia de tráfico en toda la organización.

---

## 7. Detección y triage en un SOC

### 7.1. Secuencia de triage

1. Confirmar fecha, servicio, impacto y severidad preliminar.
2. Verificar salud de telemetría y sincronización de tiempo.
3. Comparar métricas de antes/durante/después.
4. Agrupar tráfico por destino, origen, ASN, puertos, protocolo y ruta, según visibilidad.
5. Correlacionar con deploys, mantenimientos y avisos ISP.
6. Clasificar hipótesis y grado de confianza.
7. Escalar/activar playbook según umbrales y autoridad.
8. Documentar resultados y seguimiento.

### 7.2. Reglas de detección conceptuales

**Posible aumento súbito de SYN:** `SYN/s > umbral relativo a baseline` **y** `conexiones establecidas / SYN < umbral de referencia`, durante varias ventanas. Excluir ventanas de mantenimiento y comparar con pérdida de paquetes. No es regla universal.

**Abuso de solicitudes L7:** `RPS por ruta aumenta` **y** `latencia p95/5xx crecen`, con concentración o distribución de orígenes atípica. Validar con métricas del backend.

**Posible anomalía ARP:** una IP de gateway asociada a más de una MAC inesperada en corto tiempo. Validar cambios legítimos de HA, virtualización o failover.

### 7.3. Falsos positivos y negativos

- **Falso positivo:** un aumento legítimo clasificado como incidente.
- **Falso negativo:** no detectar un abuso de bajo volumen.

Optimizar una detección requiere registrar casos, revisar umbrales y validar hipótesis: una regla que nunca alerta no necesariamente funciona bien.

### 7.4. Prioridad

Severidad orientativa = **impacto en usuarios + criticidad del servicio + alcance + evidencia de actividad adversaria**. El volumen de tráfico solo no determina severidad.

---

## 8. Mitigación y arquitectura defensiva

### 8.1. Antes de un incidente

- Inventariar servicios expuestos, dependencias y proveedores.
- Disponer de métricas de baseline y alertas confiables.
- Definir contactos y procedimientos con ISP, CDN y proveedor DNS.
- Usar CDN/WAF o protección especializada cuando el caso lo justifique.
- Configurar redundancia, límites, caché y cuotas de recursos.
- Restringir puertos y servicios innecesarios.
- Preparar runbooks y simulacros.

### 8.2. Durante un incidente

| Situación | Respuesta posible | Riesgo de actuar sin análisis |
|---|---|---|
| Enlace saturado | coordinación ISP/scrubbing | bloqueo local no libera enlace |
| Abuso HTTP | WAF/rate limiting/caché | bloquear usuarios válidos |
| Estado TCP agotado | ajustes/SYN cookies/servicios perimetrales | efectos sobre clientes legítimos |
| DNS bajo presión | anycast/respuesta de proveedor/restricción de recursión | romper resolución |
| Suplantación local | aislar segmento/validar switch/DAI | pérdida de conectividad por error |

**Rate limiting:** limitar tasas según criterios apropiados. Umbrales estáticos por IP pueden perjudicar usuarios tras CGNAT, proxies corporativos o redes compartidas.

### 8.3. Firewall, IPS y WAF

- Firewall L3/L4: controla IP, puertos, estado y protocolos.
- IPS: inspecciona y puede bloquear patrones según reglas.
- WAF: controles específicos de tráfico HTTP y lógica de aplicación.

No reemplazan observabilidad, diseño seguro ni protección a nivel proveedor.

### 8.4. Resiliencia

Diseñar para **absorber, degradar de forma controlada y recuperar**. Definir SLO/SLA, RTO/RPO cuando correspondan, prioridades de negocio, capacidad y procedimientos de cambio seguro.

---

## 9. Respuesta a incidentes y evidencia forense

### 9.1. Principios DFIR

- Mantener reloj y zona horaria documentados (ideal UTC en eventos).
- Preservar logs originales antes de transformarlos; trabajar con copias.
- Calcular hashes (SHA-256) de artefactos almacenados.
- Registrar fuente, adquisición, fecha, responsable y ubicación de evidencias.
- No atribuir un ataque a un actor solo por IP/geolocalización.
- Separar **hechos**, **hipótesis** y **conclusiones**.

### 9.2. Cadena de custodia básica

```text
ID de evidencia:
Origen (equipo, interfaz, proveedor):
Fecha/hora UTC de adquisición:
Método/herramienta:
Responsable:
Nombre del archivo:
SHA-256:
Ubicación y permisos:
Transferencias/cambios de custodia:
```

Un hash acredita coincidencia de bytes entre dos momentos; **no prueba por sí solo procedencia, autenticidad ni ausencia de manipulación antes de la adquisición**.

### 9.3. Modelo de informe SOC

```text
Título e ID:
Fecha y zona horaria:
Servicio y propietarios:
Resumen ejecutivo:
Impacto en CIA:
Línea de tiempo:
Fuentes consultadas:
Indicadores observados:
Evidencias y hashes:
Hipótesis confirmadas/descartadas:
Acciones autorizadas y resultados:
Riesgo residual:
Recomendaciones:
Estado y siguientes pasos:
```

---

## 10. Casos generales de análisis

### Caso A: sitio lento durante un lanzamiento

**Datos:** RPS se triplica, porcentaje de errores estable, CDN cache hit alto, ventas suben.  
**Hipótesis:** aumento legítimo; medir backend y colas antes de declarar DoS.  
**Decisión:** ampliar capacidad si corresponde, mantener vigilancia.

### Caso B: servicio inaccesible y enlace saturado

**Datos:** interfaz WAN cerca del máximo, drops elevados, múltiples destinos externos/orígenes aparentemente dispersos.  
**Hipótesis:** saturación externa; DDoS posible, sin atribución por IP.  
**Decisión:** activar proveedor, preservar métricas y determinar si existe incidente.

### Caso C: cambios de MAC para el gateway

**Datos:** registros ARP muestran dos MAC alternando para la IP del gateway.  
**Alternativas:** failover legítimo, virtualización, error de configuración o spoofing.  
**Decisión:** verificar inventario, switch, cambios y ventana temporal.

### Caso D: consultas DNS anómalas

**Datos:** picos de NXDOMAIN, etiquetas largas y dominios poco frecuentes.  
**Alternativas:** cliente defectuoso, herramienta legítima o tunneling.  
**Decisión:** correlacionar proceso origen, destino, volumen, periodos y clasificación.

---

## 11. Mapa de competencias y progreso

- [ ] Diferencio DoS, DDoS, saturación de enlace y agotamiento L7.
- [ ] Identifico fuentes de datos para investigar caídas de disponibilidad.
- [ ] Explico spoofing IP, ARP, DNS y DHCP sin confundirlos.
- [ ] Reconozco limitaciones de IP de origen, PCAP y geoatribución.
- [ ] Interpreto bps, pps, RPS, p95, 5xx, SYN y retransmisiones.
- [ ] Creo una línea base y defino una hipótesis verificable.
- [ ] Diseño detecciones con falsos positivos plausibles.
- [ ] Propongo mitigaciones que no agraven el incidente.
- [ ] Conservo artefactos, calculo SHA-256 y documento custodia.
- [ ] Redacto un informe de triage defendible con evidencias.

**Evidencia de portfolio recomendada:** informe de análisis de una caída simulada + PCAP de laboratorio + tabla de métricas + reglas de correlación + recomendaciones; subir solo datos propios o sintéticos, sin direcciones internas sensibles, secretos ni PCAP de terceros.

**Laboratorios de esta unidad:** [`../laboratorios/Unidad-08-LABORATORIOS.md`](../laboratorios/Unidad-08-LABORATORIOS.md)

---

## 12. Glosario y referencias

**DoS:** denegación de servicio. **DDoS:** denegación distribuida. **PPS:** paquetes por segundo. **RPS:** solicitudes por segundo. **IPFIX:** exportación de información de flujos. **PCAP:** archivo de captura de paquetes. **SYN:** bandera TCP de inicio. **ARP:** resolución IPv4→dirección de enlace. **DAI:** inspección dinámica de ARP. **RPKI:** infraestructura para validación de recursos de rutas. **WAF:** firewall de aplicación web. **Scrubbing:** filtrado de tráfico malicioso en infraestructura especializada. **Baseline:** comportamiento de referencia.

### Fuentes

- [NIST SP 800-61 Rev. 3 — Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [RFC 2827 / BCP 38 — Network Ingress Filtering](https://www.rfc-editor.org/rfc/rfc2827)
- [RFC 9293 — TCP](https://www.rfc-editor.org/rfc/rfc9293)
- [RFC 826 — ARP](https://www.rfc-editor.org/rfc/rfc826)
- [MITRE ATT&CK — Enterprise](https://attack.mitre.org/)
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [CISA — DDoS resources](https://www.cisa.gov/resources-tools)

---

**Nota de aprendizaje:** esta guía combina fundamentos, criterios profesionales y escenarios hipotéticos. Los resultados de ejercicios y la experiencia laboral se documentan por separado; no se presentan ejemplos como investigaciones ejecutadas.
