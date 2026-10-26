
# Unidad 2 — Protocolos de Comunicación y Fundamentos de Ciberseguridad

> **Área:** Ciberseguridad y redes informáticas  
> **Nivel:** Fundamentos e introducción técnica  
> **Objetivo:** Comprender los principios de seguridad de la información, los mecanismos criptográficos, las amenazas, la autenticación y el funcionamiento de los principales protocolos de comunicación.

---

# Índice

1. [Fundamentos de seguridad: tríada CIA](#1-fundamentos-de-seguridad-tríada-cia)
2. [Amenazas, vulnerabilidades y riesgos](#2-amenazas-vulnerabilidades-y-riesgos)
3. [Tipos de ataques informáticos](#3-tipos-de-ataques-informáticos)
4. [Fundamentos de criptografía](#4-fundamentos-de-criptografía)
5. [Funciones hash y protección de contraseñas](#5-funciones-hash-y-protección-de-contraseñas)
6. [Autenticación, autorización y controles de acceso](#6-autenticación-autorización-y-controles-de-acceso)
7. [Introducción a los protocolos de comunicación](#7-introducción-a-los-protocolos-de-comunicación)
8. [TCP: funcionamiento detallado](#8-tcp-funcionamiento-detallado)
9. [UDP: funcionamiento detallado](#9-udp-funcionamiento-detallado)
10. [Segmentación, paquetes y puertos](#10-segmentación-paquetes-y-puertos)
11. [HTTP y HTTPS](#11-http-y-https)
12. [TLS y certificados digitales](#12-tls-y-certificados-digitales)
13. [FTP, FTPS y SFTP](#13-ftp-ftps-y-sftp)
14. [DNS y seguridad de resolución](#14-dns-y-seguridad-de-resolución)
15. [SMTP y protocolos de correo](#15-smtp-y-protocolos-de-correo)
16. [Telnet y SSH](#16-telnet-y-ssh)
17. [SNMP y administración de redes](#17-snmp-y-administración-de-redes)
18. [ARP y sus vulnerabilidades](#18-arp-y-sus-vulnerabilidades)
19. [ICMP y diagnóstico de redes](#19-icmp-y-diagnóstico-de-redes)
20. [Puertos conocidos y servicios asociados](#20-puertos-conocidos-y-servicios-asociados)
21. [Análisis de una comunicación segura](#21-análisis-de-una-comunicación-segura)
22. [Herramientas y prácticas de laboratorio](#22-herramientas-y-prácticas-de-laboratorio)
23. [Buenas prácticas de seguridad](#23-buenas-prácticas-de-seguridad)
24. [Glosario](#24-glosario)
25. [Referencias técnicas](#25-referencias-técnicas)

---

# 1. Fundamentos de seguridad: tríada CIA

## 1.1. ¿Qué es la seguridad de la información?

La seguridad de la información es el conjunto de principios, procesos, tecnologías y controles destinados a proteger la información frente a accesos, modificaciones, pérdidas, interrupciones o divulgaciones no autorizadas.

No se limita a instalar antivirus o establecer contraseñas.

También incluye:

- Protección de redes.
- Seguridad de aplicaciones.
- Administración de identidades.
- Gestión de vulnerabilidades.
- Respaldo de información.
- Monitoreo.
- Respuesta a incidentes.
- Seguridad física.
- Capacitación de usuarios.

Uno de sus modelos fundamentales es la **tríada CIA**.

CIA corresponde a:

- **Confidentiality:** confidencialidad.
- **Integrity:** integridad.
- **Availability:** disponibilidad.

## 1.2. Confidencialidad

La confidencialidad busca que la información solamente pueda ser conocida por personas, procesos o sistemas autorizados.

### Ejemplo

Una empresa almacena información de sus empleados.

No todos los trabajadores deberían poder consultar datos personales o salariales de otros empleados.

Para proteger esa información se pueden utilizar:

- Controles de acceso.
- Cifrado.
- Autenticación.
- Segmentación de redes.
- Clasificación de información.

### Amenazas a la confidencialidad

- Robo de credenciales.
- Interceptación de tráfico.
- Accesos no autorizados.
- Exfiltración de información.
- Exposición accidental de bases de datos.

## 1.3. Integridad

La integridad busca preservar la exactitud y consistencia de la información, evitando modificaciones no autorizadas o no detectadas.

### Ejemplo

Un sistema bancario registra una transferencia de $10.000.

Si un atacante consigue modificar el valor a $100.000, se ha comprometido la integridad.

### Mecanismos de protección

- Funciones hash.
- Códigos de autenticación de mensajes.
- Firmas digitales.
- Controles de permisos.
- Registros de auditoría.
- Validaciones de datos.

Una función hash simple puede ayudar a detectar modificaciones, pero no autentica por sí sola al remitente.

## 1.4. Disponibilidad

La disponibilidad busca que la información y los servicios estén accesibles cuando los usuarios autorizados los necesitan.

### Ejemplo

Un hospital necesita acceder a sus sistemas durante una emergencia.

Si el servidor deja de funcionar, la información puede seguir siendo confidencial e íntegra, pero no está disponible.

### Mecanismos de protección

- Redundancia.
- Copias de seguridad.
- Balanceo de carga.
- Monitoreo.
- Recuperación ante desastres.
- Protección contra ataques de denegación de servicio.

## 1.5. Relación entre los tres principios

Los principios CIA se complementan.

| Situación | Principio afectado |
|---|---|
| Un atacante lee documentos privados | Confidencialidad |
| Se modifican registros sin autorización | Integridad |
| Un servidor deja de responder | Disponibilidad |
| Un ransomware cifra archivos e impide utilizarlos | Principalmente disponibilidad; puede afectar otros principios |
| Se filtran contraseñas | Confidencialidad |
| Se modifica una configuración crítica | Integridad y posiblemente disponibilidad |

Un incidente puede afectar simultáneamente varios principios.

## 1.6. Otros principios importantes

Además de CIA, se consideran:

**Autenticidad:** capacidad de verificar la identidad o procedencia de una entidad o información.

**Trazabilidad:** posibilidad de relacionar acciones con eventos, sistemas o identidades mediante registros.

**Responsabilidad:** asignación de responsabilidades sobre acciones y recursos.

**No repudio:** propiedad por la cual se dispone de evidencias que dificultan negar válidamente una acción o comunicación. Las firmas digitales pueden contribuir a este objetivo, dependiendo del contexto y del sistema.

---

# 2. Amenazas, vulnerabilidades y riesgos

Estos conceptos están relacionados, pero no significan lo mismo.

## 2.1. Activo

Un activo es un recurso que tiene valor para una organización.

Ejemplos:

- Información.
- Servidores.
- Computadoras.
- Aplicaciones.
- Credenciales.
- Infraestructura de red.
- Servicios empresariales.

## 2.2. Amenaza

Una amenaza es una circunstancia, actor o evento capaz de provocar un daño.

Ejemplos:

- Un atacante.
- Un error humano.
- Un incendio.
- Un programa malicioso.
- Una falla eléctrica.

## 2.3. Vulnerabilidad

Una vulnerabilidad es una debilidad que puede ser explotada o que facilita la materialización de una amenaza.

Ejemplos:

- Software desactualizado.
- Contraseñas débiles.
- Configuraciones incorrectas.
- Servicios innecesariamente expuestos.
- Falta de controles de acceso.

## 2.4. Riesgo

El riesgo representa la posibilidad de sufrir consecuencias negativas debido a eventos que afectan activos.

En un análisis básico puede pensarse como una combinación de:

- Probabilidad.
- Impacto.

Sin embargo, las metodologías profesionales pueden incorporar exposición, amenazas, vulnerabilidades y otros factores.

### Ejemplo

Una empresa tiene un servidor con información confidencial.

El servidor utiliza software vulnerable y está accesible desde Internet.

- Activo: servidor y datos.
- Vulnerabilidad: software vulnerable.
- Amenaza: posible explotación.
- Impacto: filtración o interrupción.
- Riesgo: posibilidad y consecuencias del incidente.

## 2.5. Controles de seguridad

Los controles son medidas destinadas a modificar o reducir riesgos.

### Según su función

| Tipo | Objetivo | Ejemplo |
|---|---|---|
| Preventivo | Evitar incidentes | MFA |
| Detectivo | Identificar eventos | Monitoreo de logs |
| Correctivo | Corregir problemas | Restauración de sistemas |
| Disuasorio | Desalentar acciones | Avisos y controles visibles |
| Compensatorio | Reducir riesgos cuando no se aplica otro control | Segmentación adicional |

Los controles también pueden clasificarse como administrativos, técnicos o físicos.

---

# 3. Tipos de ataques informáticos

## 3.1. ¿Qué es un ciberataque?

Un ciberataque es una acción deliberada destinada a comprometer sistemas, información, servicios o comunicaciones.

Los ataques pueden dirigirse contra:

- Personas.
- Dispositivos.
- Aplicaciones.
- Redes.
- Servidores.
- Infraestructura.
- Organizaciones.

## 3.2. Malware

Malware significa software malicioso.

Es un término general que comprende diferentes categorías.

### Virus

Código malicioso que se incorpora a otros archivos o programas y puede propagarse cuando se ejecutan.

### Gusano — Worm

Malware capaz de propagarse entre sistemas, frecuentemente mediante mecanismos automatizados.

### Troyano

Programa que aparenta cumplir una función legítima, pero incorpora comportamientos maliciosos.

### Ransomware

Malware que busca impedir el acceso a información o sistemas, frecuentemente mediante cifrado, para exigir un pago.

Algunas campañas también roban información y amenazan con publicarla.

### Spyware

Software diseñado para recopilar información de manera no autorizada.

### Rootkit

Conjunto de técnicas o componentes destinados a ocultar actividad y mantener acceso privilegiado o persistencia.

## 3.3. Ingeniería social

Consiste en manipular personas para obtener información o inducir acciones perjudiciales.

Ejemplos:

- Solicitar credenciales.
- Suplantar personal de soporte.
- Enviar mensajes fraudulentos.
- Convencer a un usuario de ejecutar archivos maliciosos.

### Phishing

Ataque mediante comunicaciones engañosas que buscan obtener información o provocar acciones.

### Spear phishing

Phishing dirigido a una persona u organización específica.

### Smishing

Phishing mediante mensajes SMS u otros mensajes móviles.

### Vishing

Phishing mediante llamadas o comunicaciones de voz.

## 3.4. Ataques de fuerza bruta

Consisten en probar múltiples posibilidades para descubrir una credencial u otro secreto.

Variantes relacionadas:

- Prueba exhaustiva de contraseñas.
- Ataques de diccionario.
- Password spraying.
- Credential stuffing.

No son técnicas idénticas.

**Password spraying:** prueba pocas contraseñas frecuentes contra muchas cuentas.

**Credential stuffing:** utiliza combinaciones de credenciales previamente obtenidas para intentar acceder a otros servicios.

### Controles defensivos

- MFA.
- Contraseñas robustas.
- Límites de intentos.
- Detección de comportamientos anómalos.
- Bloqueo de credenciales comprometidas.

## 3.5. DoS y DDoS

### DoS — Denial of Service

Busca impedir o degradar el funcionamiento normal de un servicio.

### DDoS — Distributed Denial of Service

Busca el mismo objetivo utilizando múltiples fuentes distribuidas.

### Diferencia

| DoS | DDoS |
|---|---|
| Puede originarse en una sola fuente | Utiliza múltiples fuentes |
| Puede ser más sencillo de filtrar | Puede distribuir tráfico entre muchos orígenes |
| Afecta disponibilidad | Afecta disponibilidad |

### Ejemplos de categorías

- Ataques volumétricos.
- Agotamiento de recursos.
- Ataques a protocolos.
- Ataques a aplicaciones.

## 3.6. Man-in-the-Middle

Un ataque de intermediario ocurre cuando un tercero consigue situarse entre participantes de una comunicación.

Puede intentar:

- Observar información.
- Modificar mensajes.
- Redirigir tráfico.
- Suplantar extremos.

La validación correcta de certificados y el cifrado autenticado ayudan a proteger las comunicaciones.

## 3.7. Spoofing

Spoofing significa suplantación o falsificación de identidad o información.

Ejemplos:

- IP spoofing.
- ARP spoofing.
- DNS spoofing.
- Email spoofing.

Cada técnica actúa sobre mecanismos diferentes.

## 3.8. Replay Attack

Un ataque de repetición consiste en capturar una comunicación válida y volver a transmitirla para intentar provocar una acción no autorizada.

Los mecanismos defensivos pueden incluir:

- Nonces.
- Marcas temporales.
- Números de secuencia.
- Tokens de un solo uso.
- Protocolos de autenticación resistentes a repetición.

## 3.9. Ataques a aplicaciones

### SQL Injection

Ocurre cuando entradas no confiables pueden alterar la estructura de una consulta SQL.

### Cross-Site Scripting — XSS

Permite introducir contenido ejecutable no autorizado en el contexto de una aplicación web.

### CSRF

Busca inducir a un navegador autenticado a realizar acciones no deseadas.

### Path Traversal

Intenta acceder a rutas o archivos fuera del directorio previsto por una aplicación.

### Controles generales

- Validación de entradas.
- Consultas parametrizadas.
- Codificación de salida.
- Gestión segura de sesiones.
- Principio de mínimo privilegio.
- Actualización de dependencias.

---

# 4. Fundamentos de criptografía

## 4.1. ¿Qué es la criptografía?

La criptografía es una disciplina que estudia técnicas matemáticas para proteger información y comunicaciones.

Puede contribuir a proporcionar:

- Confidencialidad.
- Integridad.
- Autenticidad.
- Autenticación.
- Evidencia criptográfica de determinadas acciones.

## 4.2. Texto plano y texto cifrado

**Texto plano:** información antes de aplicar cifrado.

**Texto cifrado:** resultado de aplicar un algoritmo de cifrado.

Ejemplo conceptual:

```text
Texto plano:
HOLA

       |
       v

Algoritmo de cifrado + clave

       |
       v

Texto cifrado:
Datos no interpretables sin los elementos necesarios
```

Un cifrado moderno no consiste simplemente en reemplazar letras por otras.

## 4.3. Cifrado simétrico

Utiliza una clave secreta compartida para cifrar y descifrar información.

```text
Emisor                      Receptor
  |                            |
Clave secreta             Misma clave
  |                            |
Cifrado                    Descifrado
  |                            |
  +-------- Mensaje ---------->+
```

### Ventajas

- Generalmente eficiente para grandes cantidades de datos.
- Adecuado para proteger comunicaciones y almacenamiento.

### Desafío principal

La clave debe distribuirse y protegerse correctamente.

### AES

AES significa Advanced Encryption Standard.

Es un algoritmo de cifrado simétrico de bloques.

Utiliza claves de:

- 128 bits.
- 192 bits.
- 256 bits.

AES trabaja con bloques de 128 bits.

Para cifrar información de manera segura se necesita un modo de operación apropiado.

Por ejemplo, AES-GCM permite cifrado autenticado, proporcionando confidencialidad e integridad bajo condiciones de uso correctas.

## 4.4. Cifrado asimétrico

Utiliza un par de claves relacionadas matemáticamente:

- Clave pública.
- Clave privada.

La clave pública puede distribuirse.

La clave privada debe mantenerse protegida.

### Ejemplo conceptual

```text
Clave pública del destinatario
            |
            v
     Cifrar información
            |
            v
      Texto cifrado
            |
            v
Clave privada del destinatario
            |
            v
     Recuperar información
```

No todos los algoritmos asimétricos se utilizan directamente para cifrar mensajes.

Algunos se utilizan para firmas digitales o acuerdos de claves.

### Algoritmos y familias relevantes

- RSA.
- Criptografía de curvas elípticas.
- ECDH para acuerdos de claves.
- ECDSA y EdDSA para firmas digitales.

## 4.5. Criptografía híbrida

Los sistemas modernos suelen combinar mecanismos simétricos y asimétricos.

Por ejemplo:

1. Dos participantes establecen material criptográfico mediante un mecanismo de intercambio de claves.
2. Derivan claves de sesión.
3. Utilizan cifrado simétrico para proteger la comunicación.

Esto aprovecha propiedades complementarias de diferentes técnicas.

## 4.6. Firma digital

Una firma digital permite verificar criptográficamente que un mensaje fue firmado utilizando una clave privada determinada.

También permite detectar modificaciones del contenido firmado.

Proceso conceptual:

1. El firmante dispone de una clave privada.
2. Genera una firma sobre el mensaje.
3. El receptor dispone de la clave pública correspondiente.
4. Verifica la firma.
5. Determina si la verificación criptográfica es válida.

La firma no cifra automáticamente el contenido.

Una firma válida tampoco demuestra por sí sola la identidad civil del firmante: esa asociación depende de la gestión de claves y de mecanismos de confianza.

## 4.7. Codificación, cifrado y hashing

Estos conceptos no deben confundirse.

| Mecanismo | Objetivo | ¿Reversible? |
|---|---|---|
| Codificación | Representar datos en otro formato | Generalmente sí |
| Cifrado | Proteger confidencialidad | Sí, con la clave correspondiente |
| Hash criptográfico | Obtener una huella de longitud fija | No está diseñado para invertirse |

### Ejemplo de Base64

```text
Hola
```

Codificado en Base64:

```text
SG9sYQ==
```

Base64 **no es cifrado**.

Cualquier persona puede decodificarlo sin una clave secreta.

---

# 5. Funciones hash y protección de contraseñas

## 5.1. ¿Qué es una función hash?

Una función hash transforma una entrada de longitud variable en una salida de longitud determinada.

Ejemplo conceptual:

```text
Archivo
   |
   v
SHA-256
   |
   v
Huella de 256 bits
```

## 5.2. Propiedades criptográficas

Una función hash criptográfica busca proporcionar propiedades como:

### Resistencia a preimagen

Dado un hash, debe resultar computacionalmente difícil encontrar una entrada que produzca ese valor.

### Resistencia a segunda preimagen

Dada una entrada, debe ser difícil encontrar otra diferente con el mismo hash.

### Resistencia a colisiones

Debe ser difícil encontrar dos entradas diferentes que produzcan el mismo hash.

Las colisiones existen matemáticamente porque las entradas posibles son más numerosas que las salidas.

La seguridad depende de que encontrarlas sea computacionalmente difícil.

## 5.3. MD5

MD5 produce valores de 128 bits.

Actualmente no es adecuado para usos criptográficos que requieren resistencia a colisiones.

Puede encontrarse en herramientas antiguas o en contextos de identificación no adversarial, pero no debe utilizarse como mecanismo moderno de seguridad criptográfica.

## 5.4. SHA-1

SHA-1 produce valores de 160 bits.

Se conocen ataques prácticos contra su resistencia a colisiones.

No se recomienda para nuevos sistemas que dependan de esa propiedad.

## 5.5. SHA-256

SHA-256 pertenece a la familia SHA-2.

Produce un resultado de 256 bits.

Se utiliza ampliamente para comprobar integridad y como componente de diferentes construcciones criptográficas.

## 5.6. Ejemplo práctico

En Linux:

```bash
sha256sum archivo.txt
```

En Windows PowerShell:

```powershell
Get-FileHash archivo.txt -Algorithm SHA256
```

Ambos comandos permiten calcular una huella SHA-256 del archivo.

### ¿Para qué sirve?

Supongamos que descargamos un archivo y su proveedor publica un hash de referencia por un canal confiable.

Podemos calcular el hash local y compararlo.

Si coinciden, existe evidencia de que el archivo corresponde al valor esperado.

Si el atacante controla tanto el archivo como el hash publicado, esa comparación no proporciona autenticidad independiente.

## 5.7. ¿Cómo se almacenan contraseñas?

Las contraseñas no deberían almacenarse en texto plano.

Tampoco deberían almacenarse simplemente mediante SHA-256 sin un mecanismo apropiado.

Se utilizan funciones específicas de derivación o hashing de contraseñas, como:

- Argon2id.
- scrypt.
- bcrypt.
- PBKDF2.

Estas funciones están diseñadas para dificultar la prueba masiva de contraseñas.

## 5.8. Salt

Un salt es un valor aleatorio que se incorpora al proceso de hashing de una contraseña.

Debe ser único por contraseña almacenada, con suficiente aleatoriedad.

Su objetivo es dificultar ataques basados en valores precalculados y evitar que contraseñas iguales produzcan necesariamente registros idénticos.

El salt no necesita ser secreto.

## 5.9. Pepper

Un pepper es un secreto adicional utilizado por algunas arquitecturas de protección de contraseñas.

A diferencia del salt, debe mantenerse separado y protegido.

Su utilidad depende del diseño y de la administración segura de secretos.

---

# 6. Autenticación, autorización y controles de acceso

## 6.1. Identificación

La identificación consiste en declarar una identidad.

Ejemplo:

```text
Usuario: administrador
```

Esto todavía no demuestra que quien escribe el nombre sea realmente ese usuario.

## 6.2. Autenticación

La autenticación es el proceso de verificar una identidad o una afirmación de identidad.

Ejemplos:

- Contraseña.
- Llave de seguridad.
- Certificado.
- Biometría.
- Código temporal.

## 6.3. Autorización

La autorización determina qué acciones puede realizar una identidad autenticada o un sujeto dentro de un sistema.

### Ejemplo

Un usuario puede iniciar sesión correctamente, pero no tener permiso para eliminar registros.

```text
Identificación:
Soy usuario1.

Autenticación:
Demuestro que controlo esa identidad.

Autorización:
El sistema determina qué recursos puedo utilizar.
```

## 6.4. Auditoría y registro

Los sistemas pueden registrar eventos como:

- Inicio de sesión.
- Intentos fallidos.
- Modificaciones.
- Accesos a recursos.
- Cambios de permisos.

Estos registros contribuyen a la trazabilidad y a la investigación de incidentes.

## 6.5. Factores de autenticación

### Algo que sabés

- Contraseña.
- PIN.

### Algo que tenés

- Token físico.
- Llave de seguridad.
- Dispositivo autenticador.

### Algo que sos

- Huella digital.
- Reconocimiento facial.
- Otros factores biométricos.

## 6.6. MFA

MFA significa Multi-Factor Authentication.

Combina dos o más factores de categorías diferentes.

Utilizar dos contraseñas no constituye necesariamente autenticación multifactor.

### Ejemplo

```text
Contraseña
    +
Llave de seguridad
    =
Autenticación multifactor
```

Los mecanismos basados en FIDO2/WebAuthn pueden proporcionar autenticación resistente al phishing cuando se implementan y utilizan correctamente.

## 6.7. Modelos de control de acceso

### DAC — Discretionary Access Control

El propietario de un recurso puede determinar determinados permisos de acceso.

### MAC — Mandatory Access Control

El acceso se controla mediante políticas obligatorias definidas por una autoridad central.

No debe confundirse con una dirección MAC de red.

### RBAC — Role-Based Access Control

Los permisos se asignan a roles.

Ejemplo:

| Rol | Permisos |
|---|---|
| Administrador | Gestión del sistema |
| Editor | Crear y modificar contenido |
| Lector | Consultar contenido |

### ABAC — Attribute-Based Access Control

Las decisiones de acceso se basan en atributos.

Pueden incluir:

- Identidad.
- Departamento.
- Clasificación del recurso.
- Ubicación.
- Horario.
- Contexto de la solicitud.

## 6.8. Principio de mínimo privilegio

Un usuario o proceso debe disponer solamente de los permisos necesarios para realizar su función.

Esto reduce el impacto potencial de errores, accesos indebidos o cuentas comprometidas.

## 6.9. Zero Trust

Zero Trust es un enfoque de seguridad que evita otorgar confianza implícita por el simple hecho de estar dentro de una red.

Promueve principios como:

- Verificación explícita.
- Acceso con mínimo privilegio.
- Evaluación continua del contexto.
- Protección de recursos.
- Consideración de posibles compromisos.

No es un producto específico ni significa que todos los sistemas deban desconfiar indiscriminadamente de cualquier comunicación.

---

# 7. Introducción a los protocolos de comunicación

## 7.1. Definición

Un protocolo de comunicación es un conjunto de reglas que permite intercambiar información entre sistemas.

Establece aspectos como:

- Estructura de mensajes.
- Identificación de extremos.
- Orden de intercambio.
- Control de errores.
- Confirmaciones.
- Manejo de sesiones.
- Tratamiento de respuestas.

## 7.2. ¿Por qué existen tantos protocolos?

Porque diferentes problemas requieren mecanismos diferentes.

Ejemplos:

| Necesidad | Protocolo |
|---|---|
| Direccionamiento entre redes | IP |
| Transporte confiable | TCP |
| Transporte de datagramas | UDP |
| Resolución de nombres | DNS |
| Transferencia web | HTTP |
| Comunicación web cifrada | HTTPS |
| Transferencia tradicional de archivos | FTP |
| Correo saliente | SMTP |
| Administración remota segura | SSH |
| Administración y monitoreo de dispositivos | SNMP |
| Resolución IPv4-MAC en enlaces locales | ARP |
| Diagnóstico y control IP | ICMP |

## 7.3. Comunicación por capas

Una comunicación puede utilizar varios protocolos simultáneamente.

Ejemplo clásico:

```text
HTTP
 |
TLS
 |
TCP
 |
IP
 |
Ethernet
```

Otro ejemplo:

```text
DNS
 |
UDP
 |
IP
 |
Ethernet
```

Estos diagramas son ejemplos de combinaciones posibles, no reglas universales.

DNS también puede utilizar TCP y transportes cifrados.

HTTP/3 utiliza QUIC sobre UDP.

---

# 8. TCP: funcionamiento detallado

TCP significa Transmission Control Protocol.

Es un protocolo de transporte orientado a conexión que proporciona un flujo de bytes confiable y ordenado.

## 8.1. ¿Qué problema resuelve TCP?

IP puede transportar paquetes entre redes, pero no garantiza que lleguen, que lleguen en orden ni que no existan duplicados.

TCP incorpora mecanismos para ofrecer una comunicación confiable entre procesos.

## 8.2. Encabezado TCP

Un encabezado TCP contiene campos como:

| Campo | Tamaño | Función |
|---|---|---|
| Puerto de origen | 16 bits | Identifica el extremo emisor |
| Puerto de destino | 16 bits | Identifica el extremo receptor |
| Número de secuencia | 32 bits | Identifica posiciones del flujo |
| Número ACK | 32 bits | Confirma recepción acumulativa |
| Data Offset | 4 bits | Longitud del encabezado |
| Flags | Variable según representación | Control de conexión |
| Window | 16 bits | Ventana de recepción anunciada |
| Checksum | 16 bits | Detección de errores |
| Urgent Pointer | 16 bits | Datos urgentes en usos específicos |
| Opciones | Variable | Funciones adicionales |

El encabezado TCP mínimo ocupa 20 bytes.

Puede ser mayor cuando incorpora opciones.

## 8.3. Flags TCP

Los indicadores más conocidos son:

| Flag | Función |
|---|---|
| SYN | Sincronización inicial |
| ACK | Confirmación válida |
| FIN | Finalización ordenada |
| RST | Reinicio o rechazo |
| PSH | Solicitud de entrega de datos al receptor |
| URG | Indica uso del puntero urgente |
| ECE | Señalización relacionada con ECN |
| CWR | Señalización de respuesta a congestión |

## 8.4. Three-Way Handshake

El establecimiento habitual de una conexión TCP requiere tres pasos.

```text
CLIENTE                         SERVIDOR
   |                               |
   |----------- SYN -------------->|
   |                               |
   |<-------- SYN + ACK -----------|
   |                               |
   |----------- ACK -------------->|
   |                               |
   |       ESTABLISHED             |
```

### Paso 1: SYN

El cliente solicita iniciar una conexión.

Envía un número inicial de secuencia.

### Paso 2: SYN-ACK

El servidor reconoce la solicitud y envía su propio número inicial de secuencia.

### Paso 3: ACK

El cliente confirma la respuesta.

La conexión queda establecida.

## 8.5. Números de secuencia

TCP trata los datos como un flujo de bytes.

Cada byte ocupa una posición lógica dentro de ese flujo.

Ejemplo simplificado:

```text
Segmento A: bytes 1-100
Segmento B: bytes 101-200
Segmento C: bytes 201-300
```

Si el segmento B se pierde, el receptor puede detectar que faltan datos.

Los números reales de secuencia son de 32 bits y se inicializan con valores seleccionados para la conexión.

## 8.6. ACK

ACK significa acknowledgment.

Permite confirmar la recepción de información.

En TCP, el ACK acumulativo normalmente indica el siguiente número de secuencia esperado.

Ejemplo conceptual:

```text
Recibidos: bytes 1-100
ACK: 101
```

## 8.7. Retransmisión

Si determinados datos no se confirman, TCP puede retransmitirlos.

La retransmisión puede desencadenarse por mecanismos como:

- Temporizadores.
- Confirmaciones duplicadas.
- Algoritmos de recuperación de pérdidas.

Las implementaciones modernas pueden utilizar mecanismos adicionales como SACK.

## 8.8. SACK

Selective Acknowledgment permite informar sobre bloques de datos recibidos aunque existan huecos.

Esto ayuda al emisor a identificar qué partes necesitan retransmisión.

## 8.9. Control de flujo

TCP utiliza una ventana de recepción para evitar que el emisor desborde la capacidad del receptor.

El receptor anuncia cuánto espacio tiene disponible.

## 8.10. Control de congestión

El control de congestión busca evitar que los emisores sobrecarguen la red.

Entre los conceptos relevantes están:

- Congestion window.
- Slow start.
- Congestion avoidance.
- Fast retransmit.
- Fast recovery.

Existen distintos algoritmos de control de congestión, como Reno, CUBIC y BBR, con comportamientos diferentes.

## 8.11. MSS

MSS significa Maximum Segment Size.

Representa la cantidad máxima de datos de aplicación que TCP transporta en un segmento según la negociación y las limitaciones aplicables.

No debe confundirse con MTU.

Ejemplo habitual en IPv4 sobre Ethernet:

```text
MTU Ethernet:       1500 bytes
Encabezado IPv4:      20 bytes
Encabezado TCP:       20 bytes
--------------------------------
MSS TCP:            1460 bytes
```

Este cálculo supone encabezados mínimos y ausencia de otras sobrecargas.

## 8.12. Cierre TCP

Una conexión TCP puede cerrarse ordenadamente mediante FIN y ACK.

Ejemplo simplificado:

```text
CLIENTE                         SERVIDOR
   |                               |
   |------------ FIN ------------->|
   |<----------- ACK --------------|
   |<----------- FIN --------------|
   |------------ ACK ------------->|
```

El cierre de las dos direcciones del flujo es independiente.

Por eso, las secuencias reales pueden variar.

## 8.13. Estados TCP

| Estado | Descripción |
|---|---|
| CLOSED | Sin conexión |
| LISTEN | Esperando conexiones |
| SYN-SENT | SYN enviado |
| SYN-RECEIVED | SYN recibido |
| ESTABLISHED | Conexión establecida |
| FIN-WAIT-1 | Cierre iniciado |
| FIN-WAIT-2 | Esperando FIN remoto |
| CLOSE-WAIT | FIN remoto recibido |
| CLOSING | Cierre simultáneo |
| LAST-ACK | Esperando ACK final |
| TIME-WAIT | Espera posterior al cierre |

## 8.14. TCP y seguridad

Algunos problemas y ataques relacionados con TCP incluyen:

- SYN flooding.
- Secuestro de sesiones bajo determinadas condiciones.
- Inyección de segmentos.
- Suplantación de direcciones.
- Abuso de servicios expuestos.

### SYN Flood

Un SYN flood busca consumir recursos relacionados con el establecimiento de conexiones mediante numerosas solicitudes.

Entre las defensas posibles están:

- SYN cookies.
- Controles de tasa.
- Balanceo.
- Protección especializada contra DDoS.
- Ajustes de recursos y tiempos de espera.

---

# 9. UDP: funcionamiento detallado

UDP significa User Datagram Protocol.

Es un protocolo de transporte orientado a datagramas.

## 9.1. Características

UDP:

- No utiliza un handshake de conexión como TCP.
- Conserva límites de datagramas.
- No garantiza entrega.
- No garantiza orden.
- No implementa retransmisiones propias.
- Tiene una cabecera pequeña.

## 9.2. Encabezado UDP

El encabezado UDP ocupa 8 bytes.

Contiene cuatro campos:

| Campo | Tamaño |
|---|---|
| Puerto de origen | 16 bits |
| Puerto de destino | 16 bits |
| Longitud | 16 bits |
| Checksum | 16 bits |

## 9.3. Ejemplo

Una aplicación envía una consulta DNS tradicional mediante UDP.

```text
Cliente
   |
   | Consulta DNS
   v
Servidor DNS
   |
   | Respuesta DNS
   v
Cliente
```

UDP no garantiza la respuesta.

Si la aplicación no recibe una respuesta, puede aplicar sus propios mecanismos de espera, reintento o cambio de transporte.

## 9.4. ¿Por qué se utiliza UDP?

Porque algunas aplicaciones necesitan:

- Enviar datagramas individuales.
- Reducir sobrecarga del transporte.
- Controlar sus propios mecanismos de recuperación.
- Evitar las características de flujo de bytes de TCP.

## 9.5. UDP y QUIC

QUIC es un protocolo de transporte moderno que funciona sobre UDP.

Incorpora mecanismos como:

- Establecimiento seguro.
- Multiplexación de flujos.
- Recuperación de pérdidas.
- Control de congestión.

HTTP/3 utiliza QUIC.

Esto demuestra que utilizar UDP no implica necesariamente renunciar a confiabilidad o cifrado: esas funciones pueden implementarse por encima de UDP.

## 9.6. TCP frente a UDP

| Propiedad | TCP | UDP |
|---|---|---|
| Orientado a conexión | Sí | No |
| Flujo de bytes | Sí | No |
| Datagramas | No preserva límites de mensajes | Sí |
| Entrega confiable | Sí, mientras la conexión funcione | No |
| Orden garantizado | Sí | No |
| Retransmisión | Sí | No |
| Control de congestión | Sí | No |
| Cabecera mínima | 20 bytes | 8 bytes |

---

# 10. Segmentación, paquetes y puertos

## 10.1. Segmentación

La segmentación permite dividir información en unidades adecuadas para su transporte.

TCP puede distribuir un flujo de bytes entre distintos segmentos.

Las aplicaciones no deben asumir que cada escritura equivale a un segmento TCP recibido.

## 10.2. Paquete IP

Un paquete IP contiene un encabezado y una carga útil.

El encabezado incluye información necesaria para el encaminamiento.

En IPv4, algunos campos son:

- Dirección de origen.
- Dirección de destino.
- TTL.
- Protocolo.
- Longitud.
- Información de fragmentación.

## 10.3. Trama

Una trama es una unidad de datos de enlace.

Ejemplo Ethernet:

```text
+------------+----------+-----------+----------+
| MAC destino| MAC origen| Datos     | FCS      |
+------------+----------+-----------+----------+
```

El esquema omite algunos campos para simplificar.

## 10.4. Encapsulamiento

Ejemplo:

```text
Datos HTTP
    |
    v
Segmento TCP
    |
    v
Paquete IP
    |
    v
Trama Ethernet
    |
    v
Señales físicas
```

## 10.5. Puertos

TCP y UDP utilizan identificadores de puerto de 16 bits.

Rango:

```text
0 - 65535
```

Clasificación IANA:

| Rango | Categoría |
|---|---|
| 0–1023 | System / Well-Known |
| 1024–49151 | User / Registered |
| 49152–65535 | Dynamic / Private |

## 10.6. Socket

Un socket es una abstracción de comunicación proporcionada por el sistema operativo.

Una conexión TCP puede identificarse mediante:

```text
IP origen
Puerto origen
IP destino
Puerto destino
Protocolo TCP
```

Ejemplo:

```text
192.168.1.10:51000
        |
        v
203.0.113.20:443
```

## 10.7. Puertos efímeros

Un cliente suele utilizar un puerto temporal de origen para iniciar una comunicación.

El rango exacto de selección depende del sistema operativo y su configuración.

No debe suponerse que todos los sistemas utilizan exactamente el mismo rango efímero.

---

# 11. HTTP y HTTPS

## 11.1. HTTP

HTTP significa Hypertext Transfer Protocol.

Es un protocolo de aplicación basado en intercambio de mensajes.

Se utiliza para transferir representaciones de recursos y realizar operaciones sobre ellos.

## 11.2. Modelo cliente-servidor

```text
Cliente                      Servidor
   |                            |
   |------ Solicitud HTTP ----->|
   |                            |
   |<----- Respuesta HTTP ------|
```

## 11.3. Estructura de HTTP/1.1

Una solicitud contiene:

- Línea de solicitud.
- Encabezados.
- Línea vacía.
- Cuerpo opcional.

Ejemplo:

```http
GET /index.html HTTP/1.1
Host: example.com
Accept: text/html
```

## 11.4. Métodos HTTP

### GET

Solicita una representación de un recurso.

### POST

Envía información para que el servidor la procese.

### PUT

Solicita crear o reemplazar el estado de un recurso identificado.

### PATCH

Solicita aplicar modificaciones parciales.

### DELETE

Solicita eliminar la asociación del recurso de destino según la semántica del servidor.

### HEAD

Es similar a GET, pero no solicita el contenido del cuerpo de la respuesta.

### OPTIONS

Permite consultar opciones de comunicación.

## 11.5. Códigos HTTP

Los códigos se agrupan en cinco categorías:

| Categoría | Significado |
|---|---|
| 1xx | Informativos |
| 2xx | Éxito |
| 3xx | Redirecciones |
| 4xx | Errores del cliente |
| 5xx | Errores del servidor |

Ejemplos:

- 200 OK.
- 201 Created.
- 301 Moved Permanently.
- 302 Found.
- 400 Bad Request.
- 401 Unauthorized.
- 403 Forbidden.
- 404 Not Found.
- 500 Internal Server Error.
- 503 Service Unavailable.

## 11.6. HTTP es stateless

HTTP se describe como un protocolo sin estado de sesión obligatorio entre solicitudes.

Esto significa que el protocolo no exige que cada solicitud dependa de una sesión persistente de aplicación.

Las aplicaciones pueden mantener estado utilizando:

- Cookies.
- Sesiones.
- Tokens.
- Almacenamiento del servidor.

## 11.7. Cookies

Las cookies permiten almacenar pequeños valores asociados a un sitio.

Pueden utilizarse para:

- Sesiones.
- Preferencias.
- Identificadores.
- Otras funciones de aplicación.

Atributos de seguridad relevantes:

- Secure.
- HttpOnly.
- SameSite.

Estos atributos cumplen funciones diferentes.

## 11.8. HTTPS

HTTPS protege HTTP mediante TLS.

Ofrece mecanismos criptográficos de confidencialidad, integridad y autenticación del servidor cuando se implementa y valida correctamente.

## 11.9. HTTP vs HTTPS

| Propiedad | HTTP sin TLS | HTTPS |
|---|---|---|
| Cifrado de transporte | No | Sí |
| Integridad criptográfica del canal | No | Sí |
| Autenticación TLS del servidor | No | Sí, mediante validación |
| Puerto habitual | TCP 80 | TCP 443 o UDP 443 para HTTP/3 |

HTTPS no garantiza que una página sea legítima ni que sus archivos estén libres de malware.

---

# 12. TLS y certificados digitales

## 12.1. ¿Qué es TLS?

TLS significa Transport Layer Security.

Es un protocolo criptográfico diseñado para proteger comunicaciones.

TLS 1.3 es una versión moderna ampliamente utilizada.

## 12.2. Objetivos

TLS busca proporcionar:

- Confidencialidad.
- Integridad.
- Autenticación de los extremos según el modo utilizado.

## 12.3. Handshake TLS 1.3

Ejemplo simplificado:

```text
CLIENTE                         SERVIDOR
   |                               |
   |-------- ClientHello --------->|
   |                               |
   |<------- ServerHello ----------|
   |<--- Mensajes protegidos ------|
   |                               |
   |------ Finished -------------->|
   |                               |
   |     Canal seguro activo       |
```

El intercambio real contiene información adicional y puede variar según la modalidad de handshake.

## 12.4. Certificado digital

Un certificado X.509 permite asociar información de identidad con una clave pública.

Puede incluir:

- Sujeto.
- Emisor.
- Clave pública.
- Período de validez.
- Extensiones.
- Firma del emisor.

## 12.5. Autoridad certificadora

Una CA es una entidad que emite certificados digitales.

Los clientes utilizan mecanismos de confianza para evaluar cadenas de certificados.

## 12.6. Validación

Una validación adecuada puede incluir:

1. Comprobar la cadena de confianza.
2. Verificar firmas.
3. Comprobar el nombre del servidor.
4. Comprobar fechas de validez.
5. Evaluar restricciones y políticas aplicables.
6. Aplicar mecanismos de revocación según el entorno.

## 12.7. Perfect Forward Secrecy

La confidencialidad directa busca limitar el impacto de la exposición posterior de claves de largo plazo sobre sesiones anteriores.

TLS 1.3 utiliza mecanismos de establecimiento de claves que proporcionan esta propiedad en sus modos habituales de intercambio.

---

# 13. FTP, FTPS y SFTP

## 13.1. FTP

FTP significa File Transfer Protocol.

Se utiliza para transferir archivos.

Tradicionalmente utiliza TCP 21 para el canal de control.

Puede utilizar conexiones adicionales para datos.

## 13.2. Funcionamiento

1. El cliente establece una conexión de control.
2. Se realiza la autenticación cuando corresponde.
3. El cliente envía comandos.
4. Se establece una conexión de datos según el modo utilizado.
5. Se transfiere la información.

## 13.3. FTP activo

En el modo activo tradicional, el servidor inicia la conexión de datos hacia el cliente.

## 13.4. FTP pasivo

En el modo pasivo, el cliente inicia la conexión de datos hacia un puerto indicado por el servidor.

Es frecuente en entornos con NAT y firewalls.

## 13.5. Problema de seguridad

FTP tradicional no cifra credenciales ni datos de forma predeterminada.

## 13.6. FTPS

FTPS incorpora TLS a FTP.

Puede utilizar modos de negociación explícita o implícita.

## 13.7. SFTP

SFTP es un protocolo de transferencia de archivos que funciona sobre SSH.

Habitualmente utiliza TCP 22.

No es simplemente FTP con cifrado.

## 13.8. Comparación

| Protocolo | Seguridad del transporte | Puerto habitual |
|---|---|---|
| FTP | Sin cifrado nativo | TCP 21 |
| FTPS | TLS | TCP 21 o 990 según modalidad |
| SFTP | SSH | TCP 22 |

---

# 14. DNS y seguridad de resolución

## 14.1. ¿Qué es DNS?

DNS significa Domain Name System.

Permite resolver nombres y consultar registros distribuidos jerárquicamente.

## 14.2. Componentes

- Cliente o stub resolver.
- Resolvedor recursivo.
- Servidores raíz.
- Servidores TLD.
- Servidores autoritativos.

## 14.3. Resolución paso a paso

Supongamos que consultamos:

```text
www.example.com
```

1. El cliente consulta sus mecanismos locales de resolución.
2. Si necesita consultar DNS, contacta un resolvedor.
3. El resolvedor verifica su caché.
4. Si no dispone de información suficiente, puede consultar la jerarquía DNS.
5. Obtiene información autoritativa o referencias necesarias.
6. Devuelve el resultado al cliente.
7. El cliente utiliza la información para establecer la comunicación.

## 14.4. Registros DNS

| Registro | Función |
|---|---|
| A | Dirección IPv4 |
| AAAA | Dirección IPv6 |
| CNAME | Alias |
| MX | Servidores de correo |
| NS | Servidores de nombres |
| SOA | Información de autoridad de zona |
| TXT | Información textual |
| PTR | Resolución inversa |
| CAA | Autoridades certificadoras autorizadas |

## 14.5. TTL DNS

El TTL de un registro DNS indica durante cuánto tiempo puede mantenerse en caché según las reglas correspondientes.

No debe confundirse con el TTL del encabezado IPv4.

## 14.6. DNS tradicional

Habitualmente utiliza:

- UDP 53.
- TCP 53.

TCP puede utilizarse para respuestas grandes, transferencias de zona y otras situaciones.

## 14.7. DNS over HTTPS

DoH transporta consultas DNS mediante HTTPS.

## 14.8. DNS over TLS

DoT protege consultas DNS mediante TLS.

Habitualmente utiliza TCP 853.

## 14.9. DNSSEC

DNSSEC incorpora mecanismos criptográficos que permiten validar la autenticidad de origen y la integridad de datos DNS firmados.

No cifra las consultas DNS.

## 14.10. Ataques DNS

### DNS Spoofing

Falsificación o manipulación de información DNS.

### Cache Poisoning

Introducción de información incorrecta en una caché DNS.

### DNS Tunneling

Utilización de consultas o respuestas DNS para transportar información adicional, potencialmente con fines maliciosos.

### DNS Amplification

Abuso de respuestas DNS para generar tráfico amplificado hacia una víctima, frecuentemente mediante suplantación de direcciones.

---

# 15. SMTP y protocolos de correo

## 15.1. SMTP

SMTP significa Simple Mail Transfer Protocol.

Se utiliza para el envío y transferencia de correo electrónico.

## 15.2. Funcionamiento simplificado

```text
Cliente de correo
       |
       v
Servidor de envío
       |
       v
Servidor de destino
       |
       v
Buzón del destinatario
```

## 15.3. Puertos SMTP

| Puerto | Uso |
|---|---|
| TCP 25 | Transferencia entre servidores |
| TCP 587 | Envío de correo |
| TCP 465 | Envío mediante TLS implícito |

## 15.4. POP3

Permite recuperar mensajes desde un servidor de correo.

Puertos habituales:

- TCP 110.
- TCP 995 con TLS implícito.

## 15.5. IMAP

Permite acceder y administrar mensajes manteniendo información sincronizada con el servidor.

Puertos habituales:

- TCP 143.
- TCP 993 con TLS implícito.

## 15.6. SPF

SPF permite publicar políticas sobre qué servidores están autorizados para enviar correo en nombre de un dominio utilizado en la identidad SMTP correspondiente.

## 15.7. DKIM

DKIM permite asociar firmas criptográficas a mensajes de correo.

## 15.8. DMARC

DMARC permite publicar políticas y recibir informes relacionados con la autenticación y alineación de dominios en correo electrónico.

Estos mecanismos contribuyen a reducir determinados tipos de suplantación, pero no eliminan todo el phishing.

---

# 16. Telnet y SSH

## 16.1. Telnet

Telnet es un protocolo tradicional de acceso remoto.

Habitualmente utiliza TCP 23.

Su principal problema de seguridad es que no proporciona cifrado nativo de la sesión.

## 16.2. SSH

SSH significa Secure Shell.

Permite establecer conexiones remotas seguras.

Habitualmente utiliza TCP 22.

## 16.3. Autenticación SSH

Puede utilizar:

- Contraseñas.
- Claves públicas.
- Otros mecanismos admitidos por el servidor.

## 16.4. Claves SSH

Un usuario puede disponer de:

- Clave privada.
- Clave pública.

La clave privada debe protegerse.

La clave pública puede registrarse en el servidor para autorizar autenticaciones.

## 16.5. Ejemplo

```bash
ssh usuario@192.168.1.10
```

Este comando intenta conectarse al servidor SSH indicado.

Se necesita autorización y una configuración compatible.

## 16.6. Buenas prácticas

- Utilizar autenticación robusta.
- Proteger claves privadas.
- Verificar claves de host.
- Deshabilitar métodos inseguros cuando corresponda.
- Limitar accesos administrativos.
- Mantener actualizado el servicio.

---

# 17. SNMP y administración de redes

## 17.1. ¿Qué es SNMP?

SNMP significa Simple Network Management Protocol.

Permite consultar y administrar determinados datos de dispositivos de red.

## 17.2. Componentes

- Administrador SNMP.
- Agente SNMP.
- MIB.
- OID.

## 17.3. MIB

Management Information Base describe objetos de información administrables.

## 17.4. OID

Object Identifier identifica objetos dentro de una estructura jerárquica.

## 17.5. Operaciones frecuentes

- GET.
- GETNEXT.
- GETBULK.
- SET.
- TRAP.
- INFORM.

Las operaciones disponibles dependen de la versión y del dispositivo.

## 17.6. Puertos

| Puerto | Uso |
|---|---|
| UDP 161 | Consultas SNMP |
| UDP 162 | Notificaciones |

## 17.7. Versiones

### SNMPv1

Versión inicial con mecanismos de seguridad limitados.

### SNMPv2c

Incorpora mejoras funcionales, pero mantiene comunidades como mecanismo de acceso.

### SNMPv3

Puede incorporar:

- Autenticación.
- Integridad.
- Privacidad mediante cifrado.

SNMPv3 es preferible cuando se necesita una administración protegida y existe una configuración adecuada.

---

# 18. ARP y sus vulnerabilidades

## 18.1. ¿Qué es ARP?

ARP significa Address Resolution Protocol.

Permite resolver direcciones IPv4 en direcciones de enlace, como MAC Ethernet, dentro de una red local.

## 18.2. Funcionamiento

Supongamos:

```text
Equipo A
IP: 192.168.1.10

Equipo B
IP: 192.168.1.20
```

El equipo A necesita conocer la MAC correspondiente a la IP del equipo B.

### Paso 1

Consulta su caché ARP.

### Paso 2

Si no encuentra la asociación, envía una solicitud ARP.

### Paso 3

El equipo correspondiente responde con su dirección MAC.

### Paso 4

El equipo A registra la asociación.

### Paso 5

Puede enviar tramas Ethernet al destino local.

## 18.3. ARP Spoofing

Consiste en introducir información ARP falsa para alterar asociaciones entre direcciones IP y MAC.

Puede facilitar:

- Intercepción de tráfico.
- Redirección.
- Interrupción de comunicaciones.

## 18.4. Controles defensivos

- Dynamic ARP Inspection, cuando existe soporte.
- DHCP Snooping como parte de diseños compatibles.
- Segmentación.
- Monitoreo.
- Cifrado de comunicaciones.
- Controles de acceso a la red.

---

# 19. ICMP y diagnóstico de redes

## 19.1. ¿Qué es ICMP?

ICMP significa Internet Control Message Protocol.

Se utiliza para intercambiar mensajes de control y diagnóstico relacionados con IP.

ICMPv4 e ICMPv6 tienen funciones y especificaciones diferentes.

## 19.2. Echo Request y Echo Reply

Son mensajes utilizados habitualmente por `ping`.

Ejemplo:

```bash
ping 192.168.1.1
```

## 19.3. Destination Unreachable

Permite informar determinadas condiciones en las que un paquete no puede entregarse.

## 19.4. Time Exceeded

Puede indicar que se agotó el TTL o Hop Limit durante el encaminamiento.

Es importante para herramientas como traceroute.

## 19.5. Traceroute

Permite explorar saltos de red mediante paquetes de prueba y respuestas de dispositivos intermedios.

Ejemplo en Windows:

```powershell
tracert example.com
```

Ejemplo en Linux:

```bash
traceroute example.com
```

## 19.6. ICMP y seguridad

ICMP puede utilizarse para:

- Diagnóstico.
- Descubrimiento.
- Señalización de errores.
- Funciones necesarias de red.

Bloquear indiscriminadamente todo ICMP puede provocar problemas de conectividad, especialmente en IPv6.

Los controles deben considerar los tipos de mensajes necesarios.

---

# 20. Puertos conocidos y servicios asociados

Los siguientes son puertos habituales, no garantías de identificación de servicios.

| Puerto | Transporte | Servicio |
|---|---|---|
| 20 | TCP | FTP datos activo tradicional |
| 21 | TCP | FTP control |
| 22 | TCP | SSH / SFTP |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | TCP/UDP | DNS |
| 67 | UDP | DHCPv4 servidor |
| 68 | UDP | DHCPv4 cliente |
| 69 | UDP | TFTP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 123 | UDP | NTP |
| 143 | TCP | IMAP |
| 161 | UDP | SNMP |
| 162 | UDP | SNMP Trap |
| 389 | TCP/UDP | LDAP |
| 443 | TCP | HTTPS sobre TCP |
| 443 | UDP | HTTP/3 mediante QUIC |
| 445 | TCP | SMB |
| 465 | TCP | SMTP Submission TLS implícito |
| 587 | TCP | SMTP Submission |
| 636 | TCP | LDAPS |
| 853 | TCP | DNS over TLS |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |
| 1433 | TCP | Microsoft SQL Server |
| 3306 | TCP | MySQL |
| 3389 | TCP/UDP | RDP |
| 5432 | TCP | PostgreSQL |
| 5900 | TCP | VNC |
| 6379 | TCP | Redis |
| 8080 | TCP | HTTP alternativo frecuente |

## 20.1. Puerto abierto

Un puerto TCP se considera abierto en un contexto de diagnóstico cuando existe un servicio que acepta conexiones en ese extremo.

## 20.2. Puerto cerrado

Un puerto cerrado no tiene un servicio aceptando conexiones en ese momento, aunque el sistema puede responder indicando ese estado.

## 20.3. Puerto filtrado

El tráfico puede estar siendo bloqueado o descartado por un dispositivo o una política de seguridad.

## 20.4. Importancia de los puertos

Conocer los puertos permite:

- Comprender servicios.
- Diagnosticar conexiones.
- Configurar firewalls.
- Analizar tráfico.
- Identificar exposiciones.
- Diseñar segmentación.

Un puerto abierto no implica automáticamente una vulnerabilidad.

El riesgo depende del servicio, su configuración, su exposición y los controles existentes.

---

# 21. Análisis de una comunicación segura

Supongamos que un usuario accede a:

```text
https://example.com
```

## Paso 1: Configuración de red

El dispositivo dispone de:

- Dirección IP.
- Gateway.
- Configuración DNS.
- Interfaz de red.

## Paso 2: Resolución DNS

Se obtiene información de direccionamiento para el dominio.

## Paso 3: Selección de ruta

El sistema determina cómo alcanzar el destino.

## Paso 4: Comunicación de enlace

Si corresponde, resuelve la dirección de enlace del siguiente salto.

## Paso 5: Transporte

Para HTTPS sobre TCP se realiza un handshake TCP.

Para HTTP/3 se utiliza QUIC sobre UDP.

## Paso 6: Seguridad criptográfica

Se establece protección mediante TLS.

El cliente verifica la identidad del servidor según los mecanismos correspondientes.

## Paso 7: Solicitud HTTP

El navegador envía una solicitud.

## Paso 8: Procesamiento

El servidor procesa la solicitud.

## Paso 9: Respuesta

El servidor devuelve información.

## Paso 10: Interpretación

El navegador procesa el contenido.

### Relación con CIA

**Confidencialidad:** TLS protege el contenido de la comunicación frente a observadores del canal.

**Integridad:** TLS permite detectar modificaciones no autorizadas del tráfico protegido.

**Disponibilidad:** depende de que los servicios, dispositivos y redes necesarios continúen funcionando.

TLS no garantiza disponibilidad.

---

# 22. Herramientas y prácticas de laboratorio

Estas prácticas están destinadas a sistemas propios o entornos donde exista autorización.

## 22.1. Consultar configuración IP

Windows:

```powershell
ipconfig /all
```

Linux:

```bash
ip addr
```

## 22.2. Consultar rutas

Linux:

```bash
ip route
```

Windows:

```powershell
route print
```

## 22.3. Consultar conexiones TCP

Windows:

```powershell
netstat -ano
```

Linux:

```bash
ss -tn
```

## 22.4. Consultar puertos locales en escucha

Linux:

```bash
ss -tuln
```

## 22.5. Consultar DNS

```bash
nslookup example.com
```

En sistemas con `dig`:

```bash
dig example.com A
```

## 22.6. Consultar encabezados HTTP

```bash
curl -I https://example.com
```

## 22.7. Consultar certificado TLS

En sistemas con OpenSSL:

```bash
openssl s_client -connect example.com:443 -servername example.com
```

Este comando permite inspeccionar información de la conexión TLS.

La interpretación de la validación requiere examinar el resultado y la configuración de OpenSSL.

## 22.8. Wireshark

Wireshark permite capturar y analizar tráfico.

Filtros de visualización útiles:

```text
tcp
```

```text
udp
```

```text
dns
```

```text
icmp
```

```text
arp
```

```text
tcp.flags.syn == 1
```

```text
tcp.port == 443
```

### Ejercicio: observar TCP

En una captura autorizada:

1. Identificar una conexión TCP.
2. Localizar el SYN.
3. Localizar el SYN-ACK.
4. Localizar el ACK.
5. Identificar las direcciones IP.
6. Identificar los puertos.
7. Observar los números de secuencia.
8. Identificar el cierre de la conexión.

### Ejercicio: observar DNS

1. Realizar una consulta DNS.
2. Capturar el tráfico autorizado.
3. Identificar la consulta.
4. Identificar el tipo de registro.
5. Examinar la respuesta.
6. Comparar los resultados con la herramienta utilizada.

Los resultados pueden variar por cachés, cifrado DNS y configuración del sistema.

---

# 23. Buenas prácticas de seguridad

## 23.1. Protección de comunicaciones

- Preferir protocolos cifrados.
- Validar certificados.
- Evitar servicios obsoletos.
- Mantener software actualizado.

## 23.2. Protección de identidades

- Utilizar MFA.
- Aplicar mínimo privilegio.
- Proteger credenciales.
- Revisar accesos.
- Deshabilitar cuentas innecesarias.

## 23.3. Protección de redes

- Segmentar sistemas.
- Restringir servicios expuestos.
- Aplicar reglas de firewall.
- Monitorear eventos.
- Mantener inventarios.
- Revisar configuraciones.

## 23.4. Protección de información

- Utilizar cifrado apropiado.
- Realizar copias de seguridad.
- Proteger claves.
- Controlar permisos.
- Verificar integridad cuando corresponda.

## 23.5. Respuesta a incidentes

Una organización debería contar con procesos para:

1. Preparación.
2. Detección y análisis.
3. Contención.
4. Erradicación.
5. Recuperación.
6. Revisión y mejora.

Estas etapas pueden organizarse de diferentes maneras según el marco de respuesta a incidentes utilizado.

---

# 24. Glosario

| Concepto | Definición |
|---|---|
| CIA | Confidencialidad, integridad y disponibilidad |
| Activo | Recurso con valor |
| Amenaza | Evento o actor capaz de causar daño |
| Vulnerabilidad | Debilidad explotable |
| Riesgo | Posibilidad de consecuencias negativas |
| Malware | Software malicioso |
| Phishing | Engaño mediante comunicaciones fraudulentas |
| DoS | Denegación de servicio |
| DDoS | Denegación de servicio distribuida |
| Criptografía | Técnicas matemáticas para proteger información |
| Cifrado | Transformación reversible con una clave apropiada |
| Hash | Huella calculada mediante una función |
| Salt | Valor aleatorio utilizado en hashing de contraseñas |
| MFA | Autenticación multifactor |
| RBAC | Control de acceso basado en roles |
| ABAC | Control de acceso basado en atributos |
| TCP | Protocolo de transporte confiable |
| UDP | Protocolo de transporte de datagramas |
| Segmento | Unidad de datos TCP |
| Datagrama | Unidad independiente de datos |
| Puerto | Identificador de transporte |
| Socket | Interfaz de comunicación de software |
| HTTP | Protocolo de transferencia de hipertexto |
| HTTPS | HTTP protegido mediante TLS |
| TLS | Seguridad criptográfica de transporte |
| DNS | Sistema de nombres de dominio |
| SMTP | Protocolo de transferencia de correo |
| SSH | Protocolo de acceso remoto seguro |
| SNMP | Protocolo de administración de red |
| ARP | Resolución IPv4 a direcciones de enlace |
| ICMP | Protocolo de control y diagnóstico IP |
| DNSSEC | Extensiones criptográficas de seguridad DNS |
| CA | Autoridad certificadora |
| Certificado | Documento digital que vincula información de identidad con una clave pública |

---

# 25. Referencias técnicas

## Protocolos de transporte

- [RFC 9293 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc9293)
- [RFC 768 — User Datagram Protocol](https://www.rfc-editor.org/rfc/rfc768)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)

## HTTP y TLS

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)

## DNS

- [RFC 1034 — DNS Concepts](https://www.rfc-editor.org/rfc/rfc1034)
- [RFC 1035 — DNS Implementation](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 4033 — DNSSEC](https://www.rfc-editor.org/rfc/rfc4033)

## Otros protocolos

- [RFC 826 — ARP](https://www.rfc-editor.org/rfc/rfc826)
- [RFC 792 — ICMP](https://www.rfc-editor.org/rfc/rfc792)
- [RFC 5321 — SMTP](https://www.rfc-editor.org/rfc/rfc5321)
- [RFC 4251 — SSH Architecture](https://www.rfc-editor.org/rfc/rfc4251)

## Seguridad

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [IANA Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)