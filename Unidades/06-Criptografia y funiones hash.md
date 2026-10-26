# Unidad 6 — Criptografía, funciones hash y TLS 1.3

> **Orientación:** Blue Team, SOC, DFIR (Digital Forensics and Incident Response) y seguridad de comunicaciones.  
> **Alcance:** conceptos, diseño criptográfico, interpretación de evidencias y operaciones defensivas. Ningún hash o algoritmo reemplaza una cadena de custodia ni garantiza por sí solo que un sistema no haya sido comprometido.

## Índice

1. [Modelo de seguridad y casos Blue Team](#1-modelo-de-seguridad-y-casos-blue-team)
2. [Vocabulario y fundamentos criptográficos](#2-vocabulario-y-fundamentos-criptográficos)
3. [Cifrado simétrico](#3-cifrado-simétrico)
4. [Criptografía asimétrica y claves](#4-criptografía-asimétrica-y-claves)
5. [Intercambio de claves, firmas y PKI](#5-intercambio-de-claves-firmas-y-pki)
6. [Funciones hash: fundamentos](#6-funciones-hash-fundamentos)
7. [MD5, SHA-1, SHA-2 y SHA-3](#7-md5-sha-1-sha-2-y-sha-3)
8. [SHA-256 explicado internamente](#8-sha-256-explicado-internamente)
9. [Cifrado, hash, MAC y firmas: diferencias](#9-cifrado-hash-mac-y-firmas-diferencias)
10. [Contraseñas y derivación de claves](#10-contraseñas-y-derivación-de-claves)
11. [TLS 1.3 en detalle](#11-tls-13-en-detalle)
12. [TLS desde la perspectiva Blue Team](#12-tls-desde-la-perspectiva-blue-team)
13. [Integridad y análisis forense digital](#13-integridad-y-análisis-forense-digital)
14. [Detección, telemetría y correlación](#14-detección-telemetría-y-correlación)
15. [Errores frecuentes y decisiones técnicas](#15-errores-frecuentes-y-decisiones-técnicas)
16. [Guía de estudio y referencias](#16-guía-de-estudio-y-referencias)

---

# 1. Modelo de seguridad y casos Blue Team

La criptografía no es un objetivo en sí mismo: sirve para garantizar propiedades relevantes de la información y de las comunicaciones.

| Necesidad | Herramienta habitual | Límite de interpretación |
|---|---|---|
| Evitar que terceros lean datos | Cifrado autenticado, como AES-GCM | Protege frente a observadores sin clave; no protege un extremo ya comprometido |
| Detectar modificación accidental | SHA-256 sobre datos y referencia fiable | Coincidencia no identifica autor ni origen del dato |
| Verificar origen y modificación | HMAC o firma digital, según caso | Requiere claves confiables y gestión de identidades |
| Proteger conexión navegador-servidor | TLS 1.3 con validación de certificado | No asegura que la aplicación web sea legítima o no tenga vulnerabilidades |
| Demostrar continuidad de evidencia | Hashes, inventario, sellos temporales y cadena de custodia | Un digest aislado no demuestra quién capturó el archivo |
| Almacenar contraseñas | Argon2id/scrypt/bcrypt/PBKDF2 configurados adecuadamente | SHA-256 «directo» no sustituye un password hashing resistente |

**Blue Team:** interesa tanto configurar correctamente mecanismos como reconocer fallos operativos: certificados no válidos, algoritmos antiguos, claves filtradas, hashes inesperados, TLS inseguro, archivos alterados y evidencias mal preservadas.

**DFIR:** interesa poder justificar, de manera reproducible, de dónde salió una evidencia, cómo se obtuvo, si cambió después, quién la manipuló y qué conclusiones permite (y cuáles no).

# 2. Vocabulario y fundamentos criptográficos

- **Texto plano:** dato que todavía no está cifrado.
- **Texto cifrado:** resultado de cifrar un dato.
- **Algoritmo:** procedimiento criptográfico público y definido.
- **Clave:** valor secreto o público, según el mecanismo, usado por el algoritmo.
- **Nonce:** valor destinado a utilizarse bajo reglas específicas, normalmente no repetirse con la misma clave; no siempre necesita ser secreto.
- **IV:** vector de inicialización, cuyo tamaño y requisitos dependen del modo de cifrado.
- **Salt:** dato único y aleatorio utilizado al derivar hashes de contraseñas; no necesita ser secreto.
- **Digest:** resultado de una función hash.
- **MAC:** código de autenticación de mensaje basado en un secreto compartido.
- **Firma digital:** mecanismo con clave privada para firmar y clave pública para verificar.
- **Entropía:** medida de incertidumbre; en el contexto de claves importa la imprevisibilidad de su generación.

## 2.1. Principio de Kerckhoffs

La seguridad de un sistema criptográfico no debería depender de mantener secreto el algoritmo. Debe poder sostenerse aunque el diseño del algoritmo sea conocido y las claves permanezcan protegidas.

## 2.2. ¿Qué protege y qué no protege el cifrado?

Cifrar el disco protege principalmente datos en reposo frente a determinadas pérdidas o accesos físicos; cuando el sistema está desbloqueado, los procesos autorizados o un atacante con control suficiente del endpoint podrían leer datos descifrados. TLS protege el tramo de comunicación en el que está establecido: un proxy que termina TLS es otro extremo criptográfico y podría observar contenido según su función y autorización.

## 2.3. Aleatoriedad

Claves, nonces y secretos deben generarse con fuentes criptográficamente seguras, no con funciones destinadas a simulaciones estadísticas. **Nunca reutilizar un nonce con la misma clave en AES-GCM**: puede comprometer gravemente confidencialidad y autenticidad.

# 3. Cifrado simétrico

**Definición:** emisor y receptor utilizan material secreto compartido para cifrar y descifrar. Se emplea porque normalmente es eficiente para grandes cantidades de datos.

## 3.1. AES

**AES (Advanced Encryption Standard)** es un cifrador de bloques con bloques de **128 bits**. Admite claves de **128, 192 y 256 bits**; no deben confundirse tamaño de bloque y tamaño de clave. Su transformación interna consta de rondas y operaciones como sustitución de bytes, desplazamiento de filas, mezcla de columnas y adición de subclave (con variantes para la ronda final). No se usa para archivos grandes aplicando simplemente el cifrador de bloque una sola vez: se utiliza un **modo de operación** adecuado.

## 3.2. Modos de operación

| Modo | Propiedad relevante | Decisión defensiva |
|---|---|---|
| ECB | Bloques iguales pueden producir patrones reconocibles | No elegir para datos generales |
| CBC | Necesita IV y padding; no autentica por sí solo | Requiere autenticación separada y diseño cuidadoso |
| CTR | Convierte cifrado de bloque en flujo | No repetir contador/nonce con una clave; requiere autenticación adicional |
| GCM | **AEAD**: cifra y autentica | Preferible cuando se gestionan correctamente nonce, clave y tag |

**AEAD** significa *Authenticated Encryption with Associated Data*: protege la confidencialidad del texto cifrado y autentica tanto ese texto como datos asociados que no se cifran. Produce una **etiqueta de autenticación (tag)**. Si la verificación del tag falla, el contenido no debe aceptarse como válido.

## 3.3. Confidencialidad no es autenticidad

Cifrar sin autenticar puede dejar abiertos problemas de modificación del ciphertext. Para nuevos diseños se suelen preferir construcciones AEAD (por ejemplo AES-GCM o ChaCha20-Poly1305), escogidas según los requisitos y bibliotecas confiables. **Nunca diseñar criptografía propia para producción.**

# 4. Criptografía asimétrica y claves

La criptografía asimétrica utiliza un **par de claves relacionadas matemáticamente**:

- **Pública:** puede compartirse.
- **Privada:** debe permanecer bajo control del propietario.

Los pares de claves no se utilizan todos del mismo modo: hay algoritmos de **cifrado**, de **firma** y de **acuerdo de claves**.

## 4.1. RSA

RSA puede utilizarse en esquemas de cifrado y de firma con mecanismos de padding apropiados y contextos compatibles. En cifrado nuevo, el uso correcto de RSA-OAEP es sustancialmente diferente de aplicar operaciones matemáticas RSA «en crudo». En firma, RSA-PSS es un esquema moderno relevante. **No tratar la operación RSA primitiva como solución completa.**

## 4.2. Curvas elípticas

- **ECDH/X25519:** permiten establecer un secreto compartido; no son firmas.
- **ECDSA/Ed25519:** permiten crear/verificar firmas; no son mecanismos de cifrado de archivos por sí mismos.

## 4.3. ¿Por qué proteger la clave privada?

La exposición de una clave privada puede habilitar suplantación, acceso no autorizado o compromiso de material criptográfico, dependiendo de cómo se utilice. Se aplican controles como permisos estrictos, cifrado de la clave, passphrases, HSM/TPM cuando corresponde, rotación y revocación.

# 5. Intercambio de claves, firmas y PKI

## 5.1. Acuerdo de claves

En un protocolo como TLS 1.3, los participantes pueden aportar valores públicos **(EC)DHE** para derivar material secreto compartido sin transmitir ese secreto directamente. Una clave pública por sí sola no autentica la identidad del interlocutor: un protocolo debe resolver también esa cuestión.

## 5.2. Firma digital

1. Una clave privada firma un mensaje de acuerdo con un esquema de firma.
2. El verificador recibe mensaje, firma y clave pública.
3. Verifica matemáticamente la firma.
4. La confianza en *quién controla esa clave* depende de su asociación con una identidad.

La firma **no cifra** el contenido. El certificado digital puede asociar una identidad, nombre de servidor o propiedad con una clave pública bajo una cadena de confianza.

## 5.3. PKI y certificados X.509

Una infraestructura de clave pública puede incorporar autoridades certificadoras, certificados, listas de confianza, expiraciones y mecanismos de revocación. En HTTPS, el cliente debe verificar, entre otros aspectos, nombre de servidor, cadena de confianza, firmas y validez. La presencia del ícono de candado **no demuestra que un sitio sea ético o seguro frente a phishing**.

# 6. Funciones hash: fundamentos

Una función hash criptográfica transforma una entrada de longitud variable en un digest de longitud fija. Para una misma secuencia exacta de bytes y un mismo algoritmo, el digest es determinista.

Propiedades deseables:

1. **Resistencia a preimagen:** conocido un digest, es computacionalmente difícil encontrar una entrada que lo produzca.
2. **Resistencia a segunda preimagen:** dada una entrada, es difícil encontrar otra diferente con idéntico digest.
3. **Resistencia a colisiones:** es difícil hallar *cualquier par* de entradas diferentes que genere el mismo digest.
4. **Efecto avalancha:** una modificación pequeña suele alterar muchos bits de la salida; es un comportamiento importante, pero por sí solo no prueba seguridad.

Como existen infinitas entradas potenciales y una cantidad finita de resultados, **las colisiones existen necesariamente**. Lo importante es la dificultad computacional para encontrarlas.

### Ejemplo: bytes exactos

`hola` y `hola\n` son entradas distintas: el segundo incluye un salto de línea. También pueden cambiar el digest el tipo de codificación, finales de línea, metadatos incluidos en un contenedor o una sola modificación binaria.

**Un hash no es:** cifrado, compresión reversible, prueba de ausencia de malware, certificación de origen ni identificación inequívoca de un fichero malicioso.

# 7. MD5, SHA-1, SHA-2 y SHA-3

| Algoritmo | Digest | Estado y uso defensivo |
|---|---:|---|
| MD5 | 128 bits / 32 caracteres hex | Colisiones prácticas; no utilizar para nuevas garantías criptográficas. Aún aparece como identificador heredado de muestras |
| SHA-1 | 160 bits / 40 caracteres hex | Colisiones prácticas; no utilizar para aplicaciones nuevas que dependan de resistencia a colisiones |
| SHA-256 | 256 bits / 64 caracteres hex | Opción sólida para verificaciones generales de integridad bajo su modelo de seguridad |
| SHA-512 | 512 bits / 128 caracteres hex | Otra función de SHA-2, con arquitectura interna diferente |
| SHA3-256 | 256 bits / 64 caracteres hex | Familia SHA-3; **no** es SHA-256 ni tiene el mismo resultado |

**SHA-2** es una familia; **SHA-256** es uno de sus miembros. **SHA-3** constituye otra familia basada en una construcción criptográfica diferente. No confundir longitud de digest con nivel de seguridad ante colisiones: para una función ideal de `n` bits, el trabajo genérico de búsqueda de colisiones es aproximadamente `2^(n/2)` por el fenómeno del cumpleaños.

### MD5/SHA-1 en DFIR

Pueden aparecer porque una base de inteligencia, una herramienta histórica o un conjunto de evidencia utiliza esos identificadores. Es válido registrarlos como metadatos auxiliares, pero conviene calcular también SHA-256 y no utilizar MD5/SHA-1 como única prueba criptográfica de integridad adversarial.

# 8. SHA-256 explicado internamente

Esta sección describe **SHA-256 según el algoritmo SHA-2 del NIST, FIPS 180-4**. No es un procedimiento inventado ni una aproximación de «sumar bytes».

## 8.1. Parámetros fundamentales

- **Entrada:** mensaje binario de longitud variable, dentro del límite del estándar (menor que `2^64` bits).
- **Salida:** digest de **256 bits**, normalmente representado como **64 caracteres hexadecimales**.
- **Bloque de mensaje:** **512 bits = 64 bytes**.
- **Palabra de trabajo:** **32 bits**.
- **Estado interno:** ocho palabras de 32 bits (`H0 … H7`).
- **Rondas por bloque:** **64**.
- **Constantes de ronda:** 64 palabras `K[0] … K[63]` definidas por el estándar.
- **Aritmética:** adición módulo `2^32`, AND, XOR, NOT, rotaciones y desplazamientos.

### ¿Por qué 64 caracteres?

Cada dígito hexadecimal representa cuatro bits; `256 / 4 = 64`. La representación en hexadecimal **no agrega seguridad** ni constituye una operación de hashing adicional.

## 8.2. Preparación del mensaje o padding

Sea `L` la longitud original en bits. Se construye:

```text
MENSAJE ORIGINAL | bit '1' | k bits '0' | longitud L en 64 bits
```

`k` es el menor entero no negativo que cumple:

```text
(L + 1 + k) mod 512 = 448
```

Después se agregan los **64 bits** de longitud original en orden *big-endian*. Así el total queda múltiplo de 512.

**Ejemplo `abc`:** en UTF-8/ASCII son los bytes `61 62 63`, por lo tanto `L = 24` bits. Se añade el byte `80` (el bit `1` y siete ceros), luego ceros hasta ocupar 56 bytes y finalmente `0000000000000018` (24 en hexadecimal, sobre 8 bytes). El mensaje acolchado contiene **exactamente un bloque de 64 bytes**.

> Atención: si el mensaje requiere más espacio, el padding puede agregar otro bloque completo. No se descartan bytes ni se trunca el mensaje para entrar en 512 bits.

## 8.3. División en bloques y palabras

Se divide la entrada preparada en bloques `M^(1), …, M^(N)` de 512 bits. Cada bloque se divide primero en **16 palabras** de 32 bits (`W[0] … W[15]`, big-endian) y después se expande a **64 palabras**.

### Expansión del calendario de mensajes

Para `16 ≤ t ≤ 63`:

```text
W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]  (mod 2^32)
```

Donde:

```text
σ0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
σ1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
```

- `ROTR^n`: rotación circular **a la derecha** `n` bits (los bits salen y vuelven a entrar).
- `SHR^n`: desplazamiento a la derecha rellenando con ceros (los bits desplazados se pierden).
- `XOR`: OR exclusivo bit a bit.

La expansión mezcla información del bloque original en las rondas sucesivas; **no** significa que se creen nuevos datos de entrada.

## 8.4. Estado inicial

SHA-256 empieza con ocho valores fijos definidos por el estándar (hexadecimal):

```text
H0 = 6a09e667
H1 = bb67ae85
H2 = 3c6ef372
H3 = a54ff53a
H4 = 510e527f
H5 = 9b05688c
H6 = 1f83d9ab
H7 = 5be0cd19
```

No son una contraseña, ni un nonce aleatorio generado para cada archivo, ni una clave secreta. Son parte de la definición pública de SHA-256.

## 8.5. Funciones de compresión

SHA-256 define:

```text
Ch(x,y,z)  = (x AND y) XOR ((NOT x) AND z)
Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)
Σ0(x)      = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
Σ1(x)      = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
```

**Ch (choose):** selecciona bits de `y` o `z` según `x`. **Maj (majority):** aplica mayoría bit a bit. Las funciones `Σ` mezclan posiciones de bits mediante rotaciones. Todas trabajan con palabras de 32 bits.

## 8.6. Las 64 rondas

Para cada bloque se copian las ocho palabras del estado a variables `a … h`. Para cada ronda `t = 0 … 63`:

```text
T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]  (mod 2^32)
T2 = Σ0(a) + Maj(a,b,c)                      (mod 2^32)

h = g
g = f
f = e
e = d + T1    (mod 2^32)
d = c
c = b
b = a
a = T1 + T2   (mod 2^32)
```

Las constantes `K[t]` son valores públicos especificados por FIPS 180-4, no claves de cifrado. Las sumas siempre descartan el acarreo más allá de 32 bits.

## 8.7. Actualización del estado

Tras las 64 rondas se suman las variables de trabajo a las ocho palabras del estado previo, **módulo `2^32`**:

```text
H0 = H0 + a
H1 = H1 + b
H2 = H2 + c
H3 = H3 + d
H4 = H4 + e
H5 = H5 + f
H6 = H6 + g
H7 = H7 + h
```

El estado resultante alimenta el siguiente bloque. Al finalizar todos los bloques, se concatenan las ocho palabras `H0 || H1 || ... || H7` en orden big-endian.

## 8.8. Vector de prueba: `abc`

Para los **tres bytes ASCII exactos** `abc`, el digest esperado es:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

En Linux/macOS:

```bash
printf 'abc' | openssl dgst -sha256
```

En Python:

```python
import hashlib
print(hashlib.sha256(b'abc').hexdigest())
```

Si se usa `echo abc`, normalmente se agrega un salto de línea y **el resultado será diferente**.

## 8.9. ¿Qué es exactamente una colisión en SHA-256?

Dos entradas distintas con un mismo digest de 256 bits. Por el efecto cumpleaños, la búsqueda genérica de colisiones requiere del orden de `2^128` intentos para un hash ideal de 256 bits. La búsqueda genérica de una preimagen requiere del orden de `2^256` intentos. Estas son estimaciones teóricas de seguridad genérica, **no** tiempos exactos ni una garantía universal frente a todos los avances criptanalíticos.

## 8.10. Limitación crucial: length extension

SHA-256 pertenece a una construcción iterativa de tipo Merkle–Damgård y **no debe utilizarse como MAC improvisado** mediante `SHA256(clave || mensaje)`: ciertas construcciones con prefijo secreto pueden ser vulnerables a ataques de extensión de longitud. Para autenticar mensajes se utiliza **HMAC-SHA-256** u otra construcción estandarizada.

## 8.11. SHA-256 aplicado a Blue Team y DFIR

- **FIM (File Integrity Monitoring):** comparar hashes de archivos críticos contra una línea base **confiable**.
- **Inventario:** reconocer versiones o artefactos binarios por digest; no asumir que el digest da contexto de amenaza.
- **Triaging de malware:** consultar reputación de un SHA-256 y correlacionar con ruta, firma, proceso, cadena de ejecución y comportamiento.
- **Cadena de custodia:** registrar hash al adquirir evidencia y verificarlo tras transferencias; proteger de alteración también el registro donde se almacena el digest.
- **Detección:** alertar cambios de archivos relevantes fuera de ventanas esperadas; revisar falsos positivos.
- **Verificación de software:** comparar contra un digest o firma obtenidos **por un canal autenticado e independiente**.

**Advertencia forense:** dos imágenes de disco tomadas en momentos diferentes no tienen por qué compartir SHA-256. Una adquisición en vivo puede modificar datos del sistema. El método y las condiciones de adquisición deben quedar documentados.

# 9. Cifrado, hash, MAC y firmas: diferencias

| Herramienta | Secreto/clave | ¿Permite recuperar original? | Propiedad principal |
|---|---|---|---|
| Base64 | No | Sí | Codificación; **no seguridad** |
| AES-GCM | Clave secreta | Sí, con clave y nonce adecuados | Confidencialidad + autenticación/integridad |
| SHA-256 | No | No está diseñada para invertirse | Huella y detección de cambios contra referencia |
| HMAC-SHA-256 | Clave secreta compartida | No | Autenticación de mensaje + integridad |
| Ed25519 | Clave privada para firma; pública para verificar | No | Firma verificable con clave pública |

### No confundir identificación con autenticidad

Si un archivo descargado tiene el mismo SHA-256 que un hash publicado en una página **comprometida**, el atacante puede haber sustituido ambos. La autenticidad exige una fuente confiable independiente, firma verificada o cadena apropiada de confianza.

# 10. Contraseñas y derivación de claves

Un archivo con hashes SHA-256 de contraseñas sin sal es vulnerable a pruebas masivas de candidatos. Para **almacenamiento de contraseñas**, usar esquemas específicos y parámetros actuales:

- **Argon2id**: función de hashing de contraseñas con resistencia a ataques de hardware paralelo mediante uso de memoria.
- **scrypt**: función con coste computacional y de memoria.
- **bcrypt**: alternativa utilizada en sistemas heredados y actuales, con limitaciones que deben considerarse.
- **PBKDF2**: derivación basada en una PRF, útil bajo determinados requisitos y configuraciones.

Cada contraseña necesita un **salt independiente**; el servidor almacena parámetros, salt y resultado. Un **pepper** opcional se mantiene protegido por separado. La migración de parámetros debe contemplarse cuando el hardware y las recomendaciones evolucionan.

**HKDF** se utiliza para derivar claves criptográficas a partir de material secreto (por ejemplo en TLS 1.3), **no es un sustituto de Argon2id para contraseñas humanas**. HMAC, HKDF y password hashing resuelven problemas diferentes.

# 11. TLS 1.3 en detalle

> **Nombre correcto:** **TLS 1.3**. No existe una versión estándar denominada «TLS 3.1». A octubre de 2026, la referencia principal actualizada es **RFC 9846 (julio de 2026)**, que reemplazó la RFC 8446 de 2018, **sin renombrar la versión del protocolo**.

## 11.1. ¿Qué es TLS?

**Transport Layer Security** protege una comunicación entre extremos TLS y busca impedir la lectura no autorizada del contenido, su modificación inadvertida o maliciosa y determinadas suplantaciones. Lo encontramos en HTTPS y otros protocolos que emplean TLS.

TLS **no reemplaza** TCP/IP y **no es un hash**. En HTTPS clásico se sitúa entre HTTP y TCP. **HTTP/3** utiliza QUIC con mecanismos TLS 1.3 integrados en su establecimiento seguro, no la misma pila TLS-sobre-TCP.

```text
HTTPS HTTP/1.1 o HTTP/2:    HTTP → TLS → TCP → IP
HTTPS HTTP/3:               HTTP/3 → QUIC (TLS 1.3 integrado) → UDP → IP
```

## 11.2. Objetivos y límites

TLS puede proteger **confidencialidad**, **integridad** y **autenticación del servidor** si hay configuración y validación correcta. Puede proporcionar autenticación del cliente con certificados cuando se configura mTLS. No garantiza:

- Que el sitio sea benigno.
- Que la identidad que figura en una cuenta web sea legítima.
- Que no haya malware en el endpoint.
- Que el DNS previo al handshake sea necesariamente privado.
- Que no se observen direcciones IP, volúmenes, tiempos y otros metadatos de tráfico.

## 11.3. Cambios importantes respecto de TLS 1.2

- Handshake optimizado y claves derivadas mediante **HKDF**.
- Uso de **(EC)DHE** para establecimiento de claves en el handshake completo habitual, con secreto hacia adelante (*forward secrecy*).
- Cifrado de datos mediante suites **AEAD**; se retiraron numerosos algoritmos y modos heredados.
- Mayor parte de mensajes posteriores a ServerHello protegidos criptográficamente.
- Posibilidad de **reanudación** y de **0-RTT**, con consideraciones particulares de replay.

TLS 1.3 **no cifra cada metadato**; los campos visibles dependen del intercambio y de extensiones como ECH, cuando son compatibles y están desplegadas.

## 11.4. Handshake 1-RTT: vista orientativa

```text
CLIENTE                                    SERVIDOR
   |                                          |
   |------ ClientHello ---------------------->|
   |       versiones, suites, key_share       |
   |                                          |
   |<----- ServerHello -----------------------|
   |       suite elegida, key_share           |
   |           (claves handshake)             |
   |<===== EncryptedExtensions ==============|
   |<===== Certificate* =====================|
   |<===== CertificateVerify* ===============|
   |<===== Finished =========================|
   |                                          |
   |====== Finished ========================>|
   |                                          |
   |<====== Datos de aplicación ============>|
```

`*` Mensajes típicos del handshake completo con autenticación por certificado; en reanudación PSK el flujo puede cambiar. `====` representa mensajes protegidos con claves de handshake o aplicación, según la fase; no todos con la misma clave.

### Paso 1 — ClientHello

El cliente anuncia parámetros compatibles: versiones, suites de cifrado, grupos, extensiones y una contribución de intercambio de claves (*key_share*), entre otros. Puede usar **SNI** para indicar el nombre de servidor cuando corresponde.

### Paso 2 — ServerHello

El servidor elige parámetros compatibles y aporta su contribución al acuerdo de claves. Ambas partes pueden calcular un secreto de ECDHE sin transmitir ese secreto directamente.

### Paso 3 — Derivación con HKDF

**HKDF** utiliza mecanismos como HMAC para derivar secretos de tráfico diferenciados según la etapa y dirección. Conceptualmente:

```text
material de entrada / secreto compartido
           ↓
     HKDF-Extract
           ↓
     HKDF-Expand + etiquetas/contexto
           ↓
secretos handshake → secretos aplicación → claves/IV
```

El proceso exacto incluye un *key schedule* con estados y derivaciones definidas por RFC 9846. **No se calcula simplemente SHA-256 del secreto y se usa como clave AES**.

### Paso 4 — Identidad del servidor

El servidor aporta certificado y una firma de prueba de posesión de la clave privada cuando se utiliza autenticación basada en certificados. El cliente debe validar nombre, confianza y demás condiciones aplicables antes de tratar el canal como autenticado.

### Paso 5 — Finished

El mensaje `Finished` utiliza una comprobación criptográfica sobre el transcript del handshake, vinculando los mensajes negociados. La verificación correcta es crucial para confirmar que el intercambio no fue alterado de manera no autorizada.

### Paso 6 — Datos de aplicación

Se utiliza AEAD (como AES-GCM o ChaCha20-Poly1305) con claves y nonces apropiados para proteger registros de aplicación; las claves de cada dirección son independientes.

## 11.5. Suites de cifrado

Ejemplos habituales TLS 1.3:

| Suite | Cifrado autenticado | Hash asociado a derivación/handshake |
|---|---|---|
| `TLS_AES_128_GCM_SHA256` | AES-128-GCM | SHA-256 |
| `TLS_AES_256_GCM_SHA384` | AES-256-GCM | SHA-384 |
| `TLS_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 | SHA-256 |

**Error común:** `TLS_AES_128_GCM_SHA256` **no** significa «AES seguido de SHA-256 para cifrar cada mensaje». AES-GCM proporciona cifrado autenticado; SHA-256 se usa en mecanismos del handshake y derivación según la especificación.

## 11.6. SNI, ALPN y certificados

- **SNI (Server Name Indication):** extensión asociada con el nombre solicitado; en ciertos escenarios puede ser visible para observadores. ECH busca proteger determinados campos del ClientHello cuando está desplegado.
- **ALPN:** negociación del protocolo de aplicación, por ejemplo HTTP/2 o HTTP/1.1.
- **SAN (Subject Alternative Name):** nombres/direcciones para los que se valida un certificado.
- **mTLS:** ambos extremos presentan certificados cuando la aplicación lo requiere.

## 11.7. Forward secrecy

En el handshake (EC)DHE habitual, la filtración posterior de la **clave privada de autenticación de largo plazo** no permite por sí sola recuperar los secretos efímeros de sesiones capturadas anteriormente. Esta propiedad no salva sesiones si se comprometieron sus claves de sesión o los endpoints, ni convierte automáticamente cualquier modalidad de reanudación en equivalente al handshake completo.

## 11.8. Reanudación y 0-RTT

Una sesión previa puede permitir reanudaciones mediante PSK/tickets. **0-RTT** deja enviar determinados datos anticipadamente, con ventajas de latencia, pero con **riesgo de repetición (replay)**; las aplicaciones no deben tratar esas solicitudes como si toda operación fuese segura ante repetición. Es particularmente importante para transacciones con efectos secundarios.

## 11.9. Cómo se detecta un fallo de TLS

| Hallazgo | Comprobación defensiva |
|---|---|
| Certificado vencido | Fechas del certificado, reloj del cliente, renovación |
| Nombre incorrecto | SAN y nombre solicitado mediante SNI |
| Autoridad no confiable | Cadena y almacén de confianza |
| Handshake fallido | Versión, suites, grupos, certificados y errores de red |
| TLS obsoleto habilitado | Política de versiones aceptadas |
| Tráfico cifrado sospechoso | Metadatos, endpoint, procesos, DNS, reputación, contexto, volumen |

**Aviso forense:** descifrar una captura TLS de un sistema propio puede requerir claves de sesión obtenidas legítimamente o registros de claves de laboratorio. Una clave privada de servidor por sí sola normalmente **no basta** para descifrar capturas modernas TLS 1.3.

# 12. TLS desde la perspectiva Blue Team

## 12.1. Fuentes de telemetría

- Proxy y gateways: destino, dominio, resultado de inspección, políticas.
- EDR: proceso que inició conexión, usuario, ruta del binario, firma, relaciones padre-hijo.
- Firewall/NetFlow: IPs, puertos, bytes, duración, dirección y frecuencia.
- DNS: consultas asociadas a dominios.
- Logs del servidor: errores de negociación, certificados, versiones, solicitudes.
- Captura de paquetes: handshake visible y metadatos según protocolo/extensiones.

## 12.2. Investigación de ejemplo

**Alerta:** equipo corporativo establece conexiones TLS persistentes a un destino inusual.

1. Confirmar hora, zona horaria y precisión de los relojes.
2. Identificar equipo, propietario y criticidad.
3. Identificar el proceso y su árbol de ejecución (EDR).
4. Correlacionar DNS, SNI si está visible y destino IP.
5. Revisar frecuencia, horario y volúmenes.
6. Verificar si el dominio o el binario tiene reputación conocida; no usarla como prueba única.
7. Comparar con línea base y actividad aprobada.
8. Documentar hechos, hipótesis, limitaciones y acción autorizada.

**No concluir «C2» solo porque el canal es TLS o un destino es desconocido.**

# 13. Integridad y análisis forense digital

## 13.1. Qué significa integridad de evidencia

La integridad de una evidencia significa poder sostener que sus bytes corresponden a una adquisición o estado documentados, dentro de un procedimiento verificable. Una comparación de hashes ayuda a detectar cambios entre momentos de medición.

## 13.2. Flujo mínimo de preservación

```text
Identificar fuente → autorizar adquisición → registrar contexto
           ↓
Obtener copia controlada / imagen según procedimiento
           ↓
Calcular SHA-256 y registrar herramienta/versión
           ↓
Conservar original de forma protegida
           ↓
Trabajar sobre copia → recalcular y comparar
           ↓
Registrar análisis, resultados y cadena de custodia
```

**Nunca practicar cambios deliberados sobre la única copia de evidencia real**. Utilizar copias de trabajo. La adquisición original puede requerir bloqueadores de escritura, imagen bit a bit, documentación de dispositivos y herramientas especializadas según el caso.

## 13.3. Manifiesto de evidencia

Ejemplo de campos:

```text
Identificador de caso:
Identificador de evidencia:
Origen/dispositivo:
Responsable de adquisición:
Fecha y hora (con zona horaria):
Procedimiento y herramienta/versión:
Tamaño en bytes:
SHA-256:
Ubicación de almacenamiento:
Transferencias/responsables:
Observaciones/limitaciones:
```

## 13.4. Qué puede demostrar un hash

- Que dos secuencias exactas de bytes tienen el mismo digest calculado con el mismo algoritmo (evidencia muy fuerte de coincidencia, bajo supuestos criptográficos adecuados).
- Que un archivo **cambió** si su digest difiere respecto de una referencia documentada.

## 13.5. Qué no puede demostrar un hash aislado

- Quién creó un archivo.
- Que un archivo sea benigno.
- Que su procedencia sea legítima.
- Cuándo se produjo una modificación.
- Que los datos **antes de la primera medición** fueran íntegros.
- Que no exista otro archivo diferente con el mismo hash en sentido matemático.

La fuerza probatoria requiere relacionar hash, procedencia, controles del entorno, testigos, tiempos, documentación y procedimientos apropiados.

## 13.6. Hash de archivo frente a hash de sistema de archivos

Calcular SHA-256 de un documento no equivale a calcular SHA-256 de la **imagen completa de un disco**. Una imagen puede incluir espacio sin asignar, estructuras de filesystem y metadatos. Hay que documentar **qué bytes** se calcularon exactamente.

# 14. Detección, telemetría y correlación

## 14.1. Eventos útiles

| Señal | Origen | Interpretación |
|---|---|---|
| Cambio de hash de binario crítico | FIM / EDR | Requiere verificar cambio autorizado o compromiso |
| Firma de ejecutable inválida | Validación de firma | Señal de problema de integridad o cadena de confianza |
| Certificado expirado | Servidor/cliente/escáner de configuración | Riesgo de disponibilidad y confianza |
| TLS antiguo aceptado | Inventario/configuración | Potencial problema de endurecimiento |
| Clave privada accesible a usuarios indebidos | Auditoría de permisos | Riesgo de suplantación/compromiso |
| Conexiones TLS inusuales | Proxy/EDR/NetFlow | Hipótesis a corroborar, no condena automática |

## 14.2. Falso positivo vs. verdadero positivo

Una actualización legítima puede cambiar cientos de hashes. Los procesos de despliegue y mantenimiento deben integrarse a las líneas base y reglas de alerta. Una alerta que ve cambios sin información del ciclo de vida de software genera ruido.

## 14.3. Evidencia mínima para cerrar investigación

- Alerta y regla que la generó.
- Sistema, usuario, hora y zona horaria.
- Datos originales relevantes y su origen.
- Comprobaciones efectuadas y resultados.
- Hallazgos confirmados frente a hipótesis.
- Contención/remediación, si existieron y estaban autorizadas.
- Limitaciones y seguimiento.

# 15. Errores frecuentes y decisiones técnicas

1. **«Hash = cifrado».** Falso: un hash no puede descifrarse.
2. **«SHA-256 verifica autor».** Falso: sin secreto/firma y confianza en la referencia, el hash no autentica autoría.
3. **«MD5 es suficientemente seguro porque cambia al editar».** Falso para seguridad adversarial: existen colisiones prácticas.
4. **«SHA-256 es un buen hash de contraseñas por ser fuerte».** No como aplicación directa: usar derivadores de contraseñas resistentes.
5. **«TLS 1.3 se llama TLS 3.1».** Falso.
6. **«HTTPS significa que la web es segura».** Falso: protege el canal TLS, no la lógica ni conducta del sitio.
7. **«AES-256 siempre es mejor en toda condición que AES-128».** Depende de requisitos, implementación y entorno; ambos pueden ser robustos con modos y claves adecuados.
8. **«Todo tráfico cifrado es malicioso».** Falso; la mayor parte del tráfico empresarial legítimo también puede usar cifrado.
9. **«Conservar el SHA-256 es conservar toda la evidencia».** Falso: necesita archivo, contexto y trazabilidad.
10. **«Se puede descifrar una captura TLS 1.3 solo con la clave privada».** Generalmente falso en conexiones modernas con secreto efímero.

# 16. Guía de estudio y referencias

## 16.1. Checklist de competencias

Al terminar esta unidad poder:

- [ ] Explicar por qué se elige un cifrado AEAD.
- [ ] Diferenciar clave pública, privada, de sesión, salt, nonce e IV.
- [ ] Describir el objetivo de firmas, HMAC y certificados.
- [ ] Comparar MD5, SHA-1 y SHA-256 sin afirmar que un hash es prueba absoluta.
- [ ] Explicar padding, bloques, calendario y 64 rondas de SHA-256.
- [ ] Reproducir el digest de `abc` y diagnosticar discrepancias de bytes.
- [ ] Explicar ClientHello, ServerHello, Certificate, Finished y aplicación en TLS 1.3.
- [ ] Interpretar `TLS_AES_128_GCM_SHA256` sin confundir AEAD con digest de archivo.
- [ ] Calcular SHA-256 antes/después de transferir evidencia.
- [ ] Elaborar un registro de cadena de custodia de laboratorio.
- [ ] Analizar metadatos TLS sin inferir automáticamente actividad maliciosa.

## 16.2. Estándares y documentos

- **NIST FIPS 180-4 — Secure Hash Standard (SHA-256 y SHA-2):** https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf
- **NIST FIPS 197 — AES:** https://csrc.nist.gov/pubs/fips/197/final
- **NIST SP 800-38D — GCM:** https://csrc.nist.gov/pubs/sp/800/38/d/final
- **NIST FIPS 202 — SHA-3:** https://csrc.nist.gov/pubs/fips/202/final
- **RFC 2104 — HMAC:** https://www.rfc-editor.org/rfc/rfc2104
- **RFC 5869 — HKDF:** https://www.rfc-editor.org/rfc/rfc5869
- **RFC 9846 — TLS 1.3, especificación actualizada (julio 2026):** https://www.rfc-editor.org/rfc/rfc9846
- **RFC 8446 — TLS 1.3, referencia histórica reemplazada:** https://www.rfc-editor.org/rfc/rfc8446
- **NIST SP 800-86 — Integración de técnicas forenses:** https://csrc.nist.gov/pubs/sp/800/86/final
- **NIST SP 800-61 Rev. 3 — Respuesta a incidentes:** https://csrc.nist.gov/pubs/sp/800/61/r3/final
- **OWASP Password Storage Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **MITRE ATT&CK:** https://attack.mitre.org/
