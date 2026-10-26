
# Unidad 4 — DNS y Resolución de Nombres

> **Área:** Redes informáticas y ciberseguridad  
> **Objetivo:** Comprender la arquitectura del sistema DNS, el proceso completo de resolución de nombres, sus mensajes, servidores, registros, mecanismos de caché, tecnologías de seguridad y herramientas de diagnóstico.

---

# Índice

1. [Introducción al sistema DNS](#1-introducción-al-sistema-dns)
2. [Nombres de dominio y estructura jerárquica](#2-nombres-de-dominio-y-estructura-jerárquica)
3. [Arquitectura y componentes de DNS](#3-arquitectura-y-componentes-de-dns)
4. [Servidores recursivos y autoritativos](#4-servidores-recursivos-y-autoritativos)
5. [Proceso completo de resolución DNS](#5-proceso-completo-de-resolución-dns)
6. [Consultas y respuestas DNS](#6-consultas-y-respuestas-dns)
7. [Registros DNS](#7-registros-dns)
8. [Zonas DNS y delegación](#8-zonas-dns-y-delegación)
9. [Caché DNS y TTL](#9-caché-dns-y-ttl)
10. [Transporte DNS: UDP, TCP, DoT y DoH](#10-transporte-dns-udp-tcp-dot-y-doh)
11. [DNSSEC y seguridad de los registros](#11-dnssec-y-seguridad-de-los-registros)
12. [Amenazas y ataques contra DNS](#12-amenazas-y-ataques-contra-dns)
13. [DNS en redes corporativas](#13-dns-en-redes-corporativas)
14. [Diagnóstico y resolución de problemas](#14-diagnóstico-y-resolución-de-problemas)
15. [Buenas prácticas de seguridad DNS](#16-buenas-prácticas-de-seguridad-dns)
16. [Glosario](#17-glosario)
17. [Referencias técnicas](#18-referencias-técnicas)

---

# 1. Introducción al sistema DNS

## 1.1. ¿Qué es DNS?

DNS significa **Domain Name System**, o Sistema de Nombres de Dominio.

Es un sistema distribuido y jerárquico que permite almacenar y consultar información asociada a nombres de dominio.

Una de sus funciones más conocidas es relacionar nombres con direcciones IP.

Por ejemplo:

```text
www.example.com
       |
       v
Consulta DNS
       |
       v
Dirección IP del servidor
```

Los nombres son más fáciles de recordar para las personas que las direcciones IP.

Sin embargo, DNS no se limita a convertir nombres en direcciones.

También se utiliza para:

- Identificar servidores de correo.
- Publicar información de servicios.
- Establecer delegaciones entre servidores.
- Publicar políticas relacionadas con correo electrónico.
- Facilitar mecanismos de validación criptográfica.
- Realizar consultas inversas.
- Apoyar el descubrimiento de determinados servicios.

## 1.2. ¿Por qué existe DNS?

Imaginemos que para acceder a cada sitio web tuviéramos que recordar su dirección IP.

Sería necesario memorizar una gran cantidad de números.

Además, los servidores pueden cambiar de dirección IP.

DNS permite utilizar nombres relativamente estables aunque cambie la infraestructura que presta el servicio.

### Ejemplo

Un usuario introduce:

```text
https://www.example.com
```

El navegador necesita obtener información de direccionamiento para establecer una conexión.

El sistema puede consultar DNS y recibir una o varias direcciones IP.

Después utiliza esa información para continuar la comunicación.

## 1.3. ¿DNS es una base de datos?

Sí, pero no funciona como una base de datos tradicional centralizada.

DNS es una base de datos:

- Distribuida.
- Jerárquica.
- Delegada.
- Replicada.
- Consultable mediante protocolos estandarizados.

No existe un único servidor que almacene todos los nombres de Internet.

La información se distribuye entre múltiples organizaciones y servidores.

## 1.4. DNS no es un buscador web

DNS y los motores de búsqueda cumplen funciones diferentes.

| DNS | Motor de búsqueda |
|---|---|
| Consulta información asociada a nombres | Busca e indexa contenido |
| Utiliza registros DNS | Utiliza índices de documentos |
| Puede devolver direcciones IP | Devuelve resultados y enlaces |
| Participa en la conectividad | Facilita descubrir información |

---

# 2. Nombres de dominio y estructura jerárquica

## 2.1. ¿Qué es un nombre de dominio?

Es un nombre formado por etiquetas organizadas jerárquicamente.

Ejemplo:

```text
www.example.com
```

Se compone de:

- `www`
- `example`
- `com`

Cada etiqueta está separada por un punto.

## 2.2. La raíz DNS

En la parte superior de la jerarquía se encuentra la raíz.

Se representa mediante un punto final:

```text
.
```

Un nombre completamente calificado puede escribirse como:

```text
www.example.com.
```

El punto final indica explícitamente la raíz.

En muchos programas se omite visualmente.

## 2.3. TLD

TLD significa **Top-Level Domain**.

Ejemplos:

```text
.com
.org
.net
.edu
.ar
```

Los TLD pueden tener diferentes políticas de registro y administración.

## 2.4. Dominio de segundo nivel

En:

```text
example.com
```

`example` es una etiqueta inmediatamente inferior a `.com`.

No todos los sistemas de registro utilizan la misma estructura comercial o administrativa.

Por ejemplo, algunas políticas de registro permiten nombres bajo dominios públicos de varios niveles.

## 2.5. Subdominio

Un subdominio es un nombre situado por debajo de otro dentro de la jerarquía.

Ejemplos:

```text
www.example.com
mail.example.com
api.example.com
```

En términos DNS, `www`, `mail` y `api` son etiquetas de nombres subordinados a `example.com`.

## 2.6. FQDN

FQDN significa **Fully Qualified Domain Name**.

Es un nombre que identifica una posición completa dentro del árbol DNS.

Ejemplo:

```text
mail.example.com.
```

## 2.7. Estructura jerárquica

```text
                    .
                    |
          +---------+---------+
          |         |         |
         com       org        ar
          |
       example
          |
     +----+----+
     |         |
    www       mail
```

La jerarquía permite delegar la administración de distintas partes del espacio de nombres.

## 2.8. ¿Quién administra DNS?

Existen distintas responsabilidades.

**ICANN:** coordina determinadas funciones del sistema de identificadores de Internet.

**IANA:** administra registros y funciones técnicas relacionadas con identificadores y parámetros de protocolos.

**Operadores de la raíz:** mantienen instancias de los servidores raíz.

**Registros de dominios:** administran información de registro de determinados TLD.

**Registradores:** ofrecen servicios de registro de nombres de dominio.

**Operadores DNS:** administran servidores y zonas.

Estas funciones no deben confundirse.

---

# 3. Arquitectura y componentes de DNS

## 3.1. Stub resolver

Es el componente del dispositivo cliente que solicita resolución de nombres.

Puede formar parte del sistema operativo o de una biblioteca utilizada por una aplicación.

Habitualmente envía consultas a un resolvedor recursivo configurado.

## 3.2. Resolvedor recursivo

Recibe consultas de clientes y trabaja para obtener las respuestas correspondientes.

Puede:

- Consultar su caché.
- Consultar otros servidores DNS.
- Seguir delegaciones.
- Aplicar políticas.
- Validar DNSSEC cuando está configurado para hacerlo.
- Devolver respuestas a los clientes.

## 3.3. Servidores raíz

Los servidores raíz proporcionan información necesaria para localizar servidores responsables de los dominios de nivel superior.

No almacenan todos los registros de todos los sitios web.

Existen 13 identidades lógicas de servidores raíz, denominadas de A a M, implementadas mediante numerosas instancias distribuidas geográficamente.

## 3.4. Servidores TLD

Son servidores autoritativos para las zonas de nivel superior correspondientes.

Por ejemplo, los servidores de `.com` permiten obtener información de delegación hacia dominios registrados bajo ese TLD.

## 3.5. Servidores autoritativos

Son servidores que proporcionan respuestas basadas en la información autoritativa de las zonas que administran.

Por ejemplo, un servidor autoritativo para `example.com` puede responder consultas sobre registros definidos dentro de esa zona.

## 3.6. Caché

La caché conserva temporalmente respuestas o información DNS obtenida previamente.

Permite:

- Reducir latencia.
- Disminuir consultas repetidas.
- Reducir carga.
- Mejorar eficiencia.

La permanencia de los datos depende de los TTL y de las políticas del resolvedor.

---

# 4. Servidores recursivos y autoritativos

## 4.1. Diferencia fundamental

El resolvedor recursivo busca la respuesta en nombre del cliente.

El servidor autoritativo proporciona información sobre la zona DNS que administra.

| Característica | Recursivo | Autoritativo |
|---|---|---|
| Atiende consultas de clientes | Sí, habitualmente | Puede recibir consultas directas |
| Busca información en otros servidores | Sí | No como función autoritativa |
| Mantiene caché de resolución | Habitualmente | No es su función principal |
| Administra datos de una zona | No necesariamente | Sí |
| Devuelve respuestas autoritativas | No por el simple hecho de resolver | Sí, para sus zonas |

Un mismo software o servidor puede implementar más de una función, aunque suele recomendarse separar responsabilidades según el entorno.

## 4.2. Consulta recursiva

En una consulta recursiva, el cliente solicita al resolvedor que obtenga la respuesta final o devuelva un error adecuado.

Ejemplo:

```text
Cliente
   |
   | Consulta recursiva
   v
Resolvedor recursivo
   |
   | Realiza consultas necesarias
   v
Otros servidores DNS
```

## 4.3. Consulta iterativa

En una resolución iterativa, un servidor puede responder con información que permite continuar la búsqueda.

Por ejemplo, puede devolver una referencia hacia servidores de otra zona.

El resolvedor utiliza esa información para realizar consultas posteriores.

## 4.4. Ejemplo comparativo

### Recursiva

```text
Cliente:
¿Cuál es la dirección de www.example.com?

Resolvedor:
Voy a obtener la respuesta o informar el error.
```

### Iterativa

```text
Resolvedor:
¿Dónde puedo consultar información sobre example.com?

Servidor consultado:
Estos son los servidores correspondientes.
```

Las frases son analogías; los mensajes reales utilizan el formato DNS.

---

# 5. Proceso completo de resolución DNS

Analicemos qué sucede cuando se necesita resolver:

```text
www.example.com
```

Este es un recorrido didáctico. En la práctica pueden intervenir cachés, respuestas ya conocidas, consultas paralelas, alias y otros mecanismos.

## Paso 1 — El usuario introduce el dominio

El usuario escribe:

```text
https://www.example.com
```

El navegador interpreta la URL y determina el nombre del servidor.

## Paso 2 — Consulta de información local

Antes de enviar consultas externas, el sistema puede comprobar:

- Caché de la aplicación.
- Caché del sistema operativo.
- Archivo de hosts.
- Configuraciones específicas de resolución.

No existe un único orden universal: depende del sistema y de la aplicación.

## Paso 3 — Consulta al resolvedor

Si no existe información suficiente, el cliente envía una consulta al resolvedor configurado.

Puede solicitar registros:

```text
A
AAAA
```

para obtener direcciones IPv4 e IPv6.

## Paso 4 — Consulta de caché recursiva

El resolvedor verifica si dispone de información válida en caché.

Si tiene una respuesta utilizable, puede devolverla sin realizar todo el recorrido jerárquico.

## Paso 5 — Consulta a la raíz

Si necesita descubrir información desde la jerarquía DNS, puede consultar un servidor raíz.

El servidor raíz puede proporcionar una referencia hacia los servidores responsables de `.com`.

## Paso 6 — Consulta al TLD

El resolvedor consulta información correspondiente a `.com`.

El servidor TLD puede devolver una delegación hacia los servidores autoritativos de `example.com`.

## Paso 7 — Consulta al autoritativo

El resolvedor consulta al servidor autoritativo correspondiente.

Este responde con los registros solicitados, una referencia, un alias o una respuesta negativa, según el caso.

## Paso 8 — Almacenamiento en caché

El resolvedor puede almacenar la información obtenida durante el tiempo permitido por los TTL y sus políticas.

## Paso 9 — Respuesta al cliente

El resolvedor devuelve el resultado.

## Paso 10 — Inicio de la comunicación

La aplicación utiliza la información para intentar establecer la conexión con el servicio.

### Diagrama completo

```text
USUARIO
   |
   v
NAVEGADOR
   |
   v
RESOLUCIÓN LOCAL
   |
   v
RESOLVEDOR RECURSIVO
   |
   +------ ¿Respuesta en caché?
   |              |
   |             Sí
   |              |
   |              v
   |          Respuesta
   |
   +------ No disponible
                  |
                  v
             SERVIDOR RAÍZ
                  |
                  v
              SERVIDOR TLD
                  |
                  v
          SERVIDOR AUTORITATIVO
                  |
                  v
              RESPUESTA DNS
                  |
                  v
           RESOLVEDOR RECURSIVO
                  |
                  v
               CLIENTE
                  |
                  v
          CONEXIÓN AL SERVICIO
```

## 5.1. ¿Siempre se consulta a la raíz?

No.

El resolvedor puede tener información suficiente en caché.

También puede utilizar mecanismos de optimización.

Por eso, una consulta DNS no implica necesariamente que se contacten todos los niveles de la jerarquía.

## 5.2. ¿DNS establece la conexión web?

No.

DNS proporciona información de resolución.

Después intervienen otros mecanismos como:

- Enrutamiento IP.
- TCP o QUIC.
- TLS.
- HTTP.

DNS y HTTP cumplen funciones diferentes.

---

# 6. Consultas y respuestas DNS

## 6.1. Estructura de un mensaje DNS

Un mensaje DNS clásico incluye:

1. Header.
2. Question.
3. Answer.
4. Authority.
5. Additional.

## 6.2. Header

El encabezado contiene información de control.

Entre sus campos están:

- Transaction ID.
- Flags.
- QDCOUNT.
- ANCOUNT.
- NSCOUNT.
- ARCOUNT.

## 6.3. Transaction ID

Es un identificador de 16 bits utilizado para relacionar determinadas respuestas con consultas.

Por sí solo no proporciona una protección criptográfica suficiente contra falsificación.

## 6.4. Flags

Entre los indicadores DNS se encuentran:

| Indicador | Función |
|---|---|
| QR | Distingue consulta y respuesta |
| AA | Indica respuesta autoritativa |
| TC | Indica truncamiento |
| RD | Solicita recursión |
| RA | Indica disponibilidad de recursión |
| AD | Relacionado con datos autenticados |
| CD | Control de comprobación DNSSEC |

## 6.5. RCODE

Indica el resultado de la consulta.

Valores importantes:

| Código | Nombre | Significado |
|---|---|---|
| 0 | NOERROR | Sin error de protocolo |
| 1 | FORMERR | Error de formato |
| 2 | SERVFAIL | Fallo del servidor |
| 3 | NXDOMAIN | El nombre consultado no existe |
| 4 | NOTIMP | Función no implementada |
| 5 | REFUSED | Consulta rechazada |

**Importante:** `NOERROR` no significa necesariamente que exista un registro del tipo solicitado.

Una respuesta puede indicar que el nombre existe, pero no tiene registros de ese tipo.

## 6.6. Sección Question

Incluye datos como:

- QNAME: nombre consultado.
- QTYPE: tipo de registro solicitado.
- QCLASS: clase de la consulta.

Ejemplo conceptual:

```text
QNAME: www.example.com.
QTYPE: A
QCLASS: IN
```

## 6.7. Sección Answer

Contiene registros que responden a la consulta, cuando corresponde.

Ejemplo ilustrativo:

```text
www.example.com.  300  IN  A  192.0.2.10
```

`192.0.2.10` es una dirección reservada para documentación.

## 6.8. Sección Authority

Puede contener información relacionada con la autoridad de una zona o con referencias necesarias para continuar la resolución.

## 6.9. Sección Additional

Puede contener registros adicionales útiles para interpretar o continuar el proceso.

Por ejemplo, información de direcciones de determinados servidores de nombres.

## 6.10. Respuesta positiva y negativa

### Respuesta positiva

El servidor devuelve información que satisface la consulta.

### NXDOMAIN

El nombre consultado no existe según la información DNS correspondiente.

### NODATA

El nombre existe, pero no hay datos del tipo solicitado.

Generalmente se representa mediante `NOERROR` sin registros de respuesta del tipo pedido.

### SERVFAIL

El servidor no pudo completar correctamente la consulta.

Puede deberse a diferentes causas, como problemas de resolución o validación DNSSEC.

---

# 7. Registros DNS

Los registros DNS son unidades de información almacenadas en el sistema de nombres.

Un registro de recurso contiene campos como:

- Nombre.
- Tipo.
- Clase.
- TTL.
- Datos específicos.

## 7.1. Registro A

Relaciona un nombre con una dirección IPv4.

Ejemplo:

```dns
www.example.com. 300 IN A 192.0.2.10
```

## 7.2. Registro AAAA

Relaciona un nombre con una dirección IPv6.

Ejemplo:

```dns
www.example.com. 300 IN AAAA 2001:db8::10
```

## 7.3. Registro CNAME

Define un alias hacia otro nombre canónico.

Ejemplo:

```dns
www.example.com. 300 IN CNAME web.example.net.
```

El cliente o resolvedor puede necesitar consultar posteriormente los registros del nombre de destino.

Un nombre que contiene un CNAME no debe tener otros datos ordinarios incompatibles en el mismo nombre.

## 7.4. Registro MX

Indica servidores responsables de recibir correo para un dominio.

Ejemplo:

```dns
example.com. 300 IN MX 10 mail.example.com.
```

El número `10` representa una preferencia.

Valores menores tienen mayor preferencia.

## 7.5. Registro NS

Identifica servidores de nombres para una zona o delegación.

Ejemplo:

```dns
example.com. 300 IN NS ns1.example.com.
```

## 7.6. Registro SOA

SOA significa Start of Authority.

Contiene información administrativa de una zona DNS.

Puede incluir:

- Servidor primario indicado.
- Contacto administrativo.
- Número de serie.
- Temporizadores de sincronización.
- Parámetros relacionados con caché negativa.

## 7.7. Registro TXT

Almacena información textual.

Se utiliza en distintos mecanismos, como:

- SPF.
- Verificaciones de dominio.
- Configuraciones de servicios.
- Políticas y metadatos.

Ejemplo:

```dns
example.com. 300 IN TXT "v=spf1 -all"
```

Este ejemplo publica una política SPF que no autoriza emisores para el dominio correspondiente.

## 7.8. Registro PTR

Se utiliza habitualmente para resolución inversa.

Permite relacionar una dirección IP con un nombre DNS mediante zonas especiales.

## 7.9. Registro CAA

Permite expresar qué autoridades certificadoras están autorizadas para emitir determinados certificados para un dominio.

Ejemplo conceptual:

```dns
example.com. 300 IN CAA 0 issue "ca.example"
```

El valor es ilustrativo.

## 7.10. Registro SRV

Permite localizar determinados servicios mediante nombres y parámetros.

Incluye:

- Prioridad.
- Peso.
- Puerto.
- Nombre del servidor.

Ejemplo:

```dns
_servicio._tcp.example.com. 300 IN SRV 10 5 8443 host.example.com.
```

## 7.11. Registros DNSSEC

Entre los tipos importantes están:

- DNSKEY.
- DS.
- RRSIG.
- NSEC.
- NSEC3.

Se utilizan para establecer y verificar información criptográfica asociada con DNS.

## 7.12. Tabla general

| Registro | Función |
|---|---|
| A | Dirección IPv4 |
| AAAA | Dirección IPv6 |
| CNAME | Alias |
| MX | Servidores de correo |
| NS | Servidores de nombres |
| SOA | Información administrativa de zona |
| TXT | Información textual |
| PTR | Resolución inversa |
| CAA | Política de emisión de certificados |
| SRV | Descubrimiento de servicios |
| DNSKEY | Clave pública DNSSEC |
| DS | Referencia de confianza DNSSEC |
| RRSIG | Firma DNSSEC |
| NSEC/NSEC3 | Prueba de inexistencia autenticada |

---

# 8. Zonas DNS y delegación

## 8.1. ¿Qué es una zona DNS?

Una zona DNS es una porción administrada del espacio de nombres DNS.

No debe confundirse necesariamente con un dominio completo.

Un dominio puede contener varias zonas delegadas.

## 8.2. Ejemplo

Supongamos:

```text
example.com
```

Una organización administra esa zona.

Puede delegar:

```text
laboratorio.example.com
```

a otros servidores autoritativos.

## 8.3. Delegación

La delegación permite transferir responsabilidad administrativa de una parte del árbol DNS a otra zona.

Se implementa mediante información de servidores de nombres y otros datos necesarios.

## 8.4. Glue Records

Cuando los nombres de los servidores delegados dependen de la propia zona delegada, pueden ser necesarios registros de dirección adicionales para evitar dependencias circulares en la resolución.

A estos datos se los conoce como glue.

## 8.5. Transferencia de zona

Las transferencias de zona permiten sincronizar información entre servidores DNS autorizados.

Tipos conocidos:

- AXFR: transferencia completa.
- IXFR: transferencia incremental.

Habitualmente utilizan TCP.

Las transferencias deben limitarse a sistemas autorizados.

## 8.6. Primary y Secondary

En determinadas arquitecturas DNS:

**Primary:** origen de los datos de una zona para su distribución.

**Secondary:** obtiene información de zona mediante mecanismos de transferencia.

Un servidor secundario también puede proporcionar respuestas autoritativas.

---

# 9. Caché DNS y TTL

## 9.1. ¿Qué es la caché DNS?

Es el almacenamiento temporal de información obtenida mediante consultas DNS.

## 9.2. ¿Qué es TTL?

TTL significa Time To Live.

En DNS indica durante cuánto tiempo puede conservarse un registro en caché.

Se expresa en segundos.

Ejemplo:

```dns
www.example.com. 300 IN A 192.0.2.10
```

El TTL es:

```text
300 segundos
```

Equivale a cinco minutos.

## 9.3. ¿Por qué existe TTL?

Permite equilibrar:

- Rendimiento.
- Carga de consultas.
- Actualización de información.
- Disponibilidad.

## 9.4. TTL alto

Ventajas:

- Menos consultas.
- Mayor aprovechamiento de caché.

Desventajas:

- Los cambios pueden tardar más en reflejarse en cachés existentes.

## 9.5. TTL bajo

Ventajas:

- Puede facilitar cambios más rápidos.

Desventajas:

- Puede aumentar consultas.
- Incrementa dependencia de los servidores de resolución.

## 9.6. ¿Qué es la propagación DNS?

Es una expresión informal utilizada para describir el tiempo durante el cual diferentes resolvedores pueden devolver información antigua o nueva después de un cambio.

DNS no envía necesariamente cada modificación de manera instantánea a todos los servidores del mundo.

Las diferencias suelen relacionarse con:

- TTL.
- Cachés.
- Sincronización de servidores.
- Delegaciones.
- Configuración.
- Políticas de resolvedores.

## 9.7. Caché negativa

DNS también puede almacenar temporalmente información sobre respuestas negativas.

Esto reduce consultas repetidas por nombres inexistentes.

Su comportamiento está regulado por mecanismos específicos, incluyendo parámetros de la zona.

## 9.8. Vaciar caché local

En Windows:

```powershell
ipconfig /flushdns
```

En sistemas Linux que utilizan `systemd-resolved`:

```bash
resolvectl flush-caches
```

La disponibilidad y el efecto del comando dependen del sistema y del resolvedor utilizado.

Vaciar una caché local no elimina las cachés de todos los resolvedores externos.

---

# 10. Transporte DNS: UDP, TCP, DoT y DoH

## 10.1. DNS sobre UDP

DNS tradicional utiliza frecuentemente UDP 53.

Ventajas:

- Intercambio simple de datagramas.
- Menor sobrecarga de establecimiento de transporte.
- Adecuado para numerosas consultas.

Sin embargo, UDP no garantiza entrega.

Los resolvedores deben manejar tiempos de espera y reintentos.

## 10.2. DNS sobre TCP

DNS también utiliza TCP 53.

Es importante para:

- Respuestas que requieren TCP.
- Transferencias de zona.
- Determinadas consultas y operaciones.

No es correcto afirmar que DNS siempre utiliza UDP.

## 10.3. EDNS

EDNS significa Extension Mechanisms for DNS.

Permite ampliar determinadas capacidades del protocolo DNS.

Entre otras funciones, permite negociar tamaños mayores de mensajes UDP y transportar información adicional mediante mecanismos estandarizados.

## 10.4. DNS over TLS — DoT

DoT protege el transporte de consultas DNS mediante TLS.

Puerto habitual:

```text
TCP 853
```

Ayuda a evitar que determinados observadores del canal lean o modifiquen directamente las consultas protegidas.

## 10.5. DNS over HTTPS — DoH

DoH transporta consultas DNS mediante HTTPS.

Habitualmente utiliza el puerto 443.

Puede funcionar sobre diferentes versiones de HTTP y sus transportes correspondientes.

## 10.6. Comparación

| Tecnología | Transporte | Cifrado del canal |
|---|---|---|
| DNS tradicional UDP | UDP 53 | No |
| DNS tradicional TCP | TCP 53 | No |
| DoT | TLS sobre TCP | Sí |
| DoH | HTTPS | Sí |

## 10.7. ¿DoH y DoT garantizan privacidad total?

No.

Protegen el canal entre el cliente y el resolvedor correspondiente, pero:

- El resolvedor puede conocer las consultas.
- El destino de una conexión puede ser observable por otros mecanismos.
- Pueden existir registros y políticas del proveedor.
- Las aplicaciones pueden revelar información adicional.

---

# 11. DNSSEC y seguridad de los registros

## 11.1. ¿Qué es DNSSEC?

DNSSEC significa Domain Name System Security Extensions.

Es un conjunto de extensiones que permite validar criptográficamente información DNS.

Sus objetivos principales son:

- Autenticidad de origen de los datos DNS.
- Integridad de las respuestas validadas.
- Prueba autenticada de inexistencia de determinados datos.

## 11.2. ¿DNSSEC cifra DNS?

No.

DNSSEC no está diseñado para ocultar las consultas o respuestas.

Su objetivo principal es permitir la validación de la autenticidad e integridad de los datos.

## 11.3. Firmas digitales

Una zona firmada puede publicar firmas criptográficas sobre conjuntos de registros.

Un resolvedor validador puede comprobar esas firmas utilizando claves apropiadas.

## 11.4. Cadena de confianza

DNSSEC utiliza una estructura jerárquica de confianza.

Conceptualmente:

```text
Raíz DNS
   |
   v
TLD
   |
   v
Dominio
   |
   v
Registros firmados
```

## 11.5. Registros principales

### DNSKEY

Publica claves públicas utilizadas en DNSSEC.

### RRSIG

Contiene firmas sobre conjuntos de registros.

### DS

Permite vincular criptográficamente una zona delegada con información de confianza de la zona superior.

### NSEC y NSEC3

Permiten proporcionar pruebas autenticadas de inexistencia.

## 11.6. ¿Qué ocurre si falla la validación?

Un resolvedor que valida DNSSEC puede rechazar datos que no superen las comprobaciones requeridas.

Dependiendo del caso, el cliente puede recibir una respuesta de error como SERVFAIL.

## 11.7. DNSSEC y DoH no son lo mismo

| DNSSEC | DoH |
|---|---|
| Valida datos DNS | Cifra transporte DNS |
| Protege integridad y autenticidad de origen | Protege el canal cliente-resolvedor |
| No oculta consultas | Puede ocultarlas a observadores del canal |
| Utiliza firmas y cadena de confianza | Utiliza HTTPS/TLS |

Son tecnologías complementarias.

---

# 12. Amenazas y ataques contra DNS

DNS es un componente crítico de Internet y, por lo tanto, un objetivo importante para atacantes.

## 12.1. DNS Spoofing

Consiste en falsificar información DNS para inducir a un sistema a utilizar respuestas incorrectas.

### Consecuencias posibles

- Redirección a destinos maliciosos.
- Interrupción de servicios.
- Suplantación de servicios.
- Facilitación de otros ataques.

## 12.2. DNS Cache Poisoning

Consiste en introducir información falsa en la caché de un resolvedor.

### Ejemplo conceptual

Un usuario solicita:

```text
www.example.com
```

Un atacante intenta que el resolvedor almacene una dirección IP incorrecta.

Los usuarios que dependan de esa caché podrían recibir información manipulada.

### Controles defensivos

- Validación DNSSEC.
- Software actualizado.
- Aleatorización apropiada.
- Restricción de consultas.
- Configuración segura.

## 12.3. DNS Hijacking

Consiste en alterar el proceso de resolución para redirigir consultas o respuestas.

Puede ocurrir mediante:

- Cambios maliciosos de configuración.
- Compromiso de routers.
- Modificación de servidores DNS.
- Compromiso de cuentas administrativas.

## 12.4. DNS Tunneling

Consiste en transportar información adicional mediante mensajes DNS.

Puede utilizarse con fines legítimos en entornos controlados, pero también para:

- Exfiltración.
- Comunicación encubierta.
- Evasión de controles.

### Indicadores defensivos

- Consultas muy largas.
- Nombres con alta entropía.
- Volumen anómalo.
- Consultas repetitivas.
- Patrones inusuales de registros.

Estos indicadores no constituyen por sí solos prueba de actividad maliciosa.

## 12.5. DNS Amplification

Es una técnica de denegación de servicio distribuida basada en generar respuestas DNS mayores que las consultas utilizadas para provocarlas.

Puede aprovechar suplantación de direcciones IP y resolvedores mal configurados.

### Controles

- Evitar resolvedores recursivos abiertos innecesarios.
- Aplicar políticas de respuesta.
- Implementar controles contra suplantación.
- Utilizar protección contra DDoS.

## 12.6. DNS Reflection

La reflexión ocurre cuando respuestas generadas por terceros se dirigen hacia una víctima mediante manipulación de la dirección de origen.

La amplificación y la reflexión pueden combinarse.

## 12.7. Domain Generation Algorithms

Algunas familias de malware utilizan algoritmos para generar múltiples nombres de dominio.

Esto puede dificultar la interrupción de su infraestructura de comunicación.

## 12.8. Subdomain Takeover

Puede ocurrir cuando un nombre DNS continúa apuntando a un recurso externo que ya no está correctamente controlado por su propietario original.

La posibilidad real de explotación depende del proveedor y de la configuración.

### Medidas preventivas

- Inventariar registros DNS.
- Eliminar referencias obsoletas.
- Supervisar servicios externos.
- Revisar delegaciones.
- Gestionar adecuadamente bajas de infraestructura.

---

# 13. DNS en redes corporativas

## 13.1. DNS interno

Muchas organizaciones utilizan servidores DNS para resolver nombres de sistemas internos.

Ejemplo:

```text
servidor.interno.example.com
```

Estos nombres pueden no estar publicados en DNS público.

## 13.2. Split-Horizon DNS

Permite ofrecer respuestas diferentes según el origen de la consulta o la vista DNS utilizada.

Ejemplo:

```text
Consulta desde red interna:
app.example.com -> 10.10.10.20

Consulta desde Internet:
app.example.com -> 198.51.100.20
```

Las direcciones son ilustrativas.

## 13.3. Forwarders

Un servidor DNS puede reenviar determinadas consultas a otro resolvedor.

Esto permite centralizar políticas o utilizar servicios externos.

## 13.4. Conditional Forwarding

Permite reenviar consultas correspondientes a determinados dominios hacia resolvedores específicos.

Es frecuente en organizaciones con varias zonas o entornos conectados.

## 13.5. Active Directory y DNS

En entornos Microsoft Active Directory, DNS cumple funciones importantes para localizar controladores de dominio y servicios.

Se utilizan registros como SRV.

Una configuración DNS incorrecta puede afectar autenticación y administración de equipos.

## 13.6. Monitoreo DNS

El monitoreo puede ayudar a identificar:

- Errores de resolución.
- Cambios inesperados.
- Consultas inusuales.
- Problemas de disponibilidad.
- Posibles actividades maliciosas.

Debe realizarse respetando las políticas de privacidad y retención de información.

---

# 14. Diagnóstico y resolución de problemas

## 14.1. Síntomas frecuentes

- Una página no abre por nombre.
- El servicio responde por IP, pero no por dominio.
- Se obtiene una dirección incorrecta.
- Las respuestas son intermitentes.
- Un dominio devuelve NXDOMAIN.
- La resolución tarda demasiado.
- Un resolvedor devuelve SERVFAIL.

## 14.2. Diagnóstico por etapas

1. Verificar conectividad IP.
2. Comprobar configuración DNS.
3. Consultar el nombre.
4. Consultar tipos de registros específicos.
5. Comparar respuestas de resolvedores.
6. Revisar TTL.
7. Verificar delegación.
8. Comprobar DNSSEC cuando corresponda.
9. Analizar tráfico si es necesario.

## 14.3. nslookup

Consulta básica:

```bash
nslookup example.com
```

Consulta MX:

```bash
nslookup -type=MX example.com
```

Consulta NS:

```bash
nslookup -type=NS example.com
```

## 14.4. dig

Consulta A:

```bash
dig example.com A
```

Consulta AAAA:

```bash
dig example.com AAAA
```

Consulta MX:

```bash
dig example.com MX
```

Consulta NS:

```bash
dig example.com NS
```

Consulta TXT:

```bash
dig example.com TXT
```

## 14.5. Consultar un resolvedor específico

```bash
dig @1.1.1.1 example.com A
```

El comando solicita una respuesta al resolvedor indicado.

No significa que ese resolvedor sea autoritativo para el dominio.

## 14.6. Mostrar el recorrido de delegación

```bash
dig +trace example.com
```

Permite observar consultas y referencias relacionadas con el recorrido de resolución.

La salida depende del entorno y de las condiciones de red.

## 14.7. Consulta inversa

```bash
dig -x 192.0.2.10
```

Realiza una consulta inversa para una dirección IPv4 de documentación.

## 14.8. Interpretar una respuesta

Ejemplo ilustrativo:

```text
;; ->>HEADER<<- opcode: QUERY, status: NOERROR
;; QUESTION SECTION:
;www.example.com. IN A

;; ANSWER SECTION:
www.example.com. 300 IN A 192.0.2.10
```

Interpretación:

- `QUERY`: operación de consulta.
- `NOERROR`: no se produjo un error DNS de ese tipo.
- `A`: se solicitó una dirección IPv4.
- `300`: TTL en segundos.
- `192.0.2.10`: dirección de ejemplo devuelta.

## 14.9. ¿Qué significa NXDOMAIN?

El nombre consultado no existe según la respuesta DNS correspondiente.

No significa necesariamente que el servidor web esté apagado.

## 14.10. ¿Qué significa SERVFAIL?

El servidor no pudo completar la consulta.

Puede estar relacionado con:

- Fallas de comunicación.
- Problemas de delegación.
- Errores DNSSEC.
- Fallas de servidores.
- Configuraciones incorrectas.

No permite identificar una causa única sin investigar.

# 15. Buenas prácticas de seguridad DNS

## 15.1. Mantener software actualizado

Los servidores y resolvedores deben mantenerse actualizados para reducir exposición a vulnerabilidades conocidas.

## 15.2. Restringir recursión

Un servidor recursivo no debería estar disponible indiscriminadamente si su función es atender únicamente una red interna.

## 15.3. Separar funciones

Cuando el diseño lo justifique, separar servicios autoritativos de resolvedores recursivos.

## 15.4. Utilizar DNSSEC cuando corresponda

Permite verificar criptográficamente información DNS firmada.

Requiere gestión adecuada de claves y delegaciones.

## 15.5. Proteger transferencias de zona

Limitar AXFR e IXFR a servidores autorizados y utilizar mecanismos de autenticación cuando corresponda.

## 15.6. Proteger cuentas administrativas

- MFA.
- Mínimo privilegio.
- Gestión de credenciales.
- Auditoría.
- Control de cambios.

## 15.7. Supervisar registros

Detectar:

- Cambios no autorizados.
- Delegaciones inesperadas.
- Registros obsoletos.
- Fallas recurrentes.
- Configuraciones incorrectas.

## 15.8. Monitorear consultas

Analizar patrones relevantes sin asumir que cualquier consulta inusual es maliciosa.

## 15.9. Documentar zonas

Mantener registros sobre:

- Propietarios.
- Dominios.
- Subdominios.
- Servidores autoritativos.
- TTL.
- Registros críticos.
- Dependencias externas.

---

# 16. Glosario

| Concepto | Definición |
|---|---|
| DNS | Sistema de nombres de dominio |
| Dominio | Nombre dentro de la jerarquía DNS |
| TLD | Dominio de nivel superior |
| FQDN | Nombre de dominio completamente calificado |
| Stub Resolver | Componente cliente de resolución |
| Resolvedor recursivo | Sistema que obtiene respuestas para clientes |
| Servidor autoritativo | Servidor responsable de datos de una zona |
| Zona DNS | Porción administrada del espacio DNS |
| Delegación | Asignación de autoridad a otra zona |
| Registro A | Asociación con IPv4 |
| Registro AAAA | Asociación con IPv6 |
| CNAME | Alias |
| MX | Servidor de correo |
| NS | Servidor de nombres |
| SOA | Información administrativa de zona |
| TXT | Registro textual |
| PTR | Resolución inversa |
| TTL | Tiempo de vida de caché |
| NXDOMAIN | Nombre inexistente |
| SERVFAIL | Fallo del servidor DNS |
| DNSSEC | Extensiones de seguridad DNS |
| DoH | DNS sobre HTTPS |
| DoT | DNS sobre TLS |
| AXFR | Transferencia completa de zona |
| IXFR | Transferencia incremental de zona |
| Glue | Datos de dirección necesarios para determinadas delegaciones |
| Cache Poisoning | Manipulación de información almacenada en caché |
| DNS Tunneling | Transporte de información mediante mensajes DNS |
| DNS Amplification | Abuso de respuestas DNS para amplificar tráfico |

---

# 17. Referencias técnicas

## Especificaciones fundamentales

- [RFC 1034 — Domain Names: Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034)
- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 2181 — Clarifications to the DNS Specification](https://www.rfc-editor.org/rfc/rfc2181)
- [RFC 2308 — Negative Caching of DNS Queries](https://www.rfc-editor.org/rfc/rfc2308)

## DNSSEC

- [RFC 4033 — DNS Security Introduction](https://www.rfc-editor.org/rfc/rfc4033)
- [RFC 4034 — Resource Records for DNSSEC](https://www.rfc-editor.org/rfc/rfc4034)
- [RFC 4035 — Protocol Modifications for DNSSEC](https://www.rfc-editor.org/rfc/rfc4035)

## Transporte y privacidad

- [RFC 7766 — DNS Transport over TCP](https://www.rfc-editor.org/rfc/rfc7766)
- [RFC 7858 — DNS over TLS](https://www.rfc-editor.org/rfc/rfc7858)
- [RFC 8484 — DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc8484)
- [RFC 6891 — EDNS](https://www.rfc-editor.org/rfc/rfc6891)

## Administración y herramientas

- [IANA DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
- [ICANN](https://www.icann.org/)
- [BIND 9 Documentation](https://bind9.readthedocs.io/)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
