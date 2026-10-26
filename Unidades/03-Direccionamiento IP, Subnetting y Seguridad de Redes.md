
# Unidad 3 — Direccionamiento IP, Subnetting y Seguridad de Redes

> **Área:** Ciberseguridad y redes informáticas  
> **Nivel:** Fundamentos e intermedio  
> **Objetivo:** Comprender el direccionamiento IPv4, calcular y diseñar subredes, analizar tráfico de red y estudiar el funcionamiento de firewalls, NAT y VPN.

---

# Índice

1. [Fundamentos del direccionamiento IP](#1-fundamentos-del-direccionamiento-ip)
2. [Estructura y representación de IPv4](#2-estructura-y-representación-de-ipv4)
3. [Tipos de direcciones IPv4](#3-tipos-de-direcciones-ipv4)
4. [Clases de direcciones IP](#4-clases-de-direcciones-ip)
5. [Máscaras de subred y CIDR](#5-máscaras-de-subred-y-cidr)
6. [Subnetting desde cero](#6-subnetting-desde-cero)
7. [Cálculo de subredes paso a paso](#7-cálculo-de-subredes-paso-a-paso)
8. [VLSM y diseño de redes](#8-vlsm-y-diseño-de-redes)
9. [Comunicación entre equipos y puertos](#9-comunicación-entre-equipos-y-puertos)
10. [Enrutamiento y tablas de rutas](#10-enrutamiento-y-tablas-de-rutas)
11. [NAT y PAT](#11-nat-y-pat)
12. [Firewalls y filtrado de tráfico](#12-firewalls-y-filtrado-de-tráfico)
13. [VPN y túneles seguros](#13-vpn-y-túneles-seguros)
14. [Análisis de tráfico de red](#14-análisis-de-tráfico-de-red)
15. [Wireshark y captura de paquetes](#15-wireshark-y-captura-de-paquetes)
16. [Seguridad del direccionamiento y segmentación](#16-seguridad-del-direccionamiento-y-segmentación)
18. [Errores frecuentes y resolución de problemas](#17-errores-frecuentes-y-resolución-de-problemas)
19. [Glosario](#19-glosario)
19. [Referencias técnicas](#20-referencias-técnicas)

---

# 1. Fundamentos del direccionamiento IP

## 1.1. ¿Qué es una dirección IP?

Una dirección IP es una dirección lógica asignada a una interfaz de red para permitir la comunicación mediante el protocolo Internet Protocol.

Su función es permitir que los sistemas identifiquen direcciones de origen y destino y que los routers puedan encaminar paquetes entre redes.

Ejemplo:

```text
192.168.1.10
```

Una dirección IP no identifica necesariamente de manera permanente a una computadora.

Un dispositivo puede:

- Tener varias direcciones IP.
- Cambiar de dirección.
- Utilizar IPv4 e IPv6 simultáneamente.
- Compartir una dirección pública mediante NAT.
- Tener diferentes interfaces de red.

## 1.2. Dirección IP frente a dirección MAC

| Característica | IP | MAC |
|---|---|---|
| Tipo | Dirección lógica | Dirección de enlace |
| Capa OSI habitual | 3 | 2 |
| Función | Encaminamiento entre redes | Entrega dentro de enlaces compatibles |
| Formato | IPv4 o IPv6 | Generalmente 48 bits en Ethernet |
| Cambio | Puede cambiar según configuración | Puede asignarse o modificarse |
| Alcance | Interredes | Enlace local |

### Ejemplo

Una computadora quiere enviar información a un servidor remoto.

La dirección IP identifica el destino lógico.

La dirección MAC identifica el siguiente destino dentro del enlace Ethernet local.

Cuando un paquete atraviesa routers, las direcciones MAC de las tramas cambian de un enlace a otro.

Las direcciones IP de origen y destino normalmente permanecen iguales durante el trayecto, salvo mecanismos como NAT.

## 1.3. ¿Qué es una interfaz de red?

Una interfaz de red es un punto de conexión mediante el cual un sistema puede comunicarse.

Puede ser:

- Ethernet.
- Wi-Fi.
- Virtual.
- De túnel VPN.
- Loopback.

Una misma computadora puede tener varias interfaces y varias direcciones IP.

---

# 2. Estructura y representación de IPv4

## 2.1. ¿Qué es IPv4?

IPv4 significa Internet Protocol version 4.

Utiliza direcciones de 32 bits.

Una dirección IPv4 se representa habitualmente mediante cuatro octetos decimales separados por puntos.

Ejemplo:

```text
192.168.1.10
```

Cada octeto contiene 8 bits.

Por lo tanto:

```text
8 + 8 + 8 + 8 = 32 bits
```

## 2.2. Conversión decimal a binario

Cada posición de un octeto tiene un valor.

| Posición | Valor |
|---|---|
| 1 | 128 |
| 2 | 64 |
| 3 | 32 |
| 4 | 16 |
| 5 | 8 |
| 6 | 4 |
| 7 | 2 |
| 8 | 1 |

### Ejemplo: convertir 192 a binario

Descomponemos 192:

```text
192 = 128 + 64
```

Por lo tanto:

```text
128 64 32 16 8 4 2 1
 1   1  0  0 0 0 0 0
```

Resultado:

```text
192 = 11000000
```

### Ejemplo: convertir 168

```text
168 = 128 + 32 + 8
```

Resultado:

```text
168 = 10101000
```

### Dirección completa

```text
192.168.1.10
```

En binario:

```text
11000000.10101000.00000001.00001010
```

## 2.3. Conversión binaria a decimal

Ejemplo:

```text
11000000
```

Sumamos las posiciones con valor 1:

```text
128 + 64 = 192
```

Otro ejemplo:

```text
11111100
```

```text
128 + 64 + 32 + 16 + 8 + 4 = 252
```

Por lo tanto:

```text
11111100 = 252
```

## 2.4. Cantidad total de direcciones IPv4

IPv4 utiliza 32 bits.

Cada bit puede representar dos valores.

Por lo tanto:

```text
2^32 = 4.294.967.296
```

Existen aproximadamente 4.290 millones de combinaciones IPv4.

No todas pueden asignarse libremente como direcciones públicas unicast.

Existen bloques reservados, privados, especiales y otros usos definidos por estándares.

---

# 3. Tipos de direcciones IPv4

## 3.1. Direcciones públicas

Una dirección IPv4 pública globalmente enrutable permite identificar un destino dentro del espacio de direccionamiento utilizado en Internet.

Ejemplo de dirección reservada para documentación:

```text
203.0.113.10
```

**Importante:** `203.0.113.0/24` es un bloque reservado para ejemplos, no una red pública utilizable normalmente en Internet.

Las direcciones públicas pueden ser:

- Estáticas.
- Dinámicas.
- Asignadas a interfaces.
- Compartidas mediante determinados mecanismos de traducción.

Una dirección pública no implica necesariamente que un dispositivo sea accesible desde cualquier lugar.

La conectividad depende de rutas, firewalls y otros controles.

## 3.2. Direcciones privadas

RFC 1917 define tres bloques privados.

| Bloque | Prefijo | Cantidad de direcciones |
|---|---|---|
| 10.0.0.0 | /8 | 16.777.216 |
| 172.16.0.0 | /12 | 1.048.576 |
| 192.168.0.0 | /16 | 65.536 |

Estos bloques pueden utilizarse en redes privadas.

No se enrutan directamente como destinos globales en Internet pública.

### Ejemplo

```text
Computadora: 192.168.1.10
Router:      192.168.1.1
Servidor:    192.168.1.20
```

Los tres dispositivos pueden comunicarse dentro de una red local si la configuración y los controles lo permiten.

## 3.3. Loopback

El bloque:

```text
127.0.0.0/8
```

está reservado para loopback.

La dirección más conocida es:

```text
127.0.0.1
```

Representa el propio sistema en el contexto de comunicación local.

Ejemplo:

```bash
ping 127.0.0.1
```

Sirve para comprobar determinados componentes de la pila TCP/IP local.

No demuestra que una interfaz física ni Internet funcionen.

## 3.4. Link-local IPv4

El bloque:

```text
169.254.0.0/16
```

se utiliza para direccionamiento link-local IPv4.

Puede aparecer cuando un sistema no obtiene una configuración IPv4 mediante DHCP y utiliza autoconfiguración.

Estas direcciones no están diseñadas para enrutamiento entre redes.

## 3.5. Dirección de red

Identifica el prefijo de una subred.

Ejemplo:

```text
192.168.1.0/24
```

En una subred IPv4 convencional, la dirección con todos los bits de host en cero representa la dirección de red.

## 3.6. Dirección de broadcast

En IPv4, el broadcast dirigido de una subred convencional corresponde a la dirección con todos los bits de host en uno.

Ejemplo:

```text
192.168.1.255
```

para:

```text
192.168.1.0/24
```

El broadcast permite dirigir información a los participantes del dominio correspondiente, según la tecnología y las políticas de red.

IPv6 no utiliza broadcast IP.

## 3.7. Multicast

El bloque IPv4 multicast es:

```text
224.0.0.0/4
```

Permite dirigir paquetes a grupos de receptores.

No funciona igual que unicast ni broadcast.

## 3.8. Direcciones especiales

| Bloque | Uso |
|---|---|
| 0.0.0.0/8 | Direccionamiento especial |
| 10.0.0.0/8 | Privado |
| 100.64.0.0/10 | Espacio compartido, frecuente en CGNAT |
| 127.0.0.0/8 | Loopback |
| 169.254.0.0/16 | Link-local |
| 172.16.0.0/12 | Privado |
| 192.0.2.0/24 | Documentación |
| 192.168.0.0/16 | Privado |
| 198.51.100.0/24 | Documentación |
| 203.0.113.0/24 | Documentación |
| 224.0.0.0/4 | Multicast |
| 240.0.0.0/4 | Reservado y usos especiales |

El significado preciso de ciertos bloques especiales depende de los registros vigentes de IANA.

---

# 4. Clases de direcciones IP

## 4.1. Direccionamiento classful

Históricamente, IPv4 utilizó un sistema de clases.

Las clases principales fueron:

- A.
- B.
- C.
- D.
- E.

Actualmente, el direccionamiento moderno utiliza CIDR y prefijos explícitos.

Las clases siguen siendo importantes para comprender documentación histórica y conceptos básicos.

## 4.2. Clase A

Primer octeto:

```text
1 - 126
```

Máscara histórica:

```text
255.0.0.0
```

Prefijo:

```text
/8
```

Ejemplo:

```text
10.0.0.0
```

El bloque `10.0.0.0/8` también es privado.

## 4.3. Clase B

Primer octeto:

```text
128 - 191
```

Máscara histórica:

```text
255.255.0.0
```

Prefijo:

```text
/16
```

## 4.4. Clase C

Primer octeto:

```text
192 - 223
```

Máscara histórica:

```text
255.255.255.0
```

Prefijo:

```text
/24
```

## 4.5. Clase D

Primer octeto:

```text
224 - 239
```

Utilizado para multicast IPv4.

## 4.6. Clase E

Primer octeto:

```text
240 - 255
```

Reservado para usos especiales y experimentales.

## 4.7. Tabla comparativa

| Clase | Primer octeto | Máscara histórica | Uso histórico |
|---|---|---|---|
| A | 1–126 | /8 | Redes grandes |
| B | 128–191 | /16 | Redes medianas |
| C | 192–223 | /24 | Redes pequeñas |
| D | 224–239 | No aplica | Multicast |
| E | 240–255 | No aplica | Reservado |

Los valores 0 y 127 tienen usos especiales y no forman parte de los rangos habituales de asignación de redes clase A.

**Advertencia técnica:** hoy no debe determinarse la máscara de una red solamente a partir del primer octeto.

---

# 5. Máscaras de subred y CIDR

## 5.1. ¿Qué es una máscara?

Una máscara de subred permite determinar qué bits de una dirección IPv4 pertenecen al prefijo de red.

Ejemplo:

```text
IP:       192.168.1.25
Máscara:  255.255.255.0
```

La máscara en binario es:

```text
11111111.11111111.11111111.00000000
```

Los primeros 24 bits pertenecen al prefijo.

Los últimos 8 bits corresponden al identificador de host dentro de esa subred.

## 5.2. ¿Qué es CIDR?

CIDR significa Classless Inter-Domain Routing.

Permite representar prefijos sin depender de las clases históricas.

Ejemplo:

```text
192.168.1.0/24
```

El `/24` indica que los primeros 24 bits forman el prefijo.

## 5.3. Tabla de máscaras

| CIDR | Máscara | Direcciones |
|---|---|---|
| /16 | 255.255.0.0 | 65.536 |
| /17 | 255.255.128.0 | 32.768 |
| /17 | 255.255.192.0 | 16.384 |
| /19 | 255.255.224.0 | 8.192 |
| /20 | 255.255.240.0 | 4.096 |
| /21 | 255.255.248.0 | 2.048 |
| /22 | 255.255.252.0 | 1.024 |
| /23 | 255.255.254.0 | 512 |
| /24 | 255.255.255.0 | 256 |
| /25 | 255.255.255.128 | 128 |
| /26 | 255.255.255.192 | 64 |
| /27 | 255.255.255.224 | 32 |
| /28 | 255.255.255.240 | 16 |
| /29 | 255.255.255.248 | 8 |
| /30 | 255.255.255.252 | 4 |
| /31 | 255.255.255.254 | 2 |
| /32 | 255.255.255.255 | 1 |

## 5.4. Cálculo de direcciones

La fórmula es:

```text
Cantidad de direcciones = 2^(32 - prefijo)
```

Ejemplo para `/26`:

```text
32 - 26 = 6
```

```text
2^6 = 64
```

La subred contiene 64 direcciones.

En una subred convencional con dirección de red y broadcast:

```text
Hosts utilizables = 64 - 2 = 62
```

### Excepciones

- `/31` puede utilizar dos direcciones en enlaces punto a punto conforme a RFC 3021.
- `/32` identifica una única dirección.
- No debe aplicarse automáticamente la resta de dos direcciones a todos los casos.

---

# 6. Subnetting desde cero

## 6.1. ¿Qué es subnetting?

Subnetting es el proceso de dividir un bloque de direcciones IP en subredes más pequeñas.

Permite:

- Organizar redes.
- Administrar direcciones.
- Reducir dominios de broadcast IPv4.
- Facilitar segmentación.
- Aplicar políticas.
- Separar departamentos o servicios.

## 6.2. Ejemplo

Una organización dispone de:

```text
192.168.10.0/24
```

Tiene 256 direcciones.

Necesita cuatro subredes del mismo tamaño.

## 6.3. Pedir bits prestados

Un `/24` tiene 8 bits de host.

Para obtener cuatro subredes:

```text
2^2 = 4
```

Necesitamos utilizar 2 bits adicionales para el prefijo.

```text
24 + 2 = 26
```

Nueva máscara:

```text
255.255.255.192
```

Nuevo prefijo:

```text
/26
```

## 6.4. Tamaño de cada subred

```text
2^(32 - 26) = 64
```

Cada subred contiene 64 direcciones.

## 6.5. Resultado

| Subred | Red | Primer host | Último host | Broadcast |
|---|---|---|---|---|
| 1 | 192.168.10.0/26 | .1 | .62 | .63 |
| 2 | 192.168.10.64/26 | .65 | .126 | .127 |
| 3 | 192.168.10.128/26 | .129 | .190 | .191 |
| 4 | 192.168.10.192/26 | .193 | .254 | .255 |

Cada subred convencional permite 62 direcciones de host utilizables.

---

# 7. Cálculo de subredes paso a paso

## 7.1. Método del tamaño de bloque

Para calcular rápidamente subredes IPv4 se puede utilizar el tamaño del bloque en el octeto donde cambia la máscara.

Ejemplo:

```text
192.168.1.0/27
```

Máscara:

```text
255.255.255.224
```

Calculamos:

```text
256 - 224 = 32
```

El incremento es 32.

Las redes comienzan en:

```text
192.168.1.0
192.168.1.32
192.168.1.64
192.168.1.96
192.168.1.128
192.168.1.160
192.168.1.192
192.168.1.224
```

## 7.2. Ejemplo completo

Determinar la subred de:

```text
192.168.1.77/27
```

### Paso 1

Identificar la máscara:

```text
255.255.255.224
```

### Paso 2

Calcular el incremento:

```text
256 - 224 = 32
```

### Paso 3

Identificar el intervalo:

```text
64 - 95
```

La dirección 77 está dentro de ese intervalo.

### Paso 4

Determinar los resultados:

```text
Red:           192.168.1.64
Primer host:   192.168.1.65
Último host:   192.168.1.94
Broadcast:     192.168.1.95
```

### Paso 5

Cantidad de direcciones:

```text
2^(32 - 27) = 32
```

Hosts convencionales:

```text
32 - 2 = 30
```

## 7.3. Ejemplo con /20

Dirección:

```text
172.16.35.120/20
```

Máscara:

```text
255.255.240.0
```

Incremento en el tercer octeto:

```text
256 - 240 = 16
```

Intervalos:

```text
0 - 15
16 - 31
32 - 47
48 - 63
...
```

El tercer octeto 35 pertenece al intervalo 32–47.

Resultado:

```text
Red:           172.16.32.0
Broadcast:     172.16.47.255
Primer host:   172.16.32.1
Último host:   172.16.47.254
```

Cantidad total:

```text
2^(32 - 20) = 4096
```

Hosts convencionales:

```text
4094
```

## 7.4. Operación AND

La dirección de red también puede calcularse mediante AND bit a bit.

Regla:

| Bit IP | Bit máscara | Resultado |
|---|---|---|
| 0 | 0 | 0 |
| 0 | 1 | 0 |
| 1 | 0 | 0 |
| 1 | 1 | 1 |

Ejemplo:

```text
IP:
192.168.1.77

Máscara:
255.255.255.224
```

Último octeto:

```text
77  = 01001101
224 = 11100000
--------------
64  = 01000000
```

Por lo tanto:

```text
Red = 192.168.1.64
```

---

# 8. VLSM y diseño de redes

## 8.1. ¿Qué es VLSM?

VLSM significa Variable Length Subnet Mask.

Permite utilizar máscaras de diferentes longitudes dentro de un bloque de direcciones.

Es útil cuando distintas subredes necesitan cantidades diferentes de direcciones.

## 8.2. Ejemplo de organización

Una empresa dispone de:

```text
192.168.50.0/24
```

Necesita:

- Administración: 100 hosts.
- Desarrollo: 50 hosts.
- Soporte: 20 hosts.
- Laboratorio: 10 hosts.

## 8.3. Ordenar necesidades

Se comienza por la subred más grande.

| Sector | Hosts requeridos | Prefijo |
|---|---|---|
| Administración | 100 | /25 |
| Desarrollo | 50 | /26 |
| Soporte | 20 | /27 |
| Laboratorio | 10 | /28 |

## 8.4. Asignación

### Administración

```text
192.168.50.0/25
```

128 direcciones.

126 hosts convencionales.

### Desarrollo

```text
192.168.50.128/26
```

64 direcciones.

62 hosts convencionales.

### Soporte

```text
192.168.50.192/27
```

32 direcciones.

30 hosts convencionales.

### Laboratorio

```text
192.168.50.224/28
```

16 direcciones.

14 hosts convencionales.

## 8.5. Resultado

| Sector | Red | Rango utilizable | Broadcast |
|---|---|---|---|
| Administración | 192.168.50.0/25 | .1–.126 | .127 |
| Desarrollo | 192.168.50.128/26 | .129–.190 | .191 |
| Soporte | 192.168.50.192/27 | .193–.222 | .223 |
| Laboratorio | 192.168.50.224/28 | .225–.238 | .239 |

Queda disponible:

```text
192.168.50.240/28
```

para una asignación posterior.

## 8.6. Buenas prácticas

Al diseñar subredes:

1. Registrar necesidades actuales.
2. Prever crecimiento.
3. Evitar superposiciones.
4. Reservar direcciones de infraestructura.
5. Documentar gateways.
6. Definir políticas de comunicación.
7. Separar redes según requisitos de seguridad.
8. Mantener un inventario de direcciones.

---

# 9. Comunicación entre equipos y puertos

## 9.1. Comunicación en la misma subred

Ejemplo:

```text
Equipo A:
192.168.1.10/24

Equipo B:
192.168.1.20/24
```

Ambos pertenecen a:

```text
192.168.1.0/24
```

Si utilizan Ethernet:

1. A determina que B está dentro de su red local.
2. A consulta su información de vecinos.
3. Si es necesario, utiliza ARP.
4. Obtiene la dirección MAC de B.
5. Construye una trama.
6. Envía el paquete IP dentro de la trama.
7. B recibe y procesa la información.

La comunicación puede estar limitada por firewalls o políticas de seguridad.

## 9.2. Comunicación entre subredes

Ejemplo:

```text
Equipo A:
192.168.1.10/24

Equipo B:
192.168.2.20/24
```

Pertenecen a redes diferentes.

Para comunicarse necesitan conectividad de capa 3, normalmente mediante un router o switch con funciones de enrutamiento.

```text
Equipo A
192.168.1.10
     |
     v
Router
     |
     v
Equipo B
192.168.2.20
```

## 9.3. ¿Qué es un puerto?

Un puerto TCP o UDP es un identificador de 16 bits utilizado para distinguir extremos de comunicación.

Rango:

```text
0 - 65535
```

Ejemplo:

```text
192.168.1.10:53000
```

El número después de los dos puntos representa el puerto.

## 9.4. Socket

Un socket es una interfaz de comunicación proporcionada por el sistema operativo.

Una conexión TCP puede identificarse mediante:

```text
IP origen
Puerto origen
IP destino
Puerto destino
Protocolo
```

## 9.5. Ejemplo de comunicación HTTPS

```text
Cliente:
192.168.1.10:53000

Servidor:
203.0.113.20:443

Protocolo:
TCP
```

El cliente utiliza un puerto de origen temporal.

El servidor escucha habitualmente en el puerto 443 para HTTPS sobre TCP.

El ejemplo utiliza una dirección de documentación.

## 9.6. Puertos frecuentes

| Puerto | Servicio |
|---|---|
| 21/TCP | FTP |
| 22/TCP | SSH |
| 23/TCP | Telnet |
| 25/TCP | SMTP |
| 53/TCP y UDP | DNS |
| 80/TCP | HTTP |
| 110/TCP | POP3 |
| 123/UDP | NTP |
| 143/TCP | IMAP |
| 161/UDP | SNMP |
| 443/TCP | HTTPS |
| 443/UDP | HTTP/3 |
| 445/TCP | SMB |
| 3389/TCP y UDP | RDP |
| 5432/TCP | PostgreSQL |

Un puerto no determina obligatoriamente qué servicio se está ejecutando.

---

# 10. Enrutamiento y tablas de rutas

## 10.1. ¿Qué es un router?

Un router es un dispositivo o sistema que reenvía paquetes entre redes IP.

Utiliza información de enrutamiento para determinar el siguiente salto.

## 10.2. Tabla de enrutamiento

Ejemplo conceptual:

```text
Destino          Siguiente salto
192.168.1.0/24   Conectado
10.0.0.0/8       192.168.1.254
0.0.0.0/0        192.168.1.1
```

## 10.3. Ruta predeterminada

La ruta:

```text
0.0.0.0/0
```

representa la ruta predeterminada IPv4.

Se utiliza cuando no existe una ruta más específica.

## 10.4. Longest Prefix Match

Si varias rutas coinciden con un destino, normalmente se selecciona la ruta con el prefijo más específico.

Ejemplo:

```text
10.0.0.0/8
10.20.0.0/16
10.20.30.0/24
```

Para:

```text
10.20.30.15
```

la ruta `/24` es la más específica.

## 10.5. Enrutamiento estático

Las rutas se configuran manualmente.

Ventajas:

- Simplicidad en redes pequeñas.
- Control explícito.

Limitaciones:

- Requiere mantenimiento.
- No se adapta automáticamente a todos los cambios.

## 10.6. Enrutamiento dinámico

Utiliza protocolos para intercambiar información de rutas.

Ejemplos:

- OSPF.
- IS-IS.
- BGP.
- RIP.

### OSPF

Es un protocolo de estado de enlace utilizado dentro de sistemas autónomos.

### BGP

Se utiliza ampliamente para intercambiar información de alcanzabilidad entre sistemas autónomos en Internet.

## 10.7. TTL

En IPv4, TTL limita la cantidad de saltos que puede atravesar un paquete.

Cada router que lo reenvía reduce su valor.

Si llega a cero, el paquete se descarta.

Esto ayuda a evitar circulación indefinida por bucles.

---

# 11. NAT y PAT

## 11.1. ¿Qué es NAT?

NAT significa Network Address Translation.

Es un mecanismo que modifica información de direccionamiento IP durante el tránsito de paquetes.

Se utiliza frecuentemente para permitir que dispositivos con direcciones privadas accedan a servicios externos mediante direcciones públicas.

## 11.2. ¿Por qué existe NAT?

Uno de sus usos más frecuentes en IPv4 es reducir la necesidad de disponer de una dirección pública diferente para cada dispositivo interno.

## 11.3. Ejemplo

Red interna:

```text
PC1: 192.168.1.10
PC2: 192.168.1.20
PC3: 192.168.1.30
```

Router con dirección pública de ejemplo:

```text
198.51.100.10
```

```text
PC1 ----\
PC2 ----- Router NAT ---- Internet
PC3 ----/
```

Los dispositivos pueden compartir la dirección externa mediante traducción de direcciones y puertos.

## 11.4. SNAT

Source NAT modifica la dirección de origen de un paquete.

Ejemplo:

Antes:

```text
Origen: 192.168.1.10
Destino: 203.0.113.20
```

Después de una traducción de origen:

```text
Origen: 198.51.100.10
Destino: 203.0.113.20
```

## 11.5. DNAT

Destination NAT modifica la dirección de destino.

Puede utilizarse para redirigir tráfico hacia un servidor interno.

Ejemplo:

```text
Destino externo:
198.51.100.10:443
```

Traducción:

```text
Destino interno:
192.168.1.100:443
```

## 11.6. PAT

PAT significa Port Address Translation.

También se denomina frecuentemente NAPT.

Permite distinguir múltiples comunicaciones mediante traducciones de puertos.

Ejemplo:

| Equipo interno | Puerto interno | Dirección externa | Puerto externo |
|---|---|---|---|
| 192.168.1.10 | 51000 | 198.51.100.10 | 40001 |
| 192.168.1.20 | 51000 | 198.51.100.10 | 40002 |
| 192.168.1.30 | 51000 | 198.51.100.10 | 40003 |

El router mantiene información que permite asociar las respuestas con las comunicaciones correspondientes.

## 11.7. Tabla NAT

Ejemplo conceptual:

```text
Interno                    Externo traducido
192.168.1.10:51000  <-->  198.51.100.10:40001
192.168.1.20:51000  <-->  198.51.100.10:40002
```

Las traducciones reales dependen del protocolo y de la implementación.

## 11.8. NAT estático

Establece una traducción fija.

Puede utilizarse para publicar determinados servicios o mapear direcciones.

## 11.9. NAT dinámico

Utiliza un conjunto de direcciones disponibles para crear traducciones según la configuración.

## 11.10. CGNAT

CGNAT significa Carrier-Grade NAT.

Permite que un proveedor comparta direcciones IPv4 públicas entre múltiples clientes.

Puede complicar las conexiones entrantes porque el usuario no controla necesariamente las traducciones del proveedor.

## 11.11. NAT y seguridad

NAT no es equivalente a un firewall.

Aunque ciertas configuraciones dificultan conexiones entrantes no solicitadas, NAT por sí solo no sustituye una política de seguridad.

## 11.12. Limitaciones

NAT puede introducir complejidad en:

- Aplicaciones que requieren conexiones entrantes.
- Protocolos que transportan direcciones IP.
- Comunicación entre pares.
- Diagnóstico.
- Trazabilidad.
- Determinados túneles.

---

# 12. Firewalls y filtrado de tráfico

## 12.1. ¿Qué es un firewall?

Un firewall es un mecanismo de seguridad que permite controlar tráfico de red según políticas definidas.

Puede implementarse mediante:

- Software.
- Hardware.
- Sistemas virtualizados.
- Servicios de seguridad administrados.

## 12.2. ¿Qué puede examinar?

Dependiendo de su tecnología, un firewall puede utilizar:

- IP de origen.
- IP de destino.
- Puerto de origen.
- Puerto de destino.
- Protocolo.
- Estado de conexión.
- Interfaz.
- Aplicación.
- Identidad.
- Información adicional del tráfico.

## 12.3. Firewall stateless

Un firewall sin estado evalúa paquetes mediante reglas sin mantener necesariamente el estado completo de las conexiones.

Ejemplo conceptual:

```text
Permitir TCP destino 443
Bloquear TCP destino 23
```

## 12.4. Firewall stateful

Un firewall con estado mantiene información sobre conexiones o flujos.

Esto permite distinguir tráfico asociado a comunicaciones existentes.

### Ejemplo

1. Un cliente inicia una conexión TCP permitida.
2. El firewall registra información del flujo.
3. El servidor responde.
4. El firewall reconoce la respuesta como parte de la comunicación.

## 12.5. NGFW

Next-Generation Firewall es una categoría comercial y técnica de firewalls con funciones avanzadas.

Puede incluir:

- Identificación de aplicaciones.
- Inspección de tráfico.
- Prevención de intrusiones.
- Integración con identidades.
- Control de amenazas.

Las funciones concretas varían según el producto.

## 12.6. WAF

Web Application Firewall.

Está diseñado para inspeccionar y controlar tráfico relacionado con aplicaciones web.

Puede ayudar a detectar o bloquear determinados ataques HTTP.

No reemplaza el desarrollo seguro de aplicaciones.

## 12.7. Reglas de firewall

Una regla puede contener:

```text
Origen
Destino
Protocolo
Puerto
Acción
```

Ejemplo:

| Origen | Destino | Puerto | Acción |
|---|---|---|---|
| Red interna | Servidor web | TCP 443 | Permitir |
| Red de invitados | Red administrativa | Cualquiera | Bloquear |
| Equipo de administración | Servidor SSH | TCP 22 | Permitir |

## 12.8. Default Deny

Es una política que bloquea el tráfico que no esté explícitamente permitido.

Debe diseñarse considerando los servicios necesarios para evitar interrupciones.

## 12.9. Orden de reglas

Muchos firewalls procesan reglas según un orden definido.

Por eso, una regla demasiado amplia puede hacer que otras reglas nunca se apliquen.

El comportamiento exacto depende de la implementación.

## 12.10. Ejemplo con UFW

En una máquina Linux propia, con UFW instalado:

```bash
sudo ufw status verbose
```

Muestra el estado y las reglas relevantes.

Ejemplo de permitir HTTPS:

```bash
sudo ufw allow 443/tcp
```

Ejemplo de permitir SSH:

```bash
sudo ufw allow 22/tcp
```

**Precaución:** modificar reglas de firewall en un servidor remoto puede interrumpir el acceso administrativo. Es necesario revisar las reglas existentes antes de aplicar cambios.

## 12.11. Firewalls y segmentación

Un firewall puede controlar tráfico entre:

- Redes de usuarios.
- Servidores.
- Invitados.
- Entornos de desarrollo.
- Sistemas críticos.
- Redes externas.

Esto permite aplicar el principio de mínimo privilegio a las comunicaciones.

---

# 13. VPN y túneles seguros

## 13.1. ¿Qué es una VPN?

VPN significa Virtual Private Network.

Es una tecnología que permite establecer conectividad lógica a través de una infraestructura de red subyacente.

Muchas VPN incorporan cifrado y autenticación para proteger comunicaciones.

## 13.2. ¿Qué es un túnel?

Un túnel permite transportar paquetes de un protocolo dentro de otro mecanismo de comunicación.

Ejemplo conceptual:

```text
Paquete original
      |
      v
Encapsulamiento del túnel
      |
      v
Transporte por la red
      |
      v
Desencapsulamiento
      |
      v
Paquete original
```

No todos los túneles proporcionan cifrado.

## 13.3. VPN de acceso remoto

Permite conectar un dispositivo remoto con una red o servicio.

Ejemplo:

```text
Computadora remota
        |
        v
   Internet
        |
        v
 Gateway VPN
        |
        v
  Red corporativa
```

## 13.4. VPN Site-to-Site

Permite conectar redes ubicadas en diferentes lugares.

```text
Oficina A
    |
Gateway VPN
    |
 Internet
    |
Gateway VPN
    |
Oficina B
```

## 13.5. IPsec

IPsec es un conjunto de protocolos y mecanismos utilizados para proteger comunicaciones IP.

Puede proporcionar:

- Autenticación.
- Integridad.
- Confidencialidad.
- Protección contra repetición.

## 13.6. AH y ESP

### AH

Authentication Header proporciona mecanismos de autenticación e integridad, sin cifrar la carga útil.

### ESP

Encapsulating Security Payload puede proporcionar cifrado, integridad y autenticación según los algoritmos y configuraciones utilizados.

ESP es muy utilizado en VPN IPsec.

## 13.7. Modos IPsec

### Modo transporte

Protege principalmente la carga útil del paquete IP, según la configuración.

### Modo túnel

Encapsula un paquete IP dentro de otro, permitiendo proteger comunicaciones entre redes o extremos.

## 13.8. IKE

Internet Key Exchange permite negociar asociaciones de seguridad y establecer material criptográfico para IPsec.

IKEv2 es una versión moderna ampliamente utilizada.

## 13.9. OpenVPN

OpenVPN es una tecnología VPN que utiliza TLS y otros mecanismos criptográficos.

Puede funcionar sobre UDP o TCP.

Su seguridad depende de la versión, algoritmos y configuración.

## 13.10. WireGuard

WireGuard es una tecnología VPN moderna diseñada para utilizar una arquitectura criptográfica relativamente simple.

Utiliza UDP y mecanismos criptográficos definidos por su diseño.

## 13.11. Split tunneling

Permite que solamente determinado tráfico utilice la VPN.

El resto puede salir directamente por la conexión habitual.

### Ventaja

Reduce tráfico innecesario por el túnel.

### Riesgo

Puede ampliar las rutas de comunicación fuera de los controles centralizados, según el entorno.

## 13.12. Full tunneling

Dirige el tráfico definido por la política, frecuentemente la ruta predeterminada, a través de la VPN.

No garantiza automáticamente anonimato ni protección frente a todos los riesgos.

## 13.13. ¿Una VPN proporciona anonimato?

No necesariamente.

Una VPN puede ocultar determinadas características de la conexión frente a ciertos observadores, pero:

- El proveedor VPN puede observar metadatos.
- Los sitios pueden identificar usuarios mediante cuentas.
- Existen cookies y técnicas de seguimiento.
- Los extremos pueden estar comprometidos.
- Puede existir filtración de tráfico fuera del túnel.

Una VPN no reemplaza otras medidas de seguridad.

---

# 14. Análisis de tráfico de red

## 14.1. ¿Qué es analizar tráfico?

El análisis de tráfico consiste en observar y estudiar comunicaciones para comprender su funcionamiento o identificar problemas.

Puede utilizarse para:

- Diagnóstico.
- Monitoreo.
- Rendimiento.
- Seguridad.
- Investigación de incidentes.
- Aprendizaje de protocolos.

## 14.2. Paquetes y metadatos

Un paquete puede contener:

- Direcciones.
- Puertos.
- Indicadores.
- Información de control.
- Carga útil.

El análisis puede enfocarse en:

- Quién se comunica.
- Con quién.
- Mediante qué protocolo.
- Cuándo.
- Durante cuánto tiempo.
- Con qué volumen de datos.

## 14.3. Captura de paquetes

Una captura registra unidades de tráfico observadas en una interfaz o punto de monitoreo.

Formatos habituales:

- PCAP.
- PCAPNG.

## 14.4. ¿Se puede ver todo el tráfico?

No necesariamente.

La visibilidad depende de:

- Ubicación de captura.
- Topología.
- Switches.
- VLAN.
- Interfaces.
- Permisos.
- Cifrado.
- Mecanismos de monitoreo.

Una computadora conectada a un switch no recibe automáticamente todo el tráfico unicast de los demás equipos.

## 14.5. Tráfico cifrado

Cuando una comunicación utiliza TLS, normalmente es posible observar ciertos metadatos, pero no el contenido de aplicación en texto plano.

Los detalles visibles dependen del protocolo y de sus mecanismos de protección.

## 14.6. Indicadores de comportamiento anómalo

Ejemplos que pueden justificar investigación:

- Volumen inusual de conexiones.
- Numerosos intentos fallidos.
- Tráfico hacia destinos inesperados.
- Transferencias anormalmente grandes.
- Patrones DNS poco habituales.
- Conexiones persistentes no reconocidas.

Ningún indicador aislado demuestra automáticamente un ataque.

Se necesita contexto.

---

# 15. Wireshark y captura de paquetes

## 15.1. ¿Qué es Wireshark?

Wireshark es una herramienta de análisis de protocolos.

Permite capturar y examinar tráfico de red.

## 15.2. Componentes de la interfaz

Generalmente presenta:

1. Lista de paquetes.
2. Detalles del paquete seleccionado.
3. Representación de bytes.
4. Filtros.
5. Información de protocolos.

## 15.3. Filtros de visualización

### IPv4

```text
ip
```

### TCP

```text
tcp
```

### UDP

```text
udp
```

### DNS

```text
dns
```

### ICMP

```text
icmp
```

### ARP

```text
arp
```

### Dirección IP

```text
ip.addr == 192.168.1.10
```

### Origen

```text
ip.src == 192.168.1.10
```

### Destino

```text
ip.dst == 192.168.1.20
```

### Puerto TCP

```text
tcp.port == 443
```

### Puerto UDP

```text
udp.port == 53
```

## 15.4. Filtros combinados

Ejemplo:

```text
ip.addr == 192.168.1.10 && tcp.port == 443
```

Muestra paquetes IPv4 asociados con esa dirección y el puerto TCP 443.

## 15.5. Identificar el handshake TCP

Filtro:

```text
tcp.flags.syn == 1
```

Para estudiar una conexión, identificar:

1. SYN.
2. SYN-ACK.
3. ACK.
4. Intercambio de datos.
5. Finalización.

El filtro SYN también puede mostrar otros segmentos con SYN activo, por lo que debe interpretarse con los demás campos.

## 15.6. Analizar retransmisiones

Filtro de visualización:

```text
tcp.analysis.retransmission
```

Wireshark puede identificar posibles retransmisiones mediante análisis heurístico.

No todas las retransmisiones observadas indican necesariamente un problema grave.

## 15.7. Analizar DNS

Filtro:

```text
dns
```

Campos relevantes:

- Identificador de transacción.
- Tipo de consulta.
- Nombre consultado.
- Código de respuesta.
- Registros devueltos.

## 15.8. Seguir un flujo TCP

Wireshark permite seleccionar una conversación TCP y utilizar la función Follow TCP Stream.

Esto facilita analizar el intercambio de datos visibles.

En tráfico cifrado, el contenido de aplicación no aparece automáticamente descifrado.

## 15.9. Filtros de captura y visualización

No son lo mismo.

### Filtro de captura

Determina qué paquetes se registran.

Ejemplo BPF:

```text
tcp port 443
```

### Filtro de visualización

Determina qué paquetes ya capturados se muestran.

Ejemplo:

```text
tcp.port == 443
```

La sintaxis de ambos tipos de filtros es diferente.

---

# 16. Seguridad del direccionamiento y segmentación

## 16.1. Segmentación de red

La segmentación divide una infraestructura en dominios o zonas con requisitos diferentes.

Ejemplo:

```text
Red administrativa
192.168.10.0/24

Red de estudiantes
192.168.20.0/24

Red de invitados
192.168.30.0/24

Red de servidores
192.168.40.0/24
```

## 16.2. VLAN

VLAN significa Virtual Local Area Network.

Permite separar dominios de capa 2 sobre infraestructura de conmutación compatible.

Ejemplo:

| VLAN | Función |
|---|---|
| 10 | Administración |
| 20 | Usuarios |
| 30 | Invitados |
| 40 | Servidores |

Una VLAN no equivale automáticamente a una subred IP, aunque es habitual asociar una subred a cada VLAN.

## 16.3. Comunicación entre VLAN

La comunicación entre VLAN requiere mecanismos de capa 3, como:

- Router.
- Switch multicapa.

Pueden aplicarse ACL o reglas de firewall.

## 16.4. ACL

ACL significa Access Control List.

Una ACL permite definir reglas para controlar determinados accesos o flujos.

Ejemplo conceptual:

```text
Permitir:
192.168.10.0/24 -> 192.168.40.10 TCP 443

Bloquear:
192.168.30.0/24 -> 192.168.10.0/24
```

## 16.5. Microsegmentación

La microsegmentación aplica controles más granulares entre cargas de trabajo, sistemas o aplicaciones.

Puede utilizarse para limitar movimientos laterales después de un compromiso.

## 16.6. Defensa en profundidad

Consiste en utilizar múltiples controles complementarios.

Ejemplo:

```text
Autenticación
     +
Firewall
     +
Segmentación
     +
Actualizaciones
     +
Monitoreo
     +
Copias de seguridad
```

Si un control falla, otros pueden reducir el impacto.

---

# 17. Errores frecuentes y resolución de problemas

## 17.1. IP incorrecta

Un dispositivo puede tener una dirección fuera de la subred esperada.

Esto puede impedir la comunicación local.

## 17.2. Máscara incorrecta

Dos dispositivos pueden interpretar de manera diferente qué destinos pertenecen a la red local.

Ejemplo:

```text
Equipo A: 192.168.1.10/24
Equipo B: 192.168.1.20/25
```

En este caso concreto ambos pertenecen al mismo rango local interpretado por sus respectivas máscaras, pero otras direcciones pueden producir decisiones de encaminamiento inconsistentes.

## 17.3. Gateway incorrecto

Un dispositivo puede comunicarse localmente, pero no alcanzar redes externas.

## 17.4. DNS incorrecto

La conectividad IP puede funcionar, pero la resolución de nombres puede fallar.

Ejemplo de diagnóstico:

```bash
ping 1.1.1.1
```

y luego:

```bash
nslookup example.com
```

Los resultados deben interpretarse teniendo en cuenta el filtrado y la configuración.

## 17.5. Firewall bloqueando tráfico

Una regla puede impedir conexiones legítimas.

Es importante comprobar:

- Dirección.
- Puerto.
- Protocolo.
- Interfaz.
- Estado.
- Orden de reglas.

## 17.6. NAT incorrecto

Una traducción mal configurada puede impedir que las respuestas regresen correctamente.

## 17.7. Rutas incorrectas

Una tabla de rutas incorrecta puede provocar:

- Pérdida de conectividad.
- Caminos inesperados.
- Bucles.
- Envío al siguiente salto equivocado.

## 17.8. MTU y fragmentación

Una MTU inadecuada puede producir problemas de conectividad o rendimiento.

Los mecanismos de Path MTU Discovery ayudan a determinar tamaños apropiados.

Bloquear determinados mensajes ICMP necesarios puede interferir con estos mecanismos.

---

# 18. Glosario

| Concepto | Definición |
|---|---|
| IPv4 | Protocolo IP con direcciones de 32 bits |
| IPv6 | Protocolo IP con direcciones de 128 bits |
| Dirección pública | Dirección globalmente enrutable cuando corresponde |
| Dirección privada | Dirección destinada a redes privadas |
| Máscara | Identifica los bits del prefijo de red |
| CIDR | Direccionamiento sin clases |
| Subnetting | División de redes en subredes |
| VLSM | Máscaras de longitud variable |
| Gateway | Puerta de enlace |
| Router | Dispositivo de encaminamiento |
| NAT | Traducción de direcciones |
| PAT | Traducción de direcciones y puertos |
| CGNAT | NAT a escala de proveedor |
| Firewall | Control de tráfico mediante políticas |
| Stateful | Con seguimiento de estado |
| Stateless | Sin seguimiento completo de estado |
| VPN | Red privada virtual |
| IPsec | Conjunto de mecanismos de seguridad IP |
| WireGuard | Tecnología VPN |
| OpenVPN | Tecnología VPN |
| PCAP | Formato de captura de paquetes |
| Wireshark | Analizador de protocolos |
| VLAN | Red local virtual |
| ACL | Lista de control de acceso |
| MTU | Unidad máxima de transmisión |
| TTL | Campo que limita saltos IPv4 |
| DNS | Sistema de nombres de dominio |
| ARP | Resolución IPv4-MAC |
| ICMP | Protocolo de control IP |
| Puerto | Identificador de transporte |
| Socket | Interfaz de comunicación de software |

---

# 19. Referencias técnicas

## Direccionamiento

- [RFC 791 — Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 1917 — Private Address Space](https://www.rfc-editor.org/rfc/rfc1917)
- [RFC 4632 — CIDR](https://www.rfc-editor.org/rfc/rfc4632)
- [RFC 3021 — IPv4 /31 Point-to-Point Links](https://www.rfc-editor.org/rfc/rfc3021)
- [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

## NAT

- [RFC 3022 — Traditional NAT](https://www.rfc-editor.org/rfc/rfc3022)
- [RFC 6598 — Shared Address Space](https://www.rfc-editor.org/rfc/rfc6598)

## VPN e IPsec

- [RFC 4301 — Security Architecture for IP](https://www.rfc-editor.org/rfc/rfc4301)
- [RFC 7296 — IKEv2](https://www.rfc-editor.org/rfc/rfc7296)
- [WireGuard Documentation](https://www.wireguard.com/)
- [OpenVPN Documentation](https://openvpn.net/community-resources/)

## Seguridad

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST SP 800-41 — Firewall Guidelines](https://csrc.nist.gov/pubs/sp/800/41/r1/final)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [IANA Port Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)