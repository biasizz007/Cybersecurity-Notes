
# Unidad 1 — Fundamentos de Redes Informáticas

> **Área:** Ciberseguridad y redes de computadoras  
> **Nivel:** Fundamentos técnicos  
> **Objetivo:** Comprender cómo se conectan los dispositivos, cómo intercambian información y qué tecnologías hacen posible la comunicación en una red.

---

# Índice

1. [Introducción a las redes informáticas](#1-introducción-a-las-redes-informáticas)
2. [Conceptos fundamentales de comunicación](#2-conceptos-fundamentales-de-comunicación)
3. [Tipos de redes informáticas](#3-tipos-de-redes-informáticas)
4. [Topologías de red](#4-topologías-de-red)
5. [Dispositivos de interconexión](#5-dispositivos-de-interconexión)
6. [Direcciones MAC e IP](#6-direcciones-mac-e-ip)
7. [Modelos de referencia OSI y TCP/IP](#7-modelos-de-referencia-osi-y-tcpip)
8. [Las siete capas del modelo OSI](#8-las-siete-capas-del-modelo-osi)
9. [El modelo TCP/IP](#9-el-modelo-tcpip)
10. [Protocolos de red](#10-protocolos-de-red)
11. [Puertos de red y sockets](#11-puertos-de-red-y-sockets)
12. [TCP y UDP en profundidad](#12-tcp-y-udp-en-profundidad)
13. [Encapsulamiento y desencapsulamiento](#13-encapsulamiento-y-desencapsulamiento)
14. [Transmisión de datos y enrutamiento](#14-transmisión-de-datos-y-enrutamiento)
15. [Ejemplo completo de comunicación](#15-ejemplo-completo-de-comunicación)
16. [Herramientas de diagnóstico](#16-herramientas-de-diagnóstico)
17. [Relación con la ciberseguridad](#17-relación-con-la-ciberseguridad)
18. [Glosario técnico](#18-glosario-técnico)
19. [Conclusiones](#19-conclusiones)

---

# 1. Introducción a las redes informáticas

## 1.1. ¿Qué es una red informática?

Una **red informática** es un conjunto de dispositivos conectados entre sí que pueden intercambiar información y compartir recursos mediante reglas de comunicación llamadas protocolos.

Estos dispositivos pueden ser:

- Computadoras.
- Teléfonos celulares.
- Servidores.
- Impresoras.
- Cámaras de seguridad.
- Routers.
- Dispositivos inteligentes.
- Equipos industriales.

Una red no necesita estar conectada a Internet para funcionar.

Por ejemplo, dos computadoras conectadas mediante un cable Ethernet pueden formar una red local y compartir archivos sin tener acceso a Internet.

### Ejemplo cotidiano

Imaginemos una escuela que tiene diez computadoras y una impresora.

Sin una red, cada computadora necesitaría conectarse individualmente a la impresora o transferir los documentos mediante una memoria USB.

Con una red, todas las computadoras pueden enviar documentos a una impresora compartida.

La red permite que los dispositivos colaboren utilizando una infraestructura común.

## 1.2. ¿Para qué sirven las redes?

Las redes informáticas permiten:

1. Compartir archivos y documentos.
2. Acceder a servidores y aplicaciones.
3. Compartir impresoras y otros dispositivos.
4. Comunicarse mediante mensajes y videollamadas.
5. Acceder a sitios web.
6. Administrar dispositivos remotamente.
7. Centralizar servicios y almacenamiento.
8. Facilitar el trabajo colaborativo.

En ciberseguridad, comprender estas funciones es esencial porque cada conexión también puede representar un posible punto de exposición.

## 1.3. ¿Qué es Internet?

Internet es una red mundial formada por múltiples redes interconectadas.

No es una única computadora ni un único servidor.

Es una infraestructura distribuida en la que participan:

- Proveedores de servicios de Internet.
- Centros de datos.
- Routers.
- Servidores.
- Redes empresariales.
- Redes domésticas.
- Sistemas de telecomunicaciones.

Internet utiliza principalmente la familia de protocolos TCP/IP para permitir la comunicación entre sistemas diferentes.

### Internet y la Web no son lo mismo

**Internet** es la infraestructura global de redes.

**La World Wide Web (WWW)** es un servicio que funciona sobre esa infraestructura y permite acceder a páginas y recursos mediante tecnologías como HTTP y HTTPS.

Otros servicios que utilizan Internet incluyen el correo electrónico, la transferencia de archivos y las comunicaciones en tiempo real.

---

# 2. Conceptos fundamentales de comunicación

## 2.1. ¿Qué es un protocolo?

Un protocolo es un conjunto de reglas que establece cómo deben comunicarse dos o más sistemas.

Define aspectos como:

- El formato de los mensajes.
- El orden de intercambio.
- La identificación de los participantes.
- La detección de errores.
- El tratamiento de respuestas.
- El establecimiento y cierre de conexiones, cuando corresponda.

### Ejemplo sencillo

Dos personas que hablan idiomas diferentes pueden tener dificultades para entenderse.

Para comunicarse necesitan compartir reglas de interpretación.

En informática ocurre algo similar: dos dispositivos necesitan protocolos compatibles para intercambiar información correctamente.

## 2.2. ¿Qué son los datos?

Los datos son representaciones de información que un sistema puede almacenar, procesar o transmitir.

Pueden representar:

- Texto.
- Imágenes.
- Audio.
- Video.
- Archivos.
- Instrucciones.
- Mediciones.

Las computadoras representan digitalmente la información mediante bits.

## 2.3. Bits y bytes

Un **bit** es la unidad mínima de información digital y puede tomar dos valores:

- 0
- 1

Un **byte** está compuesto por ocho bits.

Ejemplo:

```text
01000001
```

Esta secuencia puede representar la letra `A` mediante una codificación como ASCII.

### Unidades frecuentes

| Unidad | Equivalencia |
|---|---|
| 1 bit | Un dígito binario |
| 1 byte | 8 bits |
| 1 KB | 1.000 bytes |
| 1 MB | 1.000.000 bytes |
| 1 GB | 1.000.000.000 bytes |
| 1 KiB | 1.024 bytes |
| 1 MiB | 1.048.576 bytes |

Las unidades decimales y binarias no deben confundirse.

## 2.4. Ancho de banda

El ancho de banda representa la capacidad de transmisión de un enlace, normalmente expresada en bits por segundo.

Por ejemplo:

```text
100 Mbps
```

Significa que el enlace tiene una velocidad nominal de 100 millones de bits por segundo.

No significa que una aplicación siempre pueda transferir datos a esa velocidad.

El rendimiento real depende de la congestión, los protocolos, los equipos y otros factores.

## 2.5. Latencia

La latencia es el tiempo que tarda la información en desplazarse entre puntos de una comunicación.

Suele medirse en milisegundos.

Una conexión puede tener mucho ancho de banda y, aun así, presentar latencia elevada.

Por ejemplo, una videollamada necesita una latencia suficientemente baja para permitir una conversación fluida.

## 2.6. Pérdida de paquetes

Ocurre cuando una o más unidades de información no llegan a su destino.

Puede deberse a:

- Congestión.
- Interferencias.
- Fallas físicas.
- Errores de configuración.
- Problemas en dispositivos intermedios.

Algunos protocolos, como TCP, pueden detectar pérdidas e intentar recuperar los datos mediante retransmisiones.

## 2.7. Jitter

El jitter es la variación en el tiempo de llegada de los paquetes.

Es especialmente importante en aplicaciones de audio y video en tiempo real.

Una latencia estable suele ser más fácil de compensar que una latencia que cambia constantemente.

## 2.8. Modos de comunicación

### Simplex

La comunicación se produce en una sola dirección.

### Half-duplex

Ambos extremos pueden transmitir, pero no simultáneamente.

### Full-duplex

Ambos extremos pueden transmitir y recibir simultáneamente.

Las conexiones Ethernet modernas conmutadas normalmente funcionan en full-duplex.

---

# 3. Tipos de redes informáticas

Las redes pueden clasificarse según su alcance geográfico, finalidad y tecnología.

## 3.1. PAN — Personal Area Network

Una PAN es una red de alcance personal.

Conecta dispositivos próximos a una persona.

Ejemplos:

- Un teléfono y auriculares Bluetooth.
- Un reloj inteligente y un celular.
- Dispositivos personales conectados a corta distancia.

## 3.2. LAN — Local Area Network

Una LAN es una red de área local.

Generalmente se encuentra dentro de un espacio limitado, como una vivienda, oficina o edificio.

Ejemplo:

```text
Computadora ── Switch ── Servidor
                   |
                Impresora
```

Una LAN permite compartir recursos y comunicarse localmente.

## 3.3. WLAN — Wireless Local Area Network

Es una red local inalámbrica.

Normalmente utiliza tecnologías Wi-Fi basadas en estándares IEEE 802.11.

Una WLAN puede formar parte de una LAN que también tenga dispositivos conectados por cable.

## 3.4. CAN — Campus Area Network

Conecta varias redes locales dentro de un campus o conjunto de edificios cercanos.

Por ejemplo, una universidad con varios edificios interconectados.

## 3.5. MAN — Metropolitan Area Network

Una MAN cubre un área metropolitana.

Puede interconectar redes ubicadas en distintos sectores de una ciudad.

## 3.6. WAN — Wide Area Network

Una WAN conecta redes ubicadas a grandes distancias.

Puede abarcar ciudades, países o continentes.

Internet es una interconexión global de redes y utiliza múltiples infraestructuras WAN.

## 3.7. VPN — Virtual Private Network

Una VPN es una tecnología que permite establecer conectividad lógica entre sistemas o redes a través de otra infraestructura.

Muchas VPN utilizan cifrado y autenticación para proteger el tráfico.

No todas las tecnologías denominadas VPN ofrecen automáticamente las mismas garantías de seguridad.

### Comparación

| Tipo | Alcance típico | Ejemplo |
|---|---|---|
| PAN | Personal | Bluetooth |
| LAN | Local | Red de una oficina |
| WLAN | Local inalámbrica | Wi-Fi doméstico |
| CAN | Campus | Universidad |
| MAN | Metropolitano | Red municipal |
| WAN | Grandes distancias | Red entre sucursales |
| VPN | Lógico, no geográfico | Acceso remoto corporativo |

---

# 4. Topologías de red

Una topología describe cómo se organizan y conectan los dispositivos de una red.

Puede ser física o lógica.

## 4.1. Topología en bus

Los dispositivos comparten un medio de comunicación común.

```text
PC1 ─── PC2 ─── PC3 ─── PC4
```

Fue utilizada en tecnologías Ethernet antiguas con cable coaxial.

Una falla en el medio compartido podía afectar la comunicación de varios dispositivos.

## 4.2. Topología en estrella

Los dispositivos se conectan a un punto central.

```text
          PC1
           |
PC2 ─── Switch ─── PC3
           |
          PC4
```

Es muy frecuente en redes Ethernet modernas.

Ventajas:

- Facilita la administración.
- Permite aislar fallas en enlaces individuales.
- Simplifica la incorporación de equipos.

Desventaja:

- El dispositivo central puede representar un punto único de falla si no existe redundancia.

## 4.3. Topología en anillo

Los dispositivos forman una estructura circular.

```text
PC1 ─── PC2
 |       |
PC4 ─── PC3
```

El comportamiento depende de la tecnología y de los mecanismos de redundancia utilizados.

## 4.4. Topología en malla

Existen múltiples conexiones entre dispositivos.

Puede ser:

- Malla completa.
- Malla parcial.

La redundancia puede mejorar la disponibilidad, aunque también incrementa los costos y la complejidad.

## 4.5. Topología en árbol

Organiza la red mediante niveles jerárquicos.

Es común en diseños de redes empresariales.

## 4.6. Topología híbrida

Combina características de varias topologías.

Las redes reales suelen utilizar diseños híbridos.

---

# 5. Dispositivos de interconexión

## 5.1. NIC — Network Interface Card

Una interfaz de red permite que un dispositivo se conecte a una red.

Puede ser:

- Ethernet.
- Wi-Fi.
- Virtual.

Las interfaces Ethernet y Wi-Fi normalmente utilizan direcciones MAC.

## 5.2. Repetidor

Un repetidor regenera o retransmite señales para extender el alcance de un medio de comunicación.

Trabaja principalmente en la capa física.

## 5.3. Hub

Un hub Ethernet tradicional recibe señales por un puerto y las replica hacia los demás.

No toma decisiones de reenvío basadas en direcciones MAC.

Los hubs fueron reemplazados en gran medida por switches.

## 5.4. Switch

Un switch Ethernet conecta dispositivos dentro de una red.

Aprende direcciones MAC y las asocia con sus puertos.

### Funcionamiento básico

1. Recibe una trama Ethernet.
2. Examina la dirección MAC de origen.
3. Aprende por qué puerto puede alcanzar esa dirección.
4. Examina la dirección MAC de destino.
5. Si conoce el puerto de destino, reenvía la trama por ese puerto.
6. Si no conoce el destino, normalmente realiza flooding dentro de la VLAN correspondiente.

Un switch de capa 2 no necesita examinar el contenido de una página web para reenviar una trama.

### Tabla MAC

Ejemplo conceptual:

| Dirección MAC | Puerto |
|---|---|
| AA:AA:AA:AA:AA:01 | 1 |
| AA:AA:AA:AA:AA:02 | 2 |
| AA:AA:AA:AA:AA:03 | 3 |

## 5.5. Router

Un router conecta redes IP diferentes.

Su función principal es reenviar paquetes según sus direcciones IP de destino y la información de su tabla de enrutamiento.

Ejemplo:

```text
Red doméstica
192.168.1.0/24
       |
     Router
       |
    Internet
```

Un router puede incorporar otras funciones, como:

- NAT.
- Firewall.
- DHCP.
- VPN.
- Wi-Fi.

Sin embargo, estas funciones no son requisitos fundamentales para que un dispositivo sea un router.

## 5.6. Access Point

Un punto de acceso permite que dispositivos inalámbricos se conecten a una red.

Puede estar integrado en un router doméstico o funcionar como dispositivo independiente.

## 5.7. Módem

Un módem adapta señales para transmitir información sobre determinados medios de comunicación.

Según la tecnología, puede utilizarse en conexiones por cable, DSL u otros sistemas.

No debe confundirse necesariamente con un router.

## 5.8. Firewall

Un firewall controla el tráfico de red según reglas de seguridad.

Puede operar mediante:

- Direcciones IP.
- Puertos.
- Protocolos.
- Estado de conexiones.
- Información de aplicaciones, según sus capacidades.

Puede implementarse mediante software, hardware o servicios virtualizados.

## 5.9. Gateway

Una puerta de enlace permite comunicar sistemas o redes y, según el contexto, puede realizar traducciones entre protocolos.

En redes IP, el término **default gateway** suele referirse al router utilizado para alcanzar destinos fuera de la red local.

---

# 6. Direcciones MAC e IP

Para que los dispositivos puedan comunicarse, necesitan mecanismos de identificación y direccionamiento.

## 6.1. Dirección MAC

Una dirección MAC es un identificador utilizado por tecnologías de enlace como Ethernet y Wi-Fi.

Una dirección MAC Ethernet tradicional tiene 48 bits.

Ejemplo:

```text
00:1A:2B:3C:4D:5E
```

Se representa normalmente mediante seis grupos de dos dígitos hexadecimales.

Las direcciones MAC pueden estar asignadas por fabricantes, configuradas administrativamente o aleatorizadas.

Por lo tanto, no siempre identifican de manera permanente y única a un dispositivo físico.

## 6.2. Dirección IP

Una dirección IP es una dirección lógica utilizada para identificar interfaces y permitir el encaminamiento de paquetes entre redes.

Existen dos versiones principales:

- IPv4.
- IPv6.

## 6.3. IPv4

IPv4 utiliza direcciones de 32 bits.

Ejemplo:

```text
192.168.1.10
```

Se representa mediante cuatro octetos decimales.

Cada octeto puede tener valores entre 0 y 255.

## 6.4. IPv6

IPv6 utiliza direcciones de 128 bits.

Ejemplo:

```text
2001:db8::1
```

El prefijo `2001:db8::/32` está reservado para documentación y ejemplos.

IPv6 ofrece un espacio de direccionamiento mucho mayor que IPv4.

## 6.5. Direcciones privadas IPv4

Los rangos privados definidos por RFC 1918 son:

| Rango | Prefijo |
|---|---|
| 10.0.0.0 – 10.255.255.255 | /8 |
| 172.16.0.0 – 172.31.255.255 | /12 |
| 192.168.0.0 – 192.168.255.255 | /16 |

Estas direcciones no se enrutan directamente en Internet pública.

## 6.6. Máscara de subred

Una máscara permite determinar qué parte de una dirección IPv4 corresponde al prefijo de red.

Ejemplo:

```text
IP:       192.168.1.10
Máscara:  255.255.255.0
Prefijo:  /24
```

La red correspondiente es:

```text
192.168.1.0/24
```

En una subred IPv4 /24 tradicional:

- Dirección de red: `192.168.1.0`
- Broadcast: `192.168.1.255`
- Hosts habituales: `192.168.1.1` a `192.168.1.254`

Las reglas de asignación pueden variar en casos especiales como enlaces /31 y /32.

## 6.7. ¿Qué es una subred?

Una subred es una división lógica de un espacio de direcciones IP.

Permite:

- Organizar dispositivos.
- Separar segmentos.
- Administrar direcciones.
- Diseñar políticas de seguridad.
- Controlar dominios de broadcast en IPv4.

## 6.8. ¿Qué es NAT?

NAT significa Network Address Translation.

Permite modificar información de direccionamiento IP al atravesar un dispositivo.

En redes domésticas se utiliza frecuentemente NAPT o PAT, que permite compartir una dirección IPv4 pública entre múltiples conexiones mediante traducción de direcciones y puertos.

NAT no sustituye a un firewall ni garantiza por sí solo una política completa de seguridad.

---

# 7. Modelos de referencia OSI y TCP/IP

Los modelos de red permiten estudiar sistemas complejos dividiendo sus funciones en capas.

La idea es separar responsabilidades.

En lugar de analizar toda una comunicación como un único proceso, se estudian sus diferentes componentes.

## 7.1. ¿Por qué existen las capas?

Imaginemos que enviamos un paquete por correo.

Para que llegue correctamente necesitamos:

1. Preparar el contenido.
2. Colocarlo dentro de un sobre.
3. Escribir una dirección.
4. Elegir un medio de transporte.
5. Entregarlo al destinatario.

Cada etapa cumple una función distinta.

En las redes informáticas ocurre algo parecido.

Las capas permiten separar responsabilidades y facilitar el desarrollo, mantenimiento y diagnóstico de tecnologías.

---

# 8. Las siete capas del modelo OSI

OSI significa **Open Systems Interconnection**.

Es un modelo de referencia desarrollado para describir funciones de comunicación mediante siete capas.

```text
+-------------------------+
| 7. Aplicación           |
+-------------------------+
| 6. Presentación         |
+-------------------------+
| 5. Sesión               |
+-------------------------+
| 4. Transporte           |
+-------------------------+
| 3. Red                  |
+-------------------------+
| 2. Enlace de datos      |
+-------------------------+
| 1. Física               |
+-------------------------+
```

El modelo OSI es especialmente útil para aprender redes y diagnosticar problemas.

Las tecnologías reales no siempre corresponden exactamente a una única capa.

## 8.1. Capa 1 — Física

Se encarga de transmitir bits mediante señales físicas.

Trabaja con aspectos como:

- Señales eléctricas.
- Señales ópticas.
- Ondas de radio.
- Conectores.
- Cableado.
- Características de transmisión.

Ejemplos:

- Cables de cobre.
- Fibra óptica.
- Componentes físicos de Ethernet.
- Repetidores.

### Ejemplo

Cuando una computadora envía información por un cable Ethernet, los bits se representan mediante señales que cumplen las especificaciones de la tecnología física utilizada.

### Relación con seguridad

Un atacante con acceso físico podría:

- Desconectar enlaces.
- Dañar cableado.
- Interferir comunicaciones inalámbricas.
- Conectar dispositivos no autorizados.

La protección física es una parte fundamental de la seguridad de redes.

## 8.2. Capa 2 — Enlace de datos

Permite transmitir tramas dentro de un enlace o segmento de red.

Funciones habituales:

- Encapsulamiento en tramas.
- Direccionamiento MAC.
- Detección de determinados errores.
- Control de acceso al medio.
- Conmutación Ethernet.

Tecnologías:

- Ethernet.
- Wi-Fi.
- PPP.
- VLAN IEEE 802.1Q.

### Ejemplo

Una computadora necesita enviar una trama Ethernet a otro dispositivo de su misma red.

Utiliza la dirección MAC de destino para que la trama pueda entregarse correctamente dentro del enlace correspondiente.

### Relación con seguridad

Algunas amenazas asociadas incluyen:

- MAC spoofing.
- ARP spoofing.
- VLAN hopping.
- Ataques contra la infraestructura de conmutación.

## 8.3. Capa 3 — Red

Se ocupa del direccionamiento lógico y del encaminamiento entre redes.

Funciones:

- Direccionamiento IP.
- Selección de rutas.
- Reenvío de paquetes.
- Manejo de determinados mensajes de control.

Protocolos:

- IPv4.
- IPv6.
- ICMP.
- ICMPv6.

Los routers trabajan principalmente en esta capa.

### Ejemplo

Una computadora en Argentina necesita comunicarse con un servidor ubicado en otro país.

Los routers intermedios utilizan información de enrutamiento para acercar los paquetes hacia la red de destino.

### Relación con seguridad

- Filtrado por direcciones IP.
- Suplantación de direcciones.
- Seguridad del enrutamiento.
- Segmentación de redes.
- Control de tráfico entre subredes.

## 8.4. Capa 4 — Transporte

Proporciona mecanismos de comunicación entre procesos de los sistemas finales.

Protocolos principales:

- TCP.
- UDP.

Entre sus funciones posibles están:

- Multiplexación mediante puertos.
- Segmentación.
- Control de flujo.
- Control de congestión.
- Recuperación de pérdidas.

No todos los protocolos de transporte implementan todas estas funciones.

TCP ofrece un flujo de bytes confiable y ordenado.

UDP ofrece datagramas sin establecer una conexión de transporte ni garantizar su entrega.

## 8.5. Capa 5 — Sesión

En el modelo OSI, administra aspectos relacionados con el establecimiento, mantenimiento y coordinación de sesiones de comunicación.

Puede incluir:

- Control de diálogo.
- Sincronización.
- Administración de sesiones.

En la arquitectura real de Internet, estas funciones suelen implementarse mediante protocolos o aplicaciones que no se separan estrictamente en una capa independiente.

## 8.6. Capa 6 — Presentación

Se ocupa de la representación de la información.

Puede incluir:

- Codificación.
- Conversión de formatos.
- Serialización.
- Compresión.
- Funciones criptográficas.

Ejemplos conceptuales:

- UTF-8.
- Formatos de representación.
- Codificación de datos.
- Cifrado aplicado a la comunicación.

TLS suele asociarse didácticamente con funciones de presentación, aunque su ubicación exacta no corresponde de manera rígida al modelo OSI.

## 8.7. Capa 7 — Aplicación

Es la capa más cercana a los programas que utilizan servicios de red.

Incluye protocolos como:

- HTTP.
- DNS.
- SMTP.
- FTP.
- SSH.

No significa que toda la aplicación de software pertenezca literalmente a esta capa.

Se refiere a las funciones y protocolos que permiten ofrecer servicios de comunicación a las aplicaciones.

---

# 9. El modelo TCP/IP

El modelo TCP/IP describe la arquitectura de protocolos utilizada en Internet.

Habitualmente se representa mediante cuatro capas:

1. Aplicación.
2. Transporte.
3. Internet.
4. Acceso a la red.

Algunos materiales utilizan un modelo pedagógico de cinco capas separando enlace y física.

## 9.1. Capa de aplicación

Incluye protocolos utilizados por servicios y aplicaciones.

Ejemplos:

- HTTP.
- HTTPS.
- DNS.
- SMTP.
- SSH.
- DHCP.

## 9.2. Capa de transporte

Permite comunicación entre procesos.

Protocolos principales:

- TCP.
- UDP.

También existen otros protocolos y mecanismos modernos de transporte.

## 9.3. Capa de Internet

Permite direccionar y encaminar paquetes entre redes.

Ejemplos:

- IPv4.
- IPv6.
- ICMP.

## 9.4. Capa de acceso a la red

Incluye mecanismos necesarios para transmitir datos por los enlaces disponibles.

Ejemplos:

- Ethernet.
- Wi-Fi.
- PPP.

## 9.5. Comparación OSI y TCP/IP

| OSI | TCP/IP |
|---|---|
| 7. Aplicación | Aplicación |
| 6. Presentación | Aplicación |
| 5. Sesión | Aplicación |
| 4. Transporte | Transporte |
| 3. Red | Internet |
| 2. Enlace de datos | Acceso a la red |
| 1. Física | Acceso a la red |

Esta comparación es conceptual, no una equivalencia exacta para todos los protocolos.

### Diferencia principal

OSI es especialmente útil como modelo de referencia para explicar funciones.

TCP/IP representa una arquitectura práctica de protocolos que sustenta Internet.

---

# 10. Protocolos de red

## 10.1. ¿Qué es un protocolo de red?

Un protocolo establece reglas para que los dispositivos intercambien mensajes interpretables.

Cada protocolo resuelve problemas concretos.

Por ejemplo:

- IP permite direccionar paquetes.
- TCP ofrece transporte confiable.
- DNS permite resolver nombres.
- HTTP permite intercambiar solicitudes y respuestas web.
- DHCP permite configurar parámetros de red automáticamente.

## 10.2. IP — Internet Protocol

IP es un protocolo de la capa de Internet.

Su función principal es transportar datagramas entre sistemas mediante direcciones lógicas.

IP no garantiza por sí mismo:

- Entrega.
- Orden.
- Ausencia de duplicados.
- Recuperación de paquetes perdidos.

Por eso se describe como un servicio de entrega de mejor esfuerzo (*best effort*).

## 10.3. ICMP

ICMP significa Internet Control Message Protocol.

Se utiliza para comunicar información de control y diagnóstico relacionada con IP.

Una herramienta conocida que utiliza ICMP es `ping`.

Ejemplo:

```bash
ping 192.168.1.1
```

Este comando intenta comprobar la respuesta del destino mediante mensajes ICMP Echo, cuando el sistema y la red lo permiten.

La falta de respuesta no demuestra necesariamente que el dispositivo esté apagado.

Puede existir filtrado de ICMP.

## 10.4. ARP

ARP significa Address Resolution Protocol.

En IPv4 sobre Ethernet, permite descubrir la dirección MAC asociada a una dirección IPv4 dentro del enlace local.

### Ejemplo paso a paso

Una computadora tiene:

```text
IP: 192.168.1.10
MAC: AA:AA:AA:AA:AA:10
```

Quiere comunicarse con:

```text
IP: 192.168.1.20
```

Si el destino está en la misma red local y no conoce su dirección MAC:

1. La computadora consulta su caché ARP.
2. Si no encuentra la asociación, envía una solicitud ARP.
3. El dispositivo que posee la IP consultada puede responder.
4. La computadora registra la asociación IP-MAC.
5. Utiliza esa dirección MAC para enviar tramas Ethernet.

Si el destino se encuentra fuera de la red local, normalmente se resuelve la MAC del siguiente salto, como el gateway.

En IPv6 no se utiliza ARP; se emplean mecanismos de Neighbor Discovery basados en ICMPv6.

## 10.5. DNS

DNS significa Domain Name System.

Permite resolver nombres de dominio y consultar distintos tipos de información asociada.

Ejemplo:

```text
www.ejemplo.com
```

Una aplicación puede necesitar conocer la dirección IP correspondiente para establecer una comunicación.

### Resolución simplificada

1. El usuario introduce un dominio.
2. El sistema comprueba mecanismos de resolución locales.
3. Si necesita una consulta DNS, contacta con un resolvedor.
4. El resolvedor utiliza su caché o realiza consultas adicionales.
5. Obtiene los registros correspondientes.
6. Devuelve la información al cliente.
7. La aplicación utiliza la dirección obtenida para continuar la conexión.

### Registros DNS frecuentes

| Registro | Función |
|---|---|
| A | Dirección IPv4 |
| AAAA | Dirección IPv6 |
| CNAME | Alias de otro nombre |
| MX | Servidores de correo |
| NS | Servidores de nombres |
| TXT | Información textual |
| PTR | Resolución inversa |

DNS tradicional utiliza habitualmente UDP 53, aunque también puede utilizar TCP 53.

Existen mecanismos como DNS over TLS y DNS over HTTPS que protegen el transporte de consultas DNS bajo determinadas condiciones.

## 10.6. DHCP

DHCP significa Dynamic Host Configuration Protocol.

Permite asignar automáticamente parámetros de configuración IP.

Puede proporcionar:

- Dirección IP.
- Máscara o prefijo.
- Gateway.
- Servidores DNS.
- Tiempo de concesión.

### Proceso DORA en DHCPv4

**D — Discover**

El cliente busca servidores DHCP.

**O — Offer**

Un servidor ofrece una configuración.

**R — Request**

El cliente solicita una oferta determinada.

**A — Acknowledgment**

El servidor confirma la concesión.

```text
Cliente                    Servidor DHCP
   |                              |
   |-------- Discover ----------->|
   |<--------- Offer -------------|
   |-------- Request ------------>|
   |<---------- ACK --------------|
   |                              |
```

Este es el intercambio típico de asignación inicial en DHCPv4. Existen otros mensajes y situaciones.

DHCPv4 utiliza habitualmente UDP 67 para el servidor y UDP 68 para el cliente.

## 10.7. HTTP

HTTP significa Hypertext Transfer Protocol.

Es un protocolo de aplicación utilizado para intercambiar solicitudes y respuestas.

### Ejemplo de solicitud

```http
GET / HTTP/1.1
Host: example.com
```

El cliente solicita un recurso al servidor.

### Métodos HTTP

| Método | Función habitual |
|---|---|
| GET | Obtener un recurso |
| POST | Enviar datos para procesamiento |
| PUT | Crear o reemplazar una representación |
| PATCH | Aplicar modificaciones parciales |
| DELETE | Solicitar eliminación |
| HEAD | Obtener encabezados |
| OPTIONS | Consultar opciones de comunicación |

El comportamiento real depende de la implementación del servidor y de la semántica del protocolo.

### Códigos de estado

| Código | Significado |
|---|---|
| 200 | OK |
| 201 | Created |
| 301 | Moved Permanently |
| 302 | Found |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

## 10.8. HTTPS

HTTPS es HTTP protegido mediante TLS.

TLS proporciona mecanismos para:

- Cifrar la comunicación.
- Proteger la integridad.
- Autenticar al servidor mediante certificados, cuando la validación se realiza correctamente.

HTTPS no garantiza que un sitio sea legítimo o que su contenido sea seguro.

Un sitio malicioso también puede utilizar HTTPS.

HTTP/1.1 y HTTP/2 suelen utilizar TCP cuando se transportan mediante HTTPS.

HTTP/3 utiliza QUIC, que funciona sobre UDP y proporciona transporte seguro.

## 10.9. FTP

FTP significa File Transfer Protocol.

Se utiliza para transferir archivos.

Tradicionalmente emplea:

- TCP 21 para control.
- Conexiones de datos adicionales.

FTP clásico no cifra de manera predeterminada las credenciales ni los datos.

No debe confundirse con SFTP.

## 10.10. SFTP

SFTP significa SSH File Transfer Protocol.

Permite transferir archivos mediante SSH.

Habitualmente utiliza TCP 22.

Aunque sus nombres sean similares, FTP y SFTP son protocolos diferentes.

## 10.11. SSH

SSH significa Secure Shell.

Permite establecer sesiones remotas seguras y ejecutar determinadas operaciones administrativas.

Habitualmente utiliza TCP 22.

Ejemplo:

```bash
ssh usuario@192.168.1.10
```

La conexión requiere que exista un servidor SSH accesible y que el usuario disponga de credenciales autorizadas.

## 10.12. Telnet

Telnet es un protocolo tradicional de acceso remoto.

Habitualmente utiliza TCP 23.

No proporciona cifrado de la sesión de forma nativa.

Por esa razón, SSH es preferible para administración remota segura.

## 10.13. SMTP

SMTP significa Simple Mail Transfer Protocol.

Se utiliza principalmente para enviar y transferir correo electrónico.

Puertos habituales:

- TCP 25: transferencia entre servidores.
- TCP 587: envío autenticado de correo.
- TCP 465: envío mediante TLS implícito.

## 10.14. POP3 e IMAP

Son protocolos utilizados para acceder al correo electrónico.

POP3 se centra tradicionalmente en la recuperación de mensajes.

IMAP permite gestionar mensajes y carpetas manteniendo el estado sincronizado con el servidor.

Puertos frecuentes:

| Protocolo | Puerto |
|---|---|
| POP3 | TCP 110 |
| POP3S | TCP 995 |
| IMAP | TCP 143 |
| IMAPS | TCP 993 |

## 10.15. SNMP

SNMP significa Simple Network Management Protocol.

Se utiliza para supervisar y administrar dispositivos de red.

Habitualmente utiliza:

- UDP 161 para consultas.
- UDP 162 para notificaciones.

SNMPv3 incorpora mecanismos de autenticación y privacidad que pueden ofrecer mayor seguridad que configuraciones tradicionales de versiones anteriores.

## 10.16. NTP

NTP significa Network Time Protocol.

Permite sincronizar relojes de sistemas informáticos.

Habitualmente utiliza UDP 123.

La sincronización horaria es importante para:

- Registros de eventos.
- Correlación de logs.
- Autenticación.
- Certificados.
- Investigaciones de seguridad.

---

# 11. Puertos de red y sockets

## 11.1. ¿Qué es un puerto?

Un puerto de transporte es un identificador numérico que permite distinguir comunicaciones y servicios dentro de un sistema.

En TCP y UDP, los números de puerto tienen 16 bits.

Por eso, sus valores posibles van de:

```text
0 a 65535
```

Una dirección IP permite identificar un destino de red.

El puerto permite identificar un punto de comunicación asociado a un protocolo de transporte.

### Ejemplo sencillo

Imaginemos un edificio de departamentos.

La dirección del edificio permite llegar al lugar.

El número de departamento permite encontrar a un destinatario dentro del edificio.

De forma aproximada:

```text
Dirección IP = edificio
Puerto       = departamento
```

Esta comparación sirve para comprender el concepto, aunque técnicamente los puertos identifican extremos de comunicación y no aplicaciones de manera universal o permanente.

## 11.2. Clasificación de puertos

| Rango | Categoría |
|---|---|
| 0–1023 | System / Well-Known Ports |
| 1024–49151 | User / Registered Ports |
| 49152–65535 | Dynamic / Private Ports |

Estas categorías corresponden al registro de números de puerto de IANA.

Un puerto registrado no implica que un servicio esté ejecutándose.

## 11.3. Puertos frecuentes

| Puerto | Transporte habitual | Servicio |
|---|---|---|
| 20 | TCP | Datos FTP en modo activo tradicional |
| 21 | TCP | Control FTP |
| 22 | TCP | SSH / SFTP |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | UDP/TCP | DNS |
| 67 | UDP | Servidor DHCPv4 |
| 68 | UDP | Cliente DHCPv4 |
| 69 | UDP | TFTP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 123 | UDP | NTP |
| 143 | TCP | IMAP |
| 161 | UDP | SNMP |
| 162 | UDP | SNMP Trap |
| 389 | TCP/UDP | LDAP |
| 443 | TCP/UDP | HTTPS / HTTP/3 |
| 445 | TCP | SMB |
| 465 | TCP | SMTP Submission con TLS implícito |
| 587 | TCP | SMTP Submission |
| 636 | TCP | LDAP sobre TLS |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |
| 1433 | TCP | Microsoft SQL Server |
| 3306 | TCP | MySQL |
| 3389 | TCP/UDP | RDP |
| 5432 | TCP | PostgreSQL |
| 5900 | TCP | VNC |
| 6379 | TCP | Redis |
| 8080 | TCP | Alternativa frecuente para HTTP |

**Importante:** estos son usos habituales, no reglas obligatorias.

Un servicio puede configurarse para utilizar un puerto diferente.

El número de puerto no demuestra por sí solo qué aplicación o protocolo se está ejecutando.

## 11.4. ¿Qué es un socket?

Un socket es una abstracción del sistema operativo utilizada por los programas para comunicarse.

En una conexión TCP se pueden identificar los extremos mediante:

```text
IP de origen
Puerto de origen
IP de destino
Puerto de destino
```

Además, el protocolo de transporte forma parte de la identificación de la comunicación.

Ejemplo:

```text
Origen:
192.168.1.10:53000

Destino:
203.0.113.20:443

Transporte:
TCP
```

`203.0.113.0/24` es un rango reservado para documentación.

## 11.5. ¿Qué significa que un puerto esté abierto?

En TCP, se suele describir como abierto un puerto en el que un servicio acepta intentos de conexión.

En UDP, determinar el estado de un puerto puede ser más complejo porque el protocolo no utiliza el mismo establecimiento de conexión que TCP.

Los estados observados durante un diagnóstico dependen también de:

- Firewalls.
- Filtrado.
- Configuración.
- Respuestas de la aplicación.
- Alcance de red.

## 11.6. ¿Por qué importan los puertos en ciberseguridad?

Los servicios expuestos pueden formar parte de la superficie de ataque de un sistema.

Por ejemplo, un servidor con un servicio administrativo accesible desde Internet puede necesitar controles adicionales.

Las buenas prácticas incluyen:

- Mantener solamente los servicios necesarios.
- Aplicar actualizaciones.
- Restringir accesos.
- Configurar firewalls.
- Utilizar autenticación segura.
- Registrar eventos relevantes.

---

# 12. TCP y UDP en profundidad

TCP y UDP son dos protocolos de transporte fundamentales en Internet.

Aunque ambos utilizan puertos, su funcionamiento es diferente.

## 12.1. TCP — Transmission Control Protocol

TCP proporciona una comunicación orientada a conexión.

Ofrece un flujo de bytes confiable y ordenado entre extremos, siempre que la conexión pueda mantenerse correctamente.

Entre sus mecanismos se encuentran:

- Números de secuencia.
- Confirmaciones.
- Retransmisiones.
- Control de flujo.
- Control de congestión.
- Establecimiento y cierre de conexiones.

## 12.2. Three-Way Handshake

TCP utiliza normalmente un intercambio de tres pasos para establecer una conexión.

```text
Cliente                         Servidor
   |                               |
   |------------ SYN ------------->|
   |                               |
   |<--------- SYN-ACK ------------|
   |                               |
   |------------ ACK ------------->|
   |                               |
   |       Conexión establecida    |
```

### Paso 1 — SYN

El cliente envía un segmento con el indicador SYN.

Propone iniciar una conexión y comunica información inicial, incluido un número de secuencia.

### Paso 2 — SYN-ACK

El servidor responde con SYN y ACK.

Reconoce la solicitud y comunica su propia información inicial de secuencia.

### Paso 3 — ACK

El cliente confirma la respuesta.

Después del establecimiento, ambos extremos pueden intercambiar datos.

## 12.3. Números de secuencia

TCP identifica posiciones dentro del flujo de bytes.

Esto permite reconstruir la información en el orden correcto aunque los segmentos lleguen desordenados.

## 12.4. Confirmaciones ACK

Las confirmaciones permiten informar qué datos fueron recibidos.

Cuando se detectan pérdidas, TCP puede retransmitir información.

## 12.5. Control de flujo

El control de flujo evita que un emisor envíe más información de la que el receptor puede manejar en un momento determinado.

TCP utiliza mecanismos como la ventana de recepción.

## 12.6. Control de congestión

El control de congestión intenta adaptar el envío de datos a las condiciones de la red.

No debe confundirse con el control de flujo.

- Control de flujo: protege la capacidad del receptor.
- Control de congestión: responde a limitaciones y congestión de la red.

## 12.7. Finalización de una conexión TCP

Una conexión TCP puede finalizar mediante intercambios que incluyen FIN y ACK.

También puede producirse una terminación abrupta mediante RST.

El cierre normal permite finalizar las direcciones del flujo de manera controlada.

## 12.8. Estados TCP

Algunos estados importantes son:

| Estado | Significado |
|---|---|
| LISTEN | Esperando conexiones |
| SYN-SENT | Solicitud de conexión enviada |
| SYN-RECEIVED | Solicitud recibida y respuesta enviada |
| ESTABLISHED | Conexión establecida |
| FIN-WAIT-1 | Inicio del cierre |
| FIN-WAIT-2 | Esperando cierre remoto |
| CLOSE-WAIT | Cierre remoto recibido |
| LAST-ACK | Esperando confirmación final |
| TIME-WAIT | Espera temporal posterior al cierre |
| CLOSED | Sin conexión activa |

Estos estados son útiles al analizar conexiones y problemas de red.

## 12.9. UDP — User Datagram Protocol

UDP es un protocolo de transporte orientado a datagramas.

No establece una conexión de transporte mediante un handshake como TCP.

Tampoco proporciona por sí mismo:

- Entrega garantizada.
- Orden garantizado.
- Retransmisiones.
- Control de congestión equivalente al de TCP.

Esto no significa que una aplicación sobre UDP no pueda implementar sus propios mecanismos de confiabilidad.

## 12.10. ¿Cuándo se utiliza UDP?

UDP es útil cuando se busca un transporte simple de datagramas o cuando los mecanismos de control se implementan en capas superiores.

Ejemplos:

- Consultas DNS tradicionales.
- DHCP.
- NTP.
- Determinadas comunicaciones en tiempo real.
- QUIC.

## 12.11. Comparación TCP y UDP

| Característica | TCP | UDP |
|---|---|---|
| Orientado a conexión | Sí | No |
| Handshake de transporte | Sí | No |
| Garantía de orden | Sí | No |
| Retransmisiones propias | Sí | No |
| Control de flujo | Sí | No |
| Control de congestión | Sí | No |
| Preserva límites de mensajes | No, flujo de bytes | Sí, datagramas |
| Cabecera mínima | 20 bytes | 8 bytes |

TCP no es necesariamente más rápido que UDP, ni UDP garantiza automáticamente menor latencia en todas las aplicaciones.

El rendimiento depende del protocolo, la implementación y las condiciones de la red.

---

# 13. Encapsulamiento y desencapsulamiento

## 13.1. ¿Qué es encapsular?

El encapsulamiento es el proceso mediante el cual distintas capas agregan información de control a los datos que se transmiten.

Cada capa incorpora los encabezados que necesita para cumplir su función.

### Ejemplo conceptual

```text
Datos de aplicación
        |
        v
[Encabezado TCP][Datos]
        |
        v
[Encabezado IP][TCP][Datos]
        |
        v
[Ethernet][IP][TCP][Datos][FCS]
        |
        v
Bits transmitidos por el medio
```

El ejemplo utiliza TCP sobre IPv4 y Ethernet.

No todas las comunicaciones utilizan exactamente estos protocolos o formatos.

## 13.2. Unidades de datos

| Capa | Unidad habitual |
|---|---|
| Aplicación | Datos o mensajes |
| Transporte TCP | Segmento |
| Transporte UDP | Datagrama |
| Red / Internet | Paquete o datagrama IP |
| Enlace | Trama |
| Física | Bits / señales |

## 13.3. Encabezado TCP

Incluye información como:

- Puerto de origen.
- Puerto de destino.
- Número de secuencia.
- Número de confirmación.
- Indicadores de control.
- Tamaño de ventana.
- Checksum.
- Opciones, cuando existen.

## 13.4. Encabezado IPv4

Incluye campos como:

- Versión.
- Longitud del encabezado.
- Longitud total.
- Identificación.
- Indicadores y desplazamiento de fragmentación.
- TTL.
- Protocolo superior.
- Checksum del encabezado.
- Dirección IP de origen.
- Dirección IP de destino.

## 13.5. Trama Ethernet

Una trama Ethernet típica contiene:

- Dirección MAC de destino.
- Dirección MAC de origen.
- EtherType o campo de longitud, según el formato.
- Datos.
- FCS para detección de errores.

Pueden existir etiquetas VLAN y otros elementos según la tecnología utilizada.

## 13.6. Desencapsulamiento

Es el proceso inverso.

Cuando un dispositivo recibe información:

1. La interfaz recibe señales físicas.
2. La capa de enlace interpreta la trama.
3. Se procesa el paquete IP.
4. El protocolo de transporte procesa su unidad de datos.
5. La aplicación recibe la información correspondiente.

No todas las capas entregan necesariamente los datos a la siguiente: una validación fallida o una política de filtrado puede provocar el descarte.

---

# 14. Transmisión de datos y enrutamiento

## 14.1. ¿Qué es el enrutamiento?

El enrutamiento permite determinar cómo alcanzar redes de destino.

Los routers mantienen tablas con información sobre rutas.

## 14.2. Tabla de enrutamiento

Ejemplo conceptual:

```text
Destino          Siguiente salto
192.168.1.0/24   Conectado directamente
0.0.0.0/0        192.168.1.1
```

La ruta `0.0.0.0/0` representa una ruta predeterminada IPv4.

Se utiliza cuando no existe una ruta más específica aplicable.

## 14.3. Longest Prefix Match

Cuando existen varias rutas compatibles, el encaminamiento IP utiliza normalmente la coincidencia con el prefijo más largo.

Ejemplo:

```text
10.0.0.0/8
10.20.0.0/16
10.20.30.0/24
```

Para un destino dentro de `10.20.30.0/24`, esa ruta es más específica que las otras dos.

## 14.4. TTL

En IPv4, TTL significa Time To Live.

Aunque su nombre hace referencia al tiempo, en el funcionamiento habitual de IPv4 se reduce por saltos de router.

Ayuda a evitar que los paquetes circulen indefinidamente debido a bucles de enrutamiento.

En IPv6 existe un campo equivalente denominado Hop Limit.

## 14.5. MTU

MTU significa Maximum Transmission Unit.

Representa el tamaño máximo de la unidad de datos de capa superior que puede transportar un enlace según su tecnología y configuración.

En Ethernet convencional es habitual encontrar una MTU IP de 1500 bytes.

## 14.6. Fragmentación

En IPv4 puede producirse fragmentación cuando un paquete supera determinadas limitaciones de tamaño.

En IPv6 los routers no fragmentan paquetes en tránsito; la fragmentación, cuando corresponde, es responsabilidad del origen.

La fragmentación puede afectar el rendimiento y complicar ciertos escenarios de seguridad.

## 14.7. Unicast, broadcast y multicast

### Unicast

Comunicación dirigida a un destino individual.

### Broadcast

Comunicación destinada a todos los participantes de un dominio de broadcast.

Es una característica utilizada en IPv4 y en determinadas tecnologías de enlace.

IPv6 no utiliza broadcast IP.

### Multicast

Comunicación dirigida a un grupo de receptores.

Permite distribuir información a múltiples participantes sin tratar cada destino como una comunicación unicast independiente en todos los casos.

---

# 15. Ejemplo completo de comunicación

## ¿Qué sucede cuando abrimos una página web?

Supongamos que una persona introduce:

```text
https://www.example.com
```

en su navegador.

Analicemos el proceso de forma simplificada.

## Paso 1 — La computadora tiene configuración de red

El dispositivo necesita información como:

```text
Dirección IP
Prefijo de red
Gateway
Servidores DNS
```

Puede haber obtenido esos datos mediante DHCP, configuración manual u otros mecanismos.

## Paso 2 — El navegador identifica el destino

El navegador interpreta la URL.

Determina:

- Esquema: HTTPS.
- Nombre de host: `www.example.com`.
- Puerto predeterminado: 443.
- Recurso solicitado.

## Paso 3 — Resolución DNS

El sistema necesita obtener información de direccionamiento para el nombre de host.

Puede consultar cachés o realizar consultas DNS.

El resultado puede incluir direcciones IPv4 o IPv6.

## Paso 4 — Selección de ruta

El sistema consulta su tabla de enrutamiento.

Si el destino está fuera de la red local, normalmente enviará los paquetes al siguiente salto correspondiente.

## Paso 5 — Resolución de dirección de enlace

Si utiliza IPv4 sobre Ethernet, puede necesitar ARP para descubrir la dirección MAC del siguiente salto.

En IPv6 se utilizan mecanismos de Neighbor Discovery.

## Paso 6 — Establecimiento del transporte

Para HTTPS sobre TCP, el cliente establece una conexión TCP con el servidor o con un intermediario correspondiente.

Se realiza el Three-Way Handshake.

Si se utiliza HTTP/3, el proceso se realiza mediante QUIC sobre UDP y es diferente.

## Paso 7 — Negociación TLS

En una conexión HTTPS, cliente y servidor negocian parámetros criptográficos mediante TLS.

Durante el proceso se pueden realizar:

- Negociación de algoritmos.
- Intercambio de material criptográfico.
- Validación del certificado.
- Derivación de claves de sesión.

Los detalles dependen de la versión de TLS y del modo de conexión.

## Paso 8 — Solicitud HTTP

Una vez establecido el canal seguro, el navegador envía una solicitud HTTP.

Por ejemplo:

```http
GET / HTTP/1.1
Host: www.example.com
```

Este ejemplo representa sintaxis HTTP/1.1.

HTTP/2 y HTTP/3 utilizan representaciones diferentes en el transporte.

## Paso 9 — Procesamiento en el servidor

El servidor recibe la solicitud y determina cómo responder.

Puede:

- Entregar contenido estático.
- Ejecutar lógica de aplicación.
- Consultar bases de datos.
- Contactar otros servicios.

## Paso 10 — Respuesta

El servidor devuelve una respuesta HTTP.

Ejemplo:

```http
HTTP/1.1 200 OK
Content-Type: text/html
```

La respuesta puede incluir contenido HTML.

## Paso 11 — Recepción y procesamiento

Los datos atraviesan las capas de red correspondientes.

El navegador interpreta los recursos recibidos.

Puede necesitar nuevas solicitudes para obtener:

- CSS.
- JavaScript.
- Imágenes.
- Fuentes.
- Otros recursos.

## Paso 12 — Visualización

El navegador procesa los recursos y representa la página.

### Resumen del recorrido

```text
Usuario
   |
   v
Navegador
   |
   v
Resolución DNS
   |
   v
Selección de ruta
   |
   v
Transporte TCP o QUIC
   |
   v
Seguridad TLS
   |
   v
Solicitud HTTP
   |
   v
Servidor
   |
   v
Respuesta HTTP
   |
   v
Navegador
   |
   v
Página visualizada
```

El diagrama es conceptual: algunas operaciones pueden ejecutarse en paralelo, reutilizar conexiones existentes o variar según el protocolo.

---

# 16. Herramientas de diagnóstico

Las herramientas de diagnóstico permiten observar cómo está configurada una red y analizar problemas de conectividad.

Los comandos deben ejecutarse en sistemas propios o donde exista autorización.

## 16.1. ipconfig

En Windows:

```powershell
ipconfig
```

Muestra información básica de las interfaces de red.

Para obtener información adicional:

```powershell
ipconfig /all
```

Puede mostrar:

- Direcciones IP.
- Máscaras.
- Gateways.
- DNS.
- Direcciones MAC.
- Información DHCP.

## 16.2. ip

En Linux:

```bash
ip addr
```

Permite consultar las direcciones asignadas a las interfaces.

Para consultar rutas:

```bash
ip route
```

Para consultar vecinos:

```bash
ip neigh
```

## 16.3. ping

Ejemplo:

```bash
ping 1.1.1.1
```

Permite realizar pruebas de alcance mediante ICMP Echo.

También puede proporcionar mediciones de tiempo de ida y vuelta.

## 16.4. traceroute y tracert

En Linux:

```bash
traceroute example.com
```

En Windows:

```powershell
tracert example.com
```

Permiten observar información sobre saltos de red utilizando respuestas generadas por determinados paquetes de prueba.

La ruta mostrada puede ser parcial y no siempre representa todos los detalles del tráfico real.

## 16.5. nslookup

Ejemplo:

```bash
nslookup example.com
```

Permite consultar información DNS.

## 16.6. dig

En sistemas donde está disponible:

```bash
dig example.com
```

Para consultar registros MX:

```bash
dig example.com MX
```

Para consultar registros AAAA:

```bash
dig example.com AAAA
```

## 16.7. netstat

En Windows:

```powershell
netstat -ano
```

Permite consultar conexiones, puertos y determinados identificadores de procesos.

La información disponible depende del sistema operativo y los permisos.

## 16.8. ss

En Linux:

```bash
ss -tuln
```

Opciones:

- `-t`: TCP.
- `-u`: UDP.
- `-l`: sockets en escucha.
- `-n`: direcciones y puertos numéricos.

Para incluir información de procesos, cuando se tienen los permisos necesarios:

```bash
ss -tulnp
```

## 16.9. curl

Permite realizar solicitudes a servicios mediante distintos protocolos.

Ejemplo:

```bash
curl -I https://example.com
```

Solicita encabezados HTTP mediante una petición HEAD, cuando el servidor y la implementación lo permiten.

## 16.10. Wireshark

Wireshark es una herramienta de análisis de tráfico de red.

Permite examinar capturas y estudiar protocolos.

Puede utilizarse para observar:

- Tramas Ethernet.
- Paquetes IP.
- Segmentos TCP.
- Datagramas UDP.
- Consultas DNS.
- Mensajes ICMP.
- Negociaciones de determinados protocolos.

### Ejemplo de filtro

```text
tcp
```

Muestra paquetes interpretados como TCP.

Otro ejemplo:

```text
dns
```

Muestra tráfico reconocido como DNS.

Y:

```text
tcp.port == 443
```

Filtra paquetes TCP asociados al puerto 443.

**Importante:** capturar tráfico requiere respetar la privacidad y las autorizaciones correspondientes. El tráfico cifrado no revela automáticamente el contenido de aplicación.

---

# 17. Relación con la ciberseguridad

Las redes son una de las bases técnicas de la ciberseguridad.

Para proteger un sistema es necesario comprender cómo se comunica.

## 17.1. Superficie de ataque

La superficie de ataque está formada por los puntos mediante los cuales un sistema podría ser alcanzado o interactuar con otros sistemas.

Puede incluir:

- Servicios de red.
- Interfaces administrativas.
- Aplicaciones web.
- Protocolos habilitados.
- Dispositivos conectados.
- Configuraciones expuestas.

## 17.2. Segmentación

La segmentación permite separar redes o grupos de dispositivos.

Puede utilizar:

- VLAN.
- Subredes IP.
- Routers.
- Firewalls.
- Controles de acceso.

Una VLAN proporciona segmentación de capa 2, pero no sustituye automáticamente los controles de seguridad entre segmentos.

## 17.3. Principio de mínimo privilegio

Consiste en otorgar únicamente los permisos y accesos necesarios para cumplir una función.

En redes puede aplicarse mediante reglas que limiten qué sistemas pueden comunicarse y qué servicios pueden utilizar.

## 17.4. Cifrado en tránsito

El cifrado en tránsito protege la información durante su comunicación.

Tecnologías relevantes incluyen:

- TLS.
- SSH.
- IPsec.
- Protocolos VPN seguros.

El cifrado no elimina todos los riesgos.

También deben protegerse los extremos, las claves y los mecanismos de autenticación.

## 17.5. Ataques asociados a redes

### ARP Spoofing

Consiste en enviar información ARP engañosa para alterar asociaciones IP-MAC en determinados entornos IPv4.

Puede facilitar la interceptación o interrupción de comunicaciones si no existen controles adecuados.

### DNS Spoofing

Consiste en manipular respuestas o información de resolución DNS para dirigir a los usuarios hacia destinos no previstos.

### IP Spoofing

Consiste en falsificar la dirección IP de origen de determinados paquetes.

### DoS

Un ataque de denegación de servicio intenta afectar la disponibilidad de un sistema o servicio.

### DDoS

Un ataque distribuido de denegación de servicio utiliza múltiples fuentes para generar tráfico o solicitudes que afectan la disponibilidad del objetivo.

### Man-in-the-Middle

Describe escenarios en los que un tercero se interpone en una comunicación para observarla o modificarla.

Los mecanismos criptográficos correctamente implementados ayudan a reducir estos riesgos.

## 17.6. Medidas defensivas

Algunas medidas fundamentales son:

1. Actualizar sistemas y servicios.
2. Deshabilitar servicios innecesarios.
3. Utilizar firewalls.
4. Segmentar redes.
5. Proteger credenciales.
6. Utilizar protocolos cifrados.
7. Supervisar registros.
8. Configurar autenticación robusta.
9. Restringir accesos administrativos.
10. Mantener inventarios de dispositivos y servicios.

---

# 18. Glosario técnico

| Término | Definición |
|---|---|
| Red | Conjunto de dispositivos interconectados |
| Protocolo | Reglas de comunicación |
| Host | Sistema conectado a una red |
| Cliente | Sistema o programa que solicita un servicio |
| Servidor | Sistema o programa que proporciona un servicio |
| NIC | Interfaz de red |
| MAC | Dirección utilizada en tecnologías de enlace |
| IP | Protocolo de direccionamiento y encaminamiento |
| Router | Dispositivo que conecta redes IP |
| Switch | Dispositivo de conmutación de tramas |
| Gateway | Puerta de enlace |
| DNS | Sistema de nombres de dominio |
| DHCP | Protocolo de configuración dinámica |
| TCP | Protocolo de transporte confiable y orientado a conexión |
| UDP | Protocolo de transporte basado en datagramas |
| Puerto | Identificador de extremo de transporte |
| Socket | Interfaz de comunicación utilizada por programas |
| Trama | Unidad de datos de enlace |
| Paquete | Unidad de datos utilizada habitualmente en red |
| Segmento | Unidad de datos TCP |
| MTU | Unidad máxima de transmisión |
| TTL | Campo que limita la permanencia de paquetes IPv4 |
| NAT | Traducción de direcciones de red |
| VLAN | Red local virtual |
| VPN | Red privada virtual |
| TLS | Protocolo criptográfico para proteger comunicaciones |
| Firewall | Sistema de filtrado y control de tráfico |
| Latencia | Tiempo de comunicación |
| Jitter | Variación de latencia |
| Ancho de banda | Capacidad nominal de transmisión |
| Encapsulamiento | Incorporación de información de control por capas |
| Enrutamiento | Selección de caminos hacia redes de destino |

---

# 19. Conclusion general

El estudio de redes informáticas permite comprender cómo se transmite la información entre dispositivos y qué tecnologías intervienen en ese proceso.

Los conocimientos fundamentales de esta unidad incluyen:

- Comprender qué es una red.
- Reconocer tipos y topologías.
- Diferenciar switches, routers y otros dispositivos.
- Entender direcciones MAC e IP.
- Comprender los modelos OSI y TCP/IP.
- Identificar las funciones de cada capa.
- Diferenciar TCP y UDP.
- Entender los puertos y sockets.
- Reconocer protocolos de aplicación.
- Comprender encapsulamiento y enrutamiento.
- Analizar una comunicación completa.
- Utilizar herramientas básicas de diagnóstico.
- Relacionar los conceptos de redes con la seguridad informática.

Estos fundamentos permiten avanzar posteriormente hacia temas como análisis de tráfico, administración de sistemas, seguridad de redes, criptografía, monitoreo y evaluación de vulnerabilidades.

---

# Referencias técnicas recomendadas

- [RFC 791 — Internet Protocol (IPv4)](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 8200 — IPv6 Specification](https://www.rfc-editor.org/rfc/rfc8200)
- [RFC 9293 — Transmission Control Protocol (TCP)](https://www.rfc-editor.org/rfc/rfc9293)
- [RFC 768 — User Datagram Protocol (UDP)](https://www.rfc-editor.org/rfc/rfc768)
- [RFC 1034 — DNS Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034)
- [RFC 1035 — DNS Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 2131 — Dynamic Host Configuration Protocol](https://www.rfc-editor.org/rfc/rfc2131)
- [RFC 826 — Address Resolution Protocol](https://www.rfc-editor.org/rfc/rfc826)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [IANA — Service Name and Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
