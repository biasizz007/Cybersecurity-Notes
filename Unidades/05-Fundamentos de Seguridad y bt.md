
# Unidad 5 — Fundamentos de Seguridad Informática y Blue Team

> **Área:** Ciberseguridad defensiva / Blue Team  
> **Objetivo:** Comprender los principios de seguridad informática y aplicarlos a la protección de activos, evaluación de riesgos, control de accesos, monitoreo y defensa de sistemas.

---

# Índice

1. Introducción a la seguridad informática y Blue Team
2. Tríada CIA: confidencialidad, integridad y disponibilidad
3. Principios fundamentales de seguridad
4. Activos, amenazas, vulnerabilidades y riesgos
5. Evaluación y tratamiento de riesgos
6. Clasificación y protección de la información
7. Identidad, autenticación y autorización
8. Modelos de control de acceso
9. Defensa en profundidad y Zero Trust
10. Hardening y protección de sistemas
11. Seguridad de endpoints, redes y servidores
12. Gestión de vulnerabilidades
13. Monitoreo de seguridad y análisis de logs
14. Introducción a SOC, SIEM, EDR y XDR
15. Detección de amenazas y MITRE ATT&CK
16. Gestión y respuesta a incidentes
17. Indicadores de compromiso y comportamiento
18. Controles de seguridad y métricas defensivas
19. Casos prácticos de Blue Team
20. Laboratorios defensivos
21. Glosario
22. Referencias técnicas

---

# 1. Introducción a la seguridad informática y Blue Team

## 1.1. ¿Qué es la seguridad informática?

La seguridad informática comprende los procesos, tecnologías, políticas y controles destinados a proteger sistemas, redes, aplicaciones e información frente a amenazas.

Busca reducir la probabilidad y el impacto de incidentes que comprometan:

- Confidencialidad.
- Integridad.
- Disponibilidad.
- Autenticidad.
- Trazabilidad.
- Continuidad operativa.

La seguridad informática no consiste únicamente en impedir accesos no autorizados.

También incluye detectar incidentes, limitar sus consecuencias y recuperar los servicios afectados.

## 1.2. ¿Qué es Blue Team?

Blue Team es el conjunto de funciones, profesionales y prácticas orientadas a defender sistemas y organizaciones frente a amenazas.

Entre sus responsabilidades se encuentran:

- Monitorear eventos de seguridad.
- Analizar alertas.
- Investigar actividades sospechosas.
- Detectar intrusiones.
- Gestionar vulnerabilidades.
- Aplicar controles de protección.
- Participar en la respuesta a incidentes.
- Mejorar la postura de seguridad.

Blue Team no es sinónimo exclusivo de SOC.

Un equipo defensivo puede incluir especialistas en:

- Seguridad de redes.
- Seguridad de endpoints.
- Ingeniería de detección.
- Seguridad en la nube.
- Gestión de identidades.
- Respuesta a incidentes.
- Análisis forense.
- Threat intelligence.
- Gestión de vulnerabilidades.

## 1.3. Red Team, Blue Team y Purple Team

| Equipo | Función principal |
|---|---|
| Red Team | Simular acciones adversarias autorizadas para evaluar defensas |
| Blue Team | Proteger, monitorear, detectar y responder |
| Purple Team | Favorecer la colaboración y mejora entre capacidades ofensivas y defensivas |

El objetivo del Blue Team no es simplemente bloquear todo.

Debe proteger los activos sin impedir innecesariamente el funcionamiento de la organización.

## 1.4. Ciclo operativo de defensa

```text
                PREVENIR
                   |
                   v
                DETECTAR
                   |
                   v
                ANALIZAR
                   |
                   v
                RESPONDER
                   |
                   v
                RECUPERAR
                   |
                   v
                MEJORAR
                   |
                   +------> PREVENIR
```

Estas actividades no siempre ocurren de forma estrictamente secuencial.

Por ejemplo, el monitoreo continúa mientras se responde a un incidente.

## 1.5. ¿Qué hace un analista SOC?

SOC significa Security Operations Center.

Un analista SOC puede:

1. Recibir una alerta.
2. Verificar su origen.
3. Consultar eventos relacionados.
4. Identificar activos y usuarios afectados.
5. Determinar si existe actividad sospechosa.
6. Evaluar la gravedad.
7. Documentar hallazgos.
8. Escalar o ejecutar acciones autorizadas.
9. Registrar el resultado.

### Ejemplo

Un sistema genera una alerta por múltiples intentos fallidos de autenticación.

El analista no debería concluir automáticamente que existe un ataque.

Primero necesita investigar:

- ¿Qué usuario está involucrado?
- ¿Cuántos intentos ocurrieron?
- ¿Desde qué direcciones IP?
- ¿Durante cuánto tiempo?
- ¿Hubo un inicio de sesión exitoso posterior?
- ¿El comportamiento coincide con la actividad habitual?
- ¿Existen otras alertas relacionadas?

**Principio fundamental del Blue Team: una alerta es una señal que requiere evaluación, no una prueba automática de compromiso.**

---

# 2. Tríada CIA: confidencialidad, integridad y disponibilidad

## 2.1. Importancia operativa

La tríada CIA es un modelo para identificar qué propiedades de seguridad deben protegerse.

Desde Blue Team, también sirve para analizar el impacto de un incidente.

## 2.2. Confidencialidad

Busca impedir la divulgación de información a entidades no autorizadas.

### Controles defensivos

- Cifrado.
- Gestión de identidades.
- Controles de acceso.
- Clasificación de información.
- DLP.
- Segmentación de redes.
- Protección de credenciales.

DLP significa Data Loss Prevention.

Las soluciones DLP pueden ayudar a detectar o impedir determinadas transferencias no autorizadas de información.

### Ejemplo Blue Team

Una cuenta comienza a descargar una cantidad inusual de documentos.

El analista investiga:

1. Identidad de la cuenta.
2. Dispositivo utilizado.
3. Archivos consultados.
4. Horario.
5. Destino de la transferencia.
6. Justificación empresarial.
7. Existencia de otras señales de compromiso.

### Evidencias posibles

- Logs de acceso.
- Eventos de descarga.
- Registros de proxy.
- Eventos DLP.
- Actividad del proveedor de identidad.

## 2.3. Integridad

Busca evitar modificaciones no autorizadas o no detectadas.

### Controles defensivos

- Hashes criptográficos.
- Firmas digitales.
- Control de versiones.
- Restricción de permisos.
- Monitoreo de integridad.
- Registros de auditoría.

### FIM

File Integrity Monitoring permite detectar cambios en archivos supervisados.

Ejemplos:

- Archivos de configuración.
- Binarios críticos.
- Scripts administrativos.
- Archivos de políticas.

### Ejemplo Blue Team

Un archivo de configuración crítico cambia fuera de una ventana de mantenimiento.

El analista verifica:

- Qué archivo cambió.
- Cuándo.
- Qué proceso lo modificó.
- Qué usuario ejecutó la acción.
- Si existe un cambio autorizado.
- Si hubo actividad sospechosa asociada.

Un cambio no autorizado no siempre implica malware, pero debe investigarse según su criticidad.

## 2.4. Disponibilidad

Busca mantener accesibles los servicios y datos cuando se necesitan.

### Controles defensivos

- Redundancia.
- Copias de seguridad.
- Monitoreo.
- Balanceo de carga.
- Protección contra DDoS.
- Planes de continuidad.
- Recuperación ante desastres.

### Ejemplo Blue Team

Un servidor comienza a recibir un volumen extraordinario de solicitudes.

El analista revisa:

- Tráfico por segundo.
- Orígenes.
- Protocolos.
- Errores.
- Consumo de CPU.
- Memoria.
- Conexiones concurrentes.
- Disponibilidad real del servicio.

No todo aumento de tráfico constituye un ataque.

## 2.5. Relación CIA con incidentes

| Evento | Confidencialidad | Integridad | Disponibilidad |
|---|---|---|---|
| Filtración de datos | Alta afectación | Posible | Posible |
| Modificación maliciosa de registros | Posible | Alta afectación | Posible |
| Ransomware | Posible | Posible | Alta afectación |
| DDoS | Generalmente indirecta | Generalmente indirecta | Alta afectación |
| Robo de credenciales | Potencial | Potencial | Potencial |

El impacto concreto depende del incidente.

---

# 3. Principios fundamentales de seguridad

## 3.1. Mínimo privilegio

Cada identidad debe disponer únicamente de los permisos necesarios para realizar su función.

### Ejemplo

Un usuario que solamente necesita consultar reportes no debería tener permisos para eliminar bases de datos.

### Aplicación Blue Team

Revisar:

- Usuarios administradores.
- Permisos excesivos.
- Cuentas de servicio.
- Accesos heredados.
- Privilegios temporales.
- Cuentas sin uso.

## 3.2. Necesidad de conocer

Need to Know significa que el acceso a información debe limitarse a quienes la necesitan para cumplir funciones autorizadas.

Tener una cuenta válida no implica necesitar acceso a toda la información.

## 3.3. Separación de funciones

Consiste en distribuir responsabilidades críticas entre diferentes personas o roles.

### Ejemplo

Una persona solicita un cambio de permisos.

Otra persona lo aprueba.

Esto reduce riesgos de abuso y errores.

## 3.4. Denegación por defecto

El acceso debe denegarse salvo que exista una autorización explícita.

Ejemplo:

```text
Regla 1: permitir HTTPS hacia servidor web
Regla 2: permitir SSH desde red administrativa
Regla final: denegar tráfico restante
```

Una política de este tipo requiere identificar previamente las comunicaciones necesarias.

## 3.5. Fail Secure

Ante determinados fallos, un sistema debe mantener un estado que no exponga indebidamente los recursos.

Ejemplo:

Un sistema de control de acceso no debería conceder privilegios administrativos cuando falla la verificación de permisos.

No debe confundirse con requisitos de seguridad física, donde ciertas salidas de emergencia necesitan permitir evacuación aunque fallen sistemas electrónicos.

## 3.6. Economía de mecanismos

Los diseños de seguridad deberían evitar complejidad innecesaria.

Los sistemas excesivamente complejos pueden ser difíciles de:

- Auditar.
- Configurar.
- Actualizar.
- Monitorear.
- Mantener.

## 3.7. Defensa en profundidad

Consiste en utilizar varias capas complementarias de seguridad.

```text
                    DATOS
                      |
                 APLICACIÓN
                      |
                   SISTEMA
                      |
                    RED
                      |
                  IDENTIDAD
                      |
               SEGURIDAD FÍSICA
```

El esquema es conceptual: las capas se complementan, no necesariamente se organizan en ese orden.

## 3.8. Seguridad por diseño

Security by Design implica incorporar requisitos de seguridad desde las primeras etapas del desarrollo o implementación.

No esperar a que aparezca un incidente para agregar controles.

## 3.9. Seguridad por defecto

Security by Default implica que las configuraciones iniciales deben evitar exposiciones innecesarias.

Ejemplos:

- Servicios innecesarios deshabilitados.
- Permisos restrictivos.
- Protocolos seguros.
- Configuraciones administrativas protegidas.

## 3.10. Zero Trust

Zero Trust es un enfoque de seguridad que evita otorgar confianza implícita por ubicación de red.

Principios asociados:

- Verificación explícita.
- Acceso de mínimo privilegio.
- Evaluación del contexto.
- Protección de recursos.
- Consideración de posibles compromisos.

No es simplemente instalar una VPN o un firewall.

---

# 4. Activos, amenazas, vulnerabilidades y riesgos

## 4.1. Activo

Un activo es cualquier recurso con valor para la organización.

Ejemplos:

- Bases de datos.
- Servidores.
- Credenciales.
- Aplicaciones.
- Dispositivos.
- Infraestructura.
- Información.
- Servicios empresariales.

## 4.2. Inventario de activos

Un Blue Team necesita saber qué está protegiendo.

Un inventario puede incluir:

| Campo | Ejemplo |
|---|---|
| Identificador | SRV-WEB-01 |
| Tipo | Servidor |
| Función | Aplicación web |
| Sistema operativo | Linux |
| Propietario | Equipo de infraestructura |
| Criticidad | Alta |
| Exposición | Internet |
| Controles | EDR, firewall, monitoreo |

Sin inventario, resulta más difícil priorizar vulnerabilidades y comprender el impacto de incidentes.

## 4.3. Amenaza

Es un evento, actor o circunstancia capaz de producir daño.

Ejemplos:

- Atacante externo.
- Usuario interno malicioso.
- Error humano.
- Malware.
- Falla eléctrica.
- Desastre natural.

## 4.4. Vulnerabilidad

Es una debilidad que puede facilitar un compromiso.

Ejemplos:

- Software vulnerable.
- Contraseña débil.
- Configuración incorrecta.
- Servicio expuesto.
- Permisos excesivos.
- Falta de actualizaciones.

## 4.5. Exposición

La exposición describe la situación en la que un activo o servicio puede ser alcanzado por determinadas amenazas.

Ejemplo:

Un servidor vulnerable accesible desde Internet presenta una exposición diferente de un servidor aislado y protegido por controles adicionales.

## 4.6. Riesgo

El riesgo combina incertidumbre y consecuencias sobre objetivos o activos.

En una aproximación básica:

```text
Riesgo ≈ Probabilidad × Impacto
```

Esta fórmula es una simplificación didáctica.

Las metodologías profesionales pueden utilizar escalas cualitativas, modelos cuantitativos y factores adicionales.

## 4.7. Diferencia entre conceptos

| Concepto | Pregunta |
|---|---|
| Activo | ¿Qué queremos proteger? |
| Amenaza | ¿Qué puede causar daño? |
| Vulnerabilidad | ¿Qué debilidad existe? |
| Exposición | ¿Cómo puede alcanzarse el activo? |
| Riesgo | ¿Qué consecuencias podrían producirse y con qué posibilidad? |
| Control | ¿Qué medida reduce el riesgo? |

## 4.8. Ejemplo completo

Un servidor tiene una aplicación desactualizada.

```text
Activo:
Servidor de aplicación.

Amenaza:
Explotación por un atacante.

Vulnerabilidad:
Versión vulnerable de software.

Exposición:
Servicio accesible desde Internet.

Impacto:
Interrupción o acceso no autorizado.

Controles:
Actualización, restricción de acceso,
monitoreo y protección adicional.
```

---

# 5. Evaluación y tratamiento de riesgos

## 5.1. Identificación

Se identifican:

1. Activos.
2. Amenazas.
3. Vulnerabilidades.
4. Controles existentes.
5. Posibles consecuencias.

## 5.2. Análisis

Se estima la probabilidad y el impacto.

Ejemplo de escala:

| Nivel | Probabilidad | Impacto |
|---|---|---|
| 1 | Muy baja | Menor |
| 2 | Baja | Limitado |
| 3 | Media | Moderado |
| 4 | Alta | Grave |
| 5 | Muy alta | Crítico |

## 5.3. Matriz de riesgo

Ejemplo didáctico:

```text
Riesgo = Probabilidad × Impacto
```

Si:

```text
Probabilidad = 4
Impacto = 5
```

Entonces:

```text
Riesgo = 20
```

El valor no tiene significado universal.

Cada organización debe definir criterios de aceptación y prioridades.

## 5.4. Tratamiento del riesgo

### Mitigar

Implementar controles para reducir probabilidad o impacto.

### Evitar

Eliminar la actividad o condición que genera el riesgo.

### Transferir o compartir

Distribuir determinadas consecuencias mediante acuerdos, seguros u otros mecanismos.

No elimina necesariamente la responsabilidad.

### Aceptar

Asumir formalmente el riesgo residual dentro de criterios aprobados.

## 5.5. Riesgo residual

Es el riesgo que permanece después de aplicar controles.

No existe seguridad absoluta.

## 5.6. Priorización Blue Team

No todas las vulnerabilidades tienen la misma urgencia.

Conviene considerar:

- Criticidad del activo.
- Exposición.
- Explotación conocida.
- Disponibilidad de parches.
- Controles compensatorios.
- Impacto empresarial.
- Evidencia de explotación activa.

---

# 6. Clasificación y protección de la información

## 6.1. ¿Por qué clasificar información?

Porque no todos los datos requieren exactamente los mismos controles.

Ejemplo de clasificación:

| Nivel | Ejemplo |
|---|---|
| Pública | Información publicada oficialmente |
| Interna | Documentación operativa |
| Confidencial | Datos comerciales sensibles |
| Restringida | Secretos críticos o credenciales |

Los nombres y criterios pueden variar según la organización.

## 6.2. Datos en reposo

Data at Rest.

Información almacenada en:

- Discos.
- Bases de datos.
- Copias de seguridad.
- Almacenamiento en nube.

Controles:

- Cifrado.
- Permisos.
- Gestión de claves.
- Respaldos.
- Monitoreo de accesos.

## 6.3. Datos en tránsito

Data in Transit.

Información que circula entre sistemas.

Controles:

- TLS.
- VPN.
- SSH.
- Protocolos seguros.
- Validación de certificados.

## 6.4. Datos en uso

Data in Use.

Información procesada en memoria o utilizada activamente.

Su protección requiere considerar:

- Aislamiento de procesos.
- Control de privilegios.
- Seguridad de aplicaciones.
- Protección del sistema operativo.
- Tecnologías especializadas cuando corresponda.

## 6.5. Copias de seguridad

Las copias de seguridad contribuyen principalmente a disponibilidad y recuperación.

Deben considerarse:

- Frecuencia.
- Retención.
- Cifrado.
- Separación de credenciales.
- Protección contra modificaciones.
- Pruebas de restauración.

## 6.6. Regla 3-2-1

Como guía tradicional:

- Tres copias de la información.
- Dos tipos de medios o sistemas.
- Una copia fuera del entorno principal.

Es una estrategia orientativa, no una garantía suficiente frente a todos los escenarios.

Para ransomware también son importantes las copias inmutables u offline y las pruebas de recuperación.

## 6.7. RPO y RTO

### RPO — Recovery Point Objective

Máxima pérdida de datos tolerable expresada como tiempo.

### RTO — Recovery Time Objective

Tiempo objetivo para recuperar un servicio.

Ejemplo:

```text
RPO: 1 hora
RTO: 4 horas
```

La organización busca limitar la pérdida de datos a una hora y recuperar el servicio dentro de cuatro horas, conforme a sus objetivos definidos.

---

# 7. Identidad, autenticación y autorización

## 7.1. Identificación

Una entidad declara una identidad.

Ejemplo:

```text
Usuario: analista01
```

## 7.2. Autenticación

El sistema verifica la identidad declarada mediante mecanismos apropiados.

Ejemplos:

- Contraseña.
- Llave de seguridad.
- Certificado.
- Biometría.
- Autenticador.

## 7.3. Autorización

El sistema determina qué operaciones están permitidas.

Ejemplo:

Un analista puede consultar alertas, pero no necesariamente modificar reglas críticas del firewall.

## 7.4. Auditoría

Permite registrar acciones relevantes.

Ejemplos:

- Inicio de sesión.
- Acceso a información.
- Cambio de privilegios.
- Modificación de configuración.
- Eliminación de registros.

## 7.5. AAA

AAA es un modelo que agrupa:

- Authentication.
- Authorization.
- Accounting.

Accounting se refiere al registro o seguimiento del uso de recursos y acciones.

## 7.6. Factores de autenticación

| Factor | Ejemplo |
|---|---|
| Algo que sabés | Contraseña |
| Algo que tenés | Llave de seguridad |
| Algo que sos | Huella digital |

## 7.7. MFA

Multi-Factor Authentication utiliza factores de diferentes categorías.

Ejemplo:

```text
Contraseña + llave de seguridad
```

No todos los métodos MFA ofrecen la misma resistencia al phishing.

## 7.8. Riesgos de autenticación

- Reutilización de contraseñas.
- Credenciales filtradas.
- Phishing.
- Robo de sesiones.
- Fatiga de notificaciones MFA.
- Cuentas sin MFA.
- Tokens mal protegidos.

## 7.9. Señales para Blue Team

Un analista puede investigar:

- Múltiples fallos de inicio de sesión.
- Autenticaciones desde ubicaciones inusuales.
- Cambios de MFA.
- Creación de cuentas.
- Elevación de privilegios.
- Inicio de sesión desde dispositivos no reconocidos.

La interpretación requiere contexto y correlación.

---

# 8. Modelos de control de acceso

## 8.1. DAC

Discretionary Access Control.

Permite que propietarios de recursos administren determinados permisos.

## 8.2. MAC

Mandatory Access Control.

Utiliza políticas obligatorias definidas centralmente.

No debe confundirse con direcciones MAC de red.

## 8.3. RBAC

Role-Based Access Control.

Los permisos se asignan a roles.

Ejemplo:

| Rol | Permisos |
|---|---|
| Administrador | Configuración y administración |
| Analista SOC | Consultar e investigar eventos |
| Auditor | Lectura de evidencias |
| Usuario | Acceso a recursos autorizados |

## 8.4. ABAC

Attribute-Based Access Control.

Utiliza atributos de:

- Sujeto.
- Recurso.
- Acción.
- Entorno.

Ejemplo:

Permitir acceso si:

```text
Rol = Analista
Y
Dispositivo = Administrado
Y
Recurso = Panel de alertas
Y
Autenticación = Válida
```

## 8.5. PAM

Privileged Access Management.

Comprende procesos y tecnologías para administrar accesos privilegiados.

Puede incluir:

- Almacenamiento protegido de credenciales.
- Rotación de secretos.
- Acceso temporal.
- Aprobaciones.
- Registro de sesiones.
- Supervisión.

## 8.6. JIT

Just-in-Time Access.

Permite conceder privilegios durante un período limitado cuando son necesarios.

## 8.7. JEA

Just Enough Administration.

Busca proporcionar solamente las capacidades administrativas necesarias para una tarea.

## 8.8. Revisión de accesos

Un proceso defensivo debería comprobar periódicamente:

1. Qué identidades existen.
2. Qué permisos poseen.
3. Si esos permisos siguen siendo necesarios.
4. Si hay cuentas inactivas.
5. Si existen privilegios excesivos.
6. Si los accesos están documentados y aprobados.

---

# 9. Defensa en profundidad y Zero Trust

## 9.1. Modelo de capas defensivas

```text
                USUARIO
                   |
             IDENTIDAD / MFA
                   |
              ACCESO A RED
                   |
                 FIREWALL
                   |
              ENDPOINT / EDR
                   |
               APLICACIÓN
                   |
                  DATOS
```

Cada capa busca reducir determinadas oportunidades de compromiso.

## 9.2. Prevención

Ejemplos:

- Parches.
- MFA.
- Restricción de permisos.
- Hardening.
- Segmentación.
- Filtrado de tráfico.

## 9.3. Detección

Ejemplos:

- Logs.
- Alertas.
- EDR.
- IDS.
- SIEM.
- Monitoreo de integridad.

## 9.4. Respuesta

Ejemplos:

- Aislar un equipo comprometido.
- Revocar sesiones.
- Deshabilitar cuentas.
- Bloquear indicadores confirmados.
- Preservar evidencias.
- Escalar incidentes.

Estas acciones deben ejecutarse de acuerdo con procedimientos y autorizaciones.

## 9.5. Recuperación

Ejemplos:

- Restaurar sistemas.
- Reinstalar equipos comprometidos.
- Rotar credenciales.
- Validar integridad.
- Verificar funcionamiento.
- Monitorear recurrencias.

## 9.6. Zero Trust aplicado

Ejemplo:

Un empleado intenta acceder a una aplicación interna.

El sistema evalúa:

- Identidad.
- MFA.
- Estado del dispositivo.
- Políticas.
- Riesgo contextual.
- Permisos.

El acceso se concede o rechaza según la decisión de autorización.

---

# 10. Hardening y protección de sistemas

## 10.1. ¿Qué es hardening?

Hardening es el proceso de reducir la superficie de ataque de un sistema mediante configuraciones y controles de seguridad.

## 10.2. Superficie de ataque

Comprende los puntos a través de los cuales un sistema puede ser alcanzado o comprometido.

Ejemplos:

- Puertos abiertos.
- Servicios.
- Aplicaciones.
- Interfaces administrativas.
- Cuentas.
- Dependencias.
- Configuraciones.

## 10.3. Medidas de hardening

- Deshabilitar servicios innecesarios.
- Eliminar software no utilizado.
- Aplicar parches.
- Configurar firewall.
- Restringir privilegios.
- Habilitar registros.
- Proteger acceso remoto.
- Aplicar políticas de contraseñas.
- Configurar protección de endpoints.
- Supervisar cambios.

## 10.4. Baselines

Una baseline de seguridad es una configuración de referencia.

Permite comparar sistemas con un estándar esperado.

Ejemplos de referencias:

- CIS Benchmarks.
- Guías de fabricantes.
- Políticas internas.
- Estándares organizacionales.

## 10.5. Configuration Drift

Es la desviación de una configuración respecto de su estado esperado.

Ejemplo:

Un servidor que originalmente tenía SSH limitado a una red administrativa comienza a permitir conexiones desde otras redes.

El Blue Team debe poder identificar cambios relevantes.

## 10.6. Validación

El hardening no termina cuando se aplica una configuración.

Es necesario verificar:

1. Que el control funciona.
2. Que no interrumpe servicios críticos.
3. Que permanece activo.
4. Que los cambios están documentados.
5. Que se monitorean desviaciones.

---

# 11. Seguridad de endpoints, redes y servidores

## 11.1. Endpoint

Un endpoint es un dispositivo o sistema que participa en la infraestructura.

Ejemplos:

- Computadora.
- Servidor.
- Dispositivo móvil.
- Estación de trabajo.
- Máquina virtual.

## 11.2. Protección de endpoints

Controles habituales:

- Antimalware.
- EDR.
- Cifrado de disco.
- Parches.
- Firewall local.
- Control de aplicaciones.
- Gestión de dispositivos.
- Restricción de privilegios.

## 11.3. Seguridad de redes

Incluye:

- Firewalls.
- Segmentación.
- ACL.
- IDS/IPS.
- VPN.
- Control de acceso a red.
- Monitoreo.
- Protección de infraestructura.

## 11.4. IDS

Intrusion Detection System.

Busca detectar actividad potencialmente maliciosa.

Puede generar alertas para investigación.

## 11.5. IPS

Intrusion Prevention System.

Puede detectar y bloquear determinadas actividades según políticas.

## 11.6. NIDS y HIDS

### NIDS

Network Intrusion Detection System.

Analiza tráfico o eventos de red.

### HIDS

Host Intrusion Detection System.

Analiza eventos o condiciones de un sistema individual.

## 11.7. Seguridad de servidores

Debe considerar:

- Servicios expuestos.
- Usuarios privilegiados.
- Configuración.
- Parches.
- Acceso remoto.
- Logs.
- Respaldos.
- Integridad.
- Disponibilidad.

---

# 12. Gestión de vulnerabilidades

## 12.1. Objetivo

La gestión de vulnerabilidades busca identificar, evaluar, priorizar y reducir debilidades de seguridad.

No consiste únicamente en ejecutar un escáner.

## 12.2. Ciclo

```text
INVENTARIAR
    |
    v
IDENTIFICAR
    |
    v
EVALUAR
    |
    v
PRIORIZAR
    |
    v
REMEDIAR
    |
    v
VERIFICAR
    |
    v
MONITOREAR
```

## 12.3. CVE

Common Vulnerabilities and Exposures.

Es un sistema de identificación de vulnerabilidades divulgadas públicamente.

Ejemplo de formato:

```text
CVE-AAAA-NNNN
```

El identificador no indica por sí solo la gravedad.

## 12.4. CVSS

Common Vulnerability Scoring System.

Permite expresar características y severidad de vulnerabilidades mediante un sistema de puntuación.

La interpretación depende de la versión y del vector utilizado.

CVSS no sustituye el análisis del riesgo organizacional.

## 12.5. CISA KEV

Known Exploited Vulnerabilities Catalog.

Es un catálogo de vulnerabilidades con evidencia de explotación conocida, mantenido por CISA.

Puede ayudar a priorizar acciones defensivas.

## 12.6. EPSS

Exploit Prediction Scoring System.

Estima probabilidades relacionadas con explotación observada en un período determinado, utilizando un modelo estadístico.

No equivale a CVSS.

## 12.7. Priorización

Ejemplo:

Una vulnerabilidad de severidad alta en un servidor aislado puede requerir un tratamiento diferente al de una vulnerabilidad explotada activamente en un servicio crítico expuesto a Internet.

El contexto importa.

## 12.8. Remediación

Puede incluir:

- Aplicar parches.
- Actualizar software.
- Cambiar configuraciones.
- Deshabilitar componentes.
- Restringir acceso.
- Implementar controles compensatorios.

## 12.9. Verificación

Después de corregir una vulnerabilidad debe comprobarse que:

- La medida se aplicó.
- El sistema sigue funcionando.
- La exposición se redujo.
- No quedaron activos similares sin tratar.

---

# 13. Monitoreo de seguridad y análisis de logs

## 13.1. ¿Qué es un log?

Un log es un registro de eventos generado por un sistema, aplicación o dispositivo.

Puede contener:

- Fecha.
- Hora.
- Fuente.
- Usuario.
- Dirección IP.
- Acción.
- Resultado.
- Identificador de evento.

## 13.2. Fuentes de logs

| Fuente | Información |
|---|---|
| Windows Event Logs | Eventos del sistema y seguridad |
| Syslog | Eventos de sistemas y dispositivos |
| Firewall | Tráfico permitido o bloqueado |
| DNS | Consultas y respuestas |
| Proxy | Acceso a recursos |
| VPN | Conexiones remotas |
| EDR | Actividad de endpoints |
| IAM | Autenticaciones y cambios de identidad |
| Servidor web | Solicitudes HTTP |

## 13.3. Ejemplo de evento

```text
2026-10-19T10:15:30Z
host=SRV-01
event=login_failed
user=analista01
source_ip=192.0.2.25
```

Es un evento ilustrativo.

## 13.4. ¿Cómo analiza un log un Blue Team?

1. Identifica el evento.
2. Verifica la hora.
3. Identifica el activo.
4. Determina el usuario.
5. Consulta eventos relacionados.
6. Busca patrones.
7. Evalúa contexto.
8. Documenta conclusiones.

## 13.5. Correlación

La correlación relaciona eventos que individualmente pueden parecer normales.

Ejemplo:

```text
10:00 - Múltiples fallos de autenticación
10:05 - Inicio de sesión exitoso
10:07 - Cambio de permisos
10:09 - Descarga masiva de archivos
```

La secuencia puede justificar una investigación de mayor prioridad.

No demuestra por sí sola un compromiso.

## 13.6. Falsos positivos

Una alerta indica actividad sospechosa, pero la investigación determina que no corresponde a la amenaza prevista.

## 13.7. Falsos negativos

Existe actividad maliciosa que el sistema de detección no identifica.

## 13.8. Calidad de los logs

Un programa defensivo debe considerar:

- Cobertura.
- Sincronización horaria.
- Integridad.
- Retención.
- Protección de accesos.
- Normalización.
- Disponibilidad.
- Privacidad.

---

# 14. Introducción a SOC, SIEM, EDR y XDR

## 14.1. SOC

Security Operations Center.

Es una función organizacional dedicada al monitoreo, detección, investigación y respuesta.

Puede funcionar mediante:

- Equipos internos.
- Servicios administrados.
- Modelos híbridos.

## 14.2. SIEM

Security Information and Event Management.

Permite centralizar, procesar y correlacionar eventos de múltiples fuentes.

Funciones posibles:

- Recolección.
- Normalización.
- Búsqueda.
- Correlación.
- Alertas.
- Dashboards.
- Investigación.

## 14.3. Flujo SIEM

```text
FIREWALL -----\
WINDOWS -------\
LINUX ----------> SIEM ---> REGLAS ---> ALERTAS
DNS -----------/                        |
EDR ----------/                         v
                                    ANALISTA SOC
```

## 14.4. EDR

Endpoint Detection and Response.

Se enfoca en observar y responder a actividad de endpoints.

Puede proporcionar:

- Telemetría de procesos.
- Eventos de archivos.
- Conexiones.
- Actividad de usuarios.
- Alertas.
- Capacidades de respuesta.

Las funciones dependen del producto.

## 14.5. XDR

Extended Detection and Response.

Busca integrar telemetría y capacidades de detección o respuesta en múltiples dominios.

Por ejemplo:

- Endpoint.
- Identidad.
- Correo.
- Red.
- Nube.

## 14.6. SOAR

Security Orchestration, Automation and Response.

Permite coordinar herramientas y automatizar determinadas tareas de seguridad.

Ejemplos:

- Enriquecimiento de alertas.
- Creación de tickets.
- Consulta de indicadores.
- Ejecución de procedimientos aprobados.

Las automatizaciones de contención requieren controles para evitar interrupciones por errores o falsos positivos.

## 14.7. Diferencias

| Tecnología | Función |
|---|---|
| SIEM | Centralizar y correlacionar eventos |
| EDR | Detectar y responder en endpoints |
| XDR | Integrar detección y respuesta entre dominios |
| SOAR | Orquestar y automatizar procedimientos |
| IDS | Detectar actividad sospechosa |
| IPS | Detectar y prevenir determinadas actividades |

---

# 15. Detección de amenazas y MITRE ATT&CK

## 15.1. ¿Qué es MITRE ATT&CK?

MITRE ATT&CK es una base de conocimiento que documenta tácticas y técnicas utilizadas por adversarios.

Permite describir comportamientos observados y relacionarlos con objetivos adversarios.

## 15.2. Tácticas

Una táctica representa el objetivo que busca alcanzar un adversario.

Ejemplos:

- Initial Access.
- Execution.
- Persistence.
- Privilege Escalation.
- Defense Evasion.
- Credential Access.
- Discovery.
- Lateral Movement.
- Collection.
- Command and Control.
- Exfiltration.
- Impact.

La matriz también contiene otras tácticas y su estructura puede evolucionar.

## 15.3. Técnicas

Una técnica describe cómo puede realizarse determinada actividad.

Ejemplo:

Un adversario puede intentar obtener credenciales mediante distintas técnicas.

## 15.4. Subtécnicas

Permiten describir variantes más específicas.

## 15.5. Uso defensivo

Blue Team puede utilizar ATT&CK para:

- Clasificar detecciones.
- Identificar brechas de cobertura.
- Diseñar pruebas.
- Investigar incidentes.
- Comunicar hallazgos.
- Priorizar mejoras.

## 15.6. Ejemplo

Se observa un inicio de sesión remoto anómalo.

El analista puede investigar si existe evidencia compatible con técnicas documentadas de uso de cuentas válidas.

Pero no debe asignar una técnica solamente porque el evento resulte extraño.

Debe existir evidencia suficiente del comportamiento.

---

# 16. Gestión y respuesta a incidentes

## 16.1. Evento frente a incidente

### Evento

Suceso observable dentro de un sistema.

### Incidente

Evento o conjunto de eventos que afecta o amenaza de manera significativa la seguridad y requiere tratamiento conforme a criterios definidos.

No todos los eventos son incidentes.

## 16.2. Ciclo de respuesta

Un modelo didáctico comprende:

1. Preparación.
2. Detección.
3. Análisis.
4. Contención.
5. Erradicación.
6. Recuperación.
7. Lecciones aprendidas.

Los marcos actuales pueden organizar estas funciones de otra manera.

## 16.3. Preparación

Incluye:

- Procedimientos.
- Roles.
- Contactos.
- Herramientas.
- Accesos.
- Respaldos.
- Capacitación.
- Ejercicios.

## 16.4. Detección

Se identifican señales de actividad sospechosa.

Fuentes:

- SIEM.
- EDR.
- IDS.
- Usuarios.
- Monitoreo.
- Inteligencia de amenazas.

## 16.5. Análisis

Busca determinar:

- Qué ocurrió.
- Cuándo.
- Cómo.
- Qué activos fueron afectados.
- Qué información está comprometida.
- Qué evidencia existe.
- Qué acciones son necesarias.

## 16.6. Contención

Busca limitar el impacto.

Ejemplos:

- Aislamiento de endpoints.
- Restricción de comunicaciones.
- Revocación de sesiones.
- Deshabilitación de credenciales.
- Bloqueo de infraestructura maliciosa confirmada.

Debe considerarse el riesgo de interrumpir servicios o destruir evidencias.

## 16.7. Erradicación

Busca eliminar la causa y los componentes asociados al compromiso.

Puede incluir:

- Eliminar persistencia maliciosa.
- Corregir vulnerabilidades.
- Reconstruir sistemas.
- Rotar secretos.
- Corregir configuraciones.

## 16.8. Recuperación

Busca restaurar operaciones de manera segura.

Incluye:

- Restauración.
- Validación.
- Monitoreo.
- Confirmación de integridad.
- Reincorporación controlada.

## 16.9. Lecciones aprendidas

Permiten identificar:

- Qué funcionó.
- Qué falló.
- Qué controles faltaban.
- Qué detecciones deben mejorarse.
- Qué procedimientos necesitan cambios.

## 16.10. Documentación de incidentes

Una investigación debería registrar:

```text
Identificador:
Fecha:
Analista:
Fuente:
Activos:
Descripción:
Evidencias:
Impacto:
Hipótesis:
Acciones:
Resultado:
Estado:
```

Las hipótesis deben diferenciarse claramente de los hechos confirmados.

---

# 17. Indicadores de compromiso y comportamiento

## 17.1. IOC

Indicator of Compromise.

Es un artefacto o dato que puede asociarse con actividad maliciosa.

Ejemplos:

- Hash de archivo malicioso.
- Dominio relacionado con una campaña.
- Dirección IP utilizada en un incidente.
- Ruta de archivo.
- Identificador de proceso o artefacto.

Un IOC aislado puede tener limitaciones y producir falsos positivos.

## 17.2. IOA

Indicator of Attack.

Describe comportamientos que pueden indicar una técnica o secuencia de ataque.

Ejemplos:

- Uso anómalo de herramientas administrativas.
- Modificaciones sospechosas de persistencia.
- Secuencias de autenticación y elevación de privilegios.
- Actividad de procesos inesperada.

## 17.3. IOC frente a IOA

| IOC | IOA |
|---|---|
| Se enfoca en artefactos | Se enfoca en comportamiento |
| Puede ser específico de una campaña | Puede describir técnicas más generales |
| Puede cambiar rápidamente | Puede resultar más resistente a cambios superficiales |
| Requiere contexto | También requiere contexto |

## 17.4. Enriquecimiento

Enriquecer una alerta consiste en incorporar contexto.

Ejemplos:

- Propietario del activo.
- Criticidad.
- Reputación de indicadores.
- Eventos históricos.
- Usuario asociado.
- Procesos.
- Relaciones con otras alertas.

---

# 18. Controles de seguridad y métricas defensivas

## 18.1. Controles preventivos

Ejemplos:

- MFA.
- Parches.
- Firewall.
- Mínimo privilegio.
- Hardening.

## 18.2. Controles detectivos

Ejemplos:

- SIEM.
- EDR.
- IDS.
- Auditoría.
- Monitoreo de integridad.

## 18.3. Controles correctivos

Ejemplos:

- Restauración.
- Corrección de configuraciones.
- Rotación de credenciales.
- Reconstrucción de sistemas.

## 18.4. Controles compensatorios

Se utilizan para reducir riesgos cuando un control previsto no puede implementarse de manera inmediata.

Ejemplo:

Una aplicación no puede actualizarse temporalmente.

Se limita su acceso mediante segmentación y reglas restrictivas mientras se planifica la remediación.

## 18.5. Métricas Blue Team

### MTTD

Mean Time to Detect.

Tiempo medio de detección.

### MTTR

Mean Time to Respond o Mean Time to Recover, según la definición utilizada.

Es necesario especificar cuál se está midiendo.

### Cobertura de logs

Porcentaje de activos o fuentes relevantes que generan la telemetría requerida.

### Cobertura de detecciones

Grado en que las detecciones implementadas cubren comportamientos o escenarios definidos.

### Tiempo de remediación

Tiempo transcurrido hasta corregir una vulnerabilidad o condición.

## 18.6. Calidad de métricas

Una métrica debe tener:

- Definición.
- Fuente.
- Período.
- Método de cálculo.
- Limitaciones.

Reducir una métrica no siempre significa mejorar la seguridad si se alteran criterios o se dejan incidentes sin registrar.

---

# 19. Casos prácticos de Blue Team

## Caso 1 — Intentos fallidos de autenticación

### Situación

Un sistema registra:

```text
10:00 - Login failed
10:01 - Login failed
10:02 - Login failed
10:03 - Login successful
```

### Preguntas del analista

1. ¿Qué usuario está involucrado?
2. ¿Desde qué IP?
3. ¿El inicio exitoso provino del mismo origen?
4. ¿Es un dispositivo conocido?
5. ¿Hubo cambios de permisos?
6. ¿Existen otros eventos sospechosos?

### Posibles explicaciones

- Error de contraseña.
- Aplicación con credenciales antiguas.
- Actividad automatizada.
- Intento de acceso no autorizado.

### Conclusión

No se puede confirmar un ataque únicamente con esos cuatro eventos.

---

## Caso 2 — Archivo crítico modificado

### Situación

Un sistema de monitoreo de integridad detecta un cambio inesperado.

### Investigación

- Identificar archivo.
- Consultar usuario.
- Revisar proceso.
- Comparar hash.
- Consultar cambios autorizados.
- Verificar eventos relacionados.

### Posibles respuestas

- Confirmar cambio legítimo.
- Revertir configuración.
- Escalar.
- Aislar el sistema si existe evidencia suficiente y autorización.

---

## Caso 3 — Servicio expuesto

### Situación

Un inventario detecta un servicio administrativo accesible desde Internet.

### Evaluación

- Identificar propietario.
- Verificar necesidad.
- Revisar autenticación.
- Consultar versiones.
- Comprobar políticas.
- Determinar exposición.
- Priorizar corrección.

### Medidas posibles

- Restringir origen.
- Utilizar acceso administrativo protegido.
- Aplicar MFA cuando sea compatible.
- Actualizar software.
- Deshabilitar servicio innecesario.

---

## Caso 4 — Posible exfiltración

### Situación

Se observa una transferencia de datos inusualmente grande hacia un destino externo.

### Investigación

1. Identificar equipo.
2. Identificar usuario.
3. Revisar proceso responsable.
4. Consultar destino.
5. Revisar horarios.
6. Comparar comportamiento histórico.
7. Determinar sensibilidad de los datos.
8. Correlacionar otras alertas.

### Precaución

Las transferencias grandes también pueden corresponder a copias de seguridad, sincronizaciones o actividades legítimas.

---

# 20. Glosario

| Concepto | Definición |
|---|---|
| Blue Team | Funciones de ciberseguridad defensiva |
| SOC | Centro de operaciones de seguridad |
| CIA | Confidencialidad, integridad y disponibilidad |
| Activo | Recurso con valor |
| Amenaza | Evento o actor capaz de causar daño |
| Vulnerabilidad | Debilidad explotable |
| Riesgo | Posibilidad de consecuencias negativas |
| Control | Medida de protección |
| Hardening | Reducción de superficie de ataque |
| Baseline | Configuración de referencia |
| Zero Trust | Modelo de seguridad sin confianza implícita |
| MFA | Autenticación multifactor |
| IAM | Gestión de identidades y accesos |
| PAM | Gestión de accesos privilegiados |
| RBAC | Control basado en roles |
| ABAC | Control basado en atributos |
| SIEM | Gestión de información y eventos de seguridad |
| EDR | Detección y respuesta en endpoints |
| XDR | Detección y respuesta extendidas |
| SOAR | Orquestación y automatización de seguridad |
| IDS | Sistema de detección de intrusiones |
| IPS | Sistema de prevención de intrusiones |
| IOC | Indicador de compromiso |
| IOA | Indicador de ataque |
| FIM | Monitoreo de integridad de archivos |
| DLP | Prevención de pérdida de datos |
| CVE | Identificador de vulnerabilidad |
| CVSS | Sistema de puntuación de severidad |
| EPSS | Sistema de estimación de explotación |
| KEV | Catálogo de vulnerabilidades explotadas conocidas |
| MTTD | Tiempo medio de detección |
| MTTR | Tiempo medio de respuesta o recuperación |
| RPO | Objetivo de punto de recuperación |
| RTO | Objetivo de tiempo de recuperación |

---

# 21. Referencias técnicas

## Marcos de seguridad

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST SP 800-53 — Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)

## Gestión de riesgos y vulnerabilidades

- [NIST SP 800-30 — Risk Assessment](https://csrc.nist.gov/pubs/sp/800/30/r1/final)
- [CVE Program](https://www.cve.org/)
- [FIRST CVSS](https://www.first.org/cvss/)
- [FIRST EPSS](https://www.first.org/epss/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Blue Team y detección

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE D3FEND](https://d3fend.mitre.org/)
- [Sigma Detection Rules](https://sigmahq.io/)
- [CISA Cybersecurity Resources](https://www.cisa.gov/cybersecurity)

## Respuesta a incidentes

- [NIST SP 800-61 Rev. 3 — Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

## Hardening y buenas prácticas

- [CIS Controls](https://www.cisecurity.org/controls)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
