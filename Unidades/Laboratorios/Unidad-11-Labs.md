# Unidad 11 — Laboratorios de logs, telemetría y correlación SOC

> **Carpeta separada de la guía:** `laboratorios/Unidad-11-LABORATORIOS.md`.
>
> **Entorno:** Windows PowerShell 5.1+ para ejemplos Windows, Linux con systemd para journalctl, Python 3.10+ para ejercicios offline. Algunas funciones necesitan privilegios y sensores instalados.
>
> **Reglas de seguridad:** usar sistemas propios o autorizados; no habilitar auditoría ni modificar políticas en equipos productivos sin permiso; sanitizar evidencias antes de publicar en GitHub. Los datasets de esta unidad son sintéticos.

## Cómo guardar resultados reales

```text
SOC-Labs/U11-investigacion-correlacion/
├── README.md
├── data/                     # solo datos sintéticos o autorizados y anonimizados
├── queries/                  # comandos exactos que utilicé
├── evidence/                 # hashes, notas y capturas sin secretos
├── scripts/                  # análisis propio reproducible
└── report.md                 # hechos, hipótesis, límites y conclusión
```

En cada laboratorio anotaré: objetivo, entorno, fecha con zona horaria, fuente, comandos, datos observados, hallazgo, interpretación, dudas, hash si corresponde y conclusión. Si algo no pude correr, lo indico; no invento una captura ni un resultado.

---

## Laboratorio 00 — Preparación y línea base

### Objetivo

Verificar herramientas, sistema operativo, reloj, zona horaria y carpeta de trabajo.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Linux: `cat /etc/os-release`, `date -Is`, `date -u -Is`, `python3 --version`; Windows: `$PSVersionTable.PSVersion`, `Get-Date -Format o`.

### Qué me puede confundir

Documentar diferencias de tiempo y alcance de permisos. No hace falta ser administrador para todas las prácticas.

### Entregable

Una ficha con sistema, versiones, reloj UTC y carpetas creadas.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 01 — Windows Security en lectura

### Objetivo

Enumerar los canales y consultar 4624/4625 de las últimas 24 horas en equipo propio.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

`Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624,4625; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 100 | Select TimeCreated,Id,Message`

### Qué me puede confundir

Puede fallar por permisos o ausencia de eventos. Identificar cuenta, logon type, origen y hora sin subir mensajes crudos privados.

### Entregable

Tabla anonimizada de tres eventos y explicación del contexto.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 02 — Sysmon disponible y campos

### Objetivo

Comprobar si Sysmon existe y consultar eventos 1 y 3 en modo lectura.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

`Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"` y `Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1,3} -MaxEvents 20`

### Qué me puede confundir

No instalar ni modificar sensores en entornos de terceros. Si no está, documentar ausencia sin inferir seguridad.

### Entregable

Lista de campos observados: ProcessGuid, Image, CommandLine, ParentImage, destino si existe.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 03 — journalctl por hora y unidad

### Objetivo

Consultar journal, comparar horas UTC y locales y buscar eventos de una unidad de servicio.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

`journalctl --list-boots`; `journalctl -b -n 30 --utc`; `journalctl -u ssh --since "1 hour ago" -o json --no-pager`

### Qué me puede confundir

El servicio puede llamarse sshd; el journal puede no ser persistente. No usar restart ni vacuum durante el análisis.

### Entregable

Cuadro con zona horaria, unidad, 3 campos y disponibilidad histórica.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 04 — Audit Linux y fuentes alternativas

### Objetivo

Verificar si auditd está configurado y dónde se consultan autenticaciones.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

`systemctl status auditd` (solo lectura), `sudo ausearch -ts today` si está disponible, `ls -l /var/log`, `journalctl -u sshd -n 50`.

### Qué me puede confundir

Un servicio ausente no significa que el sistema no genere ningún registro de seguridad.

### Entregable

Mapa de fuentes: auditd, PAM, SSH, journal, syslog tradicional y limitaciones.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 05 — CSV robusto y parsing

### Objetivo

Analizar un CSV sintético con comas dentro de campos y verificar parseo sin split ingenuo.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Usar script de Python de este documento con módulo csv; contar filas e inspeccionar campos.

### Qué me puede confundir

No confundir errores del parser con actividad maliciosa o líneas truncadas.

### Entregable

Tabla de datos parseados y detección de campos faltantes.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 06 — Normalización de timestamps

### Objetivo

Convertir marcas temporales con -03:00 y Z a UTC sin perder original.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Usar `datetime.fromisoformat(...replace("Z", "+00:00"))` y `.astimezone(timezone.utc)`.

### Qué me puede confundir

Rechazar o documentar timestamps sin zona cuando se necesitan correlaciones globales.

### Entregable

Tabla original/UTC y nota de supuestos.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 07 — Correlación por identidad e IP

### Objetivo

Comparar intentos fallidos y exitosos en una ventana de 10 minutos sobre dataset sintético.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Ejecutar `correlacion_u11.py` incluido en el laboratorio integrador.

### Qué me puede confundir

No atribuir una identidad humana por IP; distinguir red compartida y cuentas de servicio.

### Entregable

Salida del script y explicación de qué secuencias requieren triage.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 08 — Salud del pipeline

### Objetivo

Encontrar un intervalo sin eventos y diferenciar caída de sensor de inactividad legítima.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Agrupar eventos por minuto y comparar conteos; revisar último evento y datos de heartbeat simulados.

### Qué me puede confundir

Una brecha en la recepción no confirma ataque ni ausencia de actividad.

### Entregable

Hipótesis de falta de cobertura y consultas para verificarla.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 09 — Detección con ventana y umbral

### Objetivo

Definir regla simple de múltiples fallos, ensayar umbrales y analizar falsos positivos.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Dataset sintético + agrupación con Counter o pandas; distinguir por cuenta y origen.

### Qué me puede confundir

Evaluar NAT, cuentas técnicas, errores de clave y mantenimientos autorizados.

### Entregable

Versión de regla, ventana, umbral, casos positivos y negativos.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 10 — Línea temporal multi-fuente

### Objetivo

Unir eventos simulados de Windows, Sysmon, SSH y proxy usando UTC.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Ordenar JSONL por timestamp normalizado; enlazar por host, usuario y ProcessGuid cuando corresponda.

### Qué me puede confundir

Proximidad temporal no equivale a causalidad. Anotar datos que faltan para atribución.

### Entregable

Timeline de al menos seis eventos con columna de hipótesis y evidencia.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 11 — Integridad de una exportación

### Objetivo

Calcular SHA-256 de datos, copiar el archivo, comprobar coincidencia y documentar procedimiento.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Linux: `sha256sum archivo.jsonl copia.jsonl`; Windows: `Get-FileHash -Algorithm SHA256`.

### Qué me puede confundir

Hashes iguales no demuestran legitimidad histórica; cambios de metadatos no alteran necesariamente hash del contenido.

### Entregable

Manifiesto con muestras, método, fechas y hashes.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 12 — Diseño y validación de regla Sigma

### Objetivo

Revisar YAML didáctico, plantear caso positivo y falso positivo y documentar configuración necesaria.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Leer regla de la guía teórica y adaptar `Image`, `ParentImage` y nombres de campos al backend.

### Qué me puede confundir

No prometer que funciona en todos los SIEM; no ejecutar contra entornos no autorizados.

### Entregable

Fichero YAML versionado y matriz de pruebas previstas.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

## Laboratorio 13 — Informe SOC L1 integrador

### Objetivo

Recibir el dataset sintético de abajo, investigar una secuencia, preservar originales y emitir resultado.

### Preparación

- Usar tu equipo o un laboratorio explícitamente autorizado.
- Registrar versión de sistema, fecha, hora y zona horaria.
- Verificar que el comando corresponde a tu plataforma y a la configuración del sensor.
- Guardar consultas exactas en un archivo de texto del repositorio de prácticas.
- No publicar cuentas reales, IP internas sensibles, identificadores de equipos ni tokens.

### Pasos

1. Describir qué querés verificar y qué campos esperás encontrar.
2. Ejecutar solo las operaciones de lectura o simulación indicadas.
3. Comprobar si la fuente devuelve registros o si hay una limitación de cobertura.
4. Capturar tres observaciones verificables y anotar hora con zona.
5. Formular una hipótesis legítima y una potencialmente sospechosa.
6. Buscar un segundo dato que discrimine entre ambas.
7. Registrar si el resultado coincide o no con el resultado esperado.
8. Guardar archivo, consulta o tabla con la ruta exacta y SHA-256 si es evidencia exportada.
9. Escribir conclusión y límites; si no sabés, poné «pendiente de validación».

### Comandos o procedimiento

Crear JSONL y usar el script de correlación, revisar también accesos legítimos y procesos esperados.

### Qué me puede confundir

Separar hallazgo, hipótesis y conclusión; limitar afirmaciones a evidencias disponibles.

### Entregable

Un informe en Markdown con timeline, evidencias, incertidumbre y próximos pasos.

### Preguntas de control

- ¿Cuál es el dato crudo y cuál es mi interpretación?
- ¿La fuente registra todos los eventos que estoy suponiendo?
- ¿Qué otro evento ayudaría a confirmar la hipótesis?
- ¿Hay una operación de cambio que debería evitar durante el triage?
- ¿Qué dato tendría que ocultar antes de publicar en GitHub?

- [ ] Ejecutado o marcado como no disponible.
- [ ] Evidencia y fecha registradas.
- [ ] Hallazgos sin exagerar.
- [ ] Conclusión propia redactada.

---

# Dataset integrado sintético

**IMPORTANTE:** lo que sigue es inventado únicamente para aprender. No representa actividad real, ni prueba que ocurrió un incidente. Si copiás el bloque a un archivo llamado `eventos_u11.jsonl`, cada línea es un objeto JSON independiente.

```jsonl
{"timestamp":"2026-10-20T10:00:00-03:00","source":"winsec","host":"pc-lab-01","event_id":4625,"user":"analista","src_ip":"192.0.2.50","result":"failure","message":"Inicio fallido sintético"}
{"timestamp":"2026-10-20T10:01:00-03:00","source":"winsec","host":"pc-lab-01","event_id":4625,"user":"analista","src_ip":"192.0.2.50","result":"failure","message":"Inicio fallido sintético"}
{"timestamp":"2026-10-20T10:02:20-03:00","source":"winsec","host":"pc-lab-01","event_id":4624,"user":"analista","src_ip":"192.0.2.50","result":"success","logon_type":3,"message":"Inicio exitoso sintético"}
{"timestamp":"2026-10-20T13:03:00Z","source":"sysmon","host":"pc-lab-01","event_id":1,"user":"analista","process_guid":"{LAB-GUID-A}","image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parent_image":"C:\\Windows\\explorer.exe","message":"Creación de proceso sintética"}
{"timestamp":"2026-10-20T13:04:00Z","source":"sysmon","host":"pc-lab-01","event_id":3,"user":"analista","process_guid":"{LAB-GUID-A}","dst_ip":"198.51.100.20","dst_port":443,"message":"Conexión sintética"}
{"timestamp":"2026-10-20T13:06:00Z","source":"winsec","host":"pc-lab-01","event_id":4624,"user":"operador","src_ip":"192.0.2.80","result":"success","logon_type":2,"message":"Operación conocida de laboratorio"}
{"timestamp":"2026-10-20T13:08:00Z","source":"proxy","host":"pc-lab-01","user":"analista","src_ip":"192.0.2.50","dst_host":"actualizaciones.ejemplo.test","status":200,"message":"Acceso proxy sintético"}
{"timestamp":"2026-10-20T13:09:00Z","source":"linux-auth","host":"srv-lab-01","user":"devops","src_ip":"192.0.2.70","result":"success","message":"SSH sintético autorizado"}
{"timestamp":"2026-10-20T13:11:00Z","source":"linux-auth","host":"srv-lab-01","user":"root","src_ip":"192.0.2.99","result":"failure","message":"SSH fallido sintético"}
{"timestamp":"2026-10-20T13:12:00Z","source":"heartbeat","host":"pc-lab-01","message":"Agente activo"}
```

Las direcciones 192.0.2.0/24 y 198.51.100.0/24 pertenecen a rangos reservados para documentación (RFC 5737). `ejemplo.test` está puesto como nombre ficticio: no lo tomes como servicio real.

## Script del laboratorio integrador: `correlacion_u11.py`

El script no se conecta a ninguna máquina. Lee JSONL local, comprueba fechas y muestra eventos ordenados, más una búsqueda básica de fallos anteriores a éxitos de la misma cuenta y host.

```python
from __future__ import annotations
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

FILE = Path("eventos_u11.jsonl")

def parse_timestamp(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"La fecha no tiene offset: {value}")
    return dt.astimezone(timezone.utc)

rows = []
for lineno, raw in enumerate(FILE.read_text(encoding="utf-8").splitlines(), 1):
    if not raw.strip():
        continue
    try:
        row = json.loads(raw)
        row["_utc"] = parse_timestamp(row["timestamp"])
        rows.append(row)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"Línea {lineno}: no pude parsear: {exc}")

rows.sort(key=lambda r: r["_utc"])
print("EVENTOS EN UTC")
for e in rows:
    print(e["_utc"].isoformat(), e.get("source"), e.get("host"), e.get("event_id", "-"), e.get("user", "-"))

failures = defaultdict(list)
print("\nCANDIDATOS PARA TRIAGE: fallos previos a éxito")
for e in rows:
    if e.get("source") != "winsec":
        continue
    key = (e.get("host"), e.get("user"))
    if e.get("event_id") == 4625:
        failures[key].append(e)
    elif e.get("event_id") == 4624:
        recent = [f for f in failures[key] if timedelta(0) <= e["_utc"]-f["_utc"] <= timedelta(minutes=10)]
        if recent:
            print(f"{key}: {len(recent)} fallos en los 10 min previos a éxito; verificar origen, contexto y actividad posterior")
```

### Resultado esperado del dataset sintético

- Se ordenan diez eventos en una sola escala UTC, aunque algunos tenían `-03:00`.
- Se observa una secuencia de dos fallos anteriores a un éxito para la cuenta `analista` en `pc-lab-01`.
- Esa secuencia **no confirma** compromiso. Faltan autenticación MFA, contexto de dispositivo, cambio autorizado y explicación del usuario.
- El proceso y la conexión comparten el mismo `process_guid`, lo que permite relacionar **esos dos eventos Sysmon** dentro del conjunto sintético.
- El evento de otro usuario y los eventos Linux no se atribuyen automáticamente a la misma sesión.

### Ideas para extenderlo

1. Agregar un campo `ingested_at` y medir retrasos por fuente.
2. Insertar un evento duplicado y diseñar una regla de deduplicación justificable.
3. Insertar una línea inválida y contar errores de parsing sin detener el análisis.
4. Agregar dos hosts con la misma IP detrás de NAT y explicar el riesgo de atribución.
5. Crear un reporte con hechos, hipótesis y fuentes faltantes.
6. Preparar archivos de prueba de casos positivos y falsos positivos para la detección.

---

# Plantilla de cierre y autoevaluación

```markdown
# Informe SOC — Caso U11 (datos sintéticos)

## Alcance
Datos generados para aprendizaje, no registros reales.

## Pregunta de investigación
¿Qué actividad ocurrió y qué relación es posible probar?

## Evidencias
- Fuente:
- Rango de tiempo UTC:
- Cantidad de eventos:
- Método de adquisición:
- SHA-256 del archivo:
- Campos clave:

## Cronología
| Hora UTC | Fuente | Observación | Interpretación | Límite |
|---|---|---|---|---|

## Hipótesis 1
- Qué la respalda:
- Qué la contradice:
- Qué datos faltan:

## Hipótesis 2
- Qué la respalda:
- Qué la contradice:
- Qué datos faltan:

## Evaluación
Severidad, confianza, impacto, alcance conocido.

## Conclusión
Diferenciar hechos registrados de hipótesis.

## Próximos pasos
Pasos autorizados, proporcionados y reproducibles.
```

## Fuentes para repasar

- Microsoft: https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference
- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- journalctl: https://www.freedesktop.org/software/systemd/man/latest/journalctl.html
- Sigma: https://sigmahq.io/
- NIST incident response: https://csrc.nist.gov/pubs/sp/800/61/r3/final
