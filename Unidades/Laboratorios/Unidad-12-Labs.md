# Laboratorios — Unidad 12 · SIEM

> Archivo independiente del `README.md` de teoría. Las prácticas están diseñadas para realizarse en equipos propios o autorizados. **No se presentan como ejecutadas**. Los resultados de ejemplo son sintéticos.

## Organización sugerida

Cada práctica puede tener una carpeta con `README.md` de investigación, datasets sintéticos, consultas y capturas sin datos privados. Registrar software y versión utilizada, objetivo, evidencias, resultados y limitaciones. Evitar screenshots con usuarios reales, cookies o tokens.

---

## Laboratorio 00 — Entorno y alcance

**Actividad:** Registrar hardware, sistema y recursos disponibles. Elegir plataforma local/online solo después de revisar requisitos y costos. Nunca habilitar facturación por accidente.

**Resultado verificable:** Entregar un diagrama simple de fuentes y plataforma, con limitaciones reales.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 01 — Dataset y esquema común

**Actividad:** Crear un archivo JSONL con eventos sintéticos de Windows, Linux y firewall. Extraer timestamp, host, usuario, acción, origen y mensaje original.

**Resultado verificable:** Entregar tabla de campos y prueba de parsing sobre al menos tres formatos.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 02 — Splunk: búsqueda inicial

**Actividad:** Si hay Splunk autorizado, consultar índices y sourcetypes de prueba, delimitar 24 horas y mostrar 20 eventos raw; si no, razonar sobre las consultas de referencia sin afirmar ejecución.

**Resultado verificable:** Entregar SPL utilizado y ejemplo anonimizado de retorno.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 03 — Splunk: fallos por cuenta

**Actividad:** Construir una agregación de fallos 4625 por cuenta y host. Cambiar ventanas de 5 minutos y 24 horas y explicar las diferencias.

**Resultado verificable:** Entregar comparación de agregaciones y límites.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 04 — Splunk: línea temporal

**Actividad:** Unir un 4624, un proceso Sysmon ID 1 y una conexión ID 3 de un conjunto sintético, cuidando claves y timestamps.

**Resultado verificable:** Entregar línea de tiempo con origen de cada dato.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 05 — Wazuh: arquitectura y sensores

**Actividad:** Si hay una VM con recursos suficientes, identificar server, indexer, dashboard y agente y validar salud. De lo contrario, hacer una inspección guiada de documentación y datos sintéticos.

**Resultado verificable:** Entregar un diagrama de componentes y cobertura esperada.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 06 — Wazuh: decoders y reglas

**Actividad:** Usar herramienta de test en una instancia autorizada para observar parsing de un log SSH; revisar regla resultante sin modificar producción.

**Resultado verificable:** Entregar log raw, campos identificados y regla observada.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 07 — Wazuh: integridad

**Actividad:** Monitorear un archivo de prueba propio y compararlo antes y después de un cambio, diferenciando hash de contenido de permisos.

**Resultado verificable:** Entregar hashes y explicación de qué verifican.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 08 — Sentinel: consulta KQL sin costos

**Actividad:** Ejecutar KQL sobre un entorno de prueba ya disponible o evaluar el código sobre un dataset sintético en local. No activar servicios de pago sin confirmar costo.

**Resultado verificable:** Entregar KQL explicado, tabla esperada y limitaciones.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 09 — Sentinel: agregaciones

**Actividad:** Filtrar eventos 4625, agrupar por Account y bin temporal, y evaluar cómo cambia el resultado según el rango.

**Resultado verificable:** Entregar dos consultas y análisis de ventana.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 10 — Correlación entre fuentes

**Actividad:** Usar datos sintéticos con fallos, éxito y procesos; correlacionar por cuenta, host y tiempo. Incluir un evento distractor de otro host.

**Resultado verificable:** Entregar secuencia válida y motivo de exclusión del distractor.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 11 — Salud del pipeline

**Actividad:** Simular que una fuente deja de emitir durante 45 minutos; distinguir ausencia de eventos de ausencia de ataques.

**Resultado verificable:** Entregar diagnóstico de cobertura y consulta para detectar la brecha.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 12 — Regla y falsos positivos

**Actividad:** Definir una detección de múltiples fallos en distintas cuentas, incluir un dataset de spraying y otro de una tarea legítima.

**Resultado verificable:** Entregar especificación de regla, TP y FP documentados.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 13 — Investigación integradora

**Actividad:** Resolver un escenario multi-fuente, redactar 1 página con hechos, hipótesis, contradicciones, conclusión y acciones según autorización.

**Resultado verificable:** Entregar informe reproducible sin datos sensibles.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Laboratorio 14 — Portfolio SOC

**Actividad:** Elegir dos investigaciones terminadas, convertirlas en notas públicas con comandos revisados y muestras anonimizadas.

**Resultado verificable:** Entregar carpetas SOC-Labs con evidencia realmente trabajada.

**Precaución:** separar resultados esperados de resultados observados; no atribuir un compromiso sin evidencia y no ejecutar cambios en producción.

## Dataset sintético para las prácticas de consulta

```jsonl
{"timestamp":"2026-10-25T13:00:00Z","source":"windows","host":"PC-12","event_id":4625,"user":"u01","src_ip":"192.0.2.31","action":"failure"}
{"timestamp":"2026-10-25T13:00:20Z","source":"windows","host":"PC-12","event_id":4625,"user":"u02","src_ip":"192.0.2.31","action":"failure"}
{"timestamp":"2026-10-25T13:00:45Z","source":"windows","host":"PC-12","event_id":4625,"user":"u03","src_ip":"192.0.2.31","action":"failure"}
{"timestamp":"2026-10-25T13:01:10Z","source":"windows","host":"PC-12","event_id":4624,"user":"u01","src_ip":"192.0.2.99","action":"success"}
{"timestamp":"2026-10-25T13:02:00Z","source":"sysmon","host":"PC-12","event_id":1,"user":"u01","image":"C:\\Windows\\System32\\notepad.exe","action":"process_create"}
{"timestamp":"2026-10-25T13:03:00Z","source":"linux","host":"SRV-01","user":"root","action":"sudo","src_ip":null}
```

**Interpretación resuelta:** hay tres fallos sobre cuentas distintas desde un mismo origen; el éxito posterior tiene **otra IP** y un host concreto, por lo que no se puede asegurar que provenga del mismo actor. El proceso Notepad aparece después en el endpoint, pero el dataset no aporta un ProcessGuid ni una relación de sesión que permita atribuirlo a esa autenticación. La evidencia alcanza para proponer hipótesis, no para confirmar intrusión.

---

## Criterios de finalización

Un laboratorio está terminado cuando existe un resultado observado en un entorno autorizado o un análisis reproducible de un dataset sintético, con fecha, fuente, consulta y explicación de limitaciones. Una práctica solamente leída no debe presentarse como experiencia ejecutada.


# Anexo práctico: consultas y evidencias reproducibles

## A. Generar eventos sintéticos sin afectar sistemas reales

```python
import json
from pathlib import Path

rows = [
    {"timestamp":"2026-10-25T13:10:00Z","host":"PC-01","user":"u01","event_id":4625,"source_ip":"192.0.2.20"},
    {"timestamp":"2026-10-25T13:10:10Z","host":"PC-01","user":"u02","event_id":4625,"source_ip":"192.0.2.20"},
    {"timestamp":"2026-10-25T13:10:20Z","host":"PC-01","user":"u03","event_id":4625,"source_ip":"192.0.2.20"},
]
Path("auth_demo.jsonl").write_text(
    "\n".join(json.dumps(item, ensure_ascii=False) for item in rows)+"\n", encoding="utf-8"
)
print("Eventos creados:", len(rows))
```

Este código crea tres registros sintéticos con cuentas diferentes desde el mismo origen. No ejecuta intentos reales de autenticación ni interactúa con servicios de red.

## B. Agregar fallos por origen y por usuario

```python
import json
from collections import Counter, defaultdict

counts = Counter()
users = defaultdict(set)
with open("auth_demo.jsonl", encoding="utf-8") as f:
    for line in f:
        row = json.loads(line)
        if row.get("event_id") != 4625:
            continue
        ip = row.get("source_ip")
        counts[ip] += 1
        users[ip].add(row.get("user"))

for ip in sorted(counts):
    print(ip, "fallos:", counts[ip], "usuarios distintos:", len(users[ip]))
```

**Resultado esperado con el dataset anterior:** `192.0.2.20 fallos: 3 usuarios distintos: 3`. El script prueba la lógica de agregación, no la detección de un ataque.

## C. Comprobar integridad del archivo de práctica

En Linux:

```bash
sha256sum auth_demo.jsonl
cp auth_demo.jsonl auth_demo_copia.jsonl
sha256sum auth_demo_copia.jsonl
```

Si el contenido es el mismo, ambos archivos tendrán hashes iguales con altísima confianza criptográfica. Para una investigación real, registrar también cómo se produjo y transfirió la copia.

## D. Comparación de consultas entre plataformas

**SPL (requiere ingesta y campos configurados):**

```spl
index=training earliest=-1d event_id=4625
| stats count as fallos dc(user) as usuarios_distintos by source_ip
```

**KQL (requiere tabla con esquema equivalente; ejemplo ilustrativo):**

```kql
AuthTraining_CL
| where TimeGenerated > ago(1d)
| where event_id == 4625
| summarize Fallos=count(), UsuariosDistintos=dcount(user) by source_ip
```

**Wazuh:** validar el decoder y los campos almacenados antes de agregar por IP desde el indexer/dashboard. No hay una traducción 1:1 entre el motor de reglas de Wazuh, SPL y KQL.

## E. Informe final de ejemplo (sintético)

**Observación:** se registraron tres intentos fallidos para tres cuentas distintas desde una IP de documentación `192.0.2.20`.

**Hipótesis:** podría tratarse de un patrón inicial de password spraying, pero el volumen es reducido y no hay contexto de exposición ni confirmación de actividad maliciosa.

**Evidencia:** tres entradas JSONL con timestamps, cuentas y origen consistentes; conteos reproducibles mediante script.

**Limitaciones:** no existe equipo real, no hay registros de éxito, sesiones, MFA ni inventario. La muestra fue generada artificialmente para estudiar agregaciones.

**Conclusión:** el ejercicio demuestra cómo agrupar eventos y documentar una hipótesis. No representa un incidente ni acredita una investigación sobre infraestructura real.
