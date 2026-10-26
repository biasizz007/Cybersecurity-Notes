# Laboratorios Blue Team — Unidad 8: Ataques y amenazas de red

> **Ubicación GitHub:** `laboratorios/Unidad-08-LABORATORIOS.md`  
> **Relación:** [`../Unidad-08/README.md`](../Unidad-08/README.md)  
> **Objetivo:** practicar triage, análisis estadístico, PCAP, anomalías de DNS/ARP, detección y respuesta.  
> **Alcance:** únicamente datos sintéticos y dispositivos propios/autorizados. No se genera ni envía tráfico de ataque.

## Normas de laboratorio y portfolio

1. No capturar tráfico ajeno ni efectuar pruebas de carga contra servicios públicos.
2. No ejecutar floods, spoofing, redirecciones o interrupciones reales; investigar **datasets simulados**.
3. Guardar originales en carpeta de evidencia de solo lectura; analizar copias.
4. Registrar OS, versión de Python, UTC, herramienta y procedimiento.
5. Los resultados ilustrativos de esta guía **no son evidencia de trabajo realizado**. Rellenar fechas, hashes y capturas propias.
6. Antes de publicar: anonimizar IP reales, usuarios, tokens, cookies, nombres internos y cualquier dato sensible.

## Estructura sugerida de evidencias

```text
laboratorios/
  Unidad-08-LABORATORIOS.md
SOC-Labs/
  U08-network-threats/
    README.md
    datasets/
    scripts/
    evidencia/
    informes/
```

Las actividades dependen solo de Python 3 estándar, Wireshark opcional y comandos de lectura locales. En Windows usar PowerShell, y en Linux/macOS una terminal.

---

## Lab 0 — Preparación, inventario y baseline

**Objetivo:** determinar qué interfaces y conexiones existen antes de interpretar tráfico.

**Comandos Linux:**

```bash
python3 --version
ip -br addr
ip route
ss -s
```

**Windows PowerShell:**

```powershell
python --version
Get-NetIPConfiguration
Get-NetTCPConnection | Group-Object State | Select-Object Name,Count
```

**Registrar:** timestamp con zona, OS, interfaces (anonimizadas), ruta por defecto, cantidad de conexiones, servicios de laboratorio. No publicar capturas con nombres internos.

**Preguntas:** ¿la conexión aparente es TCP o UDP? ¿Hay NAT? ¿Qué métricas locales no revelan un ataque a tu ISP?

**Entregable:** `SOC-Labs/U08-network-threats/informes/00-baseline.md`.

---

## Lab 1 — Triage de disponibilidad con métricas sintéticas

**Objetivo:** distinguir fallo backend, flash crowd y posible presión de red a partir de bps, RPS, errores y latencia.

Guardar como `datasets/availability.csv`:

```csv
minute,mbps,rps,http_5xx,p95_ms,wan_drops,context
09:00,40,250,2,110,0,normal
09:01,42,260,2,115,0,normal
09:02,41,255,3,112,0,normal
09:03,85,510,4,130,0,campaign
09:04,92,540,5,140,0,campaign
09:05,310,300,75,1800,600,unknown
09:06,320,290,91,2400,1200,unknown
09:07,305,280,83,2200,990,unknown
09:08,50,250,62,1900,0,backend_issue
09:09,47,245,51,1600,0,backend_issue
```

Crear `scripts/analyze_availability.py`:

```python
import csv
from pathlib import Path

rows = list(csv.DictReader(Path('datasets/availability.csv').open(newline='', encoding='utf-8')))
base = rows[:3]
mean = lambda key: sum(float(r[key]) for r in base) / len(base)
base_mbps, base_rps = mean('mbps'), mean('rps')

print(f'Baseline: {base_mbps:.1f} Mbps; {base_rps:.1f} RPS')
for row in rows:
    mbps = float(row['mbps'])
    rps = float(row['rps'])
    errors = int(row['http_5xx'])
    drops = int(row['wan_drops'])
    flags = []
    if mbps > 3 * base_mbps and drops > 0:
        flags.append('presión posible en WAN')
    if rps > 1.8 * base_rps and errors < 10:
        flags.append('pico posiblemente legítimo')
    if errors >= 50 and drops == 0:
        flags.append('fallo app/backend posible')
    if flags:
        print(row['minute'], '|', ', '.join(flags))
```

Ejecutar:

```bash
python3 scripts/analyze_availability.py
```

**Resultados esperados:** baseline ~41 Mbps y 255 RPS; 09:03–09:04 pico de solicitudes sin gran error; 09:05–09:07 presión WAN y drops; 09:08–09:09 errores sin drops. **No es prueba de DDoS**: faltan ISP, tráfico de flujos, salud de interfaces y cambios.

**Preguntas:** ¿qué es evidencia, qué es hipótesis? ¿Qué prioridad tendría un sistema crítico? ¿Qué decisión sería riesgosa?

**Portfolio:** captura de script, tabla interpretada y sección “limitaciones del dataset”.

---

## Lab 2 — Analizar solicitudes TCP y resultados sin generar SYN flood

**Objetivo:** comprender la diferencia entre solicitudes SYN y conexiones establecidas utilizando registros sintéticos.

Guardar `datasets/tcp_windows.csv`:

```csv
window,syn_seen,established,wan_loss_pct,maintenance
10:00,110,100,0,no
10:01,115,104,0,no
10:02,1000,90,8,no
10:03,1250,100,12,no
10:04,950,110,10,no
10:05,800,760,0,yes
```

Código exploratorio:

```python
import csv
with open('datasets/tcp_windows.csv', newline='') as f:
    for r in csv.DictReader(f):
        syn, established = int(r['syn_seen']), int(r['established'])
        fraction = established / syn if syn else 0
        print(r['window'], f'{fraction:.1%}', 'pérdida', r['wan_loss_pct'],
              'mantenimiento', r['maintenance'])
```

**Observación esperada:** 10:02–10:04 porcentajes bajos de conexiones establecidas y pérdida elevada. **No deducir SYN flood solamente de ese cociente**: retransmisiones, medición y degradación de red pueden distorsionarlo. La ventana 10:05 coincide con mantenimiento.

**Entregable:** breve decisión de escalamiento y tres hipótesis alternativas.

---

## Lab 3 — DNS anómalo sin generar tunneling

**Objetivo:** detectar características de consultas inusuales en un conjunto artificial.

Crear `datasets/dns_queries.csv`:

```csv
time,host,qname,rcode
11:00,PC-01,www.example.com,NOERROR
11:01,PC-01,api.example.com,NOERROR
11:02,PC-02,zzzzzzzzzzzzzzzzzzzz.lab.example.invalid,NXDOMAIN
11:02,PC-02,abcdefghijklmnopqrst.lab.example.invalid,NXDOMAIN
11:03,PC-02,00000000000000000000.lab.example.invalid,NXDOMAIN
11:04,PC-03,updates.example.com,NOERROR
```

Script de conteo:

```python
import csv
from collections import Counter
rows = list(csv.DictReader(open('datasets/dns_queries.csv', newline='')))
for host, count in Counter(r['host'] for r in rows if r['rcode'] == 'NXDOMAIN').items():
    print(host, 'NXDOMAIN:', count)
for r in rows:
    label = r['qname'].split('.')[0]
    if len(label) >= 20:
        print('Etiqueta larga:', r['host'], len(label))
```

**Interpretación esperada:** `PC-02` concentra consultas NXDOMAIN y etiquetas largas. **Esto no confirma exfiltración**; verificar aplicación, volumen en el tiempo, respuestas, inventario y si el dominio es de laboratorio.

**Entregable:** una detección conceptual con umbrales justificados, falsos positivos y campos necesarios.

---

## Lab 4 — Interpretar cambios ARP con evidencia simulada

**Objetivo:** separar suplantación de failover legítimo sin alterar ninguna caché ARP real.

```text
14:00:00  192.168.10.1 -> 02:00:00:00:00:01  VLAN10
14:02:11  192.168.10.1 -> 02:00:00:00:00:02  VLAN10
14:02:15  192.168.10.1 -> 02:00:00:00:00:01  VLAN10
14:03:00  CAMBIO PROGRAMADO: gateway HA
```

**Investigar:** configuración de alta disponibilidad, direcciones virtuales, registros de switch, MAC OUI (cuando aplique), DHCP, ARP y cambios. No inferir “ataque confirmado”.

**Actividad:** escribir un informe de 200–300 palabras que distinga hechos, hipótesis y evidencia que faltaría.

---

## Lab 5 — Captura autorizada y análisis en Wireshark

**Objetivo:** identificar DNS, TCP, ICMP y sus límites de visibilidad, sin inducir tráfico nocivo.

1. Iniciar Wireshark en **tu propia interfaz** autorizada.
2. Ejecutar `nslookup example.com` o `dig example.com A`.
3. Ejecutar `curl -I https://example.com` en equipo propio.
4. Detener la captura tras pocos segundos.
5. Aplicar filtros de visualización:

```text
dns
tcp.flags.syn == 1
tcp.analysis.retransmission
icmp
ip.addr == 192.0.2.1
```

El último filtro utiliza una IP de ejemplo: reemplazar solo por una IP que aparezca en **tu propia captura**, sin publicar datos de terceros.

**Anotar:** direcciones y puertos (redactados), timestamps UTC, protocolo, flags, número de consultas, si el contenido HTTPS es visible, pérdidas/retransmisiones señaladas por Wireshark (heurísticas).

**Límite:** DNS cifrado o cachés pueden ocultar la consulta; captura parcial u offloading alteran interpretación de retransmisiones.

---

## Lab 6 — Controles de protección y evidencia de firewall

**Objetivo:** revisar políticas existentes; **no modificar reglas**.

Linux:

```bash
ss -tuln
sudo ufw status verbose
```

Windows:

```powershell
Get-NetFirewallProfile
Get-NetFirewallRule -Enabled True | Select-Object -First 20 DisplayName,Direction,Action
```

**Registrar:** política entrante/saliente, puertos en escucha, controles no cubiertos, distinción entre NAT y filtrado. No asumir que un puerto local en escucha sea accesible desde Internet.

**Entregable:** tabla riesgo/control/recomendación con impacto operativo y necesidad de aprobación.

---

## Lab 7 — Integridad y custodia de artefactos

**Objetivo:** comprobar que un dataset no cambió mientras se analizaba.

Linux/macOS:

```bash
sha256sum datasets/*.csv
```

Windows PowerShell:

```powershell
Get-ChildItem datasets\*.csv | Get-FileHash -Algorithm SHA256
```

Crear `evidencia/MANIFIESTO.md`:

```text
ID:
Archivo:
SHA-256 real (copiado del comando):
Origen: dataset sintético creado para laboratorio
Fecha/hora UTC:
Responsable:
Copia de trabajo:
Método de adquisición:
Cambios autorizados:
```

Comparar hashes después de analizar. Si cambian, revisar si se modificaron los originales. No atribuir procedencia auténtica solo porque los hashes coinciden.

---

## Lab 8 — Caso integrador: ¿DDoS, campaña o fallo de backend?

**Escenario:** un portal ficticio recibió picos de tráfico, la WAN registró drops y luego una aplicación comenzó a devolver 5xx. Se cuenta con los datasets de labs 1–2, sin registros del ISP y sin PCAP completo.

### Tareas

1. Reconstruir línea de tiempo UTC o indicar que los timestamps carecen de zona explícita (limitación).
2. Separar fase de campaña (09:03–09:04), presión WAN (09:05–09:07) y fallo backend (09:08–09:09).
3. Formular al menos **dos hipótesis** para cada fase.
4. Definir qué evidencia solicitarías al ISP/CDN/WAF.
5. Elaborar recomendaciones **preventivas**, **detectivas** y **de respuesta**.
6. Redactar informe final de máximo dos páginas y anexar evidencias.

### Plantilla de informe

```markdown
# U08-IR-001 — Triage de disponibilidad (SIMULADO)

## Alcance y fuentes
## Resumen ejecutivo
## Línea de tiempo
## Hallazgos comprobados
## Hipótesis y alternativas
## Impacto y limitaciones
## Mitigaciones sugeridas y riesgos
## Evidencias: archivos / SHA-256
## Próximos pasos
## Autoevaluación y aprendizaje
```

### Rúbrica (0–2 por criterio; total 12)

| Criterio | 0 | 1 | 2 |
|---|---|---|---|
| Datos y baseline | ausentes | parciales | claros y reproducibles |
| Línea temporal | ausente | incompleta | consistente y cautelosa |
| Hechos/hipótesis | mezclados | parcialmente separados | separados |
| Falsos positivos | no tratados | uno | varios plausibles |
| Mitigación | genérica | parcial | proporcional y con riesgos |
| Evidencia | no registrada | incompleta | hashes, fuentes y límites |

**Meta:** ≥10/12 antes de marcar el laboratorio como completo.

---

## Progreso de laboratorios

- [ ] Lab 0 — Inventario y baseline
- [ ] Lab 1 — Métricas de disponibilidad
- [ ] Lab 2 — Estados TCP
- [ ] Lab 3 — DNS anómalo
- [ ] Lab 4 — Cambios ARP
- [ ] Lab 5 — Wireshark
- [ ] Lab 6 — Firewall
- [ ] Lab 7 — Integridad
- [ ] Lab 8 — Informe integrador

## Referencias

- [Unidad 8 — Teoría](../Unidad-08/README.md)
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [RFC 2827 — Ingress Filtering](https://www.rfc-editor.org/rfc/rfc2827)

**Ética de publicación:** el objetivo del laboratorio es la defensa. Todos los datasets anteriores son artificiales y las alertas propuestas son hipótesis didácticas, no detecciones validadas en producción.
