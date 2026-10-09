<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-shodan-hunt/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-shodan-hunt

**Shodan OSINT Hunter — VampSecure Labs Security Research Division**

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

Open-source intelligence (OSINT) tool that queries the Shodan API to map the global exposure of vulnerabilities, products, and organizations on the Internet.

> ⚠️ **FOR AUTHORIZED AUDITS ONLY.** Unauthorized use is illegal.

### Installation

```bash
pip install vamp-shodan-hunt
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-shodan-hunt
```

### Usage

```bash
# Hosts with a specific CVE
vamp-shodan-hunt --api-key YOUR_KEY --cve CVE-2024-1234

# Exposed product instances
vamp-shodan-hunt --api-key YOUR_KEY --product "Apache Tomcat"

# Organization attack surface
vamp-shodan-hunt --api-key YOUR_KEY --org "Example Corp"

# Arbitrary Shodan query
vamp-shodan-hunt --api-key YOUR_KEY --query 'port:22 country:ES'
```

### Requirements

- Python >= 3.9
- Shodan API key (`SHODAN_API_KEY` or `--api-key`)
- `aiohttp >= 3.9.0`
- `rich >= 13.7.0`

### Authorship

© VampSecure Studios — VampSecure Labs Security Research Division  
All rights reserved. For use in authorized environments only.

---

### Sample Output

```
$ vamp-shodan-hunt --api-key $SHODAN_API_KEY --cve CVE-2024-1234
vamp-shodan-hunt v1.2 — VampSecure Labs
─────────────────────────────────────────────────────────────
[*] Querying CVE-2024-1234 (Apache Struts RCE)...
[*] 2 847 hosts exposed globally

┌──────────────────┬───────┬─────────┬──────────────────────────┬──────────────┐
│ IP               │ Port  │ Country │ Organization             │ CVEs         │
├──────────────────┼───────┼─────────┼──────────────────────────┼──────────────┤
│ 192.0.2.14       │ 8080  │ DE      │ Example Hosting GmbH     │ CVE-2024-1234│
│ 192.0.2.87       │ 443   │ US      │ Example Cloud Corp       │ CVE-2024-1234│
│ 192.0.2.203      │ 8443  │ FR      │ Exemple Hébergement SAS  │ CVE-2024-1234│
└──────────────────┴───────┴─────────┴──────────────────────────┴──────────────┘

Summary: 3 results shown (2 847 total) · export with --output results.json
```

```
$ vamp-shodan-hunt --api-key $SHODAN_API_KEY --org "Example Corp" --port 22
vamp-shodan-hunt v1.2 — VampSecure Labs
─────────────────────────────────────────────────────────────
[*] Attack surface for org:"Example Corp" port:22
[*] 12 hosts found

  192.168.0.10:22  → OpenSSH_8.9p1   [ES]  CVEs: none
  192.168.0.11:22  → OpenSSH_7.4p1   [ES]  CVEs: CVE-2023-38408 (HIGH 8.1)
  192.168.0.42:22  → Dropbear_2022   [ES]  CVEs: none

[!] 1 host with active HIGH CVE on port 22
```

### Why vamp-shodan-hunt vs. Official Shodan CLI · Censys CLI · Onyphe

| Capability | vamp-shodan-hunt | Official Shodan CLI | Censys CLI | Onyphe |
|------------|------------------|--------------------|------------|--------|
| CVE correlation inline per row | ✅ | ✅ Basic | ✅ | ✅ |
| Org-level attack surface map | ✅ `--org` | ✅ Query string | ✅ | ✅ |
| Filter composition (port + product + vuln + country) | ✅ Combined flags | ✅ Manual query | ✅ | ✅ |
| Rich terminal tables (color, CVSS, sortable) | ✅ | ❌ Plain text | ❌ Plain text | ❌ |
| JSON export | ✅ `--output` | ✅ | ✅ | ✅ |
| Importable Python library | ✅ | ❌ | ✅ | ❌ |
| VSL engagement report (HTML / PDF) | ✅ `vampsec_report` | ❌ | ❌ | ❌ |
| Self-hosted / no SaaS dependency beyond API | ✅ | ❌ Shodan account | ❌ Censys account | ❌ Onyphe account |

- **Rich terminal output** — color-coded severity, sortable tables, and inline CVSS scores make triage faster than raw JSON piped through `jq`.
- **Composable filters** — `--cve`, `--product`, `--org`, `--port`, and `--country` combine into a single Shodan query, eliminating the need to hand-craft query strings for each engagement.
- **Unified VSL report** — findings feed directly into the shared `vampsec_report` module, producing the same branded HTML/PDF as every other Labs tool.
- **NIST CSF alignment** — results map to CIS Control 1 (Asset Inventory) and NIST CSF Identify (ID.AM-1/2), supporting evidence-based asset discovery for GRC assessments.

### Check Coverage

| Check category | Standard | Notes |
|----------------|----------|-------|
| Open ports by CVE (`vuln:CVE-XXXX-YYYY`) | NIST CSF ID.AM / CIS Control 1 | Confirms real-world exposure, not just vulnerability DB membership |
| Exposed products by banner (`product:` filter) | CIS Control 2 (Software Inventory) | Detects unmanaged or shadow-IT services |
| Organization attack surface (`org:` + all ports) | NIST CSF ID.AM-1 | Complete perimeter inventory per org string |
| Country-scoped exposure (`country:` filter) | GDPR Art. 44 / data residency | Identifies cross-border data exposure |
| High-risk port exposure (22, 3306, 5432, 6379, 11211) | CIS Control 12.2 | Database and admin ports reachable from internet |
| SSL/TLS version exposure (`ssl.version:TLSv1`) | NIST SP 800-52r2 | Identifies hosts still negotiating legacy protocols |
| Default credential exposure (Shodan `default password`) | CWE-521 / OWASP A07 | Appliances and IoT devices with known factory credentials |
| ICS/SCADA protocol exposure (Modbus, BACnet, DNP3) | ICS-CERT / NERC CIP | OT devices directly reachable from internet |
| CVE CVSS score per finding | NVD scoring | Prioritizes remediation by severity |
| JSON export for downstream RBVM correlation | CIS Control 7 | Feeds vamp-cve-oracle for risk-based vulnerability management |

### Version History

| Version | Main changes |
|---------|-------------|
| v1.2 | Bilingual README (EN/ES) |
| v1.1 | Initial release |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.

---
---

<a name="español"></a>
## 🇪🇸 Español

Herramienta de inteligencia de fuentes abiertas (OSINT) que consulta la API de Shodan para mapear la exposición global de vulnerabilidades, productos y organizaciones en Internet.

> ⚠️ **USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS.** El uso no autorizado es ilegal.

### Instalación

```bash
pip install vamp-shodan-hunt
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-shodan-hunt
```

### Uso

```bash
# Hosts con un CVE específico
vamp-shodan-hunt --api-key TU_CLAVE --cve CVE-2024-1234

# Instancias de un producto expuesto
vamp-shodan-hunt --api-key TU_CLAVE --product "Apache Tomcat"

# Superficie de ataque de una organización
vamp-shodan-hunt --api-key TU_CLAVE --org "Example Corp"

# Consulta Shodan arbitraria
vamp-shodan-hunt --api-key TU_CLAVE --query 'port:22 country:ES'
```

### Requisitos

- Python >= 3.9
- Clave API de Shodan (`SHODAN_API_KEY` o `--api-key`)
- `aiohttp >= 3.9.0`
- `rich >= 13.7.0`

### Autoría

© VampSecure Studios — VampSecure Labs Security Research Division  
Todos los derechos reservados. Uso exclusivo en entornos autorizados.

---

### Sample Output

```
$ vamp-shodan-hunt --api-key $SHODAN_API_KEY --cve CVE-2024-1234
vamp-shodan-hunt v1.2 — VampSecure Labs
─────────────────────────────────────────────────────────────
[*] Querying CVE-2024-1234 (Apache Struts RCE)...
[*] 2 847 hosts exposed globally

┌──────────────────┬───────┬─────────┬──────────────────────────┬──────────────┐
│ IP               │ Port  │ Country │ Organization             │ CVEs         │
├──────────────────┼───────┼─────────┼──────────────────────────┼──────────────┤
│ 192.0.2.14       │ 8080  │ DE      │ Example Hosting GmbH     │ CVE-2024-1234│
│ 192.0.2.87       │ 443   │ US      │ Example Cloud Corp       │ CVE-2024-1234│
│ 192.0.2.203      │ 8443  │ FR      │ Exemple Hébergement SAS  │ CVE-2024-1234│
└──────────────────┴───────┴─────────┴──────────────────────────┴──────────────┘

Summary: 3 results shown (2 847 total) · export with --output results.json
```

```
$ vamp-shodan-hunt --api-key $SHODAN_API_KEY --org "Example Corp" --port 22
vamp-shodan-hunt v1.2 — VampSecure Labs
─────────────────────────────────────────────────────────────
[*] Attack surface for org:"Example Corp" port:22
[*] 12 hosts found

  192.168.0.10:22  → OpenSSH_8.9p1   [ES]  CVEs: none
  192.168.0.11:22  → OpenSSH_7.4p1   [ES]  CVEs: CVE-2023-38408 (HIGH 8.1)
  192.168.0.42:22  → Dropbear_2022   [ES]  CVEs: none

[!] 1 host with active HIGH CVE on port 22
```

### Why vamp-shodan-hunt vs. Shodan CLI oficial · Censys CLI · Onyphe

| Capability | vamp-shodan-hunt | Shodan CLI oficial | Censys CLI | Onyphe |
|------------|------------------|--------------------|------------|--------|
| CVE correlation inline per row | ✅ | ✅ Basic | ✅ | ✅ |
| Org-level attack surface map | ✅ `--org` | ✅ Query string | ✅ | ✅ |
| Filter composition (port + product + vuln + country) | ✅ Combined flags | ✅ Manual query | ✅ | ✅ |
| Rich terminal tables (color, CVSS, sortable) | ✅ | ❌ Plain text | ❌ Plain text | ❌ |
| JSON export | ✅ `--output` | ✅ | ✅ | ✅ |
| Importable Python library | ✅ | ❌ | ✅ | ❌ |
| VSL engagement report (HTML / PDF) | ✅ `vampsec_report` | ❌ | ❌ | ❌ |
| Self-hosted / no SaaS dependency beyond API | ✅ | ❌ Shodan account | ❌ Censys account | ❌ Onyphe account |

- **Rich terminal output** — tablas con color por severidad, ordenables, con scores CVSS inline hacen el triage más rápido que JSON crudo pasado por `jq`.
- **Filtros componibles** — `--cve`, `--product`, `--org`, `--port` y `--country` se combinan en una sola consulta Shodan, eliminando la necesidad de construir query strings manualmente por cada engagement.
- **Informe VSL unificado** — los hallazgos alimentan directamente el módulo `vampsec_report` compartido, produciendo el mismo HTML/PDF de marca que el resto de herramientas del laboratorio.
- **Alineación con NIST CSF** — los resultados se mapean a CIS Control 1 (Inventario de activos) y NIST CSF Identify (ID.AM-1/2), soportando el descubrimiento de activos con evidencia para evaluaciones GRC.

### Check Coverage

| Categoría de check | Estándar | Notas |
|----------------|----------|-------|
| Puertos abiertos por CVE (`vuln:CVE-XXXX-YYYY`) | NIST CSF ID.AM / CIS Control 1 | Confirma exposición real, no solo pertenencia a BD de vulnerabilidades |
| Productos expuestos por banner (`product:` filter) | CIS Control 2 (Inventario de software) | Detecta servicios no gestionados o shadow IT |
| Superficie de ataque por organización (`org:` + todos los puertos) | NIST CSF ID.AM-1 | Inventario completo del perímetro por cadena org |
| Exposición por país (`country:` filter) | GDPR Art. 44 / residencia de datos | Identifica exposición transfronteriza de datos |
| Exposición de puertos de alto riesgo (22, 3306, 5432, 6379, 11211) | CIS Control 12.2 | Puertos de base de datos y administración accesibles desde internet |
| Exposición de versión SSL/TLS (`ssl.version:TLSv1`) | NIST SP 800-52r2 | Identifica hosts que siguen negociando protocolos legacy |
| Exposición de credenciales por defecto (Shodan `default password`) | CWE-521 / OWASP A07 | Dispositivos IoT y appliances con credenciales de fábrica conocidas |
| Exposición de protocolos ICS/SCADA (Modbus, BACnet, DNP3) | ICS-CERT / NERC CIP | Dispositivos OT accesibles directamente desde internet |
| Score CVSS por CVE por hallazgo | NVD scoring | Prioriza la remediación por severidad |
| Exportación JSON para correlación RBVM | CIS Control 7 | Alimenta vamp-cve-oracle para gestión de vulnerabilidades basada en riesgo |

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.2 | README bilingüe (EN/ES) |
| v1.1 | Versión inicial |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Uso exclusivo en auditorías autorizadas. El uso no autorizado es ilegal.
