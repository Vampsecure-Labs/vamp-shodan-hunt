<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-shodan-hunt/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-shodan-hunt

**Shodan OSINT Hunter — VampSecure Labs Security Research Division**

Herramienta de inteligencia de fuentes abiertas (OSINT) que consulta la API de Shodan para mapear la exposición global de vulnerabilidades, productos y organizaciones en Internet.

> ⚠️ **USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS.** El uso no autorizado es ilegal.

## Instalación

```bash
pip install vamp-shodan-hunt
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-shodan-hunt
```

## Uso

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

## Requisitos

- Python >= 3.9
- Clave API de Shodan (`SHODAN_API_KEY` o `--api-key`)
- `aiohttp >= 3.9.0`
- `rich >= 13.7.0`

## Autoría

© VampSecure Studios — VampSecure Labs Security Research Division  
Todos los derechos reservados. Uso exclusivo en entornos autorizados.

---

## Sample Output

```
$ vamp-shodan-hunt --api-key $SHODAN_API_KEY --cve CVE-2024-1234
vamp-shodan-hunt v1.1 — VampSecure Labs
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
vamp-shodan-hunt v1.1 — VampSecure Labs
─────────────────────────────────────────────────────────────
[*] Attack surface for org:"Example Corp" port:22
[*] 12 hosts found

  192.168.0.10:22  → OpenSSH_8.9p1   [ES]  CVEs: none
  192.168.0.11:22  → OpenSSH_7.4p1   [ES]  CVEs: CVE-2023-38408 (HIGH 8.1)
  192.168.0.42:22  → Dropbear_2022   [ES]  CVEs: none

[!] 1 host with active HIGH CVE on port 22
```

## Why vamp-shodan-hunt vs. Shodan CLI oficial · Censys CLI · Onyphe

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

- **Rich terminal output** — color-coded severity, sortable tables, and inline CVSS scores make triage faster than raw JSON piped through `jq`.
- **Composable filters** — `--cve`, `--product`, `--org`, `--port`, and `--country` combine into a single Shodan query, eliminating the need to hand-craft query strings for each engagement.
- **Unified VSL report** — findings feed directly into the shared `vampsec_report` module, producing the same branded HTML/PDF as every other Labs tool.
- **NIST CSF alignment** — results map to CIS Control 1 (Asset Inventory) and NIST CSF Identify (ID.AM-1/2), supporting evidence-based asset discovery for GRC assessments.

## Check Coverage

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

---

## Versión
v1.1 — VampSecure Labs Security Research Division
