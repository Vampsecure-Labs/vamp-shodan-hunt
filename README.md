# vamp-shodan-hunt

**Shodan OSINT Hunter — VampSecure Labs Security Research Division**

Herramienta de inteligencia de fuentes abiertas (OSINT) que consulta la API de Shodan para mapear la exposición global de vulnerabilidades, productos y organizaciones en Internet.

> ⚠️ **USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS.** El uso no autorizado es ilegal.

## Instalación

```bash
pip install vamp-shodan-hunt
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
