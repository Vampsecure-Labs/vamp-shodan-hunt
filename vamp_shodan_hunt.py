#!/usr/bin/env python3
# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_shodan_hunt.py — Cazador OSINT de Superficie de Ataque con Shodan API
===========================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Auditorías de Seguridad Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Herramienta de inteligencia de fuentes abiertas (OSINT) que consulta la API
de Shodan para mapear la exposición global de vulnerabilidades, productos y
organizaciones en Internet.

Modos de operación
------------------
  --cve CVE-XXXX-XXXX    Hosts con ese CVE indexado en Shodan (uno o varios)
  --product "Product"    Instancias de un producto expuesto en Internet
  --org "Company SA"     Superficie de ataque completa de una organización
  --query 'raw query'    Consulta Shodan arbitraria pass-through

DEPENDENCIAS
------------
  aiohttp  >= 3.9.0   — Cliente HTTP asíncrono (sin SDK de Shodan)
  rich     >= 13.7.0  — Salida de consola enriquecida

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import aiohttp

# Importar tomllib (Python 3.11+) o tomli como alternativa para Python 3.9/3.10
try:
    import tomllib  # type: ignore[import]
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[import]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

VERSION   = "1.2"
TOOL_NAME = "vamp-shodan-hunt"

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-shodan-hunt v1.2 · OSINT Exposure Intelligence (Shodan·Censys·BinaryEdge)
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# Endpoints Shodan — llamadas REST directas sin SDK
SHODAN_API_INFO = "https://api.shodan.io/api-info"
SHODAN_COUNT    = "https://api.shodan.io/shodan/host/count"
SHODAN_SEARCH   = "https://api.shodan.io/shodan/host/search"

# Endpoints Censys — búsqueda de hosts con autenticación Basic (id:secret)
CENSYS_HOSTS_SEARCH = "https://search.censys.io/api/v2/hosts/search"

# Endpoints BinaryEdge — inteligencia por IP
BINARYEDGE_IP = "https://api.binaryedge.io/v2/query/ip"

# Ruta al fichero de configuración compartido de VampSecure Labs
_CONFIG_PATH = Path.home() / ".config" / "vampsec" / "config.toml"

SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}

SEV_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#06b6d4",
    "INFO":     "#6b7280",
}


def cargar_config_api(
    args_shodan_key: str | None = None,
    args_censys_id: str | None = None,
    args_censys_secret: str | None = None,
    args_binaryedge_key: str | None = None,
) -> dict:
    """
    Carga las claves de APIs de inteligencia con el siguiente orden de prioridad:

    1. Flags CLI — máxima prioridad
    2. Variables de entorno: SHODAN_API_KEY, VAMPSEC_CENSYS_API_ID,
       VAMPSEC_CENSYS_API_SECRET, VAMPSEC_BINARYEDGE_KEY
    3. Fichero ~/.config/vampsec/config.toml sección [shodan-hunt]
    4. None → la fuente se salta silenciosamente

    Devuelve un dict con claves 'shodan_key', 'censys_id', 'censys_secret',
    'binaryedge_key'.
    """
    config: dict = {
        "shodan_key":     None,
        "censys_id":      None,
        "censys_secret":  None,
        "binaryedge_key": None,
    }

    # Paso 3: leer fichero de configuración (menor prioridad base)
    if tomllib is not None and _CONFIG_PATH.exists():
        try:
            with _CONFIG_PATH.open("rb") as fh:
                toml_data = tomllib.load(fh)
            sec = toml_data.get("shodan-hunt", {})
            config["shodan_key"]     = sec.get("shodan_api_key") or None
            config["censys_id"]      = sec.get("censys_api_id") or None
            config["censys_secret"]  = sec.get("censys_api_secret") or None
            config["binaryedge_key"] = sec.get("binaryedge_api_key") or None
        except Exception:
            pass  # Config inválida → continuar sin ella

    # Paso 2: variables de entorno (sobreescriben config file)
    if os.environ.get("SHODAN_API_KEY"):
        config["shodan_key"]     = os.environ["SHODAN_API_KEY"]
    if os.environ.get("VAMPSEC_CENSYS_API_ID"):
        config["censys_id"]      = os.environ["VAMPSEC_CENSYS_API_ID"]
    if os.environ.get("VAMPSEC_CENSYS_API_SECRET"):
        config["censys_secret"]  = os.environ["VAMPSEC_CENSYS_API_SECRET"]
    if os.environ.get("VAMPSEC_BINARYEDGE_KEY"):
        config["binaryedge_key"] = os.environ["VAMPSEC_BINARYEDGE_KEY"]

    # Paso 1: flags CLI (máxima prioridad)
    if args_shodan_key:
        config["shodan_key"]     = args_shodan_key
    if args_censys_id:
        config["censys_id"]      = args_censys_id
    if args_censys_secret:
        config["censys_secret"]  = args_censys_secret
    if args_binaryedge_key:
        config["binaryedge_key"] = args_binaryedge_key

    return config


def _exposure_severity(count: int) -> str:
    """Asigna severidad orientativa en función del número de hosts expuestos."""
    if count >= 100_000:
        return "CRITICAL"
    if count >= 10_000:
        return "HIGH"
    if count >= 1_000:
        return "MEDIUM"
    if count > 0:
        return "LOW"
    return "INFO"


# ────────────────────────────────────────────────────────────────────────────
# Estructuras de datos
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class ShodanMatch:
    """Host individual encontrado en Shodan."""
    ip:      str
    port:    int
    org:     str
    country: str
    product: str
    version: str
    banner:  str
    vulns:   list[str] = field(default_factory=list)
    cpe:     str = ""      # CPE 2.3 del servicio (si Shodan lo proporciona)


@dataclass
class HuntResult:
    """Resultado completo de una consulta (un modo + un target)."""
    mode:          str               # cve | product | org | query
    query:         str               # Query Shodan enviada
    label:         str               # CVE ID / nombre producto / org / raw
    total:         int               # Total hosts en Shodan (endpoint /count)
    matches:       list[ShodanMatch] = field(default_factory=list)
    top_countries: list[tuple[str, int]] = field(default_factory=list)
    top_orgs:      list[tuple[str, int]] = field(default_factory=list)
    top_products:  list[tuple[str, int]] = field(default_factory=list)
    top_versions:  list[tuple[str, int]] = field(default_factory=list)
    error:         str | None = None


# ────────────────────────────────────────────────────────────────────────────
# Motor Shodan (sin SDK — REST directo con aiohttp)
# ────────────────────────────────────────────────────────────────────────────

class ShodanHunter:
    """
    Realiza consultas a la API pública de Shodan mediante peticiones HTTP
    directas (aiohttp). No depende del SDK oficial de Python de Shodan.
    """

    def __init__(self, api_key: str, limit: int = 100) -> None:
        self._key   = api_key
        self._limit = limit

    async def check_api(self, session: aiohttp.ClientSession) -> dict:
        """Verifica la clave y obtiene información de la cuenta."""
        async with session.get(
            SHODAN_API_INFO,
            params={"key": self._key},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 401:
                raise ValueError("Clave API Shodan inválida o sin permisos")
            resp.raise_for_status()
            return await resp.json(content_type=None)

    async def _count(self, session: aiohttp.ClientSession, query: str) -> int:
        """Conteo total de hosts para la query (sin consumir créditos de búsqueda)."""
        try:
            async with session.get(
                SHODAN_COUNT,
                params={"key": self._key, "query": query},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    return data.get("total", 0)
        except Exception:
            pass
        return -1

    async def _search_page(
        self,
        session: aiohttp.ClientSession,
        query: str,
        page: int,
    ) -> list[dict]:
        """Trae una página de resultados de Shodan."""
        try:
            async with session.get(
                SHODAN_SEARCH,
                params={"key": self._key, "query": query, "page": str(page)},
                timeout=aiohttp.ClientTimeout(total=25),
            ) as resp:
                if resp.status in (401, 402):
                    return []
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    return data.get("matches", [])
        except Exception:
            pass
        return []

    async def _search(
        self,
        session: aiohttp.ClientSession,
        query: str,
    ) -> list[ShodanMatch]:
        """Trae hasta self._limit hosts paginando la API de Shodan."""
        matches: list[ShodanMatch] = []
        page = 1

        while len(matches) < self._limit:
            raw = await self._search_page(session, query, page)
            if not raw:
                break
            for m in raw:
                if len(matches) >= self._limit:
                    break
                # Extraer CPE: Shodan puede devolver 'cpe' (lista) o 'cpe23' (lista)
                cpe_raw  = m.get("cpe23") or m.get("cpe") or []
                cpe_str  = cpe_raw[0] if isinstance(cpe_raw, list) and cpe_raw else (
                    cpe_raw if isinstance(cpe_raw, str) else ""
                )
                matches.append(ShodanMatch(
                    ip      = m.get("ip_str", ""),
                    port    = m.get("port", 0),
                    org     = m.get("org", ""),
                    country = m.get("country_name", ""),
                    product = m.get("product", ""),
                    version = m.get("version", ""),
                    banner  = (m.get("data", "") or "")[:140].replace("\n", " ").strip(),
                    vulns   = list((m.get("vulns") or {}).keys()),
                    cpe     = cpe_str,
                ))
            if len(raw) < 100:
                break
            page += 1

        return matches

    def _aggregate(self, matches: list[ShodanMatch]) -> tuple:
        """Frecuencias de países, orgs, productos y versiones."""
        return (
            Counter(m.country for m in matches if m.country).most_common(8),
            Counter(m.org     for m in matches if m.org).most_common(8),
            Counter(m.product for m in matches if m.product).most_common(8),
            Counter(m.version for m in matches if m.version and m.version.strip()).most_common(8),
        )

    async def hunt_one(
        self,
        mode: str,
        target: str,
        session: aiohttp.ClientSession,
    ) -> HuntResult:
        """Ejecuta la búsqueda para un objetivo individual."""
        if mode == "cve":
            query = f"vuln:{target}"
        elif mode == "product":
            query = f'product:"{target}"'
        elif mode == "org":
            query = f'org:"{target}"'
        else:
            query = target

        result = HuntResult(mode=mode, query=query, label=target, total=0)

        try:
            result.total = await self._count(session, query)
            if result.total < 0:
                result.error = "Error al obtener conteo"
                return result

            if result.total == 0:
                return result

            result.matches = await self._search(session, query)
            top_c, top_o, top_p, top_v = self._aggregate(result.matches)
            result.top_countries = top_c
            result.top_orgs      = top_o
            result.top_products  = top_p
            result.top_versions  = top_v

        except Exception as exc:
            result.error = str(exc)[:200]

        return result

    async def run(self, mode: str, targets: list[str]) -> list[HuntResult]:
        """Ejecuta las consultas en paralelo para todos los targets."""
        async with aiohttp.ClientSession(
            headers={"User-Agent": f"VampSecureLabs-ShodanHunt/{VERSION}"}
        ) as session:
            try:
                info = await self.check_api(session)
                plan    = info.get("plan", "?")
                credits = info.get("query_credits", "?")
                console.print(
                    f"[green]✔ Shodan API OK — plan: [bold]{plan}[/] · "
                    f"créditos disponibles: [bold]{credits}[/][/]"
                )
            except ValueError as e:
                console.print(f"[bold red]✗ {e}[/]")
                sys.exit(1)
            except Exception as e:
                console.print(f"[yellow]⚠ No se pudo verificar la cuenta Shodan: {e}[/]")

            tasks = [self.hunt_one(mode, t, session) for t in targets]
            return list(await asyncio.gather(*tasks))


# ────────────────────────────────────────────────────────────────────────────
# Motor Censys (v2 API — autenticación Basic id:secret)
# ────────────────────────────────────────────────────────────────────────────

class CensysHunter:
    """
    Consulta la API v2 de Censys para búsqueda de hosts.
    El plan gratuito permite un número limitado de búsquedas por mes.
    Requiere API ID + API Secret (ambos de censys.io/register).
    """

    def __init__(self, api_id: str, api_secret: str, limit: int = 100) -> None:
        self._id     = api_id
        self._secret = api_secret
        self._limit  = limit

    def _build_query(self, mode: str, target: str) -> str:
        """Traduce el modo/target a sintaxis de consulta Censys v2."""
        if mode == "cve":
            # Censys indexa CVEs en el campo 'labels' o como parte de servicios
            return f'services.vulnerability_cves: "{target}"'
        elif mode == "product":
            return f'services.software.product: "{target}"'
        elif mode == "org":
            return f'autonomous_system.name: "{target}"'
        else:
            return target

    def _map_match(self, hit: dict) -> ShodanMatch:
        """Mapea un resultado Censys v2 a la estructura interna ShodanMatch."""
        ip = hit.get("ip", "")
        # Servicios: lista de objetos con puerto y descripción
        servicios = hit.get("services", [])
        puerto = 0
        producto = ""
        version  = ""
        banner   = ""
        if servicios:
            svc = servicios[0]
            puerto   = svc.get("port", 0)
            software = svc.get("software", [])
            if software and isinstance(software, list):
                sw = software[0]
                producto = sw.get("product", "")
                version  = sw.get("version", "")
            banner = (svc.get("banner", "") or "")[:140].replace("\n", " ").strip()

        # Datos de localización y organización
        location = hit.get("location", {})
        pais = location.get("country", "")
        asn  = hit.get("autonomous_system", {})
        org  = asn.get("name", "")

        return ShodanMatch(
            ip=ip, port=puerto, org=org, country=pais,
            product=producto, version=version, banner=banner,
        )

    async def hunt_one(
        self,
        mode: str,
        target: str,
        session: aiohttp.ClientSession,
    ) -> HuntResult:
        """Ejecuta la búsqueda en Censys para un objetivo individual."""
        import base64
        query  = self._build_query(mode, target)
        result = HuntResult(mode=mode, query=query, label=target, total=0)
        result.label = f"[Censys] {target}"

        # Autenticación Basic con id:secret
        credencial = base64.b64encode(f"{self._id}:{self._secret}".encode()).decode()
        headers    = {"Authorization": f"Basic {credencial}"}

        cursor  = None
        matches: list[ShodanMatch] = []

        try:
            while len(matches) < self._limit:
                params: dict = {"q": query, "per_page": min(100, self._limit - len(matches))}
                if cursor:
                    params["cursor"] = cursor

                async with session.get(
                    CENSYS_HOSTS_SEARCH,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=25),
                ) as resp:
                    if resp.status == 401:
                        result.error = "Censys: credenciales inválidas (id o secret incorrecto)"
                        return result
                    if resp.status == 403:
                        result.error = "Censys: sin permisos o cuota agotada"
                        return result
                    if resp.status != 200:
                        result.error = f"Censys: HTTP {resp.status}"
                        return result
                    data = await resp.json(content_type=None)

                resultado = data.get("result", {})
                hits      = resultado.get("hits", [])
                total     = resultado.get("total", 0)
                result.total = total

                for hit in hits:
                    if len(matches) >= self._limit:
                        break
                    matches.append(self._map_match(hit))

                # Paginación via cursor
                links  = resultado.get("links", {})
                cursor = links.get("next")
                if not cursor or not hits:
                    break

        except Exception as exc:
            result.error = str(exc)[:200]
            return result

        result.matches = matches
        top_c, top_o, top_p, top_v = (
            Counter(m.country for m in matches if m.country).most_common(8),
            Counter(m.org     for m in matches if m.org).most_common(8),
            Counter(m.product for m in matches if m.product).most_common(8),
            Counter(m.version for m in matches if m.version and m.version.strip()).most_common(8),
        )
        result.top_countries = top_c
        result.top_orgs      = top_o
        result.top_products  = top_p
        result.top_versions  = top_v
        return result

    async def run(self, mode: str, targets: list[str]) -> list[HuntResult]:
        """Ejecuta las consultas Censys en paralelo para todos los targets."""
        async with aiohttp.ClientSession(
            headers={"User-Agent": f"VampSecureLabs-ShodanHunt/{VERSION}"}
        ) as session:
            tasks = [self.hunt_one(mode, t, session) for t in targets]
            return list(await asyncio.gather(*tasks))


# ────────────────────────────────────────────────────────────────────────────
# Motor BinaryEdge (v2 API — autenticación con header X-Key)
# ────────────────────────────────────────────────────────────────────────────

class BinaryEdgeHunter:
    """
    Consulta la API v2 de BinaryEdge para inteligencia por IP.
    Solo admite consultas por IP (no por CVE/producto/org directamente).
    Requiere API key de pago en binaryedge.io.
    """

    def __init__(self, api_key: str, limit: int = 100) -> None:
        self._key   = api_key
        self._limit = limit

    def _map_match(self, ip: str, evento: dict) -> ShodanMatch:
        """Mapea un evento BinaryEdge a la estructura interna ShodanMatch."""
        resultado = evento.get("result", {})
        datos     = resultado.get("data", {})

        puerto   = datos.get("port", 0)
        producto = datos.get("product", "") or datos.get("service", {}).get("name", "")
        version  = datos.get("version", "") or datos.get("service", {}).get("version", "")
        banner   = (
            str(datos.get("banner", "") or datos.get("service", {}).get("banner", "") or "")
        )[:140].replace("\n", " ").strip()

        return ShodanMatch(
            ip=ip, port=puerto, org="", country="",
            product=producto, version=version, banner=banner,
        )

    async def hunt_one(
        self,
        mode: str,
        target: str,
        session: aiohttp.ClientSession,
    ) -> HuntResult:
        """
        Consulta BinaryEdge para un target.
        Solo funciona en modo 'query' con una IP directa.
        Para modos cve/product/org devuelve un resultado vacío con nota informativa.
        """
        result = HuntResult(mode=mode, query=target, label=target, total=0)
        result.label = f"[BinaryEdge] {target}"

        # BinaryEdge v2 solo admite consultas directas por IP en el endpoint básico
        if mode not in ("query",):
            # Para CVE/product/org se requiere el endpoint de búsqueda completo
            # (disponible solo en planes enterprise)
            result.error = (
                "BinaryEdge: modo directo solo disponible para IPs con --query. "
                "Usa el plan enterprise para búsquedas por CVE/producto/org."
            )
            return result

        # Validar que el target parece una IP
        import re as _re
        if not _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target.strip()):
            result.error = "BinaryEdge: el target debe ser una IP (ej. 192.0.2.1)"
            return result

        url     = f"{BINARYEDGE_IP}/{target.strip()}"
        headers = {"X-Key": self._key}

        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as resp:
                if resp.status == 401:
                    result.error = "BinaryEdge: API key inválida"
                    return result
                if resp.status == 404:
                    result.total = 0
                    return result
                if resp.status != 200:
                    result.error = f"BinaryEdge: HTTP {resp.status}"
                    return result
                data = await resp.json(content_type=None)
        except Exception as exc:
            result.error = str(exc)[:200]
            return result

        eventos = data.get("events", [])
        result.total   = len(eventos)
        matches: list[ShodanMatch] = []

        for ev in eventos[: self._limit]:
            matches.append(self._map_match(target.strip(), ev))

        result.matches = matches
        top_p, top_v   = (
            Counter(m.product for m in matches if m.product).most_common(8),
            Counter(m.version for m in matches if m.version and m.version.strip()).most_common(8),
        )
        result.top_products = top_p
        result.top_versions = top_v
        return result

    async def run(self, mode: str, targets: list[str]) -> list[HuntResult]:
        """Ejecuta las consultas BinaryEdge en paralelo para todos los targets."""
        async with aiohttp.ClientSession(
            headers={"User-Agent": f"VampSecureLabs-ShodanHunt/{VERSION}"}
        ) as session:
            tasks = [self.hunt_one(mode, t, session) for t in targets]
            return list(await asyncio.gather(*tasks))


# ────────────────────────────────────────────────────────────────────────────
# Generación de hallazgos VSL
# ────────────────────────────────────────────────────────────────────────────

def _findings_vsl(results: list[HuntResult]) -> list:
    """Convierte los HuntResult al formato Finding de vampsec_report."""
    from vampsec_report import Finding as VSLFinding

    findings = []
    for i, r in enumerate(results, 1):
        if r.error or r.total == 0:
            continue

        sev = _exposure_severity(r.total)

        if r.mode == "cve":
            title = f"CVE expuesto globalmente: {r.label} — {r.total:,} hosts en Shodan"
            desc = (
                f"La vulnerabilidad {r.label} tiene {r.total:,} hosts afectados indexados en Shodan. "
                f"Esto indica que el parche no se ha aplicado en una fracción significativa del parque "
                f"de dispositivos expuestos a Internet. La exposición real puede ser mayor dado que "
                f"Shodan no indexa todos los hosts de forma continua."
            )
            remediation = (
                f"Aplicar los parches disponibles para {r.label}. "
                f"Verificar exposición de activos propios usando 'vuln:{r.label}' en Shodan. "
                f"Implementar controles compensatorios si el parche no es aplicable de inmediato."
            )
        elif r.mode == "product":
            title = f"Producto expuesto: {r.label} — {r.total:,} instancias en Internet"
            desc = (
                f"Se han encontrado {r.total:,} instancias de '{r.label}' expuestas públicamente "
                f"en Internet según Shodan. Este es el volumen de superficie de ataque global "
                f"para cualquier vulnerabilidad que afecte a este producto."
            )
            remediation = (
                f"Verificar que las instancias propias de '{r.label}' no estén innecesariamente "
                f"expuestas a Internet. Aplicar segmentación de red y controles de acceso."
            )
        elif r.mode == "org":
            title = f"Superficie de ataque: {r.label} — {r.total:,} hosts en Shodan"
            desc = (
                f"La organización '{r.label}' tiene {r.total:,} hosts/servicios indexados en Shodan. "
                f"Cada servicio expuesto es un vector potencial de ataque. "
                f"La muestra analizada cubre los primeros {len(r.matches)} hosts."
            )
            remediation = (
                "Revisar si todos los servicios expuestos son intencionales. "
                "Aplicar el principio de mínima exposición: solo exponer lo estrictamente necesario. "
                "Implementar monitorización continua de la superficie de ataque externa."
            )
        else:
            title = f"Consulta Shodan: {r.label[:60]} — {r.total:,} resultados"
            desc = (
                f"La consulta Shodan '{r.query}' ha devuelto {r.total:,} resultados. "
                f"Muestra analizada: {len(r.matches)} hosts."
            )
            remediation = "Revisar los hosts devueltos y evaluar la exposición de activos propios."

        # Construir evidencia
        evidence_lines = [
            f"Consulta Shodan: {r.query}",
            f"Total indexado: {r.total:,} hosts",
            f"Muestra analizada: {len(r.matches)} hosts",
        ]
        if r.top_countries:
            evidence_lines.append(
                "Top países: " + ", ".join(f"{c} ({n})" for c, n in r.top_countries[:5])
            )
        if r.top_orgs:
            evidence_lines.append(
                "Top orgs: " + ", ".join(f"{o[:30]} ({n})" for o, n in r.top_orgs[:4])
            )
        if r.top_products:
            evidence_lines.append(
                "Top productos: " + ", ".join(f"{p} ({n})" for p, n in r.top_products[:4])
            )

        findings.append(VSLFinding(
            id          = f"SHOD-{i:03d}",
            title       = title,
            severity    = sev,
            description = desc,
            evidence    = "\n".join(evidence_lines),
            affected    = r.label,
            remediation = remediation,
            tags        = ["shodan", "osint", "attack-surface", r.mode],
        ))

    return findings


# ────────────────────────────────────────────────────────────────────────────
# Salida por consola
# ────────────────────────────────────────────────────────────────────────────

def print_summary_table(results: list[HuntResult]) -> None:
    """Tabla resumen de todos los targets consultados."""
    t = Table(
        title="[bold cyan]Shodan Hunt — Resultados[/]",
        border_style="cyan",
        show_lines=True,
    )
    t.add_column("ID",       width=10)
    t.add_column("Modo",     width=10)
    t.add_column("Target",   width=30)
    t.add_column("Total",    width=12, justify="right")
    t.add_column("Muestra",  width=9, justify="right")
    t.add_column("Sev.",     width=10)

    for i, r in enumerate(results, 1):
        fid = f"SHOD-{i:03d}"
        if r.error:
            t.add_row(fid, r.mode, r.label[:30], "[red]error[/]", "—", "[dim]ERR[/]")
            continue
        if r.total == 0:
            t.add_row(fid, r.mode, r.label[:30], "[green]0[/]", "0", "[dim]—[/]")
            continue
        sev   = _exposure_severity(r.total)
        style = SEV_STYLE.get(sev, "white")
        t.add_row(
            fid,
            r.mode,
            r.label[:30],
            f"[{style}]{r.total:,}[/]",
            str(len(r.matches)),
            f"[{style}]{sev}[/]",
        )

    console.print(t)


def print_detail(result: HuntResult, fid: str) -> None:
    """Panel de detalle para un resultado individual."""
    if result.error:
        console.print(Panel(
            f"[red]Error: {result.error}[/]",
            title=f"[red]{fid} — {result.label}[/]",
            border_style="red",
        ))
        return

    if result.total == 0:
        console.print(Panel(
            "[green]Sin hosts indexados en Shodan para esta consulta.[/]",
            title=f"[dim]{fid} — {result.label}[/]",
            border_style="dim",
        ))
        return

    sev   = _exposure_severity(result.total)
    style = SEV_STYLE.get(sev, "white")

    lines = [
        f"[bold]Query Shodan:[/] {result.query}",
        f"[bold]Total indexado:[/] [{style}]{result.total:,} hosts[/]",
        f"[bold]Muestra traída:[/] {len(result.matches)} hosts",
        f"[bold]Severidad OSINT:[/] [{style}]{sev}[/]",
    ]

    if result.top_countries:
        lines += ["", "[bold]Distribución geográfica (muestra):[/]"]
        for country, n in result.top_countries[:6]:
            lines.append(f"  {country}: {n} host(s)")

    if result.top_orgs:
        lines += ["", "[bold]Principales organizaciones (muestra):[/]"]
        for org, n in result.top_orgs[:5]:
            lines.append(f"  {org[:50]}: {n} host(s)")

    if result.top_products:
        lines += ["", "[bold]Productos identificados (muestra):[/]"]
        for prod, n in result.top_products[:5]:
            lines.append(f"  {prod}: {n} host(s)")

    if result.top_versions:
        lines += ["", "[bold]Versiones identificadas (muestra):[/]"]
        for ver, n in result.top_versions[:5]:
            lines.append(f"  {ver}: {n} host(s)")

    if result.matches:
        lines += ["", "[bold]Muestra de hosts:[/]"]
        for m in result.matches[:10]:
            vulns_str = f" [red]CVEs: {', '.join(m.vulns[:3])}[/]" if m.vulns else ""
            lines.append(
                f"  {m.ip}:{m.port}"
                + (f" ({m.country})" if m.country else "")
                + (f" — {m.org[:35]}" if m.org else "")
                + vulns_str
            )
        if len(result.matches) > 10:
            lines.append(f"  [dim]... y {len(result.matches) - 10} más en la muestra[/]")

    console.print(Panel(
        "\n".join(lines),
        title=f"[{style}]{fid} — {result.label}[/]",
        border_style=style,
    ))


# ────────────────────────────────────────────────────────────────────────────
# Exportación JSON
# ────────────────────────────────────────────────────────────────────────────

def to_json(results: list[HuntResult], mode: str, generated_at: str) -> str:
    """Serializa los resultados al formato JSON estándar VSL."""
    def _match_dict(m: ShodanMatch) -> dict:
        return {
            "ip": m.ip, "port": m.port, "org": m.org,
            "country": m.country, "product": m.product,
            "version": m.version, "banner": m.banner, "vulns": m.vulns,
        }

    def _result_dict(r: HuntResult, idx: int) -> dict:
        return {
            "id":            f"SHOD-{idx:03d}",
            "mode":          r.mode,
            "label":         r.label,
            "query":         r.query,
            "total":         r.total,
            "severity":      _exposure_severity(r.total) if r.total > 0 else "INFO",
            "top_countries": r.top_countries,
            "top_orgs":      r.top_orgs,
            "top_products":  r.top_products,
            "top_versions":  r.top_versions,
            "sample_hosts":  [_match_dict(m) for m in r.matches],
            "error":         r.error,
        }

    payload = {
        "schema_version": "1.0",
        "generated":      generated_at,
        "meta": {
            "tool":    TOOL_NAME,
            "version": VERSION,
            "mode":    mode,
        },
        "summary": {
            "total_targets": len(results),
            "total_exposed": sum(r.total for r in results if not r.error),
            "by_severity":   {
                sev: sum(
                    1 for r in results
                    if not r.error and r.total > 0
                    and _exposure_severity(r.total) == sev
                )
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            },
        },
        "results": [_result_dict(r, i) for i, r in enumerate(results, 1)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────────────────
# Exportación en formato oracle (entrada para vamp-cve-oracle)
# ────────────────────────────────────────────────────────────────────────────

def to_oracle_json(results: list[HuntResult]) -> str:
    """
    Transforma los hallazgos de Shodan al formato de entrada de vamp-cve-oracle.

    Genera una lista JSON de objetos con claves host, product, version y cpe,
    deduplicados por (host, port). Los campos vacíos se incluyen como cadena
    vacía para mantener el esquema uniforme que espera vamp-cve-oracle.
    """
    oracle: list[dict] = []
    seen: set = set()

    for result in results:
        for match in result.matches:
            if not match.ip:
                continue
            key = (match.ip, match.port)
            if key in seen:
                continue
            seen.add(key)
            oracle.append({
                "host":    match.ip,
                "port":    match.port,
                "product": match.product or "",
                "version": match.version or "",
                "cpe":     match.cpe or "",
            })

    return json.dumps(oracle, indent=2, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────────────────
# Punto de entrada CLI
# ────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Parsea argumentos y ejecuta el hunt."""
    console.print(BANNER, style="bold red")

    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs Shodan Hunt v{VERSION} — "
            "OSINT de exposición global con Shodan API (sin SDK)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  %(prog)s --cve CVE-2024-21762 CVE-2023-27997\n"
            "  %(prog)s --product 'FortiGate' --limit 200\n"
            "  %(prog)s --org 'Mi Empresa SA' --output resultado.json\n"
            "  %(prog)s --query 'port:8443 product:\"Fortinet\"'\n"
            "\n"
            "La clave API Shodan puede indicarse con --key o con la\n"
            "variable de entorno SHODAN_API_KEY."
        ),
    )

    # Modo de operación (mutuamente excluyentes)
    modo_group = p.add_mutually_exclusive_group(required=True)
    modo_group.add_argument(
        "--cve", nargs="+", metavar="CVE-ID",
        help="Uno o más CVE IDs (ej. CVE-2024-21762). Busca hosts con ese CVE indexado",
    )
    modo_group.add_argument(
        "--product", metavar="PRODUCTO",
        help="Nombre de producto (ej. 'FortiGate'). Enumera instancias expuestas en Internet",
    )
    modo_group.add_argument(
        "--org", metavar="ORG",
        help="Nombre de organización. Mapea su superficie de ataque completa en Shodan",
    )
    modo_group.add_argument(
        "--query", metavar="QUERY",
        help="Consulta Shodan arbitraria pass-through (ej. 'port:8443 ssl:\"Fortinet\"')",
    )

    # Opciones generales — claves de fuentes de inteligencia
    p.add_argument(
        "--key", metavar="API_KEY",
        help="Clave API de Shodan (alternativa: SHODAN_API_KEY o ~/.config/vampsec/config.toml)",
    )
    p.add_argument(
        "--censys-id", metavar="API_ID",
        help="API ID de Censys (alternativa: VAMPSEC_CENSYS_API_ID o config.toml). "
             "Registro gratuito en censys.io/register",
    )
    p.add_argument(
        "--censys-secret", metavar="API_SECRET",
        help="API Secret de Censys (debe usarse junto con --censys-id)",
    )
    p.add_argument(
        "--binaryedge-key", metavar="API_KEY",
        help="API key de BinaryEdge (alternativa: VAMPSEC_BINARYEDGE_KEY o config.toml). "
             "Solo funciona con --query <IP> en el plan básico",
    )
    p.add_argument(
        "--source", metavar="FUENTE",
        choices=["shodan", "censys", "binaryedge", "all"],
        default="all",
        help="Fuentes de inteligencia a usar: shodan | censys | binaryedge | all "
             "(default: all — usa todas las que tengan key configurada)",
    )
    p.add_argument(
        "--limit", type=int, default=100, metavar="N",
        help="Máximo de hosts a traer por consulta (default: 100; máx recomendado: 500)",
    )
    p.add_argument(
        "--count-only", action="store_true",
        help="Solo mostrar el conteo total, sin traer resultados (no consume créditos de búsqueda)",
    )
    p.add_argument(
        "-o", "--output", metavar="FILE",
        help="Guardar resultados en formato JSON",
    )
    p.add_argument(
        "--export-oracle", metavar="FILE",
        help="Exportar hallazgos Shodan en formato de entrada para vamp-cve-oracle "
             "(lista JSON con host, product, version, cpe)",
    )
    p.add_argument(
        "--pipe-oracle", metavar="CMD",
        help="Ejecutar vamp-cve-oracle automáticamente con el JSON generado por "
             "--export-oracle (la herramienta debe estar en PATH). "
             "Ejemplo: --pipe-oracle 'vamp-cve-oracle --input'",
    )

    from vampsec_report import add_report_args
    add_report_args(p)

    args = p.parse_args()

    # Resolver claves de todas las fuentes de inteligencia
    config_api = cargar_config_api(
        args_shodan_key     = getattr(args, "key", None),
        args_censys_id      = getattr(args, "censys_id", None),
        args_censys_secret  = getattr(args, "censys_secret", None),
        args_binaryedge_key = getattr(args, "binaryedge_key", None),
    )
    shodan_key     = config_api["shodan_key"] or ""
    censys_id      = config_api["censys_id"]
    censys_secret  = config_api["censys_secret"]
    binaryedge_key = config_api["binaryedge_key"]

    # Fuente seleccionada (--source)
    fuente = getattr(args, "source", "all")

    # Determinar qué fuentes se van a usar
    usar_shodan     = fuente in ("shodan", "all") and bool(shodan_key)
    usar_censys     = fuente in ("censys", "all") and bool(censys_id) and bool(censys_secret)
    usar_binaryedge = fuente in ("binaryedge", "all") and bool(binaryedge_key)

    if not usar_shodan and not usar_censys and not usar_binaryedge:
        # Si se forzó una fuente específica y no tiene key, avisar con error
        if fuente != "all":
            console.print(
                f"[red]✗ Fuente '{fuente}' seleccionada pero sin credenciales configuradas.[/]"
            )
            console.print(
                "[dim]Usa --key / --censys-id --censys-secret / --binaryedge-key "
                "o ~/.config/vampsec/config.toml[/]"
            )
            sys.exit(1)
        # Modo 'all' sin ninguna clave → mantener compatibilidad, requerir Shodan
        console.print(
            "[red]✗ Ninguna fuente configurada. "
            "Especifica al menos una clave (--key, --censys-id/--censys-secret, "
            "--binaryedge-key o ~/.config/vampsec/config.toml)[/]"
        )
        sys.exit(1)

    # Determinar modo y targets
    if args.cve:
        mode    = "cve"
        targets = [c.upper() for c in args.cve]
    elif args.product:
        mode    = "product"
        targets = [args.product]
    elif args.org:
        mode    = "org"
        targets = [args.org]
    else:
        mode    = "query"
        targets = [args.query]

    # Mostrar resumen de fuentes activas
    fuentes_activas = []
    if usar_shodan:
        fuentes_activas.append("Shodan")
    if usar_censys:
        fuentes_activas.append("Censys")
    if usar_binaryedge:
        fuentes_activas.append("BinaryEdge")

    console.print(
        f"\n[cyan]Modo: [bold]{mode}[/] · Targets: [bold]{len(targets)}[/] · "
        f"Límite: [bold]{args.limit}[/] hosts/consulta · "
        f"Fuentes: [bold]{', '.join(fuentes_activas)}[/][/]\n"
    )

    if args.count_only:
        # Modo rápido: solo conteos Shodan (sin traer resultados completos)
        if not usar_shodan:
            console.print(
                "[yellow]⚠ --count-only solo disponible con Shodan. "
                "Configura --key o SHODAN_API_KEY.[/]"
            )
            sys.exit(1)

        async def _count_only():
            async with aiohttp.ClientSession(
                headers={"User-Agent": f"VampSecureLabs-ShodanHunt/{VERSION}"}
            ) as session:
                hunter = ShodanHunter(shodan_key, limit=0)
                try:
                    info = await hunter.check_api(session)
                    console.print(
                        f"[green]✔ Shodan API OK — plan: {info.get('plan')} · "
                        f"créditos: {info.get('query_credits')}[/]"
                    )
                except ValueError as e:
                    console.print(f"[red]✗ {e}[/]")
                    sys.exit(1)

                t = Table(title="[cyan]Shodan — Conteos[/]", border_style="cyan")
                t.add_column("Target", width=40)
                t.add_column("Hosts expuestos", justify="right", width=18)

                for target in targets:
                    if mode == "cve":
                        query = f"vuln:{target}"
                    elif mode == "product":
                        query = f'product:"{target}"'
                    elif mode == "org":
                        query = f'org:"{target}"'
                    else:
                        query = target

                    count = await hunter._count(session, query)
                    sev   = _exposure_severity(count) if count >= 0 else "INFO"
                    style = SEV_STYLE.get(sev, "white")
                    t.add_row(
                        target[:40],
                        f"[{style}]{count:,}[/]" if count >= 0 else "[red]error[/]",
                    )

                console.print(t)

        asyncio.run(_count_only())
        return

    # Ejecución completa — consultar todas las fuentes con key disponible
    results: list[HuntResult] = []

    if usar_shodan:
        hunter_shodan = ShodanHunter(shodan_key, limit=args.limit)
        resultados_shodan = asyncio.run(hunter_shodan.run(mode, targets))
        results.extend(resultados_shodan)

    if usar_censys:
        hunter_censys = CensysHunter(censys_id, censys_secret, limit=args.limit)
        resultados_censys = asyncio.run(hunter_censys.run(mode, targets))
        results.extend(resultados_censys)

    if usar_binaryedge:
        hunter_be = BinaryEdgeHunter(binaryedge_key, limit=args.limit)
        resultados_be = asyncio.run(hunter_be.run(mode, targets))
        results.extend(resultados_be)

    console.print()
    print_summary_table(results)

    for i, r in enumerate(results, 1):
        console.print()
        print_detail(r, f"SHOD-{i:03d}")

    generated_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.output:
        Path(args.output).write_text(
            to_json(results, mode, generated_at), encoding="utf-8"
        )
        console.print(f"\n[green]✔ JSON guardado en {args.output}[/]")

    # ── Export oracle (formato de entrada para vamp-cve-oracle) ─────────────
    export_oracle_path: str | None = getattr(args, "export_oracle", None)
    if export_oracle_path:
        oracle_json = to_oracle_json(results)
        Path(export_oracle_path).write_text(oracle_json, encoding="utf-8")
        n_oracle = len(json.loads(oracle_json))
        console.print(
            f"[green]✔ Oracle export:[/] {export_oracle_path} ({n_oracle} entradas)"
        )

        # ── Pipeline automático a vamp-cve-oracle ────────────────────────────
        pipe_cmd: str | None = getattr(args, "pipe_oracle", None)
        if pipe_cmd:
            import subprocess
            cmd_full = f"{pipe_cmd} {export_oracle_path}"
            console.print(f"[cyan]→ Ejecutando:[/] {cmd_full}")
            try:
                proc = subprocess.run(
                    cmd_full,
                    shell=True,
                    check=False,
                )
                if proc.returncode != 0:
                    console.print(
                        f"[yellow]⚠ vamp-cve-oracle terminó con código {proc.returncode}[/]"
                    )
            except FileNotFoundError:
                console.print(
                    "[red]✗ Comando no encontrado. Asegúrate de que vamp-cve-oracle "
                    "está instalado y en PATH.[/]"
                )
            except Exception as exc:
                console.print(f"[red]✗ Error al ejecutar pipeline: {exc}[/]")

    if args.report_html or args.report_pdf:
        from vampsec_report import VampSecReport, meta_from_args
        meta    = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        vsl_rep = VampSecReport(meta, _findings_vsl(results))
        if args.report_html:
            vsl_rep.to_html_client(args.report_html)
            console.print(f"[green]✔ Informe cliente HTML: {args.report_html}[/]")
        if args.report_pdf:
            try:
                vsl_rep.to_pdf(args.report_pdf)
                console.print(f"[green]✔ Informe cliente PDF: {args.report_pdf}[/]")
            except RuntimeError as e:
                console.print(f"[yellow]⚠ PDF no generado: {e}[/]")

    # Mensaje informativo si hay fuentes de inteligencia no configuradas
    fuentes_faltantes = []
    if not usar_censys:
        fuentes_faltantes.append(
            "  → Censys (plan gratuito): censys.io/register "
            "→ --censys-id/--censys-secret o ~/.config/vampsec/config.toml"
        )
    if not usar_binaryedge:
        fuentes_faltantes.append(
            "  → BinaryEdge (de pago): binaryedge.io "
            "→ --binaryedge-key o ~/.config/vampsec/config.toml"
        )
    if not usar_shodan:
        fuentes_faltantes.append(
            "  → Shodan (freemium): shodan.io "
            "→ --key o ~/.config/vampsec/config.toml"
        )
    if fuentes_faltantes:
        console.print("\n[dim][INFO] Fuentes de inteligencia no configuradas:[/]")
        for msg in fuentes_faltantes:
            console.print(f"[dim]{msg}[/]")

    # Código de salida según severidad máxima
    max_total = max((r.total for r in results if not r.error), default=0)
    sev = _exposure_severity(max_total)
    if sev == "CRITICAL":
        sys.exit(2)
    if sev in ("HIGH", "MEDIUM"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
