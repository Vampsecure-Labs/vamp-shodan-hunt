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

import asyncio
import aiohttp
import argparse
import json
import os
import sys
import textwrap
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule

console = Console()

VERSION   = "1.0"
TOOL_NAME = "vamp-shodan-hunt"

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___ 
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-shodan-hunt v1.0 · OSINT Exposure Intelligence
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# Endpoints Shodan — llamadas REST directas sin SDK
SHODAN_API_INFO = "https://api.shodan.io/api-info"
SHODAN_COUNT    = "https://api.shodan.io/shodan/host/count"
SHODAN_SEARCH   = "https://api.shodan.io/shodan/host/search"

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
    vulns:   List[str] = field(default_factory=list)


@dataclass
class HuntResult:
    """Resultado completo de una consulta (un modo + un target)."""
    mode:          str               # cve | product | org | query
    query:         str               # Query Shodan enviada
    label:         str               # CVE ID / nombre producto / org / raw
    total:         int               # Total hosts en Shodan (endpoint /count)
    matches:       List[ShodanMatch] = field(default_factory=list)
    top_countries: List[Tuple[str, int]] = field(default_factory=list)
    top_orgs:      List[Tuple[str, int]] = field(default_factory=list)
    top_products:  List[Tuple[str, int]] = field(default_factory=list)
    top_versions:  List[Tuple[str, int]] = field(default_factory=list)
    error:         Optional[str] = None


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

    async def check_api(self, session: aiohttp.ClientSession) -> Dict:
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
    ) -> List[Dict]:
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
    ) -> List[ShodanMatch]:
        """Trae hasta self._limit hosts paginando la API de Shodan."""
        matches: List[ShodanMatch] = []
        page = 1

        while len(matches) < self._limit:
            raw = await self._search_page(session, query, page)
            if not raw:
                break
            for m in raw:
                if len(matches) >= self._limit:
                    break
                matches.append(ShodanMatch(
                    ip      = m.get("ip_str", ""),
                    port    = m.get("port", 0),
                    org     = m.get("org", ""),
                    country = m.get("country_name", ""),
                    product = m.get("product", ""),
                    version = m.get("version", ""),
                    banner  = (m.get("data", "") or "")[:140].replace("\n", " ").strip(),
                    vulns   = list((m.get("vulns") or {}).keys()),
                ))
            if len(raw) < 100:
                break
            page += 1

        return matches

    def _aggregate(self, matches: List[ShodanMatch]) -> Tuple:
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

    async def run(self, mode: str, targets: List[str]) -> List[HuntResult]:
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
# Generación de hallazgos VSL
# ────────────────────────────────────────────────────────────────────────────

def _findings_vsl(results: List[HuntResult]) -> List:
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
                f"Revisar si todos los servicios expuestos son intencionales. "
                f"Aplicar el principio de mínima exposición: solo exponer lo estrictamente necesario. "
                f"Implementar monitorización continua de la superficie de ataque externa."
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

def print_summary_table(results: List[HuntResult]) -> None:
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

def to_json(results: List[HuntResult], mode: str, generated_at: str) -> str:
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

    # Opciones generales
    p.add_argument(
        "--key", metavar="API_KEY",
        help="Clave API de Shodan (alternativa: variable SHODAN_API_KEY)",
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

    from vampsec_report import add_report_args
    add_report_args(p)

    args = p.parse_args()

    # Resolver clave API
    shodan_key = args.key or os.environ.get("SHODAN_API_KEY", "")
    if not shodan_key:
        console.print(
            "[red]✗ Clave API de Shodan requerida: usa --key o exporta SHODAN_API_KEY[/]"
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

    console.print(
        f"\n[cyan]Modo: [bold]{mode}[/] · Targets: [bold]{len(targets)}[/] · "
        f"Límite: [bold]{args.limit}[/] hosts/consulta[/]\n"
    )

    if args.count_only:
        # Modo rápido: solo conteos, sin traer resultados
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

    # Ejecución completa
    hunter  = ShodanHunter(shodan_key, limit=args.limit)
    results = asyncio.run(hunter.run(mode, targets))

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
