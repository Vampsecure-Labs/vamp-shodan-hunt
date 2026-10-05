# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests de integración para vamp-shodan-hunt."""

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytestmark = pytest.mark.integration

with patch.dict("sys.modules", {
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.table": MagicMock(),
    "rich.panel": MagicMock(),
    "rich.rule": MagicMock(),
}):
    import vamp_shodan_hunt as vsh


# ── Test 1: ShodanHunter.run — flujo completo con mock aiohttp ───────────────

@pytest.mark.asyncio
async def test_shodan_hunter_run_completo(respuesta_shodan_search,
                                          respuesta_shodan_count,
                                          respuesta_shodan_api_info):
    """
    Verifica el flujo completo de ShodanHunter.run() con aiohttp mockeado:
    1. check_api — verifica clave y devuelve plan/créditos
    2. _count    — obtiene el total de hosts
    3. _search   — recupera la primera página de resultados
    """
    hunter = vsh.ShodanHunter("test-api-key", limit=10)

    # Mapear URLs a respuestas simuladas
    def get_side_effect(url, **kwargs):
        kwargs.get("params", {})
        mock_resp = AsyncMock()
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        if "api-info" in url:
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=respuesta_shodan_api_info)
        elif "/count" in url:
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=respuesta_shodan_count)
        elif "/search" in url:
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=respuesta_shodan_search)
        else:
            mock_resp.status = 404
            mock_resp.json = AsyncMock(return_value={})

        return mock_resp

    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=get_side_effect)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch.object(vsh.aiohttp, "ClientSession", return_value=mock_session):
        results = await hunter.run("product", ["nginx"])

    assert len(results) == 1
    result = results[0]
    assert result.mode == "product"
    assert result.total == 150000
    assert len(result.matches) == 3


# ── Test 2: ShodanHunter — sin resultados para query inexistente ──────────────

@pytest.mark.asyncio
async def test_shodan_hunter_sin_resultados():
    """
    Verifica que una query con 0 resultados devuelve un HuntResult sin matches.
    """
    hunter = vsh.ShodanHunter("test-api-key", limit=10)

    mock_resp_info = AsyncMock()
    mock_resp_info.status = 200
    mock_resp_info.json = AsyncMock(return_value={"plan": "free", "query_credits": 100})

    mock_resp_count = AsyncMock()
    mock_resp_count.status = 200
    mock_resp_count.json = AsyncMock(return_value={"total": 0})

    call_count = [0]

    def get_side(url, **kwargs):
        call_count[0] += 1
        mock = AsyncMock()
        mock.__aenter__ = AsyncMock(return_value=mock)
        mock.__aexit__ = AsyncMock(return_value=False)
        if "api-info" in url:
            mock.status = 200
            mock.json = AsyncMock(return_value={"plan": "free", "query_credits": 100})
        else:
            mock.status = 200
            mock.json = AsyncMock(return_value={"total": 0})
        return mock

    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=get_side)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch.object(vsh.aiohttp, "ClientSession", return_value=mock_session):
        results = await hunter.run("cve", ["CVE-9999-99999"])

    assert len(results) == 1
    assert results[0].total == 0
    assert results[0].matches == []


# ── Test 3: CensysHunter — mapeo de respuesta a ShodanMatch ──────────────────

@pytest.mark.asyncio
async def test_censys_hunter_mapeo_respuesta(respuesta_censys_search):
    """
    Verifica que CensysHunter._map_match() mapea los campos Censys
    a la estructura interna ShodanMatch correctamente.
    """
    hunter = vsh.CensysHunter("test-id", "test-secret")
    hit = respuesta_censys_search["result"]["hits"][0]
    match = hunter._map_match(hit)

    assert match.ip == "10.0.0.1"
    assert match.country == "Spain"
    assert match.org == "Test ISP"
    assert match.port == 443
    assert match.product == "nginx"
    assert match.version == "1.24.0"


# ── Test 4: CensysHunter — hunt_one con respuesta válida ─────────────────────

@pytest.mark.asyncio
async def test_censys_hunter_hunt_one_valido(respuesta_censys_search):
    """
    Verifica el flujo completo de CensysHunter.hunt_one() con mock aiohttp.
    """
    hunter = vsh.CensysHunter("test-id", "test-secret", limit=10)

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=respuesta_censys_search)
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)

    result = await hunter.hunt_one("product", "nginx", mock_session)

    assert result.mode == "product"
    assert len(result.matches) == 2
    assert result.matches[0].ip == "10.0.0.1"


# ── Test 5: _exposure_severity — transiciones de umbral ──────────────────────

def test_exposure_severity_umbrales():
    """
    Verifica que los umbrales de severidad producen las transiciones correctas
    en valores exactos en los límites.
    """
    # Tabla de valores límite
    casos = [
        (0, "INFO"),
        (1, "LOW"),
        (999, "LOW"),
        (1000, "MEDIUM"),
        (9999, "MEDIUM"),
        (10000, "HIGH"),
        (99999, "HIGH"),
        (100000, "CRITICAL"),
        (500000, "CRITICAL"),
    ]
    for count, esperada in casos:
        assert vsh._exposure_severity(count) == esperada, (
            f"_exposure_severity({count}) debería ser {esperada}"
        )
