# © VampSecure Studios — VampSecure Labs Security Research Division
"""Tests unitarios para vamp-shodan-hunt."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Parchear dependencias opcionales antes de importar
with patch.dict("sys.modules", {
    "rich": MagicMock(),
    "rich.console": MagicMock(),
    "rich.table": MagicMock(),
    "rich.panel": MagicMock(),
    "rich.rule": MagicMock(),
}):
    import vamp_shodan_hunt as vsh


# ── Tests para _exposure_severity ────────────────────────────────────────────

class TestExposureSeverity:
    """Pruebas para la función de asignación de severidad por exposición."""

    def test_cero_hosts_es_info(self):
        """Sin hosts expuestos, la severidad debe ser INFO."""
        assert vsh._exposure_severity(0) == "INFO"

    def test_un_host_es_low(self):
        """Un único host expuesto debe generar severidad LOW."""
        assert vsh._exposure_severity(1) == "LOW"

    def test_999_hosts_es_low(self):
        """Menos de 1000 hosts debe mantenerse en LOW."""
        assert vsh._exposure_severity(999) == "LOW"

    def test_1000_hosts_es_medium(self):
        """Exactamente 1000 hosts debe elevar la severidad a MEDIUM."""
        assert vsh._exposure_severity(1000) == "MEDIUM"

    def test_9999_hosts_es_medium(self):
        """9999 hosts sigue siendo MEDIUM."""
        assert vsh._exposure_severity(9999) == "MEDIUM"

    def test_10000_hosts_es_high(self):
        """10000 hosts debe elevar la severidad a HIGH."""
        assert vsh._exposure_severity(10000) == "HIGH"

    def test_100000_hosts_es_critical(self):
        """100000 o más hosts expuestos debe generar severidad CRITICAL."""
        assert vsh._exposure_severity(100000) == "CRITICAL"

    def test_millon_de_hosts_es_critical(self):
        """Un millón de hosts debe ser CRITICAL."""
        assert vsh._exposure_severity(1_000_000) == "CRITICAL"


# ── Tests para cargar_config_api ─────────────────────────────────────────────

class TestCargarConfigApi:
    """Pruebas para la carga de configuración de APIs."""

    def test_cli_tiene_maxima_prioridad(self):
        """Los flags CLI deben sobreescribir variables de entorno y config file."""
        with patch.dict(os.environ, {"SHODAN_API_KEY": "clave-env"}):
            config = vsh.cargar_config_api(args_shodan_key="clave-cli")
        assert config["shodan_key"] == "clave-cli"

    def test_env_tiene_segunda_prioridad(self):
        """Las variables de entorno deben sobreescribir el fichero de config."""
        with patch.dict(os.environ, {"SHODAN_API_KEY": "clave-env"}, clear=False):
            config = vsh.cargar_config_api()
        assert config["shodan_key"] == "clave-env"

    def test_sin_config_devuelve_nones(self):
        """Sin configuración de ningún tipo, todas las claves deben ser None."""
        env_limpio = {k: v for k, v in os.environ.items()
                      if k not in ("SHODAN_API_KEY", "VAMPSEC_CENSYS_API_ID",
                                   "VAMPSEC_CENSYS_API_SECRET", "VAMPSEC_BINARYEDGE_KEY")}
        with patch.dict(os.environ, env_limpio, clear=True), \
             patch("pathlib.Path.exists", return_value=False):
            config = vsh.cargar_config_api()
        assert config["shodan_key"] is None
        assert config["censys_id"] is None

    def test_censys_requiere_id_y_secret(self):
        """Proporcionar solo Censys ID sin Secret debe dejar secret en None."""
        with patch.dict(os.environ, {}, clear=True), \
             patch("pathlib.Path.exists", return_value=False):
            config = vsh.cargar_config_api(args_censys_id="mi-id")
        assert config["censys_id"] == "mi-id"
        assert config["censys_secret"] is None


# ── Tests para ShodanHunter._aggregate ───────────────────────────────────────

class TestShodanHunterAggregate:
    """Pruebas para la agregación de resultados Shodan."""

    def test_aggregate_countries_frequency(self):
        """El conteo de países debe ordenarse por frecuencia descendente."""
        matches = [
            vsh.ShodanMatch(ip="1.1.1.1", port=443, org="", country="Spain", product="", version="", banner=""),
            vsh.ShodanMatch(ip="2.2.2.2", port=443, org="", country="Spain", product="", version="", banner=""),
            vsh.ShodanMatch(ip="3.3.3.3", port=443, org="", country="France", product="", version="", banner=""),
        ]
        hunter = vsh.ShodanHunter("test-key")
        top_c, _, _, _ = hunter._aggregate(matches)
        # Spain tiene más apariciones que France
        assert top_c[0][0] == "Spain"
        assert top_c[0][1] == 2

    def test_aggregate_ignora_vacios(self):
        """El conteo de países vacíos no debe incluir cadenas vacías."""
        matches = [
            vsh.ShodanMatch(ip="1.1.1.1", port=443, org="", country="", product="nginx", version="", banner=""),
            vsh.ShodanMatch(ip="2.2.2.2", port=443, org="", country="Spain", product="Apache", version="", banner=""),
        ]
        hunter = vsh.ShodanHunter("test-key")
        top_c, _, _, _ = hunter._aggregate(matches)
        # El country vacío no debe aparecer en el conteo
        paises = [c[0] for c in top_c]
        assert "" not in paises

    def test_aggregate_top_productos(self):
        """Los productos deben contarse y ordenarse por frecuencia."""
        matches = [
            vsh.ShodanMatch(ip="1.1.1.1", port=443, org="", country="", product="nginx", version="", banner=""),
            vsh.ShodanMatch(ip="2.2.2.2", port=80, org="", country="", product="nginx", version="", banner=""),
            vsh.ShodanMatch(ip="3.3.3.3", port=8080, org="", country="", product="Apache", version="", banner=""),
        ]
        hunter = vsh.ShodanHunter("test-key")
        _, _, top_p, _ = hunter._aggregate(matches)
        assert top_p[0][0] == "nginx"
        assert top_p[0][1] == 2


# ── Tests para ShodanHunter._search ──────────────────────────────────────────

class TestShodanHunterSearch:
    """Pruebas para la lógica de búsqueda y parseo de Shodan."""

    @pytest.mark.asyncio
    async def test_busqueda_parsea_matches(self, respuesta_shodan_search):
        """Los matches de Shodan deben mapearse a ShodanMatch correctamente."""
        hunter = vsh.ShodanHunter("test-key", limit=10)

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=respuesta_shodan_search)

        mock_get = MagicMock()
        mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_get.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_get)

        result = await hunter._search_page(mock_session, "product:nginx", 1)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_401_devuelve_lista_vacia(self):
        """Un HTTP 401 en la búsqueda debe devolver lista vacía sin excepción."""
        hunter = vsh.ShodanHunter("clave-invalida", limit=10)

        mock_resp = AsyncMock()
        mock_resp.status = 401

        mock_get = MagicMock()
        mock_get.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_get.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_get)

        result = await hunter._search_page(mock_session, "product:nginx", 1)
        assert result == []


# ── Tests para ShodanHunter.hunt_one ─────────────────────────────────────────

class TestShodanHunterHuntOne:
    """Pruebas para la búsqueda de un objetivo individual."""

    @pytest.mark.asyncio
    async def test_hunt_one_modo_cve_genera_query_correcta(self):
        """El modo CVE debe generar la query con el prefijo 'vuln:'."""
        hunter = vsh.ShodanHunter("test-key", limit=5)

        mock_count_resp = AsyncMock()
        mock_count_resp.status = 200
        mock_count_resp.json = AsyncMock(return_value={"total": 0})

        mock_get = MagicMock()
        mock_get.__aenter__ = AsyncMock(return_value=mock_count_resp)
        mock_get.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_get)

        result = await hunter.hunt_one("cve", "CVE-2024-1234", mock_session)
        # La query debe tener el formato correcto
        assert result.query == "vuln:CVE-2024-1234"
        assert result.mode == "cve"

    @pytest.mark.asyncio
    async def test_hunt_one_modo_org_genera_query_correcta(self):
        """El modo ORG debe generar la query con el prefijo 'org:'."""
        hunter = vsh.ShodanHunter("test-key", limit=5)

        mock_count_resp = AsyncMock()
        mock_count_resp.status = 200
        mock_count_resp.json = AsyncMock(return_value={"total": 0})

        mock_get = MagicMock()
        mock_get.__aenter__ = AsyncMock(return_value=mock_count_resp)
        mock_get.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_get)

        result = await hunter.hunt_one("org", "Ejemplo SL", mock_session)
        assert result.query == 'org:"Ejemplo SL"'
        assert result.mode == "org"


# ── Tests para CensysHunter._build_query ─────────────────────────────────────

class TestCensysHunterBuildQuery:
    """Pruebas para la construcción de consultas Censys."""

    def test_modo_cve_genera_query_censys(self):
        """El modo CVE debe generar la sintaxis correcta de Censys."""
        hunter = vsh.CensysHunter("id", "secret")
        query = hunter._build_query("cve", "CVE-2024-1234")
        assert "CVE-2024-1234" in query

    def test_modo_product_genera_query_censys(self):
        """El modo producto debe generar la sintaxis correcta de Censys."""
        hunter = vsh.CensysHunter("id", "secret")
        query = hunter._build_query("product", "nginx")
        assert "nginx" in query

    def test_modo_org_genera_query_censys(self):
        """El modo organización debe usar autonomous_system.name."""
        hunter = vsh.CensysHunter("id", "secret")
        query = hunter._build_query("org", "Test Corp")
        assert "autonomous_system" in query
        assert "Test Corp" in query
