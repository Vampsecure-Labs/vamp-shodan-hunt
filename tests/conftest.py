# © VampSecure Studios — VampSecure Labs Security Research Division
"""Fixtures compartidas para los tests de vamp-shodan-hunt."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def api_key_test():
    """Clave API de test (sin permisos reales)."""
    return "test-api-key-0000000000000000000000000000000"


@pytest.fixture
def respuesta_shodan_search():
    """Respuesta simulada del endpoint /shodan/host/search."""
    return {
        "matches": [
            {
                "ip_str": "1.1.1.1",
                "port": 443,
                "org": "Cloudflare Inc",
                "country_name": "United States",
                "product": "nginx",
                "version": "1.24.0",
                "data": "HTTP/1.1 200 OK",
                "vulns": {},
                "cpe23": ["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"],
            },
            {
                "ip_str": "2.2.2.2",
                "port": 80,
                "org": "OVH SAS",
                "country_name": "France",
                "product": "Apache httpd",
                "version": "2.4.51",
                "data": "HTTP/1.1 200 OK",
                "vulns": {"CVE-2021-41773": {}},
                "cpe": ["cpe:/a:apache:http_server:2.4.51"],
            },
            {
                "ip_str": "3.3.3.3",
                "port": 8080,
                "org": "Amazon Technologies Inc",
                "country_name": "United States",
                "product": "",
                "version": "",
                "data": "HTTP/1.1 401 Unauthorized",
                "vulns": {},
            },
        ]
    }


@pytest.fixture
def respuesta_shodan_count():
    """Respuesta simulada del endpoint /shodan/host/count."""
    return {"total": 150000}


@pytest.fixture
def respuesta_shodan_api_info():
    """Respuesta simulada del endpoint /api-info."""
    return {
        "plan": "dev",
        "query_credits": 95,
        "scan_credits": 50,
        "unlocked": True,
        "unlocked_left": 95,
    }


@pytest.fixture
def respuesta_censys_search():
    """Respuesta simulada del endpoint Censys v2 /hosts/search."""
    return {
        "result": {
            "total": 3,
            "hits": [
                {
                    "ip": "10.0.0.1",
                    "location": {"country": "Spain"},
                    "autonomous_system": {"name": "Test ISP"},
                    "services": [
                        {
                            "port": 443,
                            "banner": "HTTP/1.1 200 OK",
                            "software": [{"product": "nginx", "version": "1.24.0"}],
                        }
                    ],
                },
                {
                    "ip": "10.0.0.2",
                    "location": {"country": "Germany"},
                    "autonomous_system": {"name": "Deutsche Telekom"},
                    "services": [{"port": 22, "banner": "SSH-2.0-OpenSSH", "software": []}],
                },
            ],
            "links": {"next": None},
        }
    }
