import pytest

from arpvpn.core.config.web import config as web_config
from arpvpn.tests.utils import default_cleanup, get_testing_app


@pytest.fixture(autouse=True)
def cleanup():
    previous = {
        "tls_mode": web_config.tls_mode,
        "tls_server_name": web_config.tls_server_name,
        "proxy_incoming_hostname": web_config.proxy_incoming_hostname,
        "redirect_http_to_https": getattr(web_config, "redirect_http_to_https", False),
        "https_port": getattr(web_config, "https_port", 8086),
    }
    yield
    web_config.tls_mode = previous["tls_mode"]
    web_config.tls_server_name = previous["tls_server_name"]
    web_config.proxy_incoming_hostname = previous["proxy_incoming_hostname"]
    web_config.redirect_http_to_https = previous["redirect_http_to_https"]
    web_config.https_port = previous["https_port"]
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def test_http_redirect_disabled_when_flag_is_off(client):
    web_config.tls_mode = web_config.TLS_MODE_SELF_SIGNED
    web_config.tls_server_name = "vpn.example.com"
    web_config.redirect_http_to_https = False

    response = client.get("/login", base_url="http://vpn.example.com", follow_redirects=False)
    assert response.status_code != 307
    location = response.headers.get("Location", "")
    assert not location.startswith("https://vpn.example.com/")


def test_http_redirect_enabled_for_self_signed(client):
    web_config.tls_mode = web_config.TLS_MODE_SELF_SIGNED
    web_config.tls_server_name = "vpn.example.com"
    web_config.redirect_http_to_https = True

    response = client.get("/login", base_url="http://vpn.example.com", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == "https://vpn.example.com:8086/login"


def test_http_redirect_preserves_query_string(client):
    web_config.tls_mode = web_config.TLS_MODE_SELF_SIGNED
    web_config.tls_server_name = "vpn.example.com"
    web_config.redirect_http_to_https = True

    response = client.get(
        "/login?next=%2Fsettings",
        base_url="http://vpn.example.com",
        follow_redirects=False,
    )
    assert response.status_code == 307
    assert response.headers["Location"] == "https://vpn.example.com:8086/login?next=%2Fsettings"


def test_http_redirect_uses_reverse_proxy_hostname(client):
    web_config.tls_mode = web_config.TLS_MODE_REVERSE_PROXY
    web_config.proxy_incoming_hostname = "vpn.proxy.example.com"
    web_config.redirect_http_to_https = True

    response = client.get("/login", base_url="http://10.10.10.100:8085", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == "https://vpn.proxy.example.com/login"


def test_http_redirect_uses_custom_https_port(client):
    web_config.tls_mode = web_config.TLS_MODE_SELF_SIGNED
    web_config.tls_server_name = "vpn.example.com"
    web_config.redirect_http_to_https = True
    web_config.https_port = 9443

    response = client.get("/login", base_url="http://vpn.example.com:8085", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == "https://vpn.example.com:9443/login"


def test_http_redirect_falls_back_to_local_ip_for_invalid_tls_server_name(client, monkeypatch):
    import arpvpn.__main__ as app_main

    web_config.tls_mode = web_config.TLS_MODE_SELF_SIGNED
    web_config.tls_server_name = "arpvpn"
    web_config.redirect_http_to_https = True
    monkeypatch.setattr(app_main, "_detect_local_server_ip", lambda: "10.10.10.100")

    response = client.get("/login", base_url="http://arpvpn:8085", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == "https://10.10.10.100:8086/login"
