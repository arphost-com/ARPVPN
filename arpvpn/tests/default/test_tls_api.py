import pytest

from arpvpn.common.models.user import User, users
from arpvpn.core.config.web import config as web_config
from arpvpn.tests.utils import default_cleanup, get_testing_app, is_http_success


@pytest.fixture(autouse=True)
def cleanup():
    snapshot = {
        "tls_mode": web_config.tls_mode,
        "tls_server_name": web_config.tls_server_name,
        "tls_letsencrypt_email": web_config.tls_letsencrypt_email,
        "proxy_incoming_hostname": web_config.proxy_incoming_hostname,
        "redirect_http_to_https": web_config.redirect_http_to_https,
        "tls_cert_file": web_config.tls_cert_file,
        "tls_key_file": web_config.tls_key_file,
    }
    yield
    web_config.tls_mode = snapshot["tls_mode"]
    web_config.tls_server_name = snapshot["tls_server_name"]
    web_config.tls_letsencrypt_email = snapshot["tls_letsencrypt_email"]
    web_config.proxy_incoming_hostname = snapshot["proxy_incoming_hostname"]
    web_config.redirect_http_to_https = snapshot["redirect_http_to_https"]
    web_config.tls_cert_file = snapshot["tls_cert_file"]
    web_config.tls_key_file = snapshot["tls_key_file"]
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def create_user(name: str, password: str, role: str):
    user = User(name, role=role)
    user.password = password
    users[user.id] = user
    return user


def login(client, username: str, password: str):
    response = client.post(
        "/login",
        data={"username": username, "password": password, "remember_me": False},
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)


def test_tls_status_api_returns_envelope(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    response = client.get("/api/v1/tls/status")
    assert is_http_success(response.status_code)
    body = response.get_json()
    assert body["ok"] is True
    assert body["data"]["mode"] in web_config.TLS_MODES
    assert "certificate" in body["data"]


def test_tls_status_api_forbidden_for_client_role(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    login(client, "client01", "clientpass")

    response = client.get("/api/v1/tls/status")
    assert response.status_code == 403


def test_tls_mode_update_api_calls_apply(monkeypatch, client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    captured = {"calls": 0}

    def fake_apply(config, generate_self_signed=False, issue_letsencrypt=False):
        captured["calls"] += 1
        captured["mode"] = config.tls_mode
        captured["generate_self_signed"] = generate_self_signed
        captured["issue_letsencrypt"] = issue_letsencrypt

    monkeypatch.setattr("arpvpn.web.router.tls_manager.apply_web_tls_config", fake_apply)

    response = client.post(
        "/api/v1/tls/mode",
        json={
            "mode": "http",
            "redirect_http_to_https": True,
        },
    )
    assert is_http_success(response.status_code)
    body = response.get_json()
    assert body["ok"] is True
    assert captured["calls"] == 1
    assert captured["mode"] == "http"
    assert captured["generate_self_signed"] is False
    assert captured["issue_letsencrypt"] is False
    assert body["data"]["redirect_http_to_https"] is False


def test_tls_self_signed_api_calls_apply(monkeypatch, client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    captured = {"calls": 0}

    def fake_apply(config, generate_self_signed=False, issue_letsencrypt=False):
        captured["calls"] += 1
        captured["mode"] = config.tls_mode
        captured["server_name"] = config.tls_server_name
        captured["generate_self_signed"] = generate_self_signed
        captured["issue_letsencrypt"] = issue_letsencrypt

    monkeypatch.setattr("arpvpn.web.router.tls_manager.apply_web_tls_config", fake_apply)

    response = client.post(
        "/api/v1/tls/self-signed",
        json={
            "server_name": "vpn.example.test",
            "regenerate": True,
            "redirect_http_to_https": True,
        },
    )
    assert is_http_success(response.status_code)
    body = response.get_json()
    assert body["ok"] is True
    assert captured["calls"] == 1
    assert captured["mode"] == web_config.TLS_MODE_SELF_SIGNED
    assert captured["server_name"] == "vpn.example.test"
    assert captured["generate_self_signed"] is True
    assert captured["issue_letsencrypt"] is False


def test_tls_letsencrypt_api_calls_apply(monkeypatch, client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    captured = {"calls": 0}

    def fake_apply(config, generate_self_signed=False, issue_letsencrypt=False):
        captured["calls"] += 1
        captured["mode"] = config.tls_mode
        captured["server_name"] = config.tls_server_name
        captured["email"] = config.tls_letsencrypt_email
        captured["generate_self_signed"] = generate_self_signed
        captured["issue_letsencrypt"] = issue_letsencrypt

    monkeypatch.setattr("arpvpn.web.router.tls_manager.apply_web_tls_config", fake_apply)

    response = client.post(
        "/api/v1/tls/letsencrypt",
        json={
            "server_name": "vpn.example.test",
            "email": "ops@example.test",
            "issue_now": True,
            "redirect_http_to_https": True,
        },
    )
    assert is_http_success(response.status_code)
    body = response.get_json()
    assert body["ok"] is True
    assert captured["calls"] == 1
    assert captured["mode"] == web_config.TLS_MODE_LETS_ENCRYPT
    assert captured["server_name"] == "vpn.example.test"
    assert captured["email"] == "ops@example.test"
    assert captured["generate_self_signed"] is False
    assert captured["issue_letsencrypt"] is True
