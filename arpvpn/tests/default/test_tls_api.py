import pytest

from arpvpn.common.models.tenant import Tenant, tenants
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
        "http_port": web_config.http_port,
        "https_port": web_config.https_port,
    }
    yield
    web_config.tls_mode = snapshot["tls_mode"]
    web_config.tls_server_name = snapshot["tls_server_name"]
    web_config.tls_letsencrypt_email = snapshot["tls_letsencrypt_email"]
    web_config.proxy_incoming_hostname = snapshot["proxy_incoming_hostname"]
    web_config.redirect_http_to_https = snapshot["redirect_http_to_https"]
    web_config.tls_cert_file = snapshot["tls_cert_file"]
    web_config.tls_key_file = snapshot["tls_key_file"]
    web_config.http_port = snapshot["http_port"]
    web_config.https_port = snapshot["https_port"]
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def create_user(name: str, password: str, role: str, tenant_id: str = ""):
    user = User(name, role=role)
    user.tenant_id = tenant_id or None
    user.password = password
    users[user.id] = user
    return user


def create_tenant(name: str) -> Tenant:
    tenant = Tenant(name=name)
    tenants[tenant.id] = tenant
    return tenant


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
    assert body["data"]["http_port"] == web_config.http_port
    assert body["data"]["https_port"] == web_config.https_port
    assert "certificate" in body["data"]


def test_tls_status_api_forbidden_for_client_role(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    login(client, "client01", "clientpass")

    response = client.get("/api/v1/tls/status")
    assert response.status_code == 403


def test_support_can_read_tls_status_but_cannot_modify_tls_mode(client):
    create_user("support", "supportpass", User.ROLE_SUPPORT)
    login(client, "support", "supportpass")

    status_response = client.get("/api/v1/tls/status")
    assert status_response.status_code == 200

    update_response = client.post("/api/v1/tls/mode", json={"mode": "http"})
    assert update_response.status_code == 403


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


def test_tls_mode_update_rejects_single_label_self_signed_hostname(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    response = client.post(
        "/api/v1/tls/mode",
        json={
            "mode": "self_signed",
            "server_name": "arpvpn",
            "redirect_http_to_https": False,
        },
    )
    assert response.status_code == 400


def test_tls_mode_update_rejects_single_label_reverse_proxy_hostname(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    response = client.post(
        "/api/v1/tls/mode",
        json={
            "mode": "reverse_proxy",
            "proxy_incoming_hostname": "arpvpn",
        },
    )
    assert response.status_code == 400


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


def test_tenant_admin_can_manage_own_tenant_tls_settings(client):
    tenant = create_tenant("Tenant One")
    create_user("tenant-admin", "tenantpass", User.ROLE_TENANT_ADMIN, tenant.id)
    login(client, "tenant-admin", "tenantpass")

    get_response = client.get(f"/api/v1/tenants/{tenant.id}/tls/status")
    assert get_response.status_code == 200
    assert get_response.get_json()["data"]["tenant_id"] == tenant.id

    update_response = client.put(
        f"/api/v1/tenants/{tenant.id}/tls",
        json={
            "mode": "self_signed",
            "server_name": "tenant-one.example.test",
            "redirect_http_to_https": True,
        },
        headers={"Idempotency-Key": "tenant-tls-1"},
    )
    assert update_response.status_code == 200
    updated = update_response.get_json()["data"]
    assert updated["mode"] == "self_signed"
    assert updated["server_name"] == "tenant-one.example.test"
    assert updated["redirect_http_to_https"] is True


def test_tenant_admin_cannot_modify_other_tenant_tls_settings(client):
    tenant_one = create_tenant("Tenant One")
    tenant_two = create_tenant("Tenant Two")
    create_user("tenant-admin", "tenantpass", User.ROLE_TENANT_ADMIN, tenant_one.id)
    login(client, "tenant-admin", "tenantpass")

    response = client.put(
        f"/api/v1/tenants/{tenant_two.id}/tls",
        json={"mode": "http"},
    )
    assert response.status_code == 403
