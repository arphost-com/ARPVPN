import pytest

from arpvpn.common.models.tenant import Tenant, tenants
from arpvpn.common.models.user import User, users
from arpvpn.core.config.web import config as web_config
from arpvpn.core.managers.config import config_manager
from arpvpn.tests.utils import default_cleanup, get_testing_app, is_http_success


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def create_user(name: str, password: str, role: str, tenant_id: str = "") -> User:
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


def test_system_health_version_and_diagnostics_endpoints(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    version_response = client.get("/api/v1/system/version")
    assert version_response.status_code == 200
    assert version_response.get_json()["data"]["release"]

    health_response = client.get("/api/v1/system/health")
    assert health_response.status_code == 200
    assert health_response.get_json()["data"]["status"] == "ok"

    diagnostics_response = client.get("/api/v1/system/diagnostics")
    assert diagnostics_response.status_code == 200
    diagnostics = diagnostics_response.get_json()["data"]
    assert diagnostics["wireguard"]["wg_bin"] == "/bin/echo"


def test_admin_can_read_and_update_global_config_and_audit_log(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    get_response = client.get("/api/v1/config/global")
    assert get_response.status_code == 200

    update_response = client.put(
        "/api/v1/config/global",
        json={
            "web": {
                "http_port": 18085,
                "https_port": 18086,
                "tls_mode": "http",
                "redirect_http_to_https": False,
            }
        },
        headers={"Idempotency-Key": "global-config-1"},
    )
    assert update_response.status_code == 200
    payload = update_response.get_json()["data"]
    assert payload["web"]["http_port"] == 18085
    assert payload["web"]["https_port"] == 18086

    audit_response = client.get("/api/v1/audit/events?limit=10&action=config.global.update")
    assert audit_response.status_code == 200
    assert audit_response.get_json()["data"]["total"] >= 1


def test_tenant_admin_can_manage_own_tenant_config_but_not_global_config(client):
    tenant = create_tenant("Tenant One")
    create_user("tenant-admin", "tenantpass", User.ROLE_TENANT_ADMIN, tenant.id)
    login(client, "tenant-admin", "tenantpass")

    get_tenant_config = client.get(f"/api/v1/tenants/{tenant.id}/config")
    assert get_tenant_config.status_code == 200

    update_tenant_config = client.put(
        f"/api/v1/tenants/{tenant.id}/config",
        json={
            "settings": {
                "branding": {"company_name": "Tenant One"},
                "limits": {"max_clients": 25},
                "defaults": {"theme": "dark"},
                "dns_servers": ["8.8.8.8", "1.1.1.1"],
            }
        },
        headers={"Idempotency-Key": "tenant-config-1"},
    )
    assert update_tenant_config.status_code == 200
    settings = update_tenant_config.get_json()["data"]["settings"]
    assert settings["branding"]["company_name"] == "Tenant One"
    assert settings["limits"]["max_clients"] == 25

    blocked_global = client.put("/api/v1/config/global", json={"web": {"http_port": 8089}})
    assert blocked_global.status_code == 403


def test_admin_can_export_and_restore_backup_snapshot(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")
    config_manager.save()

    backup_response = client.get("/api/v1/system/backup")
    assert backup_response.status_code == 200
    backup_payload = backup_response.get_json()["data"]
    assert backup_payload["format"] == "arpvpn-backup-v1"
    assert backup_payload["files"]["config"]["exists"] is True

    original_http_port = web_config.http_port
    web_config.http_port = 19085
    config_manager.save()
    assert web_config.http_port == 19085

    dry_run = client.post(
        "/api/v1/system/restore",
        json={"backup": backup_payload, "dry_run": True},
        headers={"Idempotency-Key": "restore-dry-run"},
    )
    assert dry_run.status_code == 200
    assert dry_run.get_json()["data"]["dry_run"] is True
    assert web_config.http_port == 19085

    restore_response = client.post(
        "/api/v1/system/restore",
        json={"backup": backup_payload, "dry_run": False},
        headers={"Idempotency-Key": "restore-apply"},
    )
    assert restore_response.status_code == 200
    assert restore_response.get_json()["data"]["dry_run"] is False
    assert web_config.http_port == original_http_port


def test_support_cannot_export_or_restore_backup_snapshot(client):
    create_user("support", "supportpass", User.ROLE_SUPPORT)
    login(client, "support", "supportpass")

    backup_response = client.get("/api/v1/system/backup")
    assert backup_response.status_code == 403

    restore_response = client.post(
        "/api/v1/system/restore",
        json={"format": "arpvpn-backup-v1", "files": {}},
    )
    assert restore_response.status_code == 403
