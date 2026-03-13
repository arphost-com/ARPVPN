import pytest

from arpvpn.common.models.tenant import Tenant, tenants
from arpvpn.common.models.user import User, users
from arpvpn.tests.utils import default_cleanup, get_testing_app


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
    assert response.status_code == 200


@pytest.mark.parametrize(
    ("role", "expected_status"),
    [
        (User.ROLE_ADMIN, 200),
        (User.ROLE_SUPPORT, 403),
        (User.ROLE_CLIENT, 403),
    ],
)
def test_global_backup_access_matrix(client, role: str, expected_status: int):
    create_user("user1", "pass1", role)
    login(client, "user1", "pass1")

    response = client.get("/api/v1/system/backup")
    assert response.status_code == expected_status


def test_tenant_tls_matrix_for_admin_support_and_tenant_admin(client):
    tenant = create_tenant("Tenant One")
    admin = create_user("admin", "admin", User.ROLE_ADMIN)
    support = create_user("support", "support", User.ROLE_SUPPORT)
    tenant_admin = create_user("tenant-admin", "tenantpass", User.ROLE_TENANT_ADMIN, tenant.id)

    assert admin.role == User.ROLE_ADMIN
    assert support.role == User.ROLE_SUPPORT

    login(client, "support", "support")
    support_read = client.get(f"/api/v1/tenants/{tenant.id}/tls/status")
    support_write = client.put(f"/api/v1/tenants/{tenant.id}/tls", json={"mode": "http"})
    assert support_read.status_code == 200
    assert support_write.status_code == 403

    client.get("/logout", follow_redirects=True)
    login(client, "tenant-admin", "tenantpass")
    tenant_read = client.get(f"/api/v1/tenants/{tenant.id}/tls/status")
    tenant_write = client.put(
        f"/api/v1/tenants/{tenant.id}/tls",
        json={"mode": "self_signed", "server_name": "tenant.example.test"},
        headers={"Idempotency-Key": "tenant-matrix"},
    )
    assert tenant_read.status_code == 200
    assert tenant_write.status_code == 200


@pytest.mark.parametrize(
    ("role", "expected_status"),
    [
        (User.ROLE_ADMIN, 200),
        (User.ROLE_SUPPORT, 403),
    ],
)
def test_global_tls_mutation_matrix(client, role: str, expected_status: int):
    create_user("user1", "pass1", role)
    login(client, "user1", "pass1")

    response = client.post(
        "/api/v1/tls/mode",
        json={"mode": "http", "redirect_http_to_https": False},
    )
    assert response.status_code == expected_status
