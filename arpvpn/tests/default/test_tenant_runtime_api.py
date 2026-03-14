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


def test_admin_can_allocate_and_control_tenant_runtime(client):
    tenant = create_tenant("Tenant One")
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    allocate = client.post(
        f"/api/v1/tenants/{tenant.id}/runtime/allocate",
        headers={"Idempotency-Key": "runtime-allocate-1"},
    )
    assert allocate.status_code == 200
    runtime = allocate.get_json()["data"]["runtime"]
    assert runtime["allocated"] is True
    assert runtime["http_port"] > 0
    assert runtime["https_port"] > 0
    assert runtime["vpn_port"] > 0

    start = client.post(
        f"/api/v1/tenants/{tenant.id}/runtime/start",
        headers={"Idempotency-Key": "runtime-start-1"},
    )
    assert start.status_code == 200
    assert start.get_json()["data"]["runtime"]["status"] == "running"


def test_tenant_admin_can_manage_only_own_runtime(client):
    tenant_one = create_tenant("Tenant One")
    tenant_two = create_tenant("Tenant Two")
    create_user("tenant-admin", "tenantpass", User.ROLE_TENANT_ADMIN, tenant_one.id)
    login(client, "tenant-admin", "tenantpass")

    own_allocate = client.post(
        f"/api/v1/tenants/{tenant_one.id}/runtime/allocate",
        headers={"Idempotency-Key": "runtime-own-1"},
    )
    assert own_allocate.status_code == 200

    other_get = client.get(f"/api/v1/tenants/{tenant_two.id}/runtime")
    assert other_get.status_code == 403


def test_support_cannot_mutate_tenant_runtime(client):
    tenant = create_tenant("Tenant One")
    create_user("support", "supportpass", User.ROLE_SUPPORT)
    login(client, "support", "supportpass")

    get_response = client.get(f"/api/v1/tenants/{tenant.id}/runtime")
    assert get_response.status_code == 200

    update_response = client.put(
        f"/api/v1/tenants/{tenant.id}/runtime",
        json={"http_port": 28085},
    )
    assert update_response.status_code == 403
