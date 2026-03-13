import pytest

from arpvpn.common.models.tenant import Tenant, tenants
from arpvpn.common.models.user import User, users
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


def test_admin_can_dry_run_and_import_users_in_bulk(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    tenant = create_tenant("Tenant One")
    login(client, "admin", "admin")

    rows = [
        {
            "username": "bulk-client-1",
            "password": "clientpass1",
            "role": User.ROLE_CLIENT,
            "tenant_id": tenant.id,
        },
        {
            "username": "bulk-tenant-admin",
            "password": "tenantpass1",
            "role": User.ROLE_TENANT_ADMIN,
            "tenant_id": tenant.id,
        },
    ]

    dry_run = client.post("/api/v1/users/import", json={"users": rows, "dry_run": True})
    assert dry_run.status_code == 200
    body = dry_run.get_json()["data"]
    assert body["validated_count"] == 2
    assert body["created_count"] == 0
    assert users.get_value_by_attr("name", "bulk-client-1") is None

    imported = client.post(
        "/api/v1/users/import",
        json={"users": rows},
        headers={"Idempotency-Key": "bulk-import-1"},
    )
    assert imported.status_code == 201
    imported_body = imported.get_json()["data"]
    assert imported_body["created_count"] == 2
    assert users.get_value_by_attr("name", "bulk-client-1") is not None

    replay = client.post(
        "/api/v1/users/import",
        json={"users": rows},
        headers={"Idempotency-Key": "bulk-import-1"},
    )
    assert replay.status_code == 201
    replay_body = replay.get_json()
    assert replay_body["meta"]["idempotent_replay"] is True

    exported = client.get(f"/api/v1/users/export?tenant_id={tenant.id}")
    assert exported.status_code == 200
    exported_usernames = {item["username"] for item in exported.get_json()["data"]["items"]}
    assert "bulk-client-1" in exported_usernames
    assert "bulk-tenant-admin" in exported_usernames

    exported_csv = client.get(f"/api/v1/users/export?tenant_id={tenant.id}&format=csv")
    assert exported_csv.status_code == 200
    assert b"bulk-client-1" in exported_csv.data


def test_tenant_admin_bulk_import_is_limited_to_client_role_and_own_tenant(client):
    tenant_one = create_tenant("Tenant One")
    tenant_two = create_tenant("Tenant Two")
    create_user("tenant-admin", "tenantpass", User.ROLE_TENANT_ADMIN, tenant_one.id)
    login(client, "tenant-admin", "tenantpass")

    blocked = client.post(
        "/api/v1/users/import",
        json={
            "users": [
                {
                    "username": "blocked-admin",
                    "password": "tenantpass",
                    "role": User.ROLE_TENANT_ADMIN,
                    "tenant_id": tenant_two.id,
                }
            ]
        },
    )
    assert blocked.status_code == 200
    blocked_body = blocked.get_json()["data"]
    assert blocked_body["created_count"] == 0
    assert blocked_body["error_count"] == 1
    assert users.get_value_by_attr("name", "blocked-admin") is None

    allowed = client.post(
        "/api/v1/users/import",
        json={
            "users": [
                {
                    "username": "tenant-client-1",
                    "password": "clientpass",
                    "role": User.ROLE_CLIENT,
                }
            ]
        },
    )
    assert allowed.status_code == 201
    created_user = users.get_value_by_attr("name", "tenant-client-1")
    assert created_user is not None
    assert created_user.tenant_id == tenant_one.id
