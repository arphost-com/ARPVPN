import pytest

from arpvpn.common.models.tenant import Tenant, tenants, invitations
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


def login(client, username: str, password: str):
    response = client.post(
        "/login",
        data={"username": username, "password": password, "remember_me": False},
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)


def create_tenant_fixture(name: str) -> Tenant:
    tenant = Tenant(name)
    tenants[tenant.id] = tenant
    return tenant


def test_admin_can_crud_tenant_and_create_tenant_admin_user(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    tenant_response = client.post(
        "/api/v1/tenants",
        json={
            "name": "Tenant One",
            "domains": ["tenant1.example.com"],
            "ips": ["10.10.10.10"],
            "status": "active",
        },
    )
    assert tenant_response.status_code == 201
    tenant_body = tenant_response.get_json()
    tenant_id = tenant_body["data"]["id"]

    user_response = client.post(
        "/api/v1/users",
        json={
            "username": "tenant-admin",
            "password": "tenantpass",
            "role": User.ROLE_TENANT_ADMIN,
            "tenant_id": tenant_id,
        },
    )
    assert user_response.status_code == 201
    user_body = user_response.get_json()
    assert user_body["data"]["role"] == User.ROLE_TENANT_ADMIN
    assert user_body["data"]["tenant_id"] == tenant_id

    members_response = client.get(f"/api/v1/tenants/{tenant_id}/members")
    assert members_response.status_code == 200
    members_body = members_response.get_json()
    usernames = {item["username"] for item in members_body["data"]["items"]}
    assert "tenant-admin" in usernames


def test_tenant_admin_is_scoped_to_own_tenant_for_user_crud(client):
    tenant_one = create_tenant_fixture("Tenant One")
    tenant_two = create_tenant_fixture("Tenant Two")
    create_user("tenant-admin", "tenantpass", User.ROLE_TENANT_ADMIN, tenant_id=tenant_one.id)
    create_user("other-client", "clientpass", User.ROLE_CLIENT, tenant_id=tenant_two.id)

    login(client, "tenant-admin", "tenantpass")

    list_response = client.get("/api/v1/users")
    assert list_response.status_code == 200
    usernames = {item["username"] for item in list_response.get_json()["data"]["items"]}
    assert "tenant-admin" in usernames
    assert "other-client" not in usernames

    blocked_create = client.post(
        "/api/v1/users",
        json={
            "username": "bad-client",
            "password": "clientpass",
            "role": User.ROLE_CLIENT,
            "tenant_id": tenant_two.id,
        },
    )
    assert blocked_create.status_code == 403

    allowed_create = client.post(
        "/api/v1/users",
        json={
            "username": "tenant-client",
            "password": "clientpass",
            "role": User.ROLE_CLIENT,
        },
    )
    assert allowed_create.status_code == 201
    created_body = allowed_create.get_json()
    assert created_body["data"]["tenant_id"] == tenant_one.id


def test_support_cannot_create_tenant_admin_or_admin_via_api(client):
    tenant = create_tenant_fixture("Tenant One")
    create_user("support", "support", User.ROLE_SUPPORT)
    login(client, "support", "support")

    tenant_create_response = client.post(
        "/api/v1/tenants",
        json={
            "name": "Blocked Tenant",
        },
    )
    assert tenant_create_response.status_code == 403

    bad_role_response = client.post(
        "/api/v1/users",
        json={
            "username": "bad-admin",
            "password": "adminpass",
            "role": User.ROLE_ADMIN,
        },
    )
    assert bad_role_response.status_code == 403

    bad_tenant_admin_response = client.post(
        "/api/v1/users",
        json={
            "username": "bad-tenant-admin",
            "password": "tenantpass",
            "role": User.ROLE_TENANT_ADMIN,
            "tenant_id": tenant.id,
        },
    )
    assert bad_tenant_admin_response.status_code == 403


def test_invitation_lifecycle_can_create_and_accept_client_user(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    tenant = create_tenant_fixture("Tenant One")
    login(client, "admin", "admin")

    invite_response = client.post(
        "/api/v1/invitations",
        json={
            "tenant_id": tenant.id,
            "email": "client01@example.com",
            "role": User.ROLE_CLIENT,
        },
    )
    assert invite_response.status_code == 201
    invite_body = invite_response.get_json()
    invitation_id = invite_body["data"]["id"]
    accept_token = invite_body["data"]["accept_token"]

    accept_response = client.post(
        f"/api/v1/invitations/{invitation_id}/accept",
        json={
            "token": accept_token,
            "username": "client01",
            "password": "clientpass",
            "confirm": "clientpass",
        },
    )
    assert accept_response.status_code == 201
    accept_body = accept_response.get_json()
    assert accept_body["data"]["user"]["username"] == "client01"
    assert accept_body["data"]["user"]["tenant_id"] == tenant.id
    assert accept_body["data"]["invitation"]["status"] == "accepted"
    assert users.get_value_by_attr("name", "client01") is not None
    assert invitations[invitation_id].accepted_user_id == accept_body["data"]["user"]["id"]
