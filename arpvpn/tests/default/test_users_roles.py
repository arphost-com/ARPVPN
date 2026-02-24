import pytest
from flask_login import current_user

from arpvpn.common.models.user import User, users
from arpvpn.tests.utils import default_cleanup, is_http_success, get_testing_app


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def create_user(name: str, password: str, role: str) -> User:
    u = User(name, role=role)
    u.password = password
    users[u.id] = u
    return u


def login(client, username: str, password: str):
    response = client.post(
        "/login",
        data={"username": username, "password": password, "remember_me": False},
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)


def test_admin_can_create_client_user(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    response = client.post(
        "/users",
        data={
            "username": "client01",
            "password": "clientpass",
            "confirm": "clientpass",
            "role": User.ROLE_CLIENT,
        },
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)
    created = users.get_value_by_attr("name", "client01")
    assert created is not None
    assert created.role == User.ROLE_CLIENT


def test_support_can_impersonate_client_and_return(client):
    support = create_user("support", "support", User.ROLE_SUPPORT)
    client_user = create_user("client01", "clientpass", User.ROLE_CLIENT)
    login(client, "support", "support")

    response = client.post(f"/users/{client_user.id}/impersonate", data={}, follow_redirects=True)
    assert is_http_success(response.status_code)
    assert current_user.name == "client01"
    assert current_user.role == User.ROLE_CLIENT
    with client.session_transaction() as sess:
        assert sess.get("impersonator_user_id") == support.id

    response = client.post("/impersonation/stop", data={}, follow_redirects=True)
    assert is_http_success(response.status_code)
    assert current_user.name == "support"
    assert current_user.role == User.ROLE_SUPPORT


def test_client_forbidden_on_staff_routes(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    login(client, "client01", "clientpass")

    response = client.get("/users")
    assert response.status_code == 403

    response = client.get("/wireguard")
    assert response.status_code == 403


def test_support_cannot_create_admin_or_support(client):
    create_user("support", "support", User.ROLE_SUPPORT)
    login(client, "support", "support")

    response = client.post(
        "/users",
        data={
            "username": "admin2",
            "password": "adminpass",
            "confirm": "adminpass",
            "role": User.ROLE_ADMIN,
        },
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)
    assert users.get_value_by_attr("name", "admin2") is None
