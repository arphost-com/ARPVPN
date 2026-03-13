import pytest

from arpvpn.common.models.user import User, users
from arpvpn.tests.utils import default_cleanup, get_testing_app, is_http_success


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    app = get_testing_app()
    previous = app.config.get("API_CSRF_ENABLED", False)
    app.config["API_CSRF_ENABLED"] = True
    with app.test_client() as client:
        yield client
    app.config["API_CSRF_ENABLED"] = previous


def create_user(name: str, password: str, role: str) -> User:
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


def test_cookie_authenticated_api_post_requires_csrf_token(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    missing_token = client.post("/api/v1/themes", json={"choice": "dark"})
    assert missing_token.status_code == 400
    assert missing_token.get_json()["error"]["code"] == "csrf_failed"

    token_response = client.get("/api/v1/auth/csrf")
    assert token_response.status_code == 200
    csrf_token = token_response.get_json()["data"]["csrf_token"]

    success_response = client.post(
        "/api/v1/themes",
        json={"choice": "dark"},
        headers={"X-CSRFToken": csrf_token},
    )
    assert success_response.status_code == 200
    assert success_response.get_json()["choice"] == "dark"


def test_bearer_token_api_post_does_not_require_cookie_csrf_header(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    token_response = client.post(
        "/api/v1/auth/token",
        json={"username": "admin", "password": "admin", "scope": "staff"},
    )
    assert token_response.status_code == 201
    token = token_response.get_json()["data"]["access_token"]

    response = client.post(
        "/api/v1/themes",
        json={"choice": "dark"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.get_json()["choice"] == "dark"
