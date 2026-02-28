import pytest

from arpvpn.common.models.user import User, users
from arpvpn.core.config.web import config as web_config
from arpvpn.tests.utils import default_cleanup, is_http_success, get_testing_app


@pytest.fixture(autouse=True)
def cleanup():
    snapshot = {
        "tls_mode": web_config.tls_mode,
        "redirect_http_to_https": web_config.redirect_http_to_https,
    }
    yield
    web_config.tls_mode = snapshot["tls_mode"]
    web_config.redirect_http_to_https = snapshot["redirect_http_to_https"]
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


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


def test_theme_api_get_default_choice(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    response = client.get("/api/v1/themes")
    assert is_http_success(response.status_code)
    payload = response.get_json()
    assert payload["choice"] == "auto"
    assert payload["choices"] == ["auto", "light", "dark"]


def test_theme_api_set_and_read_choice(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    response = client.post("/api/v1/themes", json={"choice": "dark"})
    assert is_http_success(response.status_code)
    payload = response.get_json()
    assert payload["choice"] == "dark"
    assert "arpvpn_theme=dark" in response.headers.get("Set-Cookie", "")

    response = client.get("/api/v1/themes")
    assert is_http_success(response.status_code)
    payload = response.get_json()
    assert payload["choice"] == "dark"


def test_theme_api_rejects_invalid_choice(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    response = client.post("/api/v1/themes", json={"choice": "neon"})
    assert response.status_code == 400


def test_theme_cookie_secure_flag_matches_strict_https(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    web_config.tls_mode = web_config.TLS_MODE_SELF_SIGNED
    web_config.redirect_http_to_https = False
    response = client.post("/api/v1/themes", json={"choice": "dark"})
    assert is_http_success(response.status_code)
    assert "Secure;" not in response.headers.get("Set-Cookie", "")

    web_config.redirect_http_to_https = True
    response = client.post("/api/v1/themes", json={"choice": "light"})
    assert is_http_success(response.status_code)
    assert "Secure;" in response.headers.get("Set-Cookie", "")
