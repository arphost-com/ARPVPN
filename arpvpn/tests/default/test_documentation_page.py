import pytest

from arpvpn.common.models.user import User, users
from arpvpn.tests.utils import default_cleanup, get_testing_app, is_http_success, login


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def test_documentation_page_contains_tls_and_api_guidance(client):
    login(client)
    response = client.get("/documentation")
    assert is_http_success(response.status_code)
    assert b"Web Access and TLS" in response.data
    assert b"API and Automation" in response.data


def test_documentation_page_contains_site_to_site_guide(client):
    login(client)
    response = client.get("/documentation")
    assert is_http_success(response.status_code)
    assert b"Site-to-site Quick Guide" in response.data
    assert b"Remote site subnets" in response.data


def test_documentation_page_shows_site_to_site_guide_for_client_user(client):
    user = User("client", role=User.ROLE_CLIENT)
    user.password = "client"
    users[user.id] = user
    response = client.post(
        "/login",
        data={"username": "client", "password": "client", "remember_me": False},
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)

    response = client.get("/documentation")
    assert is_http_success(response.status_code)
    assert b"Site-to-site Quick Guide" in response.data
    assert b"Remote site subnets" in response.data


def test_themes_page_no_longer_shows_site_to_site_guide(client):
    login(client)
    response = client.get("/themes")
    assert is_http_success(response.status_code)
    assert b"Site-to-site Quick Guide" not in response.data
