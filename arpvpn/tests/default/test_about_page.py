import pytest

from arpvpn.tests.utils import default_cleanup, get_testing_app, is_http_success, login


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def test_about_page_contains_revision_arphost_and_wireguard_content(client):
    login(client)
    response = client.get("/about")
    assert is_http_success(response.status_code)
    assert b"Revision and Build" in response.data
    assert b"About ARPHost" in response.data
    assert b"About WireGuard" in response.data


def test_footer_uses_arphost_branding_without_github_link(client):
    login(client)
    response = client.get("/dashboard")
    assert is_http_success(response.status_code)
    assert b"arphost-logo-light.png" in response.data
    assert b"Github" not in response.data
