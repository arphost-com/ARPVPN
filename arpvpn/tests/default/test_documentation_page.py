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


def test_documentation_page_contains_tls_and_api_guidance(client):
    login(client)
    response = client.get("/documentation")
    assert is_http_success(response.status_code)
    assert b"Mesh VPNs" not in response.data
    assert b"Web Access and TLS" in response.data
    assert b"API and Automation" in response.data
