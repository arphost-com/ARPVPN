import pytest

from arpvpn.tests.utils import default_cleanup, get_testing_app, login
from arpvpn.web.api_schema import API_REQUEST_SCHEMAS


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def test_every_mutating_api_route_has_registered_request_schema():
    app = get_testing_app()
    missing = []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/v1"):
            continue
        if not ({"POST", "PUT", "PATCH", "DELETE"} & set(rule.methods)):
            continue
        endpoint_name = str(rule.endpoint).rsplit(".", 1)[-1]
        if endpoint_name not in API_REQUEST_SCHEMAS:
            missing.append(f"{endpoint_name}:{rule.rule}:{sorted({'POST', 'PUT', 'PATCH', 'DELETE'} & set(rule.methods))}")
    assert missing == []


def test_schema_registry_rejects_unknown_payload_fields(client):
    login(client)
    response = client.put(
        "/api/v1/profile",
        json={"username": "root-admin", "unexpected": True},
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["ok"] is False
    assert payload["error"]["message"] == "Payload contains unsupported field(s): unexpected."
