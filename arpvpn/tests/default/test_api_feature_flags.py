import pytest

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
    assert response.status_code == 200


def test_mesh_api_feature_flag_can_disable_mesh_group(client, monkeypatch):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")
    monkeypatch.setenv("ARPVPN_FEATURE_API_MESH", "0")

    response = client.get("/api/v1/mesh/overview")
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "feature_disabled"


def test_mesh_rollout_flag_can_disable_mesh_api(client, monkeypatch):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")
    monkeypatch.setenv("ARPVPN_FEATURE_MESH_V1", "0")

    api_response = client.get("/api/v1/mesh/overview")
    assert api_response.status_code == 404
    assert api_response.get_json()["error"]["code"] == "feature_disabled"


def test_acl_rollout_flag_can_disable_policy_endpoints(client, monkeypatch):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")
    monkeypatch.setenv("ARPVPN_FEATURE_ACL_V1", "0")

    response = client.post(
        "/api/v1/mesh/policy-simulate",
        json={"source_kind": "server", "source_id": "edge-a", "destination": "10.10.10.10"},
    )
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "feature_disabled"
