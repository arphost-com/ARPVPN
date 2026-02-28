import pytest

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


def issue_token(client, username: str, password: str, scope: str = "all"):
    response = client.post(
        "/api/v1/auth/token",
        json={"username": username, "password": password, "scope": scope},
    )
    assert response.status_code == 201
    body = response.get_json()
    assert body["ok"] is True
    return body["data"]


def clear_client_session(client):
    with client.session_transaction() as session_data:
        session_data.clear()


def test_api_token_can_access_protected_stats_endpoint(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    token_data = issue_token(client, "admin", "admin", scope="staff")

    clear_client_session(client)
    response = client.get("/api/v1/stats/overview", headers={"Authorization": f"Bearer {token_data['access_token']}"})
    assert is_http_success(response.status_code)
    body = response.get_json()
    assert body["ok"] is True
    assert body["data"]["scope"] == "staff"


def test_api_refresh_rotates_refresh_token(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    token_data = issue_token(client, "admin", "admin")

    refreshed = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": token_data["refresh_token"]},
    )
    assert is_http_success(refreshed.status_code)
    refreshed_body = refreshed.get_json()
    assert refreshed_body["ok"] is True
    new_tokens = refreshed_body["data"]
    assert new_tokens["access_token"] != token_data["access_token"]
    assert new_tokens["refresh_token"] != token_data["refresh_token"]

    old_refresh = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": token_data["refresh_token"]},
    )
    assert old_refresh.status_code == 401


def test_api_revoke_invalidates_access_token(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    token_data = issue_token(client, "admin", "admin")

    revoke_response = client.post(
        "/api/v1/auth/revoke",
        json={"token": token_data["access_token"]},
        headers={"Authorization": f"Bearer {token_data['access_token']}"},
    )
    assert is_http_success(revoke_response.status_code)
    revoke_body = revoke_response.get_json()
    assert revoke_body["ok"] is True
    assert revoke_body["data"]["revoked"] is True

    clear_client_session(client)
    response = client.get("/api/v1/stats/overview", headers={"Authorization": f"Bearer {token_data['access_token']}"})
    assert response.status_code == 401


def test_api_force_logout_revokes_existing_tokens_only(client):
    admin = create_user("admin", "admin", User.ROLE_ADMIN)
    target = create_user("client01", "clientpass", User.ROLE_CLIENT)
    token_data = issue_token(client, "client01", "clientpass", scope="client")

    login(client, "admin", "admin")
    force_response = client.post(f"/api/v1/auth/force-logout/{target.id}")
    assert is_http_success(force_response.status_code)
    force_body = force_response.get_json()
    assert force_body["ok"] is True
    assert force_body["data"]["target_user_id"] == target.id

    clear_client_session(client)
    old_token_response = client.get(
        "/api/v1/stats/overview",
        headers={"Authorization": f"Bearer {token_data['access_token']}"},
    )
    assert old_token_response.status_code == 401

    fresh_token_data = issue_token(client, "client01", "clientpass", scope="client")
    clear_client_session(client)
    fresh_token_response = client.get(
        "/api/v1/stats/overview",
        headers={"Authorization": f"Bearer {fresh_token_data['access_token']}"},
    )
    assert is_http_success(fresh_token_response.status_code)

    # Keep admin referenced so role remains explicit in this test.
    assert admin.role == User.ROLE_ADMIN


def test_support_can_start_and_stop_impersonation_with_api(client):
    support = create_user("support", "support", User.ROLE_SUPPORT)
    client_user = create_user("client01", "clientpass", User.ROLE_CLIENT)
    login(client, "support", "support")

    start_response = client.post(f"/api/v1/impersonation/start/{client_user.id}")
    assert is_http_success(start_response.status_code)
    start_body = start_response.get_json()
    assert start_body["ok"] is True
    assert start_body["data"]["impersonating"] is True
    assert start_body["data"]["target_user_id"] == client_user.id

    stop_response = client.post("/api/v1/impersonation/stop")
    assert is_http_success(stop_response.status_code)
    stop_body = stop_response.get_json()
    assert stop_body["ok"] is True
    assert stop_body["data"]["impersonating"] is False
    assert stop_body["data"]["restored_user_id"] == support.id
