import pytest
from flask_login import current_user

from arpvpn.common.models.user import User, users
from arpvpn.common.utils.mfa import generate_mfa_code, generate_mfa_secret, generate_recovery_codes, recovery_code_hashes
from arpvpn.tests.utils import default_cleanup, get_testing_app, is_http_success, login, password, username


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def test_login_requires_mfa_code_when_enabled(client):
    user = User(username)
    user.password = password
    user.enable_mfa(generate_mfa_secret(), recovery_code_hashes(generate_recovery_codes(count=1)))
    users[user.id] = user

    response = client.post(
        "/login",
        data={"username": username, "password": password, "remember_me": False},
        follow_redirects=True,
    )

    assert is_http_success(response.status_code)
    assert not current_user.is_authenticated
    assert b"Invalid MFA code" in response.data


def test_login_succeeds_with_mfa_code(client):
    user = User(username)
    user.password = password
    user.enable_mfa(generate_mfa_secret(), recovery_code_hashes(generate_recovery_codes(count=1)))
    users[user.id] = user

    response = client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "mfa_code": generate_mfa_code(user.mfa_secret),
            "remember_me": False,
        },
        follow_redirects=True,
    )

    assert is_http_success(response.status_code)
    assert current_user.is_authenticated
    assert current_user.name == username
    assert b"Dashboard" in response.data


def test_profile_mfa_setup_and_disable(client):
    login(client)

    generate_response = client.post("/profile", data={"generate_secret": "Generate MFA secret"})
    assert is_http_success(generate_response.status_code)
    assert b"MFA setup is in progress" in generate_response.data
    assert current_user.mfa_secret
    assert not current_user.mfa_enabled

    enable_response = client.post(
        "/profile",
        data={
            "mfa_code": generate_mfa_code(current_user.mfa_secret),
            "enable": "Enable MFA",
        },
    )
    assert is_http_success(enable_response.status_code)
    assert current_user.mfa_enabled
    assert b"MFA enabled!" in enable_response.data

    disable_response = client.post("/profile", data={"disable": "Disable MFA"})
    assert is_http_success(disable_response.status_code)
    assert not current_user.mfa_enabled
    assert current_user.mfa_secret is None
    assert b"MFA disabled!" in disable_response.data

