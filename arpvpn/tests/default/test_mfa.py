import pytest
from flask_login import current_user

from arpvpn.common.models.user import User, users
from arpvpn.common.utils.mfa import generate_mfa_code, generate_mfa_secret, generate_recovery_codes, recovery_code_hashes
from arpvpn.core.models import Interface, Peer, interfaces
from arpvpn.tests.utils import default_cleanup, get_test_gateway, get_testing_app, is_http_success, login, password, username


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


def test_client_peer_view_requires_mfa_and_allows_download_after_mfa_login(client):
    user = User("client01", role=User.ROLE_CLIENT)
    user.password = "clientpass"
    users[user.id] = user

    iface = Interface(
        name="wgmfa0",
        description="",
        gw_iface=get_test_gateway(),
        ipv4_address="10.49.0.1/24",
        listen_port=51041,
        auto=False,
        on_up=[],
        on_down=[],
        private_key="iface-private-key",
        public_key="iface-public-key",
    )
    peer = Peer(
        name="client01",
        description="",
        interface=iface,
        ipv4_address="10.49.0.2/24",
        dns1="8.8.8.8",
        dns2="",
        nat=False,
        private_key="peer-private-key",
        public_key="peer-public-key",
        owner_user_id=user.id,
    )
    iface.add_peer(peer)
    interfaces[iface.uuid] = iface
    interfaces.sort()

    first_login = client.post(
        "/login",
        data={"username": "client01", "password": "clientpass", "remember_me": False},
        follow_redirects=True,
    )
    assert is_http_success(first_login.status_code)
    blocked = client.get(f"/wireguard/peers/{peer.uuid}")
    assert blocked.status_code == 403
    assert b"Enable MFA in Profile" in blocked.data

    user.enable_mfa(generate_mfa_secret(), recovery_code_hashes(generate_recovery_codes(count=1)))
    response = client.post(
        "/login",
        data={
            "username": "client01",
            "password": "clientpass",
            "mfa_code": generate_mfa_code(user.mfa_secret),
            "remember_me": False,
        },
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)

    peer_view = client.get(f"/wireguard/peers/{peer.uuid}")
    assert is_http_success(peer_view.status_code)
    assert b"This connection is read-only for your account." in peer_view.data

    download = client.get(f"/wireguard/peers/{peer.uuid}/download")
    assert is_http_success(download.status_code)
    assert b"AllowedIPs" in download.data
