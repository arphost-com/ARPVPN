import pytest

from arpvpn.common.models.user import User, users
from arpvpn.core.models import Interface, interfaces, Peer
from arpvpn.tests.utils import default_cleanup, is_http_success, get_testing_app


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


def setup_interface_with_peers(peer_names):
    iface = Interface(
        name="wgstats0",
        description="",
        gw_iface="eth0",
        ipv4_address="10.199.0.1/24",
        listen_port=53111,
        auto=False,
        on_up=[],
        on_down=[],
    )
    created_peers = []
    for idx, peer_name in enumerate(peer_names, start=2):
        peer = Peer(
            name=peer_name,
            description="",
            interface=iface,
            ipv4_address=f"10.199.0.{idx}/24",
            dns1="8.8.8.8",
            dns2="",
            nat=False,
        )
        iface.add_peer(peer)
        created_peers.append(peer)
    interfaces[iface.uuid] = iface
    interfaces.sort()
    return iface, created_peers


def test_admin_statistics_page_lists_interfaces_and_peers(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    iface, peers = setup_interface_with_peers(["client01", "client02"])
    login(client, "admin", "admin")

    response = client.get("/statistics")
    assert is_http_success(response.status_code)
    assert b"Connection history" in response.data
    assert b"Runtime log summary" in response.data
    assert f"/traffic/rrd/{iface.uuid}".encode() in response.data
    assert f"/traffic/rrd/{peers[0].uuid}".encode() in response.data
    assert f"/traffic/rrd/{peers[1].uuid}".encode() in response.data


def test_client_statistics_page_is_scoped_to_owned_peer(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    create_user("client02", "clientpass", User.ROLE_CLIENT)
    iface, peers = setup_interface_with_peers(["client01", "client02"])
    login(client, "client01", "clientpass")

    response = client.get("/statistics")
    assert is_http_success(response.status_code)
    assert b"client01" in response.data
    assert b"client02" not in response.data
    assert f"/traffic/rrd/{iface.uuid}".encode() in response.data
    assert f"/traffic/rrd/{peers[0].uuid}".encode() in response.data
    assert f"/traffic/rrd/{peers[1].uuid}".encode() not in response.data
