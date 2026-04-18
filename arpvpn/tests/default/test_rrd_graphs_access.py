import pytest

from arpvpn.common.models.user import User, users
from arpvpn.core.models import Interface, interfaces, Peer
from arpvpn.web import router as web_router
from arpvpn.tests.utils import default_cleanup, is_http_success, get_testing_app


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def login(client, username: str, password: str):
    response = client.post(
        "/login",
        data={"username": username, "password": password, "remember_me": False},
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)


def create_user(name: str, password: str, role: str):
    user = User(name, role=role)
    user.password = password
    users[user.id] = user
    return user


def setup_connection(owner_name: str = "client01"):
    iface = Interface(
        name="wgdemo0",
        description="",
        gw_iface="eth0",
        ipv4_address="10.123.0.1/24",
        listen_port=53111,
        auto=False,
        on_up=[],
        on_down=[],
    )
    peer = Peer(
        name=owner_name,
        description="",
        interface=iface,
        ipv4_address="10.123.0.2/24",
        dns1="8.8.8.8",
        dns2="",
        nat=False,
    )
    iface.add_peer(peer)
    interfaces[iface.uuid] = iface
    interfaces.sort()
    return iface, peer


def test_admin_can_open_rrd_page(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    _, peer = setup_connection()
    login(client, "admin", "admin")

    response = client.get(f"/traffic/rrd/{peer.uuid}")
    assert is_http_success(response.status_code)
    assert b"RRD traffic history" in response.data


def test_client_can_open_own_peer_rrd_page(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    _, peer = setup_connection(owner_name="client01")
    login(client, "client01", "clientpass")

    response = client.get(f"/traffic/rrd/{peer.uuid}")
    assert is_http_success(response.status_code)


def test_client_cannot_open_other_peer_rrd_page(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    _, peer = setup_connection(owner_name="client02")
    login(client, "client01", "clientpass")

    response = client.get(f"/traffic/rrd/{peer.uuid}")
    assert response.status_code == 403


def test_client_can_open_owned_interface_rrd_page(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    iface, _ = setup_connection(owner_name="client01")
    login(client, "client01", "clientpass")

    response = client.get(f"/traffic/rrd/{iface.uuid}")
    assert is_http_success(response.status_code)


def test_rrd_png_is_cached_for_three_hours(client, monkeypatch):
    create_user("admin", "admin", User.ROLE_ADMIN)
    _, peer = setup_connection()
    login(client, "admin", "admin")

    render_calls = {"count": 0}

    def fake_render(uuid: str, window_seconds: int):
        render_calls["count"] += 1
        assert uuid == peer.uuid
        assert window_seconds == 24 * 60 * 60
        return b"fake-png"

    monkeypatch.setattr(web_router, "_render_rrd_graph_png", fake_render)

    response = client.get(f"/traffic/rrd/{peer.uuid}.png?window=24h")
    assert is_http_success(response.status_code)
    assert response.data == b"fake-png"
    assert response.headers["Cache-Control"] == "private, max-age=10800"

    response = client.get(f"/traffic/rrd/{peer.uuid}.png?window=24h")
    assert is_http_success(response.status_code)
    assert response.data == b"fake-png"
    assert render_calls["count"] == 1


def test_admin_dashboard_contains_rrd_links_for_connections(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    iface, peer = setup_connection(owner_name="client01")
    login(client, "admin", "admin")

    response = client.get("/dashboard")
    assert is_http_success(response.status_code)
    assert f"/traffic/rrd/{iface.uuid}".encode() in response.data
    assert f"/traffic/rrd/{peer.uuid}".encode() in response.data


def test_client_dashboard_contains_rrd_links_for_owned_connections(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    iface, peer = setup_connection(owner_name="client01")
    login(client, "client01", "clientpass")

    response = client.get("/dashboard")
    assert is_http_success(response.status_code)
    assert f"/traffic/rrd/{iface.uuid}".encode() in response.data
    assert f"/traffic/rrd/{peer.uuid}".encode() in response.data
