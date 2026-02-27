from datetime import datetime, timedelta
from ipaddress import IPv4Address

import pytest

from arpvpn.common.models.user import User, users
from arpvpn.core.models import Interface, interfaces, Peer
from arpvpn.tests.utils import default_cleanup, is_http_success, get_testing_app
from arpvpn.web.client import Client, clients


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


def test_statistics_api_admin_scope(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    iface, peers = setup_interface_with_peers(["client01", "client02"])
    login(client, "admin", "admin")

    response = client.get("/api/v1/stats/statistics")
    assert is_http_success(response.status_code)
    payload = response.get_json()
    assert payload["scope"] == "staff"
    names = [item["name"] for item in payload["connections"]]
    assert iface.name in names
    assert peers[0].name in names
    assert peers[1].name in names


def test_statistics_api_client_scope(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    create_user("client02", "clientpass", User.ROLE_CLIENT)
    iface, peers = setup_interface_with_peers(["client01", "client02"])
    login(client, "client01", "clientpass")

    response = client.get("/api/v1/stats/statistics")
    assert is_http_success(response.status_code)
    payload = response.get_json()
    assert payload["scope"] == "client"
    names = [item["name"] for item in payload["connections"]]
    assert iface.name in names
    assert peers[0].name in names
    assert peers[1].name not in names
    assert payload["log_summary"]["recent_issues"] == []


def test_rollups_api_and_csv_available(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    setup_interface_with_peers(["client01"])
    login(client, "admin", "admin")

    response = client.get("/api/v1/stats/rollups")
    assert is_http_success(response.status_code)
    payload = response.get_json()
    assert payload["rollup_windows"] == ["hour", "day", "week", "month"]
    assert "hour" in payload["totals"]
    assert "connections" in payload

    response = client.get("/api/v1/stats/rollups.csv")
    assert is_http_success(response.status_code)
    assert b"hour_total_bytes" in response.data
    assert b"month_total_human" in response.data


def test_failures_api_reports_active_login_bans(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    banned = Client(IPv4Address("10.88.0.12"))
    banned.banned_until = datetime.now() + timedelta(seconds=120)
    clients[banned.ip] = banned

    response = client.get("/api/v1/stats/failures")
    assert is_http_success(response.status_code)
    payload = response.get_json()
    assert payload["failure_metrics"]["active_login_bans"] >= 1
