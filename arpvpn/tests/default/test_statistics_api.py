from datetime import datetime, timedelta
from ipaddress import IPv4Address

import pytest

from arpvpn.common.models.user import User, users
from arpvpn.core.config.traffic import config as traffic_config
from arpvpn.core.drivers.traffic_storage_driver import TrafficData
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
        private_key="test-iface-private",
        public_key="test-iface-public",
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
            private_key=f"test-peer-private-{idx}",
            public_key=f"test-peer-public-{idx}",
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
    envelope = response.get_json()
    assert envelope["ok"] is True
    payload = envelope["data"]
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
    envelope = response.get_json()
    assert envelope["ok"] is True
    payload = envelope["data"]
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
    envelope = response.get_json()
    assert envelope["ok"] is True
    payload = envelope["data"]
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
    envelope = response.get_json()
    assert envelope["ok"] is True
    payload = envelope["data"]
    assert payload["failure_metrics"]["active_login_bans"] >= 1


def test_stats_peers_and_alerts_client_scope(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    create_user("client02", "clientpass", User.ROLE_CLIENT)
    _, peers = setup_interface_with_peers(["client01", "client02"])
    login(client, "client01", "clientpass")

    peers_response = client.get("/api/v1/stats/peers")
    assert is_http_success(peers_response.status_code)
    peers_envelope = peers_response.get_json()
    assert peers_envelope["ok"] is True
    peers_payload = peers_envelope["data"]
    assert peers_payload["scope"] == "client"
    peer_names = [item["peer_name"] for item in peers_payload["peers"]]
    assert peers[0].name in peer_names
    assert peers[1].name not in peer_names

    alerts_response = client.get("/api/v1/stats/alerts")
    assert is_http_success(alerts_response.status_code)
    alerts_envelope = alerts_response.get_json()
    assert alerts_envelope["ok"] is True
    assert alerts_envelope["data"]["scope"] == "client"


def test_stats_history_and_rrd_api_scoped_access(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    create_user("client02", "clientpass", User.ROLE_CLIENT)
    iface, peers = setup_interface_with_peers(["client01", "client02"])
    login(client, "client01", "clientpass")

    own_history = client.get(f"/api/v1/stats/history/{peers[0].uuid}")
    assert is_http_success(own_history.status_code)
    own_history_envelope = own_history.get_json()
    assert own_history_envelope["ok"] is True
    own_history_payload = own_history_envelope["data"]
    assert own_history_payload["connection"]["name"] == peers[0].name
    assert own_history_payload["window"] == "24h"
    assert "rrd_image_url" in own_history_payload

    own_rrd = client.get(f"/api/v1/stats/rrd/{iface.uuid}")
    assert is_http_success(own_rrd.status_code)
    own_rrd_envelope = own_rrd.get_json()
    assert own_rrd_envelope["ok"] is True
    own_rrd_payload = own_rrd_envelope["data"]
    assert own_rrd_payload["connection"]["name"] == iface.name
    assert len(own_rrd_payload["windows"]) >= 1

    blocked_history = client.get(f"/api/v1/stats/history/{peers[1].uuid}")
    assert blocked_history.status_code == 403


def test_stats_history_uses_session_data_when_stored_history_missing(monkeypatch, client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    iface, peers = setup_interface_with_peers(["client01"])
    login(client, "admin", "admin")

    sample_ts = datetime.now()

    def fake_get_session_and_stored_data():
        return {
            sample_ts: {
                peers[0].uuid: TrafficData(4096, 2048),
                iface.uuid: TrafficData(2048, 4096),
            }
        }

    monkeypatch.setattr(traffic_config.driver, "get_session_and_stored_data", fake_get_session_and_stored_data)

    response = client.get(f"/api/v1/stats/history/{peers[0].uuid}")
    assert is_http_success(response.status_code)
    envelope = response.get_json()
    assert envelope["ok"] is True
    payload = envelope["data"]
    assert payload["points_count"] == 1
    assert payload["points"][0]["rx_bytes"] == 4096
    assert payload["points"][0]["tx_bytes"] == 2048
