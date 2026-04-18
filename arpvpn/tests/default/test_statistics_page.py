from datetime import datetime, timedelta
from ipaddress import IPv4Address

import pytest

from arpvpn.common.models.user import User, users
from arpvpn.web.client import Client, clients
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


def fake_log_diagnostics():
    return {
        "available": True,
        "logfile": "/tmp/arpvpn.log",
        "total_lines": 4587,
        "tail_lines": 3,
        "warning_lines": 48,
        "error_lines": 37,
        "suppressed_issue_lines": 0,
        "issue_entries": [
            "[WARNING] sample warning",
            "[ERROR] sample error",
        ],
        "tail_entries": [
            "[INFO] boot complete",
            "[WARNING] sample warning",
            "[ERROR] sample error",
        ],
        "read_error": None,
        "auth_failures": 6,
        "interface_failures": 0,
        "tls_failures": 0,
        "rrd_failures": 0,
        "active_login_bans": 0,
        "total": 6,
    }


def fake_peer_runtime(peer: Peer, iface: Interface):
    now = datetime.now()
    handshake_ago = "2 hours ago"
    return {
        "totals": {
            "peers": 1,
            "site_to_site_peers": 0,
            "client_peers": 1,
            "active_peers": 0,
            "stale_peers": 1,
            "offline_peers": 0,
            "never_seen_peers": 0,
            "high_traffic_peers": 0,
            "session_rx": 0,
            "session_tx": 0,
            "session_total": 0,
            "session_rx_human": "0 B",
            "session_tx_human": "0 B",
            "session_total_human": "0 B",
            "alerts": 0,
        },
        "rows": [{
            "peer": peer,
            "peer_uuid": peer.uuid,
            "peer_name": peer.name,
            "interface_uuid": iface.uuid,
            "interface_name": iface.name,
            "mode": peer.mode,
            "mode_label": "Client",
            "handshake_state": "stale",
            "handshake_badge": "warning",
            "handshake_ago": handshake_ago,
            "last_handshake": now - timedelta(hours=2),
            "last_handshake_iso": (now - timedelta(hours=2)).isoformat(),
            "seconds_since_handshake": 7200,
            "high_traffic": False,
            "session_rx": 0,
            "session_tx": 0,
            "session_total": 0,
            "session_rx_human": "0 B",
            "session_tx_human": "0 B",
            "session_total_human": "0 B",
        }],
        "alerts": [],
        "thresholds": {
            "active_peer_max_age_seconds": 180,
            "stale_peer_max_age_seconds": 1800,
            "high_traffic_threshold_bytes": 1024,
            "high_traffic_threshold_human": "1.00 KB",
        }
    }


def test_admin_statistics_page_lists_interfaces_and_peers(client, monkeypatch):
    create_user("admin", "admin", User.ROLE_ADMIN)
    iface, peers = setup_interface_with_peers(["client01", "client02"])
    monkeypatch.setattr(web_router, "build_log_diagnostics", lambda max_tail_lines=5000: fake_log_diagnostics())
    login(client, "admin", "admin")

    response = client.get("/statistics")
    assert is_http_success(response.status_code)
    assert b"Connection history" in response.data
    assert b"Runtime log summary" in response.data
    assert f"/traffic/rrd/{iface.uuid}".encode() in response.data
    assert f"/traffic/rrd/{peers[0].uuid}".encode() in response.data
    assert f"/traffic/rrd/{peers[1].uuid}".encode() in response.data
    assert b"?diagnostic=handshake" in response.data
    assert b"?diagnostic=auth" in response.data
    assert b"?diagnostic=warnings" in response.data
    assert b"?diagnostic=errors" in response.data


def test_admin_statistics_page_filters_log_errors(client, monkeypatch):
    create_user("admin", "admin", User.ROLE_ADMIN)
    setup_interface_with_peers(["client01"])
    monkeypatch.setattr(web_router, "build_log_diagnostics", lambda max_tail_lines=5000: fake_log_diagnostics())
    login(client, "admin", "admin")

    response = client.get("/statistics?diagnostic=errors")
    assert is_http_success(response.status_code)
    assert b"Filtered diagnostics: Errors / fatal" in response.data
    assert b"sample error" in response.data
    assert b"Clear filter" in response.data


def test_admin_statistics_page_filters_handshake_and_bans(client, monkeypatch):
    create_user("admin", "admin", User.ROLE_ADMIN)
    iface, peers = setup_interface_with_peers(["client01"])
    banned = Client(IPv4Address("10.199.0.250"))
    banned.banned_until = datetime.now() + timedelta(seconds=120)
    clients[banned.ip] = banned
    monkeypatch.setattr(web_router, "build_log_diagnostics", lambda max_tail_lines=5000: fake_log_diagnostics())
    monkeypatch.setattr(web_router, "get_peer_runtime_summary", lambda: fake_peer_runtime(peers[0], iface))
    login(client, "admin", "admin")

    response = client.get("/statistics?diagnostic=handshake")
    assert is_http_success(response.status_code)
    assert b"Filtered diagnostics: Handshake failures" in response.data
    assert peers[0].name.encode() in response.data

    response = client.get("/statistics?diagnostic=bans")
    assert is_http_success(response.status_code)
    assert b"Filtered diagnostics: Active login bans" in response.data
    assert str(banned.ip).encode() in response.data


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
