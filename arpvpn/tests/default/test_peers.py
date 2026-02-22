import pytest

from arpvpn.core.models import interfaces, Peer
from arpvpn.tests.utils import default_cleanup, is_http_success, login, create_test_iface, get_testing_app

url = "/wireguard/peers"


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def test_get_edit(client):
    login(client)
    iface = create_test_iface("iface1", "10.0.0.1/24", 50000)
    peer = Peer(name="peer1", description="", ipv4_address="10.0.0.2/24", nat=False, interface=iface, dns1="8.8.8.8")
    iface.add_peer(peer)
    interfaces[iface.uuid] = iface
    response = client.get(f"{url}/{peer.uuid}")
    assert is_http_success(response.status_code)
    assert peer.name.encode() in response.data
    assert peer.ipv4_address.encode() in response.data
    assert peer.dns1.encode() in response.data
    assert iface.name.encode() in response.data


def test_post_edit_ok(client):
    login(client)
    iface = create_test_iface("iface1", "10.0.0.1/24", 50000)
    peer = Peer(name="peer1", description="", ipv4_address="10.0.0.2/24", nat=False, interface=iface, dns1="8.8.8.8")
    iface.add_peer(peer)
    interfaces[iface.uuid] = iface

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "10.0.0.10/24", "dns1": peer.dns1,
        "dns2": "10.10.4.4", "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() not in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "nat": peer.nat, "description": peer.description, "ipv4": "10.0.0.254/24", "dns1": peer.dns1,
        "dns2": "10.10.4.4", "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() not in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "10.0.0.10/24", "dns1": peer.dns1,
        "dns2": "", "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() not in response.data


def test_post_edit_ko(client):
    login(client)
    iface = create_test_iface("iface1", "10.0.0.1/24", 50000)
    peer = Peer(name="peer1", description="", ipv4_address="10.0.0.2/24", nat=False, interface=iface, dns1="8.8.8.8")
    iface.add_peer(peer)
    interfaces[iface.uuid] = iface

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "10.0.0.1/24", "dns1": peer.dns1,
        "dns2": "10.10.4.4", "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "10.0.0.0/24", "dns1": peer.dns1,
        "dns2": "10.10.4.4", "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "10.0.0.255/24", "dns1": peer.dns1,
        "dns2": "10.10.4.4", "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "10.0.0.256/24", "dns1": peer.dns1,
        "dns2": "10.10.4.4", "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "10.0.1.2/24", "dns1": peer.dns1,
        "dns2": "10.10.4.4", "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "aaaa",
        "dns1": peer.dns1, "dns2": peer.dns2, "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "10.0.1",
        "dns1": peer.dns1, "dns2": peer.dns2, "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": "10.0.1.1/21/1.0",
        "dns1": peer.dns1, "dns2": peer.dns2, "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
        "nat": peer.nat, "description": peer.description, "ipv4": peer.ipv4_address, "dns1": peer.dns1,
        "dns2": "10.10.4.4", "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name, "nat": peer.nat, "description": peer.description, "ipv4": peer.ipv4_address, "dns1": "",
        "dns2": peer.dns2, "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data


def test_post_edit_site_to_site_ok(client):
    login(client)
    iface = create_test_iface("iface1", "10.0.0.1/24", 50000)
    peer = Peer(name="peer1", description="", ipv4_address="10.0.0.2/24", nat=False, interface=iface, dns1="8.8.8.8")
    iface.add_peer(peer)
    interfaces[iface.uuid] = iface

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name,
        "mode": Peer.MODE_SITE_TO_SITE,
        "nat": True,
        "description": "branch office",
        "ipv4": "10.0.0.2/24",
        "dns1": "",
        "dns2": "",
        "site_to_site_subnets": "10.10.0.0/16,172.16.50.0/24",
        "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() not in response.data
    assert peer.mode == Peer.MODE_SITE_TO_SITE
    assert peer.full_tunnel is False
    assert peer.site_to_site_subnets == ["10.10.0.0/16", "172.16.50.0/24"]
    assert peer.server_allowed_ips == ["10.0.0.2/32", "10.10.0.0/16", "172.16.50.0/24"]
    assert "AllowedIPs = 10.0.0.0/24" in peer.generate_conf()


def test_post_edit_site_to_site_full_tunnel_ok(client):
    login(client)
    iface = create_test_iface("iface1", "10.0.0.1/24", 50000)
    peer = Peer(name="peer1", description="", ipv4_address="10.0.0.2/24", nat=False, interface=iface, dns1="8.8.8.8")
    iface.add_peer(peer)
    interfaces[iface.uuid] = iface

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name,
        "mode": Peer.MODE_SITE_TO_SITE,
        "full_tunnel": "y",
        "nat": True,
        "description": "branch office",
        "ipv4": "10.0.0.2/24",
        "dns1": "",
        "dns2": "",
        "site_to_site_subnets": "10.10.0.0/16",
        "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() not in response.data
    assert peer.mode == Peer.MODE_SITE_TO_SITE
    assert peer.full_tunnel is True
    assert "AllowedIPs = 0.0.0.0/0" in peer.generate_conf()
    assert peer.server_allowed_ips == ["10.0.0.2/32", "10.10.0.0/16"]


def test_post_edit_site_to_site_ko(client):
    login(client)
    iface = create_test_iface("iface1", "10.0.0.1/24", 50000)
    peer = Peer(name="peer1", description="", ipv4_address="10.0.0.2/24", nat=False, interface=iface, dns1="8.8.8.8")
    iface.add_peer(peer)
    interfaces[iface.uuid] = iface

    response = client.post(f"{url}/{peer.uuid}", data={
        "name": peer.name,
        "mode": Peer.MODE_SITE_TO_SITE,
        "nat": False,
        "description": "branch office",
        "ipv4": peer.ipv4_address,
        "dns1": "",
        "dns2": "",
        "site_to_site_subnets": "10.10.0.0/16,not-a-cidr",
        "interface": peer.interface.name
    })
    assert is_http_success(response.status_code)
    assert "Error".encode() in response.data
