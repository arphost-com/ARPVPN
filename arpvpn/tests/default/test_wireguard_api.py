import time

import pytest

from arpvpn.common.models.tenant import Tenant, tenants
from arpvpn.common.models.user import User, users
from arpvpn.core.models import Interface, Peer, interfaces
from arpvpn.tests.utils import default_cleanup, get_test_gateway, get_testing_app, is_http_success


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def create_user(name: str, password: str, role: str, tenant_id: str = "") -> User:
    user = User(name, role=role)
    user.tenant_id = tenant_id or None
    user.password = password
    users[user.id] = user
    return user


def create_tenant(name: str) -> Tenant:
    tenant = Tenant(name=name)
    tenants[tenant.id] = tenant
    return tenant


def login(client, username: str, password: str):
    response = client.post(
        "/login",
        data={"username": username, "password": password, "remember_me": False},
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)


def create_interface(name: str, ipv4: str, port: int, tenant_id: str = "") -> Interface:
    iface = Interface(
        name=name,
        description="",
        gw_iface=get_test_gateway(),
        ipv4_address=ipv4,
        listen_port=port,
        auto=False,
        on_up=[],
        on_down=[],
        private_key="iface-private-key",
        public_key="iface-public-key",
        tenant_id=tenant_id,
    )
    interfaces[iface.uuid] = iface
    interfaces.sort()
    return iface


def add_peer(
    iface: Interface,
    name: str,
    ipv4: str,
    tenant_id: str = "",
    owner_user_id: str = "",
) -> Peer:
    peer = Peer(
        name=name,
        description="",
        interface=iface,
        ipv4_address=ipv4,
        dns1="8.8.8.8",
        dns2="",
        nat=False,
        private_key="peer-private-key",
        public_key="peer-public-key",
        tenant_id=tenant_id,
        owner_user_id=owner_user_id,
    )
    iface.add_peer(peer)
    return peer


def test_admin_can_crud_wireguard_interface_and_peer_via_api(client):
    admin = create_user("admin", "admin", User.ROLE_ADMIN)
    tenant = create_tenant("Tenant One")
    client_user = create_user("client01", "clientpass", User.ROLE_CLIENT, tenant.id)
    login(client, "admin", "admin")

    interface_response = client.post(
        "/api/v1/wireguard/interfaces",
        json={
            "name": "wgapi1",
            "gateway": get_test_gateway(),
            "ipv4": "10.44.0.1/24",
            "listen_port": 51001,
            "auto": False,
            "on_up": [],
            "on_down": [],
            "tenant_id": tenant.id,
        },
    )
    assert interface_response.status_code == 201
    interface_id = interface_response.get_json()["data"]["interface"]["id"]

    peer_response = client.post(
        "/api/v1/wireguard/peers",
        json={
            "name": "client01",
            "interface_uuid": interface_id,
            "ipv4": "10.44.0.2/24",
            "dns1": "8.8.8.8",
            "owner_user_id": client_user.id,
            "enabled": True,
        },
    )
    assert peer_response.status_code == 201
    peer_payload = peer_response.get_json()["data"]["peer"]
    assert peer_payload["enabled"] is True
    peer_id = peer_payload["id"]
    peer_public_key = peer_payload["public_key"]

    qr_response = client.get(f"/api/v1/wireguard/peers/{peer_id}/qr")
    assert qr_response.status_code == 200
    assert qr_response.get_json()["data"]["qr_data_uri"].startswith("data:image/png;base64,")

    disable_response = client.put(
        f"/api/v1/wireguard/peers/{peer_id}",
        json={
            "name": "client01",
            "interface_uuid": interface_id,
            "ipv4": "10.44.0.2/24",
            "dns1": "8.8.8.8",
            "enabled": False,
        },
    )
    assert disable_response.status_code == 200
    assert disable_response.get_json()["data"]["peer"]["enabled"] is False
    assert peer_public_key not in interfaces[interface_id].generate_conf()

    enable_response = client.put(
        f"/api/v1/wireguard/peers/{peer_id}",
        json={
            "name": "client01",
            "interface_uuid": interface_id,
            "ipv4": "10.44.0.2/24",
            "dns1": "8.8.8.8",
            "enabled": True,
        },
    )
    assert enable_response.status_code == 200
    assert enable_response.get_json()["data"]["peer"]["enabled"] is True
    assert peer_public_key in interfaces[interface_id].generate_conf()

    update_response = client.put(
        f"/api/v1/wireguard/interfaces/{interface_id}",
        json={
            "name": "wgapi1",
            "gateway": get_test_gateway(),
            "ipv4": "10.44.0.1/24",
            "listen_port": 51001,
            "auto": False,
            "on_up": [],
            "on_down": [],
            "tenant_id": tenant.id,
            "description": "async-update",
            "async": True,
        },
    )
    assert update_response.status_code == 202
    job_id = update_response.get_json()["data"]["job"]["job_id"]
    job_status = ""
    for _ in range(40):
        poll = client.get(f"/api/v1/jobs/{job_id}")
        assert poll.status_code == 200
        job_status = poll.get_json()["data"]["status"]
        if job_status in ("completed", "failed"):
            break
        time.sleep(0.1)
    assert job_status == "completed"

    download_response = client.get(f"/api/v1/wireguard/peers/{peer_id}/download")
    assert download_response.status_code == 200
    assert b"AllowedIPs" in download_response.data

    delete_peer = client.delete(f"/api/v1/wireguard/peers/{peer_id}")
    assert delete_peer.status_code == 200
    delete_interface = client.delete(f"/api/v1/wireguard/interfaces/{interface_id}")
    assert delete_interface.status_code == 200

    assert admin.role == User.ROLE_ADMIN


def test_tenant_admin_is_scoped_to_own_wireguard_objects(client):
    tenant_one = create_tenant("Tenant One")
    tenant_two = create_tenant("Tenant Two")
    tenant_admin = create_user("tenant-admin", "tenantpass", User.ROLE_TENANT_ADMIN, tenant_one.id)
    client_one = create_user("client01", "clientpass", User.ROLE_CLIENT, tenant_one.id)
    client_two = create_user("client02", "clientpass", User.ROLE_CLIENT, tenant_two.id)

    iface_one = create_interface("wgtenant1", "10.45.0.1/24", 51011, tenant_one.id)
    peer_one = add_peer(iface_one, "client01", "10.45.0.2/24", tenant_one.id, client_one.id)
    iface_two = create_interface("wgtenant2", "10.46.0.1/24", 51012, tenant_two.id)
    peer_two = add_peer(iface_two, "client02", "10.46.0.2/24", tenant_two.id, client_two.id)
    login(client, "tenant-admin", "tenantpass")

    interfaces_response = client.get("/api/v1/wireguard/interfaces")
    assert interfaces_response.status_code == 200
    interface_ids = {item["id"] for item in interfaces_response.get_json()["data"]["items"]}
    assert iface_one.uuid in interface_ids
    assert iface_two.uuid not in interface_ids

    peers_response = client.get("/api/v1/wireguard/peers")
    assert peers_response.status_code == 200
    peer_ids = {item["id"] for item in peers_response.get_json()["data"]["items"]}
    assert peer_one.uuid in peer_ids
    assert peer_two.uuid not in peer_ids

    blocked_get = client.get(f"/api/v1/wireguard/interfaces/{iface_two.uuid}")
    assert blocked_get.status_code == 403

    blocked_create = client.post(
        "/api/v1/wireguard/peers",
        json={
            "name": "blocked-peer",
            "interface_uuid": iface_two.uuid,
            "ipv4": "10.46.0.3/24",
            "dns1": "8.8.8.8",
            "owner_user_id": client_two.id,
        },
    )
    assert blocked_create.status_code == 403

    assert tenant_admin.tenant_id == tenant_one.id


def test_client_can_only_view_owned_wireguard_peer_via_api(client):
    client_one = create_user("client01", "clientpass", User.ROLE_CLIENT)
    client_two = create_user("client02", "clientpass", User.ROLE_CLIENT)
    iface = create_interface("wgclient1", "10.47.0.1/24", 51021)
    peer_one = add_peer(iface, "client01", "10.47.0.2/24", owner_user_id=client_one.id)
    peer_two = add_peer(iface, "client02", "10.47.0.3/24", owner_user_id=client_two.id)
    login(client, "client01", "clientpass")

    peers_response = client.get("/api/v1/wireguard/peers")
    assert peers_response.status_code == 200
    body = peers_response.get_json()["data"]
    assert body["total"] == 1
    assert body["items"][0]["id"] == peer_one.uuid

    interface_response = client.get(f"/api/v1/wireguard/interfaces/{iface.uuid}")
    assert interface_response.status_code == 200
    interface_peers = interface_response.get_json()["data"]["interface"]["peers"]
    assert len(interface_peers) == 1
    assert interface_peers[0]["id"] == peer_one.uuid

    blocked_peer = client.get(f"/api/v1/wireguard/peers/{peer_two.uuid}")
    assert blocked_peer.status_code == 403

    own_download = client.get(f"/api/v1/wireguard/peers/{peer_one.uuid}/download")
    assert own_download.status_code == 200
