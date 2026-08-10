import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask
from flask_login import LoginManager, login_user

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from arpvpn.common.properties import global_properties


_TEST_WORKDIR = tempfile.mkdtemp(prefix="arpvpn-tests-")
global_properties.workdir = _TEST_WORKDIR
open(global_properties.setup_filepath, "w", encoding="utf-8").close()

from arpvpn.common.models.tenant import Invitation, Tenant, invitations, tenants  # noqa: E402
from arpvpn.common.models.user import User, users  # noqa: E402
from arpvpn.common.utils.mfa import generate_mfa_code, hash_recovery_code  # noqa: E402
from arpvpn.core.models import Interface, Peer, interfaces  # noqa: E402
from arpvpn.core.drivers.traffic_storage_driver import TrafficData  # noqa: E402
from arpvpn.core.drivers.traffic_storage_driver_json import TrafficStorageDriverJson  # noqa: E402
from arpvpn.web import router as router_module  # noqa: E402
from arpvpn.web.security_api import ApiTokenStore, AuthLockoutManager, SlidingWindowRateLimiter  # noqa: E402


def make_user(username: str, role: str, tenant_id: str = "") -> User:
    user = User(username, role=role)
    user.tenant_id = tenant_id or None
    user.password = "correct horse battery staple"
    users[user.id] = user
    return user


def make_interface(name: str, tenant_id: str = "") -> Interface:
    iface = Interface(
        name=name,
        description="",
        gw_iface="eth0",
        ipv4_address="10.80.0.1/24",
        listen_port=51820 if not tenant_id else 51821,
        auto=False,
        on_up=[],
        on_down=[],
        private_key=f"{name}-private",
        public_key=f"{name}-public",
        tenant_id=tenant_id,
    )
    interfaces[iface.uuid] = iface
    return iface


@pytest.fixture(autouse=True)
def reset_state():
    users.clear()
    tenants.clear()
    invitations.clear()
    interfaces.clear()
    router_module.api_token_store.reset_for_tests()
    router_module.TRAFFIC_SESSION_CACHE["loaded_at"] = 0.0
    router_module.TRAFFIC_SESSION_CACHE["data"] = {}
    yield
    users.clear()
    tenants.clear()
    invitations.clear()
    interfaces.clear()
    router_module.api_token_store.reset_for_tests()
    router_module.TRAFFIC_SESSION_CACHE["loaded_at"] = 0.0
    router_module.TRAFFIC_SESSION_CACHE["data"] = {}


@pytest.fixture()
def app():
    app = Flask(
        __name__,
        template_folder=os.path.join(os.getcwd(), "arpvpn", "web", "templates"),
        static_folder=os.path.join(os.getcwd(), "arpvpn", "web", "static"),
    )
    app.secret_key = "test-secret"
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["TESTING"] = True

    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return users.get(user_id)

    @app.route("/test-login/<user_id>")
    def test_login(user_id):
        user = users[user_id]
        user.set_authenticated(True)
        login_user(user)
        return "ok"

    app.register_blueprint(router_module.router)
    return app


def test_tenant_admin_wireguard_api_cannot_see_control_plane_interface(app):
    tenant = Tenant("Tenant One", slug="tenant-one")
    tenants[tenant.id] = tenant
    tenant_admin = make_user("tenant-admin", User.ROLE_TENANT_ADMIN, tenant.id)
    control_plane_iface = make_interface("wgmain")
    tenant_iface = make_interface("wgtenant", tenant.id)
    control_peer = Peer(
        name="control-peer",
        description="",
        ipv4_address="10.80.0.2/24",
        nat=False,
        interface=control_plane_iface,
        dns1="8.8.8.8",
        private_key="control-private",
        public_key="control-public",
    )
    tenant_peer = Peer(
        name="tenant-peer",
        description="",
        ipv4_address="10.80.0.3/24",
        nat=False,
        interface=tenant_iface,
        dns1="8.8.8.8",
        private_key="tenant-private",
        public_key="tenant-public",
        tenant_id=tenant.id,
    )
    control_plane_iface.add_peer(control_peer)
    tenant_iface.add_peer(tenant_peer)

    client = app.test_client()
    assert client.get(f"/test-login/{tenant_admin.id}").status_code == 200

    response = client.get("/api/v1/wireguard/interfaces")
    assert response.status_code == 200
    items = response.get_json()["data"]["items"]
    assert [item["id"] for item in items] == [tenant_iface.uuid]

    assert client.get(f"/api/v1/wireguard/interfaces/{tenant_iface.uuid}").status_code == 200
    assert client.get(f"/api/v1/wireguard/interfaces/{control_plane_iface.uuid}").status_code == 403
    assert router_module.can_manage_wireguard_interface(control_plane_iface, tenant_admin) is False
    assert router_module.can_manage_wireguard_interface(tenant_iface, tenant_admin) is True

    stats_response = client.get("/api/v1/stats/peers")
    assert stats_response.status_code == 200
    peer_names = [item["peer_name"] for item in stats_response.get_json()["data"]["peers"]]
    assert peer_names == ["tenant-peer"]

    csv_response = client.get("/api/v1/stats/peers.csv")
    assert csv_response.status_code == 200
    csv_text = csv_response.get_data(as_text=True)
    assert "tenant-peer" in csv_text
    assert "control-peer" not in csv_text

    interface_export = client.get("/api/v1/wireguard/interfaces/export?format=csv")
    assert interface_export.status_code == 200
    interface_csv = interface_export.get_data(as_text=True)
    assert "wgtenant" in interface_csv
    assert "wgmain" not in interface_csv

    peer_export_csv = client.get("/api/v1/wireguard/peers/export?format=csv")
    assert peer_export_csv.status_code == 200
    peer_csv = peer_export_csv.get_data(as_text=True)
    assert "tenant-peer" in peer_csv
    assert "control-peer" not in peer_csv

    peer_export_json = client.get("/api/v1/wireguard/peers/export?format=json")
    assert peer_export_json.status_code == 200
    exported_peer_names = [item["name"] for item in peer_export_json.get_json()["data"]["items"]]
    assert exported_peer_names == ["tenant-peer"]


def test_tenant_admin_cannot_see_control_plane_interface_with_tenant_owned_peer(app):
    tenant = Tenant("MehHOst", slug="mehhost")
    tenants[tenant.id] = tenant
    tenant_admin = make_user("mehmeh", User.ROLE_TENANT_ADMIN, tenant.id)
    tenant_client = make_user("mehhost-client", User.ROLE_CLIENT, tenant.id)
    control_plane_iface = make_interface("wg-control")
    tenant_iface = make_interface("wg-mehhost", tenant.id)

    legacy_control_peer = Peer(
        name="mehhost-legacy",
        description="",
        ipv4_address="10.80.0.2/24",
        nat=False,
        interface=control_plane_iface,
        dns1="8.8.8.8",
        private_key="legacy-private",
        public_key="legacy-public",
        tenant_id=tenant.id,
        owner_user_id=tenant_client.id,
    )
    tenant_peer = Peer(
        name="mehhost-client",
        description="",
        ipv4_address="10.80.0.3/24",
        nat=False,
        interface=tenant_iface,
        dns1="8.8.8.8",
        private_key="tenant-private",
        public_key="tenant-public",
        tenant_id=tenant.id,
        owner_user_id=tenant_client.id,
    )
    control_plane_iface.add_peer(legacy_control_peer)
    tenant_iface.add_peer(tenant_peer)

    client = app.test_client()
    assert client.get(f"/test-login/{tenant_admin.id}").status_code == 200

    response = client.get("/api/v1/wireguard/interfaces")
    assert response.status_code == 200
    interface_names = [item["name"] for item in response.get_json()["data"]["items"]]
    assert interface_names == ["wg-mehhost"]

    peer_response = client.get("/api/v1/wireguard/peers")
    assert peer_response.status_code == 200
    peer_names = [item["name"] for item in peer_response.get_json()["data"]["items"]]
    assert peer_names == ["mehhost-client"]

    assert client.get(f"/api/v1/wireguard/interfaces/{control_plane_iface.uuid}").status_code == 403
    assert client.get(f"/api/v1/wireguard/peers/{legacy_control_peer.uuid}").status_code == 403
    assert router_module.interface_visible_to_actor(control_plane_iface, tenant_admin) is False
    assert router_module.peer_visible_to_actor(legacy_control_peer, tenant_admin) is False
    assert router_module.interface_visible_to_actor(tenant_iface, tenant_admin) is True
    assert router_module.peer_visible_to_actor(tenant_peer, tenant_admin) is True


def test_tenant_admin_cannot_access_other_tenant_users_networks_or_settings(app):
    tenant_one = Tenant("Tenant One", slug="tenant-one", settings={"branding": {"name": "Tenant One"}})
    tenant_two = Tenant("Tenant Two", slug="tenant-two", settings={"branding": {"name": "Tenant Two"}})
    tenants[tenant_one.id] = tenant_one
    tenants[tenant_two.id] = tenant_two
    tenant_admin = make_user("tenant-one-admin", User.ROLE_TENANT_ADMIN, tenant_one.id)
    tenant_one_client = make_user("tenant-one-client", User.ROLE_CLIENT, tenant_one.id)
    tenant_two_client = make_user("tenant-two-client", User.ROLE_CLIENT, tenant_two.id)

    tenant_one_iface = make_interface("wg-tenant-one", tenant_one.id)
    tenant_two_iface = Interface(
        name="wg-tenant-two",
        description="",
        gw_iface="eth0",
        ipv4_address="10.81.0.1/24",
        listen_port=51822,
        auto=False,
        on_up=[],
        on_down=[],
        private_key="wg-tenant-two-private",
        public_key="wg-tenant-two-public",
        tenant_id=tenant_two.id,
    )
    interfaces[tenant_two_iface.uuid] = tenant_two_iface
    tenant_one_peer = Peer(
        name="tenant-one-client",
        description="",
        ipv4_address="10.80.0.2/24",
        nat=False,
        interface=tenant_one_iface,
        dns1="8.8.8.8",
        private_key="tenant-one-private",
        public_key="tenant-one-public",
        tenant_id=tenant_one.id,
        owner_user_id=tenant_one_client.id,
    )
    tenant_two_peer = Peer(
        name="tenant-two-client",
        description="",
        ipv4_address="10.81.0.2/24",
        nat=False,
        interface=tenant_two_iface,
        dns1="8.8.8.8",
        private_key="tenant-two-private",
        public_key="tenant-two-public",
        tenant_id=tenant_two.id,
        owner_user_id=tenant_two_client.id,
    )
    tenant_one_iface.add_peer(tenant_one_peer)
    tenant_two_iface.add_peer(tenant_two_peer)

    client = app.test_client()
    assert client.get(f"/test-login/{tenant_admin.id}").status_code == 200
    csrf_token = client.get("/api/v1/auth/csrf").get_json()["data"]["csrf_token"]
    csrf_headers = {"X-CSRFToken": csrf_token}

    users_response = client.get("/api/v1/users")
    assert users_response.status_code == 200
    usernames = [item["username"] for item in users_response.get_json()["data"]["items"]]
    assert usernames == ["tenant-one-client", "tenant-one-admin"]
    assert client.get(f"/api/v1/users?tenant_id={tenant_two.id}").status_code == 403
    assert client.get(f"/api/v1/users/{tenant_two_client.id}").status_code == 403
    assert client.get(f"/users/{tenant_two_client.id}/edit").status_code == 403

    assert client.get(f"/api/v1/tenants?tenant_id={tenant_two.id}").status_code == 403
    assert client.get(f"/api/v1/tenants/{tenant_two.id}/config").status_code == 403
    assert client.put(
        f"/api/v1/tenants/{tenant_two.id}/config",
        json={"branding": {"name": "Blocked"}},
        headers=csrf_headers,
    ).status_code == 403
    assert client.get(f"/api/v1/tenants/{tenant_two.id}/tls/status").status_code == 403
    assert client.get(f"/api/v1/tenants/{tenant_two.id}/runtime").status_code == 403
    assert client.get("/api/v1/config/global").status_code == 403
    assert client.get("/settings").status_code == 403

    interfaces_response = client.get("/api/v1/wireguard/interfaces")
    assert interfaces_response.status_code == 200
    interface_names = [item["name"] for item in interfaces_response.get_json()["data"]["items"]]
    assert interface_names == ["wg-tenant-one"]
    assert client.get(f"/api/v1/wireguard/interfaces?tenant_id={tenant_two.id}").status_code == 403
    assert client.get(f"/api/v1/wireguard/interfaces/{tenant_two_iface.uuid}").status_code == 403
    assert client.post(
        f"/api/v1/wireguard/interfaces/{tenant_two_iface.uuid}/restart",
        json={},
        headers=csrf_headers,
    ).status_code == 403
    assert client.get(f"/api/v1/wireguard/peers/{tenant_two_peer.uuid}").status_code == 403
    assert client.put(
        f"/api/v1/wireguard/peers/{tenant_two_peer.uuid}",
        json={
            "name": "tenant-two-client",
            "interface_uuid": tenant_two_iface.uuid,
            "ipv4": "10.81.0.3/24",
            "dns1": "8.8.8.8",
        },
        headers=csrf_headers,
    ).status_code == 403

    peers_response = client.get("/api/v1/wireguard/peers")
    assert peers_response.status_code == 200
    peer_names = [item["name"] for item in peers_response.get_json()["data"]["items"]]
    assert peer_names == ["tenant-one-client"]

    wireguard_page = client.get("/wireguard")
    assert wireguard_page.status_code == 200
    wireguard_html = wireguard_page.get_data(as_text=True)
    assert "wg-tenant-one" in wireguard_html
    assert "tenant-one-client" in wireguard_html
    assert "wg-tenant-two" not in wireguard_html
    assert "tenant-two-client" not in wireguard_html

    health_response = client.get("/api/v1/system/health")
    assert health_response.status_code == 200
    health = health_response.get_json()["data"]
    assert health["interfaces_total"] == 1
    assert health["peers_total"] == 1
    assert "http_port" not in health
    assert "https_port" not in health
    assert "tls_mode" not in health

    about_response = client.get("/api/v1/about")
    assert about_response.status_code == 200
    about = about_response.get_json()["data"]
    assert about["wireguard"]["interfaces_total"] == 1
    assert about["wireguard"]["peers_total"] == 1
    assert "endpoint" not in about["wireguard"]


def test_invitation_accept_creates_user_in_invitation_tenant(app):
    tenant = Tenant("Tenant One", slug="tenant-one")
    tenants[tenant.id] = tenant
    invitation = Invitation(tenant.id, "client@example.com", role=User.ROLE_CLIENT)
    raw_token = invitation.raw_token
    invitations[invitation.id] = invitation

    response = app.test_client().post(
        f"/invitations/{invitation.id}/accept",
        data={
            "token": raw_token,
            "username": "tenant-client",
            "password": "client-password",
            "confirm": "client-password",
        },
    )

    assert response.status_code == 200
    created = users.get_value_by_attr("name", "tenant-client")
    assert created is not None
    assert created.role == User.ROLE_CLIENT
    assert created.tenant_id == tenant.id
    assert invitation.accepted_user_id == created.id


def test_admin_can_create_tenant_from_browser_ui(app):
    admin = make_user("admin", User.ROLE_ADMIN)
    client = app.test_client()
    assert client.get(f"/test-login/{admin.id}").status_code == 200

    page = client.get("/tenants")
    assert page.status_code == 200
    assert "Create tenant" in page.get_data(as_text=True)

    response = client.post(
        "/tenants",
        data={
            "name": "Acme VPN",
            "slug": "acme-vpn",
            "domains": "vpn.acme.example, clients.acme.example",
            "ips": "203.0.113.10",
            "status": Tenant.STATUS_ACTIVE,
            "description": "Production tenant",
        },
    )

    assert response.status_code == 200
    created = next(iter(tenants.values()))
    assert created.name == "Acme VPN"
    assert created.slug == "acme-vpn"
    assert created.domains == ["vpn.acme.example", "clients.acme.example"]
    assert created.ips == ["203.0.113.10"]
    response_text = response.get_data(as_text=True)
    assert "Tenant Acme VPN created successfully." in response_text
    assert "acme-vpn" in response_text


def test_only_admin_can_open_tenant_browser_ui(app):
    tenant = Tenant("Tenant One", slug="tenant-one")
    tenants[tenant.id] = tenant
    tenant_admin = make_user("tenant-admin", User.ROLE_TENANT_ADMIN, tenant.id)
    client = app.test_client()
    assert client.get(f"/test-login/{tenant_admin.id}").status_code == 200

    assert client.get("/tenants").status_code == 403
    assert client.post("/tenants", data={"name": "Blocked"}).status_code == 403


def test_wireguard_peer_config_modes_and_disabled_peer_generation():
    iface = make_interface("wgtenant", "tenant-1")
    disabled = Peer(
        name="disabled-peer",
        description="",
        ipv4_address="10.80.0.2/24",
        nat=False,
        interface=iface,
        dns1="8.8.8.8",
        private_key="disabled-private",
        public_key="disabled-public",
        enabled=False,
        tenant_id="tenant-1",
    )
    site = Peer(
        name="site-peer",
        description="",
        ipv4_address="10.80.0.3/24",
        nat=False,
        interface=iface,
        dns1="",
        private_key="site-private",
        public_key="site-public",
        mode=Peer.MODE_SITE_TO_SITE,
        site_to_site_subnets=["192.168.50.0/24"],
        full_tunnel=True,
        tenant_id="tenant-1",
    )
    iface.add_peer(disabled)
    iface.add_peer(site)

    server_conf = iface.generate_conf()
    assert "disabled-public" not in server_conf
    assert "site-public" in server_conf
    assert "AllowedIPs = 10.80.0.3/32, 192.168.50.0/24" in server_conf
    assert "AllowedIPs = 0.0.0.0/0" in site.generate_conf()


def test_api_token_lifecycle():
    store = ApiTokenStore("secret")
    pair = store.issue_pair("user-1", 60, 120, "127.0.0.1", "pytest", mfa_verified=True)
    access_token = pair["access"]["raw_token"]
    refresh_token = pair["refresh"]["raw_token"]

    assert store.validate_access_token(access_token).user_id == "user-1"
    assert store.validate_refresh_token(refresh_token).user_id == "user-1"
    listed = store.list_user_tokens("user-1")
    assert [record.token_kind for record in listed] == ["refresh", "access"]
    assert store.revoke_user_token_id("user-1", listed[0].token_id) is True
    assert len(store.list_user_tokens("user-1")) == 1
    assert store.revoke_token(access_token) is True
    assert store.validate_access_token(access_token) is None
    assert store.revoke_user_tokens("user-1") == 0
    assert store.validate_refresh_token(refresh_token) is None


def test_profile_api_token_ui_issue_and_revoke(app):
    admin = make_user("admin", User.ROLE_ADMIN)
    admin.login_date = datetime.now()
    client = app.test_client()
    assert client.get(f"/test-login/{admin.id}").status_code == 200

    response = client.post(
        "/profile",
        data={
            "password": "correct horse battery staple",
            "scope": "all",
            "issue_api_token": "Issue API token",
        },
    )

    assert response.status_code == 200
    assert "Access token" in response.get_data(as_text=True)
    active_tokens = router_module.api_token_store.list_user_tokens(admin.id)
    assert len(active_tokens) == 2

    response = client.post(
        "/profile",
        data={
            "token_id": active_tokens[0].token_id,
            "revoke_api_token": "Revoke",
        },
    )

    assert response.status_code == 200
    assert len(router_module.api_token_store.list_user_tokens(admin.id)) == 1

    response = client.post("/profile", data={"revoke_all_api_tokens": "Revoke all tokens"})

    assert response.status_code == 200
    assert router_module.api_token_store.list_user_tokens(admin.id) == []


def test_cookie_api_writes_require_csrf_and_lockouts_rate_limit(app):
    admin = make_user("admin", User.ROLE_ADMIN)
    client = app.test_client()
    assert client.get(f"/test-login/{admin.id}").status_code == 200

    response = client.post(
        "/api/v1/users",
        json={"username": "blocked", "password": "password", "role": User.ROLE_CLIENT},
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "csrf_failed"

    limiter = SlidingWindowRateLimiter()
    assert limiter.allow("bucket", max_requests=1, window_seconds=60) == (True, 0)
    allowed, retry_after = limiter.allow("bucket", max_requests=1, window_seconds=60)
    assert allowed is False
    assert retry_after > 0

    lockouts = AuthLockoutManager()
    assert lockouts.register_failure("login", max_attempts=2, window_seconds=60, lockout_seconds=60) == 1
    assert lockouts.register_failure("login", max_attempts=2, window_seconds=60, lockout_seconds=60) == 0
    locked, retry_after = lockouts.is_locked("login")
    assert locked is True
    assert retry_after > 0


def test_totp_and_recovery_code_consumption():
    user = User("client", role=User.ROLE_CLIENT)
    secret = "JBSWY3DPEHPK3PXP"
    recovery_code = "ABCD-EFGH-IJKL-MNOP"
    user.enable_mfa(secret, [hash_recovery_code(recovery_code)])

    assert user.verify_mfa(generate_mfa_code(secret), allow_recovery_codes=False) == (True, False)
    assert user.verify_mfa(recovery_code) == (True, True)
    assert user.verify_mfa(recovery_code) == (False, False)


def test_traffic_json_driver_reuses_unchanged_file_parse(monkeypatch):
    traffic_path = Path(global_properties.workdir) / TrafficStorageDriverJson.FILENAME
    traffic_path.write_text('{"01/01/2026 00:00:00": {}}', encoding="utf-8")
    driver = TrafficStorageDriverJson()
    real_json_load = router_module.json.load
    load_calls = []

    def tracked_json_load(handle):
        load_calls.append(handle.name)
        return real_json_load(handle)

    monkeypatch.setattr("arpvpn.core.drivers.traffic_storage_driver_json.json.load", tracked_json_load)

    first = driver.load_data()
    second = driver.load_data()
    assert len(first) == 1
    assert second == first
    assert len(load_calls) == 1


def test_request_traffic_helpers_share_live_and_history_reads(app, monkeypatch):
    session_calls = []
    history_calls = []

    def load_session():
        session_calls.append(True)
        return {"peer-1": TrafficData(10, 20)}

    def load_history(session_traffic=None):
        history_calls.append(True)
        return {datetime(2026, 1, 1): session_traffic or {}}

    monkeypatch.setattr(router_module.traffic_config.driver, "get_session_data", load_session)
    monkeypatch.setattr(router_module.traffic_config.driver, "get_session_and_stored_data", load_history)

    with app.test_request_context("/dashboard"):
        first = router_module.load_traffic_history_data(include_session=True)
        second = router_module.load_traffic_history_data(include_session=True)
        live = router_module.get_session_traffic_data()

    assert first is second
    assert live["peer-1"].rx == 10
    assert len(session_calls) == 1
    assert len(history_calls) == 1


def test_rrd_render_batches_all_updates_into_one_process(monkeypatch):
    points = [
        (1_700_000_000, 100, 200),
        (1_700_000_060, 150, 260),
        (1_700_000_120, 220, 340),
    ]
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        if command[1] == "graph":
            Path(command[2]).write_bytes(b"png")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(router_module, "get_connection_traffic_points", lambda _uuid: points)
    monkeypatch.setattr(router_module.subprocess, "run", fake_run)

    assert router_module._render_rrd_graph_png("a" * 32, 86_400) == b"png"
    update_commands = [command for command in commands if command[1] == "update"]
    assert len(update_commands) == 1
    assert update_commands[0][3:] == [
        "1700000000:100:200",
        "1700000060:150:260",
        "1700000120:220:340",
    ]


def test_connection_graph_page_loads_only_selected_window(app):
    admin = make_user("admin", User.ROLE_ADMIN)
    iface = make_interface("wgmain")
    client = app.test_client()
    assert client.get(f"/test-login/{admin.id}").status_code == 200

    response = client.get(f"/traffic/rrd/{iface.uuid}?window=24h")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert body.count(f"/traffic/rrd/{iface.uuid}.png?window=24h") == 1
    assert f"/traffic/rrd/{iface.uuid}.png?window=6h" not in body
    assert f"/traffic/rrd/{iface.uuid}.png?window=7d" not in body
    assert f"/traffic/rrd/{iface.uuid}.png?window=30d" not in body


def test_user_management_does_not_enable_optional_peer_by_default(app):
    admin = make_user("admin", User.ROLE_ADMIN)
    make_interface("wgmain")
    client = app.test_client()
    assert client.get(f"/test-login/{admin.id}").status_code == 200

    response = client.get("/users")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    checkbox = body.split('id="create_peer"', 1)[1].split(">", 1)[0]
    assert "checked" not in checkbox
    assert "users.mjs" in body


def test_create_and_delete_user_redirect_with_completion_notice(app, monkeypatch):
    admin = make_user("admin", User.ROLE_ADMIN)
    target = make_user("delete-me", User.ROLE_CLIENT)
    monkeypatch.setattr(router_module.config_manager, "save_identity_state", lambda: None)
    monkeypatch.setattr(
        router_module.RestController,
        "add_peer",
        lambda _form: pytest.fail("Optional peer provisioning should remain disabled"),
    )
    client = app.test_client()
    assert client.get(f"/test-login/{admin.id}").status_code == 200

    create_response = client.post("/users", data={
        "username": "new-support",
        "password": "correct horse battery staple",
        "confirm": "correct horse battery staple",
        "role": User.ROLE_SUPPORT,
        "tenant_id": "",
    })
    assert create_response.status_code == 302
    assert create_response.headers["Location"].endswith("/users")
    assert users.get_value_by_attr("name", "new-support") is not None

    delete_response = client.post(f"/users/{target.id}/delete", data={})
    assert delete_response.status_code == 302
    assert delete_response.headers["Location"].endswith("/users")
    assert target.id not in users

    notice_response = client.get("/users")
    assert "User deleted successfully." in notice_response.get_data(as_text=True)
