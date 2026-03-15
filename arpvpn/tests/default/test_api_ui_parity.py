import os

import pytest

from arpvpn.common.properties import global_properties
from arpvpn.common.models.user import users
from arpvpn.core.config.logger import config as logger_config
from arpvpn.core.config.traffic import config as traffic_config
from arpvpn.core.config.web import config as web_config
from arpvpn.core.config.wireguard import config as wireguard_config
from arpvpn.tests.utils import default_cleanup, get_testing_app, is_http_success, login, password, username


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


@pytest.fixture
def config_snapshot(monkeypatch):
    snapshot = {
        "logger_overwrite": logger_config.overwrite,
        "traffic_enabled": traffic_config.enabled,
        "tls_mode": web_config.tls_mode,
        "tls_server_name": web_config.tls_server_name,
        "tls_email": web_config.tls_letsencrypt_email,
        "proxy_hostname": web_config.proxy_incoming_hostname,
        "redirect_https": web_config.redirect_http_to_https,
        "endpoint": wireguard_config.endpoint,
        "wg_bin": wireguard_config.wg_bin,
        "wg_quick_bin": wireguard_config.wg_quick_bin,
        "iptables_bin": wireguard_config.iptables_bin,
    }
    yield
    logger_config.overwrite = snapshot["logger_overwrite"]
    traffic_config.enabled = snapshot["traffic_enabled"]
    web_config.tls_mode = snapshot["tls_mode"]
    web_config.tls_server_name = snapshot["tls_server_name"]
    web_config.tls_letsencrypt_email = snapshot["tls_email"]
    web_config.proxy_incoming_hostname = snapshot["proxy_hostname"]
    web_config.redirect_http_to_https = snapshot["redirect_https"]
    wireguard_config.endpoint = snapshot["endpoint"]
    wireguard_config.wg_bin = snapshot["wg_bin"]
    wireguard_config.wg_quick_bin = snapshot["wg_quick_bin"]
    wireguard_config.iptables_bin = snapshot["iptables_bin"]
    setup_path = global_properties.setup_filepath
    if os.path.exists(setup_path):
        os.remove(setup_path)


def test_about_and_network_inventory_api(client):
    login(client)

    about_response = client.get("/api/v1/about")
    assert about_response.status_code == 200
    about_payload = about_response.get_json()["data"]
    assert about_payload["product"]["vendor"] == "ARPHost"
    assert about_payload["wireguard"]["summary"]

    network_response = client.get("/api/v1/network/inventory")
    assert network_response.status_code == 200
    network_payload = network_response.get_json()["data"]
    assert "interfaces" in network_payload
    assert "routes" in network_payload


def test_profile_api_supports_read_update_and_password_change(client):
    login(client)

    profile_response = client.get("/api/v1/profile")
    assert profile_response.status_code == 200
    assert profile_response.get_json()["data"]["user"]["username"] == username

    rename_response = client.put("/api/v1/profile", json={"username": "root-admin"})
    assert rename_response.status_code == 200
    assert rename_response.get_json()["data"]["user"]["username"] == "root-admin"
    assert users.get_value_by_attr("name", "root-admin") is not None

    password_response = client.post(
        "/api/v1/profile/password",
        json={
            "old_password": password,
            "new_password": "changed-pass",
            "confirm": "changed-pass",
        },
    )
    assert password_response.status_code == 200
    renamed_user = users.get_value_by_attr("name", "root-admin")
    assert renamed_user.check_password("changed-pass") is True


def test_setup_status_and_bootstrap_api(client, monkeypatch, config_snapshot):
    login(client)
    monkeypatch.setattr("arpvpn.web.router.tls_manager.apply_web_tls_config", lambda *args, **kwargs: None)

    status_response = client.get("/api/v1/setup/status")
    assert status_response.status_code == 200
    status_payload = status_response.get_json()["data"]
    assert status_payload["setup_file_exists"] is False

    bootstrap_response = client.post(
        "/api/v1/setup/bootstrap",
        json={
            "log_overwrite": False,
            "traffic_enabled": True,
            "wireguard": {
                "endpoint": "vpn.example.com",
                "wg_bin": "/bin/echo",
                "wg_quick_bin": "/bin/echo",
                "iptables_bin": "/bin/echo",
            },
            "tls": {
                "mode": "self_signed",
                "server_name": "vpn.example.com",
                "redirect_http_to_https": False,
                "generate_self_signed": True,
                "issue_letsencrypt": False,
            },
        },
    )
    assert bootstrap_response.status_code == 200
    assert os.path.exists(global_properties.setup_filepath)
    payload = bootstrap_response.get_json()["data"]
    assert payload["setup_file_exists"] is True
    assert wireguard_config.endpoint == "vpn.example.com"


def test_system_restart_api_uses_configured_handler(client):
    login(client)
    app = get_testing_app()
    called = {}

    def fake_restart_handler(**kwargs):
        called.update(kwargs)
        return {"requested": True, "mode": "test", "target_pid": 123, "delay_seconds": kwargs["delay_seconds"]}

    app.config["ARPVPN_RESTART_HANDLER"] = fake_restart_handler
    try:
        response = client.post(
            "/api/v1/system/restart",
            json={"reason": "apply changes", "mode": "auto", "delay_seconds": 0},
        )
    finally:
        app.config.pop("ARPVPN_RESTART_HANDLER", None)

    assert response.status_code == 202
    assert called["reason"] == "apply changes"
    assert response.get_json()["data"]["mode"] == "test"
    assert is_http_success(response.status_code)
