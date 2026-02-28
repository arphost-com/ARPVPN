import os

import pytest

from arpvpn.common.properties import global_properties
from arpvpn.tests.utils import default_cleanup, is_http_success, login, get_testing_app

url = "/setup"


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        global_properties.setup_required = True
        yield client


def test_get(client):
    login(client)
    response = client.get(url)
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data


def test_redirect(client):
    login(client)
    response = client.get("/dashboard")
    assert is_http_success(response.status_code)
    assert response.status_code == 302
    assert "/setup".encode() in response.data


def remove_setup_file():
    os.remove(global_properties.setup_filepath)


def test_post_ok(client):
    login(client)
    response = client.post(url, data={
        "app_endpoint": "vpn.example.com", "app_iptables_bin": "/dev/null", "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "/dev/null", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() not in response.data

    remove_setup_file()

    response = client.post(url, data={
        "app_endpoint": "10.0.0.1", "app_iptables_bin": "/dev/null", "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "/dev/null", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() not in response.data


def test_post_defaults_to_self_signed_generation(client, monkeypatch):
    login(client)
    captured = {}

    def fake_apply_setup(self, form):
        captured["tls_mode"] = form.web_tls_mode.data
        captured["generate_self_signed"] = bool(form.web_tls_generate_self_signed.data)

    monkeypatch.setattr("arpvpn.web.router.RestController.apply_setup", fake_apply_setup)

    response = client.post(url, data={
        "app_endpoint": "vpn.example.com",
        "app_iptables_bin": "/dev/null",
        "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "/dev/null",
        "log_overwrite": False,
        "traffic_enabled": True,
        "web_tls_generate_self_signed": "y",
    })
    assert is_http_success(response.status_code)
    assert captured["tls_mode"] == "self_signed"
    assert captured["generate_self_signed"] is True

    remove_setup_file()


def test_post_ko(client):
    login(client)

    response = client.post(url, data={
        "app_endpoint": "", "app_iptables_bin": "/dev/null", "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "/dev/null", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data

    response = client.post(url, data={
        "app_endpoint": 100, "app_iptables_bin": "/dev/null", "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "/dev/null", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data

    response = client.post(url, data={
        "app_endpoint": "vpn.example.com", "app_iptables_bin": "/dev/nulls", "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "/dev/null", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data

    response = client.post(url, data={
        "app_endpoint": "vpn.example.com", "app_iptables_bin": "/dev/null", "app_wg_bin": "/dev/nullg",
        "app_wg_quick_bin": "/dev/null", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data

    response = client.post(url, data={
        "app_endpoint": "vpn.example.com", "app_iptables_bin": "/dev/null", "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "/dev/nullk", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data

    response = client.post(url, data={
        "app_endpoint": "vpn.example.com", "app_iptables_bin": "", "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "/dev/null", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data

    response = client.post(url, data={
        "app_endpoint": "vpn.example.com", "app_iptables_bin": "/dev/null", "app_wg_bin": "",
        "app_wg_quick_bin": "/dev/null", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data

    response = client.post(url, data={
        "app_endpoint": "vpn.example.com", "app_iptables_bin": "/dev/null", "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data

    response = client.post(url, data={
        "app_endpoint": 1, "app_iptables_bin": "/dev/null", "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data

    response = client.post(url, data={
        "app_endpoint": "vpn.example.com", "app_iptables_bin": 1231, "app_wg_bin": "/dev/null",
        "app_wg_quick_bin": "", "log_overwrite": False, "traffic_enabled": True, "web_tls_mode": "http"
    })
    assert is_http_success(response.status_code)
    assert "Setup".encode() in response.data
