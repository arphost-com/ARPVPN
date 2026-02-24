import os

import pytest
import yaml

from arpvpn.common.properties import global_properties
from arpvpn.core.config.web import WebConfig
from arpvpn.core.managers.tls import tls_manager


def write_uwsgi(path: str, uwsgi_settings: dict):
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump({"uwsgi": uwsgi_settings}, handle, sort_keys=False)


def read_uwsgi(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(autouse=True)
def restore_workdir():
    previous = global_properties.workdir
    yield
    global_properties.workdir = previous


def test_apply_http_mode_replaces_https_socket(tmp_path):
    global_properties.workdir = str(tmp_path)
    uwsgi_path = os.path.join(str(tmp_path), "uwsgi.yaml")
    write_uwsgi(uwsgi_path, {"https-socket": "0.0.0.0:8080,/tmp/cert.pem,/tmp/key.pem"})

    cfg = WebConfig()
    cfg.tls_mode = cfg.TLS_MODE_HTTP

    tls_manager.apply_web_tls_config(cfg)
    loaded = read_uwsgi(uwsgi_path)["uwsgi"]
    assert loaded["http-socket"] == "0.0.0.0:8080"
    assert "https-socket" not in loaded


def test_apply_self_signed_mode_sets_https_socket(tmp_path, monkeypatch):
    global_properties.workdir = str(tmp_path)
    uwsgi_path = os.path.join(str(tmp_path), "uwsgi.yaml")
    write_uwsgi(uwsgi_path, {"http-socket": "0.0.0.0:8080"})

    cert_file = os.path.join(str(tmp_path), "cert.pem")
    key_file = os.path.join(str(tmp_path), "key.pem")
    open(cert_file, "w", encoding="utf-8").close()
    open(key_file, "w", encoding="utf-8").close()

    monkeypatch.setattr(tls_manager, "generate_self_signed", lambda server_name: (cert_file, key_file))

    cfg = WebConfig()
    cfg.tls_mode = cfg.TLS_MODE_SELF_SIGNED
    cfg.tls_server_name = "vpn.example.com"

    tls_manager.apply_web_tls_config(cfg, generate_self_signed=True)
    loaded = read_uwsgi(uwsgi_path)["uwsgi"]
    assert loaded["https-socket"] == f"0.0.0.0:8080,{cert_file},{key_file}"
    assert "http-socket" not in loaded
    assert cfg.tls_cert_file == cert_file
    assert cfg.tls_key_file == key_file


def test_apply_reverse_proxy_mode_ignores_missing_uwsgi(tmp_path):
    global_properties.workdir = str(tmp_path)
    cfg = WebConfig()
    cfg.tls_mode = cfg.TLS_MODE_REVERSE_PROXY
    tls_manager.apply_web_tls_config(cfg)


def test_apply_letsencrypt_mode_uses_default_paths(tmp_path, monkeypatch):
    global_properties.workdir = str(tmp_path)
    uwsgi_path = os.path.join(str(tmp_path), "uwsgi.yaml")
    write_uwsgi(uwsgi_path, {"http-socket": "0.0.0.0:8080"})

    cert_file = os.path.join(str(tmp_path), "fullchain.pem")
    key_file = os.path.join(str(tmp_path), "privkey.pem")
    open(cert_file, "w", encoding="utf-8").close()
    open(key_file, "w", encoding="utf-8").close()

    monkeypatch.setattr(tls_manager, "default_letsencrypt_paths", lambda server_name: (cert_file, key_file))

    cfg = WebConfig()
    cfg.tls_mode = cfg.TLS_MODE_LETS_ENCRYPT
    cfg.tls_server_name = "vpn.example.com"

    tls_manager.apply_web_tls_config(cfg)
    loaded = read_uwsgi(uwsgi_path)["uwsgi"]
    assert loaded["https-socket"] == f"0.0.0.0:8080,{cert_file},{key_file}"
    assert cfg.tls_cert_file == cert_file
    assert cfg.tls_key_file == key_file
