import re
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from arpvpn.common.properties import global_properties  # noqa: E402
from arpvpn.core.config.web import WebConfig  # noqa: E402
from arpvpn.core.managers.tls import TLSManager  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "arpvpn" / "web" / "templates"

LEGACY = {
    "uwsgi": {
        "master": True,
        "processes": 1,
        "threads": 1,
        "pyargv": "/data",
        "http-socket": "0.0.0.0:8085",
        "https-socket": "0.0.0.0:8086,/data/certs/a.crt,/data/certs/a.key",
        "vacuum": True,
    }
}


@pytest.fixture()
def workdir(tmp_path, monkeypatch):
    monkeypatch.setattr(global_properties, "workdir", str(tmp_path))
    return tmp_path


def write_uwsgi(path: Path, data):
    (path / "uwsgi.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def read_uwsgi(path: Path, name="uwsgi.yaml"):
    return yaml.safe_load((path / name).read_text(encoding="utf-8"))["uwsgi"]


def test_migration_without_uwsgi_rewrites_in_place(workdir, monkeypatch):
    write_uwsgi(workdir, LEGACY)
    monkeypatch.setattr(TLSManager, "_uwsgi_module", staticmethod(lambda: None))

    assert TLSManager.migrate_uwsgi_config() is None

    settings = read_uwsgi(workdir)
    assert "http-socket" not in settings and "https-socket" not in settings
    assert settings["http"] == "0.0.0.0:8085"
    assert settings["https"] == "0.0.0.0:8086,/data/certs/a.crt,/data/certs/a.key"
    assert settings["threads"] == 4
    assert settings["http-keepalive"] == 1
    assert settings["http-buffer-size"] == 65536
    assert settings["pyargv"] == "/data"
    # A second start has nothing left to do.
    assert TLSManager.migrate_uwsgi_config() is None


def test_migration_under_uwsgi_takes_two_reloads(workdir, monkeypatch):
    write_uwsgi(workdir, LEGACY)
    monkeypatch.setattr(TLSManager, "_uwsgi_module", staticmethod(lambda: object()))

    # Step one drops the public listeners so the old sockets get closed.
    assert TLSManager.migrate_uwsgi_config() == "releasing the old web listeners"
    interim = read_uwsgi(workdir)
    assert not {"http", "https", "http-socket", "https-socket"} & set(interim)
    assert interim["socket"] == "127.0.0.1:0"
    pending = read_uwsgi(workdir, TLSManager.PENDING_UWSGI_FILENAME)
    assert pending["http"] == "0.0.0.0:8085"

    # Step two puts the router config in place and removes the pending file.
    assert TLSManager.migrate_uwsgi_config() == "binding the HTTP router"
    final = read_uwsgi(workdir)
    assert final["http"] == "0.0.0.0:8085"
    assert final["https"].startswith("0.0.0.0:8086,")
    assert "socket" not in final
    assert not (workdir / TLSManager.PENDING_UWSGI_FILENAME).exists()

    # And then it settles.
    assert TLSManager.migrate_uwsgi_config() is None


def test_migration_keeps_higher_thread_counts(workdir, monkeypatch):
    data = {"uwsgi": {"http": "0.0.0.0:8085", "threads": 8, "buffer-size": 65536}}
    write_uwsgi(workdir, data)
    monkeypatch.setattr(TLSManager, "_uwsgi_module", staticmethod(lambda: object()))
    assert TLSManager.migrate_uwsgi_config() == "applying web listener settings"
    settings = read_uwsgi(workdir)
    assert settings["threads"] == 8
    assert settings["buffer-size"] == 65536
    assert TLSManager.migrate_uwsgi_config() is None


def test_migration_ignores_missing_or_broken_files(workdir):
    assert TLSManager.migrate_uwsgi_config() is None
    (workdir / "uwsgi.yaml").write_text("not: [valid", encoding="utf-8")
    assert TLSManager.migrate_uwsgi_config() is None


def test_tls_settings_write_router_listeners(workdir, monkeypatch):
    write_uwsgi(workdir, LEGACY)
    config = WebConfig()
    config.http_port = 9085
    config.https_port = 9086

    settings = dict(LEGACY["uwsgi"])
    TLSManager._ensure_bind_http_and_https(settings, config, "/c.crt", "/c.key")
    assert settings["http"] == "0.0.0.0:9085"
    assert settings["https"] == "0.0.0.0:9086,/c.crt,/c.key"
    assert "http-socket" not in settings and "https-socket" not in settings

    TLSManager._ensure_bind_http_only(settings, config)
    assert settings["http"] == "0.0.0.0:9085"
    assert "https" not in settings
    assert settings["http-keepalive"] == 1


def test_schedule_reload_is_a_no_op_outside_uwsgi(workdir, monkeypatch):
    monkeypatch.setattr(TLSManager, "_uwsgi_module", staticmethod(lambda: None))
    assert TLSManager.schedule_reload("test") is False


def test_schedule_reload_loop_guard(workdir, monkeypatch):
    class FakeUwsgi:
        post_fork_hook = None

        @staticmethod
        def worker_id():
            return 0

    monkeypatch.setattr(TLSManager, "_uwsgi_module", staticmethod(lambda: FakeUwsgi))
    assert TLSManager.schedule_reload("first") is True
    assert callable(FakeUwsgi.post_fork_hook)
    assert TLSManager.schedule_reload("second") is False
    assert TLSManager.schedule_reload("second", ignore_loop_guard=True) is True


def test_env_ports_override_saved_ports(monkeypatch):
    monkeypatch.setenv("ARPVPN_HTTP_PORT", "18085")
    monkeypatch.setenv("ARPVPN_HTTPS_PORT", "18086")
    config = WebConfig()
    assert config.http_port == 18085
    assert config.https_port == 18086
    monkeypatch.setenv("ARPVPN_HTTP_PORT", "not-a-port")
    monkeypatch.delenv("ARPVPN_HTTPS_PORT")
    config = WebConfig()
    assert config.http_port == WebConfig.DEFAULT_HTTP_PORT
    assert config.https_port == WebConfig.DEFAULT_HTTPS_PORT


def test_sample_uwsgi_config_uses_router():
    settings = yaml.safe_load((REPO / "config" / "uwsgi.sample.yaml").read_text())["uwsgi"]
    assert "http-socket" not in settings
    assert settings["http"].endswith(":8085")
    assert settings["http-keepalive"] == 1


def test_templates_use_versioned_static_urls():
    offenders = []
    pattern = re.compile(r'(?:src|href)="(?:\.\./)*/?static/')
    for template in TEMPLATES.rglob("*.html"):
        for number, line in enumerate(template.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{template.relative_to(REPO)}:{number}")
    assert offenders == [], "use {{ asset_url('...') }} for static files: " + ", ".join(offenders)


def test_font_awesome_loads_as_css_and_csp_allows_it():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert "font-awesome/5.15.1/css/all.min.css" in base
    assert "font-awesome/5.15.1/js/all.min.js" not in base
    main = (REPO / "arpvpn" / "__main__.py").read_text(encoding="utf-8")
    style_src = re.search(r'"style-src ([^"]+)"', main).group(1)
    assert "https://cdnjs.cloudflare.com" in style_src


def test_theme_module_does_not_fetch_on_every_page():
    theme = (REPO / "arpvpn" / "web" / "static" / "js" / "modules" / "theme.mjs").read_text(encoding="utf-8")
    init = theme[theme.index("function init()"):]
    init = init[:init.index("\n}\n")]
    assert "fetch(" not in init
    assert "arpvpn-theme-choice" in theme


def test_migration_follows_env_ports(workdir, monkeypatch):
    write_uwsgi(workdir, {"uwsgi": {"http": "0.0.0.0:8085", "https": "0.0.0.0:8086,/c.crt,/c.key",
                                    "plugins": "http", **TLSManager.PERFORMANCE_SETTINGS}})
    monkeypatch.setattr(TLSManager, "_uwsgi_module", staticmethod(lambda: object()))
    monkeypatch.delenv("ARPVPN_HTTP_PORT", raising=False)
    monkeypatch.delenv("ARPVPN_HTTPS_PORT", raising=False)
    assert TLSManager.migrate_uwsgi_config() is None

    monkeypatch.setenv("ARPVPN_HTTP_PORT", "9085")
    monkeypatch.setenv("ARPVPN_HTTPS_PORT", "9086")
    assert TLSManager.migrate_uwsgi_config() == "applying web listener settings"
    settings = read_uwsgi(workdir)
    assert settings["http"] == "0.0.0.0:9085"
    assert settings["https"] == "0.0.0.0:9086,/c.crt,/c.key"
    assert TLSManager.migrate_uwsgi_config() is None


def test_router_plugin_is_requested_once(workdir, monkeypatch):
    write_uwsgi(workdir, LEGACY)
    monkeypatch.setattr(TLSManager, "_uwsgi_module", staticmethod(lambda: None))
    TLSManager.migrate_uwsgi_config()
    assert read_uwsgi(workdir)["plugins"] == "http"
    settings = {"plugins": "python3, http"}
    TLSManager._apply_performance_settings(settings)
    assert settings["plugins"] == "python3, http"
