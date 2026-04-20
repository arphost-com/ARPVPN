import http
import os
import shutil
import sys

from flask_login import current_user

from arpvpn.common.models.user import users, User
from arpvpn.common.models.tenant import tenants, invitations
from arpvpn.common.properties import global_properties
from arpvpn.common.utils.network import get_system_interfaces
from arpvpn.core.managers.cron import cron_manager
from arpvpn.core.models import interfaces, Interface
from arpvpn.web.client import clients

username = "admin"
password = "admin"


def exists_config_file() -> bool:
    from arpvpn.core.managers.config import config_manager
    return os.path.exists(config_manager.config_filepath)


def exists_credentials_file() -> bool:
    from arpvpn.core.config.web import config
    return os.path.exists(config.credentials_file)


def exists_traffic_file() -> bool:
    from arpvpn.core.config.traffic import config
    if not config.driver.filepath:
        return False
    return os.path.exists(config.driver.filepath)


def exists_log_file() -> bool:
    from arpvpn.core.config.logger import config
    return os.path.exists(config.logfile)


def default_cleanup():
    for root, dirs, files in os.walk(global_properties.workdir):
        for f in files:
            os.remove(os.path.join(root, f))
        for d in dirs:
            shutil.rmtree(os.path.join(root, d))
    users.clear()
    tenants.clear()
    invitations.clear()
    clients.clear()
    interfaces.clear()
    cron_manager.stop()
    try:
        from arpvpn.web.router import (
            api_token_store,
            api_rate_limiter,
            api_auth_lockouts,
            api_idempotency_store,
            api_async_jobs,
        )
        api_token_store.reset_for_tests()
        api_rate_limiter.reset_for_tests()
        api_auth_lockouts.reset_for_tests()
        api_idempotency_store.reset_for_tests()
        api_async_jobs.reset_for_tests()
    except Exception:
        pass
    if current_user:
        current_user.logout()


def is_http_success(code: int):
    return code < http.HTTPStatus.BAD_REQUEST


def login(client, mfa_code=None):
    u = User(username)
    u.password = password
    users[u.id] = u

    payload = {"username": username, "password": password, "remember_me": False}
    if mfa_code is not None:
        payload["mfa_code"] = mfa_code
    response = client.post("/login", data=payload)
    assert is_http_success(response.status_code), default_cleanup()
    assert current_user.name == "admin", default_cleanup()


def get_testing_app():
    workdir = "data"
    sys.argv = [sys.argv[0], workdir]
    global_properties.setup_required = False
    global_properties.dev_env = True
    if shutil.which("ip") is None:
        from arpvpn.common.utils import network as network_utils
        from arpvpn.web import router as router_module

        fake_interfaces = {
            "lo": {
                "ifname": "lo",
                "flags": ["LOOPBACK", "UP", "LOWER_UP"],
                "operstate": "UNKNOWN",
                "address": "00:00:00:00:00:00",
                "addr_info": [],
            },
            "eth0": {
                "ifname": "eth0",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "operstate": "UP",
                "address": "02:00:00:00:00:00",
                "addr_info": [],
            },
            "eth1": {
                "ifname": "eth1",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "operstate": "UP",
                "address": "02:00:00:00:00:01",
                "addr_info": [],
            },
        }

        network_utils.get_system_interfaces = lambda: fake_interfaces
        network_utils.get_default_gateway = lambda: "eth1"
        network_utils.get_routing_table = lambda: [
            {"dst": "default", "gateway": "192.0.2.1", "dev": "eth1"},
        ]
        globals()["get_system_interfaces"] = lambda: fake_interfaces
        router_module.get_system_interfaces = lambda: fake_interfaces
        router_module.get_default_gateway = lambda: "eth1"
        router_module.get_routing_table = lambda: [
            {"dst": "default", "gateway": "192.0.2.1", "dev": "eth1"},
        ]
    from arpvpn.__main__ import app
    from arpvpn.core.config.wireguard import config as wireguard_config
    wireguard_config.wg_bin = "/bin/echo"
    wireguard_config.wg_quick_bin = "/bin/echo"
    wireguard_config.iptables_bin = "/bin/echo"
    app.config["TESTING"] = True  # nosemgrep: python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_TESTING
    app.config["WTF_CSRF_ENABLED"] = False  # nosemgrep: python.flask.security.audit.wtf-csrf-disabled.flask-wtf-csrf-disabled
    app.config["API_CSRF_ENABLED"] = False
    return app


def get_test_gateway(preferred: str = "eth1") -> str:
    gateways = [name for name in get_system_interfaces().keys() if name != "lo"]
    if preferred in gateways:
        return preferred
    if gateways:
        return gateways[0]
    return preferred


def create_test_iface(name, ipv4, port):
    gw = get_test_gateway()
    from arpvpn.core.config.wireguard import config
    on_up = [
        f"{config.iptables_bin} -I FORWARD -i {name} -j ACCEPT\n" +
        f"{config.iptables_bin} -I FORWARD -o {name} -j ACCEPT\n" +
        f"{config.iptables_bin} -t nat -I POSTROUTING -o {gw} -j MASQUERADE\n"
    ]
    on_down = [
        f"{config.iptables_bin} -D FORWARD -i {name} -j ACCEPT\n" +
        f"{config.iptables_bin} -D FORWARD -o {name} -j ACCEPT\n" +
        f"{config.iptables_bin} -t nat -D POSTROUTING -o {gw} -j MASQUERADE\n"
    ]
    return Interface(
        name=name,
        description="",
        gw_iface=gw,
        ipv4_address=ipv4,
        listen_port=port,
        auto=False,
        on_up=on_up,
        on_down=on_down,
        private_key="test-private-key",
        public_key="test-public-key",
    )
