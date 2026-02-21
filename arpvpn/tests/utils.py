import http
import os
import shutil
import sys

from flask_login import current_user

from arpvpn.common.models.user import users, User
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
    clients.clear()
    interfaces.clear()
    cron_manager.stop()
    if current_user:
        current_user.logout()


def is_http_success(code: int):
    return code < http.HTTPStatus.BAD_REQUEST


def login(client):
    u = User(username)
    u.password = password
    users[u.id] = u

    response = client.post("/login", data={"username": username, "password": password, "remember_me": False})
    assert is_http_success(response.status_code), default_cleanup()
    assert current_user.name == "admin", default_cleanup()


def get_testing_app():
    workdir = "data"
    sys.argv = [sys.argv[0], workdir]
    global_properties.setup_required = False
    global_properties.dev_env = True
    from arpvpn.__main__ import app
    app.config["TESTING"] = True  # nosemgrep: python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_TESTING
    app.config["WTF_CSRF_ENABLED"] = False  # nosemgrep: python.flask.security.audit.wtf-csrf-disabled.flask-wtf-csrf-disabled
    return app


def create_test_iface(name, ipv4, port):
    gw = list(filter(lambda i: i != "lo", get_system_interfaces().keys()))[1]
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
    return Interface(name=name, description="", gw_iface=gw, ipv4_address=ipv4, listen_port=port, auto=False,
                     on_up=on_up, on_down=on_down)
