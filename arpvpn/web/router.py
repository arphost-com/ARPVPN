import csv
import io
import json
import os
import re
from datetime import datetime
from functools import wraps
from http.client import BAD_REQUEST, NOT_FOUND, INTERNAL_SERVER_ERROR, UNAUTHORIZED, NO_CONTENT, FORBIDDEN
from ipaddress import IPv4Address
from logging import warning, debug, error, info
from time import sleep
from typing import List, Dict, Any, Union, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from flask import Blueprint, abort, request, Response, redirect, url_for, jsonify, session
from flask_login import current_user, login_required, login_user

from arpvpn.common.models.user import users, User
from arpvpn.common.properties import global_properties
from arpvpn.common.utils.logs import log_exception
from arpvpn.common.utils.network import get_routing_table, get_system_interfaces
from arpvpn.common.utils.strings import list_to_str
from arpvpn.common.utils.time import get_time_ago
from arpvpn.core.config.logger import config as logger_config
from arpvpn.core.config.traffic import config as traffic_config
from arpvpn.core.config.web import config as web_config
from arpvpn.core.config.wireguard import config as wireguard_config
from arpvpn.core.drivers.traffic_storage_driver import TrafficData
from arpvpn.core.exceptions import WireguardError
from arpvpn.core.managers.config import config_manager
from arpvpn.core.models import interfaces, Interface, get_all_peers, Peer
from arpvpn.core.utils.wireguard import is_wg_iface_up
from arpvpn.web.client import clients, Client
from arpvpn.web.controllers.RestController import RestController
from arpvpn.web.controllers.ViewController import ViewController
from arpvpn.web.static.assets.resources import EMPTY_FIELD, APP_NAME

ACTIVE_PEER_MAX_AGE_SECONDS = 180
STALE_PEER_MAX_AGE_SECONDS = 1800
ALLOWED_NEXT_ENDPOINTS = {
    "/": "router.index",
    "/dashboard": "router.index",
    "/network": "router.network",
    "/wireguard": "router.wireguard",
    "/settings": "router.settings",
    "/users": "router.manage_users",
    "/themes": "router.themes",
    "/about": "router.about",
    "/setup": "router.setup",
}
IMPERSONATOR_SESSION_KEY = "impersonator_user_id"
STAFF_ROLES = (User.ROLE_ADMIN, User.ROLE_SUPPORT)


def get_env_int(name: str, default: int) -> int:
    value = os.environ.get(name, str(default))
    try:
        return int(value)
    except ValueError:
        warning(f"Invalid integer in env var {name}={value}, using default {default}")
        return default


HIGH_TRAFFIC_THRESHOLD_MB = get_env_int("ARPVPN_HIGH_TRAFFIC_THRESHOLD_MB", 1024)
HIGH_TRAFFIC_THRESHOLD_BYTES = HIGH_TRAFFIC_THRESHOLD_MB * 1024 * 1024


def is_safe_redirect_url(url: str) -> bool:
    """
    Validate that a URL is safe for redirect (prevents open redirect vulnerabilities).
    Only allows relative URLs with no scheme or netloc.
    """
    if not url:
        return False
    parsed = urlparse(url)
    return url.startswith("/") and not url.startswith("//") and not parsed.scheme and not parsed.netloc


def get_allowed_next_target(url: str) -> Optional[Tuple[str, Dict[str, str]]]:
    if not is_safe_redirect_url(url):
        return None

    path = urlparse(url).path.rstrip("/") or "/"
    endpoint = ALLOWED_NEXT_ENDPOINTS.get(path)
    if endpoint:
        return endpoint, {}

    iface_match = re.fullmatch(r"/wireguard/interfaces/([a-f0-9]{32})", path)
    if iface_match:
        return "router.get_wireguard_iface", {"uuid": iface_match.group(1)}

    peer_match = re.fullmatch(r"/wireguard/peers/([a-f0-9]{32})", path)
    if peer_match:
        return "router.get_wireguard_peer", {"uuid": peer_match.group(1)}

    return None


def redirect_to_next_or_default(next_url: Optional[str], default_endpoint: str = "router.index"):
    target = get_allowed_next_target(next_url) if next_url else None
    if target:
        endpoint, values = target
        return redirect(url_for(endpoint, **values))
    return redirect(url_for(default_endpoint))


def get_referrer_next_value():
    if not request.referrer:
        return None
    next_url = parse_qs(urlparse(request.referrer).query).get("next", None)
    if not next_url or len(next_url) < 1:
        return None
    url = next_url[0]
    if is_safe_redirect_url(url):
        return url
    return None


class Router(Blueprint):

    def __init__(self, name, import_name):
        super().__init__(name, import_name)
        self.login_attempts = 1
        self.banned_until = None


router = Router("router", __name__)

config_manager.load()


def setup_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if global_properties.setup_required and not global_properties.setup_file_exists():
            return redirect(url_for("router.setup", next=request.args.get("next", get_referrer_next_value())))
        return f(*args, **kwargs)

    return wrapped


def role_required(*roles: str):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(UNAUTHORIZED)
            if not current_user.has_role(*roles):
                abort(FORBIDDEN, "Insufficient permissions.")
            return f(*args, **kwargs)

        return wrapped

    return decorator


def get_impersonator_user() -> Optional[User]:
    impersonator_id = session.get(IMPERSONATOR_SESSION_KEY)
    if not impersonator_id:
        return None
    impersonator = users.get(impersonator_id, None)
    if not impersonator:
        session.pop(IMPERSONATOR_SESSION_KEY, None)
        return None
    if current_user.is_authenticated and impersonator.id == current_user.id:
        session.pop(IMPERSONATOR_SESSION_KEY, None)
        return None
    return impersonator


def is_impersonating() -> bool:
    return get_impersonator_user() is not None


@router.route("/")
@router.route("/dashboard")
@login_required
@setup_required
def index():
    if traffic_config.enabled:
        traffic = traffic_config.driver.get_session_and_stored_data()
    else:
        traffic = {datetime.now(): traffic_config.driver.get_session_data()}
    peer_runtime = get_peer_runtime_summary()
    iface_names = []
    ifaces_traffic = [
        {"label": "Received", "data": []},
        {"label": "Transmitted", "data": []},
    ]
    peer_names = []
    peers_traffic = [
        {"label": "Received", "data": []},
        {"label": "Transmitted", "data": []},
    ]
    for iface in interfaces.values():
        iface_names.append(iface.name)
        iface_traffic = __get_total_traffic__(iface.uuid, traffic)
        ifaces_traffic[0]["data"].append(iface_traffic.rx)
        ifaces_traffic[1]["data"].append(iface_traffic.tx)
        for peer in iface.peers.values():
            peer_names.append(peer.name)
            peer_traffic = __get_total_traffic__(peer.uuid, traffic)
            peers_traffic[0]["data"].append(peer_traffic.rx)
            peers_traffic[1]["data"].append(peer_traffic.tx)

    interface_totals = get_interface_totals()

    context = {
        "title": "Dashboard",
        "interfaces_chart": {"labels": iface_names, "datasets": ifaces_traffic},
        "peers_chart": {"labels": peer_names, "datasets": peers_traffic},
        "interfaces": interfaces,
        "interface_totals": interface_totals,
        "peer_runtime": peer_runtime,
        "top_peers": peer_runtime["rows"][:10],
        "last_update": datetime.now().strftime("%H:%M"),
        "EMPTY_FIELD": EMPTY_FIELD,
        "traffic_config": traffic_config
    }
    return ViewController("web/index.html", **context).load()


def __get_total_traffic__(uuid: str, traffic: Dict[datetime, Dict[str, TrafficData]]) -> TrafficData:
    rx = 0
    tx = 0
    for data in reversed(list(traffic.values())):
        # Get only last appearance
        if uuid in data:
            rx += data[uuid].rx
            tx += data[uuid].tx
            break
    return TrafficData(rx, tx)


def get_interface_totals() -> Dict[str, int]:
    statuses = [iface.status for iface in interfaces.values()]
    return {
        "total": len(interfaces),
        "up": statuses.count("up"),
        "down": statuses.count("down")
    }


def to_human_filesize(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    units = ["KB", "MB", "GB", "TB", "PB"]
    size = float(size_bytes)
    for unit in units:
        size = size / 1024
        if size < 1024:
            return f"{size:.2f} {unit}"
    return f"{size:.2f} PB"


def get_peer_runtime_summary() -> Dict[str, Any]:
    now = datetime.now()
    session_data = traffic_config.driver.get_session_data()
    peer_rows = []
    alerts = []
    totals = {
        "peers": 0,
        "site_to_site_peers": 0,
        "client_peers": 0,
        "active_peers": 0,
        "stale_peers": 0,
        "offline_peers": 0,
        "never_seen_peers": 0,
        "high_traffic_peers": 0,
        "session_rx": 0,
        "session_tx": 0,
    }
    for peer in get_all_peers().values():
        totals["peers"] += 1
        if peer.mode == Peer.MODE_SITE_TO_SITE:
            totals["site_to_site_peers"] += 1
        else:
            totals["client_peers"] += 1
        traffic = session_data.get(peer.uuid, TrafficData(0, 0))
        totals["session_rx"] += traffic.rx
        totals["session_tx"] += traffic.tx
        handshake_ago = None
        handshake_state = "never"
        handshake_badge = "secondary"
        last_handshake = traffic.last_handshake
        seconds_ago = None
        if traffic.last_handshake:
            seconds_ago = int((now - traffic.last_handshake).total_seconds())
            handshake_ago = get_time_ago(traffic.last_handshake)
            if seconds_ago <= ACTIVE_PEER_MAX_AGE_SECONDS:
                handshake_state = "active"
                handshake_badge = "success"
                totals["active_peers"] += 1
            elif seconds_ago <= STALE_PEER_MAX_AGE_SECONDS:
                handshake_state = "stale"
                handshake_badge = "warning"
                totals["stale_peers"] += 1
            else:
                handshake_state = "offline"
                handshake_badge = "danger"
                totals["offline_peers"] += 1
        else:
            totals["never_seen_peers"] += 1
        total_traffic = traffic.rx + traffic.tx
        high_traffic = total_traffic >= HIGH_TRAFFIC_THRESHOLD_BYTES
        if high_traffic:
            totals["high_traffic_peers"] += 1

        interface_uuid = peer.interface.uuid if peer.interface else None
        peer_rows.append({
            "peer": peer,
            "peer_uuid": peer.uuid,
            "peer_name": peer.name,
            "interface_uuid": interface_uuid,
            "interface_name": peer.interface.name if peer.interface else EMPTY_FIELD,
            "mode": peer.mode,
            "mode_label": "Site-to-site" if peer.mode == Peer.MODE_SITE_TO_SITE else "Client",
            "handshake_state": handshake_state,
            "handshake_badge": handshake_badge,
            "handshake_ago": handshake_ago,
            "last_handshake": last_handshake,
            "last_handshake_iso": last_handshake.isoformat() if last_handshake else None,
            "seconds_since_handshake": seconds_ago,
            "high_traffic": high_traffic,
            "session_rx": traffic.rx,
            "session_tx": traffic.tx,
            "session_total": total_traffic,
            "session_rx_human": to_human_filesize(traffic.rx),
            "session_tx_human": to_human_filesize(traffic.tx),
            "session_total_human": to_human_filesize(total_traffic)
        })

        if peer.mode == Peer.MODE_SITE_TO_SITE and handshake_state in ("never", "offline", "stale"):
            if handshake_state == "stale":
                level = "warning"
                title = "Site-to-site link is stale"
            else:
                level = "danger"
                title = "Site-to-site link is down"
            alerts.append({
                "level": level,
                "title": title,
                "peer_uuid": peer.uuid,
                "peer_name": peer.name,
                "message": f"{peer.name} is {handshake_state}."
            })
        elif peer.mode != Peer.MODE_SITE_TO_SITE and handshake_state == "offline":
            alerts.append({
                "level": "warning",
                "title": "Client peer appears offline",
                "peer_uuid": peer.uuid,
                "peer_name": peer.name,
                "message": f"{peer.name} has not handshaken recently."
            })

        if high_traffic:
            alerts.append({
                "level": "info",
                "title": "High traffic peer",
                "peer_uuid": peer.uuid,
                "peer_name": peer.name,
                "message": f"{peer.name} transferred {to_human_filesize(total_traffic)} in this session."
            })

    peer_rows.sort(key=lambda row: row["session_total"], reverse=True)
    alert_priority = {"danger": 0, "warning": 1, "info": 2}
    alerts.sort(key=lambda item: (alert_priority.get(item["level"], 3), item["peer_name"]))
    totals["session_total"] = totals["session_rx"] + totals["session_tx"]
    totals["session_rx_human"] = to_human_filesize(totals["session_rx"])
    totals["session_tx_human"] = to_human_filesize(totals["session_tx"])
    totals["session_total_human"] = to_human_filesize(totals["session_total"])
    totals["alerts"] = len(alerts)
    return {
        "totals": totals,
        "rows": peer_rows,
        "alerts": alerts,
        "thresholds": {
            "active_peer_max_age_seconds": ACTIVE_PEER_MAX_AGE_SECONDS,
            "stale_peer_max_age_seconds": STALE_PEER_MAX_AGE_SECONDS,
            "high_traffic_threshold_bytes": HIGH_TRAFFIC_THRESHOLD_BYTES,
            "high_traffic_threshold_human": to_human_filesize(HIGH_TRAFFIC_THRESHOLD_BYTES)
        }
    }


def serialize_peer_runtime_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "peer_uuid": row["peer_uuid"],
        "peer_name": row["peer_name"],
        "interface_uuid": row["interface_uuid"],
        "interface_name": row["interface_name"],
        "mode": row["mode"],
        "mode_label": row["mode_label"],
        "handshake_state": row["handshake_state"],
        "handshake_ago": row["handshake_ago"],
        "last_handshake_iso": row["last_handshake_iso"],
        "seconds_since_handshake": row["seconds_since_handshake"],
        "high_traffic": row["high_traffic"],
        "session_rx_bytes": row["session_rx"],
        "session_tx_bytes": row["session_tx"],
        "session_total_bytes": row["session_total"],
        "session_rx_human": row["session_rx_human"],
        "session_tx_human": row["session_tx_human"],
        "session_total_human": row["session_total_human"]
    }


def build_stats_snapshot() -> Dict[str, Any]:
    peer_runtime = get_peer_runtime_summary()
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "interfaces": get_interface_totals(),
        "peers": peer_runtime["totals"],
        "thresholds": peer_runtime["thresholds"],
        "alerts": peer_runtime["alerts"],
        "top_peers": [serialize_peer_runtime_row(row) for row in peer_runtime["rows"][:10]]
    }


def csv_response(filename: str, fieldnames: List[str], rows: List[Dict[str, Any]]) -> Response:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.route("/logout")
@login_required
@setup_required
def logout():
    session.pop(IMPERSONATOR_SESSION_KEY, None)
    current_user.logout()
    return redirect(url_for("router.index"))


@router.route("/signup", methods=["GET"])
def signup():
    if len(users) > 0:
        return redirect(url_for("router.index"))
    from arpvpn.web.forms import SignupForm
    context = {
        "title": "Create admin account",
        "form": SignupForm()
    }
    return ViewController("web/signup.html", **context).load()


@router.route("/signup", methods=["POST"])
def signup_post():
    if len(users) > 0:
        abort(UNAUTHORIZED)
    from arpvpn.web.forms import SignupForm
    form = SignupForm(request.form)
    return RestController().signup(form)


@router.route("/login", methods=["GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("router.index"))
    if len(users) < 1:
        return redirect(url_for("router.signup"))
    from arpvpn.web.forms import LoginForm
    context = {
        "title": "Login",
        "form": LoginForm()
    }
    client = get_client()
    if client.is_banned():
        context["banned_for"] = (client.banned_until - datetime.now()).seconds
    return ViewController("web/login.html", **context).load()


def run_ban_timer():
    sleep(web_config.login_ban_time)
    router.banned_until = None
    router.login_attempts = 1


def get_client() -> Client:
    client_ip = IPv4Address(request.remote_addr)
    if client_ip not in clients:
        clients[client_ip] = Client(client_ip)
    return clients[client_ip]


@router.route("/login", methods=["POST"])
def login_post():
    from arpvpn.web.forms import LoginForm
    form = LoginForm(request.form)
    info(f"Logging in user '{form.username.data}'...")
    client = get_client()
    if client.is_banned():
        return redirect_to_next_or_default(form.next.data)
    if not form.validate():
        error("Unable to validate form.")
        context = {
            "title": "Login",
            "form": form
        }
        client.login_attempts += 1
        if client.login_attempts > int(web_config.login_attempts):
            client.ban()
            context["banned_for"] = (client.banned_until - datetime.now()).seconds
        return ViewController("web/login.html", **context).load()
    del clients[client.ip]
    session.pop(IMPERSONATOR_SESSION_KEY, None)
    u = users.get_value_by_attr("name", form.username.data)
    if not login_user(u, form.remember_me.data):
        error(f"Unable to log user in.")
        abort(INTERNAL_SERVER_ERROR)
    info(f"Successfully logged user '{u.name}' in!")
    router.web_login_attempts = 1
    return redirect_to_next_or_default(request.args.get("next", None))


@router.route("/network")
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def network():
    wg_ifaces = list(interfaces.values())
    ifaces = get_network_ifaces(wg_ifaces)
    routes = get_routing_table()
    context = {
        "title": "Network",
        "interfaces": ifaces,
        "routes": routes,
        "last_update": datetime.now().strftime("%H:%M"),
        "EMPTY_FIELD": EMPTY_FIELD
    }
    return ViewController("web/network.html", **context).load()


def get_network_ifaces(wg_interfaces: List[Interface]) -> Dict[str, Dict[str, Any]]:
    interfaces = get_system_interfaces_summary()
    for iface in wg_interfaces:
        if iface.name not in interfaces:
            interfaces[iface.name] = {
                "uuid": iface.uuid,
                "name": iface.name,
                "status": "down",
                "ipv4": iface.ipv4_address,
                "ipv6": EMPTY_FIELD,
                "mac": EMPTY_FIELD,
                "flags": EMPTY_FIELD
            }
        else:
            if iface in wg_interfaces:
                interfaces[iface.name]["uuid"] = iface.uuid
            if interfaces[iface.name]["status"] == "unknown":
                if is_wg_iface_up(iface.name):
                    interfaces[iface.name]["status"] = "up"
                else:
                    interfaces[iface.name]["status"] = "down"
        interfaces[iface.name]["editable"] = True

    return interfaces


def get_system_interfaces_summary() -> Dict[str, Dict[str, Any]]:
    interfaces = {}
    for item in get_system_interfaces().values():
        flag_list = list(filter(lambda flag: "UP" not in flag, item["flags"]))
        flags = list_to_str(flag_list)
        iface = {
            "name": item["ifname"],
            "flags": flags,
            "status": item["operstate"].lower()
        }
        if "LOOPBACK" in iface["flags"]:
            iface["status"] = "up"
        if "address" in item:
            iface["mac"] = item["address"]
        else:
            iface["mac"] = EMPTY_FIELD
        addr_info = item["addr_info"]
        if addr_info:
            ipv4_info = addr_info[0]
            iface["ipv4"] = f"{ipv4_info['local']}/{ipv4_info['prefixlen']}"
            if len(addr_info) > 1:
                ipv6_info = addr_info[1]
                iface["ipv6"] = f"{ipv6_info['local']}/{ipv6_info['prefixlen']}"
            else:
                iface["ipv6"] = EMPTY_FIELD
        else:
            iface["ipv4"] = EMPTY_FIELD
            iface["ipv6"] = EMPTY_FIELD
        interfaces[iface["name"]] = iface
    return interfaces


@router.route("/wireguard")
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def wireguard():
    peer_runtime = get_peer_runtime_summary()
    interface_totals = get_interface_totals()
    context = {
        "title": "Wireguard",
        "interfaces": interfaces,
        "peer_runtime": peer_runtime,
        "wireguard_stats": {
            "interfaces_total": interface_totals["total"],
            "interfaces_up": interface_totals["up"],
            "interfaces_down": interface_totals["down"],
            "peers_total": peer_runtime["totals"]["peers"],
            "site_to_site_peers": peer_runtime["totals"]["site_to_site_peers"],
            "active_peers": peer_runtime["totals"]["active_peers"],
            "alerts": peer_runtime["totals"]["alerts"]
        },
        "last_update": datetime.now().strftime("%H:%M"),
        "EMPTY_FIELD": EMPTY_FIELD
    }
    return ViewController("web/wireguard.html", **context).load()


@router.route("/api/v1/stats/overview", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_stats_overview():
    return jsonify(build_stats_snapshot())


@router.route("/api/v1/stats/peers", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_stats_peers():
    runtime = get_peer_runtime_summary()
    return jsonify({
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "thresholds": runtime["thresholds"],
        "peers": [serialize_peer_runtime_row(row) for row in runtime["rows"]]
    })


@router.route("/api/v1/stats/alerts", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_stats_alerts():
    runtime = get_peer_runtime_summary()
    return jsonify({
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "alerts": runtime["alerts"]
    })


@router.route("/api/v1/stats/peers.csv", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_stats_peers_csv():
    runtime = get_peer_runtime_summary()
    rows = [serialize_peer_runtime_row(row) for row in runtime["rows"]]
    fields = [
        "peer_uuid", "peer_name", "interface_uuid", "interface_name", "mode", "mode_label",
        "handshake_state", "handshake_ago", "last_handshake_iso", "seconds_since_handshake",
        "high_traffic", "session_rx_bytes", "session_tx_bytes", "session_total_bytes",
        "session_rx_human", "session_tx_human", "session_total_human"
    ]
    return csv_response("arpvpn-peer-stats.csv", fields, rows)


@router.route("/api/v1/stats/alerts.csv", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_stats_alerts_csv():
    runtime = get_peer_runtime_summary()
    fields = ["level", "title", "message", "peer_name", "peer_uuid"]
    return csv_response("arpvpn-alerts.csv", fields, runtime["alerts"])


@router.route("/wireguard/interfaces/add", methods=['GET'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def create_wireguard_iface():
    from arpvpn.web.forms import AddInterfaceForm
    form = AddInterfaceForm.populate(AddInterfaceForm())
    context = {
        "title": "Add interface",
        "form": form,

    }
    return ViewController("web/wireguard-add-iface.html", **context).load()


@router.route("/wireguard/interfaces/add", methods=['POST'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def add_wireguard_iface():
    from arpvpn.web.forms import AddInterfaceForm
    form = AddInterfaceForm.from_form(AddInterfaceForm(request.form))
    view = "web/wireguard-add-iface.html"
    context = {
        "title": "Add interface",
        "form": form,

    }
    if not form.validate():
        error("Unable to validate form")
        return ViewController(view, **context).load()
    try:
        RestController().add_iface(form)
        return redirect(url_for("router.wireguard"))
    except Exception as e:
        log_exception(e)
        context["error"] = True
        context["error_details"] = e
    return ViewController(view, **context).load()


def load_traffic_data(item: Union[Peer, Interface]):
    labels = []
    datasets = {"rx": [], "tx": []}
    for timestamp, traffic_data in traffic_config.driver.load_data().items():
        labels.append(str(timestamp))
        for device, data in traffic_data.items():
            if device == item.uuid:
                datasets["rx"].append(data.rx)
                datasets["tx"].append(data.tx)
                break
    return {"labels": labels, "datasets": datasets}


@router.route("/wireguard/interfaces/<uuid>", methods=['GET', "POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def get_wireguard_iface(uuid: str):
    if uuid not in interfaces:
        abort(NOT_FOUND, f"Unknown interface '{uuid}'.")
    iface = interfaces[uuid]
    view = "web/wireguard-iface.html"
    data = load_traffic_data(iface)
    session_data = traffic_config.driver.get_session_data()
    iface_traffic = session_data.get(iface.uuid, TrafficData(0, 0))
    context = {
        "title": "Interface",
        "iface": iface,
        "last_update": datetime.now().strftime("%H:%M"),
        "EMPTY_FIELD": EMPTY_FIELD,
        "chart": {"labels": data["labels"], "datasets": data["datasets"]},
        "iface_traffic": TrafficData(iface_traffic.rx, iface_traffic.tx),
        "session_traffic": session_data,
        "traffic_config": traffic_config
    }
    from arpvpn.web.forms import EditInterfaceForm
    if request.method == 'GET':
        form = EditInterfaceForm.from_interface(iface)
        context["form"] = form
        return ViewController("web/wireguard-iface.html", **context).load()
    form = EditInterfaceForm.from_form(EditInterfaceForm(request.form), iface)
    context["form"] = form
    if not form.validate():
        error("Unable to validate form.")
        return ViewController(view, **context).load()
    try:
        RestController().apply_iface(iface, form)
        context["success"] = True
        context["success_details"] = "Interface updated successfully."
    except Exception as e:
        log_exception(e)
        context["error"] = True
        context["error_details"] = e
    return ViewController(view, **context).load()


@router.route("/wireguard/interfaces/<uuid>", methods=['DELETE'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def remove_wireguard_iface(uuid: str):
    if uuid not in interfaces:
        abort(NOT_FOUND, f"Interface {uuid} not found.")
    return RestController(uuid).remove_iface()


@router.route("/wireguard/interfaces/<uuid>/<action>", methods=['POST'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def operate_wireguard_iface(uuid: str, action: str):
    action = action.lower()
    try:
        if action == "start":
            interfaces[uuid].up()
            return Response(status=NO_CONTENT)
        if action == "restart":
            interfaces[uuid].restart()
            return Response(status=NO_CONTENT)
        if action == "stop":
            interfaces[uuid].down()
            return Response(status=NO_CONTENT)
        raise WireguardError(f"Invalid operation: {action}", BAD_REQUEST)
    except WireguardError as e:
        return Response(e.cause, status=e.http_code)


@router.route("/wireguard/<action>", methods=['POST'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def operate_wireguard_ifaces(action: str):
    action = action.lower()
    try:
        if action == "start":
            for iface in interfaces.values():
                iface.up()
            return Response(status=NO_CONTENT)
        if action == "restart":
            for iface in interfaces.values():
                iface.restart()
            return Response(status=NO_CONTENT)
        if action == "stop":
            for iface in interfaces.values():
                iface.down()
            return Response(status=NO_CONTENT)
        raise WireguardError(f"invalid operation: {action}", BAD_REQUEST)
    except WireguardError as e:
        return Response(e.cause, status=e.http_code)


@router.route("/wireguard/interfaces/<uuid>/download", methods=['GET'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def download_wireguard_iface(uuid: str):
    if uuid not in interfaces.keys():
        error(f"Unknown interface {uuid}")
        abort(NOT_FOUND)
    return RestController().download_iface(interfaces[uuid])


@router.route("/wireguard/peers/add", methods=['GET'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def create_wireguard_peer():
    if len(interfaces) < 1:
        abort(BAD_REQUEST, "There are no wireguard interfaces!")
    iface_uuid = request.args.get("interface", None)
    iface = interfaces.get(iface_uuid, None)
    from arpvpn.web.forms import AddPeerForm
    form = AddPeerForm.populate(AddPeerForm(), iface)
    context = {
        "title": "Add peer",
        "form": form,

    }
    return ViewController("web/wireguard-add-peer.html", **context).load()


@router.route("/wireguard/peers/add", methods=['POST'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def add_wireguard_peer():
    if len(interfaces) < 1:
        abort(BAD_REQUEST, "There are no wireguard interfaces!")
    from arpvpn.web.forms import AddPeerForm
    form = AddPeerForm.from_form(AddPeerForm(request.form))
    view = "web/wireguard-add-peer.html"
    context = {
        "title": "Add Peer",
        "form": form,

    }
    if not form.validate():
        error("Unable to validate form")
        return ViewController(view, **context).load()
    try:
        peer = RestController().add_peer(form)
        # Use url_for instead of constructing URL from request.url_root
        return redirect(url_for("router.get_wireguard_peer", uuid=peer.uuid))
    except Exception as e:
        log_exception(e)
        context["error"] = True
        context["error_details"] = e
    return ViewController(view, **context).load()


@router.route("/wireguard/peers/<uuid>", methods=['DELETE'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def remove_wireguard_peer(uuid: str):
    peer = get_all_peers().get(uuid, None)
    if not peer:
        raise WireguardError(f"Unknown peer '{uuid}'.", NOT_FOUND)
    return RestController().remove_peer(peer)


@router.route("/wireguard/peers/<uuid>", methods=['GET', "POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def get_wireguard_peer(uuid: str):
    peer = get_all_peers().get(uuid, None)
    if not peer:
        raise WireguardError(f"Unknown peer '{uuid}'.", NOT_FOUND)
    view = "web/wireguard-peer.html"
    data = load_traffic_data(peer)
    session_data = traffic_config.driver.get_session_data().get(peer.uuid, TrafficData(0, 0))
    handshake_ago = None
    if session_data.last_handshake:
        handshake_ago = get_time_ago(session_data.last_handshake)
    context = {
        "title": "Peer",
        "peer": peer,
        "last_update": datetime.now().strftime("%H:%M"),
        "EMPTY_FIELD": EMPTY_FIELD,
        "chart": {"labels": data["labels"], "datasets": data["datasets"]},
        "session_traffic": TrafficData(session_data.rx, session_data.tx),
        "handshake_ago": handshake_ago,
        "traffic_config": traffic_config
    }
    from arpvpn.web.forms import EditPeerForm
    if request.method == 'GET':
        form = EditPeerForm.from_peer(peer)
        context["form"] = form
        return ViewController(view, **context).load()
    form = EditPeerForm.from_form(EditPeerForm(request.form), peer)
    context["form"] = form
    if not form.validate():
        error("Unable to validate form.")
        return ViewController(view, **context).load()
    try:
        RestController().save_peer(peer, form)
        context["success"] = True
        context["success_details"] = "Peer updated successfully."
    except Exception as e:
        log_exception(e)
        context["error"] = True
        context["error_details"] = e
    return ViewController(view, **context).load()


@router.route("/wireguard/peers/<uuid>/download", methods=['GET'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def download_wireguard_peer(uuid: str):
    peer = get_all_peers().get(uuid, None)
    if not peer:
        msg = f"Unknown peer '{uuid}'."
        error(msg)
        abort(NOT_FOUND, msg)
    return RestController().download_peer(peer)


@router.route("/themes")
@login_required
@setup_required
def themes():
    context = {
        "title": "Themes"
    }
    return ViewController("web/themes.html", **context).load()


@router.route("/settings")
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def settings():
    from arpvpn.web.forms import SettingsForm
    form = SettingsForm.new()
    form.traffic_enabled.data = traffic_config.enabled
    form.log_overwrite.data = logger_config.overwrite
    form.traffic_driver_options.data = json.dumps(traffic_config.driver.__to_yaml_dict__(), indent=4, sort_keys=True)
    context = {
        "title": "Settings",
        "form": form,

    }
    return ViewController("web/settings.html", **context).load()


@router.route("/settings", methods=['POST'])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def save_settings():
    from arpvpn.web.forms import SettingsForm
    form = SettingsForm(request.form)
    view = "web/settings.html"
    context = {
        "title": "Settings",
        "form": form
    }
    if not form.validate():
        error("Unable to validate form")
        return ViewController(view, **context).load()
    try:
        RestController().save_settings(form)
        # Fill fields with default values if they were left unfilled
        form.log_file.data = form.log_file.data or logger_config.logfile

        form.web_secret_key.data = form.web_secret_key.data or web_config.secret_key
        form.web_credentials_file.data = form.web_credentials_file.data or web_config.credentials_file
        form.web_login_attempts.data = form.web_login_attempts.data or web_config.login_attempts
        form.web_login_ban_time.data = form.web_login_ban_time.data or web_config.login_ban_time
        form.web_tls_mode.data = form.web_tls_mode.data or web_config.tls_mode
        form.web_tls_server_name.data = form.web_tls_server_name.data or web_config.tls_server_name
        form.web_tls_letsencrypt_email.data = (
            form.web_tls_letsencrypt_email.data or web_config.tls_letsencrypt_email
        )
        form.web_proxy_incoming_hostname.data = (
            form.web_proxy_incoming_hostname.data or web_config.proxy_incoming_hostname
        )
        form.web_tls_generate_self_signed.data = False
        form.web_tls_issue_letsencrypt.data = False

        form.app_endpoint.data = form.app_endpoint.data or wireguard_config.endpoint
        form.app_wg_bin.data = form.app_wg_bin.data or wireguard_config.wg_bin
        form.app_wg_quick_bin.data = form.app_wg_quick_bin.data or wireguard_config.wg_quick_bin
        form.app_iptables_bin.data = form.app_iptables_bin.data or wireguard_config.iptables_bin
        form.app_interfaces_folder.data = form.app_interfaces_folder.data or wireguard_config.interfaces_folder

        form.traffic_driver_options.data = form.traffic_driver_options.data or \
                                           json.dumps(traffic_config.driver.__to_yaml_dict__(), indent=4,
                                                      sort_keys=True)

        context["success"] = True
        context["success_details"] = "Settings updated!"
        context["warning"] = True
        context["warning_details"] = f"You may need to restart {APP_NAME} to apply some changes."
    except Exception as e:
        log_exception(e)
        context["error"] = True
        context["error_details"] = e
    return ViewController(view, **context).load()


def get_users_management_context(create_form=None, impersonate_form=None, stop_form=None) -> Dict[str, Any]:
    from arpvpn.web.forms import CreateUserForm, ImpersonateClientForm, ImpersonationStopForm
    create_form = create_form or CreateUserForm()
    if current_user.has_role(User.ROLE_SUPPORT):
        create_form.role.choices = [(User.ROLE_CLIENT, "Client")]
        if request.method == "GET":
            create_form.role.data = User.ROLE_CLIENT
    impersonate_form = impersonate_form or ImpersonateClientForm()
    stop_form = stop_form or ImpersonationStopForm()
    users_list = sorted(users.values(), key=lambda u: (u.role, u.name.lower()))
    return {
        "title": "Users",
        "create_form": create_form,
        "impersonate_form": impersonate_form,
        "stop_impersonation_form": stop_form,
        "users_list": users_list,
        "is_impersonating": is_impersonating(),
    }


@router.route("/users", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def manage_users():
    context = get_users_management_context()
    return ViewController("web/users.html", **context).load()


@router.route("/users", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def create_user():
    from arpvpn.web.forms import CreateUserForm, ImpersonateClientForm, ImpersonationStopForm
    form = CreateUserForm(request.form)
    context = get_users_management_context(
        create_form=form,
        impersonate_form=ImpersonateClientForm(),
        stop_form=ImpersonationStopForm(),
    )
    if not form.validate():
        error("Unable to validate create-user form")
        return ViewController("web/users.html", **context).load()
    if current_user.has_role(User.ROLE_SUPPORT) and form.role.data != User.ROLE_CLIENT:
        context["error"] = True
        context["error_details"] = "Support users can only create client accounts."
        return ViewController("web/users.html", **context).load()
    try:
        RestController.create_user(form.username.data, form.password.data, form.role.data)
        context = get_users_management_context()
        context["success"] = True
        context["success_details"] = "User created successfully."
    except Exception as e:
        log_exception(e)
        context["error"] = True
        context["error_details"] = e
    return ViewController("web/users.html", **context).load()


@router.route("/users/<user_id>/impersonate", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def start_impersonation(user_id: str):
    from arpvpn.web.forms import ImpersonateClientForm
    form = ImpersonateClientForm(request.form)
    if not form.validate():
        abort(BAD_REQUEST, "Invalid impersonation request.")
    if is_impersonating():
        abort(BAD_REQUEST, "Already impersonating a user.")
    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    if target_user.role != User.ROLE_CLIENT:
        abort(BAD_REQUEST, "Only client users can be impersonated.")
    if target_user.id == current_user.id:
        abort(BAD_REQUEST, "Cannot impersonate your own account.")
    session[IMPERSONATOR_SESSION_KEY] = current_user.id
    if not login_user(target_user, remember=False):
        abort(INTERNAL_SERVER_ERROR, "Unable to impersonate target user.")
    return redirect(url_for("router.index"))


@router.route("/impersonation/stop", methods=["POST"])
@login_required
@setup_required
def stop_impersonation():
    from arpvpn.web.forms import ImpersonationStopForm
    form = ImpersonationStopForm(request.form)
    if not form.validate():
        abort(BAD_REQUEST, "Invalid stop-impersonation request.")
    impersonator = get_impersonator_user()
    if not impersonator:
        abort(BAD_REQUEST, "No active impersonation session.")
    session.pop(IMPERSONATOR_SESSION_KEY, None)
    if not login_user(impersonator, remember=False):
        abort(INTERNAL_SERVER_ERROR, "Unable to restore original user.")
    return redirect(url_for("router.manage_users"))


@router.route("/setup")
@login_required
@role_required(*STAFF_ROLES)
def setup():
    if global_properties.setup_file_exists():
        return redirect_to_next_or_default(request.args.get("next", None))
    from arpvpn.web.forms import SetupForm
    form = SetupForm()
    wireguard_config.set_default_endpoint()
    form.app_endpoint.data = wireguard_config.endpoint
    form.web_tls_server_name.data = web_config.tls_server_name or wireguard_config.endpoint
    context = {
        "title": "Setup",
        "form": form,
    }
    return ViewController("web/setup.html", **context).load()


@router.route("/setup", methods=['POST'])
@login_required
@role_required(*STAFF_ROLES)
def apply_setup():
    if global_properties.setup_file_exists():
        abort(BAD_REQUEST, "Setup already performed!")
    from arpvpn.web.forms import SetupForm
    form = SetupForm(request.form)
    view = "web/setup.html"
    context = {
        "title": "Setup",
        "form": form
    }
    if not form.validate():
        error("Unable to validate form")
        return ViewController(view, **context).load()
    try:
        RestController().apply_setup(form)
        with open(global_properties.setup_filepath, "w") as f:
            f.write("")
        return redirect_to_next_or_default(request.args.get("next", None))
    except Exception as e:
        log_exception(e)
        context["error"] = True
        context["error_details"] = e
    return ViewController(view, **context).load()


@router.route("/about", methods=['GET'])
@login_required
@setup_required
def about():
    view = "web/about.html"
    context = {
        "title": "About",
    }
    return ViewController(view, **context).load()


@router.route("/profile", methods=['GET'])
@login_required
@setup_required
def profile():
    from arpvpn.web.forms import ProfileForm, PasswordResetForm
    profile_form = ProfileForm()
    profile_form.username.data = current_user.name
    if request.form:
        password_reset_form = PasswordResetForm(request.form)
    else:
        password_reset_form = PasswordResetForm()
    view = "web/profile.html"
    context = {
        "title": "Profile",
        "profile_form": profile_form,
        "password_reset_form": password_reset_form,
        "login_ago": get_time_ago(current_user.login_date),
    }
    return ViewController(view, **context).load()


@router.route("/profile", methods=['POST'])
@login_required
@setup_required
def save_profile():
    if "new_password" in request.form:
        return password_reset()
    from arpvpn.web.forms import ProfileForm, PasswordResetForm
    view = "web/profile.html"
    profile_form = ProfileForm(request.form)
    password_reset_form = PasswordResetForm()
    context = {
        "title": "Profile",
        "profile_form": profile_form,
        "password_reset_form": password_reset_form,
        "login_ago": get_time_ago(current_user.login_date),
    }
    if not profile_form.validate():
        error("Unable to validate form")
        return ViewController(view, **context).load()
    try:
        existing = users.get_value_by_attr("name", profile_form.username.data)
        if existing and existing.id != current_user.id:
            profile_form.username.errors.append("Username already in use")
            return ViewController(view, **context).load()
        current_user.name = profile_form.username.data
        config_manager.save_credentials()
        context["success"] = True
        context["success_details"] = "Profile updated!"
    except Exception as e:
        context["error"] = True
        context["error_details"] = e
    return ViewController(view, **context).load()


def password_reset():
    view = "web/profile.html"
    from arpvpn.web.forms import PasswordResetForm, ProfileForm
    profile_form = ProfileForm()
    profile_form.username.data = current_user.name
    password_reset_form = PasswordResetForm(request.form)
    context = {
        "title": "Profile",
        "profile_form": profile_form,
        "password_reset_form": password_reset_form,
        "login_ago": get_time_ago(current_user.login_date),
    }
    if not password_reset_form.validate():
        error("Unable to validate form")
        return ViewController(view, **context).load()
    try:
        current_user.password = password_reset_form.new_password.data
        config_manager.save_credentials()
        context["success"] = True
        context["success_details"] = "Password updated!"
    except Exception as e:
        context["error"] = True
        context["error_details"] = e
    return ViewController(view, **context).load()


@router.app_errorhandler(BAD_REQUEST)
def bad_request(err):
    error_code = int(BAD_REQUEST)
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": str(err).split(":", 1)[1]
    }
    return ViewController("error/error-main.html", **context).load(), error_code


@router.app_errorhandler(UNAUTHORIZED)
def unauthorized(err):
    warning(f"Unauthorized request from {request.remote_addr}!")
    if request.method == "GET":
        debug(f"Redirecting to login...")
        try:
            next_url = url_for(request.endpoint)
        except Exception:
            uuid = request.path.rsplit("/", 1)[-1]
            next_url = url_for(request.endpoint, uuid=uuid)
        return redirect(url_for("router.login", next=next_url))
    error_code = int(UNAUTHORIZED)
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": str(err).split(":", 1)[1]
    }
    return ViewController("error/error-main.html", **context).load(), error_code


@router.app_errorhandler(FORBIDDEN)
def forbidden(err):
    error_code = int(FORBIDDEN)
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": str(err).split(":", 1)[1]
    }
    return ViewController("error/error-main.html", **context).load(), error_code


@router.app_errorhandler(NOT_FOUND)
def not_found(err):
    error_code = int(NOT_FOUND)
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": str(err).split(":", 1)[1],
        "image": "/static/assets/img/error-404-monochrome.svg"
    }
    return ViewController("error/error-img.html", **context).load(), error_code


@router.app_errorhandler(INTERNAL_SERVER_ERROR)
def not_found(err):
    error_code = int(INTERNAL_SERVER_ERROR)
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": str(err).split(":", 1)[1]
    }
    return ViewController("error/error-main.html", **context).load(), error_code
