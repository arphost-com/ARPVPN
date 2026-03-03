import csv
import copy
import io
import json
import os
import re
import secrets
import subprocess
from collections import deque
from datetime import datetime, timezone
from functools import wraps
from http.client import BAD_REQUEST, NOT_FOUND, INTERNAL_SERVER_ERROR, UNAUTHORIZED, NO_CONTENT, FORBIDDEN
from ipaddress import IPv4Address
from logging import warning, debug, error, info
from time import sleep
from typing import List, Dict, Any, Union, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from flask import Blueprint, abort, request, Response, redirect, url_for, jsonify, session, g, current_app
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
from arpvpn.core.mesh import MeshTopology, VPNLink, RouteAdvertisement, AccessPolicy
from arpvpn.core.managers.config import config_manager
from arpvpn.core.managers.tls import tls_manager
from arpvpn.core.models import interfaces, Interface, get_all_peers, Peer
from arpvpn.core.utils.wireguard import is_wg_iface_up
from arpvpn.web.client import clients, Client
from arpvpn.web.controllers.RestController import RestController
from arpvpn.web.controllers.ViewController import ViewController
from arpvpn.web.security_api import ApiTokenStore, SlidingWindowRateLimiter, AuthLockoutManager
from arpvpn.web.static.assets.resources import EMPTY_FIELD, APP_NAME
from arpvpn.web.validators import is_valid_tls_server_name

ACTIVE_PEER_MAX_AGE_SECONDS = 180
STALE_PEER_MAX_AGE_SECONDS = 1800
ALLOWED_NEXT_ENDPOINTS = {
    "/": "router.index",
    "/dashboard": "router.index",
    "/statistics": "router.statistics",
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
RRD_GRAPH_WINDOWS_SECONDS = {
    "6h": 6 * 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
    "30d": 30 * 24 * 60 * 60,
}
TRAFFIC_ROLLUP_WINDOWS_SECONDS = {
    "hour": 60 * 60,
    "day": 24 * 60 * 60,
    "week": 7 * 24 * 60 * 60,
    "month": 30 * 24 * 60 * 60,
}
RRD_STEP_SECONDS = 60
THEME_CHOICES = ("auto", "light", "dark")
THEME_COOKIE_NAME = "arpvpn_theme"
THEME_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365
MAX_HISTORY_POINTS = 5000
API_AUTH_ACCESS_TTL_SECONDS = get_env_int("ARPVPN_API_ACCESS_TTL_SECONDS", 15 * 60)
API_AUTH_REFRESH_TTL_SECONDS = get_env_int("ARPVPN_API_REFRESH_TTL_SECONDS", 24 * 60 * 60)
API_AUTH_RATE_WINDOW_SECONDS = get_env_int("ARPVPN_API_AUTH_WINDOW_SECONDS", 60)
API_AUTH_MAX_ATTEMPTS = get_env_int("ARPVPN_API_AUTH_MAX_ATTEMPTS", 8)
API_AUTH_LOCKOUT_SECONDS = get_env_int("ARPVPN_API_AUTH_LOCKOUT_SECONDS", 300)
API_RATE_LIMIT_WINDOW_SECONDS = get_env_int("ARPVPN_API_RATE_LIMIT_WINDOW_SECONDS", 60)
API_RATE_LIMIT_MAX_REQUESTS = get_env_int("ARPVPN_API_RATE_LIMIT_MAX_REQUESTS", 120)
API_AUTH_SCOPE_ALL = "all"
API_AUTH_SCOPE_STAFF = "staff"
API_AUTH_SCOPE_CLIENT = "client"
API_AUTH_SCOPES = (API_AUTH_SCOPE_ALL, API_AUTH_SCOPE_STAFF, API_AUTH_SCOPE_CLIENT)
API_AUTH_PUBLIC_ENDPOINTS = {
    "router.api_auth_issue_token",
    "router.api_auth_refresh_token",
}
BENIGN_LOG_ISSUE_PATTERNS = (
    "failed to run 'ip a | grep -w",
    "already down.",
    "csrf validation failed on login; not counting toward lockout.",
)
api_token_store = ApiTokenStore(web_config.secret_key)
api_rate_limiter = SlidingWindowRateLimiter()
api_auth_lockouts = AuthLockoutManager()


def is_safe_redirect_url(url: str) -> bool:
    """
    Validate that a URL is safe for redirect (prevents open redirect vulnerabilities).
    Only allows relative URLs with no scheme or netloc.
    """
    if not url:
        return False
    parsed = urlparse(url)
    return url.startswith("/") and not url.startswith("//") and not parsed.scheme and not parsed.netloc


def normalize_theme_choice(value: Optional[str]) -> str:
    if not value:
        return "auto"
    choice = value.strip().lower()
    if choice not in THEME_CHOICES:
        return "auto"
    return choice


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

    rrd_match = re.fullmatch(r"/traffic/rrd/([a-f0-9]{32})", path)
    if rrd_match:
        return "router.connection_rrd_graph", {"uuid": rrd_match.group(1)}

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


def is_api_request() -> bool:
    return request.path.startswith("/api/")


def current_scope_label() -> str:
    return "staff" if current_user.has_role(*STAFF_ROLES) else "client"


def should_use_secure_cookie() -> bool:
    configured_secure = bool(current_app.config.get("SESSION_COOKIE_SECURE", False))
    return configured_secure or bool(web_config.strict_https_mode)


def ensure_request_id() -> str:
    request_id = request.headers.get("X-Request-ID", "").strip()
    if not request_id:
        request_id = secrets.token_hex(16)
    g.request_id = request_id
    return request_id


def get_request_id() -> str:
    request_id = getattr(g, "request_id", None)
    if request_id:
        return request_id
    return ensure_request_id()


@router.before_request
def assign_request_id():
    ensure_request_id()


@router.after_request
def apply_request_id_header(response: Response):
    response.headers["X-Request-ID"] = get_request_id()
    return response


def get_request_ip() -> str:
    return str(request.remote_addr or "unknown")


def get_request_user_agent() -> str:
    user_agent = request.headers.get("User-Agent", "")
    return str(user_agent or "").strip()


def extract_bearer_token() -> Optional[str]:
    auth_header = str(request.headers.get("Authorization", "") or "").strip()
    if not auth_header:
        return None
    if not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    return token or None


def current_actor() -> Optional[User]:
    actor = getattr(g, "api_actor_user", None)
    if actor:
        return actor
    if current_user and current_user.is_authenticated:
        return current_user
    return None


def current_actor_role() -> Optional[str]:
    actor = current_actor()
    if not actor:
        return None
    return getattr(actor, "role", None)


def normalize_auth_scope(value: Any) -> str:
    scope = str(value or "").strip().lower()
    if scope not in API_AUTH_SCOPES:
        return API_AUTH_SCOPE_ALL
    return scope


def role_allowed_in_scope(role: str, scope: str) -> bool:
    if scope == API_AUTH_SCOPE_ALL:
        return True
    if scope == API_AUTH_SCOPE_STAFF:
        return role in STAFF_ROLES
    if scope == API_AUTH_SCOPE_CLIENT:
        return role == User.ROLE_CLIENT
    return False


def build_rbac_matrix() -> Dict[str, Dict[str, bool]]:
    return {
        "super_admin": {
            "maps_to_role": User.ROLE_ADMIN,
            "impersonate_clients": True,
            "manage_users": True,
            "manage_tls": True,
            "manage_mesh": True,
        },
        "support_admin": {
            "maps_to_role": User.ROLE_SUPPORT,
            "impersonate_clients": True,
            "manage_users": True,
            "manage_tls": True,
            "manage_mesh": True,
        },
        "tenant_admin": {
            "maps_to_role": User.ROLE_SUPPORT,
            "impersonate_clients": True,
            "manage_users": True,
            "manage_tls": True,
            "manage_mesh": True,
        },
        "client": {
            "maps_to_role": User.ROLE_CLIENT,
            "impersonate_clients": False,
            "manage_users": False,
            "manage_tls": False,
            "manage_mesh": False,
        },
    }


def log_audit_event(action: str, status: str = "success", details: Optional[Dict[str, Any]] = None):
    actor = current_actor()
    payload: Dict[str, Any] = {
        "request_id": get_request_id(),
        "action": action,
        "status": status,
        "actor_id": actor.id if actor else None,
        "actor_name": actor.name if actor else None,
        "actor_role": actor.role if actor else None,
        "ip": get_request_ip(),
        "path": request.path,
    }
    if details:
        payload["details"] = details
    info(f"[AUDIT] {json.dumps(payload, sort_keys=True)}")


def apply_api_rate_limit_or_abort(bucket: str, max_requests: int, window_seconds: int):
    key = f"{bucket}:{get_request_ip()}"
    allowed, retry_after = api_rate_limiter.allow(key, max_requests=max_requests, window_seconds=window_seconds)
    if allowed:
        return
    abort(429, f"Rate limit exceeded. Retry in {retry_after} second(s).")


def parse_auth_token_payload() -> Dict[str, Any]:
    payload = parse_json_payload()
    username = str(payload.get("username", "") or "").strip()
    password = str(payload.get("password", "") or "")
    scope = normalize_auth_scope(payload.get("scope"))
    if not username:
        abort(BAD_REQUEST, "username is required.")
    if not password:
        abort(BAD_REQUEST, "password is required.")
    return {
        "username": username,
        "password": password,
        "scope": scope,
    }


def build_token_response_payload(token_pair: Dict[str, Any], scope: str) -> Dict[str, Any]:
    access = token_pair["access"]
    refresh = token_pair["refresh"]
    return {
        "token_type": "Bearer",
        "scope": scope,
        "access_token": access["raw_token"],
        "access_token_id": access["token_id"],
        "access_expires_at": access["expires_at"].isoformat().replace("+00:00", "Z"),
        "access_expires_in": access["expires_in"],
        "refresh_token": refresh["raw_token"],
        "refresh_token_id": refresh["token_id"],
        "refresh_expires_at": refresh["expires_at"].isoformat().replace("+00:00", "Z"),
        "refresh_expires_in": refresh["expires_in"],
    }


def get_refresh_token_from_request() -> str:
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        raw = payload.get("refresh_token", "")
        candidate = str(raw or "").strip()
        if candidate:
            return candidate
    bearer = extract_bearer_token()
    if bearer:
        return bearer
    abort(BAD_REQUEST, "refresh_token is required.")


def get_revoke_token_from_request() -> Optional[str]:
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        raw = payload.get("token", "")
        candidate = str(raw or "").strip()
        if candidate:
            return candidate
    return extract_bearer_token()


def resolve_api_actor_user_from_token(token_value: str) -> Optional[User]:
    if not token_value:
        return None
    token_record = api_token_store.validate_access_token(token_value)
    if not token_record:
        return None
    user = users.get(token_record.user_id, None)
    if not user:
        return None
    user.set_authenticated(True)
    g.api_token_id = token_record.token_id
    g.api_actor_user = user
    login_user(user, remember=False, force=True)
    return user


@router.before_request
def refresh_api_token_signing_key():
    api_token_store.set_signing_key(web_config.secret_key)


@router.before_request
def enforce_forced_logout_state():
    actor = current_actor()
    if not actor:
        return None
    revoked_after = api_token_store.get_user_revocation_cutoff(actor.id)
    if not revoked_after:
        return None
    login_date = getattr(actor, "login_date", None)
    if login_date is not None:
        if login_date.tzinfo is None:
            login_date = login_date.replace(tzinfo=timezone.utc)
        if login_date > revoked_after:
            return None
    if request.endpoint in API_AUTH_PUBLIC_ENDPOINTS:
        return None
    log_audit_event(
        "auth.forced_logout.enforced",
        status="success",
        details={
            "target_user_id": actor.id,
            "revoked_after": revoked_after.isoformat().replace("+00:00", "Z"),
        }
    )
    session.pop(IMPERSONATOR_SESSION_KEY, None)
    actor.logout()
    if is_api_request():
        return api_error(UNAUTHORIZED, "forced_logout", "User session has been revoked by an administrator.")
    return redirect(url_for("router.login"))


@router.before_request
def authenticate_api_bearer_token():
    if not is_api_request():
        return None
    if request.endpoint in API_AUTH_PUBLIC_ENDPOINTS:
        return None
    token_value = extract_bearer_token()
    if token_value:
        actor = resolve_api_actor_user_from_token(token_value)
        if actor:
            return None
        return api_error(UNAUTHORIZED, "invalid_token", "Invalid or expired access token.")
    if current_user and current_user.is_authenticated:
        g.api_actor_user = current_user
        return None
    return None


def api_success(
    data: Any,
    status_code: int = 200,
    meta: Optional[Dict[str, Any]] = None
) -> Tuple[Response, int]:
    payload: Dict[str, Any] = {
        "ok": True,
        "request_id": get_request_id(),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "data": data,
    }
    if meta:
        payload["meta"] = meta
    return jsonify(payload), status_code


def api_error(
    status_code: int,
    code: str,
    message: str,
    details: Optional[Dict[str, Any]] = None
) -> Tuple[Response, int]:
    payload: Dict[str, Any] = {
        "ok": False,
        "request_id": get_request_id(),
        "error": {
            "code": code,
            "message": message,
        },
    }
    if details:
        payload["error"]["details"] = details
    return jsonify(payload), status_code


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
    peer_runtime = filter_peer_runtime_for_current_user(get_peer_runtime_summary())
    visible_interfaces = get_visible_interfaces_for_current_user()
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
    for iface in visible_interfaces.values():
        iface_names.append(iface.name)
        iface_traffic = __get_total_traffic__(iface.uuid, traffic)
        ifaces_traffic[0]["data"].append(iface_traffic.rx)
        ifaces_traffic[1]["data"].append(iface_traffic.tx)
        for peer in iface.peers.values():
            peer_names.append(peer.name)
            peer_traffic = __get_total_traffic__(peer.uuid, traffic)
            peers_traffic[0]["data"].append(peer_traffic.rx)
            peers_traffic[1]["data"].append(peer_traffic.tx)

    interface_statuses = [iface.status for iface in visible_interfaces.values()]
    interface_totals = {
        "total": len(visible_interfaces),
        "up": interface_statuses.count("up"),
        "down": interface_statuses.count("down")
    }

    context = {
        "title": "Dashboard",
        "interfaces_chart": {"labels": iface_names, "datasets": ifaces_traffic},
        "peers_chart": {"labels": peer_names, "datasets": peers_traffic},
        "interfaces": visible_interfaces,
        "interface_totals": interface_totals,
        "peer_runtime": peer_runtime,
        "top_peers": peer_runtime["rows"][:10],
        "last_update": datetime.now().strftime("%H:%M"),
        "EMPTY_FIELD": EMPTY_FIELD,
        "traffic_config": traffic_config
    }
    return ViewController("web/index.html", **context).load()


def build_statistics_rows(
        visible_interfaces: Dict[str, Interface],
        peer_runtime: Dict[str, Any],
        traffic: Dict[datetime, Dict[str, TrafficData]],
        sample_counts: Dict[str, int]
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for iface in visible_interfaces.values():
        iface_traffic = __get_total_traffic__(iface.uuid, traffic)
        rows.append({
            "type": "interface",
            "type_label": "Interface",
            "uuid": iface.uuid,
            "name": iface.name,
            "parent_name": EMPTY_FIELD,
            "status": iface.status,
            "session_rx_human": to_human_filesize(iface_traffic.rx),
            "session_tx_human": to_human_filesize(iface_traffic.tx),
            "session_total_human": to_human_filesize(iface_traffic.rx + iface_traffic.tx),
            "sample_points": sample_counts.get(iface.uuid, 0),
        })

    for peer in peer_runtime["rows"]:
        rows.append({
            "type": "peer",
            "type_label": "Peer",
            "uuid": peer["peer_uuid"],
            "name": peer["peer_name"],
            "parent_name": peer["interface_name"],
            "status": peer["handshake_state"],
            "session_rx_human": peer["session_rx_human"],
            "session_tx_human": peer["session_tx_human"],
            "session_total_human": peer["session_total_human"],
            "sample_points": sample_counts.get(peer["peer_uuid"], 0),
        })
    rows.sort(key=lambda item: (item["type"], item["name"].lower()))
    return rows


def load_traffic_history_data(include_session: bool = True) -> Dict[datetime, Dict[str, TrafficData]]:
    try:
        if include_session:
            if traffic_config.enabled:
                return traffic_config.driver.get_session_and_stored_data()
            return {datetime.now(): traffic_config.driver.get_session_data()}
        return traffic_config.driver.load_data()
    except Exception as e:
        log_exception(e)
        return {}


def get_connection_history_map() -> Dict[str, List[Tuple[int, int, int]]]:
    history_by_uuid: Dict[str, List[Tuple[int, int, int]]] = {}
    history = load_traffic_history_data(include_session=True)
    if not history:
        return history_by_uuid

    for timestamp, traffic_data in sorted(history.items(), key=lambda pair: pair[0]):
        unix_ts = int(timestamp.timestamp())
        for device_uuid, sample in traffic_data.items():
            points = history_by_uuid.setdefault(device_uuid, [])
            if points and points[-1][0] == unix_ts:
                points[-1] = (unix_ts, sample.rx, sample.tx)
            else:
                points.append((unix_ts, sample.rx, sample.tx))
    return history_by_uuid


def compute_rollup_window(points: List[Tuple[int, int, int]], window_seconds: int) -> Dict[str, Any]:
    if not points:
        return {
            "rx_bytes": 0,
            "tx_bytes": 0,
            "total_bytes": 0,
            "rx_human": to_human_filesize(0),
            "tx_human": to_human_filesize(0),
            "total_human": to_human_filesize(0),
        }

    latest_ts, latest_rx, latest_tx = points[-1]
    start_ts = latest_ts - window_seconds
    baseline_rx = points[0][1]
    baseline_tx = points[0][2]
    for ts, rx_value, tx_value in points:
        if ts <= start_ts:
            baseline_rx = rx_value
            baseline_tx = tx_value
            continue
        break

    rx_delta = max(latest_rx - baseline_rx, 0)
    tx_delta = max(latest_tx - baseline_tx, 0)
    total_delta = rx_delta + tx_delta
    return {
        "rx_bytes": rx_delta,
        "tx_bytes": tx_delta,
        "total_bytes": total_delta,
        "rx_human": to_human_filesize(rx_delta),
        "tx_human": to_human_filesize(tx_delta),
        "total_human": to_human_filesize(total_delta),
    }


def build_connection_rollups(
        statistics_rows: List[Dict[str, Any]],
        history_by_uuid: Dict[str, List[Tuple[int, int, int]]]
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for row in statistics_rows:
        points = history_by_uuid.get(row["uuid"], [])
        windows: Dict[str, Dict[str, Any]] = {}
        for window_name, seconds in TRAFFIC_ROLLUP_WINDOWS_SECONDS.items():
            windows[window_name] = compute_rollup_window(points, seconds)
        rows.append({
            "uuid": row["uuid"],
            "type": row["type"],
            "type_label": row["type_label"],
            "name": row["name"],
            "parent_name": row["parent_name"],
            "status": row["status"],
            "sample_points": row["sample_points"],
            "windows": windows,
        })
    return rows


def summarize_rollups(rollup_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    totals: Dict[str, Dict[str, Any]] = {}
    for window_name in TRAFFIC_ROLLUP_WINDOWS_SECONDS.keys():
        totals[window_name] = {"rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0}
    for row in rollup_rows:
        for window_name, values in row["windows"].items():
            totals[window_name]["rx_bytes"] += values["rx_bytes"]
            totals[window_name]["tx_bytes"] += values["tx_bytes"]
            totals[window_name]["total_bytes"] += values["total_bytes"]
    for window_name, values in totals.items():
        values["rx_human"] = to_human_filesize(values["rx_bytes"])
        values["tx_human"] = to_human_filesize(values["tx_bytes"])
        values["total_human"] = to_human_filesize(values["total_bytes"])
    return totals


def get_failure_metrics(max_tail_lines: int = 5000) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {
        "auth_failures": 0,
        "interface_failures": 0,
        "tls_failures": 0,
        "rrd_failures": 0,
        "active_login_bans": 0,
        "inspected_log_lines": 0,
        "log_available": False,
        "total": 0,
    }

    metrics["active_login_bans"] = sum(1 for client in clients.values() if client.is_banned())
    logfile = logger_config.logfile
    if not os.path.exists(logfile):
        metrics["total"] = metrics["active_login_bans"]
        return metrics

    tail: deque[str] = deque(maxlen=max_tail_lines)
    try:
        with open(logfile, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                entry = line.strip()
                if not entry:
                    continue
                tail.append(entry)
    except OSError:
        metrics["total"] = metrics["active_login_bans"]
        return metrics

    auth_patterns = (
        "login_post): unable to validate form",
        "unable to log in",
        "unable to validate field 'password'",
        "unable to validate field 'username'",
    )
    interface_patterns = (
        "failed to start interface",
        "failed to stop interface",
        "invalid operation:",
    )
    tls_patterns = (
        "unable to issue let's encrypt certificate",
        "unable to generate self-signed certificate",
        "tls mode requires certificate",
        "let's encrypt certificate was issued but expected files were not found",
    )
    rrd_patterns = (
        "unable to create rrd file",
        "unable to update rrd data",
        "unable to generate rrd graph",
    )

    for entry in tail:
        lowered = entry.lower()
        if any(pattern in lowered for pattern in auth_patterns):
            metrics["auth_failures"] += 1
        if any(pattern in lowered for pattern in interface_patterns):
            metrics["interface_failures"] += 1
        if any(pattern in lowered for pattern in tls_patterns):
            metrics["tls_failures"] += 1
        if any(pattern in lowered for pattern in rrd_patterns):
            metrics["rrd_failures"] += 1

    metrics["inspected_log_lines"] = len(tail)
    metrics["log_available"] = True
    metrics["total"] = (
        metrics["auth_failures"] +
        metrics["interface_failures"] +
        metrics["tls_failures"] +
        metrics["rrd_failures"] +
        metrics["active_login_bans"]
    )
    return metrics


def build_statistics_payload(include_log_issues: bool = False) -> Dict[str, Any]:
    if traffic_config.enabled:
        traffic = traffic_config.driver.get_session_and_stored_data()
    else:
        traffic = {datetime.now(): traffic_config.driver.get_session_data()}
    peer_runtime = filter_peer_runtime_for_current_user(get_peer_runtime_summary())
    visible_interfaces = get_visible_interfaces_for_current_user()
    sample_counts = get_connection_sample_counts()
    statistics_rows = build_statistics_rows(visible_interfaces, peer_runtime, traffic, sample_counts)
    history_by_uuid = get_connection_history_map()
    rollup_rows = build_connection_rollups(statistics_rows, history_by_uuid)
    rollup_totals = summarize_rollups(rollup_rows)
    rollup_index = {row["uuid"]: row["windows"] for row in rollup_rows}
    log_summary = get_log_summary(include_recent_issues=include_log_issues)
    failure_metrics = get_failure_metrics()

    peer_totals = peer_runtime["totals"]
    handshake_failures = peer_totals["stale_peers"] + peer_totals["offline_peers"] + peer_totals["never_seen_peers"]
    failure_count = handshake_failures + failure_metrics["total"]
    rrd_ready_count = len([row for row in statistics_rows if row["sample_points"] > 0])

    return {
        "statistics_rows": statistics_rows,
        "peer_runtime": peer_runtime,
        "rollup_rows": rollup_rows,
        "rollup_totals": rollup_totals,
        "rollup_index": rollup_index,
        "window_options": sorted(
            RRD_GRAPH_WINDOWS_SECONDS.keys(),
            key=lambda key: RRD_GRAPH_WINDOWS_SECONDS[key]
        ),
        "default_window": "24h",
        "connections_total": len(statistics_rows),
        "rrd_ready_count": rrd_ready_count,
        "failure_count": failure_count,
        "handshake_failures": handshake_failures,
        "log_summary": log_summary,
        "failure_metrics": failure_metrics,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope": "staff" if current_user.has_role(*STAFF_ROLES) else "client",
    }


@router.route("/statistics", methods=["GET"])
@login_required
@setup_required
def statistics():
    is_staff_view = current_user.has_role(*STAFF_ROLES)
    payload = build_statistics_payload(include_log_issues=is_staff_view)
    context = {
        "title": "Statistics",
        "statistics_rows": payload["statistics_rows"],
        "peer_runtime": payload["peer_runtime"],
        "window_options": payload["window_options"],
        "default_window": payload["default_window"],
        "connections_total": payload["connections_total"],
        "rrd_ready_count": payload["rrd_ready_count"],
        "failure_count": payload["failure_count"],
        "handshake_failures": payload["handshake_failures"],
        "rollup_index": payload["rollup_index"],
        "rollup_totals": payload["rollup_totals"],
        "failure_metrics": payload["failure_metrics"],
        "log_summary": payload["log_summary"],
        "is_staff_view": is_staff_view,
        "last_update": datetime.now().strftime("%H:%M"),
        "traffic_config": traffic_config
    }
    return ViewController("web/statistics.html", **context).load()


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


def calculate_interface_totals(visible_interfaces: Dict[str, Interface]) -> Dict[str, int]:
    statuses = [iface.status for iface in visible_interfaces.values()]
    return {
        "total": len(visible_interfaces),
        "up": statuses.count("up"),
        "down": statuses.count("down")
    }


def get_interface_totals() -> Dict[str, int]:
    return calculate_interface_totals(dict(interfaces.items()))


def get_visible_interface_totals_for_current_user() -> Dict[str, int]:
    return calculate_interface_totals(get_visible_interfaces_for_current_user())


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


def calculate_peer_runtime_totals(rows: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    totals = {
        "peers": len(rows),
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
    for row in rows:
        if row["mode"] == Peer.MODE_SITE_TO_SITE:
            totals["site_to_site_peers"] += 1
        else:
            totals["client_peers"] += 1
        if row["handshake_state"] == "active":
            totals["active_peers"] += 1
        elif row["handshake_state"] == "stale":
            totals["stale_peers"] += 1
        elif row["handshake_state"] == "offline":
            totals["offline_peers"] += 1
        else:
            totals["never_seen_peers"] += 1
        if row["high_traffic"]:
            totals["high_traffic_peers"] += 1
        totals["session_rx"] += row["session_rx"]
        totals["session_tx"] += row["session_tx"]
    totals["session_total"] = totals["session_rx"] + totals["session_tx"]
    totals["session_rx_human"] = to_human_filesize(totals["session_rx"])
    totals["session_tx_human"] = to_human_filesize(totals["session_tx"])
    totals["session_total_human"] = to_human_filesize(totals["session_total"])
    totals["alerts"] = len(alerts)
    return totals


def filter_peer_runtime_for_current_user(runtime: Dict[str, Any]) -> Dict[str, Any]:
    if current_user.has_role(*STAFF_ROLES):
        return runtime
    if not current_user.has_role(User.ROLE_CLIENT):
        return runtime
    client_name = current_user.name.lower()
    rows = [row for row in runtime["rows"] if row["peer_name"].lower() == client_name]
    alerts = [alert for alert in runtime["alerts"] if alert["peer_name"].lower() == client_name]
    return {
        "totals": calculate_peer_runtime_totals(rows, alerts),
        "rows": rows,
        "alerts": alerts,
        "thresholds": runtime["thresholds"]
    }


def get_visible_interfaces_for_current_user() -> Dict[str, Interface]:
    if current_user.has_role(*STAFF_ROLES):
        return dict(interfaces.items())
    if not current_user.has_role(User.ROLE_CLIENT):
        return {}
    visible: Dict[str, Interface] = {}
    client_name = current_user.name.lower()
    for iface in interfaces.values():
        visible_peers = [
            peer for peer in iface.peers.values()
            if peer.name.lower() == client_name
        ]
        if not visible_peers:
            continue
        iface_view = copy.copy(iface)
        iface_view.peers = iface.peers.__class__()
        for peer in visible_peers:
            iface_view.peers[peer.uuid] = peer
        iface_view.peers.sort()
        visible[iface.uuid] = iface_view
    return visible


def resolve_connection_item(uuid: str) -> Tuple[str, Union[Peer, Interface]]:
    peer = get_all_peers().get(uuid, None)
    if peer:
        return "peer", peer
    iface = interfaces.get(uuid, None)
    if iface:
        return "interface", iface
    abort(NOT_FOUND, "Connection not found.")


def user_can_access_connection(item_type: str, item: Union[Peer, Interface]) -> bool:
    if current_user.has_role(*STAFF_ROLES):
        return True
    if not current_user.has_role(User.ROLE_CLIENT):
        return False
    if item_type == "peer":
        return item.name.lower() == current_user.name.lower()
    return any(peer.name.lower() == current_user.name.lower() for peer in item.peers.values())


def get_connection_traffic_points(uuid: str) -> List[Tuple[int, int, int]]:
    points = []
    history = load_traffic_history_data(include_session=True)
    for timestamp, traffic_data in sorted(history.items(), key=lambda pair: pair[0]):
        sample = traffic_data.get(uuid, None)
        if not sample:
            continue
        unix_ts = int(timestamp.timestamp())
        if points and points[-1][0] == unix_ts:
            points[-1] = (unix_ts, sample.rx, sample.tx)
            continue
        points.append((unix_ts, sample.rx, sample.tx))
    return points


def get_connection_sample_counts() -> Dict[str, int]:
    counts: Dict[str, int] = {}
    history = load_traffic_history_data(include_session=True)
    if not history:
        return counts
    for _, traffic_data in sorted(history.items(), key=lambda pair: pair[0]):
        for device_uuid in traffic_data.keys():
            counts[device_uuid] = counts.get(device_uuid, 0) + 1
    return counts


def get_log_summary(max_tail_lines: int = 5000, include_recent_issues: bool = False) -> Dict[str, Any]:
    logfile = logger_config.logfile
    summary: Dict[str, Any] = {
        "available": False,
        "logfile": logfile,
        "total_lines": 0,
        "tail_lines": 0,
        "warning_lines": 0,
        "error_lines": 0,
        "suppressed_issue_lines": 0,
        "recent_issues": [],
        "read_error": None,
    }
    if not os.path.exists(logfile):
        return summary

    tail: deque[str] = deque(maxlen=max_tail_lines)
    try:
        with open(logfile, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                summary["total_lines"] += 1
                entry = line.strip()
                if not entry:
                    continue
                tail.append(entry)
    except OSError as e:
        summary["read_error"] = str(e)
        return summary

    issue_entries: List[str] = []
    for entry in tail:
        is_error = "[ERROR]" in entry or "[FATAL]" in entry
        is_warning = "[WARNING]" in entry
        if not is_error and not is_warning:
            continue

        lowered_entry = entry.lower()
        if any(pattern in lowered_entry for pattern in BENIGN_LOG_ISSUE_PATTERNS):
            summary["suppressed_issue_lines"] += 1
            continue

        if is_error:
            summary["error_lines"] += 1
        elif is_warning:
            summary["warning_lines"] += 1
        issue_entries.append(entry)
    summary["tail_lines"] = len(tail)
    if include_recent_issues:
        summary["recent_issues"] = list(reversed(issue_entries))[:8]
    summary["available"] = True
    return summary


def generate_rrd_graph_png(uuid: str, window_seconds: int) -> Optional[bytes]:
    points = get_connection_traffic_points(uuid)
    if len(points) < 1:
        return None

    graph_dir = global_properties.join_workdir("rrd_graphs")
    os.makedirs(graph_dir, exist_ok=True)
    token = secrets.token_hex(8)
    rrd_file = os.path.join(graph_dir, f"{uuid}-{window_seconds}-{token}.rrd")
    png_file = os.path.join(graph_dir, f"{uuid}-{window_seconds}-{token}.png")
    heartbeat = RRD_STEP_SECONDS * 2
    if len(points) > 1:
        deltas = [
            points[index][0] - points[index - 1][0]
            for index in range(1, len(points))
            if points[index][0] > points[index - 1][0]
        ]
        if deltas:
            max_gap_seconds = max(deltas)
            heartbeat = max(heartbeat, min(max_gap_seconds * 2, 24 * 60 * 60))

    try:
        create_cmd = [
            "rrdtool",
            "create",
            rrd_file,
            "--step",
            str(RRD_STEP_SECONDS),
            "--start",
            str(max(0, points[0][0] - RRD_STEP_SECONDS)),
            f"DS:rx:COUNTER:{heartbeat}:0:U",
            f"DS:tx:COUNTER:{heartbeat}:0:U",
            "RRA:AVERAGE:0.5:1:100000",
        ]
        created = subprocess.run(create_cmd, capture_output=True, text=True, check=False)
        if created.returncode != 0:
            err_detail = (created.stderr or created.stdout or "unknown rrdtool error").strip()
            raise RuntimeError(f"Unable to create RRD file: {err_detail}")

        for unix_ts, rx, tx in points:
            update = subprocess.run(
                ["rrdtool", "update", rrd_file, f"{unix_ts}:{rx}:{tx}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if update.returncode != 0:
                err_detail = (update.stderr or update.stdout or "unknown rrdtool error").strip()
                raise RuntimeError(f"Unable to update RRD data: {err_detail}")

        graph_cmd = [
            "rrdtool",
            "graph",
            png_file,
            "--start",
            f"end-{window_seconds}",
            "--end",
            "now",
            "--width",
            "960",
            "--height",
            "280",
            "--title",
            "Connection traffic rate",
            "--vertical-label",
            "Bytes/s",
            "--lower-limit",
            "0",
            f"DEF:rx={rrd_file}:rx:AVERAGE",
            f"DEF:tx={rrd_file}:tx:AVERAGE",
            "CDEF:rxs=rx,UN,0,rx,IF",
            "CDEF:txs=tx,UN,0,tx,IF",
            "LINE2:rxs#1f77b4:Received rate",
            "LINE2:txs#ff7f0e:Transmitted rate",
            r"GPRINT:rxs:LAST:Last RX/s\: %8.2lf%sB/s",
            r"GPRINT:txs:LAST:Last TX/s\: %8.2lf%sB/s",
            r"GPRINT:rxs:MAX:Max RX/s\: %8.2lf%sB/s",
            r"GPRINT:txs:MAX:Max TX/s\: %8.2lf%sB/s",
        ]
        graphed = subprocess.run(graph_cmd, capture_output=True, text=True, check=False)
        if graphed.returncode != 0:
            err_detail = (graphed.stderr or graphed.stdout or "unknown rrdtool error").strip()
            raise RuntimeError(f"Unable to generate RRD graph: {err_detail}")

        if not os.path.exists(png_file):
            raise RuntimeError("RRD graph generation finished without producing an image.")

        with open(png_file, "rb") as handle:
            return handle.read()
    finally:
        for file_path in (rrd_file, png_file):
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except OSError:
                pass


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


def get_scoped_peer_runtime_summary() -> Dict[str, Any]:
    return filter_peer_runtime_for_current_user(get_peer_runtime_summary())


def build_connection_descriptor(item_type: str, item: Union[Peer, Interface]) -> Dict[str, Any]:
    parent_name = EMPTY_FIELD
    if item_type == "peer" and item.interface:
        parent_name = item.interface.name
    return {
        "type": item_type,
        "uuid": item.uuid,
        "name": item.name,
        "parent_name": parent_name,
    }


def filter_points_for_window(points: List[Tuple[int, int, int]], requested_window: str) -> List[Tuple[int, int, int]]:
    if requested_window == "all" or not points:
        return points
    if requested_window not in RRD_GRAPH_WINDOWS_SECONDS:
        abort(BAD_REQUEST, "Unknown graph window.")
    latest_ts = points[-1][0]
    start_ts = latest_ts - RRD_GRAPH_WINDOWS_SECONDS[requested_window]
    return [point for point in points if point[0] >= start_ts]


def serialize_traffic_points(points: List[Tuple[int, int, int]]) -> List[Dict[str, Any]]:
    serialized: List[Dict[str, Any]] = []
    for unix_ts, rx_bytes, tx_bytes in points[-MAX_HISTORY_POINTS:]:
        total_bytes = rx_bytes + tx_bytes
        serialized.append({
            "timestamp_unix": unix_ts,
            "timestamp_iso": datetime.fromtimestamp(unix_ts, timezone.utc).isoformat().replace("+00:00", "Z"),
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "total_bytes": total_bytes,
            "total_human": to_human_filesize(total_bytes),
        })
    return serialized


def build_stats_snapshot() -> Dict[str, Any]:
    peer_runtime = get_scoped_peer_runtime_summary()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope": current_scope_label(),
        "interfaces": get_visible_interface_totals_for_current_user(),
        "peers": peer_runtime["totals"],
        "thresholds": peer_runtime["thresholds"],
        "alerts": peer_runtime["alerts"],
        "top_peers": [serialize_peer_runtime_row(row) for row in peer_runtime["rows"][:10]]
    }


def serialize_statistics_row(row: Dict[str, Any], rollup_index: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "type": row["type"],
        "type_label": row["type_label"],
        "uuid": row["uuid"],
        "name": row["name"],
        "parent_name": row["parent_name"],
        "status": row["status"],
        "sample_points": row["sample_points"],
        "session_rx_human": row["session_rx_human"],
        "session_tx_human": row["session_tx_human"],
        "session_total_human": row["session_total_human"],
        "rrd_page_url": url_for("router.connection_rrd_graph", uuid=row["uuid"]),
        "rrd_image_url": url_for("router.connection_rrd_graph_png", uuid=row["uuid"], window="24h"),
        "rollups": rollup_index.get(row["uuid"], {}),
    }


def flatten_rollup_rows_for_csv(rows: List[Dict[str, Any]], rollup_index: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    flattened: List[Dict[str, Any]] = []
    for row in rows:
        rollups = rollup_index.get(row["uuid"], {})
        item: Dict[str, Any] = {
            "type": row["type"],
            "type_label": row["type_label"],
            "uuid": row["uuid"],
            "name": row["name"],
            "parent_name": row["parent_name"],
            "status": row["status"],
            "sample_points": row["sample_points"],
            "session_rx_human": row["session_rx_human"],
            "session_tx_human": row["session_tx_human"],
            "session_total_human": row["session_total_human"],
        }
        for window_name in TRAFFIC_ROLLUP_WINDOWS_SECONDS.keys():
            rollup = rollups.get(window_name, {})
            item[f"{window_name}_rx_bytes"] = rollup.get("rx_bytes", 0)
            item[f"{window_name}_tx_bytes"] = rollup.get("tx_bytes", 0)
            item[f"{window_name}_total_bytes"] = rollup.get("total_bytes", 0)
            item[f"{window_name}_total_human"] = rollup.get("total_human", to_human_filesize(0))
        flattened.append(item)
    return flattened


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


def parse_openssl_time(raw_value: str) -> Optional[datetime]:
    value = (raw_value or "").strip()
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def read_certificate_metadata(cert_file: str, key_file: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "cert_file": cert_file,
        "key_file": key_file,
        "cert_exists": bool(cert_file) and os.path.exists(cert_file),
        "key_exists": bool(key_file) and os.path.exists(key_file),
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "sans": [],
        "read_error": None,
    }
    if not metadata["cert_exists"]:
        return metadata

    openssl_cmd = [
        "openssl",
        "x509",
        "-in",
        cert_file,
        "-noout",
        "-subject",
        "-issuer",
        "-startdate",
        "-enddate",
        "-ext",
        "subjectAltName",
    ]
    try:
        result = subprocess.run(openssl_cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        metadata["read_error"] = "openssl command not found."
        return metadata

    if result.returncode != 0:
        metadata["read_error"] = (result.stderr or result.stdout or "unknown openssl error").strip()
        return metadata

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("subject="):
            metadata["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            metadata["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            metadata["not_before"] = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            metadata["not_after"] = line.split("=", 1)[1].strip()
        elif "DNS:" in line:
            sans = [item.strip().replace("DNS:", "") for item in line.split(",") if "DNS:" in item]
            metadata["sans"] = [item for item in sans if item]

    expiry = parse_openssl_time(metadata["not_after"] or "")
    if expiry:
        metadata["not_after_iso"] = expiry.isoformat()
        metadata["days_remaining"] = int((expiry - datetime.now(timezone.utc)).total_seconds() // 86400)
    else:
        metadata["not_after_iso"] = None
    return metadata


def build_tls_status_payload() -> Dict[str, Any]:
    cert_metadata = read_certificate_metadata(web_config.tls_cert_file, web_config.tls_key_file)
    return {
        "scope": current_scope_label(),
        "mode": web_config.tls_mode,
        "available_modes": list(web_config.TLS_MODES),
        "server_name": web_config.tls_server_name,
        "letsencrypt_email": web_config.tls_letsencrypt_email,
        "redirect_http_to_https": web_config.redirect_http_to_https,
        "proxy_incoming_hostname": web_config.proxy_incoming_hostname,
        "http_port": web_config.http_port,
        "https_port": web_config.https_port,
        "strict_https_mode": web_config.strict_https_mode,
        "certificate": cert_metadata,
    }


def parse_json_payload() -> Dict[str, Any]:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(BAD_REQUEST, "Invalid payload.")
    return payload


def parse_tls_mode(mode_value: Any) -> str:
    mode = str(mode_value or "").strip()
    if not mode:
        abort(BAD_REQUEST, "TLS mode is required.")
    if mode not in web_config.TLS_MODES:
        abort(BAD_REQUEST, "Unknown TLS mode.")
    return mode


def parse_tls_server_name(
    value: Any,
    *,
    allow_ipv4: bool,
    allow_localhost: bool,
    field_name: str = "server_name",
) -> str:
    server_name = str(value or "").strip()
    if not server_name:
        abort(BAD_REQUEST, f"{field_name} is required.")
    if not is_valid_tls_server_name(server_name, allow_ipv4=allow_ipv4, allow_localhost=allow_localhost):
        if allow_ipv4:
            abort(
                BAD_REQUEST,
                f"{field_name} must be a valid IPv4 address or fully-qualified hostname "
                "(example: vpn.example.com).",
            )
        abort(BAD_REQUEST, f"{field_name} must be a fully-qualified hostname (example: vpn.example.com).")
    return server_name


def parse_json_bool(payload: Dict[str, Any], key: str, default: bool = False) -> bool:
    if key not in payload:
        return default
    value = payload.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("1", "true", "yes", "on"):
            return True
        if lowered in ("0", "false", "no", "off"):
            return False
    abort(BAD_REQUEST, f"Invalid boolean value for '{key}'.")


def parse_mesh_uuid(value: Any, field_name: str = "uuid") -> str:
    uuid = str(value or "").strip()
    if not uuid:
        abort(BAD_REQUEST, f"{field_name} is required.")
    return uuid


def parse_mesh_str(value: Any) -> str:
    return str(value or "").strip()


def sort_and_persist_mesh():
    wireguard_config.mesh.topologies.sort()
    wireguard_config.mesh.vpn_links.sort()
    wireguard_config.mesh.route_advertisements.sort()
    wireguard_config.mesh.access_policies.sort()
    config_manager.save(apply=False)


def mesh_control_plane_payload() -> Dict[str, Any]:
    mesh = wireguard_config.mesh
    return {
        "topologies": [topology.__to_yaml_dict__() for topology in mesh.topologies.values()],
        "vpn_links": [link.__to_yaml_dict__() for link in mesh.vpn_links.values()],
        "route_advertisements": [route.__to_yaml_dict__() for route in mesh.route_advertisements.values()],
        "access_policies": [policy.__to_yaml_dict__() for policy in mesh.access_policies.values()],
        "route_conflicts": mesh.validate_route_advertisements(),
    }


def validate_mesh_references(mesh_data) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    topology_ids = {item.uuid for item in mesh_data.topologies.values()}
    link_ids = {item.uuid for item in mesh_data.vpn_links.values()}

    for link in mesh_data.vpn_links.values():
        if link.topology_uuid and link.topology_uuid not in topology_ids:
            issues.append({
                "code": "missing_topology_reference",
                "message": f"vpn_link '{link.uuid}' references unknown topology '{link.topology_uuid}'.",
                "entity_uuid": link.uuid,
            })
        if not link.source_server or not link.target_server:
            issues.append({
                "code": "invalid_link_servers",
                "message": f"vpn_link '{link.uuid}' must include source_server and target_server.",
                "entity_uuid": link.uuid,
            })

    for route in mesh_data.route_advertisements.values():
        if route.via_link_uuid and route.via_link_uuid not in link_ids:
            issues.append({
                "code": "missing_link_reference",
                "message": f"route_advertisement '{route.uuid}' references unknown link '{route.via_link_uuid}'.",
                "entity_uuid": route.uuid,
            })
        if not route.owner_server:
            issues.append({
                "code": "missing_owner_server",
                "message": f"route_advertisement '{route.uuid}' is missing owner_server.",
                "entity_uuid": route.uuid,
            })

    for policy in mesh_data.access_policies.values():
        if not policy.destinations:
            issues.append({
                "code": "empty_policy_destinations",
                "message": f"access_policy '{policy.uuid}' has no destinations.",
                "entity_uuid": policy.uuid,
            })

    return issues


def build_mesh_from_payload(payload: Dict[str, Any]):
    topologies = payload.get("topologies", [])
    links = payload.get("vpn_links", [])
    routes = payload.get("route_advertisements", [])
    policies = payload.get("access_policies", [])
    if not isinstance(topologies, list):
        abort(BAD_REQUEST, "topologies must be a list.")
    if not isinstance(links, list):
        abort(BAD_REQUEST, "vpn_links must be a list.")
    if not isinstance(routes, list):
        abort(BAD_REQUEST, "route_advertisements must be a list.")
    if not isinstance(policies, list):
        abort(BAD_REQUEST, "access_policies must be a list.")

    mesh = wireguard_config.mesh.__class__()

    for item in topologies:
        if not isinstance(item, dict):
            abort(BAD_REQUEST, "Invalid topology entry.")
        topology = MeshTopology(
            uuid=parse_mesh_str(item.get("uuid")),
            name=parse_mesh_str(item.get("name")),
            preset=parse_mesh_str(item.get("preset")) or MeshTopology.PRESET_POINT_TO_POINT,
            server_ids=item.get("server_ids", []),
            hub_server_id=parse_mesh_str(item.get("hub_server_id")),
            description=parse_mesh_str(item.get("description")),
        )
        mesh.topologies[topology.uuid] = topology

    for item in links:
        if not isinstance(item, dict):
            abort(BAD_REQUEST, "Invalid vpn_link entry.")
        link = VPNLink(
            uuid=parse_mesh_str(item.get("uuid")),
            source_server=parse_mesh_str(item.get("source_server")),
            target_server=parse_mesh_str(item.get("target_server")),
            interface_uuid=parse_mesh_str(item.get("interface_uuid")),
            status=parse_mesh_str(item.get("status")) or VPNLink.STATUS_PENDING,
            key_metadata=item.get("key_metadata", {}),
            topology_uuid=parse_mesh_str(item.get("topology_uuid")),
            description=parse_mesh_str(item.get("description")),
            enabled=bool(item.get("enabled", True)),
        )
        mesh.vpn_links[link.uuid] = link

    for item in routes:
        if not isinstance(item, dict):
            abort(BAD_REQUEST, "Invalid route_advertisement entry.")
        route = RouteAdvertisement(
            uuid=parse_mesh_str(item.get("uuid")),
            owner_server=parse_mesh_str(item.get("owner_server")),
            cidr=parse_mesh_str(item.get("cidr")),
            via_link_uuid=parse_mesh_str(item.get("via_link_uuid")),
            description=parse_mesh_str(item.get("description")),
            enabled=bool(item.get("enabled", True)),
        )
        mesh.route_advertisements[route.uuid] = route

    for item in policies:
        if not isinstance(item, dict):
            abort(BAD_REQUEST, "Invalid access_policy entry.")
        policy = AccessPolicy(
            uuid=parse_mesh_str(item.get("uuid")),
            name=parse_mesh_str(item.get("name")),
            source_kind=parse_mesh_str(item.get("source_kind")) or AccessPolicy.SOURCE_PEER,
            source_id=parse_mesh_str(item.get("source_id")),
            destinations=item.get("destinations", []),
            action=parse_mesh_str(item.get("action")) or AccessPolicy.ACTION_ALLOW,
            priority=item.get("priority", AccessPolicy.DEFAULT_PRIORITY),
            description=parse_mesh_str(item.get("description")),
            enabled=bool(item.get("enabled", True)),
        )
        mesh.access_policies[policy.uuid] = policy

    mesh.topologies.sort()
    mesh.vpn_links.sort()
    mesh.route_advertisements.sort()
    mesh.access_policies.sort()
    return mesh


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


def is_csrf_only_login_failure(form: Any) -> bool:
    csrf_field = getattr(form, "csrf_token", None)
    csrf_errors = list(getattr(csrf_field, "errors", []) or [])
    if not csrf_errors:
        return False
    for field_name, errors in getattr(form, "errors", {}).items():
        if field_name == "csrf_token":
            continue
        if errors:
            return False
    return True


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
        if is_csrf_only_login_failure(form):
            warning("CSRF validation failed on login; not counting toward lockout.")
            return ViewController("web/login.html", **context).load()
        max_attempts = int(web_config.login_attempts)
        if max_attempts > 0:
            client.login_attempts += 1
            if client.login_attempts > max_attempts:
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


@router.route("/api/v1/auth/modes", methods=["GET"])
@setup_required
def api_auth_modes():
    return api_success({
        "cookie_session_auth": {
            "enabled": True,
            "description": "Browser session/cookie auth for UI and API calls from same-origin pages.",
        },
        "bearer_token_auth": {
            "enabled": True,
            "description": "Access/refresh token auth for API clients.",
            "access_ttl_seconds": API_AUTH_ACCESS_TTL_SECONDS,
            "refresh_ttl_seconds": API_AUTH_REFRESH_TTL_SECONDS,
        },
    })


@router.route("/api/v1/auth/rbac", methods=["GET"])
@login_required
@setup_required
def api_auth_rbac():
    return api_success({
        "scope": current_scope_label(),
        "matrix": build_rbac_matrix(),
    })


@router.route("/api/v1/auth/token", methods=["POST"])
@setup_required
def api_auth_issue_token():
    apply_api_rate_limit_or_abort(
        "api-auth-token",
        max_requests=API_RATE_LIMIT_MAX_REQUESTS,
        window_seconds=API_RATE_LIMIT_WINDOW_SECONDS,
    )
    payload = parse_auth_token_payload()
    username = payload["username"]
    scope = payload["scope"]
    lockout_key = f"{get_request_ip()}:{username.lower()}"
    locked, retry_after = api_auth_lockouts.is_locked(lockout_key)
    if locked:
        log_audit_event(
            "auth.token.issue",
            status="locked",
            details={"username": username, "retry_after_seconds": retry_after},
        )
        return api_error(
            429,
            "auth_locked",
            "Too many failed authentication attempts.",
            details={"retry_after_seconds": retry_after},
        )

    user = users.get_value_by_attr("name", username)
    if not user or not user.check_password(payload["password"]):
        remaining_attempts = api_auth_lockouts.register_failure(
            lockout_key,
            max_attempts=API_AUTH_MAX_ATTEMPTS,
            window_seconds=API_AUTH_RATE_WINDOW_SECONDS,
            lockout_seconds=API_AUTH_LOCKOUT_SECONDS,
        )
        log_audit_event(
            "auth.token.issue",
            status="failed",
            details={"username": username, "remaining_attempts": remaining_attempts},
        )
        return api_error(
            UNAUTHORIZED,
            "invalid_credentials",
            "Invalid username or password.",
            details={"remaining_attempts": remaining_attempts},
        )

    if not role_allowed_in_scope(user.role, scope):
        log_audit_event(
            "auth.token.issue",
            status="forbidden_scope",
            details={"username": username, "user_role": user.role, "requested_scope": scope},
        )
        return api_error(
            FORBIDDEN,
            "invalid_scope",
            f"Role '{user.role}' cannot request scope '{scope}'.",
        )

    api_auth_lockouts.clear_failures(lockout_key)
    token_pair = api_token_store.issue_pair(
        user_id=user.id,
        access_ttl_seconds=API_AUTH_ACCESS_TTL_SECONDS,
        refresh_ttl_seconds=API_AUTH_REFRESH_TTL_SECONDS,
        issued_ip=get_request_ip(),
        issued_user_agent=get_request_user_agent(),
    )
    log_audit_event(
        "auth.token.issue",
        status="success",
        details={
            "target_user_id": user.id,
            "target_user_name": user.name,
            "target_user_role": user.role,
            "scope": scope,
        },
    )
    return api_success(build_token_response_payload(token_pair, scope), status_code=201)


@router.route("/api/v1/auth/refresh", methods=["POST"])
@setup_required
def api_auth_refresh_token():
    apply_api_rate_limit_or_abort(
        "api-auth-refresh",
        max_requests=API_RATE_LIMIT_MAX_REQUESTS,
        window_seconds=API_RATE_LIMIT_WINDOW_SECONDS,
    )
    refresh_token = get_refresh_token_from_request()
    record = api_token_store.validate_refresh_token(refresh_token)
    if not record:
        log_audit_event("auth.token.refresh", status="failed")
        return api_error(UNAUTHORIZED, "invalid_refresh_token", "Invalid or expired refresh token.")

    user = users.get(record.user_id, None)
    if not user:
        return api_error(UNAUTHORIZED, "user_not_found", "Refresh token user no longer exists.")

    api_token_store.revoke_token(refresh_token)
    scope = API_AUTH_SCOPE_STAFF if user.has_role(*STAFF_ROLES) else API_AUTH_SCOPE_CLIENT
    token_pair = api_token_store.issue_pair(
        user_id=user.id,
        access_ttl_seconds=API_AUTH_ACCESS_TTL_SECONDS,
        refresh_ttl_seconds=API_AUTH_REFRESH_TTL_SECONDS,
        issued_ip=get_request_ip(),
        issued_user_agent=get_request_user_agent(),
    )
    log_audit_event(
        "auth.token.refresh",
        status="success",
        details={"target_user_id": user.id, "scope": scope},
    )
    return api_success(build_token_response_payload(token_pair, scope))


@router.route("/api/v1/auth/revoke", methods=["POST"])
@login_required
@setup_required
def api_auth_revoke_token():
    target_token = get_revoke_token_from_request()
    if not target_token:
        return api_error(BAD_REQUEST, "token_required", "No token was provided for revocation.")

    record = api_token_store.inspect_token(target_token)
    if not record:
        return api_error(NOT_FOUND, "token_not_found", "Token was not found or already revoked.")
    actor = current_actor()
    if not actor:
        abort(UNAUTHORIZED)
    if record.user_id != actor.id and not actor.has_role(*STAFF_ROLES):
        abort(FORBIDDEN, "Insufficient permissions.")

    if not api_token_store.revoke_token(target_token):
        return api_error(NOT_FOUND, "token_not_found", "Token was not found or already revoked.")

    log_audit_event(
        "auth.token.revoke",
        status="success",
        details={"revoked_token_id": record.token_id, "target_user_id": record.user_id},
    )
    return api_success({"revoked": True})


@router.route("/api/v1/auth/revoke-all", methods=["POST"])
@login_required
@setup_required
def api_auth_revoke_all_tokens():
    payload = request.get_json(silent=True) or {}
    target_user_id = str(payload.get("user_id", "") or "").strip()
    actor = current_actor()
    if not actor:
        abort(UNAUTHORIZED)
    if target_user_id and target_user_id != actor.id and not actor.has_role(*STAFF_ROLES):
        abort(FORBIDDEN, "Insufficient permissions.")
    if not target_user_id:
        target_user_id = actor.id
    revoked = api_token_store.revoke_user_tokens(target_user_id)
    log_audit_event(
        "auth.token.revoke_all",
        status="success",
        details={"target_user_id": target_user_id, "revoked_tokens": revoked},
    )
    return api_success({
        "target_user_id": target_user_id,
        "revoked_tokens": revoked,
    })


@router.route("/api/v1/auth/force-logout/<user_id>", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_auth_force_logout(user_id: str):
    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    revoked_tokens = api_token_store.revoke_user_tokens(target_user.id)
    api_token_store.mark_user_forced_logout(target_user.id)
    target_user.set_authenticated(False)
    log_audit_event(
        "auth.force_logout",
        status="success",
        details={"target_user_id": target_user.id, "revoked_tokens": revoked_tokens},
    )
    return api_success({
        "target_user_id": target_user.id,
        "revoked_tokens": revoked_tokens,
        "forced_logout": True,
    })


@router.route("/api/v1/impersonation/start/<user_id>", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_start_impersonation(user_id: str):
    if is_impersonating():
        abort(BAD_REQUEST, "Already impersonating a user.")
    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    if target_user.role != User.ROLE_CLIENT:
        abort(BAD_REQUEST, "Only client users can be impersonated.")
    actor = current_actor()
    if actor and target_user.id == actor.id:
        abort(BAD_REQUEST, "Cannot impersonate your own account.")
    session[IMPERSONATOR_SESSION_KEY] = actor.id if actor else ""
    target_user.set_authenticated(True)
    if not login_user(target_user, remember=False):
        abort(INTERNAL_SERVER_ERROR, "Unable to impersonate target user.")
    g.api_actor_user = target_user
    log_audit_event(
        "impersonation.start",
        status="success",
        details={"target_user_id": target_user.id, "target_user_name": target_user.name},
    )
    return api_success({
        "impersonating": True,
        "target_user_id": target_user.id,
        "target_user_name": target_user.name,
    })


@router.route("/api/v1/impersonation/stop", methods=["POST"])
@login_required
@setup_required
def api_stop_impersonation():
    impersonator = get_impersonator_user()
    if not impersonator:
        abort(BAD_REQUEST, "No active impersonation session.")
    session.pop(IMPERSONATOR_SESSION_KEY, None)
    impersonator.set_authenticated(True)
    if not login_user(impersonator, remember=False):
        abort(INTERNAL_SERVER_ERROR, "Unable to restore original user.")
    g.api_actor_user = impersonator
    log_audit_event(
        "impersonation.stop",
        status="success",
        details={"restored_user_id": impersonator.id, "restored_user_name": impersonator.name},
    )
    return api_success({
        "impersonating": False,
        "restored_user_id": impersonator.id,
        "restored_user_name": impersonator.name,
    })


@router.route("/api/v1/mesh/overview", methods=["GET"])
@login_required
@setup_required
def api_mesh_overview():
    mesh_payload = mesh_control_plane_payload()
    data: Dict[str, Any] = {
        "scope": current_scope_label(),
        "counts": {
            "topologies": len(mesh_payload["topologies"]),
            "vpn_links": len(mesh_payload["vpn_links"]),
            "route_advertisements": len(mesh_payload["route_advertisements"]),
            "access_policies": len(mesh_payload["access_policies"]),
        },
        "route_conflicts": mesh_payload["route_conflicts"],
    }
    if current_user.has_role(*STAFF_ROLES):
        data["mesh"] = mesh_payload
    return api_success(data)


@router.route("/api/v1/mesh/topologies", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_topologies():
    return api_success({
        "scope": current_scope_label(),
        "items": [item.__to_yaml_dict__() for item in wireguard_config.mesh.topologies.values()],
    })


@router.route("/api/v1/mesh/topologies", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_create_topology():
    payload = parse_json_payload()
    topology = MeshTopology(
        name=parse_mesh_str(payload.get("name")),
        preset=parse_mesh_str(payload.get("preset")) or MeshTopology.PRESET_POINT_TO_POINT,
        server_ids=payload.get("server_ids", []),
        hub_server_id=parse_mesh_str(payload.get("hub_server_id")),
        description=parse_mesh_str(payload.get("description")),
    )
    wireguard_config.mesh.topologies[topology.uuid] = topology
    sort_and_persist_mesh()
    log_audit_event("mesh.topology.create", details={"topology_uuid": topology.uuid, "topology_name": topology.name})
    return api_success(topology.__to_yaml_dict__(), status_code=201)


@router.route("/api/v1/mesh/topologies/<uuid>", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_get_topology(uuid: str):
    topology = wireguard_config.mesh.topologies.get(uuid, None)
    if not topology:
        abort(NOT_FOUND, "Topology not found.")
    return api_success(topology.__to_yaml_dict__())


@router.route("/api/v1/mesh/topologies/<uuid>", methods=["PUT"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_update_topology(uuid: str):
    topology = wireguard_config.mesh.topologies.get(uuid, None)
    if not topology:
        abort(NOT_FOUND, "Topology not found.")
    payload = parse_json_payload()
    updated = MeshTopology(
        uuid=topology.uuid,
        name=parse_mesh_str(payload.get("name", topology.name)),
        preset=parse_mesh_str(payload.get("preset", topology.preset)) or topology.preset,
        server_ids=payload.get("server_ids", topology.server_ids),
        hub_server_id=parse_mesh_str(payload.get("hub_server_id", topology.hub_server_id)),
        description=parse_mesh_str(payload.get("description", topology.description)),
    )
    wireguard_config.mesh.topologies[updated.uuid] = updated
    sort_and_persist_mesh()
    log_audit_event("mesh.topology.update", details={"topology_uuid": updated.uuid, "topology_name": updated.name})
    return api_success(updated.__to_yaml_dict__())


@router.route("/api/v1/mesh/topologies/<uuid>", methods=["DELETE"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_delete_topology(uuid: str):
    topology = wireguard_config.mesh.topologies.get(uuid, None)
    if not topology:
        abort(NOT_FOUND, "Topology not found.")
    del wireguard_config.mesh.topologies[uuid]
    deleted_links = []
    for link in list(wireguard_config.mesh.vpn_links.values()):
        if link.topology_uuid == uuid:
            deleted_links.append(link.uuid)
            del wireguard_config.mesh.vpn_links[link.uuid]
    for route in wireguard_config.mesh.route_advertisements.values():
        if route.via_link_uuid in deleted_links:
            route.via_link_uuid = ""
    sort_and_persist_mesh()
    log_audit_event(
        "mesh.topology.delete",
        details={"topology_uuid": uuid, "deleted_links": len(deleted_links)},
    )
    return api_success({"deleted": True, "topology_uuid": uuid, "deleted_links": deleted_links})


@router.route("/api/v1/mesh/links", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_links():
    return api_success({
        "scope": current_scope_label(),
        "items": [item.__to_yaml_dict__() for item in wireguard_config.mesh.vpn_links.values()],
    })


@router.route("/api/v1/mesh/links", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_create_link():
    payload = parse_json_payload()
    link = VPNLink(
        source_server=parse_mesh_str(payload.get("source_server")),
        target_server=parse_mesh_str(payload.get("target_server")),
        interface_uuid=parse_mesh_str(payload.get("interface_uuid")),
        status=parse_mesh_str(payload.get("status")) or VPNLink.STATUS_PENDING,
        key_metadata=payload.get("key_metadata", {}),
        topology_uuid=parse_mesh_str(payload.get("topology_uuid")),
        description=parse_mesh_str(payload.get("description")),
        enabled=parse_json_bool(payload, "enabled", True),
    )
    wireguard_config.mesh.vpn_links[link.uuid] = link
    sort_and_persist_mesh()
    log_audit_event("mesh.link.create", details={"link_uuid": link.uuid})
    return api_success(link.__to_yaml_dict__(), status_code=201)


@router.route("/api/v1/mesh/links/<uuid>", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_get_link(uuid: str):
    link = wireguard_config.mesh.vpn_links.get(uuid, None)
    if not link:
        abort(NOT_FOUND, "VPN link not found.")
    return api_success(link.__to_yaml_dict__())


@router.route("/api/v1/mesh/links/<uuid>", methods=["PUT"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_update_link(uuid: str):
    link = wireguard_config.mesh.vpn_links.get(uuid, None)
    if not link:
        abort(NOT_FOUND, "VPN link not found.")
    payload = parse_json_payload()
    updated = VPNLink(
        uuid=link.uuid,
        source_server=parse_mesh_str(payload.get("source_server", link.source_server)),
        target_server=parse_mesh_str(payload.get("target_server", link.target_server)),
        interface_uuid=parse_mesh_str(payload.get("interface_uuid", link.interface_uuid)),
        status=parse_mesh_str(payload.get("status", link.status)) or link.status,
        key_metadata=payload.get("key_metadata", link.key_metadata),
        topology_uuid=parse_mesh_str(payload.get("topology_uuid", link.topology_uuid)),
        description=parse_mesh_str(payload.get("description", link.description)),
        enabled=parse_json_bool(payload, "enabled", link.enabled),
    )
    wireguard_config.mesh.vpn_links[updated.uuid] = updated
    sort_and_persist_mesh()
    log_audit_event("mesh.link.update", details={"link_uuid": updated.uuid})
    return api_success(updated.__to_yaml_dict__())


@router.route("/api/v1/mesh/links/<uuid>", methods=["DELETE"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_delete_link(uuid: str):
    link = wireguard_config.mesh.vpn_links.get(uuid, None)
    if not link:
        abort(NOT_FOUND, "VPN link not found.")
    del wireguard_config.mesh.vpn_links[uuid]
    for route in wireguard_config.mesh.route_advertisements.values():
        if route.via_link_uuid == uuid:
            route.via_link_uuid = ""
    sort_and_persist_mesh()
    log_audit_event("mesh.link.delete", details={"link_uuid": uuid})
    return api_success({"deleted": True, "link_uuid": uuid})


@router.route("/api/v1/mesh/routes", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_routes():
    return api_success({
        "scope": current_scope_label(),
        "items": [item.__to_yaml_dict__() for item in wireguard_config.mesh.route_advertisements.values()],
    })


@router.route("/api/v1/mesh/routes", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_create_route():
    payload = parse_json_payload()
    try:
        route = RouteAdvertisement(
            owner_server=parse_mesh_str(payload.get("owner_server")),
            cidr=parse_mesh_str(payload.get("cidr")),
            via_link_uuid=parse_mesh_str(payload.get("via_link_uuid")),
            description=parse_mesh_str(payload.get("description")),
            enabled=parse_json_bool(payload, "enabled", True),
        )
    except Exception as e:
        abort(BAD_REQUEST, f"Invalid route payload: {e}")
    wireguard_config.mesh.route_advertisements[route.uuid] = route
    sort_and_persist_mesh()
    log_audit_event("mesh.route.create", details={"route_uuid": route.uuid, "cidr": route.cidr})
    return api_success(route.__to_yaml_dict__(), status_code=201)


@router.route("/api/v1/mesh/routes/<uuid>", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_get_route(uuid: str):
    route = wireguard_config.mesh.route_advertisements.get(uuid, None)
    if not route:
        abort(NOT_FOUND, "Route advertisement not found.")
    return api_success(route.__to_yaml_dict__())


@router.route("/api/v1/mesh/routes/<uuid>", methods=["PUT"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_update_route(uuid: str):
    route = wireguard_config.mesh.route_advertisements.get(uuid, None)
    if not route:
        abort(NOT_FOUND, "Route advertisement not found.")
    payload = parse_json_payload()
    try:
        updated = RouteAdvertisement(
            uuid=route.uuid,
            owner_server=parse_mesh_str(payload.get("owner_server", route.owner_server)),
            cidr=parse_mesh_str(payload.get("cidr", route.cidr)),
            via_link_uuid=parse_mesh_str(payload.get("via_link_uuid", route.via_link_uuid)),
            description=parse_mesh_str(payload.get("description", route.description)),
            enabled=parse_json_bool(payload, "enabled", route.enabled),
        )
    except Exception as e:
        abort(BAD_REQUEST, f"Invalid route payload: {e}")
    wireguard_config.mesh.route_advertisements[updated.uuid] = updated
    sort_and_persist_mesh()
    log_audit_event("mesh.route.update", details={"route_uuid": updated.uuid, "cidr": updated.cidr})
    return api_success(updated.__to_yaml_dict__())


@router.route("/api/v1/mesh/routes/<uuid>", methods=["DELETE"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_delete_route(uuid: str):
    route = wireguard_config.mesh.route_advertisements.get(uuid, None)
    if not route:
        abort(NOT_FOUND, "Route advertisement not found.")
    del wireguard_config.mesh.route_advertisements[uuid]
    sort_and_persist_mesh()
    log_audit_event("mesh.route.delete", details={"route_uuid": uuid})
    return api_success({"deleted": True, "route_uuid": uuid})


@router.route("/api/v1/mesh/policies", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_policies():
    return api_success({
        "scope": current_scope_label(),
        "items": [item.__to_yaml_dict__() for item in wireguard_config.mesh.access_policies.values()],
    })


@router.route("/api/v1/mesh/policies", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_create_policy():
    payload = parse_json_payload()
    policy = AccessPolicy(
        name=parse_mesh_str(payload.get("name")),
        source_kind=parse_mesh_str(payload.get("source_kind")) or AccessPolicy.SOURCE_PEER,
        source_id=parse_mesh_str(payload.get("source_id")),
        destinations=payload.get("destinations", []),
        action=parse_mesh_str(payload.get("action")) or AccessPolicy.ACTION_ALLOW,
        priority=payload.get("priority", AccessPolicy.DEFAULT_PRIORITY),
        description=parse_mesh_str(payload.get("description")),
        enabled=parse_json_bool(payload, "enabled", True),
    )
    wireguard_config.mesh.access_policies[policy.uuid] = policy
    sort_and_persist_mesh()
    log_audit_event("mesh.policy.create", details={"policy_uuid": policy.uuid, "policy_name": policy.name})
    return api_success(policy.__to_yaml_dict__(), status_code=201)


@router.route("/api/v1/mesh/policies/<uuid>", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_get_policy(uuid: str):
    policy = wireguard_config.mesh.access_policies.get(uuid, None)
    if not policy:
        abort(NOT_FOUND, "Access policy not found.")
    return api_success(policy.__to_yaml_dict__())


@router.route("/api/v1/mesh/policies/<uuid>", methods=["PUT"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_update_policy(uuid: str):
    policy = wireguard_config.mesh.access_policies.get(uuid, None)
    if not policy:
        abort(NOT_FOUND, "Access policy not found.")
    payload = parse_json_payload()
    updated = AccessPolicy(
        uuid=policy.uuid,
        name=parse_mesh_str(payload.get("name", policy.name)),
        source_kind=parse_mesh_str(payload.get("source_kind", policy.source_kind)) or policy.source_kind,
        source_id=parse_mesh_str(payload.get("source_id", policy.source_id)),
        destinations=payload.get("destinations", policy.destinations),
        action=parse_mesh_str(payload.get("action", policy.action)) or policy.action,
        priority=payload.get("priority", policy.priority),
        description=parse_mesh_str(payload.get("description", policy.description)),
        enabled=parse_json_bool(payload, "enabled", policy.enabled),
    )
    wireguard_config.mesh.access_policies[updated.uuid] = updated
    sort_and_persist_mesh()
    log_audit_event("mesh.policy.update", details={"policy_uuid": updated.uuid, "policy_name": updated.name})
    return api_success(updated.__to_yaml_dict__())


@router.route("/api/v1/mesh/policies/<uuid>", methods=["DELETE"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_delete_policy(uuid: str):
    policy = wireguard_config.mesh.access_policies.get(uuid, None)
    if not policy:
        abort(NOT_FOUND, "Access policy not found.")
    del wireguard_config.mesh.access_policies[uuid]
    sort_and_persist_mesh()
    log_audit_event("mesh.policy.delete", details={"policy_uuid": uuid})
    return api_success({"deleted": True, "policy_uuid": uuid})


@router.route("/api/v1/mesh/dry-run", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_dry_run():
    payload = parse_json_payload()
    mesh_payload = payload.get("mesh", None)
    if mesh_payload is None:
        mesh_payload = mesh_control_plane_payload()
    if not isinstance(mesh_payload, dict):
        abort(BAD_REQUEST, "mesh must be an object.")
    try:
        mesh_candidate = build_mesh_from_payload(mesh_payload)
    except Exception as e:
        abort(BAD_REQUEST, f"Invalid mesh payload: {e}")

    route_conflicts = mesh_candidate.validate_route_advertisements()
    reference_issues = validate_mesh_references(mesh_candidate)
    valid = (
        len(reference_issues) < 1 and
        len(route_conflicts["duplicate_ownership"]) < 1 and
        len(route_conflicts["overlapping_cidrs"]) < 1
    )
    return api_success({
        "valid": valid,
        "reference_issues": reference_issues,
        "route_conflicts": route_conflicts,
        "counts": {
            "topologies": len(mesh_candidate.topologies),
            "vpn_links": len(mesh_candidate.vpn_links),
            "route_advertisements": len(mesh_candidate.route_advertisements),
            "access_policies": len(mesh_candidate.access_policies),
        },
    })


@router.route("/api/v1/mesh/export", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_export():
    return api_success({
        "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "mesh": mesh_control_plane_payload(),
    })


@router.route("/api/v1/mesh/import", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_mesh_import():
    payload = parse_json_payload()
    mesh_payload = payload.get("mesh", None)
    if not isinstance(mesh_payload, dict):
        abort(BAD_REQUEST, "mesh is required.")
    allow_conflicts = parse_json_bool(payload, "allow_conflicts", False)
    try:
        mesh_candidate = build_mesh_from_payload(mesh_payload)
    except Exception as e:
        abort(BAD_REQUEST, f"Invalid mesh payload: {e}")

    route_conflicts = mesh_candidate.validate_route_advertisements()
    reference_issues = validate_mesh_references(mesh_candidate)
    has_conflicts = bool(
        reference_issues or
        route_conflicts["duplicate_ownership"] or
        route_conflicts["overlapping_cidrs"]
    )
    if has_conflicts and not allow_conflicts:
        return api_error(
            BAD_REQUEST,
            "mesh_validation_failed",
            "Mesh import has validation errors/conflicts.",
            details={
                "reference_issues": reference_issues,
                "route_conflicts": route_conflicts,
            },
        )

    wireguard_config.mesh = mesh_candidate
    sort_and_persist_mesh()
    log_audit_event(
        "mesh.import",
        status="success",
        details={
            "allow_conflicts": allow_conflicts,
            "reference_issues": len(reference_issues),
            "duplicate_conflicts": len(route_conflicts["duplicate_ownership"]),
            "overlap_conflicts": len(route_conflicts["overlapping_cidrs"]),
        },
    )
    return api_success({
        "imported": True,
        "allow_conflicts": allow_conflicts,
        "reference_issues": reference_issues,
        "route_conflicts": route_conflicts,
        "mesh": mesh_control_plane_payload(),
    })


@router.route("/api/v1/stats/overview", methods=["GET"])
@login_required
@setup_required
def api_stats_overview():
    return api_success(build_stats_snapshot())


@router.route("/api/v1/stats/peers", methods=["GET"])
@login_required
@setup_required
def api_stats_peers():
    runtime = get_scoped_peer_runtime_summary()
    return api_success({
        "scope": current_scope_label(),
        "thresholds": runtime["thresholds"],
        "peers": [serialize_peer_runtime_row(row) for row in runtime["rows"]]
    })


@router.route("/api/v1/stats/alerts", methods=["GET"])
@login_required
@setup_required
def api_stats_alerts():
    runtime = get_scoped_peer_runtime_summary()
    return api_success({
        "scope": current_scope_label(),
        "thresholds": runtime["thresholds"],
        "alerts": runtime["alerts"]
    })


@router.route("/api/v1/stats/peers.csv", methods=["GET"])
@login_required
@setup_required
def api_stats_peers_csv():
    runtime = get_scoped_peer_runtime_summary()
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
@setup_required
def api_stats_alerts_csv():
    runtime = get_scoped_peer_runtime_summary()
    fields = ["level", "title", "message", "peer_name", "peer_uuid"]
    return csv_response("arpvpn-alerts.csv", fields, runtime["alerts"])


@router.route("/api/v1/stats/statistics", methods=["GET"])
@login_required
@setup_required
def api_stats_statistics():
    include_log_issues = current_user.has_role(*STAFF_ROLES)
    payload = build_statistics_payload(include_log_issues=include_log_issues)
    rows = [
        serialize_statistics_row(row, payload["rollup_index"])
        for row in payload["statistics_rows"]
    ]
    return api_success({
        "scope": payload["scope"],
        "connections_total": payload["connections_total"],
        "rrd_ready_count": payload["rrd_ready_count"],
        "failure_count": payload["failure_count"],
        "handshake_failures": payload["handshake_failures"],
        "peers": payload["peer_runtime"]["totals"],
        "failure_metrics": payload["failure_metrics"],
        "log_summary": payload["log_summary"],
        "rollup_windows": list(TRAFFIC_ROLLUP_WINDOWS_SECONDS.keys()),
        "connections": rows,
    })


@router.route("/api/v1/stats/rollups", methods=["GET"])
@login_required
@setup_required
def api_stats_rollups():
    payload = build_statistics_payload(include_log_issues=False)
    return api_success({
        "scope": payload["scope"],
        "rollup_windows": list(TRAFFIC_ROLLUP_WINDOWS_SECONDS.keys()),
        "totals": payload["rollup_totals"],
        "connections": payload["rollup_rows"],
    })


@router.route("/api/v1/stats/rollups.csv", methods=["GET"])
@login_required
@setup_required
def api_stats_rollups_csv():
    payload = build_statistics_payload(include_log_issues=False)
    rows = flatten_rollup_rows_for_csv(payload["statistics_rows"], payload["rollup_index"])
    fieldnames = [
        "type", "type_label", "uuid", "name", "parent_name", "status", "sample_points",
        "session_rx_human", "session_tx_human", "session_total_human",
    ]
    for window_name in TRAFFIC_ROLLUP_WINDOWS_SECONDS.keys():
        fieldnames.extend([
            f"{window_name}_rx_bytes",
            f"{window_name}_tx_bytes",
            f"{window_name}_total_bytes",
            f"{window_name}_total_human",
        ])
    return csv_response("arpvpn-rollups.csv", fieldnames, rows)


@router.route("/api/v1/stats/failures", methods=["GET"])
@login_required
@setup_required
def api_stats_failures():
    payload = build_statistics_payload(include_log_issues=False)
    return api_success({
        "scope": payload["scope"],
        "failure_count": payload["failure_count"],
        "handshake_failures": payload["handshake_failures"],
        "failure_metrics": payload["failure_metrics"],
    })


@router.route("/api/v1/stats/history/<uuid>", methods=["GET"])
@login_required
@setup_required
def api_stats_history(uuid: str):
    item_type, item = resolve_connection_item(uuid)
    if not user_can_access_connection(item_type, item):
        abort(FORBIDDEN, "Insufficient permissions.")
    requested_window = (request.args.get("window", "24h") or "24h").lower()
    points = get_connection_traffic_points(uuid)
    filtered_points = filter_points_for_window(points, requested_window)
    return api_success({
        "scope": current_scope_label(),
        "connection": build_connection_descriptor(item_type, item),
        "window": requested_window,
        "window_seconds": RRD_GRAPH_WINDOWS_SECONDS.get(requested_window, None),
        "points_count": len(filtered_points),
        "points": serialize_traffic_points(filtered_points),
        "rrd_page_url": url_for("router.connection_rrd_graph", uuid=uuid, window=requested_window),
        "rrd_image_url": url_for("router.connection_rrd_graph_png", uuid=uuid, window=requested_window),
    })


@router.route("/api/v1/stats/rrd/<uuid>", methods=["GET"])
@login_required
@setup_required
def api_stats_rrd(uuid: str):
    item_type, item = resolve_connection_item(uuid)
    if not user_can_access_connection(item_type, item):
        abort(FORBIDDEN, "Insufficient permissions.")
    requested_window = (request.args.get("window", "24h") or "24h").lower()
    if requested_window not in RRD_GRAPH_WINDOWS_SECONDS:
        abort(BAD_REQUEST, "Unknown graph window.")
    windows = []
    for window_name in sorted(RRD_GRAPH_WINDOWS_SECONDS.keys(), key=lambda key: RRD_GRAPH_WINDOWS_SECONDS[key]):
        windows.append({
            "name": window_name,
            "seconds": RRD_GRAPH_WINDOWS_SECONDS[window_name],
            "rrd_page_url": url_for("router.connection_rrd_graph", uuid=uuid, window=window_name),
            "rrd_image_url": url_for("router.connection_rrd_graph_png", uuid=uuid, window=window_name),
        })
    return api_success({
        "scope": current_scope_label(),
        "connection": build_connection_descriptor(item_type, item),
        "selected_window": requested_window,
        "windows": windows,
    })


@router.route("/traffic/rrd/<uuid>", methods=["GET"])
@login_required
@setup_required
def connection_rrd_graph(uuid: str):
    item_type, item = resolve_connection_item(uuid)
    if not user_can_access_connection(item_type, item):
        abort(FORBIDDEN, "Insufficient permissions.")
    requested_window = (request.args.get("window", "24h") or "24h").lower()
    if requested_window not in RRD_GRAPH_WINDOWS_SECONDS:
        abort(BAD_REQUEST, "Unknown graph window.")
    context = {
        "title": "Connection graph",
        "connection_type": item_type,
        "connection_uuid": uuid,
        "connection_name": item.name,
        "window": requested_window,
        "window_options": sorted(
            RRD_GRAPH_WINDOWS_SECONDS.keys(),
            key=lambda key: RRD_GRAPH_WINDOWS_SECONDS[key]
        ),
        "image_url": url_for("router.connection_rrd_graph_png", uuid=uuid, window=requested_window),
    }
    return ViewController("web/traffic-rrd.html", **context).load()


@router.route("/traffic/rrd/<uuid>.png", methods=["GET"])
@login_required
@setup_required
def connection_rrd_graph_png(uuid: str):
    item_type, item = resolve_connection_item(uuid)
    if not user_can_access_connection(item_type, item):
        abort(FORBIDDEN, "Insufficient permissions.")
    requested_window = (request.args.get("window", "24h") or "24h").lower()
    if requested_window not in RRD_GRAPH_WINDOWS_SECONDS:
        abort(BAD_REQUEST, "Unknown graph window.")

    try:
        png_data = generate_rrd_graph_png(uuid, RRD_GRAPH_WINDOWS_SECONDS[requested_window])
    except RuntimeError as e:
        log_exception(e)
        abort(INTERNAL_SERVER_ERROR, str(e))

    if png_data is None:
        abort(NOT_FOUND, "No traffic data available for this connection yet.")
    return Response(
        png_data,
        mimetype="image/png",
        headers={"Cache-Control": "no-store, max-age=0"}
    )


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
    history = load_traffic_history_data(include_session=True)
    for timestamp, traffic_data in sorted(history.items(), key=lambda pair: pair[0]):
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


@router.route("/api/v1/themes", methods=["GET"])
@login_required
@setup_required
def api_get_theme_choice():
    choice = normalize_theme_choice(request.cookies.get(THEME_COOKIE_NAME, "auto"))
    return jsonify({
        "choice": choice,
        "choices": list(THEME_CHOICES)
    })


@router.route("/api/v1/themes", methods=["POST"])
@login_required
@setup_required
def api_set_theme_choice():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        abort(BAD_REQUEST, "Invalid payload.")
    raw_choice = payload.get("choice", None)
    if not isinstance(raw_choice, str):
        abort(BAD_REQUEST, "Theme choice must be a string.")
    choice = raw_choice.strip().lower()
    if choice not in THEME_CHOICES:
        abort(BAD_REQUEST, "Unknown theme choice.")
    response = jsonify({
        "choice": choice,
        "choices": list(THEME_CHOICES)
    })
    secure_cookie = should_use_secure_cookie()
    response.set_cookie(
        THEME_COOKIE_NAME,
        choice,
        max_age=THEME_COOKIE_MAX_AGE_SECONDS,
        secure=secure_cookie,
        httponly=True,
        samesite="Lax",
    )
    return response


@router.route("/api/v1/tls/status", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_tls_status():
    return api_success(build_tls_status_payload())


@router.route("/api/v1/tls/certificate", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_tls_certificate_status():
    payload = build_tls_status_payload()
    return api_success({
        "scope": payload["scope"],
        "mode": payload["mode"],
        "server_name": payload["server_name"],
        "certificate": payload["certificate"],
    })


@router.route("/api/v1/tls/mode", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_tls_mode_update():
    payload = parse_json_payload()
    mode = parse_tls_mode(payload.get("mode"))
    server_name = str(payload.get("server_name", web_config.tls_server_name) or "").strip()
    letsencrypt_email = str(payload.get("letsencrypt_email", web_config.tls_letsencrypt_email) or "").strip()
    proxy_incoming_hostname = str(payload.get("proxy_incoming_hostname", web_config.proxy_incoming_hostname) or "").strip()
    redirect_http_to_https = parse_json_bool(payload, "redirect_http_to_https", web_config.redirect_http_to_https)

    requires_hostname = mode in (web_config.TLS_MODE_SELF_SIGNED, web_config.TLS_MODE_LETS_ENCRYPT)
    if requires_hostname:
        server_name = parse_tls_server_name(
            server_name,
            allow_ipv4=mode == web_config.TLS_MODE_SELF_SIGNED,
            allow_localhost=mode == web_config.TLS_MODE_SELF_SIGNED,
            field_name="server_name",
        )
    if mode == web_config.TLS_MODE_REVERSE_PROXY:
        proxy_incoming_hostname = parse_tls_server_name(
            proxy_incoming_hostname,
            allow_ipv4=False,
            allow_localhost=True,
            field_name="proxy_incoming_hostname",
        )
    if mode == web_config.TLS_MODE_LETS_ENCRYPT and not letsencrypt_email:
        warning("TLS mode switched to letsencrypt without explicit email; certbot may require follow-up.")

    web_config.tls_mode = mode
    web_config.tls_server_name = server_name
    web_config.tls_letsencrypt_email = letsencrypt_email
    web_config.proxy_incoming_hostname = proxy_incoming_hostname
    web_config.redirect_http_to_https = redirect_http_to_https and mode != web_config.TLS_MODE_HTTP

    tls_manager.apply_web_tls_config(web_config)
    config_manager.save()
    return api_success(build_tls_status_payload())


@router.route("/api/v1/tls/self-signed", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_tls_generate_self_signed():
    payload = parse_json_payload()
    server_name = parse_tls_server_name(
        payload.get("server_name", web_config.tls_server_name),
        allow_ipv4=True,
        allow_localhost=True,
        field_name="server_name",
    )
    regenerate = parse_json_bool(payload, "regenerate", True)
    redirect_http_to_https = parse_json_bool(payload, "redirect_http_to_https", web_config.redirect_http_to_https)

    web_config.tls_mode = web_config.TLS_MODE_SELF_SIGNED
    web_config.tls_server_name = server_name
    web_config.redirect_http_to_https = redirect_http_to_https
    tls_manager.apply_web_tls_config(web_config, generate_self_signed=regenerate)
    config_manager.save()
    return api_success(build_tls_status_payload())


@router.route("/api/v1/tls/letsencrypt", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_tls_issue_letsencrypt():
    payload = parse_json_payload()
    server_name = parse_tls_server_name(
        payload.get("server_name", web_config.tls_server_name),
        allow_ipv4=False,
        allow_localhost=False,
        field_name="server_name",
    )
    email = str(payload.get("email", web_config.tls_letsencrypt_email) or "").strip()
    issue_now = parse_json_bool(payload, "issue_now", True)
    redirect_http_to_https = parse_json_bool(payload, "redirect_http_to_https", web_config.redirect_http_to_https)

    web_config.tls_mode = web_config.TLS_MODE_LETS_ENCRYPT
    web_config.tls_server_name = server_name
    web_config.tls_letsencrypt_email = email
    web_config.redirect_http_to_https = redirect_http_to_https
    tls_manager.apply_web_tls_config(web_config, issue_letsencrypt=issue_now)
    config_manager.save()
    return api_success(build_tls_status_payload())


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
        form.web_redirect_http_to_https.data = web_config.redirect_http_to_https
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


def count_users_by_role(role: str) -> int:
    return len([user_item for user_item in users.values() if user_item.role == role])


def can_manage_user_account(target_user: User) -> bool:
    if current_user.has_role(User.ROLE_ADMIN):
        return True
    if current_user.has_role(User.ROLE_SUPPORT):
        return target_user.role == User.ROLE_CLIENT
    return False


def build_user_actions(users_list: List[User]) -> Dict[str, Dict[str, bool]]:
    actions: Dict[str, Dict[str, bool]] = {}
    admin_count = count_users_by_role(User.ROLE_ADMIN)
    for user_item in users_list:
        can_manage = can_manage_user_account(user_item)
        can_delete = can_manage and user_item.id != current_user.id
        if user_item.role == User.ROLE_ADMIN and admin_count <= 1:
            can_delete = False
        actions[user_item.id] = {
            "can_edit": can_manage,
            "can_delete": can_delete,
            "can_impersonate": (
                user_item.role == User.ROLE_CLIENT and
                user_item.id != current_user.id and
                not is_impersonating()
            ),
        }
    return actions


def get_users_management_context(create_form=None, edit_form=None, delete_form=None,
                                 impersonate_form=None, stop_form=None) -> Dict[str, Any]:
    from arpvpn.web.forms import CreateUserForm, EditUserForm, DeleteUserForm, ImpersonateClientForm, ImpersonationStopForm
    create_form = create_form or CreateUserForm()
    edit_form = edit_form or EditUserForm()
    delete_form = delete_form or DeleteUserForm()
    if current_user.has_role(User.ROLE_SUPPORT):
        create_form.role.choices = [(User.ROLE_CLIENT, "Client")]
        if request.method == "GET":
            create_form.role.data = User.ROLE_CLIENT
        edit_form.role.choices = [(User.ROLE_CLIENT, "Client")]
    impersonate_form = impersonate_form or ImpersonateClientForm()
    stop_form = stop_form or ImpersonationStopForm()
    users_list = sorted(users.values(), key=lambda u: (u.role, u.name.lower()))
    return {
        "title": "Users",
        "create_form": create_form,
        "edit_form": edit_form,
        "delete_form": delete_form,
        "impersonate_form": impersonate_form,
        "stop_impersonation_form": stop_form,
        "users_list": users_list,
        "user_actions": build_user_actions(users_list),
        "is_impersonating": is_impersonating(),
    }


def summarize_form_errors(form: Any) -> str:
    issues: List[str] = []
    for field_name, errors in getattr(form, "errors", {}).items():
        if not errors:
            continue
        for issue in errors:
            issues.append(f"{field_name}: {issue}")
    return "; ".join(issues)


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
    from arpvpn.web.forms import CreateUserForm, EditUserForm, DeleteUserForm, ImpersonateClientForm, ImpersonationStopForm
    form = CreateUserForm(request.form)
    context = get_users_management_context(
        create_form=form,
        edit_form=EditUserForm(),
        delete_form=DeleteUserForm(),
        impersonate_form=ImpersonateClientForm(),
        stop_form=ImpersonationStopForm(),
    )
    if not form.validate():
        details = summarize_form_errors(form) or "unknown validation error"
        error(f"Unable to validate create-user form: {details}")
        context["error"] = True
        context["error_details"] = f"Unable to create user: {details}"
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


@router.route("/users/<user_id>/edit", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def edit_user(user_id: str):
    from arpvpn.web.forms import EditUserForm
    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    if not can_manage_user_account(target_user):
        abort(FORBIDDEN, "Insufficient permissions.")

    form = EditUserForm()
    if current_user.has_role(User.ROLE_SUPPORT):
        form.role.choices = [(User.ROLE_CLIENT, "Client")]
    form.username.data = target_user.name
    form.role.data = target_user.role

    context = {
        "title": "Edit user",
        "form": form,
        "target_user": target_user,
    }
    return ViewController("web/user-edit.html", **context).load()


@router.route("/users/<user_id>/edit", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def save_user(user_id: str):
    from arpvpn.web.forms import EditUserForm
    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    if not can_manage_user_account(target_user):
        abort(FORBIDDEN, "Insufficient permissions.")

    form = EditUserForm(request.form)
    if current_user.has_role(User.ROLE_SUPPORT):
        form.role.choices = [(User.ROLE_CLIENT, "Client")]

    view = "web/user-edit.html"
    context = {
        "title": "Edit user",
        "form": form,
        "target_user": target_user,
    }

    if not form.validate():
        error("Unable to validate edit-user form")
        return ViewController(view, **context).load()

    requested_username = (form.username.data or "").strip()
    requested_role = form.role.data or target_user.role

    existing_user = users.get_value_by_attr("name", requested_username)
    if existing_user and existing_user.id != target_user.id:
        form.username.errors.append("Username already in use")
        return ViewController(view, **context).load()

    if current_user.has_role(User.ROLE_SUPPORT) and requested_role != User.ROLE_CLIENT:
        form.role.errors.append("Support users can only assign the client role.")
        return ViewController(view, **context).load()

    if target_user.id == current_user.id and requested_role != target_user.role:
        form.role.errors.append("You cannot change your own role from this page.")
        return ViewController(view, **context).load()

    if target_user.role == User.ROLE_ADMIN and requested_role != User.ROLE_ADMIN:
        if count_users_by_role(User.ROLE_ADMIN) <= 1:
            form.role.errors.append("Cannot demote the last admin user.")
            return ViewController(view, **context).load()

    try:
        target_user.name = requested_username
        target_user.role = requested_role
        if form.new_password.data:
            target_user.password = form.new_password.data
        users.sort()
        users.save(web_config.credentials_file, web_config.secret_key)

        context = get_users_management_context()
        context["success"] = True
        context["success_details"] = "User updated successfully."
        return ViewController("web/users.html", **context).load()
    except Exception as e:
        log_exception(e)
        context["error"] = True
        context["error_details"] = e
        return ViewController(view, **context).load()


@router.route("/users/<user_id>/delete", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def delete_user(user_id: str):
    from arpvpn.web.forms import DeleteUserForm
    form = DeleteUserForm(request.form)
    if not form.validate():
        abort(BAD_REQUEST, "Invalid delete-user request.")

    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    if not can_manage_user_account(target_user):
        abort(FORBIDDEN, "Insufficient permissions.")
    if target_user.id == current_user.id:
        context = get_users_management_context()
        context["error"] = True
        context["error_details"] = "You cannot delete your own account."
        return ViewController("web/users.html", **context).load()
    if target_user.role == User.ROLE_ADMIN and count_users_by_role(User.ROLE_ADMIN) <= 1:
        context = get_users_management_context()
        context["error"] = True
        context["error_details"] = "Cannot delete the last admin user."
        return ViewController("web/users.html", **context).load()

    try:
        del users[target_user.id]
        users.save(web_config.credentials_file, web_config.secret_key)
        context = get_users_management_context()
        context["success"] = True
        context["success_details"] = "User deleted successfully."
        return ViewController("web/users.html", **context).load()
    except Exception as e:
        log_exception(e)
        context = get_users_management_context()
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
    target_user.set_authenticated(True)
    if not login_user(target_user, remember=False):
        abort(INTERNAL_SERVER_ERROR, "Unable to impersonate target user.")
    log_audit_event(
        "impersonation.start",
        status="success",
        details={"target_user_id": target_user.id, "target_user_name": target_user.name},
    )
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
    impersonator.set_authenticated(True)
    if not login_user(impersonator, remember=False):
        abort(INTERNAL_SERVER_ERROR, "Unable to restore original user.")
    log_audit_event(
        "impersonation.stop",
        status="success",
        details={"restored_user_id": impersonator.id, "restored_user_name": impersonator.name},
    )
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
    form.web_tls_mode.data = web_config.TLS_MODE_SELF_SIGNED
    form.web_tls_server_name.data = web_config.tls_server_name or wireguard_config.endpoint
    form.web_redirect_http_to_https.data = web_config.redirect_http_to_https
    form.web_tls_generate_self_signed.data = True
    form.web_tls_issue_letsencrypt.data = False
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


def get_error_message(err: Exception, fallback: str) -> str:
    raw = str(err).strip()
    if not raw:
        return fallback
    if ":" in raw:
        return raw.split(":", 1)[1].strip()
    return raw


@router.app_errorhandler(BAD_REQUEST)
def bad_request(err):
    error_code = int(BAD_REQUEST)
    error_msg = get_error_message(err, "Invalid request.")
    if is_api_request():
        return api_error(error_code, "bad_request", error_msg.strip())
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": error_msg
    }
    return ViewController("error/error-main.html", **context).load(), error_code


@router.app_errorhandler(UNAUTHORIZED)
def unauthorized(err):
    warning(f"Unauthorized request from {request.remote_addr}!")
    error_code = int(UNAUTHORIZED)
    error_msg = get_error_message(err, "Authentication required.")
    if is_api_request():
        return api_error(error_code, "unauthorized", error_msg.strip())
    if request.method == "GET":
        debug(f"Redirecting to login...")
        try:
            next_url = url_for(request.endpoint)
        except Exception:
            uuid = request.path.rsplit("/", 1)[-1]
            next_url = url_for(request.endpoint, uuid=uuid)
        return redirect(url_for("router.login", next=next_url))
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": error_msg
    }
    return ViewController("error/error-main.html", **context).load(), error_code


@router.app_errorhandler(FORBIDDEN)
def forbidden(err):
    error_code = int(FORBIDDEN)
    error_msg = get_error_message(err, "Insufficient permissions.")
    if is_api_request():
        return api_error(error_code, "forbidden", error_msg.strip())
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": error_msg
    }
    return ViewController("error/error-main.html", **context).load(), error_code


@router.app_errorhandler(NOT_FOUND)
def not_found(err):
    error_code = int(NOT_FOUND)
    error_msg = get_error_message(err, "Resource not found.")
    if is_api_request():
        return api_error(error_code, "not_found", error_msg.strip())
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": error_msg,
        "image": "/static/assets/img/error-404-monochrome.svg"
    }
    return ViewController("error/error-img.html", **context).load(), error_code


@router.app_errorhandler(429)
def too_many_requests(err):
    error_code = 429
    error_msg = get_error_message(err, "Too many requests.")
    if is_api_request():
        return api_error(error_code, "too_many_requests", error_msg.strip())
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": error_msg
    }
    return ViewController("error/error-main.html", **context).load(), error_code


@router.app_errorhandler(INTERNAL_SERVER_ERROR)
def internal_server_error(err):
    error_code = int(INTERNAL_SERVER_ERROR)
    error_msg = get_error_message(err, "Internal server error.")
    if is_api_request():
        return api_error(error_code, "internal_server_error", error_msg.strip())
    context = {
        "title": error_code,
        "error_code": error_code,
        "error_msg": error_msg
    }
    return ViewController("error/error-main.html", **context).load(), error_code
