import csv
import copy
import io
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import signal
import secrets
import subprocess
import tempfile
from collections import deque
from datetime import datetime, timezone
from functools import wraps
from http.client import BAD_REQUEST, NOT_FOUND, INTERNAL_SERVER_ERROR, UNAUTHORIZED, NO_CONTENT, FORBIDDEN, CONFLICT, ACCEPTED
from ipaddress import IPv4Address
from logging import warning, debug, error, info
from threading import Thread, Lock
from time import sleep, time
from typing import List, Dict, Any, Union, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from flask import Blueprint, abort, request, Response, redirect, url_for, jsonify, session, g, current_app
from flask_login import current_user, login_required, login_user
from flask_wtf.csrf import generate_csrf, validate_csrf
from wtforms.validators import ValidationError as WTValidationError
import yaml
from werkzeug.exceptions import HTTPException

from arpvpn.common.models.user import users, User
from arpvpn.common.models.tenant import Tenant, Invitation, tenants, invitations, slugify_name
from arpvpn.common.properties import global_properties
from arpvpn.common.utils.mfa import generate_mfa_secret, generate_recovery_codes, recovery_code_hashes
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
from arpvpn.core.managers.tls import tls_manager
from arpvpn.core.models import interfaces, Interface, get_all_peers, Peer
from arpvpn.core.utils.wireguard import is_wg_iface_up
from arpvpn.web.client import clients, Client
from arpvpn.web.controllers.RestController import RestController
from arpvpn.web.controllers.ViewController import ViewController
from arpvpn.web.security_api import (
    ApiTokenStore,
    SlidingWindowRateLimiter,
    AuthLockoutManager,
    IdempotencyStore,
    AsyncJobStore,
)
from arpvpn.web.api_schema import (
    ApiSchemaValidationError,
    get_api_request_schema,
)
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
    "/documentation": "router.documentation",
    "/about": "router.about",
    "/setup": "router.setup",
}
IMPERSONATOR_SESSION_KEY = "impersonator_user_id"
MFA_VERIFIED_SESSION_USER_ID_KEY = "mfa_verified_user_id"
MFA_VERIFIED_SESSION_AT_KEY = "mfa_verified_at"
STAFF_ROLES = (User.ROLE_ADMIN, User.ROLE_SUPPORT)
USER_MANAGEMENT_ROLES = (User.ROLE_ADMIN, User.ROLE_SUPPORT, User.ROLE_TENANT_ADMIN)
API_AUTH_STAFF_ROLES = USER_MANAGEMENT_ROLES
EMAIL_ADDRESS_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_env_int(name: str, default: int) -> int:
    value = os.environ.get(name, str(default))
    try:
        return int(value)
    except ValueError:
        warning(f"Invalid integer in env var {name}={value}, using default {default}")
        return default


def get_env_bool(name: str, default: bool = True) -> bool:
    value = str(os.environ.get(name, "1" if default else "0") or "").strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    warning(f"Invalid boolean in env var {name}={value}, using default {default}")
    return default


HIGH_TRAFFIC_THRESHOLD_MB = get_env_int("ARPVPN_HIGH_TRAFFIC_THRESHOLD_MB", 1024)
HIGH_TRAFFIC_THRESHOLD_BYTES = HIGH_TRAFFIC_THRESHOLD_MB * 1024 * 1024
RRD_GRAPH_WINDOWS_SECONDS = {
    "6h": 6 * 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
    "30d": 30 * 24 * 60 * 60,
}
RRD_GRAPH_CACHE_TTL_SECONDS = get_env_int("ARPVPN_RRD_GRAPH_CACHE_TTL_SECONDS", 3 * 60 * 60)
RRD_GRAPH_CACHE_DIRNAME = "rrd_graph_cache"
RRD_GRAPH_CACHE_LOCKS: Dict[str, Lock] = {}
RRD_GRAPH_CACHE_LOCKS_LOCK = Lock()
STATISTICS_DIAGNOSTIC_FILTERS = (
    "handshake",
    "auth",
    "interface",
    "tls",
    "rrd",
    "bans",
    "warnings",
    "errors",
    "all",
)
STATISTICS_DIAGNOSTIC_DISPLAY_LIMIT = 200
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
API_CSRF_HEADER_NAMES = ("X-CSRFToken", "X-CSRF-Token")
API_MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")
API_BACKUP_FORMAT = "arpvpn-backup-v1"
API_FEATURE_FLAGS = {
    "/api/v1/auth": "ARPVPN_FEATURE_API_AUTH",
    "/api/v1/stats": "ARPVPN_FEATURE_API_STATS",
    "/api/v1/system": "ARPVPN_FEATURE_API_SYSTEM",
    "/api/v1/tls": "ARPVPN_FEATURE_API_TLS",
    "/api/v1/config": "ARPVPN_FEATURE_API_CONFIG",
    "/api/v1/profile": "ARPVPN_FEATURE_API_SYSTEM",
    "/api/v1/network": "ARPVPN_FEATURE_API_SYSTEM",
    "/api/v1/about": "ARPVPN_FEATURE_API_SYSTEM",
    "/api/v1/setup": "ARPVPN_FEATURE_API_SYSTEM",
    "/api/v1/tenants": "ARPVPN_FEATURE_API_TENANTS",
    "/api/v1/users": "ARPVPN_FEATURE_API_TENANTS",
    "/api/v1/invitations": "ARPVPN_FEATURE_API_TENANTS",
    "/api/v1/wireguard": "ARPVPN_FEATURE_API_WIREGUARD",
}
API_AUTH_PUBLIC_ENDPOINTS = {
    "router.api_auth_issue_token",
    "router.api_auth_refresh_token",
}
AUDIT_SIGNATURE_ALGORITHM = "hmac-sha256"
BENIGN_LOG_ISSUE_PATTERNS = (
    "failed to run 'ip a | grep -w",
    "already down.",
    "csrf validation failed on login; not counting toward lockout.",
)
LOG_AUTH_FAILURE_PATTERNS = (
    "login_post): unable to validate form",
    "unable to log in",
    "unable to validate field 'password'",
    "unable to validate field 'username'",
)
LOG_INTERFACE_FAILURE_PATTERNS = (
    "failed to start interface",
    "failed to stop interface",
    "invalid operation:",
)
LOG_TLS_FAILURE_PATTERNS = (
    "unable to issue let's encrypt certificate",
    "unable to generate self-signed certificate",
    "tls mode requires certificate",
    "let's encrypt certificate was issued but expected files were not found",
)
LOG_RRD_FAILURE_PATTERNS = (
    "unable to create rrd file",
    "unable to update rrd data",
    "unable to generate rrd graph",
)
LOG_DIAGNOSTIC_LABELS = {
    "all": "Log tail",
    "warnings": "Warnings",
    "errors": "Errors / fatal",
    "handshake": "Handshake failures",
    "auth": "Auth failures",
    "interface": "Interface failures",
    "tls": "TLS failures",
    "rrd": "RRD failures",
    "bans": "Active login bans",
}
LOG_DIAGNOSTIC_KINDS = {
    "all": "logs",
    "warnings": "logs",
    "errors": "logs",
    "auth": "logs",
    "interface": "logs",
    "tls": "logs",
    "rrd": "logs",
    "handshake": "peers",
    "bans": "bans",
}
api_token_store = ApiTokenStore(web_config.secret_key)
api_rate_limiter = SlidingWindowRateLimiter()
api_auth_lockouts = AuthLockoutManager()
api_idempotency_store = IdempotencyStore()
api_async_jobs = AsyncJobStore()
recent_audit_events_memory: deque[Dict[str, Any]] = deque(maxlen=500)
PROCESS_STARTED_AT = datetime.now(timezone.utc)


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


def get_api_feature_flag_name(path: str) -> str:
    for prefix, env_name in API_FEATURE_FLAGS.items():
        if path.startswith(prefix):
            return env_name
    return ""


def current_scope_label() -> str:
    if current_user.has_role(*STAFF_ROLES):
        return "staff"
    if current_user.has_role(User.ROLE_TENANT_ADMIN):
        return "tenant"
    return "client"


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


@router.before_request
def enforce_api_feature_flags():
    if not is_api_request():
        return None
    env_name = get_api_feature_flag_name(request.path)
    if not env_name:
        return None
    if get_env_bool(env_name, True):
        return None
    return api_error(NOT_FOUND, "feature_disabled", f"API group disabled by {env_name}.")


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
        try:
            return actor._get_current_object()
        except Exception:
            return actor
    if current_user and current_user.is_authenticated:
        try:
            return current_user._get_current_object()
        except Exception:
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
        return role in API_AUTH_STAFF_ROLES
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
        },
        "support_admin": {
            "maps_to_role": User.ROLE_SUPPORT,
            "impersonate_clients": True,
            "manage_users": True,
            "manage_tls": False,
        },
        "tenant_admin": {
            "maps_to_role": User.ROLE_TENANT_ADMIN,
            "impersonate_clients": True,
            "manage_users": True,
            "manage_tls": True,
        },
        "client": {
            "maps_to_role": User.ROLE_CLIENT,
            "impersonate_clients": False,
            "manage_users": False,
            "manage_tls": False,
        },
    }


def log_audit_event(action: str, status: str = "success", details: Optional[Dict[str, Any]] = None):
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    actor = current_actor()
    payload: Dict[str, Any] = {
        "created_at": created_at,
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
    signature = sign_audit_payload(payload)
    if signature:
        payload["signature_alg"] = AUDIT_SIGNATURE_ALGORITHM
        payload["signature"] = signature
    memory_payload = dict(payload)
    memory_payload["signature_valid"] = bool(signature)
    recent_audit_events_memory.append(memory_payload)
    info(f"[AUDIT] {json.dumps(payload, sort_keys=True)}")


def get_audit_signing_key() -> bytes:
    configured_key = str(os.environ.get("ARPVPN_AUDIT_SIGNING_KEY", "") or "").strip()
    if configured_key:
        return configured_key.encode("utf-8")
    secret_key = str(web_config.secret_key or "").strip()
    return secret_key.encode("utf-8")


def sign_audit_payload(payload: Dict[str, Any]) -> str:
    signing_key = get_audit_signing_key()
    if not signing_key:
        return ""
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(signing_key, serialized.encode("utf-8"), hashlib.sha256).hexdigest()


def audit_signature_valid(event: Dict[str, Any]) -> bool:
    signature = str(event.get("signature", "") or "").strip()
    if not signature:
        return False
    candidate = dict(event)
    candidate.pop("signature", None)
    candidate.pop("signature_alg", None)
    candidate.pop("signature_valid", None)
    expected = sign_audit_payload(candidate)
    return bool(expected) and hmac.compare_digest(signature, expected)


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
    mfa_code = parse_optional_string(payload.get("mfa_code", ""))
    if not username:
        abort(BAD_REQUEST, "username is required.")
    if not password:
        abort(BAD_REQUEST, "password is required.")
    return {
        "username": username,
        "password": password,
        "scope": scope,
        "mfa_code": mfa_code,
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
    payload = parse_json_payload(allow_empty=True)
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
    payload = parse_json_payload(allow_empty=True)
    if isinstance(payload, dict):
        raw = payload.get("token", "")
        candidate = str(raw or "").strip()
        if candidate:
            return candidate
    return extract_bearer_token()


def api_csrf_enabled() -> bool:
    return bool(current_app.config.get("API_CSRF_ENABLED", True))


def get_api_csrf_token_from_request() -> str:
    for header_name in API_CSRF_HEADER_NAMES:
        candidate = str(request.headers.get(header_name, "") or "").strip()
        if candidate:
            return candidate
    return ""


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
    g.api_token_record = token_record
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
        try:
            g.api_actor_user = current_user._get_current_object()
        except Exception:
            g.api_actor_user = current_user
        return None
    return None


@router.before_request
def enforce_api_csrf_for_cookie_auth():
    if not is_api_request():
        return None
    if request.method not in API_MUTATING_METHODS:
        return None
    if request.endpoint in API_AUTH_PUBLIC_ENDPOINTS:
        return None
    if not api_csrf_enabled():
        return None
    if extract_bearer_token():
        return None
    actor = current_actor()
    if not actor:
        return None
    csrf_token = get_api_csrf_token_from_request()
    if not csrf_token:
        log_audit_event("auth.csrf.failed", status="denied", details={"reason": "missing_api_csrf_token"})
        return api_error(BAD_REQUEST, "csrf_failed", "CSRF token is required for cookie-auth API requests.")
    try:
        validate_csrf(csrf_token)
    except WTValidationError as exc:
        log_audit_event("auth.csrf.failed", status="denied", details={"reason": str(exc)})
        return api_error(BAD_REQUEST, "csrf_failed", "CSRF token validation failed.")
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


def clear_session_mfa_verification():
    session.pop(MFA_VERIFIED_SESSION_USER_ID_KEY, None)
    session.pop(MFA_VERIFIED_SESSION_AT_KEY, None)


def mark_session_mfa_verified(user: Optional[User] = None):
    actor = user or current_actor()
    if not actor:
        clear_session_mfa_verification()
        return
    session[MFA_VERIFIED_SESSION_USER_ID_KEY] = actor.id
    session[MFA_VERIFIED_SESSION_AT_KEY] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def current_request_has_mfa_verification(actor: Optional[User] = None) -> bool:
    actor = actor or current_actor()
    if not actor or not actor.has_mfa():
        return False
    token_record = getattr(g, "api_token_record", None)
    if token_record and getattr(token_record, "user_id", "") == actor.id:
        return bool(getattr(token_record, "mfa_verified", False))
    session_user_id = str(session.get(MFA_VERIFIED_SESSION_USER_ID_KEY, "") or "").strip()
    session_verified_at = str(session.get(MFA_VERIFIED_SESSION_AT_KEY, "") or "").strip()
    return bool(session_user_id == actor.id and session_verified_at)


def require_client_wireguard_config_mfa():
    actor = current_actor()
    if not actor:
        abort(UNAUTHORIZED)
    impersonator = get_impersonator_user()
    if impersonator and impersonator.has_role(*STAFF_ROLES):
        return
    if not actor.has_role(User.ROLE_CLIENT):
        return
    if not actor.has_mfa():
        abort(FORBIDDEN, "Enable MFA in Profile before viewing or downloading your WireGuard configuration.")
    if not current_request_has_mfa_verification(actor):
        abort(FORBIDDEN, "Complete an MFA-authenticated login before viewing or downloading your WireGuard configuration.")


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


def build_log_diagnostics(max_tail_lines: int = 5000) -> Dict[str, Any]:
    logfile = logger_config.logfile
    diagnostics: Dict[str, Any] = {
        "available": False,
        "logfile": logfile,
        "total_lines": 0,
        "tail_lines": 0,
        "warning_lines": 0,
        "error_lines": 0,
        "suppressed_issue_lines": 0,
        "issue_entries": [],
        "tail_entries": [],
        "read_error": None,
        "auth_failures": 0,
        "interface_failures": 0,
        "tls_failures": 0,
        "rrd_failures": 0,
        "active_login_bans": sum(1 for client in clients.values() if client.is_banned()),
        "total": 0,
    }
    if not os.path.exists(logfile):
        diagnostics["total"] = diagnostics["active_login_bans"]
        return diagnostics

    tail: deque[str] = deque(maxlen=max_tail_lines)
    try:
        with open(logfile, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                diagnostics["total_lines"] += 1
                entry = line.strip()
                if not entry:
                    continue
                tail.append(entry)
    except OSError as e:
        diagnostics["read_error"] = str(e)
        diagnostics["total"] = diagnostics["active_login_bans"]
        return diagnostics

    issue_entries: List[str] = []
    for entry in tail:
        lowered = entry.lower()
        is_error = "[error]" in lowered or "[fatal]" in lowered
        is_warning = "[warning]" in lowered
        if any(pattern in lowered for pattern in LOG_AUTH_FAILURE_PATTERNS):
            diagnostics["auth_failures"] += 1
        if any(pattern in lowered for pattern in LOG_INTERFACE_FAILURE_PATTERNS):
            diagnostics["interface_failures"] += 1
        if any(pattern in lowered for pattern in LOG_TLS_FAILURE_PATTERNS):
            diagnostics["tls_failures"] += 1
        if any(pattern in lowered for pattern in LOG_RRD_FAILURE_PATTERNS):
            diagnostics["rrd_failures"] += 1
        if not is_error and not is_warning:
            continue
        if any(pattern in lowered for pattern in BENIGN_LOG_ISSUE_PATTERNS):
            diagnostics["suppressed_issue_lines"] += 1
            continue
        if is_error:
            diagnostics["error_lines"] += 1
        elif is_warning:
            diagnostics["warning_lines"] += 1
        issue_entries.append(entry)

    tail_entries = list(tail)
    diagnostics["tail_entries"] = tail_entries
    diagnostics["tail_lines"] = len(tail_entries)
    diagnostics["issue_entries"] = issue_entries
    diagnostics["available"] = True
    diagnostics["total"] = (
        diagnostics["auth_failures"]
        + diagnostics["interface_failures"]
        + diagnostics["tls_failures"]
        + diagnostics["rrd_failures"]
        + diagnostics["active_login_bans"]
    )
    return diagnostics


def get_failure_metrics(max_tail_lines: int = 5000) -> Dict[str, Any]:
    diagnostics = build_log_diagnostics(max_tail_lines=max_tail_lines)
    metrics: Dict[str, Any] = {
        "auth_failures": diagnostics["auth_failures"],
        "interface_failures": diagnostics["interface_failures"],
        "tls_failures": diagnostics["tls_failures"],
        "rrd_failures": diagnostics["rrd_failures"],
        "active_login_bans": diagnostics["active_login_bans"],
        "inspected_log_lines": diagnostics["tail_lines"],
        "log_available": diagnostics["available"],
        "total": diagnostics["total"],
    }
    return metrics


def normalize_statistics_diagnostic(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    if candidate in STATISTICS_DIAGNOSTIC_FILTERS:
        return candidate
    return ""


def categorize_log_entry(entry: str) -> str:
    lowered = entry.lower()
    if "[fatal]" in lowered or "[error]" in lowered:
        return "error"
    if "[warning]" in lowered:
        return "warning"
    return "info"


def matches_statistics_log_filter(entry: str, diagnostic: str) -> bool:
    lowered = entry.lower()
    if diagnostic == "all":
        return True
    if diagnostic == "warnings":
        return "[warning]" in lowered and not any(pattern in lowered for pattern in BENIGN_LOG_ISSUE_PATTERNS)
    if diagnostic == "errors":
        return ("[error]" in lowered or "[fatal]" in lowered) and not any(
            pattern in lowered for pattern in BENIGN_LOG_ISSUE_PATTERNS
        )
    if diagnostic == "auth":
        return any(pattern in lowered for pattern in LOG_AUTH_FAILURE_PATTERNS)
    if diagnostic == "interface":
        return any(pattern in lowered for pattern in LOG_INTERFACE_FAILURE_PATTERNS)
    if diagnostic == "tls":
        return any(pattern in lowered for pattern in LOG_TLS_FAILURE_PATTERNS)
    if diagnostic == "rrd":
        return any(pattern in lowered for pattern in LOG_RRD_FAILURE_PATTERNS)
    return False


def build_statistics_diagnostic_view(
        diagnostic: str,
        diagnostics: Dict[str, Any],
        peer_runtime: Dict[str, Any],
) -> Dict[str, Any]:
    selected = normalize_statistics_diagnostic(diagnostic)
    if not selected:
        return {
            "selected": "",
            "kind": "none",
            "title": "",
            "subtitle": "",
            "entries": [],
            "count": 0,
            "displayed_count": 0,
        }

    title = LOG_DIAGNOSTIC_LABELS[selected]
    if selected == "handshake":
        rows = [
            row for row in peer_runtime["rows"]
            if row["handshake_state"] in ("stale", "offline", "never")
        ]
        handshake_order = {"never": 0, "offline": 1, "stale": 2}
        rows.sort(key=lambda row: (handshake_order.get(row["handshake_state"], 3), row["peer_name"].lower()))
        entries = [{
            "peer_uuid": row["peer_uuid"],
            "peer_name": row["peer_name"],
            "interface_name": row["interface_name"],
            "handshake_state": row["handshake_state"],
            "handshake_label": row["handshake_state"].title(),
            "handshake_ago": row["handshake_ago"] or "Never",
            "seconds_since_handshake": row["seconds_since_handshake"],
            "message": f"{row['peer_name']} is {row['handshake_state']}.",
            "badge": "warning" if row["handshake_state"] == "stale" else "danger",
        } for row in rows]
        return {
            "selected": selected,
            "kind": "peers",
            "title": title,
            "subtitle": f"{len(entries)} peer(s) with stale, offline, or never-seen handshakes.",
            "entries": entries,
            "count": len(entries),
            "displayed_count": len(entries),
        }

    if selected == "bans":
        entries = []
        now = datetime.now()
        for client in sorted(clients.values(), key=lambda item: str(item.ip)):
            if not client.is_banned():
                continue
            remaining_seconds = max(int((client.banned_until - now).total_seconds()), 0)
            entries.append({
                "ip": str(client.ip),
                "login_attempts": client.login_attempts,
                "banned_for_seconds": remaining_seconds,
                "banned_until": client.banned_until.isoformat(),
            })
        return {
            "selected": selected,
            "kind": "bans",
            "title": title,
            "subtitle": f"{len(entries)} active login ban(s).",
            "entries": entries,
            "count": len(entries),
            "displayed_count": len(entries),
        }

    tail_entries = diagnostics.get("tail_entries", [])
    matched_entries = [
        entry for entry in tail_entries
        if matches_statistics_log_filter(entry, selected)
    ]
    if selected == "all":
        display_entries = matched_entries[-STATISTICS_DIAGNOSTIC_DISPLAY_LIMIT:]
        subtitle = (
            f"Showing the most recent {len(display_entries)} of {len(matched_entries)} log lines."
            if matched_entries else "No log lines available yet."
        )
    else:
        display_entries = matched_entries[-STATISTICS_DIAGNOSTIC_DISPLAY_LIMIT:]
        subtitle = (
            f"Showing {len(display_entries)} matching log line(s) from the inspected tail."
            if matched_entries else "No matching log lines found in the inspected tail."
        )
    start_line = max(int(diagnostics.get("total_lines", 0)) - len(tail_entries) + 1, 1)
    entries = []
    for index, entry in enumerate(tail_entries, start=start_line):
        if not matches_statistics_log_filter(entry, selected):
            continue
        entries.append({
            "line_number": index,
            "line": entry,
            "category": categorize_log_entry(entry),
        })
    entries = entries[-STATISTICS_DIAGNOSTIC_DISPLAY_LIMIT:]
    return {
        "selected": selected,
        "kind": LOG_DIAGNOSTIC_KINDS[selected],
        "title": title,
        "subtitle": subtitle,
        "entries": entries,
        "count": len(matched_entries),
        "displayed_count": len(entries),
    }


def build_statistics_payload(include_log_issues: bool = False, diagnostic_filter: str = "") -> Dict[str, Any]:
    diagnostics = build_log_diagnostics()
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
    log_summary = {
        "available": diagnostics["available"],
        "logfile": diagnostics["logfile"],
        "total_lines": diagnostics["total_lines"],
        "tail_lines": diagnostics["tail_lines"],
        "warning_lines": diagnostics["warning_lines"],
        "error_lines": diagnostics["error_lines"],
        "suppressed_issue_lines": diagnostics["suppressed_issue_lines"],
        "recent_issues": list(reversed(diagnostics["issue_entries"]))[:8] if include_log_issues else [],
        "read_error": diagnostics["read_error"],
    }
    failure_metrics = {
        "auth_failures": diagnostics["auth_failures"],
        "interface_failures": diagnostics["interface_failures"],
        "tls_failures": diagnostics["tls_failures"],
        "rrd_failures": diagnostics["rrd_failures"],
        "active_login_bans": diagnostics["active_login_bans"],
        "inspected_log_lines": diagnostics["tail_lines"],
        "log_available": diagnostics["available"],
        "total": diagnostics["total"],
    }
    diagnostic_view = build_statistics_diagnostic_view(diagnostic_filter, diagnostics, peer_runtime) if include_log_issues else {
        "selected": "",
        "kind": "none",
        "title": "",
        "subtitle": "",
        "entries": [],
        "count": 0,
        "displayed_count": 0,
    }

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
        "diagnostic_view": diagnostic_view,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope": "staff" if current_user.has_role(*STAFF_ROLES) else "client",
    }


@router.route("/statistics", methods=["GET"])
@login_required
@setup_required
def statistics():
    is_staff_view = current_user.has_role(*STAFF_ROLES)
    selected_diagnostic = normalize_statistics_diagnostic(request.args.get("diagnostic")) if is_staff_view else ""
    payload = build_statistics_payload(
        include_log_issues=is_staff_view,
        diagnostic_filter=selected_diagnostic,
    )
    diagnostic_links = {}
    if is_staff_view:
        diagnostic_links = {
            "clear": url_for("router.statistics"),
            "handshake": url_for("router.statistics", diagnostic="handshake"),
            "auth": url_for("router.statistics", diagnostic="auth"),
            "interface": url_for("router.statistics", diagnostic="interface"),
            "tls": url_for("router.statistics", diagnostic="tls"),
            "rrd": url_for("router.statistics", diagnostic="rrd"),
            "bans": url_for("router.statistics", diagnostic="bans"),
            "warnings": url_for("router.statistics", diagnostic="warnings"),
            "errors": url_for("router.statistics", diagnostic="errors"),
            "all": url_for("router.statistics", diagnostic="all"),
        }
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
        "diagnostic_view": payload["diagnostic_view"],
        "diagnostic_links": diagnostic_links,
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
        "disabled_peers": 0,
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
        last_handshake = traffic.last_handshake
        seconds_ago = None
        if not peer.enabled:
            handshake_state = "disabled"
            handshake_badge = "secondary"
            totals["disabled_peers"] += 1
        elif traffic.last_handshake:
            handshake_state = "never"
            handshake_badge = "secondary"
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
            handshake_state = "never"
            handshake_badge = "secondary"
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
            "enabled": peer.enabled,
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

        if peer.enabled and peer.mode == Peer.MODE_SITE_TO_SITE and handshake_state in ("never", "offline", "stale"):
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
        elif peer.enabled and peer.mode != Peer.MODE_SITE_TO_SITE and handshake_state == "offline":
            alerts.append({
                "level": "warning",
                "title": "Client peer appears offline",
                "peer_uuid": peer.uuid,
                "peer_name": peer.name,
                "message": f"{peer.name} has not handshaken recently."
            })

        if peer.enabled and high_traffic:
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
        "disabled_peers": 0,
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
        if not row.get("enabled", True):
            totals["disabled_peers"] += 1
        elif row["handshake_state"] == "active":
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
    if current_user.has_role(User.ROLE_TENANT_ADMIN):
        actor_tenant_id = get_actor_tenant_id(current_user)
        rows = []
        alerts = []
        for row in runtime["rows"]:
            peer = get_all_peers().get(row["peer_uuid"], None)
            if peer and actor_tenant_id and resolve_peer_tenant_id(peer) == actor_tenant_id:
                rows.append(row)
        allowed_peer_ids = {row["peer_uuid"] for row in rows}
        for alert in runtime["alerts"]:
            peer_uuid = str(alert.get("peer_uuid", "") or "").strip()
            if peer_uuid and peer_uuid in allowed_peer_ids:
                alerts.append(alert)
        return {
            "totals": calculate_peer_runtime_totals(rows, alerts),
            "rows": rows,
            "alerts": alerts,
            "thresholds": runtime["thresholds"]
        }
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
    if current_user.has_role(User.ROLE_TENANT_ADMIN):
        return {iface.uuid: iface for iface in get_accessible_interfaces(current_user)}
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
    diagnostics = build_log_diagnostics(max_tail_lines=max_tail_lines)
    summary: Dict[str, Any] = {
        "available": diagnostics["available"],
        "logfile": diagnostics["logfile"],
        "total_lines": diagnostics["total_lines"],
        "tail_lines": diagnostics["tail_lines"],
        "warning_lines": diagnostics["warning_lines"],
        "error_lines": diagnostics["error_lines"],
        "suppressed_issue_lines": diagnostics["suppressed_issue_lines"],
        "recent_issues": list(reversed(diagnostics["issue_entries"]))[:8] if include_recent_issues else [],
        "read_error": diagnostics["read_error"],
    }
    return summary


def get_audit_events(max_tail_lines: int = 5000) -> List[Dict[str, Any]]:
    logfile = logger_config.logfile
    tail: deque[str] = deque(maxlen=max_tail_lines)
    if os.path.exists(logfile):
        try:
            with open(logfile, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    entry = line.strip()
                    if entry:
                        tail.append(entry)
        except OSError:
            pass
    events: List[Dict[str, Any]] = []
    for entry in tail:
        if "[AUDIT]" not in entry:
            continue
        _, _, payload = entry.partition("[AUDIT]")
        candidate = payload.strip()
        if not candidate:
            continue
        try:
            event = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        event["signature_valid"] = audit_signature_valid(event)
        events.append(event)
    merged: List[Dict[str, Any]] = []
    seen = set()
    for event in list(reversed(recent_audit_events_memory)) + list(reversed(events)):
        key = (
            event.get("created_at"),
            event.get("request_id"),
            event.get("action"),
            event.get("status"),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(event)
    return merged


def build_global_config_payload() -> Dict[str, Any]:
    return {
        "logger": {
            "level": logger_config.level,
            "overwrite": logger_config.overwrite,
            "logfile": logger_config.logfile,
        },
        "web": {
            "login_attempts": web_config.login_attempts,
            "login_ban_time": web_config.login_ban_time,
            "tls_mode": web_config.tls_mode,
            "tls_server_name": web_config.tls_server_name,
            "tls_letsencrypt_email": web_config.tls_letsencrypt_email,
            "proxy_incoming_hostname": web_config.proxy_incoming_hostname,
            "redirect_http_to_https": web_config.redirect_http_to_https,
            "http_port": web_config.http_port,
            "https_port": web_config.https_port,
        },
        "wireguard": {
            "endpoint": wireguard_config.endpoint,
            "wg_bin": wireguard_config.wg_bin,
            "wg_quick_bin": wireguard_config.wg_quick_bin,
            "iptables_bin": wireguard_config.iptables_bin,
            "interfaces_folder": wireguard_config.interfaces_folder,
        },
        "traffic": {
            "enabled": traffic_config.enabled,
            "driver": traffic_config.driver.get_name(),
            "driver_options": traffic_config.driver.__to_yaml_dict__(),
        },
    }


def update_global_config_from_payload(payload: Dict[str, Any]):
    from arpvpn.core.managers import traffic_storage

    logger_payload = payload.get("logger", {})
    if logger_payload:
        logger_config.level = parse_optional_string(logger_payload.get("level", logger_config.level)) or logger_config.level
        logger_config.overwrite = parse_boolean_value(logger_payload.get("overwrite", logger_config.overwrite), logger_config.overwrite)

    web_payload = payload.get("web", {})
    if web_payload:
        web_config.login_attempts = parse_integer_value(
            web_payload.get("login_attempts", web_config.login_attempts),
            "web.login_attempts",
            minimum=0,
            maximum=1000,
        )
        web_config.login_ban_time = parse_integer_value(
            web_payload.get("login_ban_time", web_config.login_ban_time),
            "web.login_ban_time",
            minimum=0,
            maximum=86400,
        )
        tls_mode = parse_optional_string(web_payload.get("tls_mode", web_config.tls_mode)) or web_config.tls_mode
        if tls_mode not in web_config.TLS_MODES:
            abort(BAD_REQUEST, "web.tls_mode is invalid.")
        web_config.tls_mode = tls_mode
        web_config.tls_server_name = parse_optional_string(web_payload.get("tls_server_name", web_config.tls_server_name))
        web_config.tls_letsencrypt_email = parse_optional_string(
            web_payload.get("tls_letsencrypt_email", web_config.tls_letsencrypt_email)
        )
        web_config.proxy_incoming_hostname = parse_optional_string(
            web_payload.get("proxy_incoming_hostname", web_config.proxy_incoming_hostname)
        )
        web_config.redirect_http_to_https = parse_boolean_value(
            web_payload.get("redirect_http_to_https", web_config.redirect_http_to_https),
            web_config.redirect_http_to_https,
        )
        web_config.http_port = parse_integer_value(
            web_payload.get("http_port", web_config.http_port),
            "web.http_port",
            minimum=web_config.MIN_PORT,
            maximum=web_config.MAX_PORT,
        )
        web_config.https_port = parse_integer_value(
            web_payload.get("https_port", web_config.https_port),
            "web.https_port",
            minimum=web_config.MIN_PORT,
            maximum=web_config.MAX_PORT,
        )
        if web_config.tls_mode == web_config.TLS_MODE_HTTP and web_config.redirect_http_to_https:
            abort(BAD_REQUEST, "HTTP redirect requires a TLS mode other than http.")
        if web_config.tls_mode == web_config.TLS_MODE_SELF_SIGNED and web_config.tls_server_name:
            if not is_valid_tls_server_name(web_config.tls_server_name, allow_ipv4=True, allow_localhost=True):
                abort(BAD_REQUEST, "web.tls_server_name must be a valid IPv4 or fully-qualified hostname.")
        if web_config.tls_mode == web_config.TLS_MODE_LETS_ENCRYPT and web_config.tls_server_name:
            if not is_valid_tls_server_name(web_config.tls_server_name, allow_ipv4=False, allow_localhost=False):
                abort(BAD_REQUEST, "web.tls_server_name must be a fully-qualified hostname for Let's Encrypt.")

    wireguard_payload = payload.get("wireguard", {})
    if wireguard_payload:
        web_endpoint = parse_optional_string(wireguard_payload.get("endpoint", wireguard_config.endpoint))
        if web_endpoint:
            wireguard_config.endpoint = web_endpoint
        wg_bin = parse_optional_string(wireguard_payload.get("wg_bin", wireguard_config.wg_bin))
        wg_quick_bin = parse_optional_string(wireguard_payload.get("wg_quick_bin", wireguard_config.wg_quick_bin))
        iptables_bin = parse_optional_string(wireguard_payload.get("iptables_bin", wireguard_config.iptables_bin))
        if wg_bin:
            wireguard_config.wg_bin = wg_bin
        if wg_quick_bin:
            wireguard_config.wg_quick_bin = wg_quick_bin
        if iptables_bin:
            wireguard_config.iptables_bin = iptables_bin

    traffic_payload = payload.get("traffic", {})
    if traffic_payload:
        traffic_config.enabled = parse_boolean_value(traffic_payload.get("enabled", traffic_config.enabled), traffic_config.enabled)
        driver_name = parse_optional_string(traffic_payload.get("driver", traffic_config.driver.get_name())) or traffic_config.driver.get_name()
        if driver_name not in traffic_storage.registered_drivers:
            abort(BAD_REQUEST, "traffic.driver is invalid.")
        driver_options = traffic_payload.get("driver_options", traffic_config.driver.__to_yaml_dict__())
        if not isinstance(driver_options, dict):
            abort(BAD_REQUEST, "traffic.driver_options must be an object.")
        driver_template = traffic_storage.registered_drivers[driver_name]
        traffic_config.driver = driver_template.__from_yaml_dict__(driver_options)

    tls_manager.apply_web_tls_config(web_config, generate_self_signed=False, issue_letsencrypt=False)
    config_manager.save()


def build_system_health_payload() -> Dict[str, Any]:
    from arpvpn import __version__

    return {
        "status": "ok",
        "release": getattr(__version__, "release", "unknown"),
        "commit": getattr(__version__, "commit", "unknown"),
        "scope": current_scope_label(),
        "setup_required": bool(global_properties.setup_required and not global_properties.setup_file_exists()),
        "uptime_seconds": int((datetime.now(timezone.utc) - PROCESS_STARTED_AT).total_seconds()),
        "http_port": web_config.http_port,
        "https_port": web_config.https_port,
        "tls_mode": web_config.tls_mode,
        "interfaces_total": len(interfaces),
        "peers_total": len(get_all_peers()),
    }


def build_system_diagnostics_payload() -> Dict[str, Any]:
    from arpvpn import __version__

    return {
        "release": getattr(__version__, "release", "unknown"),
        "commit": getattr(__version__, "commit", "unknown"),
        "workdir": global_properties.workdir,
        "http_port": web_config.http_port,
        "https_port": web_config.https_port,
        "tls_mode": web_config.tls_mode,
        "tls_server_name": web_config.tls_server_name,
        "wireguard": {
            "endpoint": wireguard_config.endpoint,
            "wg_bin": wireguard_config.wg_bin,
            "wg_bin_exists": bool(wireguard_config.wg_bin and os.path.exists(wireguard_config.wg_bin)),
            "wg_quick_bin": wireguard_config.wg_quick_bin,
            "wg_quick_bin_exists": bool(wireguard_config.wg_quick_bin and os.path.exists(wireguard_config.wg_quick_bin)),
            "iptables_bin": wireguard_config.iptables_bin,
            "iptables_bin_exists": bool(wireguard_config.iptables_bin and os.path.exists(wireguard_config.iptables_bin)),
            "interfaces_folder": wireguard_config.interfaces_folder,
        },
        "traffic": {
            "enabled": traffic_config.enabled,
            "driver": traffic_config.driver.get_name(),
        },
        "interfaces_total": len(interfaces),
        "peers_total": len(get_all_peers()),
        "log_summary": get_log_summary(include_recent_issues=True),
    }


def build_network_inventory_payload() -> Dict[str, Any]:
    wg_ifaces = list(interfaces.values())
    inventory = list(get_network_ifaces(wg_ifaces).values())
    inventory.sort(key=lambda item: item["name"])
    return {
        "scope": current_scope_label(),
        "interfaces": inventory,
        "routes": get_routing_table(),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def build_about_payload() -> Dict[str, Any]:
    from arpvpn import __version__

    return {
        "product": {
            "name": APP_NAME,
            "vendor": "ARPHost",
            "release": getattr(__version__, "release", "unknown"),
            "commit": getattr(__version__, "commit", "unknown"),
            "scope": current_scope_label(),
        },
        "arp_host": {
            "summary": "ARPHost packages and operates ARPVPN for customer VPN management, observability, and hosted delivery.",
            "documentation_url": url_for("router.documentation", _external=False),
        },
        "wireguard": {
            "summary": "WireGuard is a modern VPN protocol focused on simplicity, performance, and strong cryptography.",
            "endpoint": wireguard_config.endpoint,
            "interfaces_total": len(interfaces),
            "peers_total": len(get_all_peers()),
        },
        "system": build_system_health_payload(),
    }


def build_profile_payload(user_item: Optional[User] = None) -> Dict[str, Any]:
    user_item = user_item or current_user
    tenant = tenants.get(getattr(user_item, "tenant_id", "") or "", None)
    login_date = getattr(user_item, "login_date", None)
    return {
        "user": {
            "id": getattr(user_item, "id", ""),
            "username": getattr(user_item, "name", ""),
            "role": getattr(user_item, "role", ""),
            "tenant_id": getattr(user_item, "tenant_id", None),
            "tenant_name": tenant.name if tenant else None,
            "login_at": login_date.isoformat() if login_date else None,
            "login_ago": get_time_ago(login_date) if login_date else None,
            "is_impersonating": is_impersonating(),
        }
    }


def update_profile_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    username = parse_non_empty_string(payload.get("username"), "username")
    existing = users.get_value_by_attr("name", username)
    if existing and existing.id != current_user.id:
        abort(CONFLICT, "Username already exists.")
    current_user.name = username
    config_manager.save_credentials()
    log_audit_event("profile.update", details={"target_user_id": current_user.id, "target_user_name": username})
    return build_profile_payload()


def update_profile_password_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    old_password = parse_non_empty_string(payload.get("old_password"), "old_password")
    new_password = parse_non_empty_string(payload.get("new_password"), "new_password")
    confirm = parse_non_empty_string(payload.get("confirm"), "confirm")
    if not current_user.check_password(old_password):
        abort(FORBIDDEN, "old_password is incorrect.")
    if new_password != confirm:
        abort(BAD_REQUEST, "confirm must match new_password.")
    if current_user.check_password(new_password):
        abort(BAD_REQUEST, "new_password cannot be the same as the current password.")
    current_user.password = new_password
    config_manager.save_credentials()
    log_audit_event("profile.password.update", details={"target_user_id": current_user.id})
    return build_profile_payload()


def build_setup_status_payload() -> Dict[str, Any]:
    return {
        "setup_required": bool(global_properties.setup_required and not global_properties.setup_file_exists()),
        "setup_file_exists": global_properties.setup_file_exists(),
        "defaults": {
            "wireguard": {
                "endpoint": wireguard_config.endpoint,
                "wg_bin": wireguard_config.wg_bin,
                "wg_quick_bin": wireguard_config.wg_quick_bin,
                "iptables_bin": wireguard_config.iptables_bin,
            },
            "tls": {
                "mode": web_config.TLS_MODE_SELF_SIGNED,
                "server_name": web_config.tls_server_name or wireguard_config.endpoint,
                "redirect_http_to_https": web_config.redirect_http_to_https,
            },
            "traffic_enabled": traffic_config.enabled,
            "log_overwrite": logger_config.overwrite,
        },
    }


def apply_setup_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if global_properties.setup_file_exists():
        abort(BAD_REQUEST, "Setup already performed.")
    logger_config.overwrite = parse_boolean_value(payload.get("log_overwrite"), logger_config.overwrite)
    traffic_config.enabled = parse_boolean_value(payload.get("traffic_enabled"), traffic_config.enabled)

    wireguard_payload = payload.get("wireguard", {})
    tls_payload = payload.get("tls", {})
    if not isinstance(wireguard_payload, dict):
        abort(BAD_REQUEST, "wireguard must be an object.")
    if not isinstance(tls_payload, dict):
        abort(BAD_REQUEST, "tls must be an object.")

    wireguard_config.endpoint = parse_non_empty_string(wireguard_payload.get("endpoint"), "wireguard.endpoint")
    wireguard_config.wg_bin = parse_non_empty_string(wireguard_payload.get("wg_bin"), "wireguard.wg_bin")
    wireguard_config.wg_quick_bin = parse_non_empty_string(
        wireguard_payload.get("wg_quick_bin"),
        "wireguard.wg_quick_bin",
    )
    wireguard_config.iptables_bin = parse_non_empty_string(
        wireguard_payload.get("iptables_bin"),
        "wireguard.iptables_bin",
    )

    mode = parse_tls_mode(tls_payload.get("mode"))
    server_name = str(tls_payload.get("server_name", wireguard_config.endpoint) or "").strip()
    letsencrypt_email = str(tls_payload.get("letsencrypt_email", web_config.tls_letsencrypt_email) or "").strip()
    proxy_incoming_hostname = str(
        tls_payload.get("proxy_incoming_hostname", web_config.proxy_incoming_hostname) or ""
    ).strip()
    redirect_http_to_https = parse_boolean_value(
        tls_payload.get("redirect_http_to_https"),
        web_config.redirect_http_to_https,
    )
    generate_self_signed = parse_boolean_value(tls_payload.get("generate_self_signed"), mode == web_config.TLS_MODE_SELF_SIGNED)
    issue_letsencrypt = parse_boolean_value(tls_payload.get("issue_letsencrypt"), False)

    requires_hostname = mode in (web_config.TLS_MODE_SELF_SIGNED, web_config.TLS_MODE_LETS_ENCRYPT)
    if requires_hostname:
        server_name = parse_tls_server_name(
            server_name,
            allow_ipv4=mode == web_config.TLS_MODE_SELF_SIGNED,
            allow_localhost=mode == web_config.TLS_MODE_SELF_SIGNED,
            field_name="tls.server_name",
        )
    if mode == web_config.TLS_MODE_REVERSE_PROXY:
        proxy_incoming_hostname = parse_tls_server_name(
            proxy_incoming_hostname,
            allow_ipv4=False,
            allow_localhost=True,
            field_name="tls.proxy_incoming_hostname",
        )
    if redirect_http_to_https and mode == web_config.TLS_MODE_HTTP:
        abort(BAD_REQUEST, "tls.redirect_http_to_https requires a TLS mode other than http.")
    if generate_self_signed and mode != web_config.TLS_MODE_SELF_SIGNED:
        abort(BAD_REQUEST, "tls.generate_self_signed requires self-signed TLS mode.")
    if issue_letsencrypt and mode != web_config.TLS_MODE_LETS_ENCRYPT:
        abort(BAD_REQUEST, "tls.issue_letsencrypt requires letsencrypt TLS mode.")

    web_config.tls_mode = mode
    web_config.tls_server_name = server_name
    web_config.tls_letsencrypt_email = letsencrypt_email
    web_config.proxy_incoming_hostname = proxy_incoming_hostname
    web_config.redirect_http_to_https = redirect_http_to_https and mode != web_config.TLS_MODE_HTTP

    tls_manager.apply_web_tls_config(
        web_config,
        generate_self_signed=generate_self_signed,
        issue_letsencrypt=issue_letsencrypt,
    )
    config_manager.save()
    with open(global_properties.setup_filepath, "w", encoding="utf-8") as handle:
        handle.write("")
    log_audit_event("system.setup.bootstrap", details={"tls_mode": mode, "endpoint": wireguard_config.endpoint})
    return build_setup_status_payload()


def _process_name(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as handle:
            return handle.read().strip().lower()
    except OSError:
        return ""


def _write_restart_marker(reason: str, requested_mode: str) -> str:
    marker_path = global_properties.join_workdir("restart-request.json")
    os.makedirs(os.path.dirname(marker_path), exist_ok=True)
    with open(marker_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "requested_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "requested_by_user_id": getattr(current_user, "id", ""),
                "requested_by_user_name": getattr(current_user, "name", ""),
                "reason": reason,
                "requested_mode": requested_mode,
            },
            handle,
            indent=2,
            sort_keys=True,
        )
    return marker_path


def request_process_restart(reason: str, requested_mode: str = "auto", delay_seconds: int = 1) -> Dict[str, Any]:
    handler = current_app.config.get("ARPVPN_RESTART_HANDLER")
    if callable(handler):
        return handler(reason=reason, requested_mode=requested_mode, delay_seconds=delay_seconds)

    mode = str(requested_mode or "auto").strip().lower() or "auto"
    delay_seconds = max(0, int(delay_seconds))
    parent_pid = os.getppid()
    parent_name = _process_name(parent_pid)
    target_pid = None
    signal_mode = None
    if mode in ("auto", "parent") and "uwsgi" in parent_name:
        target_pid = parent_pid
        signal_mode = "parent-hup"
    elif mode == "self":
        target_pid = os.getpid()
        signal_mode = "self-hup"

    if target_pid is not None:
        def _dispatch_restart():
            sleep(max(1, delay_seconds))
            try:
                os.kill(target_pid, signal.SIGHUP)
            except OSError as exc:
                error(f"Unable to signal restart target {target_pid}: {exc}")

        Thread(target=_dispatch_restart, daemon=True).start()
        return {
            "requested": True,
            "mode": signal_mode,
            "target_pid": target_pid,
            "delay_seconds": delay_seconds,
            "reason": reason,
        }

    marker_path = _write_restart_marker(reason, mode)
    return {
        "requested": True,
        "mode": "marker",
        "target_pid": None,
        "delay_seconds": delay_seconds,
        "reason": reason,
        "marker_path": marker_path,
    }


def _render_rrd_graph_png(uuid: str, window_seconds: int) -> Optional[bytes]:
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


def _rrd_graph_cache_path(uuid: str, window_seconds: int) -> str:
    cache_dir = global_properties.join_workdir(RRD_GRAPH_CACHE_DIRNAME)
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, f"{uuid}-{window_seconds}.png")


def _rrd_graph_cache_lock(cache_path: str) -> Lock:
    with RRD_GRAPH_CACHE_LOCKS_LOCK:
        lock = RRD_GRAPH_CACHE_LOCKS.get(cache_path)
        if lock is None:
            lock = Lock()
            RRD_GRAPH_CACHE_LOCKS[cache_path] = lock
        return lock


def _load_rrd_graph_cache(cache_path: str) -> Optional[bytes]:
    if not os.path.exists(cache_path):
        return None
    if RRD_GRAPH_CACHE_TTL_SECONDS > 0:
        age_seconds = max(0.0, time() - os.path.getmtime(cache_path))
        if age_seconds > RRD_GRAPH_CACHE_TTL_SECONDS:
            return None
    with open(cache_path, "rb") as handle:
        return handle.read()


def _store_rrd_graph_cache(cache_path: str, png_data: bytes):
    cache_dir = os.path.dirname(cache_path)
    os.makedirs(cache_dir, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=cache_dir, suffix=".tmp", delete=False) as handle:
        handle.write(png_data)
        temp_path = handle.name
    os.replace(temp_path, cache_path)


def generate_rrd_graph_png(uuid: str, window_seconds: int) -> Optional[bytes]:
    if RRD_GRAPH_CACHE_TTL_SECONDS <= 0:
        return _render_rrd_graph_png(uuid, window_seconds)

    cache_path = _rrd_graph_cache_path(uuid, window_seconds)
    cached_png = _load_rrd_graph_cache(cache_path)
    if cached_png is not None:
        return cached_png

    lock = _rrd_graph_cache_lock(cache_path)
    with lock:
        cached_png = _load_rrd_graph_cache(cache_path)
        if cached_png is not None:
            return cached_png
        try:
            png_data = _render_rrd_graph_png(uuid, window_seconds)
        except RuntimeError:
            if os.path.exists(cache_path):
                warning(f"Serving stale cached RRD graph for {uuid} ({window_seconds}s) after render failure.")
                with open(cache_path, "rb") as handle:
                    return handle.read()
            raise
        if png_data is None:
            return None
        _store_rrd_graph_cache(cache_path, png_data)
        return png_data


def serialize_peer_runtime_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "peer_uuid": row["peer_uuid"],
        "peer_name": row["peer_name"],
        "interface_uuid": row["interface_uuid"],
        "interface_name": row["interface_name"],
        "mode": row["mode"],
        "mode_label": row["mode_label"],
        "enabled": row["enabled"],
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
        writer.writerow({field: row.get(field) for field in fieldnames})
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


def get_tenant_tls_settings(tenant: Tenant) -> Dict[str, Any]:
    tenant_settings = copy.deepcopy(getattr(tenant, "settings", {}) or {})
    tls_settings = tenant_settings.get("tls", {})
    if not isinstance(tls_settings, dict):
        tls_settings = {}
    normalized = default_tenant_tls_settings()
    normalized.update(parse_tenant_tls_settings(tls_settings))
    return normalized


def build_tenant_tls_status_payload(tenant: Tenant) -> Dict[str, Any]:
    settings = get_tenant_tls_settings(tenant)
    return {
        "scope": "tenant",
        "tenant_id": tenant.id,
        "tenant_name": tenant.name,
        "mode": settings["mode"],
        "available_modes": list(web_config.TLS_MODES),
        "server_name": settings["server_name"],
        "letsencrypt_email": settings["letsencrypt_email"],
        "redirect_http_to_https": settings["redirect_http_to_https"],
        "proxy_incoming_hostname": settings["proxy_incoming_hostname"],
        "certificate_provider": settings["certificate_provider"],
        "applied": settings["applied"],
        "note": "Tenant TLS settings are stored for tenant-scoped deployments and separate tenant runtime stacks.",
    }


def get_tenant_runtime_settings(tenant: Tenant) -> Dict[str, Any]:
    tenant_settings = copy.deepcopy(getattr(tenant, "settings", {}) or {})
    runtime_settings = tenant_settings.get("runtime", {})
    if not isinstance(runtime_settings, dict):
        runtime_settings = {}
    normalized = default_tenant_runtime_settings(tenant)
    normalized.update(parse_tenant_runtime_settings(runtime_settings, tenant))
    return normalized


def build_tenant_runtime_payload(tenant: Tenant) -> Dict[str, Any]:
    runtime = get_tenant_runtime_settings(tenant)
    return {
        "scope": "tenant",
        "tenant_id": tenant.id,
        "tenant_name": tenant.name,
        "runtime": runtime,
        "control_plane_only": True,
        "note": "Runtime allocation/status is an ARPVPN control-plane record for separate tenant VPN stacks.",
    }


def system_backup_file_targets() -> Dict[str, str]:
    return {
        "config": config_manager.config_filepath,
        "credentials": web_config.credentials_file,
        "tenants": web_config.tenants_file,
        "invitations": web_config.invitations_file,
    }


def read_backup_target(path: str) -> Dict[str, Any]:
    exists = bool(path) and os.path.exists(path)
    if not exists:
        return {
            "exists": False,
            "size_bytes": 0,
            "sha256": None,
            "content_b64": "",
        }
    with open(path, "rb") as handle:
        content = handle.read()
    return {
        "exists": True,
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "content_b64": base64.b64encode(content).decode("ascii"),
    }


def build_system_backup_payload() -> Dict[str, Any]:
    from arpvpn import __version__

    files = {
        label: {
            "path": path,
            **read_backup_target(path),
        }
        for label, path in system_backup_file_targets().items()
    }
    return {
        "format": API_BACKUP_FORMAT,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "release": getattr(__version__, "release", "unknown"),
        "commit": getattr(__version__, "commit", "unknown"),
        "workdir": global_properties.workdir,
        "files": files,
    }


def parse_system_backup_payload(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    backup = payload.get("backup", payload)
    if not isinstance(backup, dict):
        abort(BAD_REQUEST, "backup must be an object.")
    if str(backup.get("format", "") or "").strip() != API_BACKUP_FORMAT:
        abort(BAD_REQUEST, "Unsupported backup format.")
    raw_files = backup.get("files", {})
    if not isinstance(raw_files, dict):
        abort(BAD_REQUEST, "backup.files must be an object.")
    parsed: Dict[str, Dict[str, Any]] = {}
    for label, target_path in system_backup_file_targets().items():
        entry = raw_files.get(label, {})
        if not isinstance(entry, dict):
            abort(BAD_REQUEST, f"backup.files.{label} must be an object.")
        exists = bool(entry.get("exists", False))
        content_b64 = str(entry.get("content_b64", "") or "")
        content = b""
        if exists:
            try:
                content = base64.b64decode(content_b64.encode("ascii"), validate=True)
            except Exception:
                abort(BAD_REQUEST, f"backup.files.{label}.content_b64 is invalid.")
            expected_sha = str(entry.get("sha256", "") or "").strip().lower()
            if expected_sha:
                actual_sha = hashlib.sha256(content).hexdigest()
                if actual_sha != expected_sha:
                    abort(BAD_REQUEST, f"backup.files.{label}.sha256 does not match content.")
            if label == "config":
                try:
                    loaded_docs = list(yaml.safe_load_all(content.decode("utf-8")))
                except Exception as exc:
                    abort(BAD_REQUEST, f"backup.files.config could not be parsed: {exc}")
                if not loaded_docs or not isinstance(loaded_docs[0], dict):
                    abort(BAD_REQUEST, "backup.files.config must contain a valid configuration document.")
        parsed[label] = {
            "path": target_path,
            "exists": exists,
            "content": content,
            "size_bytes": len(content),
        }
    return parsed


def apply_system_backup_payload(backup_files: Dict[str, Dict[str, Any]]):
    previous_state = {
        label: {
            "path": target["path"],
            **read_backup_target(target["path"]),
        }
        for label, target in backup_files.items()
    }
    try:
        for target in backup_files.values():
            target_path = target["path"]
            parent = os.path.dirname(target_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            if target["exists"]:
                with open(target_path, "wb") as handle:
                    handle.write(target["content"])
            elif os.path.exists(target_path):
                os.remove(target_path)
        config_manager.reload_from_disk()
    except Exception:
        for previous in previous_state.values():
            target_path = previous["path"]
            parent = os.path.dirname(target_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            if previous["exists"]:
                restored_content = base64.b64decode(previous["content_b64"].encode("ascii"))
                with open(target_path, "wb") as handle:
                    handle.write(restored_content)
            elif os.path.exists(target_path):
                os.remove(target_path)
        config_manager.reload_from_disk()
        raise


def parse_json_payload(allow_empty: bool = False) -> Dict[str, Any]:
    payload = request.get_json(silent=True)
    if payload is None and allow_empty:
        payload = {}
    if not isinstance(payload, dict):
        abort(BAD_REQUEST, "Invalid payload.")
    endpoint_name = str(request.endpoint or "").rsplit(".", 1)[-1]
    schema = get_api_request_schema(endpoint_name)
    if schema is not None:
        try:
            payload = schema.validate(payload)
        except ApiSchemaValidationError as exc:
            abort(BAD_REQUEST, str(exc))
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


def actor_is_global_staff(actor: Optional[User] = None) -> bool:
    actor = actor or current_actor()
    return bool(actor and actor.has_role(User.ROLE_ADMIN, User.ROLE_SUPPORT))


def actor_is_tenant_admin(actor: Optional[User] = None) -> bool:
    actor = actor or current_actor()
    return bool(actor and actor.has_role(User.ROLE_TENANT_ADMIN))


def get_actor_tenant_id(actor: Optional[User] = None) -> Optional[str]:
    actor = actor or current_actor()
    tenant_id = getattr(actor, "tenant_id", None) if actor else None
    return str(tenant_id or "").strip() or None


def sync_invitation_status(invitation: Invitation) -> str:
    current_status = invitation.current_status()
    if current_status != invitation.status:
        invitation.status = current_status
        invitation.touch()
    return current_status


def actor_can_access_tenant(tenant_id: Optional[str], actor: Optional[User] = None) -> bool:
    actor = actor or current_actor()
    if not actor:
        return False
    if actor_is_global_staff(actor):
        return True
    actor_tenant_id = get_actor_tenant_id(actor)
    return actor_tenant_id is not None and actor_tenant_id == str(tenant_id or "").strip()


def tenant_visible_to_actor(tenant: Tenant, actor: Optional[User] = None) -> bool:
    return actor_can_access_tenant(tenant.id, actor)


def user_visible_to_actor(user_item: User, actor: Optional[User] = None) -> bool:
    actor = actor or current_actor()
    if not actor:
        return False
    if actor_is_global_staff(actor):
        return True
    if actor_is_tenant_admin(actor):
        actor_tenant_id = get_actor_tenant_id(actor)
        return actor_tenant_id is not None and user_item.tenant_id == actor_tenant_id
    return actor.id == user_item.id


def invitation_visible_to_actor(invitation: Invitation, actor: Optional[User] = None) -> bool:
    return actor_can_access_tenant(invitation.tenant_id, actor)


def get_accessible_tenants(actor: Optional[User] = None) -> List[Tenant]:
    actor = actor or current_actor()
    items = [tenant for tenant in tenants.values() if tenant_visible_to_actor(tenant, actor)]
    items.sort(key=lambda tenant: tenant.name.lower())
    return items


def get_accessible_users(actor: Optional[User] = None) -> List[User]:
    actor = actor or current_actor()
    items = [user_item for user_item in users.values() if user_visible_to_actor(user_item, actor)]
    items.sort(key=lambda user_item: (user_item.role, user_item.name.lower()))
    return items


def get_accessible_invitations(actor: Optional[User] = None) -> List[Invitation]:
    actor = actor or current_actor()
    items: List[Invitation] = []
    for invitation in invitations.values():
        sync_invitation_status(invitation)
        if invitation_visible_to_actor(invitation, actor):
            items.append(invitation)
    items.sort(key=lambda invitation: (invitation.current_status(), invitation.email))
    return items


def tenant_to_api_dict(tenant: Tenant) -> Dict[str, Any]:
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "domains": list(tenant.domains),
        "ips": list(tenant.ips),
        "status": tenant.status,
        "description": tenant.description,
        "settings": copy.deepcopy(getattr(tenant, "settings", {}) or {}),
        "created_at": tenant.created_at,
        "updated_at": tenant.updated_at,
    }


def user_to_api_dict(user_item: User) -> Dict[str, Any]:
    return {
        "id": user_item.id,
        "username": user_item.name,
        "role": user_item.role,
        "tenant_id": user_item.tenant_id,
    }


def invitation_to_api_dict(invitation: Invitation, raw_token: str = "") -> Dict[str, Any]:
    tenant = tenants.get(invitation.tenant_id, None)
    payload: Dict[str, Any] = {
        "id": invitation.id,
        "tenant_id": invitation.tenant_id,
        "tenant_name": tenant.name if tenant else None,
        "email": invitation.email,
        "role": invitation.role,
        "status": invitation.current_status(),
        "invited_by_user_id": invitation.invited_by_user_id,
        "accepted_user_id": invitation.accepted_user_id or None,
        "created_at": invitation.created_at,
        "updated_at": invitation.updated_at,
        "last_sent_at": invitation.last_sent_at,
        "expires_at": invitation.expires_at,
        "sent_count": invitation.sent_count,
        "accept_endpoint": url_for("router.api_accept_invitation", invitation_id=invitation.id, _external=False),
    }
    if raw_token:
        payload["accept_token"] = raw_token
    return payload


def parse_non_empty_string(value: Any, field_name: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        abort(BAD_REQUEST, f"{field_name} is required.")
    return candidate


def parse_optional_string(value: Any) -> str:
    return str(value or "").strip()


def parse_email_address(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    if not candidate:
        abort(BAD_REQUEST, "email is required.")
    if not EMAIL_ADDRESS_PATTERN.fullmatch(candidate):
        abort(BAD_REQUEST, "email must be a valid email address.")
    return candidate


def parse_string_list_value(value: Any, field_name: str) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = value.split(",")
    elif isinstance(value, list):
        values = value
    else:
        abort(BAD_REQUEST, f"{field_name} must be a list or comma-separated string.")
    normalized: List[str] = []
    for item in values:
        candidate = str(item or "").strip()
        if candidate:
            normalized.append(candidate)
    return normalized


def parse_ip_metadata(value: Any) -> List[str]:
    items = parse_string_list_value(value, "ips")
    for item in items:
        try:
            ipaddress.ip_address(item)
        except ValueError:
            abort(BAD_REQUEST, f"Invalid IP metadata entry: {item}")
    return items


def default_tenant_tls_settings() -> Dict[str, Any]:
    return {
        "mode": web_config.TLS_MODE_HTTP,
        "server_name": "",
        "letsencrypt_email": "",
        "proxy_incoming_hostname": "",
        "redirect_http_to_https": False,
        "certificate_provider": "tenant_scoped",
        "applied": False,
    }


def parse_tenant_tls_settings(value: Any) -> Dict[str, Any]:
    settings = default_tenant_tls_settings()
    if value in (None, ""):
        return settings
    if not isinstance(value, dict):
        abort(BAD_REQUEST, "settings.tls must be an object.")
    mode = parse_tls_mode(value.get("mode", settings["mode"]))
    server_name = str(value.get("server_name", settings["server_name"]) or "").strip()
    letsencrypt_email = str(value.get("letsencrypt_email", settings["letsencrypt_email"]) or "").strip()
    proxy_incoming_hostname = str(
        value.get("proxy_incoming_hostname", settings["proxy_incoming_hostname"]) or ""
    ).strip()
    redirect_http_to_https = parse_boolean_value(
        value.get("redirect_http_to_https", settings["redirect_http_to_https"]),
        settings["redirect_http_to_https"],
    )
    if mode == web_config.TLS_MODE_SELF_SIGNED and server_name:
        server_name = parse_tls_server_name(
            server_name,
            allow_ipv4=True,
            allow_localhost=True,
            field_name="settings.tls.server_name",
        )
    elif mode == web_config.TLS_MODE_LETS_ENCRYPT:
        server_name = parse_tls_server_name(
            server_name,
            allow_ipv4=False,
            allow_localhost=False,
            field_name="settings.tls.server_name",
        )
        if letsencrypt_email:
            letsencrypt_email = parse_email_value(letsencrypt_email, "settings.tls.letsencrypt_email")
    if mode == web_config.TLS_MODE_REVERSE_PROXY and proxy_incoming_hostname:
        proxy_incoming_hostname = parse_tls_server_name(
            proxy_incoming_hostname,
            allow_ipv4=False,
            allow_localhost=True,
            field_name="settings.tls.proxy_incoming_hostname",
        )
    settings.update({
        "mode": mode,
        "server_name": server_name,
        "letsencrypt_email": letsencrypt_email,
        "proxy_incoming_hostname": proxy_incoming_hostname,
        "redirect_http_to_https": bool(redirect_http_to_https and mode != web_config.TLS_MODE_HTTP),
        "certificate_provider": "tenant_scoped",
        "applied": False,
    })
    return settings


def default_tenant_runtime_settings(tenant: Optional[Tenant] = None) -> Dict[str, Any]:
    slug = slugify_name(getattr(tenant, "slug", "") or getattr(tenant, "name", "") or "tenant")
    image_tag = str(os.environ.get("ARPVPN_IMAGE", "") or "").strip()
    return {
        "allocated": False,
        "enabled": False,
        "status": "planned",
        "desired_state": "stopped",
        "container_name": f"arpvpn-{slug}" if slug else "arpvpn-tenant",
        "compose_project_name": f"arpvpn_{slug}" if slug else "arpvpn_tenant",
        "image_tag": image_tag,
        "http_port": 0,
        "https_port": 0,
        "vpn_port": 0,
        "notes": "",
        "control_plane_only": True,
    }


def collect_reserved_tenant_runtime_ports(exclude_tenant_id: str = "") -> Dict[str, set[int]]:
    reserved = {
        "http_port": set(),
        "https_port": set(),
        "vpn_port": set(),
    }
    for tenant in tenants.values():
        if exclude_tenant_id and tenant.id == exclude_tenant_id:
            continue
        runtime = getattr(tenant, "settings", {}) or {}
        runtime_settings = runtime.get("runtime", {})
        if not isinstance(runtime_settings, dict):
            continue
        for key in reserved.keys():
            value = runtime_settings.get(key, 0)
            if isinstance(value, int) and value > 0:
                reserved[key].add(value)
    return reserved


def allocate_tenant_runtime_ports(tenant: Tenant, current: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    settings = default_tenant_runtime_settings(tenant)
    if isinstance(current, dict):
        settings.update(copy.deepcopy(current))
    reserved = collect_reserved_tenant_runtime_ports(exclude_tenant_id=tenant.id)
    stride = get_env_int("ARPVPN_TENANT_RUNTIME_PORT_STRIDE", 10)
    base_http = get_env_int("ARPVPN_TENANT_RUNTIME_HTTP_BASE", 18085)
    base_https = get_env_int("ARPVPN_TENANT_RUNTIME_HTTPS_BASE", 18086)
    base_vpn = get_env_int("ARPVPN_TENANT_RUNTIME_VPN_BASE", 51820)
    index = 0
    while True:
        http_port = base_http + (index * stride)
        https_port = base_https + (index * stride)
        vpn_port = base_vpn + (index * stride)
        if (
            http_port not in reserved["http_port"]
            and https_port not in reserved["https_port"]
            and vpn_port not in reserved["vpn_port"]
        ):
            settings["http_port"] = http_port
            settings["https_port"] = https_port
            settings["vpn_port"] = vpn_port
            settings["allocated"] = True
            settings["enabled"] = True
            settings["status"] = "planned"
            settings["desired_state"] = "stopped"
            return settings
        index += 1


def parse_tenant_runtime_settings(value: Any, tenant: Optional[Tenant] = None) -> Dict[str, Any]:
    settings = default_tenant_runtime_settings(tenant)
    if value in (None, ""):
        return settings
    if not isinstance(value, dict):
        abort(BAD_REQUEST, "settings.runtime must be an object.")
    settings.update(copy.deepcopy(value))
    settings["allocated"] = parse_boolean_value(value.get("allocated", settings["allocated"]), settings["allocated"])
    settings["enabled"] = parse_boolean_value(value.get("enabled", settings["enabled"]), settings["enabled"])
    status = str(value.get("status", settings["status"]) or "").strip().lower()
    desired_state = str(value.get("desired_state", settings["desired_state"]) or "").strip().lower()
    if status not in ("planned", "running", "stopped", "error"):
        abort(BAD_REQUEST, "settings.runtime.status is invalid.")
    if desired_state not in ("running", "stopped", "restarting"):
        abort(BAD_REQUEST, "settings.runtime.desired_state is invalid.")
    settings["status"] = status
    settings["desired_state"] = desired_state
    settings["container_name"] = str(value.get("container_name", settings["container_name"]) or "").strip() or settings["container_name"]
    settings["compose_project_name"] = str(
        value.get("compose_project_name", settings["compose_project_name"]) or ""
    ).strip() or settings["compose_project_name"]
    settings["image_tag"] = str(value.get("image_tag", settings["image_tag"]) or "").strip()
    settings["notes"] = str(value.get("notes", settings["notes"]) or "").strip()
    for field_name in ("http_port", "https_port", "vpn_port"):
        settings[field_name] = parse_integer_value(
            value.get(field_name, settings[field_name]),
            f"settings.runtime.{field_name}",
            minimum=0,
            maximum=65535,
        )
    reserved = collect_reserved_tenant_runtime_ports(exclude_tenant_id=getattr(tenant, "id", ""))
    for field_name in ("http_port", "https_port", "vpn_port"):
        port = settings[field_name]
        if port > 0 and port in reserved[field_name]:
            abort(CONFLICT, f"settings.runtime.{field_name} is already allocated to another tenant.")
    return settings


def parse_tenant_settings(value: Any, tenant: Optional[Tenant] = None) -> Dict[str, Any]:
    if value in (None, ""):
        return {
            "branding": {},
            "limits": {},
            "defaults": {},
            "dns_servers": [],
            "tls": default_tenant_tls_settings(),
            "runtime": default_tenant_runtime_settings(),
        }
    if not isinstance(value, dict):
        abort(BAD_REQUEST, "settings must be an object.")
    branding = value.get("branding", {})
    limits = value.get("limits", {})
    defaults = value.get("defaults", {})
    if not isinstance(branding, dict) or not isinstance(limits, dict) or not isinstance(defaults, dict):
        abort(BAD_REQUEST, "settings.branding, settings.limits, and settings.defaults must be objects.")
    dns_servers = parse_string_list_value(value.get("dns_servers", []), "settings.dns_servers")
    for dns_value in dns_servers:
        try:
            ipaddress.ip_address(dns_value)
        except ValueError:
            abort(BAD_REQUEST, f"Invalid DNS server entry: {dns_value}")
    tls_settings = parse_tenant_tls_settings(value.get("tls", {}))
    runtime_settings = parse_tenant_runtime_settings(value.get("runtime", {}), tenant)
    return {
        "branding": copy.deepcopy(branding),
        "limits": copy.deepcopy(limits),
        "defaults": copy.deepcopy(defaults),
        "dns_servers": dns_servers,
        "tls": tls_settings,
        "runtime": runtime_settings,
    }


def parse_tenant_status(value: Any) -> str:
    status = str(value or Tenant.STATUS_ACTIVE).strip().lower()
    if status not in Tenant.STATUSES:
        abort(BAD_REQUEST, "status must be active, suspended, or disabled.")
    return status


def parse_role_value(value: Any) -> str:
    role = str(value or User.ROLE_CLIENT).strip().lower()
    if role not in User.ROLES:
        abort(BAD_REQUEST, "Invalid role.")
    return role


def parse_expiry_hours(value: Any, default: int = Invitation.DEFAULT_EXPIRY_HOURS) -> int:
    if value in (None, ""):
        return default
    try:
        hours = int(value)
    except (TypeError, ValueError):
        abort(BAD_REQUEST, "expires_in_hours must be an integer.")
    if hours < 1 or hours > 24 * 30:
        abort(BAD_REQUEST, "expires_in_hours must be between 1 and 720.")
    return hours


def parse_boolean_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    candidate = str(value or "").strip().lower()
    if candidate in ("1", "true", "yes", "on", "y"):
        return True
    if candidate in ("0", "false", "no", "off", "n", ""):
        return False
    return default


def parse_integer_value(
    value: Any,
    field_name: str,
    *,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
    default: Optional[int] = None,
) -> int:
    if value in (None, ""):
        if default is not None:
            return default
        abort(BAD_REQUEST, f"{field_name} is required.")
    try:
        candidate = int(value)
    except (TypeError, ValueError):
        abort(BAD_REQUEST, f"{field_name} must be an integer.")
    if minimum is not None and candidate < minimum:
        abort(BAD_REQUEST, f"{field_name} must be greater than or equal to {minimum}.")
    if maximum is not None and candidate > maximum:
        abort(BAD_REQUEST, f"{field_name} must be less than or equal to {maximum}.")
    return candidate


def parse_string_or_list_lines(value: Any, field_name: str) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    elif isinstance(value, str):
        items = [chunk for chunk in re.split(r"\r?\n", value) if chunk is not None]
    else:
        abort(BAD_REQUEST, f"{field_name} must be a list or string.")
    return [str(item or "").strip() for item in items if str(item or "").strip()]


def get_user_by_username(username: str) -> Optional[User]:
    candidate = str(username or "").strip()
    if not candidate:
        return None
    return users.get_value_by_attr("name", candidate)


def get_user_or_404(user_id: str) -> User:
    user_item = users.get(str(user_id or "").strip(), None)
    if not user_item:
        abort(NOT_FOUND, "User not found.")
    return user_item


def get_peer_or_404(peer_id: str) -> Peer:
    peer = get_all_peers().get(str(peer_id or "").strip(), None)
    if not peer:
        abort(NOT_FOUND, "Peer not found.")
    return peer


def get_interface_or_404(interface_id: str) -> Interface:
    iface = interfaces.get(str(interface_id or "").strip(), None)
    if not iface:
        abort(NOT_FOUND, "Interface not found.")
    return iface


def resolve_peer_owner(peer: Peer) -> Optional[User]:
    owner_user_id = str(getattr(peer, "owner_user_id", "") or "").strip()
    if owner_user_id:
        owner = users.get(owner_user_id, None)
        if owner:
            return owner
    return get_user_by_username(getattr(peer, "name", ""))


def resolve_peer_tenant_id(peer: Peer) -> Optional[str]:
    explicit_tenant_id = str(getattr(peer, "tenant_id", "") or "").strip() or None
    if explicit_tenant_id:
        return explicit_tenant_id
    owner = resolve_peer_owner(peer)
    if owner and owner.tenant_id:
        return str(owner.tenant_id)
    iface = getattr(peer, "interface", None)
    if iface:
        iface_tenant_id = str(getattr(iface, "tenant_id", "") or "").strip() or None
        if iface_tenant_id:
            return iface_tenant_id
    return None


def resolve_interface_tenant_id(iface: Interface) -> Optional[str]:
    explicit_tenant_id = str(getattr(iface, "tenant_id", "") or "").strip() or None
    if explicit_tenant_id:
        return explicit_tenant_id
    peer_tenant_ids = {
        tenant_id
        for tenant_id in (resolve_peer_tenant_id(peer) for peer in iface.peers.values())
        if tenant_id
    }
    if len(peer_tenant_ids) == 1:
        return next(iter(peer_tenant_ids))
    return None


def peer_visible_to_actor(peer: Peer, actor: Optional[User] = None) -> bool:
    actor = actor or current_actor()
    if not actor:
        return False
    if actor.has_role(*STAFF_ROLES):
        return True
    peer_tenant_id = resolve_peer_tenant_id(peer)
    if actor.has_role(User.ROLE_TENANT_ADMIN):
        actor_tenant_id = get_actor_tenant_id(actor)
        return actor_tenant_id is not None and peer_tenant_id == actor_tenant_id
    if actor.has_role(User.ROLE_CLIENT):
        owner = resolve_peer_owner(peer)
        if owner and owner.id == actor.id:
            return True
        return peer.name.lower() == actor.name.lower()
    return False


def interface_visible_to_actor(iface: Interface, actor: Optional[User] = None) -> bool:
    actor = actor or current_actor()
    if not actor:
        return False
    if actor.has_role(*STAFF_ROLES):
        return True
    iface_tenant_id = resolve_interface_tenant_id(iface)
    if actor.has_role(User.ROLE_TENANT_ADMIN):
        actor_tenant_id = get_actor_tenant_id(actor)
        if actor_tenant_id and iface_tenant_id == actor_tenant_id:
            return True
        return any(peer_visible_to_actor(peer, actor) for peer in iface.peers.values())
    if actor.has_role(User.ROLE_CLIENT):
        return any(peer_visible_to_actor(peer, actor) for peer in iface.peers.values())
    return False


def get_accessible_interfaces(actor: Optional[User] = None) -> List[Interface]:
    actor = actor or current_actor()
    if not actor:
        return []
    return [iface for iface in interfaces.values() if interface_visible_to_actor(iface, actor)]


def get_accessible_peers(actor: Optional[User] = None) -> List[Peer]:
    actor = actor or current_actor()
    if not actor:
        return []
    return [peer for peer in get_all_peers().values() if peer_visible_to_actor(peer, actor)]


def can_manage_wireguard_interface(iface: Interface, actor: Optional[User] = None) -> bool:
    actor = actor or current_actor()
    if not actor:
        return False
    if actor.has_role(*STAFF_ROLES):
        return True
    if actor.has_role(User.ROLE_TENANT_ADMIN):
        actor_tenant_id = get_actor_tenant_id(actor)
        if actor_tenant_id is None:
            return False
        iface_tenant_id = resolve_interface_tenant_id(iface)
        if iface_tenant_id:
            return iface_tenant_id == actor_tenant_id
        if not iface.peers:
            return True
        return all(
            resolve_peer_tenant_id(peer) in (None, actor_tenant_id)
            for peer in iface.peers.values()
        )
    return False


def can_manage_wireguard_peer(peer: Peer, actor: Optional[User] = None) -> bool:
    actor = actor or current_actor()
    if not actor:
        return False
    if actor.has_role(*STAFF_ROLES):
        return True
    if actor.has_role(User.ROLE_TENANT_ADMIN):
        actor_tenant_id = get_actor_tenant_id(actor)
        return actor_tenant_id is not None and resolve_peer_tenant_id(peer) == actor_tenant_id
    return False


def interface_to_api_dict(iface: Interface, include_peers: bool = False, actor: Optional[User] = None) -> Dict[str, Any]:
    actor = actor or current_actor()
    payload: Dict[str, Any] = {
        "id": iface.uuid,
        "uuid": iface.uuid,
        "name": iface.name,
        "description": iface.description,
        "gateway": iface.gw_iface,
        "ipv4": iface.ipv4_address,
        "listen_port": iface.listen_port,
        "auto": iface.auto,
        "status": iface.status,
        "tenant_id": resolve_interface_tenant_id(iface),
        "public_key": iface.public_key,
        "peer_count": len(iface.peers),
        "on_up": list(iface.on_up),
        "on_down": list(iface.on_down),
        "download_endpoint": url_for("router.api_download_wireguard_interface", interface_id=iface.uuid, _external=False),
        "operations_endpoint": url_for("router.api_operate_wireguard_interface", interface_id=iface.uuid, action="restart", _external=False).rsplit("/", 1)[0],
    }
    if include_peers:
        payload["peers"] = [
            peer_to_api_dict(peer)
            for peer in iface.peers.values()
            if actor is None or peer_visible_to_actor(peer, actor) or actor.has_role(*STAFF_ROLES)
        ]
    return payload


def peer_to_api_dict(peer: Peer) -> Dict[str, Any]:
    owner = resolve_peer_owner(peer)
    return {
        "id": peer.uuid,
        "uuid": peer.uuid,
        "name": peer.name,
        "description": peer.description,
        "ipv4": peer.ipv4_address,
        "nat": peer.nat,
        "mode": peer.mode,
        "full_tunnel": bool(peer.full_tunnel),
        "site_to_site_subnets": list(peer.site_to_site_subnets),
        "enabled": bool(peer.enabled),
        "dns1": peer.dns1,
        "dns2": peer.dns2,
        "tenant_id": resolve_peer_tenant_id(peer),
        "owner_user_id": owner.id if owner else str(getattr(peer, "owner_user_id", "") or "").strip() or None,
        "owner_username": owner.name if owner else None,
        "interface_uuid": peer.interface.uuid if peer.interface else None,
        "interface_name": peer.interface.name if peer.interface else None,
        "public_key": peer.public_key,
        "endpoint": peer.endpoint,
        "download_endpoint": url_for("router.api_download_wireguard_peer", peer_id=peer.uuid, _external=False),
        "qr_endpoint": url_for("router.api_wireguard_peer_qr", peer_id=peer.uuid, _external=False),
    }


def resolve_wireguard_tenant_for_actor(requested_tenant_id: Optional[str], actor: Optional[User] = None) -> Optional[str]:
    actor = actor or current_actor()
    if not actor:
        abort(UNAUTHORIZED)
    tenant_id = str(requested_tenant_id or "").strip() or None
    if actor.has_role(*STAFF_ROLES):
        if tenant_id:
            get_tenant_or_404(tenant_id)
        return tenant_id
    if actor.has_role(User.ROLE_TENANT_ADMIN):
        actor_tenant_id = get_actor_tenant_id(actor)
        if not actor_tenant_id:
            abort(FORBIDDEN, "Tenant admin is not assigned to a tenant.")
        if tenant_id and tenant_id != actor_tenant_id:
            abort(FORBIDDEN, "Tenant admins can only manage their assigned tenant.")
        return actor_tenant_id
    abort(FORBIDDEN, "Insufficient permissions.")


def parse_idempotency_replay() -> Optional[Tuple[Any, int]]:
    key = str(request.headers.get("Idempotency-Key", "") or "").strip()
    if not key:
        return None
    actor = current_actor()
    actor_id = actor.id if actor else "anonymous"
    scope_key = f"{actor_id}:{request.method}:{request.path}:{key}"
    fingerprint = api_idempotency_store.build_fingerprint(
        request.method,
        request.path,
        actor_id,
        request.get_data(cache=True, as_text=True),
    )
    record = api_idempotency_store.get(scope_key)
    if not record:
        g.api_idempotency_scope_key = scope_key
        g.api_idempotency_fingerprint = fingerprint
        return None
    if record.fingerprint != fingerprint:
        abort(CONFLICT, "Idempotency-Key was already used with a different request payload.")
    return record.response_data, record.status_code


def store_idempotency_response(response_data: Any, status_code: int):
    scope_key = getattr(g, "api_idempotency_scope_key", "")
    fingerprint = getattr(g, "api_idempotency_fingerprint", "")
    if not scope_key or not fingerprint:
        return
    api_idempotency_store.store(scope_key, fingerprint, response_data, status_code)


def build_qr_data_uri(content: str) -> str:
    try:
        import qrcode
    except Exception as exc:  # pragma: no cover - dependency should exist in runtime
        raise WireguardError(str(exc), INTERNAL_SERVER_ERROR) from exc
    image = qrcode.make(str(content or ""))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def get_tenant_or_404(tenant_id: str) -> Tenant:
    tenant = tenants.get(tenant_id, None)
    if not tenant:
        abort(NOT_FOUND, "Tenant not found.")
    return tenant


def get_invitation_or_404(invitation_id: str) -> Invitation:
    invitation = invitations.get(invitation_id, None)
    if not invitation:
        abort(NOT_FOUND, "Invitation not found.")
    sync_invitation_status(invitation)
    return invitation


def parse_interface_payload(payload: Dict[str, Any], existing: Optional[Interface] = None) -> Dict[str, Any]:
    name = parse_non_empty_string(payload.get("name", existing.name if existing else None), "name")
    if not Interface.is_name_valid(name):
        abort(BAD_REQUEST, "name is invalid.")
    if Interface.is_name_in_use(name, existing):
        abort(CONFLICT, "Interface name already exists.")

    description = parse_optional_string(payload.get("description", existing.description if existing else ""))
    gateway = parse_non_empty_string(payload.get("gateway", existing.gw_iface if existing else None), "gateway")
    available_gateways = set(get_system_interfaces().keys()) - {"lo"}
    if gateway not in available_gateways:
        abort(BAD_REQUEST, "gateway must be a valid system interface.")

    ipv4_text = parse_non_empty_string(payload.get("ipv4", existing.ipv4_address if existing else None), "ipv4")
    try:
        ipv4_value = ipaddress.IPv4Interface(ipv4_text)
    except ValueError:
        abort(BAD_REQUEST, "ipv4 must be a valid IPv4 interface in CIDR notation.")
    if Interface.is_ip_in_use(str(ipv4_value), existing):
        abort(CONFLICT, "Interface IP address is already in use.")
    if Interface.is_network_in_use(ipv4_value, existing):
        abort(CONFLICT, f"Network {ipv4_value.network} already has a WireGuard interface.")
    if ipv4_value.ip in (ipv4_value.network.network_address, ipv4_value.network.broadcast_address):
        abort(BAD_REQUEST, "ipv4 cannot use a network or broadcast address.")

    listen_port = parse_integer_value(
        payload.get("listen_port", payload.get("port", existing.listen_port if existing else None)),
        "listen_port",
        minimum=web_config.MIN_PORT,
        maximum=web_config.MAX_PORT,
    )
    if Interface.is_port_in_use(listen_port, existing):
        abort(CONFLICT, "listen_port is already in use.")

    actor = current_actor()
    tenant_seed = payload.get("tenant_id", getattr(existing, "tenant_id", ""))
    tenant_id = resolve_wireguard_tenant_for_actor(tenant_seed, actor) if actor and actor.has_role(*USER_MANAGEMENT_ROLES) else None

    return {
        "name": name,
        "description": description,
        "gateway": gateway,
        "ipv4": str(ipv4_value),
        "listen_port": listen_port,
        "auto": parse_boolean_value(payload.get("auto", existing.auto if existing else False), False),
        "on_up": parse_string_or_list_lines(payload.get("on_up", existing.on_up if existing else []), "on_up"),
        "on_down": parse_string_or_list_lines(payload.get("on_down", existing.on_down if existing else []), "on_down"),
        "tenant_id": tenant_id,
    }


def resolve_peer_owner_for_payload(payload: Dict[str, Any]) -> Tuple[Optional[User], Optional[str]]:
    actor = current_actor()
    owner_user_id = parse_optional_string(payload.get("owner_user_id"))
    owner_username = parse_optional_string(payload.get("owner_username", payload.get("username")))
    owner = None
    if owner_user_id:
        owner = get_user_or_404(owner_user_id)
    elif owner_username:
        owner = get_user_by_username(owner_username)

    tenant_seed = payload.get("tenant_id")
    if owner:
        if owner.role != User.ROLE_CLIENT:
            abort(BAD_REQUEST, "WireGuard peers can only be assigned to client users.")
        if actor and not user_visible_to_actor(owner, actor):
            abort(FORBIDDEN, "Insufficient permissions.")
        tenant_id = owner.tenant_id
    else:
        tenant_id = resolve_wireguard_tenant_for_actor(tenant_seed, actor) if actor else None
    return owner, (str(tenant_id or "").strip() or None)


def parse_peer_payload(payload: Dict[str, Any], existing: Optional[Peer] = None) -> Dict[str, Any]:
    interface_ref = parse_non_empty_string(
        payload.get("interface_uuid", payload.get("interface", existing.interface.uuid if existing and existing.interface else None)),
        "interface_uuid",
    )
    iface = interfaces.get(interface_ref, None) or interfaces.get_value_by_attr("name", interface_ref)
    if not iface:
        abort(BAD_REQUEST, "interface_uuid must reference an existing interface.")
    if not can_manage_wireguard_interface(iface):
        abort(FORBIDDEN, "Insufficient permissions.")

    name = parse_non_empty_string(payload.get("name", existing.name if existing else None), "name")
    if not Peer.is_name_valid(name):
        abort(BAD_REQUEST, "name is invalid.")

    mode = str(payload.get("mode", existing.mode if existing else Peer.MODE_CLIENT) or Peer.MODE_CLIENT).strip().lower()
    if mode not in Peer.MODES:
        abort(BAD_REQUEST, "mode must be client or site_to_site.")

    ipv4_text = parse_non_empty_string(payload.get("ipv4", existing.ipv4_address if existing else None), "ipv4")
    try:
        peer_ip = ipaddress.IPv4Interface(ipv4_text)
    except ValueError:
        abort(BAD_REQUEST, "ipv4 must be a valid IPv4 address in CIDR notation.")
    iface_network = ipaddress.IPv4Interface(iface.ipv4_address).network
    normalized_peer_ip = ipaddress.IPv4Interface(f"{peer_ip.ip}/{iface_network.prefixlen}")
    if normalized_peer_ip not in iface_network:
        abort(BAD_REQUEST, f"ipv4 must belong to network {iface_network}.")
    if normalized_peer_ip.ip in (iface_network.network_address, iface_network.broadcast_address):
        abort(BAD_REQUEST, "ipv4 cannot use a network or broadcast address.")
    if Peer.is_ip_in_use(str(normalized_peer_ip), existing):
        abort(CONFLICT, "Peer IP address is already in use.")

    dns1 = parse_optional_string(payload.get("dns1", existing.dns1 if existing else ""))
    dns2 = parse_optional_string(payload.get("dns2", existing.dns2 if existing else ""))
    if mode != Peer.MODE_SITE_TO_SITE and not dns1:
        abort(BAD_REQUEST, "dns1 is required for client peers.")
    for field_name, value in (("dns1", dns1), ("dns2", dns2)):
        if not value:
            continue
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            abort(BAD_REQUEST, f"{field_name} must be a valid IPv4 address.")

    site_to_site_subnets = []
    if mode == Peer.MODE_SITE_TO_SITE:
        try:
            site_to_site_subnets = Peer.parse_site_to_site_subnets(
                payload.get("site_to_site_subnets", existing.site_to_site_subnets if existing else [])
            )
        except ValueError:
            abort(BAD_REQUEST, "site_to_site_subnets must be a list of IPv4 CIDR blocks.")

    owner, tenant_id = resolve_peer_owner_for_payload(payload)
    if tenant_id and resolve_interface_tenant_id(iface) and resolve_interface_tenant_id(iface) != tenant_id:
        abort(CONFLICT, "Peer tenant does not match the target interface tenant.")

    return {
        "name": name,
        "description": parse_optional_string(payload.get("description", existing.description if existing else "")),
        "interface": iface,
        "ipv4": str(normalized_peer_ip),
        "nat": parse_boolean_value(payload.get("nat", existing.nat if existing else False), False),
        "dns1": dns1,
        "dns2": dns2,
        "mode": mode,
        "enabled": parse_boolean_value(payload.get("enabled", existing.enabled if existing else True), True),
        "full_tunnel": parse_boolean_value(payload.get("full_tunnel", existing.full_tunnel if existing else False), False)
        if mode == Peer.MODE_SITE_TO_SITE else False,
        "site_to_site_subnets": site_to_site_subnets,
        "owner_user_id": owner.id if owner else None,
        "tenant_id": tenant_id or resolve_interface_tenant_id(iface),
    }


def run_async_job_or_execute(operation: str, target):
    actor = current_actor()
    payload = parse_json_payload(allow_empty=True)
    if parse_boolean_value(request.args.get("async"), False) or parse_boolean_value(payload.get("async"), False):
        app = current_app._get_current_object()
        request_path = request.path
        request_base_url = request.host_url

        def target_with_context():
            with app.test_request_context(path=request_path, base_url=request_base_url):
                if actor:
                    actor.set_authenticated(True)
                    g.api_actor_user = actor
                    login_user(actor, remember=False, force=True)
                return target()

        job = api_async_jobs.start_job(operation, actor.id if actor else "", target_with_context)
        return api_success({"job": job.to_dict()}, status_code=ACCEPTED)
    return target()


def operate_interface_action(iface: Interface, action: str) -> Dict[str, Any]:
    operation = str(action or "").strip().lower()
    if operation == "start":
        iface.up()
    elif operation == "restart":
        iface.restart()
    elif operation == "stop":
        iface.down()
    else:
        abort(BAD_REQUEST, "action must be start, stop, or restart.")
    config_manager.save()
    return interface_to_api_dict(iface, include_peers=True)


@router.route("/logout")
@login_required
@setup_required
def logout():
    session.pop(IMPERSONATOR_SESSION_KEY, None)
    clear_session_mfa_verification()
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
    clear_session_mfa_verification()
    u = users.get_value_by_attr("name", form.username.data)
    mfa_recovery_consumed = False
    if u and u.has_mfa():
        mfa_verified, mfa_recovery_consumed = u.verify_mfa(form.mfa_code.data)
        if not mfa_verified:
            u.set_authenticated(False)
            error("Unable to log user in.")
            form.mfa_code.errors.append("Invalid MFA code.")
            context = {
                "title": "Login",
                "form": form,
            }
            max_attempts = int(web_config.login_attempts)
            if max_attempts > 0:
                client.login_attempts += 1
                if client.login_attempts > max_attempts:
                    client.ban()
                    context["banned_for"] = (client.banned_until - datetime.now()).seconds
            return ViewController("web/login.html", **context).load()
    if not login_user(u, form.remember_me.data):
        error(f"Unable to log user in.")
        abort(INTERNAL_SERVER_ERROR)
    if u and u.has_mfa():
        mark_session_mfa_verified(u)
    if mfa_recovery_consumed:
        config_manager.save_credentials()
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
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def wireguard():
    peer_runtime = filter_peer_runtime_for_current_user(get_peer_runtime_summary())
    interface_totals = get_interface_totals()
    context = {
        "title": "Wireguard",
        "interfaces": get_visible_interfaces_for_current_user(),
        "peer_runtime": peer_runtime,
        "wireguard_stats": {
            "interfaces_total": interface_totals["total"],
            "interfaces_up": interface_totals["up"],
            "interfaces_down": interface_totals["down"],
            "peers_total": peer_runtime["totals"]["peers"],
            "disabled_peers": peer_runtime["totals"]["disabled_peers"],
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


@router.route("/api/v1/auth/csrf", methods=["GET"])
@login_required
@setup_required
def api_auth_csrf():
    return api_success({
        "csrf_token": generate_csrf(),
        "required_for_cookie_auth": api_csrf_enabled(),
        "header_names": list(API_CSRF_HEADER_NAMES),
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

    mfa_recovery_consumed = False
    mfa_verified = False
    if user.has_mfa():
        if not payload["mfa_code"]:
            remaining_attempts = api_auth_lockouts.register_failure(
                lockout_key,
                max_attempts=API_AUTH_MAX_ATTEMPTS,
                window_seconds=API_AUTH_RATE_WINDOW_SECONDS,
                lockout_seconds=API_AUTH_LOCKOUT_SECONDS,
            )
            log_audit_event(
                "auth.token.issue",
                status="failed_mfa",
                details={"username": username, "remaining_attempts": remaining_attempts},
            )
            return api_error(
                UNAUTHORIZED,
                "mfa_required",
                "A valid MFA code is required for this account.",
                details={"remaining_attempts": remaining_attempts},
            )
        mfa_verified, mfa_recovery_consumed = user.verify_mfa(payload["mfa_code"])
        if not mfa_verified:
            remaining_attempts = api_auth_lockouts.register_failure(
                lockout_key,
                max_attempts=API_AUTH_MAX_ATTEMPTS,
                window_seconds=API_AUTH_RATE_WINDOW_SECONDS,
                lockout_seconds=API_AUTH_LOCKOUT_SECONDS,
            )
            log_audit_event(
                "auth.token.issue",
                status="failed_mfa",
                details={"username": username, "remaining_attempts": remaining_attempts},
            )
            return api_error(
                UNAUTHORIZED,
                "invalid_mfa_code",
                "Invalid MFA code.",
                details={"remaining_attempts": remaining_attempts},
            )

    api_auth_lockouts.clear_failures(lockout_key)
    if mfa_recovery_consumed:
        config_manager.save_credentials()
    token_pair = api_token_store.issue_pair(
        user_id=user.id,
        access_ttl_seconds=API_AUTH_ACCESS_TTL_SECONDS,
        refresh_ttl_seconds=API_AUTH_REFRESH_TTL_SECONDS,
        issued_ip=get_request_ip(),
        issued_user_agent=get_request_user_agent(),
        mfa_verified=mfa_verified,
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
    scope = API_AUTH_SCOPE_STAFF if user.has_role(*API_AUTH_STAFF_ROLES) else API_AUTH_SCOPE_CLIENT
    token_pair = api_token_store.issue_pair(
        user_id=user.id,
        access_ttl_seconds=API_AUTH_ACCESS_TTL_SECONDS,
        refresh_ttl_seconds=API_AUTH_REFRESH_TTL_SECONDS,
        issued_ip=get_request_ip(),
        issued_user_agent=get_request_user_agent(),
        mfa_verified=record.mfa_verified,
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
    parse_json_payload(allow_empty=True)
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
    payload = parse_json_payload(allow_empty=True)
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
    parse_json_payload(allow_empty=True)
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
    parse_json_payload(allow_empty=True)
    if is_impersonating():
        abort(BAD_REQUEST, "Already impersonating a user.")
    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    if target_user.role != User.ROLE_CLIENT:
        abort(BAD_REQUEST, "Only client users can be impersonated.")
    if not can_manage_user_account(target_user):
        abort(FORBIDDEN, "Insufficient permissions.")
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
    parse_json_payload(allow_empty=True)
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


def resolve_user_management_role_and_tenant(
    requested_role: str,
    requested_tenant_id: Optional[str],
    *,
    actor: Optional[User] = None,
) -> Tuple[str, Optional[str]]:
    actor = actor or current_actor()
    if not actor:
        abort(UNAUTHORIZED)

    tenant_id = str(requested_tenant_id or "").strip() or None
    if tenant_id:
        get_tenant_or_404(tenant_id)

    if actor.has_role(User.ROLE_ADMIN):
        if requested_role == User.ROLE_TENANT_ADMIN and not tenant_id:
            abort(BAD_REQUEST, "tenant_id is required for tenant_admin users.")
        return requested_role, tenant_id

    if actor.has_role(User.ROLE_SUPPORT):
        if requested_role != User.ROLE_CLIENT:
            abort(FORBIDDEN, "Support users can only manage client accounts.")
        return requested_role, tenant_id

    if actor.has_role(User.ROLE_TENANT_ADMIN):
        actor_tenant_id = get_actor_tenant_id(actor)
        if not actor_tenant_id:
            abort(FORBIDDEN, "Tenant admin is not assigned to a tenant.")
        if requested_role != User.ROLE_CLIENT:
            abort(FORBIDDEN, "Tenant admins can only manage client accounts.")
        if tenant_id and tenant_id != actor_tenant_id:
            abort(FORBIDDEN, "Tenant admins can only manage users in their assigned tenant.")
        return requested_role, actor_tenant_id

    abort(FORBIDDEN, "Insufficient permissions.")


def resolve_invitation_role_and_tenant(
    requested_role: str,
    requested_tenant_id: Optional[str],
    *,
    actor: Optional[User] = None,
) -> Tuple[str, str]:
    resolved_role, tenant_id = resolve_user_management_role_and_tenant(
        requested_role,
        requested_tenant_id,
        actor=actor,
    )
    if not tenant_id:
        abort(BAD_REQUEST, "tenant_id is required for invitations.")
    return resolved_role, tenant_id


def validate_unique_tenant_fields(name: str, slug: str, exclude_id: str = ""):
    for tenant in tenants.values():
        if exclude_id and tenant.id == exclude_id:
            continue
        if tenant.name.lower() == name.lower():
            abort(CONFLICT, "Tenant name already exists.")
        if tenant.slug.lower() == slug.lower():
            abort(CONFLICT, "Tenant slug already exists.")


def validate_unique_username(username: str, exclude_id: str = ""):
    existing_user = users.get_value_by_attr("name", username)
    if existing_user and existing_user.id != exclude_id:
        abort(CONFLICT, "Username already exists.")


@router.route("/api/v1/tenants", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_list_tenants():
    actor = current_actor()
    tenant_id_filter = parse_optional_string(request.args.get("tenant_id", ""))
    items = get_accessible_tenants(actor)
    if tenant_id_filter:
        items = [tenant for tenant in items if tenant.id == tenant_id_filter]
    return api_success({
        "items": [tenant_to_api_dict(tenant) for tenant in items],
        "total": len(items),
        "scope": "global" if actor_is_global_staff(actor) else "tenant",
    })


@router.route("/api/v1/tenants", methods=["POST"])
@login_required
@role_required(User.ROLE_ADMIN)
@setup_required
def api_create_tenant():
    payload = parse_json_payload()
    name = parse_non_empty_string(payload.get("name"), "name")
    slug = slugify_name(payload.get("slug") or name) or f"tenant-{secrets.token_hex(4)}"
    validate_unique_tenant_fields(name, slug)
    tenant = Tenant(
        name=name,
        slug=slug,
        domains=parse_string_list_value(payload.get("domains", []), "domains"),
        ips=parse_ip_metadata(payload.get("ips", [])),
        status=parse_tenant_status(payload.get("status", Tenant.STATUS_ACTIVE)),
        description=parse_optional_string(payload.get("description")),
        settings={},
    )
    tenant.settings = parse_tenant_settings(payload.get("settings", {}), tenant)
    tenants[tenant.id] = tenant
    tenants.sort()
    config_manager.save_identity_state()
    log_audit_event("tenant.create", status="success", details={"tenant_id": tenant.id, "tenant_name": tenant.name})
    return api_success(tenant_to_api_dict(tenant), status_code=201)


@router.route("/api/v1/tenants/<tenant_id>", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_get_tenant(tenant_id: str):
    tenant = get_tenant_or_404(tenant_id)
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success(tenant_to_api_dict(tenant))


@router.route("/api/v1/tenants/<tenant_id>", methods=["PUT"])
@login_required
@role_required(User.ROLE_ADMIN)
@setup_required
def api_update_tenant(tenant_id: str):
    tenant = get_tenant_or_404(tenant_id)
    payload = parse_json_payload()
    name = parse_non_empty_string(payload.get("name", tenant.name), "name")
    slug = slugify_name(payload.get("slug") or tenant.slug or name) or tenant.slug
    validate_unique_tenant_fields(name, slug, exclude_id=tenant.id)
    tenant.name = name
    tenant.slug = slug
    tenant.domains = parse_string_list_value(payload.get("domains", tenant.domains), "domains")
    tenant.ips = parse_ip_metadata(payload.get("ips", tenant.ips))
    tenant.status = parse_tenant_status(payload.get("status", tenant.status))
    tenant.description = parse_optional_string(payload.get("description", tenant.description))
    tenant.settings = parse_tenant_settings(payload.get("settings", getattr(tenant, "settings", {})), tenant)
    tenant.touch()
    tenants.sort()
    config_manager.save_identity_state()
    log_audit_event("tenant.update", status="success", details={"tenant_id": tenant.id, "tenant_name": tenant.name})
    return api_success(tenant_to_api_dict(tenant))


@router.route("/api/v1/tenants/<tenant_id>", methods=["DELETE"])
@login_required
@role_required(User.ROLE_ADMIN)
@setup_required
def api_delete_tenant(tenant_id: str):
    parse_json_payload(allow_empty=True)
    tenant = get_tenant_or_404(tenant_id)
    tenant_users = [user_item for user_item in users.values() if user_item.tenant_id == tenant.id]
    tenant_invitations = [invitation for invitation in invitations.values() if invitation.tenant_id == tenant.id]
    if tenant_users:
        abort(CONFLICT, "Cannot delete a tenant that still has users.")
    if tenant_invitations:
        abort(CONFLICT, "Cannot delete a tenant that still has invitations.")
    del tenants[tenant.id]
    config_manager.save_identity_state()
    log_audit_event("tenant.delete", status="success", details={"tenant_id": tenant.id, "tenant_name": tenant.name})
    return api_success({"deleted": True, "tenant_id": tenant.id})


@router.route("/api/v1/users", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_list_users():
    actor = current_actor()
    items = get_accessible_users(actor)
    tenant_id_filter = parse_optional_string(request.args.get("tenant_id", ""))
    role_filter = parse_optional_string(request.args.get("role", "")).lower()
    if tenant_id_filter:
        if not actor_can_access_tenant(tenant_id_filter, actor):
            abort(FORBIDDEN, "Insufficient permissions.")
        items = [user_item for user_item in items if (user_item.tenant_id or "") == tenant_id_filter]
    if role_filter:
        items = [user_item for user_item in items if user_item.role == role_filter]
    return api_success({
        "items": [user_to_api_dict(user_item) for user_item in items],
        "total": len(items),
        "scope": "global" if actor_is_global_staff(actor) else "tenant",
    })


@router.route("/api/v1/users/export", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_export_users():
    actor = current_actor()
    tenant_id_filter = parse_optional_string(request.args.get("tenant_id", ""))
    export_format = parse_optional_string(request.args.get("format", "json")).lower() or "json"
    items = get_accessible_users(actor)
    if tenant_id_filter:
        if not actor_can_access_tenant(tenant_id_filter, actor):
            abort(FORBIDDEN, "Insufficient permissions.")
        items = [user_item for user_item in items if (user_item.tenant_id or "") == tenant_id_filter]

    rows = []
    for user_item in items:
        row = user_to_api_dict(user_item)
        tenant = tenants.get(user_item.tenant_id or "", None)
        row["tenant_name"] = tenant.name if tenant else None
        rows.append(row)

    if export_format == "csv":
        output = io.StringIO()
        fieldnames = ["id", "username", "role", "tenant_id", "tenant_name"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fieldnames})
        response = Response(output.getvalue(), mimetype="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=arpvpn-users.csv"
        return response

    if export_format != "json":
        abort(BAD_REQUEST, "format must be json or csv.")

    return api_success({
        "items": rows,
        "total": len(rows),
        "scope": "global" if actor_is_global_staff(actor) else "tenant",
    })


@router.route("/api/v1/users/import", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_import_users():
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})

    actor = current_actor()
    payload = parse_json_payload()
    rows = payload.get("users", payload.get("items", []))
    if not isinstance(rows, list) or not rows:
        abort(BAD_REQUEST, "users must be a non-empty list.")

    dry_run = parse_boolean_value(payload.get("dry_run"), False)
    continue_on_error = parse_boolean_value(payload.get("continue_on_error"), False)
    seen_usernames = set()
    validated_rows = []
    errors = []

    for index, raw_item in enumerate(rows):
        if not isinstance(raw_item, dict):
            errors.append({"index": index, "message": "Each import item must be an object."})
            if not continue_on_error:
                break
            continue
        try:
            username = parse_non_empty_string(raw_item.get("username"), "username")
            password = parse_non_empty_string(raw_item.get("password"), "password")
            requested_role = parse_role_value(raw_item.get("role", User.ROLE_CLIENT))
            resolved_role, resolved_tenant_id = resolve_user_management_role_and_tenant(
                requested_role,
                parse_optional_string(raw_item.get("tenant_id")),
                actor=actor,
            )
            username_key = username.lower()
            if username_key in seen_usernames:
                raise ValueError("Username appears more than once in this import batch.")
            seen_usernames.add(username_key)
            validate_unique_username(username)
            validated_rows.append({
                "username": username,
                "password": password,
                "role": resolved_role,
                "tenant_id": resolved_tenant_id or "",
            })
        except HTTPException as exc:
            errors.append({"index": index, "message": str(exc.description)})
            if not continue_on_error:
                break
        except Exception as exc:
            errors.append({"index": index, "message": str(exc)})
            if not continue_on_error:
                break

    created_users = []
    if not dry_run and (continue_on_error or not errors):
        for row in validated_rows:
            created = RestController.create_user(
                row["username"],
                row["password"],
                row["role"],
                tenant_id=row["tenant_id"],
            )
            created_users.append(user_to_api_dict(created))

    response_payload = {
        "dry_run": dry_run,
        "continue_on_error": continue_on_error,
        "requested_count": len(rows),
        "validated_count": len(validated_rows),
        "created_count": len(created_users),
        "error_count": len(errors),
        "created": created_users,
        "errors": errors,
    }
    status_code = 201 if created_users and not errors else 200
    store_idempotency_response(response_payload, status_code)
    log_audit_event(
        "user.bulk_import",
        status="success" if not errors else "partial",
        details={
            "requested_count": len(rows),
            "created_count": len(created_users),
            "error_count": len(errors),
            "dry_run": dry_run,
        },
    )
    return api_success(response_payload, status_code=status_code)


@router.route("/api/v1/users", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_create_user():
    actor = current_actor()
    payload = parse_json_payload()
    username = parse_non_empty_string(payload.get("username"), "username")
    password = parse_non_empty_string(payload.get("password"), "password")
    requested_role = parse_role_value(payload.get("role", User.ROLE_CLIENT))
    resolved_role, resolved_tenant_id = resolve_user_management_role_and_tenant(
        requested_role,
        parse_optional_string(payload.get("tenant_id")),
        actor=actor,
    )
    validate_unique_username(username)
    created_user = None
    created_peer = None
    try:
        created_user = RestController.create_user(username, password, resolved_role, tenant_id=resolved_tenant_id or "")
        created_peer = provision_peer_for_created_client(created_user, payload)
        response_payload = user_to_api_dict(created_user)
        response_payload["peer"] = peer_to_api_dict(created_peer) if created_peer else None
        log_audit_event(
            "user.create",
            status="success",
            details={
                "target_user_id": created_user.id,
                "target_user_name": created_user.name,
                "target_role": created_user.role,
                "provisioned_peer": bool(created_peer),
            },
        )
        return api_success(response_payload, status_code=201)
    except Exception:
        if created_peer:
            try:
                created_peer.remove()
                config_manager.save()
            except Exception as rollback_error:
                log_exception(rollback_error)
        if created_user and created_user.id in users:
            try:
                del users[created_user.id]
                config_manager.save_identity_state()
            except Exception as rollback_error:
                log_exception(rollback_error)
        raise


@router.route("/api/v1/users/<user_id>", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_get_user(user_id: str):
    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    if not user_visible_to_actor(target_user):
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success(user_to_api_dict(target_user))


@router.route("/api/v1/users/<user_id>", methods=["PUT"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_update_user(user_id: str):
    actor = current_actor()
    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    if not can_manage_user_account(target_user):
        abort(FORBIDDEN, "Insufficient permissions.")

    payload = parse_json_payload()
    requested_username = parse_non_empty_string(payload.get("username", target_user.name), "username")
    requested_role = parse_role_value(payload.get("role", target_user.role))
    requested_tenant_id = parse_optional_string(payload.get("tenant_id", target_user.tenant_id or ""))
    resolved_role, resolved_tenant_id = resolve_user_management_role_and_tenant(
        requested_role,
        requested_tenant_id,
        actor=actor,
    )
    validate_unique_username(requested_username, exclude_id=target_user.id)

    if target_user.id == actor.id and resolved_role != target_user.role:
        abort(FORBIDDEN, "You cannot change your own role.")
    if target_user.role == User.ROLE_ADMIN and resolved_role != User.ROLE_ADMIN and count_users_by_role(User.ROLE_ADMIN) <= 1:
        abort(CONFLICT, "Cannot demote the last admin user.")

    target_user.name = requested_username
    target_user.role = resolved_role
    target_user.tenant_id = resolved_tenant_id or None
    new_password = parse_optional_string(payload.get("password"))
    if new_password:
        target_user.password = new_password
    users.sort()
    config_manager.save_identity_state()
    log_audit_event(
        "user.update",
        status="success",
        details={"target_user_id": target_user.id, "target_user_name": target_user.name, "target_role": target_user.role},
    )
    return api_success(user_to_api_dict(target_user))


@router.route("/api/v1/users/<user_id>", methods=["DELETE"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_delete_user(user_id: str):
    parse_json_payload(allow_empty=True)
    actor = current_actor()
    target_user = users.get(user_id, None)
    if not target_user:
        abort(NOT_FOUND, "User not found.")
    if not can_manage_user_account(target_user):
        abort(FORBIDDEN, "Insufficient permissions.")
    if actor and target_user.id == actor.id:
        abort(FORBIDDEN, "You cannot delete your own account.")
    if target_user.role == User.ROLE_ADMIN and count_users_by_role(User.ROLE_ADMIN) <= 1:
        abort(CONFLICT, "Cannot delete the last admin user.")
    del users[target_user.id]
    config_manager.save_identity_state()
    log_audit_event(
        "user.delete",
        status="success",
        details={"target_user_id": target_user.id, "target_user_name": target_user.name},
    )
    return api_success({"deleted": True, "user_id": target_user.id})


@router.route("/api/v1/tenants/<tenant_id>/members", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_list_tenant_members(tenant_id: str):
    tenant = get_tenant_or_404(tenant_id)
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    items = [user_item for user_item in get_accessible_users(current_actor()) if user_item.tenant_id == tenant.id]
    return api_success({
        "tenant": tenant_to_api_dict(tenant),
        "items": [user_to_api_dict(user_item) for user_item in items],
        "total": len(items),
    })


@router.route("/api/v1/tenants/<tenant_id>/members", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_create_tenant_member(tenant_id: str):
    tenant = get_tenant_or_404(tenant_id)
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    actor = current_actor()
    payload = parse_json_payload()
    username = parse_non_empty_string(payload.get("username"), "username")
    password = parse_non_empty_string(payload.get("password"), "password")
    requested_role = parse_role_value(payload.get("role", User.ROLE_CLIENT))
    resolved_role, resolved_tenant_id = resolve_user_management_role_and_tenant(
        requested_role,
        tenant.id,
        actor=actor,
    )
    validate_unique_username(username)
    created_user = None
    created_peer = None
    try:
        created_user = RestController.create_user(username, password, resolved_role, tenant_id=resolved_tenant_id or "")
        created_peer = provision_peer_for_created_client(created_user, payload)
        response_payload = user_to_api_dict(created_user)
        response_payload["peer"] = peer_to_api_dict(created_peer) if created_peer else None
        log_audit_event(
            "tenant.member.create",
            status="success",
            details={
                "tenant_id": tenant.id,
                "target_user_id": created_user.id,
                "target_user_name": created_user.name,
                "provisioned_peer": bool(created_peer),
            },
        )
        return api_success(response_payload, status_code=201)
    except Exception:
        if created_peer:
            try:
                created_peer.remove()
                config_manager.save()
            except Exception as rollback_error:
                log_exception(rollback_error)
        if created_user and created_user.id in users:
            try:
                del users[created_user.id]
                config_manager.save_identity_state()
            except Exception as rollback_error:
                log_exception(rollback_error)
        raise


@router.route("/api/v1/invitations", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_list_invitations():
    actor = current_actor()
    items = get_accessible_invitations(actor)
    tenant_id_filter = parse_optional_string(request.args.get("tenant_id", ""))
    if tenant_id_filter:
        if not actor_can_access_tenant(tenant_id_filter, actor):
            abort(FORBIDDEN, "Insufficient permissions.")
        items = [invitation for invitation in items if invitation.tenant_id == tenant_id_filter]
    return api_success({
        "items": [invitation_to_api_dict(invitation) for invitation in items],
        "total": len(items),
        "scope": "global" if actor_is_global_staff(actor) else "tenant",
    })


@router.route("/api/v1/invitations", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_create_invitation():
    actor = current_actor()
    payload = parse_json_payload()
    email = parse_email_address(payload.get("email"))
    requested_role = parse_role_value(payload.get("role", User.ROLE_CLIENT))
    resolved_role, resolved_tenant_id = resolve_invitation_role_and_tenant(
        requested_role,
        parse_optional_string(payload.get("tenant_id")),
        actor=actor,
    )
    raw_token = ""
    invitation = Invitation(
        tenant_id=resolved_tenant_id,
        email=email,
        role=resolved_role,
        invited_by_user_id=actor.id if actor else "",
        expires_in_hours=parse_expiry_hours(payload.get("expires_in_hours")),
    )
    raw_token = invitation.raw_token
    invitations[invitation.id] = invitation
    invitations.sort()
    config_manager.save_identity_state()
    log_audit_event(
        "invitation.create",
        status="success",
        details={"invitation_id": invitation.id, "tenant_id": invitation.tenant_id, "email": invitation.email},
    )
    return api_success(invitation_to_api_dict(invitation, raw_token=raw_token), status_code=201)


@router.route("/api/v1/invitations/<invitation_id>", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_get_invitation(invitation_id: str):
    invitation = get_invitation_or_404(invitation_id)
    if not invitation_visible_to_actor(invitation):
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success(invitation_to_api_dict(invitation))


@router.route("/api/v1/invitations/<invitation_id>/resend", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_resend_invitation(invitation_id: str):
    invitation = get_invitation_or_404(invitation_id)
    if not invitation_visible_to_actor(invitation):
        abort(FORBIDDEN, "Insufficient permissions.")
    payload = parse_json_payload(allow_empty=True)
    raw_token = invitation.issue_token(parse_expiry_hours(payload.get("expires_in_hours")))
    config_manager.save_identity_state()
    log_audit_event(
        "invitation.resend",
        status="success",
        details={"invitation_id": invitation.id, "tenant_id": invitation.tenant_id, "email": invitation.email},
    )
    return api_success(invitation_to_api_dict(invitation, raw_token=raw_token))


@router.route("/api/v1/invitations/<invitation_id>/revoke", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_revoke_invitation(invitation_id: str):
    parse_json_payload(allow_empty=True)
    invitation = get_invitation_or_404(invitation_id)
    if not invitation_visible_to_actor(invitation):
        abort(FORBIDDEN, "Insufficient permissions.")
    invitation.revoke()
    config_manager.save_identity_state()
    log_audit_event(
        "invitation.revoke",
        status="success",
        details={"invitation_id": invitation.id, "tenant_id": invitation.tenant_id, "email": invitation.email},
    )
    return api_success(invitation_to_api_dict(invitation))


@router.route("/api/v1/invitations/<invitation_id>/accept", methods=["POST"])
@setup_required
def api_accept_invitation(invitation_id: str):
    invitation = get_invitation_or_404(invitation_id)
    if invitation.current_status() == Invitation.STATUS_REVOKED:
        abort(FORBIDDEN, "Invitation has been revoked.")
    if invitation.current_status() == Invitation.STATUS_ACCEPTED:
        abort(CONFLICT, "Invitation has already been accepted.")
    if invitation.current_status() == Invitation.STATUS_EXPIRED:
        abort(FORBIDDEN, "Invitation has expired.")

    payload = parse_json_payload()
    raw_token = parse_non_empty_string(payload.get("token"), "token")
    if not invitation.matches_token(raw_token):
        abort(UNAUTHORIZED, "Invalid invitation token.")
    username = parse_non_empty_string(payload.get("username"), "username")
    password = parse_non_empty_string(payload.get("password"), "password")
    confirm = parse_non_empty_string(payload.get("confirm"), "confirm")
    if password != confirm:
        abort(BAD_REQUEST, "confirm must match password.")
    validate_unique_username(username)
    tenant = get_tenant_or_404(invitation.tenant_id)
    created = RestController.create_user(username, password, invitation.role, tenant_id=tenant.id)
    invitation.accept(created.id)
    config_manager.save_identity_state()
    log_audit_event(
        "invitation.accept",
        status="success",
        details={
            "invitation_id": invitation.id,
            "tenant_id": invitation.tenant_id,
            "target_user_id": created.id,
            "target_user_name": created.name,
        },
    )
    return api_success({
        "invitation": invitation_to_api_dict(invitation),
        "user": user_to_api_dict(created),
        "tenant": tenant_to_api_dict(tenant),
    }, status_code=201)


@router.route("/api/v1/jobs/<job_id>", methods=["GET"])
@login_required
@setup_required
def api_get_job(job_id: str):
    job = api_async_jobs.get_job(job_id)
    if not job:
        abort(NOT_FOUND, "Job not found.")
    actor = current_actor()
    if actor and not actor.has_role(*STAFF_ROLES) and job.actor_user_id != actor.id:
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success(job.to_dict())


@router.route("/api/v1/wireguard/interfaces", methods=["GET"])
@login_required
@setup_required
def api_list_wireguard_interfaces():
    actor = current_actor()
    items = get_accessible_interfaces(actor)
    tenant_id_filter = parse_optional_string(request.args.get("tenant_id", ""))
    if tenant_id_filter:
        if not actor_can_access_tenant(tenant_id_filter, actor):
            abort(FORBIDDEN, "Insufficient permissions.")
        items = [iface for iface in items if resolve_interface_tenant_id(iface) == tenant_id_filter]
    return api_success({
        "items": [interface_to_api_dict(iface, include_peers=True) for iface in items],
        "total": len(items),
        "scope": current_scope_label(),
    })


@router.route("/api/v1/wireguard/interfaces", methods=["POST"])
@login_required
@role_required(User.ROLE_ADMIN)
@setup_required
def api_create_wireguard_interface():
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})

    payload = parse_interface_payload(parse_json_payload())
    actor = current_actor()

    def create_interface():
        iface = Interface(
            name=payload["name"],
            description=payload["description"],
            gw_iface=payload["gateway"],
            ipv4_address=payload["ipv4"],
            listen_port=payload["listen_port"],
            auto=payload["auto"],
            on_up=payload["on_up"],
            on_down=payload["on_down"],
            tenant_id=payload["tenant_id"] or "",
        )
        interfaces[iface.uuid] = iface
        interfaces.sort()
        config_manager.save()
        return {"interface": interface_to_api_dict(iface, include_peers=True, actor=actor)}

    response_or_data = run_async_job_or_execute("wireguard.interface.create", create_interface)
    if isinstance(response_or_data, tuple):
        return response_or_data
    store_idempotency_response(response_or_data, 201)
    log_audit_event("wireguard.interface.create", details={"interface_name": payload["name"]})
    return api_success(response_or_data, status_code=201)


@router.route("/api/v1/wireguard/interfaces/<interface_id>", methods=["GET"])
@login_required
@setup_required
def api_get_wireguard_interface(interface_id: str):
    iface = get_interface_or_404(interface_id)
    if not interface_visible_to_actor(iface):
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success({"interface": interface_to_api_dict(iface, include_peers=True)})


@router.route("/api/v1/wireguard/interfaces/<interface_id>", methods=["PUT"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_update_wireguard_interface(interface_id: str):
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})

    iface = get_interface_or_404(interface_id)
    if not can_manage_wireguard_interface(iface):
        abort(FORBIDDEN, "Insufficient permissions.")
    payload = parse_interface_payload(parse_json_payload(), existing=iface)
    actor = current_actor()

    def update_interface():
        iface.edit(
            name=payload["name"],
            description=payload["description"],
            ipv4_address=payload["ipv4"],
            port=payload["listen_port"],
            gw_iface=payload["gateway"],
            auto=payload["auto"],
            on_up=payload["on_up"],
            on_down=payload["on_down"],
            tenant_id=payload["tenant_id"] or "",
        )
        config_manager.save()
        return {"interface": interface_to_api_dict(iface, include_peers=True, actor=actor)}

    response_or_data = run_async_job_or_execute("wireguard.interface.update", update_interface)
    if isinstance(response_or_data, tuple):
        return response_or_data
    store_idempotency_response(response_or_data, 200)
    log_audit_event("wireguard.interface.update", details={"interface_id": iface.uuid, "interface_name": iface.name})
    return api_success(response_or_data)


@router.route("/api/v1/wireguard/interfaces/<interface_id>", methods=["DELETE"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_delete_wireguard_interface(interface_id: str):
    parse_json_payload(allow_empty=True)
    iface = get_interface_or_404(interface_id)
    if not can_manage_wireguard_interface(iface):
        abort(FORBIDDEN, "Insufficient permissions.")

    def delete_interface():
        iface.remove()
        config_manager.save()
        return {"deleted": True, "interface_id": interface_id}

    response_or_data = run_async_job_or_execute("wireguard.interface.delete", delete_interface)
    if isinstance(response_or_data, tuple):
        return response_or_data
    log_audit_event("wireguard.interface.delete", details={"interface_id": interface_id})
    return api_success(response_or_data)


@router.route("/api/v1/wireguard/interfaces/<interface_id>/<action>", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_operate_wireguard_interface(interface_id: str, action: str):
    parse_json_payload(allow_empty=True)
    iface = get_interface_or_404(interface_id)
    if not can_manage_wireguard_interface(iface):
        abort(FORBIDDEN, "Insufficient permissions.")
    actor = current_actor()

    def operate_interface():
        operate_interface_action(iface, action)
        return {"interface": interface_to_api_dict(iface, include_peers=True, actor=actor)}

    response_or_data = run_async_job_or_execute(f"wireguard.interface.{action}", operate_interface)
    if isinstance(response_or_data, tuple):
        return response_or_data
    log_audit_event("wireguard.interface.operate", details={"interface_id": interface_id, "action": action})
    return api_success(response_or_data)


@router.route("/api/v1/wireguard/interfaces/<interface_id>/download", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_download_wireguard_interface(interface_id: str):
    iface = get_interface_or_404(interface_id)
    if not interface_visible_to_actor(iface):
        abort(FORBIDDEN, "Insufficient permissions.")
    return RestController().download_iface(iface)


@router.route("/api/v1/wireguard/interfaces/<interface_id>/qr", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_wireguard_interface_qr(interface_id: str):
    iface = get_interface_or_404(interface_id)
    if not interface_visible_to_actor(iface):
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success({
        "interface_id": iface.uuid,
        "qr_data_uri": build_qr_data_uri(iface.generate_conf()),
    })


@router.route("/api/v1/wireguard/peers", methods=["GET"])
@login_required
@setup_required
def api_list_wireguard_peers():
    actor = current_actor()
    items = get_accessible_peers(actor)
    interface_filter = parse_optional_string(request.args.get("interface_id", ""))
    tenant_id_filter = parse_optional_string(request.args.get("tenant_id", ""))
    if interface_filter:
        items = [peer for peer in items if peer.interface and peer.interface.uuid == interface_filter]
    if tenant_id_filter:
        if not actor_can_access_tenant(tenant_id_filter, actor):
            abort(FORBIDDEN, "Insufficient permissions.")
        items = [peer for peer in items if resolve_peer_tenant_id(peer) == tenant_id_filter]
    return api_success({
        "items": [peer_to_api_dict(peer) for peer in items],
        "total": len(items),
        "scope": current_scope_label(),
    })


@router.route("/api/v1/wireguard/peers", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_create_wireguard_peer():
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})

    payload = parse_peer_payload(parse_json_payload())

    def create_peer():
        peer = Peer(
            name=payload["name"],
            description=payload["description"],
            ipv4_address=payload["ipv4"],
            nat=payload["nat"],
            interface=payload["interface"],
            dns1=payload["dns1"],
            dns2=payload["dns2"],
            mode=payload["mode"],
            site_to_site_subnets=payload["site_to_site_subnets"],
            full_tunnel=payload["full_tunnel"],
            tenant_id=payload["tenant_id"] or "",
            owner_user_id=payload["owner_user_id"] or "",
            enabled=payload["enabled"],
        )
        payload["interface"].add_peer(peer)
        config_manager.save()
        return {"peer": peer_to_api_dict(peer)}

    response_or_data = run_async_job_or_execute("wireguard.peer.create", create_peer)
    if isinstance(response_or_data, tuple):
        return response_or_data
    store_idempotency_response(response_or_data, 201)
    log_audit_event("wireguard.peer.create", details={"peer_name": payload["name"]})
    return api_success(response_or_data, status_code=201)


@router.route("/api/v1/wireguard/peers/<peer_id>", methods=["GET"])
@login_required
@setup_required
def api_get_wireguard_peer(peer_id: str):
    peer = get_peer_or_404(peer_id)
    if not peer_visible_to_actor(peer):
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success({"peer": peer_to_api_dict(peer)})


@router.route("/api/v1/wireguard/peers/<peer_id>", methods=["PUT"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_update_wireguard_peer(peer_id: str):
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})

    peer = get_peer_or_404(peer_id)
    if not can_manage_wireguard_peer(peer):
        abort(FORBIDDEN, "Insufficient permissions.")
    payload = parse_peer_payload(parse_json_payload(), existing=peer)

    def update_peer():
        peer.edit(
            name=payload["name"],
            description=payload["description"],
            ipv4_address=payload["ipv4"],
            interface=payload["interface"],
            dns1=payload["dns1"],
            dns2=payload["dns2"],
            nat=payload["nat"],
            mode=payload["mode"],
            site_to_site_subnets=payload["site_to_site_subnets"],
            full_tunnel=payload["full_tunnel"],
            tenant_id=payload["tenant_id"] or "",
            owner_user_id=payload["owner_user_id"] or "",
            enabled=payload["enabled"],
        )
        config_manager.save()
        return {"peer": peer_to_api_dict(peer)}

    response_or_data = run_async_job_or_execute("wireguard.peer.update", update_peer)
    if isinstance(response_or_data, tuple):
        return response_or_data
    store_idempotency_response(response_or_data, 200)
    log_audit_event("wireguard.peer.update", details={"peer_id": peer_id, "peer_name": peer.name})
    return api_success(response_or_data)


@router.route("/api/v1/wireguard/peers/<peer_id>", methods=["DELETE"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_delete_wireguard_peer(peer_id: str):
    parse_json_payload(allow_empty=True)
    peer = get_peer_or_404(peer_id)
    if not can_manage_wireguard_peer(peer):
        abort(FORBIDDEN, "Insufficient permissions.")

    def delete_peer():
        peer.remove()
        config_manager.save()
        return {"deleted": True, "peer_id": peer_id}

    response_or_data = run_async_job_or_execute("wireguard.peer.delete", delete_peer)
    if isinstance(response_or_data, tuple):
        return response_or_data
    log_audit_event("wireguard.peer.delete", details={"peer_id": peer_id})
    return api_success(response_or_data)


@router.route("/api/v1/wireguard/peers/<peer_id>/download", methods=["GET"])
@login_required
@setup_required
def api_download_wireguard_peer(peer_id: str):
    peer = get_peer_or_404(peer_id)
    if not peer_visible_to_actor(peer):
        abort(FORBIDDEN, "Insufficient permissions.")
    require_client_wireguard_config_mfa()
    return RestController().download_peer(peer)


@router.route("/api/v1/wireguard/peers/<peer_id>/qr", methods=["GET"])
@login_required
@setup_required
def api_wireguard_peer_qr(peer_id: str):
    peer = get_peer_or_404(peer_id)
    if not peer_visible_to_actor(peer):
        abort(FORBIDDEN, "Insufficient permissions.")
    require_client_wireguard_config_mfa()
    return api_success({
        "peer_id": peer.uuid,
        "qr_data_uri": build_qr_data_uri(peer.generate_conf()),
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
        "enabled",
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
    cache_control = (
        "no-store, max-age=0"
        if RRD_GRAPH_CACHE_TTL_SECONDS <= 0
        else f"private, max-age={RRD_GRAPH_CACHE_TTL_SECONDS}"
    )
    return Response(
        png_data,
        mimetype="image/png",
        headers={"Cache-Control": cache_control}
    )


@router.route("/wireguard/interfaces/add", methods=['GET'])
@login_required
@role_required(User.ROLE_ADMIN)
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
@role_required(User.ROLE_ADMIN)
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
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def get_wireguard_iface(uuid: str):
    if uuid not in interfaces:
        abort(NOT_FOUND, f"Unknown interface '{uuid}'.")
    iface = interfaces[uuid]
    if request.method == "GET" and not interface_visible_to_actor(iface):
        abort(FORBIDDEN, "Insufficient permissions.")
    if request.method == "POST" and not can_manage_wireguard_interface(iface):
        abort(FORBIDDEN, "Insufficient permissions.")
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
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def remove_wireguard_iface(uuid: str):
    if uuid not in interfaces:
        abort(NOT_FOUND, f"Interface {uuid} not found.")
    if not can_manage_wireguard_interface(interfaces[uuid]):
        abort(FORBIDDEN, "Insufficient permissions.")
    return RestController(uuid).remove_iface()


@router.route("/wireguard/interfaces/<uuid>/<action>", methods=['POST'])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def operate_wireguard_iface(uuid: str, action: str):
    action = action.lower()
    if uuid not in interfaces:
        abort(NOT_FOUND, f"Interface {uuid} not found.")
    if not can_manage_wireguard_interface(interfaces[uuid]):
        abort(FORBIDDEN, "Insufficient permissions.")
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
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def download_wireguard_iface(uuid: str):
    if uuid not in interfaces.keys():
        error(f"Unknown interface {uuid}")
        abort(NOT_FOUND)
    if not interface_visible_to_actor(interfaces[uuid]):
        abort(FORBIDDEN, "Insufficient permissions.")
    return RestController().download_iface(interfaces[uuid])


@router.route("/wireguard/peers/add", methods=['GET'])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
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
    if len(form.interface.choices) < 1:
        abort(FORBIDDEN, "There are no accessible wireguard interfaces for this account.")
    return ViewController("web/wireguard-add-peer.html", **context).load()


@router.route("/wireguard/peers/add", methods=['POST'])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
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
    target_iface = interfaces.get_value_by_attr("name", form.interface.data)
    if not target_iface or not can_manage_wireguard_interface(target_iface):
        abort(FORBIDDEN, "Insufficient permissions.")
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
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def remove_wireguard_peer(uuid: str):
    peer = get_all_peers().get(uuid, None)
    if not peer:
        raise WireguardError(f"Unknown peer '{uuid}'.", NOT_FOUND)
    if not can_manage_wireguard_peer(peer):
        abort(FORBIDDEN, "Insufficient permissions.")
    return RestController().remove_peer(peer)


@router.route("/wireguard/peers/<uuid>", methods=['GET', "POST"])
@login_required
@setup_required
def get_wireguard_peer(uuid: str):
    peer = get_all_peers().get(uuid, None)
    if not peer:
        raise WireguardError(f"Unknown peer '{uuid}'.", NOT_FOUND)
    if request.method == "GET" and not peer_visible_to_actor(peer):
        abort(FORBIDDEN, "Insufficient permissions.")
    if request.method == "POST" and not can_manage_wireguard_peer(peer):
        abort(FORBIDDEN, "Insufficient permissions.")
    if request.method == "GET":
        require_client_wireguard_config_mfa()
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
        can_manage_peer = can_manage_wireguard_peer(peer)
        if not can_manage_peer:
            for field_name, field in form._fields.items():
                if field_name in ("csrf_token", "submit"):
                    continue
                render_kw = dict(field.render_kw or {})
                render_kw["disabled"] = True
                field.render_kw = render_kw
        context["form"] = form
        context["can_manage_peer"] = can_manage_peer
        return ViewController(view, **context).load()
    form = EditPeerForm.from_form(EditPeerForm(request.form), peer)
    context["form"] = form
    context["can_manage_peer"] = True
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
@setup_required
def download_wireguard_peer(uuid: str):
    peer = get_all_peers().get(uuid, None)
    if not peer:
        msg = f"Unknown peer '{uuid}'."
        error(msg)
        abort(NOT_FOUND, msg)
    if not peer_visible_to_actor(peer):
        abort(FORBIDDEN, "Insufficient permissions.")
    require_client_wireguard_config_mfa()
    return RestController().download_peer(peer)


@router.route("/themes")
@login_required
@setup_required
def themes():
    context = {
        "title": "Themes"
    }
    return ViewController("web/themes.html", **context).load()


@router.route("/documentation")
@login_required
@setup_required
def documentation():
    context = {
        "title": "Documentation",
    }
    return ViewController("web/documentation.html", **context).load()


@router.route("/api/v1/network/inventory", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_network_inventory():
    return api_success(build_network_inventory_payload())


@router.route("/api/v1/about", methods=["GET"])
@login_required
@setup_required
def api_about():
    return api_success(build_about_payload())


@router.route("/api/v1/profile", methods=["GET"])
@login_required
@setup_required
def api_profile():
    return api_success(build_profile_payload())


@router.route("/api/v1/profile", methods=["PUT"])
@login_required
@setup_required
def api_profile_update():
    return api_success(update_profile_from_payload(parse_json_payload()))


@router.route("/api/v1/profile/password", methods=["POST"])
@login_required
@setup_required
def api_profile_password_update():
    return api_success(update_profile_password_from_payload(parse_json_payload()))


@router.route("/api/v1/setup/status", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
def api_setup_status():
    return api_success(build_setup_status_payload())


@router.route("/api/v1/setup/bootstrap", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
def api_setup_bootstrap():
    return api_success(apply_setup_payload(parse_json_payload()))


@router.route("/api/v1/system/version", methods=["GET"])
@login_required
@setup_required
def api_system_version():
    from arpvpn import __version__

    return api_success({
        "release": getattr(__version__, "release", "unknown"),
        "commit": getattr(__version__, "commit", "unknown"),
        "scope": current_scope_label(),
    })


@router.route("/api/v1/system/health", methods=["GET"])
@login_required
@setup_required
def api_system_health():
    return api_success(build_system_health_payload())


@router.route("/api/v1/system/diagnostics", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_system_diagnostics():
    return api_success(build_system_diagnostics_payload())


@router.route("/api/v1/system/backup", methods=["GET"])
@login_required
@role_required(User.ROLE_ADMIN)
@setup_required
def api_system_backup():
    return api_success(build_system_backup_payload())


@router.route("/api/v1/system/restore", methods=["POST"])
@login_required
@role_required(User.ROLE_ADMIN)
@setup_required
def api_system_restore():
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})
    payload = parse_json_payload()
    backup_files = parse_system_backup_payload(payload)
    dry_run = parse_json_bool(payload, "dry_run", False)
    response_payload = {
        "format": API_BACKUP_FORMAT,
        "dry_run": dry_run,
        "files": {
            label: {
                "path": item["path"],
                "exists": item["exists"],
                "size_bytes": item["size_bytes"],
            }
            for label, item in backup_files.items()
        },
    }
    if not dry_run:
        apply_system_backup_payload(backup_files)
    store_idempotency_response(response_payload, 200)
    log_audit_event("system.restore", details={"dry_run": dry_run, "files": list(backup_files.keys())})
    return api_success(response_payload)


@router.route("/api/v1/system/restart", methods=["POST"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_system_restart():
    payload = parse_json_payload()
    reason = parse_optional_string(payload.get("reason")) or "Requested from ARPVPN UI/API."
    requested_mode = parse_optional_string(payload.get("mode")) or "auto"
    delay_seconds = parse_integer_value(payload.get("delay_seconds", 1), "delay_seconds", minimum=0, maximum=30)
    response_payload = request_process_restart(reason, requested_mode=requested_mode, delay_seconds=delay_seconds)
    log_audit_event("system.restart.request", details=response_payload)
    return api_success(response_payload, status_code=ACCEPTED)


@router.route("/api/v1/audit/events", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_audit_events():
    limit = parse_integer_value(request.args.get("limit", 100), "limit", minimum=1, maximum=1000)
    action_filter = parse_optional_string(request.args.get("action", ""))
    status_filter = parse_optional_string(request.args.get("status", ""))
    actor_id_filter = parse_optional_string(request.args.get("actor_id", ""))
    events = get_audit_events(max_tail_lines=max(limit * 20, 500))
    filtered = []
    for event in events:
        if action_filter and event.get("action") != action_filter:
            continue
        if status_filter and event.get("status") != status_filter:
            continue
        if actor_id_filter and event.get("actor_id") != actor_id_filter:
            continue
        filtered.append(event)
        if len(filtered) >= limit:
            break
    return api_success({
        "items": filtered,
        "total": len(filtered),
    })


@router.route("/api/v1/config/global", methods=["GET"])
@login_required
@role_required(*STAFF_ROLES)
@setup_required
def api_get_global_config():
    return api_success(build_global_config_payload())


@router.route("/api/v1/config/global", methods=["PUT"])
@login_required
@role_required(User.ROLE_ADMIN)
@setup_required
def api_update_global_config():
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})
    request_payload = parse_json_payload()
    update_global_config_from_payload(request_payload)
    response_payload = build_global_config_payload()
    store_idempotency_response(response_payload, 200)
    log_audit_event("config.global.update", details={"sections": list(request_payload.keys())})
    return api_success(response_payload)


@router.route("/api/v1/tenants/<tenant_id>/config", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_get_tenant_config(tenant_id: str):
    tenant = get_tenant_or_404(tenant_id)
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success({
        "tenant": tenant_to_api_dict(tenant),
        "settings": copy.deepcopy(getattr(tenant, "settings", {}) or {}),
    })


@router.route("/api/v1/tenants/<tenant_id>/config", methods=["PUT"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_update_tenant_config(tenant_id: str):
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})
    tenant = get_tenant_or_404(tenant_id)
    actor = current_actor()
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    if actor and actor.has_role(User.ROLE_SUPPORT):
        abort(FORBIDDEN, "Support users cannot update tenant configuration.")
    payload = parse_json_payload()
    settings_payload = payload.get("settings", None)
    if settings_payload is None:
        settings_payload = {
            key: payload.get(key)
            for key in ("branding", "limits", "defaults", "dns_servers", "tls", "runtime")
            if key in payload
        }
    tenant.settings = parse_tenant_settings(settings_payload, tenant)
    tenant.touch()
    tenants.sort()
    config_manager.save_identity_state()
    response_payload = {
        "tenant": tenant_to_api_dict(tenant),
        "settings": copy.deepcopy(tenant.settings),
    }
    store_idempotency_response(response_payload, 200)
    log_audit_event("config.tenant.update", details={"tenant_id": tenant.id})
    return api_success(response_payload)


@router.route("/api/v1/tenants/<tenant_id>/tls/status", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_get_tenant_tls_status(tenant_id: str):
    tenant = get_tenant_or_404(tenant_id)
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success(build_tenant_tls_status_payload(tenant))


@router.route("/api/v1/tenants/<tenant_id>/tls", methods=["PUT"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_update_tenant_tls_status(tenant_id: str):
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})
    tenant = get_tenant_or_404(tenant_id)
    actor = current_actor()
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    if actor and actor.has_role(User.ROLE_SUPPORT):
        abort(FORBIDDEN, "Support users cannot update tenant TLS configuration.")
    payload = parse_json_payload()
    tls_payload = payload.get("tls", payload)
    current_settings = copy.deepcopy(getattr(tenant, "settings", {}) or {})
    current_settings["tls"] = parse_tenant_tls_settings(tls_payload)
    tenant.settings = parse_tenant_settings(current_settings, tenant)
    tenant.touch()
    tenants.sort()
    config_manager.save_identity_state()
    response_payload = build_tenant_tls_status_payload(tenant)
    store_idempotency_response(response_payload, 200)
    log_audit_event("config.tenant.tls.update", details={"tenant_id": tenant.id})
    return api_success(response_payload)


@router.route("/api/v1/tenants/<tenant_id>/runtime", methods=["GET"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_get_tenant_runtime(tenant_id: str):
    tenant = get_tenant_or_404(tenant_id)
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    return api_success(build_tenant_runtime_payload(tenant))


@router.route("/api/v1/tenants/<tenant_id>/runtime", methods=["PUT"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_update_tenant_runtime(tenant_id: str):
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})
    tenant = get_tenant_or_404(tenant_id)
    actor = current_actor()
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    if actor and actor.has_role(User.ROLE_SUPPORT):
        abort(FORBIDDEN, "Support users cannot update tenant runtime configuration.")
    payload = parse_json_payload()
    runtime_payload = payload.get("runtime", payload)
    current_settings = copy.deepcopy(getattr(tenant, "settings", {}) or {})
    current_settings["runtime"] = parse_tenant_runtime_settings(runtime_payload, tenant)
    tenant.settings = parse_tenant_settings(current_settings, tenant)
    tenant.touch()
    tenants.sort()
    config_manager.save_identity_state()
    response_payload = build_tenant_runtime_payload(tenant)
    store_idempotency_response(response_payload, 200)
    log_audit_event("config.tenant.runtime.update", details={"tenant_id": tenant.id})
    return api_success(response_payload)


@router.route("/api/v1/tenants/<tenant_id>/runtime/allocate", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_allocate_tenant_runtime(tenant_id: str):
    parse_json_payload(allow_empty=True)
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})
    tenant = get_tenant_or_404(tenant_id)
    actor = current_actor()
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    if actor and actor.has_role(User.ROLE_SUPPORT):
        abort(FORBIDDEN, "Support users cannot allocate tenant runtime configuration.")
    current_settings = copy.deepcopy(getattr(tenant, "settings", {}) or {})
    allocated_runtime = allocate_tenant_runtime_ports(tenant, current_settings.get("runtime", {}))
    current_settings["runtime"] = allocated_runtime
    tenant.settings = parse_tenant_settings(current_settings, tenant)
    tenant.touch()
    tenants.sort()
    config_manager.save_identity_state()
    response_payload = build_tenant_runtime_payload(tenant)
    store_idempotency_response(response_payload, 200)
    log_audit_event("config.tenant.runtime.allocate", details={"tenant_id": tenant.id})
    return api_success(response_payload)


@router.route("/api/v1/tenants/<tenant_id>/runtime/<action>", methods=["POST"])
@login_required
@role_required(*USER_MANAGEMENT_ROLES)
@setup_required
def api_control_tenant_runtime(tenant_id: str, action: str):
    parse_json_payload(allow_empty=True)
    replay = parse_idempotency_replay()
    if replay:
        return api_success(replay[0], status_code=replay[1], meta={"idempotent_replay": True})
    tenant = get_tenant_or_404(tenant_id)
    actor = current_actor()
    if not tenant_visible_to_actor(tenant):
        abort(FORBIDDEN, "Insufficient permissions.")
    if actor and actor.has_role(User.ROLE_SUPPORT):
        abort(FORBIDDEN, "Support users cannot change tenant runtime state.")
    runtime = get_tenant_runtime_settings(tenant)
    operation = str(action or "").strip().lower()
    if operation == "start":
        runtime["desired_state"] = "running"
        runtime["status"] = "running"
        runtime["enabled"] = True
    elif operation == "stop":
        runtime["desired_state"] = "stopped"
        runtime["status"] = "stopped"
    elif operation == "restart":
        runtime["desired_state"] = "restarting"
        runtime["status"] = "planned"
        runtime["enabled"] = True
    else:
        abort(BAD_REQUEST, "action must be start, stop, or restart.")
    current_settings = copy.deepcopy(getattr(tenant, "settings", {}) or {})
    current_settings["runtime"] = runtime
    tenant.settings = parse_tenant_settings(current_settings, tenant)
    tenant.touch()
    tenants.sort()
    config_manager.save_identity_state()
    response_payload = build_tenant_runtime_payload(tenant)
    response_payload["requested_action"] = operation
    store_idempotency_response(response_payload, 200)
    log_audit_event("config.tenant.runtime.control", details={"tenant_id": tenant.id, "action": operation})
    return api_success(response_payload)


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
    payload = parse_json_payload()
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
@role_required(User.ROLE_ADMIN)
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
@role_required(User.ROLE_ADMIN)
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
@role_required(User.ROLE_ADMIN)
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


def get_user_peers(user_item: User) -> List[Peer]:
    return [
        peer
        for peer in get_all_peers().values()
        if (owner := resolve_peer_owner(peer)) and owner.id == user_item.id
    ]


def build_user_vpn_access_summary(user_item: User) -> List[Dict[str, Any]]:
    summaries: List[Dict[str, Any]] = []
    for peer in get_user_peers(user_item):
        summaries.append({
            "peer_id": peer.uuid,
            "peer_name": peer.name,
            "interface_name": peer.interface.name if peer.interface else None,
            "mode": peer.mode,
            "enabled": bool(peer.enabled),
            "full_tunnel": bool(peer.full_tunnel),
            "site_to_site_subnets": list(peer.site_to_site_subnets),
        })
    return summaries


def can_manage_user_account(target_user: User) -> bool:
    if current_user.has_role(User.ROLE_ADMIN):
        return True
    if current_user.has_role(User.ROLE_SUPPORT):
        return target_user.role == User.ROLE_CLIENT
    if current_user.has_role(User.ROLE_TENANT_ADMIN):
        actor_tenant_id = get_actor_tenant_id(current_user)
        return (
            target_user.role == User.ROLE_CLIENT and
            actor_tenant_id is not None and
            target_user.tenant_id == actor_tenant_id
        )
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
    create_form.peer_interface.choices = []
    if current_user.has_role(User.ROLE_SUPPORT, User.ROLE_TENANT_ADMIN):
        create_form.role.choices = [(User.ROLE_CLIENT, "Client")]
        if request.method == "GET":
            create_form.role.data = User.ROLE_CLIENT
        edit_form.role.choices = [(User.ROLE_CLIENT, "Client")]
    from arpvpn.web.forms import AddPeerForm
    create_form.peer_interface.choices = AddPeerForm.get_choices()
    if request.method == "GET" and create_form.role.data == User.ROLE_CLIENT and create_form.peer_interface.choices:
        create_form.create_peer.data = True
        default_iface_name = create_form.peer_interface.choices[0][0]
        create_form.peer_interface.data = default_iface_name
        default_iface = interfaces.get_value_by_attr("name", default_iface_name)
        if default_iface:
            from arpvpn.web.forms import AddPeerForm as PeerForm
            peer_form = PeerForm.populate(PeerForm(meta={"csrf": False}), default_iface)
            create_form.peer_mode.data = peer_form.mode.data
            create_form.peer_enabled.data = peer_form.enabled.data
            create_form.peer_nat.data = peer_form.nat.data
            create_form.peer_full_tunnel.data = peer_form.full_tunnel.data
            create_form.peer_description.data = peer_form.description.data
            create_form.peer_ipv4.data = peer_form.ipv4.data
            create_form.peer_dns1.data = peer_form.dns1.data
            create_form.peer_dns2.data = peer_form.dns2.data
            create_form.peer_site_to_site_subnets.data = peer_form.site_to_site_subnets.data
    impersonate_form = impersonate_form or ImpersonateClientForm()
    stop_form = stop_form or ImpersonationStopForm()
    users_list = get_accessible_users(current_user)
    return {
        "title": "Users",
        "create_form": create_form,
        "edit_form": edit_form,
        "delete_form": delete_form,
        "impersonate_form": impersonate_form,
        "stop_impersonation_form": stop_form,
        "users_list": users_list,
        "user_actions": build_user_actions(users_list),
        "user_vpn_access": {user_item.id: build_user_vpn_access_summary(user_item) for user_item in users_list},
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


def provision_peer_for_created_client(created_user: User, payload: Dict[str, Any]):
    if created_user.role != User.ROLE_CLIENT:
        return None
    if not parse_boolean_value(payload.get("create_peer"), False):
        return None
    from arpvpn.web.forms import AddPeerForm, derive_peer_name

    peer_form = AddPeerForm(meta={"csrf": False})
    peer_form.name.data = parse_optional_string(payload.get("peer_name")) or derive_peer_name(created_user.name)
    peer_form.mode.data = parse_optional_string(payload.get("peer_mode")) or Peer.MODE_CLIENT
    peer_form.enabled.data = parse_boolean_value(payload.get("peer_enabled"), True)
    peer_form.nat.data = parse_boolean_value(payload.get("peer_nat"), False)
    peer_form.full_tunnel.data = parse_boolean_value(payload.get("peer_full_tunnel"), False)
    peer_form.description.data = parse_optional_string(payload.get("peer_description"))
    peer_form.interface.choices = AddPeerForm.get_choices()
    peer_form.interface.data = parse_optional_string(payload.get("peer_interface"))
    peer_form.ipv4.data = parse_optional_string(payload.get("peer_ipv4"))
    peer_form.dns1.data = parse_optional_string(payload.get("peer_dns1")) or "8.8.8.8"
    peer_form.dns2.data = parse_optional_string(payload.get("peer_dns2"))
    peer_form.site_to_site_subnets.data = payload.get("peer_site_to_site_subnets", "")
    if not peer_form.interface.choices:
        abort(BAD_REQUEST, "No accessible WireGuard interfaces are available.")
    if not peer_form.interface.data:
        peer_form.interface.data = peer_form.interface.choices[0][0]
    if not peer_form.validate():
        details = summarize_form_errors(peer_form) or "unknown validation error"
        abort(BAD_REQUEST, f"Unable to provision WireGuard connection: {details}")
    return RestController().add_peer(peer_form)


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
    from arpvpn.web.forms import (
        AddPeerForm,
        CreateUserForm,
        DeleteUserForm,
        EditUserForm,
        ImpersonateClientForm,
        ImpersonationStopForm,
        derive_peer_name,
    )
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
    created_user = None
    created_peer = None
    try:
        created_user = RestController.create_user(form.username.data, form.password.data, form.role.data)
        if form.create_peer.data and created_user.role == User.ROLE_CLIENT:
            peer_form = AddPeerForm(meta={"csrf": False})
            peer_form.name.data = derive_peer_name(created_user.name)
            peer_form.mode.data = form.peer_mode.data or Peer.MODE_CLIENT
            peer_form.enabled.data = bool(form.peer_enabled.data)
            peer_form.nat.data = bool(form.peer_nat.data)
            peer_form.full_tunnel.data = bool(form.peer_full_tunnel.data)
            peer_form.description.data = form.peer_description.data
            peer_form.interface.choices = AddPeerForm.get_choices()
            peer_form.interface.data = form.peer_interface.data or peer_form.interface.choices[0][0]
            peer_form.ipv4.data = form.peer_ipv4.data
            peer_form.dns1.data = form.peer_dns1.data
            peer_form.dns2.data = form.peer_dns2.data
            peer_form.site_to_site_subnets.data = form.peer_site_to_site_subnets.data
            created_peer = RestController().add_peer(peer_form)
        context = get_users_management_context()
        context["success"] = True
        if created_peer:
            context["success_details"] = "User created successfully and their WireGuard connection was provisioned."
        else:
            context["success_details"] = "User created successfully."
    except Exception as e:
        if created_peer:
            try:
                created_peer.remove()
                config_manager.save()
            except Exception as rollback_error:
                log_exception(rollback_error)
        if created_user and created_user.id in users:
            try:
                del users[created_user.id]
                config_manager.save_identity_state()
            except Exception as rollback_error:
                log_exception(rollback_error)
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
    from arpvpn.web.forms import MfaForm, ProfileForm, PasswordResetForm
    profile_form = ProfileForm()
    profile_form.username.data = current_user.name
    if request.form:
        password_reset_form = PasswordResetForm(request.form)
    else:
        password_reset_form = PasswordResetForm()
    mfa_form = MfaForm()
    mfa_provisioning_uri = current_user.mfa_provisioning_uri(APP_NAME) if current_user.mfa_secret else None
    view = "web/profile.html"
    context = {
        "title": "Profile",
        "profile_form": profile_form,
        "password_reset_form": password_reset_form,
        "mfa_form": mfa_form,
        "mfa_enabled": current_user.mfa_enabled,
        "mfa_secret": current_user.mfa_secret,
        "mfa_provisioning_uri": mfa_provisioning_uri,
        "mfa_recovery_codes": [],
        "login_ago": get_time_ago(current_user.login_date),
    }
    return ViewController(view, **context).load()


@router.route("/profile", methods=['POST'])
@login_required
@setup_required
def save_profile():
    if "generate_secret" in request.form or "enable" in request.form or "disable" in request.form:
        return update_profile_mfa()
    if "new_password" in request.form:
        return password_reset()
    from arpvpn.web.forms import MfaForm, ProfileForm, PasswordResetForm
    view = "web/profile.html"
    profile_form = ProfileForm(request.form)
    password_reset_form = PasswordResetForm()
    mfa_form = MfaForm()
    context = {
        "title": "Profile",
        "profile_form": profile_form,
        "password_reset_form": password_reset_form,
        "mfa_form": mfa_form,
        "mfa_enabled": current_user.mfa_enabled,
        "mfa_secret": current_user.mfa_secret,
        "mfa_provisioning_uri": current_user.mfa_provisioning_uri(APP_NAME) if current_user.mfa_secret else None,
        "mfa_recovery_codes": [],
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


def update_profile_mfa():
    from arpvpn.web.forms import MfaForm, ProfileForm, PasswordResetForm
    view = "web/profile.html"
    profile_form = ProfileForm()
    profile_form.username.data = current_user.name
    password_reset_form = PasswordResetForm()
    mfa_form = MfaForm(request.form)
    context = {
        "title": "Profile",
        "profile_form": profile_form,
        "password_reset_form": password_reset_form,
        "mfa_form": mfa_form,
        "mfa_enabled": current_user.mfa_enabled,
        "mfa_secret": current_user.mfa_secret,
        "mfa_provisioning_uri": current_user.mfa_provisioning_uri(APP_NAME) if current_user.mfa_secret else None,
        "mfa_recovery_codes": [],
        "login_ago": get_time_ago(current_user.login_date),
    }
    if mfa_form.generate_secret.data:
        secret = generate_mfa_secret()
        recovery_codes = generate_recovery_codes()
        current_user.mfa_secret = secret
        current_user.mfa_enabled = False
        current_user.mfa_recovery_code_hashes = recovery_code_hashes(recovery_codes)
        config_manager.save_credentials()
        context["success"] = True
        context["success_details"] = "MFA setup secret generated. Scan it and confirm with a code from your authenticator app."
        context["mfa_secret"] = secret
        context["mfa_provisioning_uri"] = current_user.mfa_provisioning_uri(APP_NAME)
        context["mfa_recovery_codes"] = recovery_codes
        return ViewController(view, **context).load()
    if mfa_form.enable.data:
        if not current_user.mfa_secret:
            mfa_form.mfa_code.errors.append("Generate a setup secret first.")
            error("Unable to enable MFA: no setup secret.")
            return ViewController(view, **context).load()
        verified, consumed = current_user.verify_mfa(mfa_form.mfa_code.data, allow_recovery_codes=False)
        if not verified:
            mfa_form.mfa_code.errors.append("Invalid authenticator code.")
            error("Unable to enable MFA: invalid code.")
            return ViewController(view, **context).load()
        current_user.mfa_enabled = True
        mark_session_mfa_verified(current_user)
        config_manager.save_credentials()
        context["success"] = True
        context["success_details"] = "MFA enabled!"
        context["mfa_enabled"] = True
        if consumed:
            context["mfa_recovery_codes"] = []
        return ViewController(view, **context).load()
    if mfa_form.disable.data:
        if not current_user.mfa_enabled and not current_user.mfa_secret:
            context["warning"] = True
            context["warning_details"] = "MFA is already disabled."
            return ViewController(view, **context).load()
        current_user.disable_mfa()
        clear_session_mfa_verification()
        config_manager.save_credentials()
        context["success"] = True
        context["success_details"] = "MFA disabled!"
        context["mfa_enabled"] = False
        context["mfa_secret"] = None
        context["mfa_provisioning_uri"] = None
        context["mfa_recovery_codes"] = []
        return ViewController(view, **context).load()
    return ViewController(view, **context).load()


def password_reset():
    view = "web/profile.html"
    from arpvpn.web.forms import MfaForm, PasswordResetForm, ProfileForm
    profile_form = ProfileForm()
    profile_form.username.data = current_user.name
    password_reset_form = PasswordResetForm(request.form)
    mfa_form = MfaForm()
    context = {
        "title": "Profile",
        "profile_form": profile_form,
        "password_reset_form": password_reset_form,
        "mfa_form": mfa_form,
        "mfa_enabled": current_user.mfa_enabled,
        "mfa_secret": current_user.mfa_secret,
        "mfa_provisioning_uri": current_user.mfa_provisioning_uri(APP_NAME) if current_user.mfa_secret else None,
        "mfa_recovery_codes": [],
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
