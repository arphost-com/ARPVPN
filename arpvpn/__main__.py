import argparse
import atexit
import ipaddress
import os
import re
import socket
from datetime import datetime, timedelta, timezone
from logging import warning, fatal, info, debug

from flask import Flask, session, current_app, request, redirect
from flask_login import LoginManager, current_user
from flask_login import login_manager as flask_login_manager
from flask_qrcode import QRcode
from flask_wtf.csrf import generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix

from arpvpn.__version__ import commit, release
from arpvpn.common.models.user import users, User
from arpvpn.common.properties import global_properties
from arpvpn.common.utils.system import try_makedir
from arpvpn.core.managers.cron import cron_manager
from arpvpn.core.managers.wireguard import wireguard_manager
from arpvpn.web.static.assets.resources import APP_NAME

class ARPLoginManager(LoginManager):
    """
    Flask-Login 0.6.3 uses datetime.utcnow() for remember-cookie expiry.
    Keep behavior but avoid deprecated naive UTC datetime on Python 3.12+.
    """

    def _set_cookie(self, response):
        config = current_app.config
        cookie_name = config.get("REMEMBER_COOKIE_NAME", flask_login_manager.COOKIE_NAME)
        domain = config.get("REMEMBER_COOKIE_DOMAIN")
        path = config.get("REMEMBER_COOKIE_PATH", "/")

        secure = config.get("REMEMBER_COOKIE_SECURE", flask_login_manager.COOKIE_SECURE)
        httponly = config.get("REMEMBER_COOKIE_HTTPONLY", flask_login_manager.COOKIE_HTTPONLY)
        samesite = config.get("REMEMBER_COOKIE_SAMESITE", flask_login_manager.COOKIE_SAMESITE)

        if "_remember_seconds" in session:
            duration = timedelta(seconds=session["_remember_seconds"])
        else:
            duration = config.get("REMEMBER_COOKIE_DURATION", flask_login_manager.COOKIE_DURATION)

        data = flask_login_manager.encode_cookie(str(session["_user_id"]))

        if isinstance(duration, int):
            duration = timedelta(seconds=duration)

        try:
            expires = datetime.now(timezone.utc) + duration
        except TypeError as e:
            raise Exception(
                "REMEMBER_COOKIE_DURATION must be a datetime.timedelta,"
                f" instead got: {duration}"
            ) from e

        response.set_cookie(
            cookie_name,
            value=data,
            expires=expires,
            domain=domain,
            path=path,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )


login_manager = ARPLoginManager()


@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id, None)


def parse_args():
    parser = argparse.ArgumentParser(description=f"Welcome to {APP_NAME}, the best WireGuard's web GUI :)")
    parser.add_argument("workdir", type=str,
                        help=f"Path to the directory used to store all data related to {APP_NAME}.")
    parser.add_argument("--debug", help="Start flask in debug mode.", action="store_true")
    return parser.parse_args()


args = parse_args()

workdir = os.path.abspath(args.workdir)
if os.path.exists(workdir) and not os.path.isdir(workdir):
    fatal(f"'{workdir}' is not a valid working directory!")
try_makedir(workdir)
global_properties.workdir = workdir

from arpvpn.core.config.web import config as web_config
from arpvpn.core.config.logger import config as log_config
from arpvpn.core.managers.config import config_manager
from arpvpn.web.router import router

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
info(f"Logging to '{log_config.logfile}'...")
config_manager.load()
if log_config.overwrite:
    log_config.reset_logfile()

_COOKIE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


def _sanitize_cookie_name(name: str, fallback: str) -> str:
    candidate = (name or "").strip()
    if not candidate:
        return fallback
    if _COOKIE_NAME_PATTERN.fullmatch(candidate):
        return candidate
    warning("Ignoring invalid cookie name '%s'; using '%s' instead.", candidate, fallback)
    return fallback


def _container_cookie_suffix() -> str:
    explicit_suffix = (os.environ.get("ARPVPN_COOKIE_SUFFIX", "") or "").strip()
    if explicit_suffix:
        return re.sub(r"[^A-Za-z0-9]+", "_", explicit_suffix).strip("_").lower()

    raw_container_name = (os.environ.get("ARPVPN_CONTAINER_NAME", "") or "").strip()
    if raw_container_name:
        return re.sub(r"[^A-Za-z0-9]+", "_", raw_container_name).strip("_").lower()

    compose_project = (os.environ.get("COMPOSE_PROJECT_NAME", "") or "").strip()
    if compose_project:
        return re.sub(r"[^A-Za-z0-9]+", "_", compose_project).strip("_").lower()
    return ""


def _resolve_session_cookie_name() -> str:
    suffix = _container_cookie_suffix()
    default_name = f"arpvpn_session_{suffix}" if suffix else "arpvpn_session"
    return _sanitize_cookie_name(os.environ.get("ARPVPN_SESSION_COOKIE_NAME", ""), default_name)


def _resolve_remember_cookie_name(session_cookie_name: str) -> str:
    default_name = f"{session_cookie_name}_remember"
    return _sanitize_cookie_name(os.environ.get("ARPVPN_REMEMBER_COOKIE_NAME", ""), default_name)


secure_cookies_env = os.environ.get("ARPVPN_SECURE_COOKIES", "0").lower() not in ("0", "false", "no")
secure_transport_by_config = web_config.strict_https_mode
session_cookie_name = _resolve_session_cookie_name()
remember_cookie_name = _resolve_remember_cookie_name(session_cookie_name)
initial_secure_cookie_flag = bool(secure_transport_by_config and not args.debug)

app.config['SECRET_KEY'] = web_config.secret_key
app.config["SESSION_COOKIE_NAME"] = session_cookie_name
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = initial_secure_cookie_flag
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_NAME"] = remember_cookie_name
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SECURE"] = initial_secure_cookie_flag
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.config.setdefault("API_CSRF_ENABLED", True)
if secure_transport_by_config:
    app.config["PREFERRED_URL_SCHEME"] = "https"

if web_config.tls_mode == web_config.TLS_MODE_REVERSE_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    if web_config.proxy_incoming_hostname:
        app.config["SERVER_NAME"] = web_config.proxy_incoming_hostname

app.register_blueprint(router)
app.jinja_env.globals["csrf_token"] = generate_csrf
QRcode(app)
login_manager.init_app(app)
login_manager.login_view = "router.login"
wireguard_manager.start()
cron_manager.start()


def _https_redirect_mode_enabled() -> bool:
    if not bool(getattr(web_config, "redirect_http_to_https", False)):
        return False
    return web_config.tls_mode in (
        web_config.TLS_MODE_SELF_SIGNED,
        web_config.TLS_MODE_LETS_ENCRYPT,
        web_config.TLS_MODE_REVERSE_PROXY,
    )


def _is_valid_redirect_host(hostname: str) -> bool:
    candidate = (hostname or "").strip()
    if not candidate:
        return False
    if candidate.lower() == "localhost":
        return True
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        pass
    if "." not in candidate:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    if any(ch not in allowed for ch in candidate):
        return False
    return not candidate.startswith(".") and not candidate.endswith(".") and ".." not in candidate


def _detect_local_server_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 80))
            ip_value = (sock.getsockname()[0] or "").strip()
            if ip_value and not ipaddress.IPv4Address(ip_value).is_unspecified:
                return ip_value
    except OSError:
        pass
    try:
        host_ips = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        host_ips = []
    for ip_value in host_ips:
        if ip_value and not ip_value.startswith("127.") and not ipaddress.IPv4Address(ip_value).is_unspecified:
            return ip_value
    return ""


def _https_redirect_host() -> str:
    configured_host = ""
    if web_config.tls_mode == web_config.TLS_MODE_REVERSE_PROXY:
        configured_host = (web_config.proxy_incoming_hostname or "").strip()
    else:
        configured_host = (web_config.tls_server_name or "").strip()
    if _is_valid_redirect_host(configured_host):
        return configured_host
    fallback_ip = _detect_local_server_ip()
    if fallback_ip:
        if configured_host:
            warning(
                "Configured TLS server name '%s' is not a valid redirect host. "
                "Falling back to local IP '%s'.",
                configured_host,
                fallback_ip,
            )
        return fallback_ip
    request_host = (request.host or "").strip()
    if request_host.startswith("[") and "]" in request_host:
        request_host = request_host[1:request_host.index("]")]
    else:
        request_host = request_host.split(":", 1)[0].strip()
    if _is_valid_redirect_host(request_host):
        if configured_host:
            warning(
                "Configured TLS server name '%s' is not a valid redirect host. "
                "Falling back to request host '%s'.",
                configured_host,
                request_host,
            )
        return request_host
    return configured_host


def _https_redirect_port() -> int:
    if web_config.tls_mode == web_config.TLS_MODE_REVERSE_PROXY:
        return 443
    return int(getattr(web_config, "https_port", 443) or 443)


def _format_https_authority(host: str, port: int) -> str:
    candidate = (host or "").strip()
    if not candidate:
        return ""
    if candidate.startswith("[") and "]:" in candidate:
        return candidate
    if not candidate.startswith("[") and ":" in candidate:
        maybe_port = candidate.rsplit(":", 1)[1]
        if maybe_port.isdigit():
            return candidate
    if port == 443:
        return candidate
    return f"{candidate}:{port}"


def _request_uses_https_transport() -> bool:
    if request.is_secure:
        return True
    x_forwarded_proto = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
    return x_forwarded_proto == "https"


def _resolve_secure_cookie_flag_for_request() -> bool:
    if args.debug:
        return False
    if web_config.strict_https_mode:
        return True
    # Compatibility behavior for mixed HTTP/HTTPS deployments:
    # honor secure cookies only on HTTPS requests when forced via env.
    if secure_cookies_env:
        return _request_uses_https_transport()
    return False


@app.before_request
def sync_cookie_security_with_request_transport():
    secure_flag = _resolve_secure_cookie_flag_for_request()
    app.config["SESSION_COOKIE_SECURE"] = secure_flag
    app.config["REMEMBER_COOKIE_SECURE"] = secure_flag


@app.before_request
def maybe_redirect_http_to_https():
    if not _https_redirect_mode_enabled():
        return None
    if request.is_secure:
        return None
    x_forwarded_proto = request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower()
    if x_forwarded_proto == "https":
        return None

    host = _https_redirect_host()
    if not host:
        warning("HTTP->HTTPS redirect enabled but no trusted hostname configured; skipping redirect.")
        return None
    authority = _format_https_authority(host, _https_redirect_port())
    if not authority:
        warning("HTTP->HTTPS redirect enabled but no trusted hostname configured; skipping redirect.")
        return None

    path = request.path or "/"
    query = request.query_string.decode("utf-8", errors="ignore")
    location = f"https://{authority}{path}"
    if query:
        location = f"{location}?{query}"
    return redirect(location, code=307)


@app.context_processor
def inject_user_access_context():
    role = None
    can_manage_users = False
    is_staff = False
    impersonator_name = None
    impersonator_role = None
    impersonating = False
    if current_user and current_user.is_authenticated:
        role = getattr(current_user, "role", User.ROLE_CLIENT)
        is_staff = role in (User.ROLE_ADMIN, User.ROLE_SUPPORT)
        can_manage_users = is_staff
        impersonator_id = session.get("impersonator_user_id")
        if impersonator_id:
            impersonator = users.get(impersonator_id, None)
            if impersonator and impersonator.id != current_user.id:
                impersonating = True
                can_manage_users = False
                impersonator_name = impersonator.name
                impersonator_role = impersonator.role
            else:
                session.pop("impersonator_user_id", None)
    from arpvpn.web.forms import ImpersonationStopForm
    return {
        "current_user_role": role,
        "current_user_is_staff": is_staff,
        "current_user_can_manage_users": can_manage_users,
        "is_impersonating": impersonating,
        "impersonator_name": impersonator_name,
        "impersonator_role": impersonator_role,
        "stop_impersonation_form": ImpersonationStopForm(),
    }


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if web_config.strict_https_mode and not args.debug:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://code.jquery.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.datatables.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.datatables.net; "
        "img-src 'self' data:; "
        "font-src 'self' https: data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    return response


@atexit.register
def on_exit():
    warning(f"Shutting down {APP_NAME}...")
    cron_manager.stop()
    wireguard_manager.stop()


if __name__ == "__main__":
    warning("**************************")
    warning("RUNNING DEVELOPMENT SERVER")
    warning("**************************")
    global_properties.dev_env = True
    # Override log level (although it can be manually edited via UI)
    log_config.level = "debug"
    log_config.apply()
    # Unlike the production scenario, a missing version file is not fatal
    if not release or not commit:
        warning("!! No versioning information provided !!")
    else:
        info(f"Running {APP_NAME} {release}")
        debug(f"Commit hash: {commit}")
    # Keep debug server local-only; expose remotely only via hardened reverse proxy.
    app.run(debug=args.debug, port=8080, host="127.0.0.1")
else:
    if not release:
        if global_properties.dev_env:
            warning("!! No versioning information provided !!")
        else:
            fatal("!! No versioning information provided !!")
            exit(1)
    if not commit:
        warning("!! No commit information provided !!")
    if "-" in release or "+" in release:
        global_properties.dev_env = True
    info(f"Running {APP_NAME} {release}")
    if commit:
        debug(f"Commit hash: {commit}")
