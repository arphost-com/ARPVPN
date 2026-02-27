import argparse
import atexit
import os
from datetime import datetime, timedelta, timezone
from logging import warning, fatal, info, debug

from flask import Flask, session, current_app, request, redirect
from flask_login import LoginManager, current_user
from flask_login import login_manager as flask_login_manager
from flask_qrcode import QRcode
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

secure_cookies_env = os.environ.get("ARPVPN_SECURE_COOKIES", "0").lower() not in ("0", "false", "no")
secure_transport_by_config = web_config.tls_mode in (
    web_config.TLS_MODE_SELF_SIGNED,
    web_config.TLS_MODE_LETS_ENCRYPT,
    web_config.TLS_MODE_REVERSE_PROXY,
)
secure_cookies_enabled = secure_cookies_env or secure_transport_by_config

app.config['SECRET_KEY'] = web_config.secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = secure_cookies_enabled and not args.debug
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SECURE"] = secure_cookies_enabled and not args.debug
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
if secure_cookies_enabled:
    app.config["PREFERRED_URL_SCHEME"] = "https"

if web_config.tls_mode == web_config.TLS_MODE_REVERSE_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    if web_config.proxy_incoming_hostname:
        app.config["SERVER_NAME"] = web_config.proxy_incoming_hostname

app.register_blueprint(router)
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


def _https_redirect_host() -> str:
    if web_config.tls_mode == web_config.TLS_MODE_REVERSE_PROXY:
        return (web_config.proxy_incoming_hostname or "").strip()
    return (web_config.tls_server_name or "").strip()


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

    path = request.path or "/"
    query = request.query_string.decode("utf-8", errors="ignore")
    location = f"https://{host}{path}"
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
    if secure_cookies_enabled and not args.debug:
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
