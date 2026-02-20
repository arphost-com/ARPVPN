import argparse
import atexit
import os
from datetime import timedelta
from logging import warning, fatal, info, debug

from flask import Flask
from flask_login import LoginManager
from flask_qrcode import QRcode

from arpvpn.__version__ import commit, release
from arpvpn.common.models.user import users
from arpvpn.common.properties import global_properties
from arpvpn.common.utils.system import try_makedir
from arpvpn.core.managers.cron import cron_manager
from arpvpn.core.managers.wireguard import wireguard_manager
from arpvpn.web.static.assets.resources import APP_NAME

login_manager = LoginManager()


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

secure_cookies_enabled = os.environ.get("ARPVPN_SECURE_COOKIES", "1").lower() not in ("0", "false", "no")

app.config['SECRET_KEY'] = web_config.secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = secure_cookies_enabled and not args.debug
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SECURE"] = secure_cookies_enabled and not args.debug
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.register_blueprint(router)
QRcode(app)
login_manager.init_app(app)
login_manager.login_view = "router.login"
wireguard_manager.start()
cron_manager.start()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if not args.debug:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://code.jquery.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.datatables.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.datatables.net; "
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
    app.run(debug=args.debug, port=8080, host="0.0.0.0")
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
