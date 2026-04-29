import ipaddress
import json
import re
from secrets import randbelow
from shutil import which
from typing import List, Tuple

from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField, SubmitField, SelectField, IntegerField, \
    TextAreaField
from wtforms.validators import DataRequired, InputRequired

from arpvpn.common.models.user import User
from arpvpn.common.utils.encryption import CryptoUtils
from arpvpn.common.utils.network import get_system_interfaces, get_default_gateway
from arpvpn.common.utils.strings import list_to_str
from arpvpn.core.config.logger import config as logger_config
from arpvpn.core.config.traffic import config as traffic_config
from arpvpn.core.config.web import config as web_config
from arpvpn.core.config.wireguard import config as wireguard_config, detect_wireguard_binary
from arpvpn.core.managers import traffic_storage
from arpvpn.core.managers.config import config_manager
from arpvpn.core.models import Interface, Peer, interfaces
from arpvpn.web.utils import fake
from arpvpn.web.validators import LoginUsernameValidator, LoginPasswordValidator, SignupPasswordValidator, \
    SignupUsernameValidator, SettingsSecretKeyValidator, PositiveIntegerValidator, \
    InterfaceIpValidator, InterfaceNameValidator, InterfacePortValidator, PeerIpValidator, PeerPrimaryDnsValidator, \
    PeerSecondaryDnsValidator, PeerNameValidator, NewPasswordValidator, OldPasswordValidator, JsonDataValidator, \
    PathExistsValidator, EndpointValidator, PeerSiteToSiteSubnetsValidator, HostnameOrIPv4Validator, \
    HostnameValidator, EmailValidator, is_valid_tls_server_name


def derive_peer_name(source: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(source or "").strip()).strip("-_. ")
    candidate = candidate[:Peer.MAX_NAME_LENGTH]
    if candidate and Peer.is_name_valid(candidate):
        return candidate
    return Peer.generate_valid_name()


def fill_missing_wireguard_binary_fields(form):
    defaults = {
        "app_wg_bin": detect_wireguard_binary("wg"),
        "app_wg_quick_bin": detect_wireguard_binary("wg-quick"),
        "app_iptables_bin": detect_wireguard_binary("iptables"),
    }
    for field_name, detected_path in defaults.items():
        if not detected_path:
            continue
        field = getattr(form, field_name, None)
        if field is not None and not (field.data or "").strip():
            field.data = detected_path


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), LoginUsernameValidator()],
                           render_kw={"placeholder": "Enter username", "autocomplete": "username"})
    password = PasswordField('Password', validators=[DataRequired(), LoginPasswordValidator()],
                             render_kw={"placeholder": "Enter password", "autocomplete": "current-password"})
    mfa_code = StringField('MFA code', render_kw={"placeholder": "123456", "autocomplete": "one-time-code"})
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Log in')
    next = StringField()


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), SignupUsernameValidator()],
                           render_kw={"placeholder": "Enter username", "autocomplete": "username"})
    password = PasswordField(
        'Password',
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter password", "autocomplete": "new-password"},
    )
    confirm = PasswordField('Confirm password', validators=[DataRequired(), SignupPasswordValidator()],
                            render_kw={"placeholder": "Confirm password", "autocomplete": "new-password"})
    submit = SubmitField('Create account')
    next = StringField()


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), SignupUsernameValidator()],
                           render_kw={"placeholder": "Enter username", "autocomplete": "username"})
    password = PasswordField(
        'Password',
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter password", "autocomplete": "new-password"},
    )
    confirm = PasswordField('Confirm password', validators=[DataRequired(), SignupPasswordValidator()],
                            render_kw={"placeholder": "Confirm password", "autocomplete": "new-password"})
    role = SelectField(
        "Role",
        choices=[
            (User.ROLE_CLIENT, "Client"),
            (User.ROLE_SUPPORT, "Support"),
            (User.ROLE_ADMIN, "Admin"),
        ],
        default=User.ROLE_CLIENT,
    )
    create_peer = BooleanField("Provision WireGuard connection", default=False)
    peer_interface = SelectField("WireGuard interface", validate_choice=False)
    peer_mode = SelectField(
        "VPN access",
        choices=[
            (Peer.MODE_CLIENT, "Client"),
            (Peer.MODE_SITE_TO_SITE, "Site-to-site"),
        ],
        default=Peer.MODE_CLIENT,
    )
    peer_enabled = BooleanField("Enabled", default=True)
    peer_nat = BooleanField("NAT", default=False)
    peer_full_tunnel = BooleanField("Full tunnel", default=False)
    peer_description = TextAreaField("Connection description", render_kw={"placeholder": "Some details..."})
    peer_ipv4 = StringField("Peer IPv4", render_kw={"placeholder": "0.0.0.0/32"})
    peer_dns1 = StringField("Primary DNS", render_kw={"placeholder": "8.8.8.8"})
    peer_dns2 = StringField("Secondary DNS", render_kw={"placeholder": "8.8.4.4"})
    peer_site_to_site_subnets = TextAreaField(
        "Remote site subnets",
        render_kw={"placeholder": "10.10.0.0/16, 172.16.50.0/24"},
    )
    submit = SubmitField('Create user')

    def validate(self, extra_validators=None):
        valid = super().validate(extra_validators)
        role = (self.role.data or User.ROLE_CLIENT).strip()
        create_peer = bool(self.create_peer.data) and role == User.ROLE_CLIENT
        self.create_peer.data = create_peer

        if not valid:
            return False

        if not create_peer:
            return True

        peer_form = AddPeerForm(meta={"csrf": False})
        peer_form.name.data = derive_peer_name(self.username.data)
        peer_form.mode.data = self.peer_mode.data or Peer.MODE_CLIENT
        peer_form.enabled.data = bool(self.peer_enabled.data)
        peer_form.nat.data = bool(self.peer_nat.data)
        peer_form.full_tunnel.data = bool(self.peer_full_tunnel.data)
        peer_form.description.data = self.peer_description.data
        peer_form.interface.choices = AddPeerForm.get_choices()
        peer_form.interface.data = self.peer_interface.data
        peer_form.ipv4.data = self.peer_ipv4.data
        peer_form.dns1.data = self.peer_dns1.data
        peer_form.dns2.data = self.peer_dns2.data
        peer_form.site_to_site_subnets.data = self.peer_site_to_site_subnets.data

        if not peer_form.interface.choices:
            self.create_peer.errors.append("No accessible WireGuard interfaces are available.")
            return False
        if not peer_form.interface.data:
            peer_form.interface.data = peer_form.interface.choices[0][0]
            self.peer_interface.data = peer_form.interface.data

        if not peer_form.validate():
            for field_name, errors in peer_form.errors.items():
                target_field = getattr(self, f"peer_{field_name}", None)
                if target_field is None:
                    continue
                target_field.errors.extend(errors)
            return False
        return True


class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()],
                           render_kw={"placeholder": "Enter username"})
    role = SelectField(
        "Role",
        choices=[
            (User.ROLE_CLIENT, "Client"),
            (User.ROLE_SUPPORT, "Support"),
            (User.ROLE_ADMIN, "Admin"),
        ],
        default=User.ROLE_CLIENT,
    )
    new_password = PasswordField('New password', render_kw={"placeholder": "Leave blank to keep current password"})
    confirm = PasswordField('Confirm new password', render_kw={"placeholder": "Confirm new password"})
    submit = SubmitField('Save user')

    def validate(self, extra_validators=None):
        valid = super().validate(extra_validators)
        username = (self.username.data or "").strip()
        if not username:
            self.username.errors.append("is required.")
            valid = False

        if self.new_password.data or self.confirm.data:
            if not self.new_password.data:
                self.new_password.errors.append("is required when changing the password.")
                valid = False
            if self.new_password.data != self.confirm.data:
                self.confirm.errors.append("must match the new password.")
                valid = False
        return valid


class DeleteUserForm(FlaskForm):
    submit = SubmitField("Delete")


class ImpersonationStopForm(FlaskForm):
    submit = SubmitField("Stop impersonating")


class ImpersonateClientForm(FlaskForm):
    submit = SubmitField("Impersonate")


class SettingsForm(FlaskForm):
    web_login_attempts = IntegerField("Max login attempts",
                                      validators=[InputRequired(), PositiveIntegerValidator()],
                                      render_kw={"placeholder": f"{web_config.DEFAULT_LOGIN_ATTEMPTS}",
                                                 "type": "number"}, default=web_config.login_attempts)
    web_login_ban_time = IntegerField("Login ban time", validators=[InputRequired(), PositiveIntegerValidator()],
                                      render_kw={"placeholder": f"{web_config.DEFAULT_BAN_SECONDS}",
                                                 "type": "number"}, default=web_config.login_ban_time)
    web_secret_key = StringField("Secret key", validators=[DataRequired(), SettingsSecretKeyValidator()],
                                 render_kw={"placeholder": f'A {CryptoUtils.KEY_LEN} characters long secret key'},
                                 default=web_config.secret_key)
    web_credentials_file = StringField("Credentials file",
                                       render_kw={"placeholder": "path/to/file", "disabled": "disabled"},
                                       default=web_config.credentials_file, validators=[DataRequired()])
    web_tls_mode = SelectField(
        "TLS mode",
        choices=[
            (web_config.TLS_MODE_HTTP, "Direct HTTP"),
            (web_config.TLS_MODE_SELF_SIGNED, "Self-signed certificate"),
            (web_config.TLS_MODE_LETS_ENCRYPT, "Let's Encrypt certificate"),
            (web_config.TLS_MODE_REVERSE_PROXY, "Behind reverse proxy"),
        ],
        default=web_config.tls_mode,
    )
    web_tls_server_name = StringField(
        "TLS / External hostname",
        render_kw={"placeholder": "vpn.example.com"},
        default=web_config.tls_server_name,
        validators=[HostnameOrIPv4Validator()],
    )
    web_tls_letsencrypt_email = StringField(
        "Let's Encrypt email",
        render_kw={"placeholder": "admin@example.com"},
        default=web_config.tls_letsencrypt_email,
        validators=[EmailValidator()],
    )
    web_proxy_incoming_hostname = StringField(
        "Reverse proxy incoming hostname",
        render_kw={"placeholder": "vpn.example.com"},
        default=web_config.proxy_incoming_hostname,
        validators=[HostnameValidator()],
    )
    web_redirect_http_to_https = BooleanField(
        "Redirect HTTP requests to HTTPS",
        default=web_config.redirect_http_to_https,
    )
    web_tls_generate_self_signed = BooleanField("Generate/re-generate self-signed certificate now", default=False)
    web_tls_issue_letsencrypt = BooleanField("Issue/renew Let's Encrypt certificate now", default=False)

    app_config_file = StringField("Configuration file", render_kw={"disabled": "disabled"},
                                  default=config_manager.config_filepath, validators=[DataRequired()])
    app_endpoint = StringField("Endpoint", render_kw={"placeholder": "vpn.example.com"},
                               default=wireguard_config.endpoint, validators=[DataRequired(), EndpointValidator()])
    app_interfaces_folder = StringField("Interfaces' directory",
                                        render_kw={"placeholder": "path/to/folder", "disabled": "disabled"},
                                        default=wireguard_config.interfaces_folder, validators=[DataRequired()])
    app_wg_bin = StringField("wg bin", render_kw={"placeholder": "path/to/file"}, default=wireguard_config.wg_bin,
                             validators=[DataRequired(), PathExistsValidator()])
    app_wg_quick_bin = StringField("wg-quick bin", render_kw={"placeholder": "path/to/file"},
                                   default=wireguard_config.wg_quick_bin,
                                   validators=[DataRequired(), PathExistsValidator()])
    app_iptables_bin = StringField("iptables bin", render_kw={"placeholder": "path/to/file"},
                                   default=wireguard_config.iptables_bin,
                                   validators=[DataRequired(), PathExistsValidator()])

    log_overwrite = BooleanField("Overwrite", default=logger_config.overwrite)
    log_file = StringField("Logfile", render_kw={"placeholder": "path/to/file", "disabled": "disabled"},
                           default=logger_config.logfile)
    log_level = SelectField(choices=logger_config.LEVELS.keys(), default=logger_config.level)

    traffic_enabled = BooleanField("Enabled", default=traffic_config.enabled)
    traffic_driver = SelectField("Driver", choices=traffic_storage.registered_drivers.keys())
    traffic_driver_options = TextAreaField("Driver configuration", validators=[DataRequired(), JsonDataValidator()])

    submit = SubmitField('Save')

    def validate(self, extra_validators=None):
        fill_missing_wireguard_binary_fields(self)
        valid = super().validate(extra_validators)
        mode = (self.web_tls_mode.data or web_config.TLS_MODE_HTTP).strip()
        if mode not in web_config.TLS_MODES:
            self.web_tls_mode.errors.append("invalid TLS mode selected.")
            valid = False
            mode = web_config.TLS_MODE_HTTP
        self.web_tls_mode.data = mode

        requires_hostname = mode in (
            web_config.TLS_MODE_SELF_SIGNED,
            web_config.TLS_MODE_LETS_ENCRYPT,
        )
        hostname = (self.web_tls_server_name.data or "").strip()
        if requires_hostname and not hostname:
            self.web_tls_server_name.errors.append(
                "is required when TLS mode is self-signed or Let's Encrypt."
            )
            valid = False

        if mode == web_config.TLS_MODE_SELF_SIGNED and hostname:
            if not is_valid_tls_server_name(hostname, allow_ipv4=True, allow_localhost=True):
                self.web_tls_server_name.errors.append(
                    "must be a valid IPv4 address or fully-qualified hostname "
                    "(example: vpn.example.com)."
                )
                valid = False

        if mode == web_config.TLS_MODE_LETS_ENCRYPT and hostname:
            if not is_valid_tls_server_name(hostname, allow_ipv4=False, allow_localhost=False):
                self.web_tls_server_name.errors.append(
                    "must be a fully-qualified hostname for Let's Encrypt."
                )
                valid = False

        if self.web_tls_generate_self_signed.data and mode != web_config.TLS_MODE_SELF_SIGNED:
            self.web_tls_generate_self_signed.errors.append(
                "can only be used when TLS mode is set to self-signed."
            )
            valid = False

        if self.web_tls_issue_letsencrypt.data and mode != web_config.TLS_MODE_LETS_ENCRYPT:
            self.web_tls_issue_letsencrypt.errors.append(
                "can only be used when TLS mode is set to Let's Encrypt."
            )
            valid = False

        if mode == web_config.TLS_MODE_REVERSE_PROXY:
            proxy_hostname = (self.web_proxy_incoming_hostname.data or "").strip()
            if not proxy_hostname:
                self.web_proxy_incoming_hostname.errors.append(
                    "is required when reverse proxy mode is enabled."
                )
                valid = False
            elif not is_valid_tls_server_name(proxy_hostname, allow_ipv4=False, allow_localhost=True):
                self.web_proxy_incoming_hostname.errors.append(
                    "must be localhost or a fully-qualified hostname (example: vpn.example.com)."
                )
                valid = False

        if self.web_redirect_http_to_https.data and mode == web_config.TLS_MODE_HTTP:
            self.web_redirect_http_to_https.errors.append(
                "can only be enabled when TLS mode is not Direct HTTP."
            )
            valid = False
        return valid

    @classmethod
    def new(cls) -> "SettingsForm":
        form = cls()
        form.web_login_attempts.data = web_config.login_attempts
        form.web_login_ban_time.data = web_config.login_ban_time
        form.web_secret_key.data = web_config.secret_key
        form.web_credentials_file.data = web_config.credentials_file
        form.web_tls_mode.data = web_config.tls_mode
        form.web_tls_server_name.data = web_config.tls_server_name
        form.web_tls_letsencrypt_email.data = web_config.tls_letsencrypt_email
        form.web_proxy_incoming_hostname.data = web_config.proxy_incoming_hostname
        form.web_redirect_http_to_https.data = web_config.redirect_http_to_https
        form.web_tls_generate_self_signed.data = False
        form.web_tls_issue_letsencrypt.data = False

        form.app_config_file.data = config_manager.config_filepath
        form.app_endpoint.data = wireguard_config.endpoint
        form.app_interfaces_folder.data = wireguard_config.interfaces_folder
        form.app_wg_bin.data = wireguard_config.wg_bin
        form.app_wg_quick_bin.data = wireguard_config.wg_quick_bin
        form.app_iptables_bin.data = wireguard_config.iptables_bin
        fill_missing_wireguard_binary_fields(form)

        form.log_overwrite.data = logger_config.overwrite
        form.log_file.data = logger_config.logfile
        form.log_level.data = logger_config.level

        form.traffic_enabled.data = traffic_config.enabled
        form.traffic_driver.data = traffic_storage.registered_drivers.keys()
        form.traffic_driver_options.data = json.dumps(traffic_config.driver.__to_yaml_dict__(), indent=4,
                                                      sort_keys=True)
        return form


class SetupForm(FlaskForm):
    app_endpoint = StringField("Endpoint", render_kw={"placeholder": "vpn.example.com"},
                               default=wireguard_config.endpoint, validators=[DataRequired(), EndpointValidator()])
    app_wg_bin = StringField("wg bin", render_kw={"placeholder": "path/to/file"}, default=wireguard_config.wg_bin,
                             validators=[DataRequired(), PathExistsValidator()])
    app_wg_quick_bin = StringField("wg-quick bin", render_kw={"placeholder": "path/to/file"},
                                   default=wireguard_config.wg_quick_bin,
                                   validators=[DataRequired(), PathExistsValidator()])
    app_iptables_bin = StringField("iptables bin", render_kw={"placeholder": "path/to/file"},
                                   default=wireguard_config.iptables_bin,
                                   validators=[DataRequired(), PathExistsValidator()])
    web_tls_mode = SelectField(
        "TLS mode",
        choices=[
            (web_config.TLS_MODE_HTTP, "Direct HTTP"),
            (web_config.TLS_MODE_SELF_SIGNED, "Self-signed certificate"),
            (web_config.TLS_MODE_LETS_ENCRYPT, "Let's Encrypt certificate"),
            (web_config.TLS_MODE_REVERSE_PROXY, "Behind reverse proxy"),
        ],
        default=web_config.TLS_MODE_SELF_SIGNED,
    )
    web_tls_server_name = StringField(
        "TLS / External hostname",
        render_kw={"placeholder": "vpn.example.com"},
        default=web_config.tls_server_name,
        validators=[HostnameOrIPv4Validator()],
    )
    web_tls_letsencrypt_email = StringField(
        "Let's Encrypt email",
        render_kw={"placeholder": "admin@example.com"},
        default=web_config.tls_letsencrypt_email,
        validators=[EmailValidator()],
    )
    web_proxy_incoming_hostname = StringField(
        "Reverse proxy incoming hostname",
        render_kw={"placeholder": "vpn.example.com"},
        default=web_config.proxy_incoming_hostname,
        validators=[HostnameValidator()],
    )
    web_redirect_http_to_https = BooleanField(
        "Redirect HTTP requests to HTTPS",
        default=web_config.redirect_http_to_https,
    )
    web_tls_generate_self_signed = BooleanField("Generate self-signed certificate now", default=True)
    web_tls_issue_letsencrypt = BooleanField("Issue Let's Encrypt certificate now", default=False)

    log_overwrite = BooleanField("Overwrite", default=logger_config.overwrite)

    traffic_enabled = BooleanField("Enabled", default=traffic_config.enabled)

    submit = SubmitField('Next')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fill_missing_wireguard_binary_fields(self)

    def validate(self, extra_validators=None):
        fill_missing_wireguard_binary_fields(self)
        valid = super().validate(extra_validators)
        mode = (self.web_tls_mode.data or web_config.TLS_MODE_HTTP).strip()
        if mode not in web_config.TLS_MODES:
            self.web_tls_mode.errors.append("invalid TLS mode selected.")
            valid = False
            mode = web_config.TLS_MODE_HTTP
        self.web_tls_mode.data = mode

        requires_hostname = mode in (
            web_config.TLS_MODE_SELF_SIGNED,
            web_config.TLS_MODE_LETS_ENCRYPT,
        )
        if requires_hostname and not (self.web_tls_server_name.data or "").strip():
            fallback_server_name = (self.app_endpoint.data or "").strip()
            if fallback_server_name:
                self.web_tls_server_name.data = fallback_server_name
        hostname = (self.web_tls_server_name.data or "").strip()
        if requires_hostname and not hostname:
            self.web_tls_server_name.errors.append(
                "is required when TLS mode is self-signed or Let's Encrypt."
            )
            valid = False

        if mode == web_config.TLS_MODE_SELF_SIGNED and hostname:
            if not is_valid_tls_server_name(hostname, allow_ipv4=True, allow_localhost=True):
                self.web_tls_server_name.errors.append(
                    "must be a valid IPv4 address or fully-qualified hostname "
                    "(example: vpn.example.com)."
                )
                valid = False

        if mode == web_config.TLS_MODE_LETS_ENCRYPT and hostname:
            if not is_valid_tls_server_name(hostname, allow_ipv4=False, allow_localhost=False):
                self.web_tls_server_name.errors.append(
                    "must be a fully-qualified hostname for Let's Encrypt."
                )
                valid = False

        if self.web_tls_generate_self_signed.data and mode != web_config.TLS_MODE_SELF_SIGNED:
            self.web_tls_generate_self_signed.errors.append(
                "can only be used when TLS mode is set to self-signed."
            )
            valid = False

        if self.web_tls_issue_letsencrypt.data and mode != web_config.TLS_MODE_LETS_ENCRYPT:
            self.web_tls_issue_letsencrypt.errors.append(
                "can only be used when TLS mode is set to Let's Encrypt."
            )
            valid = False

        if mode == web_config.TLS_MODE_REVERSE_PROXY:
            proxy_hostname = (self.web_proxy_incoming_hostname.data or "").strip()
            if not proxy_hostname:
                self.web_proxy_incoming_hostname.errors.append(
                    "is required when reverse proxy mode is enabled."
                )
                valid = False
            elif not is_valid_tls_server_name(proxy_hostname, allow_ipv4=False, allow_localhost=True):
                self.web_proxy_incoming_hostname.errors.append(
                    "must be localhost or a fully-qualified hostname (example: vpn.example.com)."
                )
                valid = False

        if self.web_redirect_http_to_https.data and mode == web_config.TLS_MODE_HTTP:
            self.web_redirect_http_to_https.errors.append(
                "can only be enabled when TLS mode is not Direct HTTP."
            )
            valid = False
        return valid


class AddInterfaceForm(FlaskForm):
    LOCAL_ROUTE_UP_RE = re.compile(
        r"^(?P<ip_bin>\S+)\s+route\s+replace\s+"
        r"(?P<network>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+via\s+"
        r"(?P<gateway>\d{1,3}(?:\.\d{1,3}){3})$"
    )
    LOCAL_ROUTE_DOWN_RE = re.compile(
        r"^(?P<ip_bin>\S+)\s+route\s+del\s+"
        r"(?P<network>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+via\s+"
        r"(?P<gateway>\d{1,3}(?:\.\d{1,3}){3})\s*\|\|\s*true$"
    )

    name = StringField("Name", validators=[DataRequired(), InterfaceNameValidator()])
    auto = BooleanField("Auto", default=True)
    description = TextAreaField("Description", render_kw={"placeholder": "Some details..."})
    gateway = SelectField("Gateway", validate_choice=False)
    ipv4 = StringField("IPv4", validators=[DataRequired(), InterfaceIpValidator()],
                       render_kw={"placeholder": "0.0.0.0/32"})
    port = IntegerField("Listen port", validators=[InterfacePortValidator()],
                        render_kw={"placeholder": "25000", "type": "number"})
    local_routes_enabled = BooleanField("Manage local server routes", default=False)
    local_route_gateway = StringField(
        "Route gateway IP",
        render_kw={"placeholder": "192.168.1.1"},
    )
    local_routes = TextAreaField(
        "Local route subnets",
        render_kw={"placeholder": "192.168.10.0/24, 192.168.1.0/24"},
    )
    on_up = TextAreaField("On up")
    on_down = TextAreaField("On down")
    iface = None
    submit = SubmitField('Add')

    @staticmethod
    def _split_lines(value: str) -> List[str]:
        lines: List[str] = []
        for line in re.split(r"\r?\n", str(value or "")):
            entry = str(line or "").strip()
            if entry:
                lines.append(entry)
        return lines

    @classmethod
    def _normalize_command_list(cls, values: List[str]) -> List[str]:
        commands: List[str] = []
        for value in values:
            commands.extend(cls._split_lines(value))
        return commands

    @classmethod
    def _parse_managed_route_up(cls, command: str):
        match = cls.LOCAL_ROUTE_UP_RE.match(str(command or "").strip())
        if not match:
            return None
        if match.group("ip_bin").split("/")[-1] != "ip":
            return None
        try:
            route = str(ipaddress.IPv4Network(match.group("network"), strict=False))
            gateway = str(ipaddress.IPv4Address(match.group("gateway")))
        except ValueError:
            return None
        return route, gateway

    @classmethod
    def _parse_managed_route_down(cls, command: str):
        match = cls.LOCAL_ROUTE_DOWN_RE.match(str(command or "").strip())
        if not match:
            return None
        if match.group("ip_bin").split("/")[-1] != "ip":
            return None
        try:
            route = str(ipaddress.IPv4Network(match.group("network"), strict=False))
            gateway = str(ipaddress.IPv4Address(match.group("gateway")))
        except ValueError:
            return None
        return route, gateway

    @classmethod
    def _strip_managed_local_route_commands(
            cls,
            on_up_commands: List[str],
            on_down_commands: List[str],
    ) -> Tuple[List[str], List[str], str, List[str]]:
        up_pairs = {
            parsed for parsed in (cls._parse_managed_route_up(command) for command in on_up_commands)
            if parsed is not None
        }
        down_pairs = {
            parsed for parsed in (cls._parse_managed_route_down(command) for command in on_down_commands)
            if parsed is not None
        }
        managed_pairs = up_pairs.intersection(down_pairs)
        if not managed_pairs:
            return on_up_commands, on_down_commands, "", []
        gateways = {pair[1] for pair in managed_pairs}
        if len(gateways) != 1:
            return on_up_commands, on_down_commands, "", []
        cleaned_on_up = [
            command for command in on_up_commands
            if cls._parse_managed_route_up(command) not in managed_pairs
        ]
        cleaned_on_down = [
            command for command in on_down_commands
            if cls._parse_managed_route_down(command) not in managed_pairs
        ]
        routes = sorted(
            {pair[0] for pair in managed_pairs},
            key=lambda item: (int(ipaddress.IPv4Network(item).network_address), ipaddress.IPv4Network(item).prefixlen),
        )
        return cleaned_on_up, cleaned_on_down, next(iter(gateways)), routes

    @staticmethod
    def _parse_local_routes_field(value: str) -> List[str]:
        routes: List[str] = []
        seen = set()
        for chunk in re.split(r"[,\r\n]+", str(value or "")):
            candidate = str(chunk or "").strip()
            if not candidate:
                continue
            route = str(ipaddress.IPv4Network(candidate, strict=False))
            if route in seen:
                continue
            seen.add(route)
            routes.append(route)
        return routes

    @staticmethod
    def _default_nat_commands(name: str, gateway_iface: str) -> Tuple[List[str], List[str]]:
        return (
            [
                f"{wireguard_config.iptables_bin} -I FORWARD -i {name} -j ACCEPT",
                f"{wireguard_config.iptables_bin} -I FORWARD -o {name} -j ACCEPT",
                f"{wireguard_config.iptables_bin} -t nat -I POSTROUTING -o {gateway_iface} -j MASQUERADE",
            ],
            [
                f"{wireguard_config.iptables_bin} -D FORWARD -i {name} -j ACCEPT",
                f"{wireguard_config.iptables_bin} -D FORWARD -o {name} -j ACCEPT",
                f"{wireguard_config.iptables_bin} -t nat -D POSTROUTING -o {gateway_iface} -j MASQUERADE",
            ],
        )

    def validate(self, extra_validators=None):
        valid = super().validate(extra_validators)
        self._normalized_local_routes = []
        self._normalized_local_route_gateway = ""
        if not valid:
            return False

        if not self.local_routes_enabled.data:
            return True

        try:
            routes = self._parse_local_routes_field(self.local_routes.data)
        except ValueError:
            self.local_routes.errors.append(
                "must be a comma/newline-separated list of IPv4 CIDR blocks (example: 192.168.10.0/24)."
            )
            return False
        if not routes:
            self.local_routes.errors.append("add at least one route subnet when local route management is enabled.")
            return False

        gateway_raw = str(self.local_route_gateway.data or "").strip()
        if not gateway_raw:
            self.local_route_gateway.errors.append("is required when local route management is enabled.")
            return False
        try:
            gateway = str(ipaddress.IPv4Address(gateway_raw))
        except ValueError:
            self.local_route_gateway.errors.append("must be a valid IPv4 address.")
            return False

        self._normalized_local_routes = routes
        self._normalized_local_route_gateway = gateway
        self.local_routes.data = list_to_str(routes, separator="\n")
        self.local_route_gateway.data = gateway
        return True

    def build_interface_hooks(self) -> Tuple[List[str], List[str]]:
        on_up_commands = self._split_lines(self.on_up.data)
        on_down_commands = self._split_lines(self.on_down.data)
        on_up_commands, on_down_commands, _, _ = self._strip_managed_local_route_commands(
            on_up_commands,
            on_down_commands,
        )

        if self.local_routes_enabled.data:
            routes = list(getattr(self, "_normalized_local_routes", []))
            if not routes:
                routes = self._parse_local_routes_field(self.local_routes.data)
            gateway = str(getattr(self, "_normalized_local_route_gateway", "") or self.local_route_gateway.data).strip()
            ip_bin = which("ip") or "ip"
            for route in routes:
                on_up_commands.append(f"{ip_bin} route replace {route} via {gateway}")
                on_down_commands.append(f"{ip_bin} route del {route} via {gateway} || true")
        return on_up_commands, on_down_commands

    @classmethod
    def get_choices(cls, exclusions: List[str]) -> List[Tuple[str, str]]:
        gateways = list(set(get_system_interfaces().keys()) - set(exclusions))
        choices = []
        for choice in gateways:
            choices.append((choice, choice))
        return choices

    @classmethod
    def from_form(cls, form: "AddInterfaceForm") -> "AddInterfaceForm":
        new_form = AddInterfaceForm()
        new_form.name.data = form.name.data
        new_form.gateway.choices = cls.get_choices(exclusions=["lo"])
        new_form.gateway.data = form.gateway.data
        new_form.ipv4.data = form.ipv4.data
        new_form.port.data = form.port.data
        new_form.local_routes_enabled.data = form.local_routes_enabled.data
        new_form.local_route_gateway.data = form.local_route_gateway.data
        new_form.local_routes.data = form.local_routes.data
        new_form.on_up.data = form.on_up.data
        new_form.on_down.data = form.on_down.data
        return new_form

    @classmethod
    def populate(cls, form: "AddInterfaceForm") -> "AddInterfaceForm":
        name = Interface.generate_valid_name()
        form.name.data = name
        form.gateway.choices = cls.get_choices(exclusions=["lo"])
        gw = get_default_gateway()
        form.gateway.data = gw

        tries = 0
        max_tries = 100
        ip = ipaddress.IPv4Interface(f"{fake.ipv4_private()}/{8 + randbelow(23)}")
        while tries < max_tries and (Interface.is_ip_in_use(str(ip)) or Interface.is_network_in_use(ip)):
            ip = ipaddress.IPv4Interface(f"{fake.ipv4_private()}/{8 + randbelow(23)}")
            tries += 1
        if tries < max_tries:
            form.ipv4.data = str(ip)
        else:
            form.ipv4.data = "No addresses available!"
        form.port.data = Interface.get_unused_port()
        default_on_up, default_on_down = cls._default_nat_commands(name, gw)
        form.local_routes_enabled.data = False
        form.local_route_gateway.data = ""
        form.local_routes.data = ""
        form.on_up.data = list_to_str(default_on_up, separator="\n")
        form.on_down.data = list_to_str(default_on_down, separator="\n")
        return form


class EditInterfaceForm(AddInterfaceForm):
    public_key = StringField("Public key", render_kw={"disabled": "disabled"})
    private_key = StringField("Private key", render_kw={"disabled": "disabled"})
    submit = SubmitField('Save')

    @classmethod
    def from_form(cls, form: "EditInterfaceForm", iface: Interface) -> "EditInterfaceForm":
        new_form = EditInterfaceForm()
        new_form.iface = iface
        new_form.name.data = form.name.data
        new_form.gateway.choices = cls.get_choices(exclusions=["lo", form.name])
        new_form.gateway.data = form.gateway.data
        new_form.ipv4.data = form.ipv4.data
        new_form.port.data = form.port.data
        new_form.local_routes_enabled.data = form.local_routes_enabled.data
        new_form.local_route_gateway.data = form.local_route_gateway.data
        new_form.local_routes.data = form.local_routes.data
        new_form.on_up.data = form.on_up.data
        new_form.on_down.data = form.on_down.data
        new_form.public_key.data = iface.public_key
        new_form.private_key.data = iface.private_key
        return new_form

    @classmethod
    def from_interface(cls, iface: Interface) -> "EditInterfaceForm":
        form = EditInterfaceForm()
        form.iface = iface
        form.name.data = iface.name
        form.description.data = iface.description
        form.ipv4.data = iface.ipv4_address
        form.port.data = iface.listen_port
        form.gateway.choices = cls.get_choices(exclusions=["lo", form.name])
        form.gateway.data = iface.gw_iface
        on_up_commands = cls._normalize_command_list(list(iface.on_up))
        on_down_commands = cls._normalize_command_list(list(iface.on_down))
        on_up_commands, on_down_commands, local_route_gateway, local_routes = cls._strip_managed_local_route_commands(
            on_up_commands,
            on_down_commands,
        )
        form.local_routes_enabled.data = bool(local_routes)
        form.local_route_gateway.data = local_route_gateway
        form.local_routes.data = list_to_str(local_routes, separator="\n")
        form.on_up.data = list_to_str(on_up_commands, separator="\n")
        form.on_down.data = list_to_str(on_down_commands, separator="\n")
        form.auto.data = iface.auto
        form.public_key.data = iface.public_key
        form.private_key.data = iface.private_key
        return form


class AddPeerForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), PeerNameValidator()])
    mode = SelectField("Mode", choices=[(Peer.MODE_CLIENT, "Client"), (Peer.MODE_SITE_TO_SITE, "Site-to-site")],
                       default=Peer.MODE_CLIENT)
    enabled = BooleanField("Enabled", default=True)
    nat = BooleanField("NAT", default=False)
    full_tunnel = BooleanField("Full tunnel", default=False)
    description = TextAreaField("Description", render_kw={"placeholder": "Some details..."})
    interface = SelectField("Interface", validate_choice=False)
    ipv4 = StringField("IPv4", validators=[DataRequired(), PeerIpValidator()],
                       render_kw={"placeholder": "0.0.0.0/32"})
    dns1 = StringField("Primary DNS", validators=[PeerPrimaryDnsValidator()],
                       default="8.8.8.8", render_kw={"placeholder": "8.8.8.8"})
    dns2 = StringField("Secondary DNS", validators=[PeerSecondaryDnsValidator()],
                       render_kw={"placeholder": "8.8.4.4"})
    site_to_site_subnets = TextAreaField("Remote site subnets", validators=[PeerSiteToSiteSubnetsValidator()],
                                         render_kw={"placeholder": "10.10.0.0/16, 172.16.50.0/24"})
    peer = None
    submit = SubmitField('Add')

    @classmethod
    def get_choices(cls) -> List[Tuple[str, str]]:
        choices = []
        for iface in interfaces.values():
            if (
                current_user and current_user.is_authenticated and
                getattr(current_user, "role", "") == User.ROLE_TENANT_ADMIN
            ):
                iface_tenant_id = str(getattr(iface, "tenant_id", "") or "")
                actor_tenant_id = str(getattr(current_user, "tenant_id", "") or "")
                if iface_tenant_id and iface_tenant_id != actor_tenant_id:
                    continue
            choices.append((iface.name, f"{iface.name} ({iface.ipv4_address})"))
        return choices

    @classmethod
    def from_form(cls, form: "AddPeerForm") -> "AddPeerForm":
        new_form = AddPeerForm()
        new_form.name.data = form.name.data
        new_form.mode.data = form.mode.data or Peer.MODE_CLIENT
        new_form.enabled.data = form.enabled.data
        new_form.nat.data = form.nat.data
        new_form.full_tunnel.data = form.full_tunnel.data
        new_form.description.data = form.description.data
        new_form.dns1.data = form.dns1.data
        new_form.dns2.data = form.dns2.data
        new_form.site_to_site_subnets.data = form.site_to_site_subnets.data
        new_form.ipv4.data = form.ipv4.data
        new_form.interface.choices = cls.get_choices()
        new_form.interface.data = form.interface.data
        return new_form

    @classmethod
    def populate(cls, form: "AddPeerForm", iface: Interface = None) -> "AddPeerForm":
        form.name.data = Peer.generate_valid_name()
        form.mode.data = Peer.MODE_CLIENT
        form.enabled.data = True
        form.full_tunnel.data = False
        form.site_to_site_subnets.data = ""
        form.interface.choices = cls.get_choices()
        if iface:
            form.interface.data = iface.name
        else:
            iface = interfaces.get_value_by_attr("name", form.interface.choices[0][0])
        iface_network = ipaddress.IPv4Interface(iface.ipv4_address).network
        peer_ip = "No addresses available for this network!"
        for host in iface_network.hosts():
            if not Peer.is_ip_in_use(str(host)):
                peer_ip = host
                break
        form.ipv4.data = peer_ip
        return form


class EditPeerForm(AddPeerForm):
    public_key = StringField("Public key", render_kw={"disabled": "disabled"})
    private_key = StringField("Private key", render_kw={"disabled": "disabled"})
    submit = SubmitField('Save')

    @classmethod
    def from_form(cls, form: "EditPeerForm", peer: Peer) -> "EditPeerForm":
        new_form = EditPeerForm()
        new_form.peer = peer
        new_form.name.data = form.name.data
        new_form.mode.data = form.mode.data or Peer.MODE_CLIENT
        new_form.enabled.data = form.enabled.data
        new_form.full_tunnel.data = form.full_tunnel.data
        new_form.ipv4.data = form.ipv4.data
        new_form.dns1.data = form.dns1.data
        new_form.dns2.data = form.dns2.data
        new_form.site_to_site_subnets.data = form.site_to_site_subnets.data
        new_form.nat.data = form.nat.data
        new_form.description.data = form.description.data
        new_form.public_key.data = peer.public_key
        new_form.private_key.data = peer.private_key
        new_form.interface.choices = cls.get_choices()
        new_form.interface.data = form.interface.data
        return new_form

    @classmethod
    def from_peer(cls, peer: Peer) -> "EditPeerForm":
        form = EditPeerForm()
        form.peer = peer
        form.name.data = peer.name
        form.mode.data = peer.mode
        form.enabled.data = peer.enabled
        form.full_tunnel.data = peer.full_tunnel
        form.description.data = peer.description
        form.ipv4.data = peer.ipv4_address
        form.dns1.data = peer.dns1
        form.dns2.data = peer.dns2
        form.site_to_site_subnets.data = list_to_str(peer.site_to_site_subnets)
        form.nat.data = peer.nat
        form.public_key.data = peer.public_key
        form.private_key.data = peer.private_key
        form.interface.choices = cls.get_choices()
        form.interface.data = peer.interface.name
        return form


class ProfileForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()], render_kw={"placeholder": "admin"})
    submit = SubmitField('Save')


class PasswordResetForm(FlaskForm):
    old_password = PasswordField("Old password", validators=[DataRequired(), OldPasswordValidator()],
                                 render_kw={"placeholder": "Your old password"})
    new_password = PasswordField("New password", validators=[DataRequired(), NewPasswordValidator()],
                                 render_kw={"placeholder": "A strong new password"})
    confirm = PasswordField("Confirm password", validators=[DataRequired()],
                            render_kw={"placeholder": "A strong new password"})
    submit = SubmitField('Save')


class MfaForm(FlaskForm):
    mfa_code = StringField(
        "Authenticator code",
        render_kw={"placeholder": "123456", "autocomplete": "one-time-code"},
    )
    generate_secret = SubmitField("Generate MFA secret")
    enable = SubmitField("Enable MFA")
    disable = SubmitField("Disable MFA")
