import ipaddress
import json
from secrets import randbelow
from typing import List, Tuple

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
from arpvpn.core.config.wireguard import config as wireguard_config
from arpvpn.core.managers import traffic_storage
from arpvpn.core.managers.config import config_manager
from arpvpn.core.models import Interface, Peer, interfaces
from arpvpn.web.utils import fake
from arpvpn.web.validators import LoginUsernameValidator, LoginPasswordValidator, SignupPasswordValidator, \
    SignupUsernameValidator, SettingsSecretKeyValidator, PositiveIntegerValidator, \
    InterfaceIpValidator, InterfaceNameValidator, InterfacePortValidator, PeerIpValidator, PeerPrimaryDnsValidator, \
    PeerSecondaryDnsValidator, PeerNameValidator, NewPasswordValidator, OldPasswordValidator, JsonDataValidator, \
    PathExistsValidator, EndpointValidator, PeerSiteToSiteSubnetsValidator, HostnameOrIPv4Validator, \
    HostnameValidator, EmailValidator


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), LoginUsernameValidator()],
                           render_kw={"placeholder": "Enter username"})
    password = PasswordField('Password', validators=[DataRequired(), LoginPasswordValidator()],
                             render_kw={"placeholder": "Enter password"})
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Log in')
    next = StringField()


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), SignupUsernameValidator()],
                           render_kw={"placeholder": "Enter username"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Enter password"})
    confirm = PasswordField('Confirm password', validators=[DataRequired(), SignupPasswordValidator()],
                            render_kw={"placeholder": "Confirm password"})
    submit = SubmitField('Create account')
    next = StringField()


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), SignupUsernameValidator()],
                           render_kw={"placeholder": "Enter username"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Enter password"})
    confirm = PasswordField('Confirm password', validators=[DataRequired(), SignupPasswordValidator()],
                            render_kw={"placeholder": "Confirm password"})
    role = SelectField(
        "Role",
        choices=[
            (User.ROLE_CLIENT, "Client"),
            (User.ROLE_SUPPORT, "Support"),
            (User.ROLE_ADMIN, "Admin"),
        ],
        default=User.ROLE_CLIENT,
    )
    submit = SubmitField('Create user')


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
            self.web_tls_server_name.errors.append(
                "is required when TLS mode is self-signed or Let's Encrypt."
            )
            valid = False

        if mode == web_config.TLS_MODE_LETS_ENCRYPT:
            hostname = (self.web_tls_server_name.data or "").strip()
            try:
                ipaddress.IPv4Address(hostname)
                self.web_tls_server_name.errors.append(
                    "must be a hostname for Let's Encrypt (IP addresses are not supported)."
                )
                valid = False
            except ValueError:
                pass

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

        if mode == web_config.TLS_MODE_REVERSE_PROXY and not (self.web_proxy_incoming_hostname.data or "").strip():
            self.web_proxy_incoming_hostname.errors.append(
                "is required when reverse proxy mode is enabled."
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
    web_tls_generate_self_signed = BooleanField("Generate self-signed certificate now", default=False)
    web_tls_issue_letsencrypt = BooleanField("Issue Let's Encrypt certificate now", default=False)

    log_overwrite = BooleanField("Overwrite", default=logger_config.overwrite)

    traffic_enabled = BooleanField("Enabled", default=traffic_config.enabled)

    submit = SubmitField('Next')

    def validate(self, extra_validators=None):
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
            self.web_tls_server_name.errors.append(
                "is required when TLS mode is self-signed or Let's Encrypt."
            )
            valid = False

        if mode == web_config.TLS_MODE_LETS_ENCRYPT:
            hostname = (self.web_tls_server_name.data or "").strip()
            try:
                ipaddress.IPv4Address(hostname)
                self.web_tls_server_name.errors.append(
                    "must be a hostname for Let's Encrypt (IP addresses are not supported)."
                )
                valid = False
            except ValueError:
                pass

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

        if mode == web_config.TLS_MODE_REVERSE_PROXY and not (self.web_proxy_incoming_hostname.data or "").strip():
            self.web_proxy_incoming_hostname.errors.append(
                "is required when reverse proxy mode is enabled."
            )
            valid = False

        if self.web_redirect_http_to_https.data and mode == web_config.TLS_MODE_HTTP:
            self.web_redirect_http_to_https.errors.append(
                "can only be enabled when TLS mode is not Direct HTTP."
            )
            valid = False
        return valid


class AddInterfaceForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), InterfaceNameValidator()])
    auto = BooleanField("Auto", default=True)
    description = TextAreaField("Description", render_kw={"placeholder": "Some details..."})
    gateway = SelectField("Gateway", validate_choice=False)
    ipv4 = StringField("IPv4", validators=[DataRequired(), InterfaceIpValidator()],
                       render_kw={"placeholder": "0.0.0.0/32"})
    port = IntegerField("Listen port", validators=[InterfacePortValidator()],
                        render_kw={"placeholder": "25000", "type": "number"})
    on_up = TextAreaField("On up")
    on_down = TextAreaField("On down")
    iface = None
    submit = SubmitField('Add')

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
        form.on_up.data = list_to_str([
            f"{wireguard_config.iptables_bin} -I FORWARD -i {name} -j ACCEPT\n" +
            f"{wireguard_config.iptables_bin} -I FORWARD -o {name} -j ACCEPT\n" +
            f"{wireguard_config.iptables_bin} -t nat -I POSTROUTING -o {gw} -j MASQUERADE\n"
        ])
        form.on_down.data = list_to_str([
            f"{wireguard_config.iptables_bin} -D FORWARD -i {name} -j ACCEPT\n" +
            f"{wireguard_config.iptables_bin} -D FORWARD -o {name} -j ACCEPT\n" +
            f"{wireguard_config.iptables_bin} -t nat -D POSTROUTING -o {gw} -j MASQUERADE\n"
        ])
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
        form.on_up.data = list_to_str(iface.on_up, separator="\n")
        form.on_down.data = list_to_str(iface.on_down, separator="\n")
        form.auto.data = iface.auto
        form.public_key.data = iface.public_key
        form.private_key.data = iface.private_key
        return form


class AddPeerForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), PeerNameValidator()])
    mode = SelectField("Mode", choices=[(Peer.MODE_CLIENT, "Client"), (Peer.MODE_SITE_TO_SITE, "Site-to-site")],
                       default=Peer.MODE_CLIENT)
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
            choices.append((iface.name, f"{iface.name} ({iface.ipv4_address})"))
        return choices

    @classmethod
    def from_form(cls, form: "AddPeerForm") -> "AddPeerForm":
        new_form = AddPeerForm()
        new_form.name.data = form.name.data
        new_form.mode.data = form.mode.data or Peer.MODE_CLIENT
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
