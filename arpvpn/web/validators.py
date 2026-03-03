import ipaddress
import json
import os.path
import re
from logging import error

from flask_login import current_user
from wtforms.validators import StopValidation

from arpvpn.common.models.user import users
from arpvpn.common.utils.encryption import CryptoUtils
from arpvpn.core.config.web import config
from arpvpn.core.models import Interface, Peer, interfaces


def stop_validation(field, error_msg):
    error(f"Unable to validate field '{field.label.text}': {error_msg}")
    raise StopValidation(error_msg)


class LoginUsernameValidator:
    def __call__(self, form, field):
        u = users.get_value_by_attr("name", field.data)
        if not u:
            msg = "User not found"
            error(f"Unable to log in: {msg}")
            raise StopValidation(msg)


class LoginPasswordValidator:
    def __call__(self, form, field):
        u = users.get_value_by_attr("name", form.username.data)
        if u and not u.login(field.data):
            msg = "Invalid credentials"
            error(f"Unable to log in: {msg}")
            raise StopValidation(msg)


class SignupUsernameValidator:
    def __call__(self, form, field):
        u = users.get_value_by_attr("name", field.data)
        if u:
            msg = "Username already in use"
            error(f"Unable to sign up: {msg}")
            raise StopValidation(msg)


class SignupPasswordValidator:
    def __call__(self, form, field):
        if field.data != form.password.data:
            msg = "Passwords do not match"
            error(f"Unable to sign up: {msg}")
            raise StopValidation(msg)


class SettingsSecretKeyValidator:
    def __call__(self, form, field):
        if not field.data:
            return
        if len(field.data) != CryptoUtils.KEY_LEN:
            msg = f"must be a {CryptoUtils.KEY_LEN} characters long string."
            stop_validation(field, msg)


class PositiveIntegerValidator:
    def __call__(self, form, field):
        if type(field.data) is not int:
            return
        if field.data and field.data < 0:
            stop_validation(field, "must be an integer value equal to or greater than 0.")


class InterfaceNameValidator:
    def __call__(self, form, field):
        if not Interface.is_name_valid(field.data):
            msg = f"can only contain alphanumeric characters, underscores (_) and " \
                  f"hyphens (-). It must also begin with a letter and be between {Interface.MIN_NAME_LENGTH} and " \
                  f"{Interface.MAX_NAME_LENGTH} characters long."
            stop_validation(field, msg)
        if Interface.is_name_in_use(field.data, form.iface):
            stop_validation(field, "already in use!")


class InterfaceIpValidator:
    def __call__(self, form, field):
        if len(field.data.split("/")) != 2:
            return stop_validation(field, "must be valid IPv4 interface. Follow the format 'X.X.X.X/Y'.")
        try:
            ip = ipaddress.IPv4Interface(field.data)
        except ValueError:
            return stop_validation(field, "must be valid IPv4 interface. Follow the format 'X.X.X.X/Y'.")
        if Interface.is_ip_in_use(str(ip), form.iface):
            return stop_validation(field, "address already in use!")
        if Interface.is_network_in_use(ip, form.iface):
            return stop_validation(field, f"network {ip.network} already has a wireguard interface!")
        if ip.ip == ip.network.broadcast_address or ip.ip == ip.network.network_address:
            return stop_validation(field, f"unable to use a reserved address")


class InterfacePortValidator:
    def __call__(self, form, field):
        if type(field.data) is not int:
            return
        if field.data and field.data < config.MIN_PORT or field.data > config.MAX_PORT:
            msg = f"must be an integer value between {config.MIN_PORT} and {config.MAX_PORT}."
            stop_validation(field, msg)
        if Interface.is_port_in_use(field.data, form.iface):
            stop_validation(field, "port already in use!")


class PeerNameValidator:
    def __call__(self, form, field):
        if not Peer.is_name_valid(field.data):
            msg = (f"can only contain alphanumeric characters, underscores (_), hyphens (-) and whitespaces. "
                   f"It must also begin with a letter and be between {Peer.MIN_NAME_LENGTH} and "
                   f"{Peer.MAX_NAME_LENGTH} characters long.")
            stop_validation(field, msg)


class PeerIpValidator:
    def __call__(self, form, field):
        try:
            ipaddress.IPv4Interface(field.data)
        except ValueError:
            msg = "must be valid IPv4 address. Follow the format 'X.X.X.X'."
            return stop_validation(field, msg)
        iface = interfaces.get_value_by_attr("name", form.interface.data)
        if not iface:
            return stop_validation(field, "unknown interface")
        iface_network = ipaddress.IPv4Interface(iface.ipv4_address).network
        peer_ip = ipaddress.IPv4Interface(f"{field.data.split('/')[0]}/{iface_network.prefixlen}")
        if Peer.is_ip_in_use(str(peer_ip), form.peer):
            return stop_validation(field, "address already in use!")
        if peer_ip not in iface_network:
            return stop_validation(field, f"address must belong to network {iface_network}")
        if peer_ip.ip == iface_network.broadcast_address or peer_ip.ip == iface_network.network_address:
            return stop_validation(field, f"unable to use a reserved address")


class PeerPrimaryDnsValidator:
    def __call__(self, form, field):
        is_site_to_site = getattr(form, "mode", None) and form.mode.data == Peer.MODE_SITE_TO_SITE
        if not field.data:
            if is_site_to_site:
                return
            msg = "must be valid IPv4 address. Follow the format 'X.X.X.X'."
            stop_validation(field, msg)
        try:
            ipaddress.IPv4Address(field.data)
        except ValueError:
            msg = "must be valid IPv4 address. Follow the format 'X.X.X.X'."
            stop_validation(field, msg)


class PeerSecondaryDnsValidator:
    def __call__(self, form, field):
        if not field.data:
            return
        try:
            ipaddress.IPv4Address(field.data)
        except ValueError:
            msg = "must be valid IPv4 address. Follow the format 'X.X.X.X'."
            stop_validation(field, msg)


class PeerSiteToSiteSubnetsValidator:
    def __call__(self, form, field):
        if getattr(form, "mode", None) and form.mode.data != Peer.MODE_SITE_TO_SITE:
            return
        if not field.data:
            return
        try:
            Peer.parse_site_to_site_subnets(field.data)
        except ValueError:
            msg = "must be a comma-separated list of IPv4 CIDR blocks, e.g. '10.10.0.0/16, 172.16.50.0/24'."
            stop_validation(field, msg)


class NewPasswordValidator:
    def __call__(self, form, field):
        if field.data != form.confirm.data:
            msg = "passwords do not match"
            raise StopValidation(msg)
        if current_user.check_password(field.data):
            stop_validation(field, "the new password cannot be the same as the old one!")


class OldPasswordValidator:
    def __call__(self, form, field):
        if not current_user.check_password(field.data):
            stop_validation(field, "wrong password")


class JsonDataValidator:
    def __call__(self, form, field):
        try:
            json.loads(field.data.replace("\'", "\""))
        except Exception:
            stop_validation(field, "invalid format, must be JSON data")


class PathExistsValidator:
    def __call__(self, form, field):
        if not os.path.exists(field.data):
            stop_validation(field, f"{field.data} does not exist")


# https://stackoverflow.com/a/3809435
URL_REGEX = re.compile(r"[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)")
HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_hostname_or_ipv4(value: str, allow_ipv4: bool = True) -> bool:
    if not value:
        return False
    if any(ch in value for ch in (":", "/", "@", " ")):
        return False
    try:
        ipaddress.IPv4Address(value)
        return allow_ipv4
    except ValueError:
        return HOSTNAME_REGEX.match(value) is not None


def is_valid_tls_server_name(
    value: str,
    allow_ipv4: bool,
    allow_localhost: bool = True,
) -> bool:
    candidate = str(value or "").strip()
    if not candidate:
        return False

    if allow_localhost and candidate.lower() == "localhost":
        return True

    try:
        ipaddress.IPv4Address(candidate)
        return allow_ipv4
    except ValueError:
        pass

    if HOSTNAME_REGEX.match(candidate) is None:
        return False

    # Reject single-label hostnames for TLS redirect targets to avoid
    # host fallback behavior and ambiguous browser resolution.
    return "." in candidate


class EndpointValidator:
    def __call__(self, form, field):
        try:
            ipaddress.IPv4Address(field.data)
        except ValueError:
            if not URL_REGEX.match(field.data):
                stop_validation(field, "must be valid url or IPv4 address. "
                                       "Follow the format 'X.X.X.X' or 'vpn.example.com'.")


class HostnameOrIPv4Validator:
    def __call__(self, form, field):
        if not field.data:
            return
        if not _validate_hostname_or_ipv4(field.data.strip(), allow_ipv4=True):
            stop_validation(field, "must be a valid hostname or IPv4 address.")


class HostnameValidator:
    def __call__(self, form, field):
        if not field.data:
            return
        if not _validate_hostname_or_ipv4(field.data.strip(), allow_ipv4=False):
            stop_validation(field, "must be a valid hostname (example: vpn.example.com).")


class EmailValidator:
    def __call__(self, form, field):
        if not field.data:
            return
        if EMAIL_REGEX.match(field.data.strip()) is None:
            stop_validation(field, "must be a valid email address.")
