from typing import Any, Dict, Type

from yamlable import yaml_info, Y

from arpvpn.common.models.user import users
from arpvpn.common.properties import global_properties
from arpvpn.common.utils.encryption import CryptoUtils
from arpvpn.core.config.base import BaseConfig


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def parse_port(value: Any, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    if port < minimum or port > maximum:
        return default
    return port


@yaml_info(yaml_tag='web')
class WebConfig(BaseConfig):
    MAX_PORT = 65535
    MIN_PORT = 1
    DEFAULT_LOGIN_ATTEMPTS = 0
    DEFAULT_BAN_SECONDS = 120
    DEFAULT_HTTP_PORT = 8085
    DEFAULT_HTTPS_PORT = 8086
    CREDENTIALS_FILENAME = ".credentials"
    TLS_MODE_HTTP = "http"
    TLS_MODE_SELF_SIGNED = "self_signed"
    TLS_MODE_LETS_ENCRYPT = "letsencrypt"
    TLS_MODE_REVERSE_PROXY = "reverse_proxy"
    TLS_MODES = (
        TLS_MODE_HTTP,
        TLS_MODE_SELF_SIGNED,
        TLS_MODE_LETS_ENCRYPT,
        TLS_MODE_REVERSE_PROXY,
    )

    __secret_key: str
    login_attempts: int
    login_ban_time: int
    tls_mode: str
    tls_server_name: str
    tls_letsencrypt_email: str
    proxy_incoming_hostname: str
    redirect_http_to_https: bool
    tls_cert_file: str
    tls_key_file: str
    http_port: int
    https_port: int

    @property
    def secret_key(self):
        return self.__secret_key

    @secret_key.setter
    def secret_key(self, value: str):
        self.__secret_key = value

    @property
    def credentials_file(self):
        return global_properties.join_workdir(self.CREDENTIALS_FILENAME)

    def __init__(self):
        super().__init__()
        self.load_defaults()

    @property
    def strict_https_mode(self) -> bool:
        if self.tls_mode == self.TLS_MODE_REVERSE_PROXY:
            return True
        if self.tls_mode in (self.TLS_MODE_SELF_SIGNED, self.TLS_MODE_LETS_ENCRYPT):
            return bool(self.redirect_http_to_https)
        return False

    def load_defaults(self):
        self.login_attempts = self.DEFAULT_LOGIN_ATTEMPTS
        self.login_ban_time = self.DEFAULT_BAN_SECONDS
        self.__secret_key = CryptoUtils.generate_key()
        self.tls_mode = self.TLS_MODE_HTTP
        self.tls_server_name = ""
        self.tls_letsencrypt_email = ""
        self.proxy_incoming_hostname = ""
        self.redirect_http_to_https = False
        self.tls_cert_file = ""
        self.tls_key_file = ""
        self.http_port = self.DEFAULT_HTTP_PORT
        self.https_port = self.DEFAULT_HTTPS_PORT

    def load(self, config: "WebConfig"):
        self.login_attempts = config.login_attempts or self.login_attempts
        self.login_ban_time = config.login_ban_time or self.login_ban_time
        self.secret_key = config.secret_key or self.secret_key
        self.tls_mode = config.tls_mode or self.tls_mode
        if self.tls_mode not in self.TLS_MODES:
            self.tls_mode = self.TLS_MODE_HTTP
        self.tls_server_name = config.tls_server_name or self.tls_server_name
        self.tls_letsencrypt_email = config.tls_letsencrypt_email or self.tls_letsencrypt_email
        self.proxy_incoming_hostname = config.proxy_incoming_hostname or self.proxy_incoming_hostname
        self.redirect_http_to_https = parse_bool(getattr(config, "redirect_http_to_https", False), False)
        self.tls_cert_file = config.tls_cert_file or self.tls_cert_file
        self.tls_key_file = config.tls_key_file or self.tls_key_file
        self.http_port = parse_port(
            getattr(config, "http_port", self.http_port),
            self.DEFAULT_HTTP_PORT,
            self.MIN_PORT,
            self.MAX_PORT,
        )
        self.https_port = parse_port(
            getattr(config, "https_port", self.https_port),
            self.DEFAULT_HTTPS_PORT,
            self.MIN_PORT,
            self.MAX_PORT,
        )

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return {
            "login_attempts": self.login_attempts,
            "login_ban_time": self.login_ban_time,
            "secret_key": self.secret_key,
            "tls_mode": self.tls_mode,
            "tls_server_name": self.tls_server_name,
            "tls_letsencrypt_email": self.tls_letsencrypt_email,
            "proxy_incoming_hostname": self.proxy_incoming_hostname,
            "redirect_http_to_https": self.redirect_http_to_https,
            "tls_cert_file": self.tls_cert_file,
            "tls_key_file": self.tls_key_file,
            "http_port": self.http_port,
            "https_port": self.https_port,
        }

    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        config = WebConfig()
        config.login_attempts = dct.get("login_attempts", None) or config.login_attempts
        config.login_ban_time = dct.get("login_ban_time", None) or config.login_ban_time
        config.secret_key = dct.get("secret_key", None) or config.secret_key
        config.tls_mode = dct.get("tls_mode", None) or config.tls_mode
        if config.tls_mode not in config.TLS_MODES:
            config.tls_mode = config.TLS_MODE_HTTP
        config.tls_server_name = dct.get("tls_server_name", None) or config.tls_server_name
        config.tls_letsencrypt_email = dct.get("tls_letsencrypt_email", None) or config.tls_letsencrypt_email
        config.proxy_incoming_hostname = dct.get("proxy_incoming_hostname", None) or config.proxy_incoming_hostname
        config.redirect_http_to_https = parse_bool(dct.get("redirect_http_to_https", False), False)
        config.tls_cert_file = dct.get("tls_cert_file", None) or config.tls_cert_file
        config.tls_key_file = dct.get("tls_key_file", None) or config.tls_key_file
        config.http_port = parse_port(
            dct.get("http_port", config.DEFAULT_HTTP_PORT),
            config.DEFAULT_HTTP_PORT,
            config.MIN_PORT,
            config.MAX_PORT,
        )
        config.https_port = parse_port(
            dct.get("https_port", config.DEFAULT_HTTPS_PORT),
            config.DEFAULT_HTTPS_PORT,
            config.MIN_PORT,
            config.MAX_PORT,
        )
        return config

    def apply(self):
        super(WebConfig, self).apply()
        if not self.credentials_file or len(users) < 1:
            return
        users.save(self.credentials_file, self.__secret_key)


config = WebConfig()
