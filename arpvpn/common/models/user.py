from datetime import datetime
from typing import Type, Dict, Any, Mapping
from uuid import uuid4 as gen_uuid

from flask_login import logout_user, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from yamlable import YamlAble, yaml_info, Y

from arpvpn.common.models.encrypted_yamlable import EncryptedYamlAble
from arpvpn.common.models.enhanced_dict import EnhancedDict, K, V
from arpvpn.common.utils.mfa import build_mfa_provisioning_uri, hash_recovery_code, verify_mfa_code


@yaml_info(yaml_tag='user')
class User(UserMixin, YamlAble):
    HASHING_METHOD = "pbkdf2:sha256"
    ROLE_ADMIN = "admin"
    ROLE_SUPPORT = "support"
    ROLE_TENANT_ADMIN = "tenant_admin"
    ROLE_CLIENT = "client"
    ROLES = (
        ROLE_ADMIN,
        ROLE_SUPPORT,
        ROLE_TENANT_ADMIN,
        ROLE_CLIENT,
    )
    login_date: datetime

    def __init__(self, name: str, role: str = ROLE_ADMIN):
        self.id = gen_uuid().hex
        self.name = name
        self.role = role if role in self.ROLES else self.ROLE_ADMIN
        self.tenant_id = None
        self.__password = None
        self.__authenticated = False
        self.mfa_enabled = False
        self.mfa_secret = None
        self.mfa_recovery_code_hashes = []

    def __str__(self):
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "authenticated": self.__authenticated
        }.__str__()

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, value: str):
        self.__password = generate_password_hash(str(value), self.HASHING_METHOD)

    def __to_yaml_dict__(self):
        """ Called when you call yaml.dump()"""
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "password": self.password,
            "mfa_enabled": self.mfa_enabled,
            "mfa_secret": self.mfa_secret,
            "mfa_recovery_code_hashes": list(self.mfa_recovery_code_hashes),
        }

    @classmethod
    def __from_yaml_dict__(cls,      # type: Type[Y]
                           dct,      # type: Dict[str, Any]
                           yaml_tag  # type: str
                           ):  # type: (...) -> Y
        u = User(dct["name"], dct.get("role", cls.ROLE_ADMIN))
        u.id = dct["id"]
        u.tenant_id = dct.get("tenant_id", None)
        u.__password = str(dct["password"])
        u.mfa_enabled = bool(dct.get("mfa_enabled", False))
        u.mfa_secret = dct.get("mfa_secret", None)
        recovery_hashes = dct.get("mfa_recovery_code_hashes", [])
        if recovery_hashes is None:
            recovery_hashes = []
        if isinstance(recovery_hashes, str):
            recovery_hashes = [recovery_hashes]
        u.mfa_recovery_code_hashes = list(recovery_hashes)
        return u

    def login(self, password: str) -> bool:
        if self.is_authenticated:
            return True
        self.__authenticated = self.check_password(password)
        if self.__authenticated:
            self.login_date = datetime.now()
        return self.__authenticated

    def set_authenticated(self, authenticated: bool = True):
        self.__authenticated = bool(authenticated)

    def check_password(self, password: str) -> bool:
        """Check if the specified password matches the user's password without triggering a proper login."""
        return check_password_hash(self.password, password)

    def has_mfa(self) -> bool:
        return bool(self.mfa_enabled and self.mfa_secret)

    def mfa_provisioning_uri(self, issuer: str) -> str:
        if not self.mfa_secret:
            return ""
        return build_mfa_provisioning_uri(self.mfa_secret, self.name, issuer)

    def verify_mfa(self, code: str, allow_recovery_codes: bool = True) -> tuple[bool, bool]:
        if not self.mfa_secret:
            return False, False

        normalized_code = str(code or "").strip()
        if not normalized_code:
            return False, False

        if allow_recovery_codes:
            code_hash = hash_recovery_code(normalized_code)
            if code_hash in self.mfa_recovery_code_hashes:
                self.mfa_recovery_code_hashes = [
                    stored_hash for stored_hash in self.mfa_recovery_code_hashes
                    if stored_hash != code_hash
                ]
                return True, True

        return verify_mfa_code(self.mfa_secret, normalized_code), False

    def enable_mfa(self, secret: str, recovery_code_hashes: list[str]):
        self.mfa_secret = secret
        self.mfa_recovery_code_hashes = list(recovery_code_hashes)
        self.mfa_enabled = True

    def disable_mfa(self):
        self.mfa_enabled = False
        self.mfa_secret = None
        self.mfa_recovery_code_hashes = []

    def logout(self):
        self.__authenticated = False
        return logout_user()

    @property
    def is_authenticated(self):
        return self.__authenticated

    def has_role(self, *roles: str) -> bool:
        return self.role in roles


@yaml_info(yaml_tag='users')
class UserDict(EnhancedDict, EncryptedYamlAble, Mapping[K, V]):

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self

    @classmethod
    def __from_yaml_dict__(cls,      # type: Type[Y]
                           dct,      # type: Dict[str, Any]
                           yaml_tag  # type: str
                           ):  # type: (...) -> Y
        u = UserDict()
        u.update(dct)
        return u

    def sort(self, order_by=lambda pair: pair[1].name):
        super(UserDict, self).sort(order_by)


users: UserDict[str, User]
users = UserDict()
