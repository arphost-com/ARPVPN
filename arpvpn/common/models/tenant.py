from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Type, Dict, Any, Mapping, List
from uuid import uuid4 as gen_uuid

from yamlable import YamlAble, yaml_info, Y

from arpvpn.common.models.encrypted_yamlable import EncryptedYamlAble
from arpvpn.common.models.enhanced_dict import EnhancedDict, K, V
from arpvpn.common.models.user import User


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_string_list(values: Any) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = values.split(",")
    if not isinstance(values, list):
        return []
    normalized: List[str] = []
    for item in values:
        candidate = str(item or "").strip()
        if candidate:
            normalized.append(candidate)
    return normalized


def slugify_name(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-")


@yaml_info(yaml_tag="tenant")
class Tenant(YamlAble):
    STATUS_ACTIVE = "active"
    STATUS_SUSPENDED = "suspended"
    STATUS_DISABLED = "disabled"
    STATUSES = (
        STATUS_ACTIVE,
        STATUS_SUSPENDED,
        STATUS_DISABLED,
    )

    def __init__(
        self,
        name: str,
        slug: str = "",
        domains: Any = None,
        ips: Any = None,
        status: str = STATUS_ACTIVE,
        description: str = "",
    ):
        self.id = gen_uuid().hex
        self.name = str(name or "").strip()
        self.slug = slugify_name(slug or self.name) or f"tenant-{self.id[:8]}"
        self.domains = normalize_string_list(domains)
        self.ips = normalize_string_list(ips)
        self.status = status if status in self.STATUSES else self.STATUS_ACTIVE
        self.description = str(description or "").strip()
        self.created_at = utcnow_iso()
        self.updated_at = self.created_at

    def touch(self):
        self.updated_at = utcnow_iso()

    def __to_yaml_dict__(self):
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "domains": self.domains,
            "ips": self.ips,
            "status": self.status,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def __from_yaml_dict__(cls, dct: Dict[str, Any], yaml_tag: str):  # type: ignore[override]
        tenant = Tenant(
            dct.get("name", ""),
            slug=dct.get("slug", ""),
            domains=dct.get("domains", []),
            ips=dct.get("ips", []),
            status=dct.get("status", cls.STATUS_ACTIVE),
            description=dct.get("description", ""),
        )
        tenant.id = dct.get("id", tenant.id)
        tenant.created_at = dct.get("created_at", tenant.created_at)
        tenant.updated_at = dct.get("updated_at", tenant.updated_at)
        return tenant


@yaml_info(yaml_tag="tenants")
class TenantDict(EnhancedDict, EncryptedYamlAble, Mapping[K, V]):
    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self

    @classmethod
    def __from_yaml_dict__(cls, dct: Dict[str, Any], yaml_tag: str):  # type: ignore[override]
        tenants_dict = TenantDict()
        tenants_dict.update(dct)
        return tenants_dict

    def sort(self, order_by=lambda pair: pair[1].name.lower()):
        super(TenantDict, self).sort(order_by)


def generate_invitation_token() -> str:
    return secrets.token_urlsafe(24)


def hash_invitation_token(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


@yaml_info(yaml_tag="invitation")
class Invitation(YamlAble):
    STATUS_PENDING = "pending"
    STATUS_ACCEPTED = "accepted"
    STATUS_REVOKED = "revoked"
    STATUS_EXPIRED = "expired"
    STATUSES = (
        STATUS_PENDING,
        STATUS_ACCEPTED,
        STATUS_REVOKED,
        STATUS_EXPIRED,
    )
    DEFAULT_EXPIRY_HOURS = 7 * 24

    def __init__(
        self,
        tenant_id: str,
        email: str,
        role: str = User.ROLE_CLIENT,
        invited_by_user_id: str = "",
        expires_in_hours: int = DEFAULT_EXPIRY_HOURS,
    ):
        self.id = gen_uuid().hex
        self.tenant_id = str(tenant_id or "").strip()
        self.email = str(email or "").strip().lower()
        self.role = role if role in User.ROLES else User.ROLE_CLIENT
        self.invited_by_user_id = str(invited_by_user_id or "").strip()
        self.status = self.STATUS_PENDING
        self.created_at = utcnow_iso()
        self.updated_at = self.created_at
        self.last_sent_at = self.created_at
        self.sent_count = 1
        self.accepted_at = ""
        self.revoked_at = ""
        self.accepted_user_id = ""
        self.expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=max(int(expires_in_hours or 1), 1))
        ).isoformat().replace("+00:00", "Z")
        raw_token = generate_invitation_token()
        self.token_hash = hash_invitation_token(raw_token)
        self._raw_token = raw_token

    @property
    def raw_token(self) -> str:
        return getattr(self, "_raw_token", "")

    def touch(self):
        self.updated_at = utcnow_iso()

    def issue_token(self, expires_in_hours: int = DEFAULT_EXPIRY_HOURS) -> str:
        raw_token = generate_invitation_token()
        self.token_hash = hash_invitation_token(raw_token)
        self.status = self.STATUS_PENDING
        self.last_sent_at = utcnow_iso()
        self.sent_count = int(self.sent_count or 0) + 1
        self.expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=max(int(expires_in_hours or 1), 1))
        ).isoformat().replace("+00:00", "Z")
        self.touch()
        self._raw_token = raw_token
        return raw_token

    def matches_token(self, raw_token: str) -> bool:
        candidate = str(raw_token or "").strip()
        if not candidate:
            return False
        return secrets.compare_digest(self.token_hash, hash_invitation_token(candidate))

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            expires_at = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return datetime.now(timezone.utc) >= expires_at

    def current_status(self) -> str:
        if self.status == self.STATUS_PENDING and self.is_expired():
            return self.STATUS_EXPIRED
        return self.status

    def revoke(self):
        self.status = self.STATUS_REVOKED
        self.revoked_at = utcnow_iso()
        self.touch()

    def accept(self, user_id: str):
        self.status = self.STATUS_ACCEPTED
        self.accepted_user_id = str(user_id or "").strip()
        self.accepted_at = utcnow_iso()
        self.touch()

    def __to_yaml_dict__(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "email": self.email,
            "role": self.role,
            "invited_by_user_id": self.invited_by_user_id,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_sent_at": self.last_sent_at,
            "sent_count": self.sent_count,
            "accepted_at": self.accepted_at,
            "revoked_at": self.revoked_at,
            "accepted_user_id": self.accepted_user_id,
            "expires_at": self.expires_at,
            "token_hash": self.token_hash,
        }

    @classmethod
    def __from_yaml_dict__(cls, dct: Dict[str, Any], yaml_tag: str):  # type: ignore[override]
        invitation = Invitation(
            dct.get("tenant_id", ""),
            dct.get("email", ""),
            role=dct.get("role", User.ROLE_CLIENT),
            invited_by_user_id=dct.get("invited_by_user_id", ""),
            expires_in_hours=1,
        )
        invitation.id = dct.get("id", invitation.id)
        invitation.status = dct.get("status", invitation.status)
        invitation.created_at = dct.get("created_at", invitation.created_at)
        invitation.updated_at = dct.get("updated_at", invitation.updated_at)
        invitation.last_sent_at = dct.get("last_sent_at", invitation.last_sent_at)
        invitation.sent_count = int(dct.get("sent_count", invitation.sent_count) or 0)
        invitation.accepted_at = dct.get("accepted_at", "")
        invitation.revoked_at = dct.get("revoked_at", "")
        invitation.accepted_user_id = dct.get("accepted_user_id", "")
        invitation.expires_at = dct.get("expires_at", invitation.expires_at)
        invitation.token_hash = dct.get("token_hash", invitation.token_hash)
        invitation._raw_token = ""
        return invitation


@yaml_info(yaml_tag="invitations")
class InvitationDict(EnhancedDict, EncryptedYamlAble, Mapping[K, V]):
    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self

    @classmethod
    def __from_yaml_dict__(cls, dct: Dict[str, Any], yaml_tag: str):  # type: ignore[override]
        invitation_dict = InvitationDict()
        invitation_dict.update(dct)
        return invitation_dict

    def sort(self, order_by=lambda pair: pair[1].email.lower()):
        super(InvitationDict, self).sort(order_by)


tenants: TenantDict[str, Tenant]
tenants = TenantDict()

invitations: InvitationDict[str, Invitation]
invitations = InvitationDict()
