import base64
import hashlib
import hmac
import re
import secrets
from time import time
from typing import Iterable, List, Tuple
from urllib.parse import quote, urlencode

MFA_CODE_DIGITS = 6
MFA_PERIOD_SECONDS = 30
MFA_SECRET_LENGTH = 32
MFA_SECRET_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
MFA_RECOVERY_CODE_COUNT = 8
MFA_RECOVERY_CODE_GROUP_SIZE = 4
MFA_RECOVERY_CODE_GROUPS = 4
_MFA_CODE_NORMALIZER = re.compile(r"[\s-]+")


def normalize_mfa_code(value: str) -> str:
    return _MFA_CODE_NORMALIZER.sub("", str(value or "")).upper().strip()


def generate_mfa_secret(length: int = MFA_SECRET_LENGTH) -> str:
    return "".join(secrets.choice(MFA_SECRET_ALPHABET) for _ in range(max(16, int(length))))


def build_mfa_provisioning_uri(secret: str, account_name: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account_name}")
    params = urlencode({
        "secret": normalize_mfa_code(secret),
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": str(MFA_CODE_DIGITS),
        "period": str(MFA_PERIOD_SECONDS),
    })
    return f"otpauth://totp/{label}?{params}"


def _base32_decode(secret: str) -> bytes:
    normalized = normalize_mfa_code(secret)
    padding = "=" * (-len(normalized) % 8)
    return base64.b32decode(f"{normalized}{padding}", casefold=True)


def _totp_code(secret: str, counter: int, digits: int = MFA_CODE_DIGITS) -> str:
    key = _base32_decode(secret)
    message = counter.to_bytes(8, "big")
    digest = hmac.new(key, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(binary % (10 ** digits)).zfill(digits)


def generate_mfa_code(secret: str, at_time: float | None = None, period_seconds: int = MFA_PERIOD_SECONDS) -> str:
    counter = int((time() if at_time is None else float(at_time)) // max(1, int(period_seconds)))
    return _totp_code(secret, counter)


def verify_mfa_code(secret: str, code: str, window: int = 1, period_seconds: int = MFA_PERIOD_SECONDS) -> bool:
    candidate = normalize_mfa_code(code)
    if not candidate or not candidate.isdigit() or len(candidate) != MFA_CODE_DIGITS:
        return False

    counter = int(time() // max(1, int(period_seconds)))
    for offset in range(-abs(int(window)), abs(int(window)) + 1):
        if hmac.compare_digest(_totp_code(secret, counter + offset), candidate):
            return True
    return False


def generate_recovery_codes(
    count: int = MFA_RECOVERY_CODE_COUNT,
    groups: int = MFA_RECOVERY_CODE_GROUPS,
    group_size: int = MFA_RECOVERY_CODE_GROUP_SIZE,
) -> List[str]:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789"
    count = max(1, int(count))
    groups = max(1, int(groups))
    group_size = max(1, int(group_size))
    recovery_codes: List[str] = []
    for _ in range(count):
        chunks = []
        for _ in range(groups):
            chunk = "".join(secrets.choice(alphabet) for _ in range(group_size))
            chunks.append(chunk)
        recovery_codes.append("-".join(chunks))
    return recovery_codes


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(normalize_mfa_code(code).encode("utf-8")).hexdigest()


def recovery_code_hashes(codes: Iterable[str]) -> List[str]:
    return [hash_recovery_code(code) for code in codes]
