import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any, Callable, Deque, Dict, Optional, Tuple


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ApiTokenRecord:
    token_id: str
    token_kind: str
    user_id: str
    secret_fingerprint: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
    issued_ip: str = ""
    issued_user_agent: str = ""
    mfa_verified: bool = False

    def is_expired(self, as_of: Optional[datetime] = None) -> bool:
        reference = as_of or now_utc()
        return reference >= self.expires_at


@dataclass
class IdempotencyRecord:
    scope_key: str
    fingerprint: str
    response_data: Any
    status_code: int
    created_at: datetime
    expires_at: datetime

    def is_expired(self, as_of: Optional[datetime] = None) -> bool:
        reference = as_of or now_utc()
        return reference >= self.expires_at


@dataclass
class AsyncJobRecord:
    job_id: str
    operation: str
    actor_user_id: str
    created_at: datetime
    status: str = "queued"
    finished_at: Optional[datetime] = None
    result: Any = None
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "operation": self.operation,
            "actor_user_id": self.actor_user_id,
            "status": self.status,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "finished_at": (
                self.finished_at.isoformat().replace("+00:00", "Z")
                if self.finished_at else None
            ),
            "result": self.result,
            "error": self.error or None,
        }


class ApiTokenStore:
    TOKEN_KIND_ACCESS = "access"
    TOKEN_KIND_REFRESH = "refresh"

    def __init__(self, signing_key: str):
        self._signing_key = str(signing_key or "")
        self._records: Dict[str, ApiTokenRecord] = {}
        self._user_revocation_cutoff: Dict[str, datetime] = {}
        self._lock = Lock()

    def set_signing_key(self, signing_key: str):
        with self._lock:
            self._signing_key = str(signing_key or "")

    def _fingerprint_secret(self, secret_value: str) -> str:
        seed = f"{self._signing_key}:{secret_value}".encode("utf-8")
        return hashlib.sha256(seed).hexdigest()

    @staticmethod
    def _new_token_parts() -> Tuple[str, str]:
        token_id = secrets.token_hex(16)
        token_secret = secrets.token_urlsafe(40)
        return token_id, token_secret

    @staticmethod
    def _pack_raw_token(token_id: str, token_secret: str) -> str:
        return f"{token_id}.{token_secret}"

    @staticmethod
    def _unpack_raw_token(raw_token: str) -> Tuple[str, str]:
        candidate = str(raw_token or "").strip()
        if "." not in candidate:
            return "", ""
        token_id, token_secret = candidate.split(".", 1)
        return token_id.strip(), token_secret.strip()

    def _issue_token(
        self,
        token_kind: str,
        user_id: str,
        ttl_seconds: int,
        issued_ip: str,
        issued_user_agent: str,
        mfa_verified: bool,
    ) -> Dict[str, Any]:
        token_id, token_secret = self._new_token_parts()
        issued_at = now_utc()
        expires_at = issued_at + timedelta(seconds=max(int(ttl_seconds), 1))
        record = ApiTokenRecord(
            token_id=token_id,
            token_kind=token_kind,
            user_id=user_id,
            secret_fingerprint=self._fingerprint_secret(token_secret),
            issued_at=issued_at,
            expires_at=expires_at,
            issued_ip=str(issued_ip or ""),
            issued_user_agent=str(issued_user_agent or ""),
            mfa_verified=bool(mfa_verified),
        )
        self._records[token_id] = record
        return {
            "raw_token": self._pack_raw_token(token_id, token_secret),
            "token_id": token_id,
            "token_kind": token_kind,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "expires_in": int((expires_at - issued_at).total_seconds()),
        }

    def issue_pair(
        self,
        user_id: str,
        access_ttl_seconds: int,
        refresh_ttl_seconds: int,
        issued_ip: str,
        issued_user_agent: str,
        mfa_verified: bool = False,
    ) -> Dict[str, Any]:
        with self._lock:
            self._cleanup_locked()
            access = self._issue_token(
                token_kind=self.TOKEN_KIND_ACCESS,
                user_id=user_id,
                ttl_seconds=access_ttl_seconds,
                issued_ip=issued_ip,
                issued_user_agent=issued_user_agent,
                mfa_verified=mfa_verified,
            )
            refresh = self._issue_token(
                token_kind=self.TOKEN_KIND_REFRESH,
                user_id=user_id,
                ttl_seconds=refresh_ttl_seconds,
                issued_ip=issued_ip,
                issued_user_agent=issued_user_agent,
                mfa_verified=mfa_verified,
            )
            return {
                "access": access,
                "refresh": refresh,
            }

    def _validate_token(self, raw_token: str, expected_kind: str) -> Optional[ApiTokenRecord]:
        token_id, token_secret = self._unpack_raw_token(raw_token)
        if not token_id or not token_secret:
            return None

        with self._lock:
            self._cleanup_locked()
            record = self._records.get(token_id)
            if not record:
                return None
            if record.revoked:
                return None
            if record.token_kind != expected_kind:
                return None
            if record.is_expired():
                return None
            expected_fingerprint = self._fingerprint_secret(token_secret)
            if not hmac.compare_digest(record.secret_fingerprint, expected_fingerprint):
                return None
            revoked_after = self._user_revocation_cutoff.get(record.user_id)
            if revoked_after and record.issued_at <= revoked_after:
                return None
            return record

    def validate_access_token(self, raw_token: str) -> Optional[ApiTokenRecord]:
        return self._validate_token(raw_token, self.TOKEN_KIND_ACCESS)

    def validate_refresh_token(self, raw_token: str) -> Optional[ApiTokenRecord]:
        return self._validate_token(raw_token, self.TOKEN_KIND_REFRESH)

    def revoke_token(self, raw_token: str) -> bool:
        token_id, token_secret = self._unpack_raw_token(raw_token)
        if not token_id or not token_secret:
            return False

        with self._lock:
            self._cleanup_locked()
            record = self._records.get(token_id)
            if not record:
                return False
            expected_fingerprint = self._fingerprint_secret(token_secret)
            if not hmac.compare_digest(record.secret_fingerprint, expected_fingerprint):
                return False
            record.revoked = True
            return True

    def inspect_token(self, raw_token: str) -> Optional[ApiTokenRecord]:
        token_id, token_secret = self._unpack_raw_token(raw_token)
        if not token_id or not token_secret:
            return None

        with self._lock:
            self._cleanup_locked()
            record = self._records.get(token_id)
            if not record:
                return None
            expected_fingerprint = self._fingerprint_secret(token_secret)
            if not hmac.compare_digest(record.secret_fingerprint, expected_fingerprint):
                return None
            return record

    def revoke_token_id(self, token_id: str) -> bool:
        with self._lock:
            self._cleanup_locked()
            record = self._records.get(str(token_id or "").strip())
            if not record:
                return False
            record.revoked = True
            return True

    def revoke_user_tokens(self, user_id: str) -> int:
        with self._lock:
            self._cleanup_locked()
            revoked = 0
            for record in self._records.values():
                if record.user_id != user_id:
                    continue
                if record.revoked:
                    continue
                record.revoked = True
                revoked += 1
            return revoked

    def mark_user_forced_logout(self, user_id: str):
        with self._lock:
            self._user_revocation_cutoff[user_id] = now_utc()

    def clear_user_forced_logout(self, user_id: str):
        with self._lock:
            self._user_revocation_cutoff.pop(user_id, None)

    def is_user_forced_logout(self, user_id: str) -> bool:
        with self._lock:
            return str(user_id or "") in self._user_revocation_cutoff

    def get_user_revocation_cutoff(self, user_id: str) -> Optional[datetime]:
        with self._lock:
            return self._user_revocation_cutoff.get(str(user_id or ""))

    def _cleanup_locked(self):
        now_value = now_utc()
        expired_ids = []
        for token_id, record in self._records.items():
            if record.revoked or record.is_expired(now_value):
                expired_ids.append(token_id)
        for token_id in expired_ids:
            self._records.pop(token_id, None)

    def reset_for_tests(self):
        with self._lock:
            self._records.clear()
            self._user_revocation_cutoff.clear()


class SlidingWindowRateLimiter:
    def __init__(self):
        self._events: Dict[str, Deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        limit = max(int(max_requests), 1)
        window = max(int(window_seconds), 1)
        now_value = time.time()

        with self._lock:
            window_events = self._events.setdefault(key, deque())
            while window_events and (now_value - window_events[0]) >= window:
                window_events.popleft()
            if len(window_events) >= limit:
                retry_after = int(max(1, window - (now_value - window_events[0])))
                return False, retry_after
            window_events.append(now_value)
            return True, 0

    def reset_for_tests(self):
        with self._lock:
            self._events.clear()


class AuthLockoutManager:
    def __init__(self):
        self._failures: Dict[str, Deque[float]] = {}
        self._locked_until: Dict[str, float] = {}
        self._lock = Lock()

    def is_locked(self, key: str) -> Tuple[bool, int]:
        now_value = time.time()
        with self._lock:
            locked_until = self._locked_until.get(key, 0.0)
            if locked_until <= now_value:
                self._locked_until.pop(key, None)
                return False, 0
            return True, int(max(1, locked_until - now_value))

    def register_failure(self, key: str, max_attempts: int, window_seconds: int, lockout_seconds: int) -> int:
        attempts = max(int(max_attempts), 1)
        window = max(int(window_seconds), 1)
        lockout = max(int(lockout_seconds), 1)
        now_value = time.time()

        with self._lock:
            failures = self._failures.setdefault(key, deque())
            while failures and (now_value - failures[0]) >= window:
                failures.popleft()
            failures.append(now_value)
            if len(failures) >= attempts:
                self._locked_until[key] = now_value + lockout
                failures.clear()
                return 0
            return max(0, attempts - len(failures))

    def clear_failures(self, key: str):
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def reset_for_tests(self):
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()


class IdempotencyStore:
    def __init__(self):
        self._records: Dict[str, IdempotencyRecord] = {}
        self._lock = Lock()

    @staticmethod
    def build_fingerprint(method: str, path: str, actor_user_id: str, request_body: str) -> str:
        data = "\n".join([
            str(method or "").upper(),
            str(path or ""),
            str(actor_user_id or ""),
            str(request_body or ""),
        ]).encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def get(self, scope_key: str) -> Optional[IdempotencyRecord]:
        key = str(scope_key or "").strip()
        if not key:
            return None
        with self._lock:
            self._cleanup_locked()
            return self._records.get(key)

    def store(
        self,
        scope_key: str,
        fingerprint: str,
        response_data: Any,
        status_code: int,
        ttl_seconds: int = 24 * 60 * 60,
    ) -> IdempotencyRecord:
        key = str(scope_key or "").strip()
        if not key:
            raise ValueError("scope_key is required")
        now_value = now_utc()
        record = IdempotencyRecord(
            scope_key=key,
            fingerprint=str(fingerprint or "").strip(),
            response_data=response_data,
            status_code=int(status_code),
            created_at=now_value,
            expires_at=now_value + timedelta(seconds=max(int(ttl_seconds), 1)),
        )
        with self._lock:
            self._cleanup_locked()
            self._records[key] = record
        return record

    def _cleanup_locked(self):
        now_value = now_utc()
        expired = [
            key for key, record in self._records.items()
            if record.is_expired(now_value)
        ]
        for key in expired:
            self._records.pop(key, None)

    def reset_for_tests(self):
        with self._lock:
            self._records.clear()


class AsyncJobStore:
    def __init__(self):
        self._jobs: Dict[str, AsyncJobRecord] = {}
        self._lock = Lock()

    def create_job(self, operation: str, actor_user_id: str) -> AsyncJobRecord:
        job = AsyncJobRecord(
            job_id=secrets.token_hex(16),
            operation=str(operation or "").strip() or "operation",
            actor_user_id=str(actor_user_id or "").strip(),
            created_at=now_utc(),
        )
        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> Optional[AsyncJobRecord]:
        with self._lock:
            return self._jobs.get(str(job_id or "").strip())

    def start_job(
        self,
        operation: str,
        actor_user_id: str,
        target: Callable[[], Any],
    ) -> AsyncJobRecord:
        job = self.create_job(operation, actor_user_id)

        def runner():
            with self._lock:
                job.status = "running"
            try:
                result = target()
            except Exception as exc:  # pragma: no cover - thread exception path is timing-sensitive
                with self._lock:
                    job.status = "failed"
                    job.error = str(exc)
                    job.finished_at = now_utc()
                return
            with self._lock:
                job.status = "completed"
                job.result = result
                job.finished_at = now_utc()

        thread = threading.Thread(target=runner, daemon=True, name=f"arpvpn-job-{job.job_id[:8]}")
        thread.start()
        return job

    def reset_for_tests(self):
        with self._lock:
            self._jobs.clear()
