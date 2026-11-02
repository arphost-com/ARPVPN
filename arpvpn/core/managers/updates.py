"""In-app update checks and update requests.

The web application never touches Docker. It only

* asks GitHub which release tags exist and what changed,
* reads the state published by the arpvpn-updater container, and
* writes a small request file that the updater picks up.

The updater (``arpvpn.updater``) runs as a separate container that holds the
Docker socket, publishes no ports and validates every request on its own.
"""

import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import requests

from arpvpn.__version__ import release as current_release
from arpvpn.common.properties import global_properties

GITHUB_REPOSITORY = "arphost-com/ARPVPN"
# git's smart-HTTP ref advertisement: no API token or rate limit involved.
GITHUB_REFS_URL = f"https://github.com/{GITHUB_REPOSITORY}.git/info/refs?service=git-upload-pack"
GITHUB_CHANGELOG_URL = "https://raw.githubusercontent.com/" + GITHUB_REPOSITORY + "/{tag}/docs/source/changelog.rst"

RELEASE_TAG_PATTERN = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
CHANGELOG_HEADING = re.compile(r"^(\d+\.\d+\.\d+)\s*\n-{3,}\s*$", re.MULTILINE)

UPDATER_DIRNAME = ".updater"
HEARTBEAT_FILENAME = "heartbeat.json"
STATUS_FILENAME = "status.json"
LOG_FILENAME = "update.log"
REQUEST_FILENAME = ".update-request.json"

HEARTBEAT_MAX_AGE_SECONDS = 90
CHECK_CACHE_SECONDS = 3600
LOG_TAIL_LINES = 200
HTTP_TIMEOUT_SECONDS = 10


class UpdateError(Exception):
    """Raised for update requests that must be refused."""


def parse_version(value: str) -> Optional[Tuple[int, int, int]]:
    match = VERSION_PATTERN.match(str(value or "").strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def parse_release_tag(tag: str) -> Optional[Tuple[int, int, int]]:
    match = RELEASE_TAG_PATTERN.match(str(tag or "").strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def newest_release_tag(tag_names: List[str]) -> Optional[str]:
    releases = [(parse_release_tag(name), name) for name in tag_names]
    releases = [item for item in releases if item[0] is not None]
    if not releases:
        return None
    return max(releases)[1]


def parse_tag_refs(advertisement: bytes) -> List[str]:
    """Extract tag names from a git smart-HTTP ref advertisement (pkt-line format)."""
    names: List[str] = []
    data = advertisement or b""
    index = 0
    while index + 4 <= len(data):
        try:
            length = int(data[index:index + 4], 16)
        except ValueError:
            break
        if length == 0:
            index += 4
            continue
        line = data[index + 4:index + length].decode("utf-8", errors="replace")
        index += length
        line = line.split("\0", 1)[0].strip()
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1].startswith("refs/tags/"):
            name = parts[1][len("refs/tags/"):]
            if name.endswith("^{}"):
                name = name[:-3]
            if name not in names:
                names.append(name)
    return names


def changelog_sections(changelog: str, newer_than: str, up_to: str) -> List[Dict[str, str]]:
    """Return changelog sections with newer_than < version <= up_to, newest first."""
    lower = parse_version(newer_than) or (0, 0, 0)
    upper = parse_version(up_to)
    headings = list(CHANGELOG_HEADING.finditer(changelog or ""))
    sections: List[Dict[str, str]] = []
    for index, heading in enumerate(headings):
        version = heading.group(1)
        parsed = parse_version(version)
        if parsed is None or parsed <= lower or (upper is not None and parsed > upper):
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(changelog)
        body = changelog[heading.end():end].strip()
        sections.append({"version": version, "notes": body})
    sections.sort(key=lambda item: parse_version(item["version"]) or (0, 0, 0), reverse=True)
    return sections


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _tail(path: str, lines: int) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return "".join(handle.readlines()[-lines:])
    except OSError:
        return ""


class UpdateManager:

    def __init__(self):
        self._lock = Lock()
        self._cache: Dict[str, Any] = {}
        self._cache_time = 0.0

    # Paths ------------------------------------------------------------------
    @staticmethod
    def _updater_path(filename: str) -> str:
        return global_properties.join_workdir(os.path.join(UPDATER_DIRNAME, filename))

    @staticmethod
    def request_path() -> str:
        return global_properties.join_workdir(REQUEST_FILENAME)

    # GitHub -----------------------------------------------------------------
    @staticmethod
    def _http_get(url: str) -> requests.Response:
        response = requests.get(
            url,
            headers={"User-Agent": f"ARPVPN/{current_release}"},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response

    def check(self, force: bool = False) -> Dict[str, Any]:
        with self._lock:
            if not force and self._cache and time.time() - self._cache_time < CHECK_CACHE_SECONDS:
                return dict(self._cache)
            result: Dict[str, Any] = {
                "checked_at": _utc_now_iso(),
                "latest_tag": None,
                "latest_version": None,
                "changes": [],
                "error": None,
            }
            try:
                names = parse_tag_refs(self._http_get(GITHUB_REFS_URL).content)
                latest = newest_release_tag(names)
                if latest:
                    result["latest_tag"] = latest
                    result["latest_version"] = latest[1:]
                    if self.is_newer(result["latest_version"]):
                        changelog = self._http_get(GITHUB_CHANGELOG_URL.format(tag=latest)).text
                        result["changes"] = changelog_sections(changelog, current_release, result["latest_version"])
            except (requests.RequestException, ValueError) as exc:
                result["error"] = f"Unable to check GitHub for updates: {exc}"
            self._cache = result
            self._cache_time = time.time()
            return dict(result)

    @staticmethod
    def is_newer(version: Optional[str]) -> bool:
        candidate = parse_version(version or "")
        installed = parse_version(current_release)
        if candidate is None:
            return False
        if installed is None:
            return True
        return candidate > installed

    # Updater state ----------------------------------------------------------
    def updater_state(self) -> Dict[str, Any]:
        heartbeat = _read_json(self._updater_path(HEARTBEAT_FILENAME)) or {}
        age = None
        if heartbeat:
            try:
                age = max(0, int(time.time() - float(heartbeat.get("ts", 0))))
            except (TypeError, ValueError):
                age = None
        alive = bool(heartbeat) and age is not None and age <= HEARTBEAT_MAX_AGE_SECONDS
        mode = str(heartbeat.get("mode", "")) if alive else "missing"
        return {
            "present": alive,
            "mode": mode,
            "detail": str(heartbeat.get("detail", "")) if alive else "",
            "heartbeat_age_seconds": age,
        }

    def job_state(self) -> Dict[str, Any]:
        status = _read_json(self._updater_path(STATUS_FILENAME)) or {"state": "idle"}
        status["request_pending"] = os.path.exists(self.request_path())
        status["log"] = _tail(self._updater_path(LOG_FILENAME), LOG_TAIL_LINES)
        return status

    def status(self, force_check: bool = False) -> Dict[str, Any]:
        check = self.check(force=force_check)
        updater = self.updater_state()
        job = self.job_state()
        update_available = self.is_newer(check.get("latest_version"))
        busy = job.get("state") == "running" or job.get("request_pending")
        return {
            "current_version": current_release,
            "latest_version": check.get("latest_version"),
            "latest_tag": check.get("latest_tag"),
            "update_available": update_available,
            "changes": check.get("changes", []),
            "checked_at": check.get("checked_at"),
            "check_error": check.get("error"),
            "updater": updater,
            "job": job,
            "can_update": bool(update_available and updater["present"] and updater["mode"] == "ready" and not busy),
        }

    # Requests ---------------------------------------------------------------
    def request_update(self, tag: str, requested_by: str) -> Dict[str, Any]:
        tag = str(tag or "").strip()
        if parse_release_tag(tag) is None:
            raise UpdateError("Update target must be a release tag such as v3.1.0.")
        status = self.status()
        if status["latest_tag"] != tag:
            raise UpdateError("Only the newest published release can be installed.")
        if not status["update_available"]:
            raise UpdateError(f"ARPVPN {current_release} is already up to date.")
        updater = status["updater"]
        if not updater["present"]:
            raise UpdateError("The ARPVPN updater container is not running, so updates cannot be installed from here.")
        if updater["mode"] != "ready":
            raise UpdateError(updater["detail"] or "The ARPVPN updater is not ready.")
        if status["job"].get("state") == "running" or status["job"].get("request_pending"):
            raise UpdateError("An update is already in progress.")
        request = {
            "id": secrets.token_hex(8),
            "tag": tag,
            "from_version": current_release,
            "requested_by": requested_by,
            "requested_at": _utc_now_iso(),
        }
        path = self.request_path()
        temp_path = f"{path}.tmp"
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(request, handle)
        os.replace(temp_path, path)
        return request


update_manager = UpdateManager()
