"""ARPVPN updater: rebuild the ARPVPN container from a GitHub release tag.

Runs in its own container with the Docker socket and the ARPVPN data folder
mounted and no published ports. The web application can only drop a request
file naming a release tag; everything else (repository, image name, container
to replace) comes from this container's own environment.
"""

import io
import json
import os
import re
import tarfile
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from arpvpn.updater.docker_api import DockerClient, DockerError

RELEASE_TAG_PATTERN = re.compile(r"^v\d+\.\d+\.\d+$")
DEFAULT_REPOSITORY = "arphost-com/ARPVPN"
TARBALL_URL = "https://codeload.github.com/{repo}/tar.gz/refs/tags/{tag}"
DOCKERFILE = "docker/Dockerfile"
MAX_TARBALL_BYTES = 50 * 1024 * 1024
HEALTH_TIMEOUT_SECONDS = 240
NO_HEALTHCHECK_SETTLE_SECONDS = 20
OLD_SUFFIX = "-pre-update"

# Container settings that compose copies from the image unless the compose file
# overrides them. When they still equal the old image's values we drop them so
# the new image's defaults apply.
INHERITABLE_CONFIG_KEYS = ("Cmd", "Entrypoint", "WorkingDir", "User", "Healthcheck",
                           "ExposedPorts", "StopSignal", "Shell", "OnBuild", "ArgsEscaped")
DROP_CONFIG_KEYS = ("Image", "Hostname", "Domainname")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class UpdateFailed(Exception):
    pass


class Updater:

    def __init__(self, data_dir: str, target: str, docker: DockerClient,
                 repository: str = DEFAULT_REPOSITORY, buildargs: Optional[Dict[str, str]] = None,
                 opener: Callable[..., Any] = urllib.request.urlopen, sleep: Callable[[float], None] = time.sleep):
        self.data_dir = data_dir
        self.state_dir = os.path.join(data_dir, ".updater")
        self.request_path = os.path.join(data_dir, ".update-request.json")
        self.target = target
        self.docker = docker
        self.repository = repository
        self.buildargs = dict(buildargs or {})
        self.opener = opener
        self.sleep = sleep
        os.makedirs(self.state_dir, mode=0o755, exist_ok=True)

    # State files -------------------------------------------------------------
    def _write_json(self, filename: str, data: Dict[str, Any]):
        path = os.path.join(self.state_dir, filename)
        temp_path = f"{path}.tmp"
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, path)

    def log(self, message: str):
        line = f"[{utc_now()}] {message}\n"
        path = os.path.join(self.state_dir, "update.log")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line)
        os.chmod(path, 0o644)
        print(line, end="", flush=True)

    def set_status(self, **fields):
        self.status.update(fields)
        self._write_json("status.json", self.status)

    # Target inspection ---------------------------------------------------------
    def describe_target(self) -> Dict[str, str]:
        try:
            container = self.docker.inspect_container(self.target)
        except DockerError as exc:
            if exc.status == 404:
                return {"mode": "error", "detail": f"Container '{self.target}' was not found."}
            return {"mode": "error", "detail": str(exc)}
        image = str(container.get("Config", {}).get("Image", ""))
        if "/" in image or "@" in image:
            return {"mode": "managed",
                    "detail": "This install runs a registry image and is updated by its deployment pipeline, not from here."}
        if not image:
            return {"mode": "error", "detail": "Unable to determine the ARPVPN image name."}
        return {"mode": "ready", "detail": "", "image": image}

    def heartbeat(self):
        state = self.describe_target()
        state["ts"] = time.time()
        state["target"] = self.target
        self._write_json("heartbeat.json", state)
        return state

    # Request handling -----------------------------------------------------------
    def take_request(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self.request_path):
            return None
        try:
            with open(self.request_path, "r", encoding="utf-8") as handle:
                request = json.load(handle)
        except (OSError, ValueError):
            request = None
        try:
            os.remove(self.request_path)
        except OSError:
            pass
        if not isinstance(request, dict):
            self.log("Ignored an unreadable update request.")
            return None
        return request

    def run_request(self, request: Dict[str, Any]) -> bool:
        tag = str(request.get("tag", ""))
        self.status = {
            "state": "running",
            "step": "validating",
            "request_id": str(request.get("id", ""))[:32],
            "target_tag": tag[:32],
            "from_version": str(request.get("from_version", ""))[:32],
            "requested_by": str(request.get("requested_by", ""))[:64],
            "started_at": utc_now(),
            "finished_at": None,
            "message": "",
        }
        self._write_json("status.json", self.status)
        log_path = os.path.join(self.state_dir, "update.log")
        with open(log_path, "w", encoding="utf-8"):
            pass
        try:
            if not RELEASE_TAG_PATTERN.match(tag):
                raise UpdateFailed(f"Refusing update: '{tag}' is not a release tag.")
            target = self.describe_target()
            if target["mode"] != "ready":
                raise UpdateFailed(target["detail"])
            self.log(f"Updating {self.target} to {tag} (requested by {self.status['requested_by'] or 'unknown'}).")
            self.perform_update(tag, target["image"])
        except UpdateFailed as exc:
            self.log(f"ERROR: {exc}")
            self.set_status(state="failed", step="done", finished_at=utc_now(), message=str(exc))
            return False
        except Exception as exc:  # pragma: no cover - unexpected failure path
            self.log(f"ERROR: unexpected failure: {exc}")
            self.set_status(state="failed", step="done", finished_at=utc_now(), message=f"Unexpected failure: {exc}")
            return False
        self.log("Update finished.")
        self.set_status(state="success", step="done", finished_at=utc_now(),
                        message=f"ARPVPN is now running {tag}.")
        return True

    # Update steps -----------------------------------------------------------------
    def perform_update(self, tag: str, image: str):
        self.set_status(step="downloading")
        with tempfile.TemporaryDirectory(prefix="arpvpn-update-") as workdir:
            context_path = os.path.join(workdir, "context.tar")
            self.download_context(tag, context_path)
            self.set_status(step="building")
            self.build(context_path, image)
        self.set_status(step="replacing")
        self.replace_container(image)

    def download_context(self, tag: str, context_path: str):
        url = TARBALL_URL.format(repo=self.repository, tag=tag)
        self.log(f"Downloading {self.repository} {tag} from GitHub.")
        try:
            with self.opener(url, timeout=120) as response:
                data = response.read(MAX_TARBALL_BYTES + 1)
        except Exception as exc:
            raise UpdateFailed(f"Download failed: {exc}") from exc
        if len(data) > MAX_TARBALL_BYTES:
            raise UpdateFailed("Download is larger than expected; refusing to build it.")
        # GitHub tarballs wrap everything in "<repo>-<tag>/"; strip it so the
        # repository root becomes the build context root.
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as source, \
                    tarfile.open(context_path, mode="w") as context:
                for member in source.getmembers():
                    parts = member.name.split("/", 1)
                    if len(parts) < 2 or not parts[1]:
                        continue
                    name = parts[1]
                    if name.startswith("/") or ".." in name.split("/"):
                        raise UpdateFailed(f"Unsafe path in release archive: {member.name}")
                    if member.issym() or member.islnk():
                        link = member.linkname
                        if link.startswith("/") or ".." in link.split("/"):
                            raise UpdateFailed(f"Unsafe link in release archive: {member.name}")
                    member.name = name
                    fileobj = source.extractfile(member) if member.isfile() else None
                    context.addfile(member, fileobj)
        except tarfile.TarError as exc:
            raise UpdateFailed(f"Release archive is not a valid tarball: {exc}") from exc
        with tarfile.open(context_path, mode="r") as check:
            if DOCKERFILE not in check.getnames():
                raise UpdateFailed(f"Release archive does not contain {DOCKERFILE}.")

    def build(self, context_path: str, image: str):
        self.log(f"Building image {image}. This takes several minutes.")
        last_lines: List[str] = []
        for message in self.docker.build_image(context_path, image, DOCKERFILE, self.buildargs):
            if message.get("error"):
                detail = message.get("errorDetail", {}).get("message") or message["error"]
                for line in last_lines[-10:]:
                    self.log(f"  {line}")
                raise UpdateFailed(f"Image build failed: {detail.strip()}")
            text = str(message.get("stream", "")).strip()
            if text:
                last_lines.append(text)
                if text.startswith("Step ") or text.startswith("Successfully"):
                    self.log(f"  {text}")
        self.log("Image build finished.")

    @staticmethod
    def _creation_spec(container: Dict[str, Any], old_image: Dict[str, Any], image: str) -> Dict[str, Any]:
        config = dict(container.get("Config", {}))
        image_config = old_image.get("Config", {}) or {}
        for key in DROP_CONFIG_KEYS:
            config.pop(key, None)
        for key in INHERITABLE_CONFIG_KEYS:
            if key in config and config.get(key) == image_config.get(key):
                config.pop(key)
        image_env = set(image_config.get("Env") or [])
        config["Env"] = [item for item in (config.get("Env") or []) if item not in image_env]
        image_labels = image_config.get("Labels") or {}
        config["Labels"] = {k: v for k, v in (config.get("Labels") or {}).items() if image_labels.get(k) != v}
        config["Image"] = image
        host_config = dict(container.get("HostConfig", {}))
        spec = dict(config)
        spec["HostConfig"] = host_config
        network_mode = host_config.get("NetworkMode", "")
        networks = (container.get("NetworkSettings", {}) or {}).get("Networks", {}) or {}
        if networks and network_mode not in ("host", "none") and not network_mode.startswith("container:"):
            spec["NetworkingConfig"] = {"EndpointsConfig": {
                name: {key: value for key, value in (settings or {}).items()
                       if key in ("Aliases", "IPAMConfig", "Links", "DriverOpts") and value}
                for name, settings in networks.items()
            }}
        return spec

    def wait_healthy(self, name: str) -> bool:
        deadline = time.time() + HEALTH_TIMEOUT_SECONDS
        settle_until = time.time() + NO_HEALTHCHECK_SETTLE_SECONDS
        while time.time() < deadline:
            state = self.docker.inspect_container(name).get("State", {})
            if not state.get("Running") and state.get("Status") in ("exited", "dead"):
                return False
            health = (state.get("Health") or {}).get("Status")
            if health == "healthy":
                return True
            if health == "unhealthy":
                return False
            if health is None and state.get("Running") and time.time() >= settle_until:
                return True
            self.sleep(3)
        return False

    def replace_container(self, image: str):
        name = self.target
        old_name = f"{name}{OLD_SUFFIX}"
        container = self.docker.inspect_container(name)
        old_image_id = container.get("Image", "")
        old_image = self.docker.inspect_image(old_image_id) if old_image_id else {}
        new_image = self.docker.inspect_image(image)
        if new_image.get("Id") == old_image_id:
            self.log("The built image is identical to the running one; nothing to replace.")
            return
        spec = self._creation_spec(container, old_image, image)
        try:
            self.docker.remove_container(old_name, force=True)
        except DockerError:
            pass

        self.log("Stopping the current ARPVPN container.")
        self.docker.stop_container(name)
        self.docker.rename_container(name, old_name)
        try:
            self.docker.create_container(name, spec)
            self.docker.start_container(name)
            self.log("Waiting for the new container to report healthy.")
            healthy = self.wait_healthy(name)
        except DockerError as exc:
            self.log(f"Starting the new container failed: {exc}")
            healthy = False
        if healthy:
            self.log("New container is healthy; removing the previous one.")
            self.docker.remove_container(old_name, force=True)
            try:
                self.docker.remove_image(old_image_id)
            except DockerError:
                pass
            return
        self.set_status(step="rolling back")
        try:
            for line in self.docker.container_logs(name, tail=40).splitlines():
                self.log(f"  new container: {line}")
        except DockerError:
            pass
        self.log("New container did not become healthy. Restoring the previous version.")
        try:
            self.docker.remove_container(name, force=True)
        except DockerError:
            pass
        self.docker.rename_container(old_name, name)
        self.docker.start_container(name)
        raise UpdateFailed("The new version did not start correctly, so the previous version was restored.")

    # Main loop --------------------------------------------------------------------
    def run_forever(self, poll_seconds: float = 5.0, heartbeat_seconds: float = 15.0):
        self.status = {"state": "idle"}
        existing = os.path.join(self.state_dir, "status.json")
        if os.path.exists(existing):
            try:
                with open(existing, "r", encoding="utf-8") as handle:
                    previous = json.load(handle)
                if previous.get("state") == "running":
                    previous.update(state="failed", step="done", finished_at=utc_now(),
                                    message="The updater restarted while an update was running.")
                    self._write_json("status.json", previous)
            except (OSError, ValueError):
                pass
        last_heartbeat = 0.0
        while True:
            if time.time() - last_heartbeat >= heartbeat_seconds:
                try:
                    self.heartbeat()
                except Exception as exc:  # pragma: no cover - keep the loop alive
                    print(f"heartbeat failed: {exc}", flush=True)
                last_heartbeat = time.time()
            request = self.take_request()
            if request:
                self.run_request(request)
                last_heartbeat = 0.0
            self.sleep(poll_seconds)
