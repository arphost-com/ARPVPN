import base64
import io
import json
import os
import sys
import tarfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from arpvpn.common.properties import global_properties  # noqa: E402
from arpvpn.core.managers import updates as updates_module  # noqa: E402
from arpvpn.core.managers.updates import (  # noqa: E402
    UpdateError,
    UpdateManager,
    changelog_sections,
    newest_release_tag,
    parse_tag_refs,
)
from arpvpn.updater.core import Updater  # noqa: E402
from arpvpn.updater.docker_api import DockerError  # noqa: E402

CHANGELOG = """Changelog
=========

3.2.0
-----

* Big feature.

3.1.0
-----

* Update tab.

3.0.8
-----

* Docs.
"""


# ---------------------------------------------------------------------------
# Web side
# ---------------------------------------------------------------------------

def test_newest_release_tag_ignores_non_release_tags():
    assert newest_release_tag(["v3.0.8", "v3.10.0", "v3.9.9", "latest", "v4.0.0-rc1"]) == "v3.10.0"
    assert newest_release_tag(["main", "test"]) is None


def test_changelog_sections_between_versions_newest_first():
    sections = changelog_sections(CHANGELOG, "3.0.8", "3.2.0")
    assert [item["version"] for item in sections] == ["3.2.0", "3.1.0"]
    assert sections[1]["notes"] == "* Update tab."


def pkt(line):
    data = line.encode()
    return f"{len(data) + 4:04x}".encode() + data


ADVERTISEMENT = (pkt("# service=git-upload-pack\n") + b"0000"
                 + pkt("b6daec2a3069be5ab4062ee42959f8e6c1a89bf0 HEAD\0multi_ack side-band-64k\n")
                 + pkt("b6daec2a3069be5ab4062ee42959f8e6c1a89bf0 refs/heads/main\n")
                 + pkt("1111111111111111111111111111111111111111 refs/tags/v3.0.8\n")
                 + pkt("2222222222222222222222222222222222222222 refs/tags/v3.1.0\n")
                 + pkt("3333333333333333333333333333333333333333 refs/tags/v3.1.0^{}\n")
                 + pkt("4444444444444444444444444444444444444444 refs/tags/nightly\n")
                 + b"0000")


def test_parse_tag_refs_reads_git_advertisement():
    assert parse_tag_refs(ADVERTISEMENT) == ["v3.0.8", "v3.1.0", "nightly"]


class FakeResponse:
    def __init__(self, payload=None, text="", content=b""):
        self._payload = payload
        self.text = text
        self.content = content

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(global_properties, "workdir", str(tmp_path))
    monkeypatch.setattr(updates_module, "current_release", "3.0.8")

    def fake_get(url):
        if "info/refs" in url:
            return FakeResponse(content=ADVERTISEMENT)
        return FakeResponse(text=CHANGELOG)

    mgr = UpdateManager()
    monkeypatch.setattr(mgr, "_http_get", fake_get)
    return mgr


def write_heartbeat(tmp_path, mode="ready", age=0):
    state_dir = tmp_path / ".updater"
    state_dir.mkdir(exist_ok=True)
    (state_dir / "heartbeat.json").write_text(json.dumps({"ts": time.time() - age, "mode": mode, "detail": ""}))


def test_status_reports_available_update_and_changes(manager, tmp_path):
    write_heartbeat(tmp_path)
    status = manager.status()
    assert status["latest_tag"] == "v3.1.0"
    assert status["update_available"] is True
    assert [item["version"] for item in status["changes"]] == ["3.1.0"]
    assert status["can_update"] is True


def test_request_update_writes_request_file(manager, tmp_path):
    write_heartbeat(tmp_path)
    request = manager.request_update("v3.1.0", requested_by="admin")
    stored = json.loads((tmp_path / ".update-request.json").read_text())
    assert stored["tag"] == "v3.1.0" and stored["id"] == request["id"]
    with pytest.raises(UpdateError):
        manager.request_update("v3.1.0", requested_by="admin")  # already pending


@pytest.mark.parametrize("tag", ["main", "v3.1.0; rm -rf /", "v3.0.9", "../v3.1.0"])
def test_request_update_rejects_anything_but_newest_release(manager, tmp_path, tag):
    write_heartbeat(tmp_path)
    with pytest.raises(UpdateError):
        manager.request_update(tag, requested_by="admin")
    assert not (tmp_path / ".update-request.json").exists()


def test_request_update_requires_live_ready_updater(manager, tmp_path):
    with pytest.raises(UpdateError, match="not running"):
        manager.request_update("v3.1.0", requested_by="admin")
    write_heartbeat(tmp_path, age=600)
    with pytest.raises(UpdateError, match="not running"):
        manager.request_update("v3.1.0", requested_by="admin")
    write_heartbeat(tmp_path, mode="managed")
    with pytest.raises(UpdateError):
        manager.request_update("v3.1.0", requested_by="admin")


def test_check_failure_is_reported_not_raised(tmp_path, monkeypatch):
    monkeypatch.setattr(global_properties, "workdir", str(tmp_path))
    mgr = UpdateManager()

    def broken(url):
        raise updates_module.requests.ConnectionError("offline")

    monkeypatch.setattr(mgr, "_http_get", broken)
    status = mgr.status()
    assert status["update_available"] is False
    assert "offline" in status["check_error"]


# ---------------------------------------------------------------------------
# Updater side
# ---------------------------------------------------------------------------

def release_tarball(extra_members=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in [("ARPVPN-3.1.0/docker/Dockerfile", b"FROM scratch\n"),
                              ("ARPVPN-3.1.0/arpvpn/__init__.py", b"")] + list(extra_members or []):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


class FakeOpener:
    def __init__(self, data):
        self.data = data
        self.urls = []

    def __call__(self, url, timeout=None):
        self.urls.append(url)
        data = self.data

        class _Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return _Response(data)


class FakeDocker:
    def __init__(self, healthy=True, image="arpvpn:local", build_error=False):
        self.healthy = healthy
        self.build_error = build_error
        self.calls = []
        self.containers = {
            "arpvpn": {
                "Image": "sha256:old",
                "Config": {"Image": image, "Env": ["PATH=/x", "ARPVPN_HTTP_PORT=8085"], "Cmd": ["/bin/bash", "-lc", "x"],
                           "User": "arpvpn", "Labels": {"com.docker.compose.service": "arpvpn",
                                                                       "com.docker.compose.image": "sha256:old"}},
                "HostConfig": {"NetworkMode": "host", "Binds": ["/srv/data:/data"]},
                "NetworkSettings": {"Networks": {"host": {}}},
                "State": {"Running": True, "Health": {"Status": "healthy"}},
            }
        }
        self.created_spec = None

    def inspect_container(self, name):
        if name not in self.containers:
            raise DockerError(404, "no such container")
        return self.containers[name]

    def inspect_image(self, ref):
        if ref == "sha256:old":
            return {"Id": "sha256:old", "Config": {"Env": ["PATH=/x"], "Cmd": ["/bin/bash", "/entrypoint.sh"], "User": "arpvpn"}}
        return {"Id": "sha256:new", "Config": {}}

    def build_image(self, context, tag, dockerfile, buildargs):
        self.calls.append(("build", tag, dockerfile, dict(buildargs)))
        with tarfile.open(context) as archive:
            self.context_names = archive.getnames()
        trace = base64.b64encode(b"\x12\x26[1/2] FROM docker.io/library/python:3.14\x00\x10[2/2] RUN install.sh").decode()
        yield {"id": "moby.buildkit.trace", "aux": trace}
        if self.build_error:
            yield {"error": "process did not complete successfully", "errorDetail": {"message": "process did not complete successfully"}}
            return
        yield {"id": "moby.image.id", "aux": {"ID": "sha256:new"}}

    def stop_container(self, name, timeout_seconds=30):
        self.calls.append(("stop", name))
        self.containers[name]["State"] = {"Running": False, "Status": "exited"}

    def rename_container(self, name, new_name):
        self.calls.append(("rename", name, new_name))
        self.containers[new_name] = self.containers.pop(name)

    def create_container(self, name, spec):
        self.calls.append(("create", name))
        self.created_spec = spec
        health = "healthy" if self.healthy else "unhealthy"
        self.containers[name] = {"Image": "sha256:new", "Config": spec, "State": {"Running": True, "Health": {"Status": health}}}
        return "new"

    def start_container(self, name):
        self.calls.append(("start", name))
        self.containers[name]["State"]["Running"] = True

    def remove_container(self, name, force=False):
        self.calls.append(("remove", name))
        if name not in self.containers:
            raise DockerError(404, "no such container")
        self.containers.pop(name)

    def tag_image(self, ref, repository, tag):
        self.calls.append(("tag", ref, repository, tag))

    def remove_image(self, ref):
        self.calls.append(("rmi", ref))

    def container_logs(self, name, tail=80):
        return "boom"


def make_updater(tmp_path, docker, opener=None):
    return Updater(str(tmp_path), "arpvpn", docker, buildargs={"ARPVPN_UID": "1000"},
                   opener=opener or FakeOpener(release_tarball()), sleep=lambda s: None)


def queue(tmp_path, tag="v3.1.0"):
    (tmp_path / ".update-request.json").write_text(json.dumps({"id": "abc", "tag": tag, "requested_by": "admin"}))


def test_successful_update_does_not_retag(tmp_path):
    docker = FakeDocker()
    updater = make_updater(tmp_path, docker)
    queue(tmp_path)
    assert updater.run_request(updater.take_request()) is True
    assert not any(call[0] == "tag" for call in docker.calls)


def test_successful_update_rebuilds_and_swaps_container(tmp_path):
    docker = FakeDocker()
    updater = make_updater(tmp_path, docker)
    queue(tmp_path)
    assert updater.run_request(updater.take_request()) is True
    assert not (tmp_path / ".update-request.json").exists()
    assert ("build", "arpvpn:local", "docker/Dockerfile", {"ARPVPN_UID": "1000"}) in docker.calls
    assert "docker/Dockerfile" in docker.context_names
    assert not any(name.startswith("ARPVPN-3.1.0") for name in docker.context_names)
    assert docker.created_spec["Image"] == "arpvpn:local"
    assert docker.created_spec["Cmd"] == ["/bin/bash", "-lc", "x"]  # compose override kept
    assert "User" not in docker.created_spec  # equal to old image default, so inherited
    assert docker.created_spec["Env"] == ["ARPVPN_HTTP_PORT=8085"]
    assert docker.created_spec["HostConfig"]["Binds"] == ["/srv/data:/data"]
    assert docker.created_spec["Labels"]["com.docker.compose.image"] == "sha256:new"
    assert docker.created_spec["Labels"]["com.docker.compose.service"] == "arpvpn"
    assert ("remove", "arpvpn-pre-update") in docker.calls
    assert "arpvpn-pre-update" not in docker.containers
    status = json.loads((tmp_path / ".updater" / "status.json").read_text())
    assert status["state"] == "success"


def test_unhealthy_update_restores_previous_container(tmp_path):
    docker = FakeDocker(healthy=False)
    updater = make_updater(tmp_path, docker)
    queue(tmp_path)
    assert updater.run_request(updater.take_request()) is False
    assert docker.containers["arpvpn"]["Image"] == "sha256:old"
    assert ("rename", "arpvpn-pre-update", "arpvpn") in docker.calls
    assert ("tag", "sha256:old", "arpvpn", "local") in docker.calls
    assert ("rmi", "sha256:new") in docker.calls
    assert docker.calls.index(("start", "arpvpn")) < docker.calls.index(("tag", "sha256:old", "arpvpn", "local"))
    status = json.loads((tmp_path / ".updater" / "status.json").read_text())
    assert status["state"] == "failed" and "restored" in status["message"]


def test_registry_image_installs_are_left_to_the_pipeline(tmp_path):
    docker = FakeDocker(image="registry.example/arphost/arpvpn:3.0.8")
    updater = make_updater(tmp_path, docker)
    assert updater.heartbeat()["mode"] == "managed"
    queue(tmp_path)
    assert updater.run_request(updater.take_request()) is False
    assert not any(call[0] == "build" for call in docker.calls)


@pytest.mark.parametrize("tag", ["main", "v3.1.0/../../x", "v3.1.0 --evil"])
def test_updater_rejects_non_release_tags(tmp_path, tag):
    docker = FakeDocker()
    opener = FakeOpener(release_tarball())
    updater = make_updater(tmp_path, docker, opener)
    queue(tmp_path, tag)
    assert updater.run_request(updater.take_request()) is False
    assert opener.urls == []


def test_updater_rejects_archives_with_path_traversal(tmp_path):
    docker = FakeDocker()
    opener = FakeOpener(release_tarball([("ARPVPN-3.1.0/../../etc/passwd", b"x")]))
    updater = make_updater(tmp_path, docker, opener)
    queue(tmp_path)
    assert updater.run_request(updater.take_request()) is False
    assert not any(call[0] == "build" for call in docker.calls)
    assert opener.urls == ["https://codeload.github.com/arphost-com/ARPVPN/tar.gz/refs/tags/v3.1.0"]


def test_state_files_are_world_readable_for_the_web_app(tmp_path):
    updater = make_updater(tmp_path, FakeDocker())
    updater.heartbeat()
    mode = os.stat(tmp_path / ".updater" / "heartbeat.json").st_mode & 0o777
    assert mode == 0o644


def test_tarball_url_override_is_limited_to_https_and_file(monkeypatch):
    from arpvpn.updater.__main__ import tarball_url_from_env
    from arpvpn.updater.core import TARBALL_URL

    monkeypatch.setenv("ARPVPN_UPDATER_TARBALL_URL", "file:///releases/{tag}.tar.gz")
    assert tarball_url_from_env() == "file:///releases/{tag}.tar.gz"
    monkeypatch.setenv("ARPVPN_UPDATER_TARBALL_URL", "http://example.test/{tag}.tar.gz")
    assert tarball_url_from_env() == TARBALL_URL
    monkeypatch.setenv("ARPVPN_UPDATER_TARBALL_URL", "https://mirror.example/fixed.tar.gz")
    assert tarball_url_from_env() == TARBALL_URL


def test_docker_client_uses_daemon_api_version(tmp_path):
    import socket
    import threading
    from arpvpn.updater.docker_api import DockerClient

    path = str(tmp_path / "docker.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(4)
    seen = []

    def serve():
        for _ in range(2):
            conn, _ = server.accept()
            request = conn.recv(65536).decode()
            seen.append(request.split(" ")[1])
            body = b'{"ApiVersion": "1.56"}' if " /version " in request else b'{"Id": "c1"}'
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    DockerClient(path, timeout=5).inspect_container("arpvpn")
    thread.join(5)
    server.close()
    assert seen == ["/version", "/v1.56/containers/arpvpn/json"]


def test_build_failure_leaves_running_container_untouched(tmp_path):
    docker = FakeDocker(build_error=True)
    updater = make_updater(tmp_path, docker)
    queue(tmp_path)
    assert updater.run_request(updater.take_request()) is False
    assert not any(call[0] in ("stop", "rename", "create") for call in docker.calls)
    log = (tmp_path / ".updater" / "update.log").read_text()
    assert "[1/2] FROM docker.io/library/python:3.14" in log
    assert "[2/2] RUN install.sh" in log
    assert "Image build failed" in log


def test_buildkit_step_names_are_normalised():
    trace = base64.b64encode(b"\x10[2/9] RUN apt-get update\x00\x11[2/9] RUN apt-get update*").decode()
    assert Updater.buildkit_steps({"id": "moby.buildkit.trace", "aux": trace}) == [
        "[2/9] RUN apt-get update", "[2/9] RUN apt-get update"]
