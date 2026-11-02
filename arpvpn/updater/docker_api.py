"""Minimal Docker Engine API client over the unix socket (standard library only)."""

import http.client
import json
import socket
from typing import Any, Dict, Iterator, Optional, Tuple
from urllib.parse import quote, urlencode

FALLBACK_API_VERSION = "1.44"


class DockerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"Docker API {status}: {message}")
        self.status = status


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


class DockerClient:

    def __init__(self, socket_path: str = "/var/run/docker.sock", timeout: float = 60.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self._api_version: Optional[str] = None

    def api_version(self) -> str:
        """Use the daemon's own API version so engine upgrades never strand the client."""
        if self._api_version is None:
            version = FALLBACK_API_VERSION
            conn = _UnixHTTPConnection(self.socket_path, self.timeout)
            try:
                conn.request("GET", "/version")
                response = conn.getresponse()
                data = json.loads(response.read() or b"{}")
                candidate = str(data.get("ApiVersion", "")).strip()
                if candidate.replace(".", "").isdigit():
                    version = candidate
            except (OSError, ValueError):
                pass
            finally:
                conn.close()
            self._api_version = version
        return self._api_version

    def _request(self, method: str, path: str, query: Optional[Dict[str, Any]] = None,
                 body: Any = None, headers: Optional[Dict[str, str]] = None,
                 timeout: Optional[float] = None) -> Tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
        url = f"/v{self.api_version()}{path}"
        if query:
            url = f"{url}?{urlencode({k: v for k, v in query.items() if v is not None})}"
        conn = _UnixHTTPConnection(self.socket_path, timeout or self.timeout)
        send_headers = dict(headers or {})
        payload = body
        if isinstance(body, (dict, list)):
            payload = json.dumps(body).encode("utf-8")
            send_headers.setdefault("Content-Type", "application/json")
        conn.request(method, url, body=payload, headers=send_headers)
        return conn, conn.getresponse()

    def _call(self, method: str, path: str, query=None, body=None, ok=(200, 201, 204, 304),
              timeout: Optional[float] = None) -> Any:
        conn, response = self._request(method, path, query=query, body=body, timeout=timeout)
        try:
            raw = response.read()
        finally:
            conn.close()
        if response.status not in ok:
            message = raw.decode("utf-8", errors="replace")
            try:
                message = json.loads(message).get("message", message)
            except ValueError:
                pass
            raise DockerError(response.status, message.strip())
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode("utf-8", errors="replace")

    # Containers -------------------------------------------------------------
    def inspect_container(self, name: str) -> Dict[str, Any]:
        return self._call("GET", f"/containers/{quote(name, safe='')}/json")

    def inspect_image(self, ref: str) -> Dict[str, Any]:
        return self._call("GET", f"/images/{quote(ref, safe='')}/json")

    def stop_container(self, name: str, timeout_seconds: int = 30):
        self._call("POST", f"/containers/{quote(name, safe='')}/stop", query={"t": timeout_seconds},
                   timeout=timeout_seconds + 30)

    def start_container(self, name: str):
        self._call("POST", f"/containers/{quote(name, safe='')}/start")

    def rename_container(self, name: str, new_name: str):
        self._call("POST", f"/containers/{quote(name, safe='')}/rename", query={"name": new_name})

    def remove_container(self, name: str, force: bool = False):
        self._call("DELETE", f"/containers/{quote(name, safe='')}", query={"force": "1" if force else "0"})

    def create_container(self, name: str, spec: Dict[str, Any]) -> str:
        created = self._call("POST", "/containers/create", query={"name": name}, body=spec)
        return created["Id"]

    def remove_image(self, ref: str):
        self._call("DELETE", f"/images/{quote(ref, safe='')}", query={"noprune": "0"}, ok=(200,))

    def container_logs(self, name: str, tail: int = 80) -> str:
        conn, response = self._request("GET", f"/containers/{quote(name, safe='')}/logs",
                                       query={"stdout": "1", "stderr": "1", "tail": tail})
        try:
            raw = response.read()
        finally:
            conn.close()
        # Strip the 8-byte multiplexing headers used for non-TTY containers.
        out = bytearray()
        index = 0
        while index + 8 <= len(raw) and raw[index] in (0, 1, 2) and raw[index + 1:index + 4] == b"\x00\x00\x00":
            size = int.from_bytes(raw[index + 4:index + 8], "big")
            out += raw[index + 8:index + 8 + size]
            index += 8 + size
        if index == 0:
            out = bytearray(raw)
        return out.decode("utf-8", errors="replace")

    # Images -----------------------------------------------------------------
    def build_image(self, context_tar_path: str, tag: str, dockerfile: str,
                    buildargs: Dict[str, str], timeout: float = 3600.0) -> Iterator[Dict[str, Any]]:
        """Build an image from a tar context, yielding the daemon's JSON progress messages."""
        # version=2 selects BuildKit, which the ARPVPN Dockerfile needs (COPY
        # --chmod) and which works with an uploaded tar context without a client
        # session. The classic builder is deprecated in current Docker releases.
        query = {
            "t": tag,
            "dockerfile": dockerfile,
            "buildargs": json.dumps(buildargs),
            "rm": "1",
            "pull": "1",
            "version": "2",
        }
        with open(context_tar_path, "rb") as handle:
            data = handle.read()
        conn, response = self._request("POST", "/build", query=query, body=data,
                                       headers={"Content-Type": "application/x-tar"}, timeout=timeout)
        try:
            if response.status != 200:
                raise DockerError(response.status, response.read().decode("utf-8", errors="replace"))
            buffer = b""
            while True:
                chunk = response.read1(65536) if hasattr(response, "read1") else response.read(65536)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except ValueError:
                            yield {"stream": line.decode("utf-8", errors="replace")}
            if buffer.strip():
                try:
                    yield json.loads(buffer)
                except ValueError:
                    yield {"stream": buffer.decode("utf-8", errors="replace")}
        finally:
            conn.close()
