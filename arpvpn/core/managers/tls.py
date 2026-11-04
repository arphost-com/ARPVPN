import os
import signal
import time
from logging import info, warning
from subprocess import PIPE, run  # nosec B404 - local certificate issuance requires subprocess
from threading import Thread
from typing import Dict, Any, Optional

import yaml

from arpvpn.common.properties import global_properties
from arpvpn.core.config.web import WebConfig


class TLSManager:
    UWSGI_FILENAME = "uwsgi.yaml"
    CERTS_DIRNAME = "certs"
    SELFSIGNED_CERT_FILENAME = "selfsigned.crt"
    SELFSIGNED_KEY_FILENAME = "selfsigned.key"

    @staticmethod
    def _run_checked(cmd: list[str], error_prefix: str):
        try:
            result = run(cmd, shell=False, check=False, stdout=PIPE, stderr=PIPE, text=True)  # nosec B603 B607 - fixed argv, shell disabled
        except FileNotFoundError as exc:
            raise RuntimeError(f"{error_prefix}: command not found ({cmd[0]}).") from exc
        if result.returncode != 0:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            detail = stderr or stdout or f"exit code {result.returncode}"
            raise RuntimeError(f"{error_prefix}: {detail}")

    @classmethod
    def _uwsgi_path(cls) -> str:
        return global_properties.join_workdir(cls.UWSGI_FILENAME)

    @classmethod
    def _load_uwsgi(cls) -> Dict[str, Any]:
        uwsgi_path = cls._uwsgi_path()
        if not os.path.exists(uwsgi_path):
            raise RuntimeError(f"Unable to apply TLS settings: {uwsgi_path} not found.")
        with open(uwsgi_path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if "uwsgi" not in data or not isinstance(data["uwsgi"], dict):
            raise RuntimeError(f"Unable to apply TLS settings: invalid uwsgi config file ({uwsgi_path}).")
        return data

    # uWSGI's HTTP/HTTPS router handles TLS, keep-alive and slow clients in its
    # own process and hands finished requests to the Python worker. The older
    # http-socket/https-socket mode made the worker do all of that itself, one
    # connection at a time, with a fresh TLS handshake for every request.
    LISTENER_KEYS = ("http", "https")
    LEGACY_LISTENER_KEYS = {"http-socket": "http", "https-socket": "https"}
    PERFORMANCE_SETTINGS = {
        "threads": 4,
        "offload-threads": 1,
        "http-keepalive": 1,
        # The router copies the response to the client one buffer at a time.
        # With the default 4 KB buffer most pages go out in several small
        # writes, and on a kept-alive connection each extra write can wait
        # about 40 ms for a delayed ACK.
        "http-buffer-size": 65536,
        "buffer-size": 32768,
    }

    @classmethod
    def _save_uwsgi(cls, data: Dict[str, Any]) -> bool:
        """Write uwsgi.yaml and return True when its content changed."""
        uwsgi_path = cls._uwsgi_path()
        previous: Dict[str, Any] = {}
        try:
            with open(uwsgi_path, "r", encoding="utf-8") as handle:
                previous = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError):
            previous = {}
        with open(uwsgi_path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(data, handle, sort_keys=False)
        return previous != data

    @classmethod
    def _apply_performance_settings(cls, uwsgi_settings: Dict[str, Any]):
        # Debian's uWSGI ships the router as a loadable plugin. Builds that have
        # it compiled in only print a warning for this.
        plugins = [item.strip() for item in str(uwsgi_settings.get("plugins") or "").split(",") if item.strip()]
        if "http" not in plugins:
            uwsgi_settings["plugins"] = ",".join(plugins + ["http"])
        for key, value in cls.PERFORMANCE_SETTINGS.items():
            current = uwsgi_settings.get(key)
            if key == "threads":
                try:
                    if int(current) >= value:
                        continue
                except (TypeError, ValueError):
                    pass
            if key in ("buffer-size", "http-buffer-size"):
                try:
                    if int(current) >= value:
                        continue
                except (TypeError, ValueError):
                    pass
            uwsgi_settings[key] = value

    @classmethod
    def _drop_legacy_listeners(cls, uwsgi_settings: Dict[str, Any]):
        for legacy_key in cls.LEGACY_LISTENER_KEYS:
            uwsgi_settings.pop(legacy_key, None)

    @staticmethod
    def _resolve_bind_host(_uwsgi_settings: Dict[str, Any], _web_config: WebConfig) -> str:
        # Always bind ARPVPN listeners on all interfaces for remote management.
        return "0.0.0.0"  # nosec B104 - intentional container/service bind address

    @classmethod
    def _ensure_bind_http_only(cls, uwsgi_settings: Dict[str, Any], web_config: WebConfig):
        bind_host = cls._resolve_bind_host(uwsgi_settings, web_config)
        cls._drop_legacy_listeners(uwsgi_settings)
        uwsgi_settings["http"] = f"{bind_host}:{web_config.http_port}"
        uwsgi_settings.pop("https", None)
        cls._apply_performance_settings(uwsgi_settings)

    @classmethod
    def _ensure_bind_http_and_https(
        cls,
        uwsgi_settings: Dict[str, Any],
        web_config: WebConfig,
        cert_file: str,
        key_file: str,
    ):
        bind_host = cls._resolve_bind_host(uwsgi_settings, web_config)
        cls._drop_legacy_listeners(uwsgi_settings)
        uwsgi_settings["http"] = f"{bind_host}:{web_config.http_port}"
        uwsgi_settings["https"] = f"{bind_host}:{web_config.https_port},{cert_file},{key_file}"
        cls._apply_performance_settings(uwsgi_settings)

    # ------------------------------------------------------------------
    # Startup migration of older uwsgi.yaml files
    # ------------------------------------------------------------------
    RELOAD_MARKER_FILENAME = ".listener-reload"
    RELOAD_LOOP_GUARD_SECONDS = 60
    RELOAD_DELAY_SECONDS = 2

    @staticmethod
    def _apply_env_ports(uwsgi_settings: Dict[str, Any]):
        """Keep the listener ports in line with ARPVPN_HTTP_PORT / ARPVPN_HTTPS_PORT."""
        from arpvpn.core.config.web import env_port

        for key, env_name in (("http", "ARPVPN_HTTP_PORT"), ("https", "ARPVPN_HTTPS_PORT")):
            value = uwsgi_settings.get(key)
            port = env_port(env_name)
            if not isinstance(value, str) or port is None:
                continue
            address, sep, rest = value.partition(",")
            host, colon, _old_port = address.rpartition(":")
            if not colon:
                continue
            uwsgi_settings[key] = f"{host}:{port}{sep}{rest}"

    PENDING_UWSGI_FILENAME = "uwsgi.router-pending.yaml"

    @classmethod
    def _pending_uwsgi_path(cls) -> str:
        return global_properties.join_workdir(cls.PENDING_UWSGI_FILENAME)

    @classmethod
    def migrate_uwsgi_config(cls) -> Optional[str]:
        """Move an older uwsgi.yaml to router mode, keeping its ports and certificates.

        Returns a reason string when uWSGI must reload for the change to take
        effect, otherwise None. Never raises, so startup is not affected.

        A running uWSGI hands its open listening sockets to the reloaded process,
        and the router cannot bind a port the old http-socket still holds. So
        the switch takes two reloads. The first runs with no public listener,
        which closes the old sockets, and the second binds the router. The
        final config waits in uwsgi.router-pending.yaml in between.
        """
        try:
            pending_path = cls._pending_uwsgi_path()
            if os.path.exists(pending_path):
                with open(pending_path, "r", encoding="utf-8") as handle:
                    pending = yaml.safe_load(handle) or {}
                os.remove(pending_path)
                if isinstance(pending.get("uwsgi"), dict):
                    cls._save_uwsgi(pending)
                    return "binding the HTTP router"
                return None

            data = cls._load_uwsgi()
            settings = data["uwsgi"]
            if not any(key in settings for key in cls.LEGACY_LISTENER_KEYS):
                if "http" in settings or "https" in settings:
                    cls._apply_performance_settings(settings)
                    cls._apply_env_ports(settings)
                    if cls._save_uwsgi(data):
                        return "applying web listener settings"
                return None

            for legacy_key, router_key in cls.LEGACY_LISTENER_KEYS.items():
                if legacy_key in settings:
                    settings.setdefault(router_key, settings.pop(legacy_key))
            cls._apply_performance_settings(settings)
            cls._apply_env_ports(settings)
            if cls._uwsgi_module() is None:
                # Not running under uWSGI, so nothing holds the sockets. The new
                # file is used as is on the next start.
                cls._save_uwsgi(data)
                return None

            with open(pending_path, "w", encoding="utf-8") as handle:
                yaml.safe_dump(data, handle, sort_keys=False)
            interim = {"uwsgi": {key: value for key, value in settings.items()
                                 if key not in cls.LISTENER_KEYS}}
            interim["uwsgi"]["socket"] = "127.0.0.1:0"
            cls._save_uwsgi(interim)
            return "releasing the old web listeners"
        except (RuntimeError, OSError, yaml.YAMLError, AttributeError) as exc:
            warning("Unable to update %s: %s", cls._uwsgi_path(), exc)
            return None

    @staticmethod
    def enable_listener_nodelay() -> int:
        """Turn on TCP_NODELAY for the router's listening sockets.

        The uWSGI HTTP/HTTPS router has no option for it, and without it the
        kernel holds back the last part of a response larger than one TLS
        record until the client ACKs, which adds up to 40 ms per page. Linux
        copies the flag from a listening socket to every connection accepted
        on it, and the master shares those sockets with the router processes,
        so setting it here once covers them. Returns how many sockets changed.
        """
        import socket as socket_module

        changed = 0
        try:
            fds = [int(name) for name in os.listdir("/proc/self/fd")]
        except OSError:
            return 0
        for fd in fds:
            try:
                sock = socket_module.socket(fileno=fd)
            except OSError:
                continue
            try:
                if sock.family not in (socket_module.AF_INET, socket_module.AF_INET6):
                    continue
                if sock.type != socket_module.SOCK_STREAM:
                    continue
                if not sock.getsockopt(socket_module.SOL_SOCKET, socket_module.SO_ACCEPTCONN):
                    continue
                host = sock.getsockname()[0]
                if host.startswith("127.") or host == "::1":
                    continue  # the internal router to worker socket
                sock.setsockopt(socket_module.IPPROTO_TCP, socket_module.TCP_NODELAY, 1)
                changed += 1
            except OSError:
                pass
            finally:
                sock.detach()
        return changed

    @staticmethod
    def _uwsgi_module():
        try:
            import uwsgi  # type: ignore  # noqa: F401  (only importable inside uWSGI)
            return uwsgi
        except ImportError:
            return None

    @classmethod
    def _reload_marker_path(cls) -> str:
        return global_properties.join_workdir(cls.RELOAD_MARKER_FILENAME)

    @classmethod
    def _recently_reloaded(cls) -> bool:
        try:
            age = time.time() - os.path.getmtime(cls._reload_marker_path())
        except OSError:
            return False
        return age < cls.RELOAD_LOOP_GUARD_SECONDS

    @classmethod
    def schedule_reload(cls, reason: str, ignore_loop_guard: bool = False) -> bool:
        """Ask the uWSGI master for one graceful reload so it re-reads uwsgi.yaml.

        Does nothing outside uWSGI (tests, dev server) and refuses to reload twice
        within RELOAD_LOOP_GUARD_SECONDS, so a bad config can never loop.
        """
        uwsgi = cls._uwsgi_module()
        if uwsgi is None:
            return False
        if not ignore_loop_guard and cls._recently_reloaded():
            warning("Skipping uWSGI reload (%s): one happened less than %ss ago.",
                    reason, cls.RELOAD_LOOP_GUARD_SECONDS)
            return False
        try:
            with open(cls._reload_marker_path(), "w", encoding="utf-8") as handle:
                handle.write(reason)
        except OSError:
            return False
        info("Reloading uWSGI: %s", reason)

        def _delayed_reload():
            # No logging in here: the reload tears the worker down, and a log
            # lock held by another thread at that moment can crash the process.
            time.sleep(cls.RELOAD_DELAY_SECONDS)
            try:
                master_pid = int(uwsgi.masterpid() or 0)
                if master_pid > 0:
                    os.kill(master_pid, signal.SIGHUP)
                else:
                    uwsgi.reload()
            except Exception:  # pragma: no cover - depends on uWSGI runtime  # nosec B110
                pass

        def _start():
            Thread(target=_delayed_reload, daemon=True).start()

        try:
            in_worker = int(uwsgi.worker_id() or 0) > 0
        except Exception:
            in_worker = False
        if in_worker:
            _start()
            return True
        # The app is imported in the master before workers fork, and threads
        # started there do not survive the fork, so fire from the first worker.
        previous_hook = getattr(uwsgi, "post_fork_hook", None)
        fired = []

        def _post_fork_hook():
            if callable(previous_hook):
                previous_hook()
            if not fired:
                fired.append(True)
                _start()

        uwsgi.post_fork_hook = _post_fork_hook
        return True

    @classmethod
    def _selfsigned_paths(cls) -> tuple[str, str]:
        certs_dir = global_properties.join_workdir(cls.CERTS_DIRNAME)
        return (
            os.path.join(certs_dir, cls.SELFSIGNED_CERT_FILENAME),
            os.path.join(certs_dir, cls.SELFSIGNED_KEY_FILENAME),
        )

    @classmethod
    def generate_self_signed(cls, server_name: str) -> tuple[str, str]:
        cert_file, key_file = cls._selfsigned_paths()
        os.makedirs(os.path.dirname(cert_file), exist_ok=True)
        # Try to include SAN. If the OpenSSL version does not support -addext,
        # retry without it so generation still works.
        cmd = [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-days",
            "825",
            "-keyout",
            key_file,
            "-out",
            cert_file,
            "-subj",
            f"/CN={server_name}",
            "-addext",
            f"subjectAltName=DNS:{server_name}",
        ]
        try:
            result = run(cmd, shell=False, check=False, stdout=PIPE, stderr=PIPE, text=True)  # nosec B603 B607 - fixed argv, shell disabled
        except FileNotFoundError as exc:
            raise RuntimeError("Unable to generate self-signed certificate: command not found (openssl).") from exc
        if result.returncode != 0:
            fallback_cmd = cmd[:-2]
            cls._run_checked(fallback_cmd, "Unable to generate self-signed certificate")
        info(f"Generated self-signed certificate for {server_name} at {cert_file}")
        return cert_file, key_file

    @classmethod
    def issue_letsencrypt(cls, server_name: str, email: str = "") -> tuple[str, str]:
        cmd = [
            "sudo",
            "-n",
            "certbot",
            "certonly",
            "--standalone",
            "--non-interactive",
            "--agree-tos",
            "--keep-until-expiring",
            "-d",
            server_name,
        ]
        if email:
            cmd.extend(["--email", email])
        else:
            cmd.append("--register-unsafely-without-email")
        cls._run_checked(cmd, "Unable to issue Let's Encrypt certificate")

        cert_file = f"/etc/letsencrypt/live/{server_name}/fullchain.pem"
        key_file = f"/etc/letsencrypt/live/{server_name}/privkey.pem"
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            raise RuntimeError("Let's Encrypt certificate was issued but expected files were not found.")
        return cert_file, key_file

    @staticmethod
    def default_letsencrypt_paths(server_name: str) -> tuple[str, str]:
        return (
            f"/etc/letsencrypt/live/{server_name}/fullchain.pem",
            f"/etc/letsencrypt/live/{server_name}/privkey.pem",
        )

    @classmethod
    def apply_web_tls_config(
        cls,
        web_config,
        generate_self_signed: bool = False,
        issue_letsencrypt: bool = False,
    ):
        mode = web_config.tls_mode or WebConfig.TLS_MODE_HTTP
        uwsgi_path = cls._uwsgi_path()
        if not os.path.exists(uwsgi_path):
            if mode in (WebConfig.TLS_MODE_HTTP, WebConfig.TLS_MODE_REVERSE_PROXY):
                return
            raise RuntimeError(f"Unable to apply TLS settings: {uwsgi_path} not found.")
        config_data = cls._load_uwsgi()
        uwsgi_settings = config_data["uwsgi"]

        if mode == WebConfig.TLS_MODE_HTTP or mode == WebConfig.TLS_MODE_REVERSE_PROXY:
            cls._ensure_bind_http_only(uwsgi_settings, web_config)
            cls._save_uwsgi(config_data)
            return

        if mode == WebConfig.TLS_MODE_SELF_SIGNED:
            if generate_self_signed or not web_config.tls_cert_file or not web_config.tls_key_file:
                cert_file, key_file = cls.generate_self_signed(web_config.tls_server_name)
                web_config.tls_cert_file = cert_file
                web_config.tls_key_file = key_file
            cert_file = web_config.tls_cert_file
            key_file = web_config.tls_key_file
        else:
            if issue_letsencrypt:
                cert_file, key_file = cls.issue_letsencrypt(
                    web_config.tls_server_name,
                    web_config.tls_letsencrypt_email,
                )
                web_config.tls_cert_file = cert_file
                web_config.tls_key_file = key_file
            cert_file = web_config.tls_cert_file
            key_file = web_config.tls_key_file
            if not cert_file or not key_file:
                cert_file, key_file = cls.default_letsencrypt_paths(web_config.tls_server_name)
                web_config.tls_cert_file = cert_file
                web_config.tls_key_file = key_file

        if not cert_file or not key_file:
            raise RuntimeError("TLS mode requires certificate and key paths.")
        if not os.path.exists(cert_file):
            raise RuntimeError(f"Certificate file not found: {cert_file}")
        if not os.path.exists(key_file):
            raise RuntimeError(f"Private key file not found: {key_file}")

        cls._ensure_bind_http_and_https(uwsgi_settings, web_config, cert_file, key_file)
        cls._save_uwsgi(config_data)


tls_manager = TLSManager()
