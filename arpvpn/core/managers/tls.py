import os
from logging import info
from subprocess import PIPE, run
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
            result = run(cmd, shell=False, check=False, stdout=PIPE, stderr=PIPE, text=True)
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

    @classmethod
    def _save_uwsgi(cls, data: Dict[str, Any]):
        with open(cls._uwsgi_path(), "w", encoding="utf-8") as handle:
            yaml.safe_dump(data, handle, sort_keys=False)

    @staticmethod
    def _extract_bind(socket_value: Optional[str], default_port: int) -> str:
        if socket_value and isinstance(socket_value, str):
            bind = socket_value.split(",", 1)[0].strip()
            if bind:
                return bind
        return f"0.0.0.0:{default_port}"

    @staticmethod
    def _split_bind(bind: str) -> tuple[str, str]:
        value = (bind or "").strip()
        if not value:
            return "0.0.0.0", ""
        if value.startswith("["):
            index = value.rfind("]:")
            if index > -1:
                return value[:index + 1], value[index + 2:]
            return value, ""
        if ":" not in value:
            return value, ""
        host, port = value.rsplit(":", 1)
        return host or "0.0.0.0", port

    @classmethod
    def _resolve_bind_host(cls, uwsgi_settings: Dict[str, Any], web_config: WebConfig) -> str:
        http_bind = cls._extract_bind(uwsgi_settings.get("http-socket"), web_config.http_port)
        https_bind = cls._extract_bind(uwsgi_settings.get("https-socket"), web_config.https_port)
        http_host, _ = cls._split_bind(http_bind)
        if http_host:
            return http_host
        https_host, _ = cls._split_bind(https_bind)
        if https_host:
            return https_host
        return "0.0.0.0"

    @classmethod
    def _ensure_bind_http_only(cls, uwsgi_settings: Dict[str, Any], web_config: WebConfig):
        bind_host = cls._resolve_bind_host(uwsgi_settings, web_config)
        uwsgi_settings["http-socket"] = f"{bind_host}:{web_config.http_port}"
        uwsgi_settings.pop("https-socket", None)

    @classmethod
    def _ensure_bind_http_and_https(
        cls,
        uwsgi_settings: Dict[str, Any],
        web_config: WebConfig,
        cert_file: str,
        key_file: str,
    ):
        bind_host = cls._resolve_bind_host(uwsgi_settings, web_config)
        uwsgi_settings["http-socket"] = f"{bind_host}:{web_config.http_port}"
        uwsgi_settings["https-socket"] = f"{bind_host}:{web_config.https_port},{cert_file},{key_file}"

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
            result = run(cmd, shell=False, check=False, stdout=PIPE, stderr=PIPE, text=True)
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
