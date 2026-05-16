#!/usr/bin/env python3
from __future__ import annotations

import atexit
from http import HTTPStatus
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - depends on runtime environment
    yaml = None


_OPENAPI_WORKDIR = ""


def _fake_network_helpers_if_needed():
    if shutil.which("ip") is not None:
        return
    from arpvpn.common.utils import network as network_utils

    fake_interfaces = {
        "lo": {
            "ifname": "lo",
            "flags": ["LOOPBACK", "UP", "LOWER_UP"],
            "operstate": "UNKNOWN",
            "address": "00:00:00:00:00:00",
            "addr_info": [],
        },
        "eth0": {
            "ifname": "eth0",
            "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "operstate": "UP",
            "address": "02:00:00:00:00:00",
            "addr_info": [],
        },
    }
    network_utils.get_system_interfaces = lambda: fake_interfaces
    network_utils.get_default_gateway = lambda: "eth0"
    network_utils.get_routing_table = lambda: [
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0"},
    ]


def _cleanup_openapi_workdir():
    if _OPENAPI_WORKDIR:
        shutil.rmtree(_OPENAPI_WORKDIR, ignore_errors=True)


def get_testing_app_instance():
    global _OPENAPI_WORKDIR
    if not _OPENAPI_WORKDIR:
        _OPENAPI_WORKDIR = tempfile.mkdtemp(prefix="arpvpn-openapi-")
        atexit.register(_cleanup_openapi_workdir)

    from arpvpn.common.properties import global_properties

    sys.argv = [sys.argv[0], _OPENAPI_WORKDIR]
    global_properties.setup_required = False
    global_properties.dev_env = True
    _fake_network_helpers_if_needed()

    from arpvpn.__main__ import app
    from arpvpn.core.config.wireguard import config as wireguard_config

    wireguard_config.wg_bin = "/bin/echo"
    wireguard_config.wg_quick_bin = "/bin/echo"
    wireguard_config.iptables_bin = "/bin/echo"
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["API_CSRF_ENABLED"] = False
    return app


def iter_live_api_operations() -> List[Dict[str, Any]]:
    app = get_testing_app_instance()
    operations: List[Dict[str, Any]] = []
    for rule in sorted(app.url_map.iter_rules(), key=lambda item: (item.rule, item.endpoint)):
        if not rule.rule.startswith("/api/v1"):
            continue
        methods = sorted(set(rule.methods) & {"GET", "POST", "PUT", "PATCH", "DELETE"})
        if not methods:
            continue
        for method in methods:
            operations.append(
                {
                    "path": rule.rule,
                    "openapi_path": re.sub(r"<([^>]+)>", r"{\1}", rule.rule),
                    "method": method.lower(),
                    "endpoint": str(rule.endpoint).rsplit(".", 1)[-1],
                    "path_params": re.findall(r"<([^>]+)>", rule.rule),
                }
            )
    return operations


def request_schema_components() -> Dict[str, Dict[str, Any]]:
    from arpvpn.web.api_schema import API_REQUEST_SCHEMAS

    components: Dict[str, Dict[str, Any]] = {}
    for endpoint, schema in sorted(API_REQUEST_SCHEMAS.items()):
        if not schema.fields:
            continue
        components[f"{endpoint}Request"] = schema.to_openapi_schema()
    return components


def request_schema_component_name(endpoint: str) -> str:
    return f"{endpoint}Request"


def load_request_schema(endpoint: str):
    from arpvpn.web.api_schema import get_api_request_schema

    return get_api_request_schema(endpoint)


_PUBLIC_ENDPOINTS = {
    "api_auth_modes",
    "api_auth_csrf",
    "api_auth_issue_token",
    "api_auth_refresh_token",
    "api_accept_invitation",
}


_TAG_OVERRIDES = {
    "auth": "Auth",
    "impersonation": "Auth",
    "tenants": "Tenants",
    "users": "Tenants",
    "invitations": "Tenants",
    "wireguard": "WireGuard",
    "stats": "Stats",
    "themes": "Themes",
    "tls": "TLS",
    "system": "System",
    "audit": "System",
    "config": "System",
    "profile": "System",
    "network": "System",
    "about": "System",
    "setup": "System",
}


_RESPONSE_STATUS_OVERRIDES = {
    "api_auth_issue_token": HTTPStatus.CREATED,
    "api_create_tenant": HTTPStatus.CREATED,
    "api_create_user": HTTPStatus.CREATED,
    "api_create_tenant_member": HTTPStatus.CREATED,
    "api_create_invitation": HTTPStatus.CREATED,
    "api_create_wireguard_interface": HTTPStatus.CREATED,
    "api_create_wireguard_peer": HTTPStatus.CREATED,
    "api_accept_invitation": HTTPStatus.CREATED,
    "api_system_restart": HTTPStatus.ACCEPTED,
}


_DOWNLOAD_ENDPOINT_SUFFIXES = ("/download", ".csv")


def guess_tag(path: str) -> str:
    parts = [item for item in path.split("/") if item]
    if len(parts) < 3:
        return "System"
    return _TAG_OVERRIDES.get(parts[2], "System")


def guess_summary(endpoint: str, path: str, method: str) -> str:
    base = endpoint
    if base.startswith("api_"):
        base = base[4:]
    base = base.replace("_", " ").strip()
    if base:
        base = base[0].upper() + base[1:]
    else:
        base = f"{method.upper()} {path}"
    return base


def response_status_code(endpoint: str, method: str) -> int:
    if endpoint in _RESPONSE_STATUS_OVERRIDES:
        return _RESPONSE_STATUS_OVERRIDES[endpoint]
    if method.lower() == "post" and endpoint.startswith("api_create_"):
        return 201
    return 200


def route_security(endpoint: str) -> List[Dict[str, List[str]]]:
    if endpoint in _PUBLIC_ENDPOINTS:
        return []
    return [{"bearerAuth": []}, {"cookieAuth": []}]


def is_download_endpoint(path: str) -> bool:
    return path.endswith(_DOWNLOAD_ENDPOINT_SUFFIXES)


def build_openapi_document(version: str) -> Dict[str, Any]:
    operations = iter_live_api_operations()
    request_components = request_schema_components()
    document: Dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": "ARPVPN API",
            "version": version,
            "description": "Generated OpenAPI document for the live ARPVPN API surface.",
        },
        "servers": [{"url": "/", "description": "ARPVPN application root"}],
        "tags": [{"name": tag} for tag in ["Auth", "Tenants", "WireGuard", "Stats", "Themes", "TLS", "System"]],
        "paths": {},
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "arpvpn_session"},
            },
            "schemas": {
                "ApiSuccessEnvelope": {
                    "type": "object",
                    "required": ["ok", "request_id", "generated_at", "data"],
                    "properties": {
                        "ok": {"type": "boolean", "example": True},
                        "request_id": {"type": "string", "example": "req-1234"},
                        "generated_at": {"type": "string", "format": "date-time"},
                        "data": {"type": "object", "additionalProperties": True},
                        "meta": {"type": "object", "additionalProperties": True},
                    },
                },
                "ApiErrorEnvelope": {
                    "type": "object",
                    "required": ["ok", "request_id", "error"],
                    "properties": {
                        "ok": {"type": "boolean", "example": False},
                        "request_id": {"type": "string", "example": "req-1234"},
                        "error": {
                            "type": "object",
                            "required": ["code", "message"],
                            "properties": {
                                "code": {"type": "string", "example": "bad_request"},
                                "message": {"type": "string", "example": "Invalid payload."},
                                "details": {"type": "object", "additionalProperties": True},
                            },
                        },
                    },
                },
                **request_components,
            },
        },
    }

    for item in operations:
        path_item = document["paths"].setdefault(item["openapi_path"], {})
        endpoint = item["endpoint"]
        method = item["method"]
        path = item["path"]
        operation: Dict[str, Any] = {
            "tags": [guess_tag(path)],
            "operationId": endpoint,
            "summary": guess_summary(endpoint, path, method),
            "responses": {},
        }
        security = route_security(endpoint)
        if security:
            operation["security"] = security
        if item["path_params"]:
            operation["parameters"] = [
                {
                    "in": "path",
                    "name": name,
                    "required": True,
                    "schema": {"type": "string"},
                }
                for name in item["path_params"]
            ]
        schema = load_request_schema(endpoint)
        if method in {"post", "put", "patch", "delete"} and schema and schema.fields:
            component_name = request_schema_component_name(endpoint)
            operation["requestBody"] = {
                "required": any(field.required for field in schema.fields.values()),
                "content": {
                    "application/json": {
                        "schema": {"$ref": f"#/components/schemas/{component_name}"},
                        "example": schema.example_payload(),
                    }
                },
            }
        status_code = str(response_status_code(endpoint, method))
        if is_download_endpoint(path):
            media_type = "text/csv" if path.endswith(".csv") else "text/plain"
            operation["responses"][status_code] = {
                "description": "Successful response.",
                "content": {media_type: {"schema": {"type": "string"}}},
            }
        else:
            operation["responses"][status_code] = {
                "description": "Successful response.",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/ApiSuccessEnvelope"}
                    }
                },
            }
        operation["responses"]["400"] = {
            "description": "Bad request.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiErrorEnvelope"}}},
        }
        operation["responses"]["401"] = {
            "description": "Unauthorized.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiErrorEnvelope"}}},
        }
        operation["responses"]["403"] = {
            "description": "Forbidden.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiErrorEnvelope"}}},
        }
        path_item[method] = operation
    return document


def dump_yaml(data: Dict[str, Any], path: Path):
    if yaml is None:
        raise RuntimeError("PyYAML is required to generate OpenAPI artifacts.")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=False)


def load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load OpenAPI artifacts.")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def snake_case(name: str) -> str:
    first = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", first).replace("-", "_").lower()
