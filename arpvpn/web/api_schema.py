from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


class ApiSchemaValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ApiFieldSchema:
    kind: str
    required: bool = False
    nullable: bool = False
    enum: Tuple[Any, ...] = ()
    properties: Dict[str, "ApiFieldSchema"] = field(default_factory=dict)
    items: Optional["ApiFieldSchema"] = None
    additional_properties: bool = False
    min_items: Optional[int] = None
    description: str = ""
    example: Any = None

    def validate(self, value: Any, path: str):
        if value is None:
            if self.nullable:
                return
            raise ApiSchemaValidationError(f"{path} cannot be null.")

        if self.kind == "string":
            if not isinstance(value, str):
                raise ApiSchemaValidationError(f"{path} must be a string.")
        elif self.kind == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ApiSchemaValidationError(f"{path} must be an integer.")
        elif self.kind == "boolean":
            if not isinstance(value, bool):
                raise ApiSchemaValidationError(f"{path} must be a boolean.")
        elif self.kind == "object":
            self._validate_object(value, path)
        elif self.kind == "array":
            self._validate_array(value, path)
        elif self.kind == "string_list":
            self._validate_string_list(value, path)
        else:
            raise ApiSchemaValidationError(f"Unsupported schema kind '{self.kind}' for {path}.")

        if self.enum and value not in self.enum:
            allowed = ", ".join(str(item) for item in self.enum)
            raise ApiSchemaValidationError(f"{path} must be one of: {allowed}.")

    def _validate_object(self, value: Any, path: str):
        if not isinstance(value, dict):
            raise ApiSchemaValidationError(f"{path} must be an object.")
        for name, schema in self.properties.items():
            if schema.required and name not in value:
                raise ApiSchemaValidationError(f"{path}.{name} is required.")
        if not self.additional_properties:
            unknown = sorted(set(value.keys()) - set(self.properties.keys()))
            if unknown:
                raise ApiSchemaValidationError(
                    f"{path} contains unsupported field(s): {', '.join(unknown)}."
                )
        for name, item in value.items():
            child_schema = self.properties.get(name)
            if child_schema is None:
                continue
            child_schema.validate(item, f"{path}.{name}")

    def _validate_array(self, value: Any, path: str):
        if not isinstance(value, list):
            raise ApiSchemaValidationError(f"{path} must be an array.")
        if self.min_items is not None and len(value) < self.min_items:
            raise ApiSchemaValidationError(f"{path} must contain at least {self.min_items} item(s).")
        if self.items is None:
            return
        for index, item in enumerate(value):
            self.items.validate(item, f"{path}[{index}]")

    def _validate_string_list(self, value: Any, path: str):
        if isinstance(value, str):
            return
        if not isinstance(value, list):
            raise ApiSchemaValidationError(f"{path} must be a string or array of strings.")
        for index, item in enumerate(value):
            if not isinstance(item, str):
                raise ApiSchemaValidationError(f"{path}[{index}] must be a string.")

    def to_openapi_schema(self) -> Dict[str, Any]:
        schema: Dict[str, Any]
        if self.kind == "string":
            schema = {"type": "string"}
        elif self.kind == "integer":
            schema = {"type": "integer"}
        elif self.kind == "boolean":
            schema = {"type": "boolean"}
        elif self.kind == "object":
            schema = {
                "type": "object",
                "properties": {
                    key: child.to_openapi_schema()
                    for key, child in self.properties.items()
                },
                "additionalProperties": self.additional_properties,
            }
            required = [key for key, child in self.properties.items() if child.required]
            if required:
                schema["required"] = required
        elif self.kind == "array":
            schema = {"type": "array"}
            if self.items is not None:
                schema["items"] = self.items.to_openapi_schema()
            if self.min_items is not None:
                schema["minItems"] = self.min_items
        elif self.kind == "string_list":
            schema = {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}},
                ]
            }
        else:
            schema = {"type": "object"}
        if self.enum:
            schema["enum"] = list(self.enum)
        if self.nullable:
            schema["nullable"] = True
        if self.description:
            schema["description"] = self.description
        example_value = self.example_payload()
        if example_value is not None:
            schema["example"] = example_value
        return schema

    def example_payload(self) -> Any:
        if self.example is not None:
            return self.example
        if self.kind == "string":
            return "example"
        if self.kind == "integer":
            return 1
        if self.kind == "boolean":
            return False
        if self.kind == "object":
            sample: Dict[str, Any] = {}
            for name, child in self.properties.items():
                child_sample = child.example_payload()
                if child.required or child_sample is not None:
                    sample[name] = child_sample
            return sample
        if self.kind == "array":
            if self.items is None:
                return []
            item_sample = self.items.example_payload()
            return [item_sample] if item_sample is not None else []
        if self.kind == "string_list":
            return ["example"]
        return None


@dataclass(frozen=True)
class ApiRequestSchema:
    fields: Dict[str, ApiFieldSchema] = field(default_factory=dict)
    allow_additional: bool = False
    description: str = ""

    def validate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise ApiSchemaValidationError("Payload must be an object.")
        for name, schema in self.fields.items():
            if schema.required and name not in payload:
                raise ApiSchemaValidationError(f"{name} is required.")
        if not self.allow_additional:
            unknown = sorted(set(payload.keys()) - set(self.fields.keys()))
            if unknown:
                raise ApiSchemaValidationError(
                    f"Payload contains unsupported field(s): {', '.join(unknown)}."
                )
        for name, value in payload.items():
            field_schema = self.fields.get(name)
            if field_schema is None:
                continue
            field_schema.validate(value, name)
        return payload

    def to_openapi_schema(self) -> Dict[str, Any]:
        schema = {
            "type": "object",
            "properties": {
                name: field_schema.to_openapi_schema()
                for name, field_schema in self.fields.items()
            },
            "additionalProperties": self.allow_additional,
        }
        required = [name for name, field_schema in self.fields.items() if field_schema.required]
        if required:
            schema["required"] = required
        if self.description:
            schema["description"] = self.description
        example_value = self.example_payload()
        if example_value:
            schema["example"] = example_value
        return schema

    def example_payload(self) -> Dict[str, Any]:
        sample: Dict[str, Any] = {}
        for name, field_schema in self.fields.items():
            value = field_schema.example_payload()
            if field_schema.required or value is not None:
                sample[name] = value
        return sample


def string_field(*, required: bool = False, nullable: bool = False, enum: Iterable[Any] = (), example: Any = None, description: str = "") -> ApiFieldSchema:
    return ApiFieldSchema("string", required=required, nullable=nullable, enum=tuple(enum), example=example, description=description)


def integer_field(*, required: bool = False, nullable: bool = False, example: Any = None, description: str = "") -> ApiFieldSchema:
    return ApiFieldSchema("integer", required=required, nullable=nullable, example=example, description=description)


def boolean_field(*, required: bool = False, nullable: bool = False, example: Any = None, description: str = "") -> ApiFieldSchema:
    return ApiFieldSchema("boolean", required=required, nullable=nullable, example=example, description=description)


def object_field(*, required: bool = False, nullable: bool = False, properties: Optional[Dict[str, ApiFieldSchema]] = None, additional_properties: bool = False, example: Any = None, description: str = "") -> ApiFieldSchema:
    return ApiFieldSchema(
        "object",
        required=required,
        nullable=nullable,
        properties=properties or {},
        additional_properties=additional_properties,
        example=example,
        description=description,
    )


def array_field(*, items: Optional[ApiFieldSchema] = None, required: bool = False, min_items: Optional[int] = None, example: Any = None, description: str = "") -> ApiFieldSchema:
    return ApiFieldSchema("array", required=required, items=items, min_items=min_items, example=example, description=description)


def string_list_field(*, required: bool = False, description: str = "") -> ApiFieldSchema:
    return ApiFieldSchema("string_list", required=required, description=description)


def empty_schema(description: str = "") -> ApiRequestSchema:
    return ApiRequestSchema(fields={}, allow_additional=False, description=description)


ROLE_ENUM = ("client", "tenant_admin", "admin", "support")
TENANT_STATUS_ENUM = ("active", "suspended", "disabled")
TLS_MODE_ENUM = ("http", "self_signed", "letsencrypt", "reverse_proxy")
MESH_PRESET_ENUM = ("point_to_point", "hub_spoke", "full_mesh")
MESH_LINK_STATUS_ENUM = ("pending", "active", "degraded", "error", "disabled")
MESH_SOURCE_KIND_ENUM = ("peer", "group", "server", "all")
MESH_ACTION_ENUM = ("allow", "deny")
THEME_ENUM = ("auto", "light", "dark")

TENANT_TLS_FIELD = object_field(
    properties={
        "mode": string_field(enum=TLS_MODE_ENUM, example="self_signed"),
        "server_name": string_field(example="tenant.example.com"),
        "letsencrypt_email": string_field(example="admin@example.com"),
        "redirect_http_to_https": boolean_field(example=True),
        "proxy_incoming_hostname": string_field(example="tenant.example.com"),
    }
)

TENANT_RUNTIME_FIELD = object_field(
    properties={
        "allocated": boolean_field(example=True),
        "enabled": boolean_field(example=True),
        "status": string_field(example="planned"),
        "desired_state": string_field(enum=("running", "stopped", "restarting"), example="stopped"),
        "container_name": string_field(example="arpvpn-tenant-one"),
        "compose_project_name": string_field(example="tenant_one"),
        "image_tag": string_field(example="latest"),
        "notes": string_field(example="Dedicated stack for Tenant One"),
        "http_port": integer_field(example=18085),
        "https_port": integer_field(example=18086),
        "vpn_port": integer_field(example=51820),
    }
)

TENANT_SETTINGS_FIELD = object_field(
    properties={
        "branding": object_field(additional_properties=True, example={"company_name": "Tenant One"}),
        "limits": object_field(additional_properties=True, example={"max_clients": 25}),
        "defaults": object_field(additional_properties=True, example={"theme": "dark"}),
        "dns_servers": string_list_field(),
        "tls": TENANT_TLS_FIELD,
        "runtime": TENANT_RUNTIME_FIELD,
    }
)

GLOBAL_CONFIG_FIELD = object_field(
    properties={
        "logger": object_field(
            properties={
                "level": string_field(example="info"),
                "overwrite": boolean_field(example=False),
                "logfile": string_field(example="/data/log/arpvpn.log"),
            }
        ),
        "web": object_field(
            properties={
                "login_attempts": integer_field(example=5),
                "login_ban_time": integer_field(example=300),
                "tls_mode": string_field(enum=TLS_MODE_ENUM, example="http"),
                "tls_server_name": string_field(example="vpn.example.com"),
                "tls_letsencrypt_email": string_field(example="admin@example.com"),
                "proxy_incoming_hostname": string_field(example="vpn.example.com"),
                "redirect_http_to_https": boolean_field(example=False),
                "http_port": integer_field(example=8085),
                "https_port": integer_field(example=8086),
            }
        ),
        "wireguard": object_field(
            properties={
                "endpoint": string_field(example="vpn.example.com"),
                "wg_bin": string_field(example="/usr/bin/wg"),
                "wg_quick_bin": string_field(example="/usr/bin/wg-quick"),
                "iptables_bin": string_field(example="/usr/sbin/iptables"),
                "interfaces_folder": string_field(example="/data/interfaces"),
            }
        ),
        "traffic": object_field(
            properties={
                "enabled": boolean_field(example=True),
                "driver": string_field(example="json"),
                "driver_options": object_field(additional_properties=True, example={"filepath": "/data/traffic.json"}),
            }
        ),
    }
)

INTERFACE_PAYLOAD_FIELD = object_field(
    properties={
        "name": string_field(required=True, example="wg0"),
        "description": string_field(example="Primary interface"),
        "gateway": string_field(required=True, example="eth0"),
        "ipv4": string_field(required=True, example="10.10.0.1/24"),
        "listen_port": integer_field(example=51820),
        "port": integer_field(example=51820),
        "auto": boolean_field(example=True),
        "on_up": string_list_field(),
        "on_down": string_list_field(),
        "tenant_id": string_field(example="tenant-123"),
        "async": boolean_field(example=False),
    }
)

PEER_PAYLOAD_FIELD = object_field(
    properties={
        "interface_uuid": string_field(required=True, example="iface-123"),
        "interface": string_field(example="wg0"),
        "name": string_field(required=True, example="client-1"),
        "description": string_field(example="Client peer"),
        "ipv4": string_field(required=True, example="10.10.0.2/32"),
        "nat": boolean_field(example=True),
        "dns1": string_field(example="8.8.8.8"),
        "dns2": string_field(example="1.1.1.1"),
        "mode": string_field(enum=("client", "site_to_site"), example="client"),
        "full_tunnel": boolean_field(example=False),
        "site_to_site_subnets": string_list_field(),
        "enabled": boolean_field(example=True),
        "owner_user_id": string_field(example="user-123"),
        "owner_username": string_field(example="client1"),
        "username": string_field(example="client1"),
        "tenant_id": string_field(example="tenant-123"),
        "async": boolean_field(example=False),
    }
)

TOPOLOGY_FIELD = object_field(
    properties={
        "uuid": string_field(example="topology-123"),
        "name": string_field(required=True, example="core-mesh"),
        "preset": string_field(enum=MESH_PRESET_ENUM, example="full_mesh"),
        "server_ids": string_list_field(required=True),
        "hub_server_id": string_field(example="edge-a"),
        "description": string_field(example="Primary site mesh"),
    }
)

LINK_FIELD = object_field(
    properties={
        "uuid": string_field(example="link-123"),
        "source_server": string_field(required=True, example="edge-a"),
        "target_server": string_field(required=True, example="edge-b"),
        "interface_uuid": string_field(example="iface-123"),
        "status": string_field(enum=MESH_LINK_STATUS_ENUM, example="active"),
        "key_metadata": object_field(additional_properties=True, example={"local_public_key": "pub-key"}),
        "topology_uuid": string_field(example="topology-123"),
        "description": string_field(example="A to B"),
        "enabled": boolean_field(example=True),
    }
)

ROUTE_FIELD = object_field(
    properties={
        "uuid": string_field(example="route-123"),
        "owner_server": string_field(required=True, example="edge-a"),
        "cidr": string_field(required=True, example="10.55.0.0/24"),
        "via_link_uuid": string_field(example="link-123"),
        "description": string_field(example="Branch LAN"),
        "enabled": boolean_field(example=True),
    }
)

POLICY_FIELD = object_field(
    properties={
        "uuid": string_field(example="policy-123"),
        "name": string_field(required=True, example="allow-branch-lan"),
        "source_kind": string_field(enum=MESH_SOURCE_KIND_ENUM, example="server"),
        "source_id": string_field(example="edge-a"),
        "destinations": string_list_field(required=True),
        "action": string_field(enum=MESH_ACTION_ENUM, example="allow"),
        "priority": integer_field(example=100),
        "description": string_field(example="Allow branch traffic"),
        "enabled": boolean_field(example=True),
    }
)

MESH_PAYLOAD_FIELD = object_field(
    additional_properties=True,
    properties={
        "topologies": array_field(items=TOPOLOGY_FIELD, example=[TOPOLOGY_FIELD.example_payload()]),
        "vpn_links": array_field(items=LINK_FIELD, example=[LINK_FIELD.example_payload()]),
        "route_advertisements": array_field(items=ROUTE_FIELD, example=[ROUTE_FIELD.example_payload()]),
        "access_policies": array_field(items=POLICY_FIELD, example=[POLICY_FIELD.example_payload()]),
    }
)

API_REQUEST_SCHEMAS: Dict[str, ApiRequestSchema] = {
    "api_auth_issue_token": ApiRequestSchema(fields={
        "username": string_field(required=True, example="admin"),
        "password": string_field(required=True, example="change-me"),
        "scope": string_field(example="staff"),
        "mfa_code": string_field(example="123456"),
    }),
    "api_auth_refresh_token": ApiRequestSchema(fields={
        "refresh_token": string_field(required=True, example="refresh-token"),
    }),
    "api_auth_revoke_token": ApiRequestSchema(fields={
        "token": string_field(example="access-token"),
    }),
    "api_auth_revoke_all_tokens": ApiRequestSchema(fields={
        "user_id": string_field(example="user-123"),
    }),
    "api_auth_force_logout": empty_schema(),
    "api_start_impersonation": empty_schema(),
    "api_stop_impersonation": empty_schema(),
    "api_create_tenant": ApiRequestSchema(fields={
        "name": string_field(required=True, example="Tenant One"),
        "slug": string_field(example="tenant-one"),
        "domains": string_list_field(),
        "ips": string_list_field(),
        "status": string_field(enum=TENANT_STATUS_ENUM, example="active"),
        "description": string_field(example="Managed customer"),
        "settings": TENANT_SETTINGS_FIELD,
    }),
    "api_update_tenant": ApiRequestSchema(fields={
        "name": string_field(example="Tenant One"),
        "slug": string_field(example="tenant-one"),
        "domains": string_list_field(),
        "ips": string_list_field(),
        "status": string_field(enum=TENANT_STATUS_ENUM, example="active"),
        "description": string_field(example="Managed customer"),
        "settings": TENANT_SETTINGS_FIELD,
    }),
    "api_delete_tenant": empty_schema(),
    "api_import_users": ApiRequestSchema(fields={
        "users": array_field(items=object_field(properties={
            "username": string_field(required=True, example="client1"),
            "password": string_field(required=True, example="change-me"),
            "role": string_field(enum=ROLE_ENUM, example="client"),
            "tenant_id": string_field(example="tenant-123"),
        }), min_items=1),
        "items": array_field(items=object_field(properties={
            "username": string_field(required=True, example="client1"),
            "password": string_field(required=True, example="change-me"),
            "role": string_field(enum=ROLE_ENUM, example="client"),
            "tenant_id": string_field(example="tenant-123"),
        }), min_items=1),
        "dry_run": boolean_field(example=False),
        "continue_on_error": boolean_field(example=False),
    }),
    "api_create_user": ApiRequestSchema(fields={
        "username": string_field(required=True, example="client1"),
        "password": string_field(required=True, example="change-me"),
        "role": string_field(enum=ROLE_ENUM, example="client"),
        "tenant_id": string_field(example="tenant-123"),
    }),
    "api_update_user": ApiRequestSchema(fields={
        "username": string_field(example="client1"),
        "password": string_field(example="change-me"),
        "role": string_field(enum=ROLE_ENUM, example="client"),
        "tenant_id": string_field(example="tenant-123"),
    }),
    "api_delete_user": empty_schema(),
    "api_create_tenant_member": ApiRequestSchema(fields={
        "username": string_field(required=True, example="client1"),
        "password": string_field(required=True, example="change-me"),
        "role": string_field(enum=ROLE_ENUM, example="client"),
    }),
    "api_create_invitation": ApiRequestSchema(fields={
        "email": string_field(required=True, example="client@example.com"),
        "role": string_field(enum=ROLE_ENUM, example="client"),
        "tenant_id": string_field(example="tenant-123"),
        "expires_in_hours": integer_field(example=72),
    }),
    "api_resend_invitation": ApiRequestSchema(fields={
        "expires_in_hours": integer_field(example=72),
    }),
    "api_revoke_invitation": empty_schema(),
    "api_accept_invitation": ApiRequestSchema(fields={
        "token": string_field(required=True, example="invite-token"),
        "username": string_field(required=True, example="client1"),
        "password": string_field(required=True, example="change-me"),
        "confirm": string_field(required=True, example="change-me"),
    }),
    "api_create_wireguard_interface": ApiRequestSchema(fields=INTERFACE_PAYLOAD_FIELD.properties),
    "api_update_wireguard_interface": ApiRequestSchema(fields={
        **INTERFACE_PAYLOAD_FIELD.properties,
        "name": string_field(example="wg0"),
        "gateway": string_field(example="eth0"),
        "ipv4": string_field(example="10.10.0.1/24"),
    }),
    "api_delete_wireguard_interface": ApiRequestSchema(fields={
        "async": boolean_field(example=False),
    }),
    "api_operate_wireguard_interface": ApiRequestSchema(fields={
        "async": boolean_field(example=False),
    }),
    "api_create_wireguard_peer": ApiRequestSchema(fields=PEER_PAYLOAD_FIELD.properties),
    "api_update_wireguard_peer": ApiRequestSchema(fields={
        **PEER_PAYLOAD_FIELD.properties,
        "interface_uuid": string_field(example="iface-123"),
        "name": string_field(example="client-1"),
        "ipv4": string_field(example="10.10.0.2/32"),
    }),
    "api_delete_wireguard_peer": ApiRequestSchema(fields={
        "async": boolean_field(example=False),
    }),
    "api_mesh_create_topology": ApiRequestSchema(fields=TOPOLOGY_FIELD.properties),
    "api_mesh_update_topology": ApiRequestSchema(fields={
        **TOPOLOGY_FIELD.properties,
        "name": string_field(example="core-mesh"),
        "server_ids": string_list_field(),
    }),
    "api_mesh_delete_topology": empty_schema(),
    "api_mesh_create_link": ApiRequestSchema(fields=LINK_FIELD.properties),
    "api_mesh_update_link": ApiRequestSchema(fields=LINK_FIELD.properties),
    "api_mesh_delete_link": empty_schema(),
    "api_mesh_create_route": ApiRequestSchema(fields=ROUTE_FIELD.properties),
    "api_mesh_update_route": ApiRequestSchema(fields=ROUTE_FIELD.properties),
    "api_mesh_delete_route": empty_schema(),
    "api_mesh_create_policy": ApiRequestSchema(fields=POLICY_FIELD.properties),
    "api_mesh_update_policy": ApiRequestSchema(fields=POLICY_FIELD.properties),
    "api_mesh_delete_policy": empty_schema(),
    "api_mesh_dry_run": ApiRequestSchema(fields={
        "mesh": MESH_PAYLOAD_FIELD,
    }),
    "api_mesh_import": ApiRequestSchema(fields={
        "mesh": object_field(required=True, properties=MESH_PAYLOAD_FIELD.properties, additional_properties=True),
        "allow_conflicts": boolean_field(example=False),
    }),
    "api_mesh_policy_simulate": ApiRequestSchema(fields={
        "source_kind": string_field(required=True, enum=MESH_SOURCE_KIND_ENUM, example="server"),
        "source_id": string_field(required=True, example="edge-a"),
        "destination": string_field(required=True, example="10.55.0.10"),
    }),
    "api_system_restore": ApiRequestSchema(fields={
        "backup": object_field(required=True, additional_properties=True, example={"format": "arpvpn-backup-v1", "files": {}}),
        "dry_run": boolean_field(example=True),
    }),
    "api_update_global_config": ApiRequestSchema(fields=GLOBAL_CONFIG_FIELD.properties),
    "api_update_tenant_config": ApiRequestSchema(fields={
        "settings": TENANT_SETTINGS_FIELD,
        "branding": object_field(additional_properties=True, example={"company_name": "Tenant One"}),
        "limits": object_field(additional_properties=True, example={"max_clients": 25}),
        "defaults": object_field(additional_properties=True, example={"theme": "dark"}),
        "dns_servers": string_list_field(),
        "tls": TENANT_TLS_FIELD,
        "runtime": TENANT_RUNTIME_FIELD,
    }),
    "api_update_tenant_tls_status": ApiRequestSchema(fields={
        "tls": TENANT_TLS_FIELD,
        "mode": string_field(enum=TLS_MODE_ENUM, example="self_signed"),
        "server_name": string_field(example="tenant.example.com"),
        "letsencrypt_email": string_field(example="admin@example.com"),
        "redirect_http_to_https": boolean_field(example=True),
        "proxy_incoming_hostname": string_field(example="tenant.example.com"),
    }),
    "api_update_tenant_runtime": ApiRequestSchema(fields={
        "runtime": TENANT_RUNTIME_FIELD,
        **TENANT_RUNTIME_FIELD.properties,
    }),
    "api_allocate_tenant_runtime": empty_schema(),
    "api_control_tenant_runtime": empty_schema(),
    "api_set_theme_choice": ApiRequestSchema(fields={
        "choice": string_field(required=True, enum=THEME_ENUM, example="dark"),
    }),
    "api_tls_mode_update": ApiRequestSchema(fields={
        "mode": string_field(required=True, enum=TLS_MODE_ENUM, example="http"),
        "server_name": string_field(example="vpn.example.com"),
        "letsencrypt_email": string_field(example="admin@example.com"),
        "proxy_incoming_hostname": string_field(example="vpn.example.com"),
        "redirect_http_to_https": boolean_field(example=False),
    }),
    "api_tls_generate_self_signed": ApiRequestSchema(fields={
        "server_name": string_field(required=True, example="vpn.example.com"),
        "regenerate": boolean_field(example=True),
        "redirect_http_to_https": boolean_field(example=True),
    }),
    "api_tls_issue_letsencrypt": ApiRequestSchema(fields={
        "server_name": string_field(required=True, example="vpn.example.com"),
        "email": string_field(example="admin@example.com"),
        "issue_now": boolean_field(example=True),
        "redirect_http_to_https": boolean_field(example=True),
    }),
    "api_system_restart": ApiRequestSchema(fields={
        "reason": string_field(example="Apply updated settings"),
        "mode": string_field(example="auto"),
        "delay_seconds": integer_field(example=1),
    }),
    "api_setup_bootstrap": ApiRequestSchema(fields={
        "log_overwrite": boolean_field(example=False),
        "traffic_enabled": boolean_field(example=True),
        "wireguard": object_field(required=True, properties={
            "endpoint": string_field(required=True, example="vpn.example.com"),
            "wg_bin": string_field(required=True, example="/usr/bin/wg"),
            "wg_quick_bin": string_field(required=True, example="/usr/bin/wg-quick"),
            "iptables_bin": string_field(required=True, example="/usr/sbin/iptables"),
        }),
        "tls": object_field(required=True, properties={
            "mode": string_field(required=True, enum=TLS_MODE_ENUM, example="self_signed"),
            "server_name": string_field(example="vpn.example.com"),
            "letsencrypt_email": string_field(example="admin@example.com"),
            "proxy_incoming_hostname": string_field(example="vpn.example.com"),
            "redirect_http_to_https": boolean_field(example=False),
            "generate_self_signed": boolean_field(example=True),
            "issue_letsencrypt": boolean_field(example=False),
        }),
    }),
    "api_profile_update": ApiRequestSchema(fields={
        "username": string_field(required=True, example="admin"),
    }),
    "api_profile_password_update": ApiRequestSchema(fields={
        "old_password": string_field(required=True, example="old-password"),
        "new_password": string_field(required=True, example="new-password"),
        "confirm": string_field(required=True, example="new-password"),
    }),
}


def get_api_request_schema(endpoint_name: str) -> Optional[ApiRequestSchema]:
    return API_REQUEST_SCHEMAS.get(endpoint_name)
