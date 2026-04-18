import ipaddress
import json
import os
import sqlite3
from datetime import datetime, timezone
from logging import debug, info, warning
from typing import Any, Mapping
from uuid import uuid4 as gen_uuid

from arpvpn.common.properties import global_properties
from arpvpn.common.utils.system import try_makedir


class TenancyManager:
    DB_FILENAME = ".tenancy.sqlite3"
    PHASE1_MIGRATION_NAME = "phase1_bootstrap_v1"
    DEFAULT_TENANT_ID = "tenant-default"
    DEFAULT_TENANT_SLUG = "default"
    DEFAULT_TENANT_NAME = "Default Tenant"

    @property
    def db_path(self) -> str:
        return global_properties.join_workdir(self.DB_FILENAME)

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _create_schema(connection: sqlite3.Connection):
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS mt_schema_migrations (
                name TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mt_tenants (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('active', 'disabled', 'archived')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mt_users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                legacy_role TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mt_memberships (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                tenant_id TEXT,
                role TEXT NOT NULL CHECK(role IN ('super_admin', 'support_admin', 'tenant_admin', 'client')),
                status TEXT NOT NULL CHECK(status IN ('active', 'suspended', 'invited')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES mt_users(id) ON DELETE CASCADE,
                FOREIGN KEY(tenant_id) REFERENCES mt_tenants(id) ON DELETE CASCADE,
                CHECK(
                    (
                        role IN ('super_admin', 'support_admin')
                        AND tenant_id IS NULL
                    )
                    OR
                    (
                        role IN ('tenant_admin', 'client')
                        AND tenant_id IS NOT NULL
                    )
                )
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mt_memberships_unique_tenant
                ON mt_memberships(user_id, tenant_id, role)
                WHERE tenant_id IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_mt_memberships_unique_global
                ON mt_memberships(user_id, role)
                WHERE tenant_id IS NULL;

            CREATE TABLE IF NOT EXISTS mt_invites (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('tenant_admin', 'client')),
                token_hash TEXT NOT NULL,
                invited_by_user_id TEXT,
                expires_at TEXT NOT NULL,
                accepted_at TEXT,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(tenant_id) REFERENCES mt_tenants(id) ON DELETE CASCADE,
                FOREIGN KEY(invited_by_user_id) REFERENCES mt_users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mt_invites_tenant ON mt_invites(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_mt_invites_email ON mt_invites(email);

            CREATE TABLE IF NOT EXISTS mt_vpn_instances (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                name TEXT NOT NULL,
                container_name TEXT,
                runtime_type TEXT NOT NULL CHECK(runtime_type IN ('container', 'legacy_host')),
                status TEXT NOT NULL CHECK(status IN ('provisioning', 'running', 'stopped', 'error', 'legacy_imported')),
                host_ip TEXT,
                host_udp_port INTEGER,
                endpoint_domain TEXT,
                data_path TEXT,
                source_interface_uuid TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(tenant_id) REFERENCES mt_tenants(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_mt_vpn_instances_tenant ON mt_vpn_instances(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_mt_vpn_instances_port ON mt_vpn_instances(host_udp_port);

            CREATE TABLE IF NOT EXISTS mt_vpn_clients (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                vpn_instance_id TEXT,
                user_id TEXT,
                display_name TEXT NOT NULL,
                source_peer_uuid TEXT,
                status TEXT NOT NULL CHECK(status IN ('active', 'disabled', 'pending_invite', 'revoked')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(tenant_id) REFERENCES mt_tenants(id) ON DELETE CASCADE,
                FOREIGN KEY(vpn_instance_id) REFERENCES mt_vpn_instances(id) ON DELETE SET NULL,
                FOREIGN KEY(user_id) REFERENCES mt_users(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mt_vpn_clients_tenant ON mt_vpn_clients(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_mt_vpn_clients_instance ON mt_vpn_clients(vpn_instance_id);

            CREATE TABLE IF NOT EXISTS mt_tenant_domains (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                domain TEXT NOT NULL UNIQUE,
                dedicated_ip TEXT,
                verification_status TEXT NOT NULL CHECK(verification_status IN ('pending', 'verified', 'failed')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(tenant_id) REFERENCES mt_tenants(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_mt_tenant_domains_tenant ON mt_tenant_domains(tenant_id);

            CREATE TABLE IF NOT EXISTS mt_tenant_certificates (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                scope TEXT NOT NULL CHECK(scope IN ('global', 'tenant')),
                mode TEXT NOT NULL CHECK(mode IN ('letsencrypt', 'custom', 'self_signed', 'inherited')),
                common_name TEXT,
                issuer TEXT,
                not_before TEXT,
                not_after TEXT,
                renew_after TEXT,
                status TEXT NOT NULL CHECK(status IN ('pending', 'valid', 'expiring', 'expired', 'error')),
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(tenant_id) REFERENCES mt_tenants(id) ON DELETE CASCADE,
                CHECK(
                    (
                        scope = 'global'
                        AND tenant_id IS NULL
                    )
                    OR
                    (
                        scope = 'tenant'
                        AND tenant_id IS NOT NULL
                    )
                )
            );
            CREATE INDEX IF NOT EXISTS idx_mt_tenant_certificates_tenant ON mt_tenant_certificates(tenant_id);

            CREATE TABLE IF NOT EXISTS mt_impersonation_audit (
                id TEXT PRIMARY KEY,
                actor_user_id TEXT NOT NULL,
                target_user_id TEXT NOT NULL,
                tenant_id TEXT,
                actor_role TEXT NOT NULL,
                reason TEXT,
                source_ip TEXT,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                status TEXT NOT NULL CHECK(status IN ('active', 'ended', 'terminated')),
                FOREIGN KEY(actor_user_id) REFERENCES mt_users(id) ON DELETE RESTRICT,
                FOREIGN KEY(target_user_id) REFERENCES mt_users(id) ON DELETE RESTRICT,
                FOREIGN KEY(tenant_id) REFERENCES mt_tenants(id) ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mt_impersonation_actor ON mt_impersonation_audit(actor_user_id, started_at);
            CREATE INDEX IF NOT EXISTS idx_mt_impersonation_target ON mt_impersonation_audit(target_user_id, started_at);
            """
        )

    @staticmethod
    def _migration_is_applied(connection: sqlite3.Connection, name: str) -> bool:
        row = connection.execute(
            "SELECT 1 FROM mt_schema_migrations WHERE name = ? LIMIT 1",
            (name,),
        ).fetchone()
        return row is not None

    def _mark_migration(self, connection: sqlite3.Connection, name: str):
        connection.execute(
            """
            INSERT INTO mt_schema_migrations(name, applied_at)
            VALUES(?, ?)
            ON CONFLICT(name) DO NOTHING
            """,
            (name, self._utc_now()),
        )

    def _ensure_default_tenant(self, connection: sqlite3.Connection) -> str:
        now = self._utc_now()
        connection.execute(
            """
            INSERT INTO mt_tenants(id, slug, name, status, created_at, updated_at)
            VALUES(?, ?, ?, 'active', ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                slug = excluded.slug,
                name = excluded.name,
                status = excluded.status,
                updated_at = excluded.updated_at
            """,
            (
                self.DEFAULT_TENANT_ID,
                self.DEFAULT_TENANT_SLUG,
                self.DEFAULT_TENANT_NAME,
                now,
                now,
            ),
        )
        return self.DEFAULT_TENANT_ID

    def _upsert_global_certificate_config(self, connection: sqlite3.Connection, web_config: Any):
        tls_mode = (getattr(web_config, "tls_mode", "") or "").strip().lower()
        mode_map = {
            "self_signed": "self_signed",
            "letsencrypt": "letsencrypt",
            "reverse_proxy": "inherited",
            "http": "inherited",
        }
        mode = mode_map.get(tls_mode, "inherited")
        cert_file = (getattr(web_config, "tls_cert_file", "") or "").strip()
        key_file = (getattr(web_config, "tls_key_file", "") or "").strip()
        status = "valid" if cert_file and key_file else "pending"
        common_name = (
            (getattr(web_config, "tls_server_name", "") or "").strip()
            or (getattr(web_config, "proxy_incoming_hostname", "") or "").strip()
            or None
        )
        metadata = {
            "tls_mode": tls_mode,
            "tls_letsencrypt_email": (getattr(web_config, "tls_letsencrypt_email", "") or "").strip(),
            "tls_cert_file": cert_file,
            "tls_key_file": key_file,
        }
        now = self._utc_now()
        connection.execute(
            """
            INSERT INTO mt_tenant_certificates(
                id, tenant_id, scope, mode, common_name, issuer, not_before, not_after, renew_after,
                status, metadata_json, created_at, updated_at
            )
            VALUES(
                'global-certificate-policy', NULL, 'global', ?, ?, NULL, NULL, NULL, NULL, ?, ?, ?, ?
            )
            ON CONFLICT(id) DO UPDATE SET
                scope = excluded.scope,
                mode = excluded.mode,
                common_name = excluded.common_name,
                status = excluded.status,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            """,
            (
                mode,
                common_name,
                status,
                json.dumps(metadata, sort_keys=True),
                now,
                now,
            ),
        )

    def _bootstrap_phase1(
        self,
        connection: sqlite3.Connection,
        legacy_users: Mapping[str, Any],
        legacy_interfaces: Mapping[str, Any],
        web_config: Any = None,
        wireguard_config: Any = None,
    ):
        if self._migration_is_applied(connection, self.PHASE1_MIGRATION_NAME):
            debug("Phase 1 bootstrap already applied; skipping.")
            return

        default_tenant_id = self._ensure_default_tenant(connection)
        username_to_user_id = {}
        now = self._utc_now()

        for user in legacy_users.values():
            user_id = getattr(user, "id", None)
            username = (getattr(user, "name", "") or "").strip()
            password_hash = (getattr(user, "password", "") or "").strip()
            legacy_role = (getattr(user, "role", "") or "").strip().lower()

            if not user_id or not username or not password_hash:
                continue

            connection.execute(
                """
                INSERT INTO mt_users(id, username, password_hash, legacy_role, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    username = excluded.username,
                    password_hash = excluded.password_hash,
                    legacy_role = excluded.legacy_role,
                    updated_at = excluded.updated_at
                """,
                (user_id, username, password_hash, legacy_role, now, now),
            )
            username_to_user_id[username.lower()] = user_id

            memberships = []
            if legacy_role == "admin":
                memberships.append(("super_admin", None))
                memberships.append(("tenant_admin", default_tenant_id))
            elif legacy_role == "support":
                memberships.append(("support_admin", None))
            else:
                memberships.append(("client", default_tenant_id))

            for role, tenant_id in memberships:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO mt_memberships(
                        id, user_id, tenant_id, role, status, created_at, updated_at
                    )
                    VALUES(?, ?, ?, ?, 'active', ?, ?)
                    """,
                    (gen_uuid().hex, user_id, tenant_id, role, now, now),
                )

        endpoint = ""
        if wireguard_config is not None:
            endpoint = (getattr(wireguard_config, "endpoint", "") or "").strip()
        if endpoint and not self._is_ipv4(endpoint):
            connection.execute(
                """
                INSERT OR IGNORE INTO mt_tenant_domains(
                    id, tenant_id, domain, dedicated_ip, verification_status, created_at, updated_at
                )
                VALUES(?, ?, ?, NULL, 'verified', ?, ?)
                """,
                (gen_uuid().hex, default_tenant_id, endpoint, now, now),
            )

        if web_config is not None:
            self._upsert_global_certificate_config(connection, web_config)

        interfaces_folder = ""
        if wireguard_config is not None:
            interfaces_folder = (getattr(wireguard_config, "interfaces_folder", "") or "").strip()
        imported_instances = 0
        imported_clients = 0
        for interface in legacy_interfaces.values():
            interface_id = getattr(interface, "uuid", None)
            if not interface_id:
                continue

            iface_name = (getattr(interface, "name", "") or "").strip() or interface_id
            interface_data_path = interfaces_folder
            conf_file = (getattr(interface, "conf_file", "") or "").strip()
            if conf_file:
                interface_data_path = os.path.dirname(conf_file) or interfaces_folder

            connection.execute(
                """
                INSERT INTO mt_vpn_instances(
                    id, tenant_id, name, container_name, runtime_type, status, host_ip, host_udp_port,
                    endpoint_domain, data_path, source_interface_uuid, created_at, updated_at
                )
                VALUES(?, ?, ?, ?, 'legacy_host', 'legacy_imported', NULL, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    name = excluded.name,
                    container_name = excluded.container_name,
                    runtime_type = excluded.runtime_type,
                    status = excluded.status,
                    host_udp_port = excluded.host_udp_port,
                    endpoint_domain = excluded.endpoint_domain,
                    data_path = excluded.data_path,
                    source_interface_uuid = excluded.source_interface_uuid,
                    updated_at = excluded.updated_at
                """,
                (
                    interface_id,
                    default_tenant_id,
                    iface_name,
                    f"legacy-{iface_name}",
                    int(getattr(interface, "listen_port", 0) or 0) or None,
                    endpoint or None,
                    interface_data_path or None,
                    interface_id,
                    now,
                    now,
                ),
            )
            imported_instances += 1

            for peer in getattr(interface, "peers", {}).values():
                peer_id = getattr(peer, "uuid", None)
                peer_name = (getattr(peer, "name", "") or "").strip()
                if not peer_id or not peer_name:
                    continue
                user_id = username_to_user_id.get(peer_name.lower())
                connection.execute(
                    """
                    INSERT INTO mt_vpn_clients(
                        id, tenant_id, vpn_instance_id, user_id, display_name, source_peer_uuid, status,
                        created_at, updated_at
                    )
                    VALUES(?, ?, ?, ?, ?, ?, 'active', ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        tenant_id = excluded.tenant_id,
                        vpn_instance_id = excluded.vpn_instance_id,
                        user_id = excluded.user_id,
                        display_name = excluded.display_name,
                        source_peer_uuid = excluded.source_peer_uuid,
                        status = excluded.status,
                        updated_at = excluded.updated_at
                    """,
                    (peer_id, default_tenant_id, interface_id, user_id, peer_name, peer_id, now, now),
                )
                imported_clients += 1

        self._mark_migration(connection, self.PHASE1_MIGRATION_NAME)
        info(
            f"Phase 1 tenancy bootstrap completed: "
            f"users={len(legacy_users)}, vpn_instances={imported_instances}, vpn_clients={imported_clients}"
        )

    def initialize(
        self,
        legacy_users: Mapping[str, Any],
        legacy_interfaces: Mapping[str, Any],
        web_config: Any = None,
        wireguard_config: Any = None,
    ):
        if not global_properties.workdir:
            warning("Tenancy store initialization skipped: workdir is not configured yet.")
            return
        try_makedir(os.path.dirname(self.db_path))
        with self._connect() as connection:
            self._create_schema(connection)
            self._bootstrap_phase1(
                connection=connection,
                legacy_users=legacy_users,
                legacy_interfaces=legacy_interfaces,
                web_config=web_config,
                wireguard_config=wireguard_config,
            )
            connection.commit()


tenancy_manager = TenancyManager()
