import os
import shutil
import sqlite3
from os.path import dirname, join

import pytest

from arpvpn.common.models.user import User, users
from arpvpn.common.properties import global_properties
from arpvpn.core.managers.config import config_manager
from arpvpn.core.managers.tenancy import tenancy_manager
from arpvpn.tests.utils import default_cleanup


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()
    config_manager.load_defaults()


def table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def extract_sample_secret(sample_filepath: str) -> str:
    with open(sample_filepath, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped.startswith("secret_key:"):
                continue
            return stripped.split(":", 1)[1].strip()
    raise RuntimeError("Unable to find secret_key in sample configuration file.")


def test_tenancy_schema_is_created_on_config_load():
    workdir = join(dirname(__file__), "data")
    global_properties.workdir = workdir

    config_manager.load()

    assert os.path.exists(tenancy_manager.db_path)
    with sqlite3.connect(tenancy_manager.db_path) as connection:
        for table in (
            "mt_schema_migrations",
            "mt_tenants",
            "mt_users",
            "mt_memberships",
            "mt_invites",
            "mt_vpn_instances",
            "mt_vpn_clients",
            "mt_tenant_domains",
            "mt_tenant_certificates",
            "mt_impersonation_audit",
        ):
            assert table_exists(connection, table), table


def test_tenancy_phase1_bootstrap_imports_legacy_data():
    workdir = join(dirname(__file__), "data")
    os.makedirs(workdir, exist_ok=True)
    global_properties.workdir = workdir

    sample_config = join(dirname(dirname(dirname(dirname(__file__)))), "config", "arpvpn.sample.yaml")
    shutil.copy(sample_config, join(workdir, "arpvpn.yaml"))
    secret = extract_sample_secret(sample_config)

    users.clear()
    admin_user = User("admin", role=User.ROLE_ADMIN)
    admin_user.password = "admin"
    users[admin_user.id] = admin_user

    support_user = User("support", role=User.ROLE_SUPPORT)
    support_user.password = "support"
    users[support_user.id] = support_user

    client_user = User("jim halpert", role=User.ROLE_CLIENT)
    client_user.password = "client"
    users[client_user.id] = client_user

    users.save(join(workdir, ".credentials"), secret)
    users.clear()

    config_manager.load()

    with sqlite3.connect(tenancy_manager.db_path) as connection:
        default_tenant = connection.execute(
            "SELECT id FROM mt_tenants WHERE slug = 'default' LIMIT 1"
        ).fetchone()
        assert default_tenant is not None
        default_tenant_id = default_tenant[0]

        total_users = connection.execute("SELECT COUNT(*) FROM mt_users").fetchone()[0]
        assert total_users == 3

        global_roles = {
            row[0]
            for row in connection.execute(
                "SELECT role FROM mt_memberships WHERE tenant_id IS NULL"
            ).fetchall()
        }
        tenant_roles = {
            row[0]
            for row in connection.execute(
                "SELECT role FROM mt_memberships WHERE tenant_id = ?",
                (default_tenant_id,),
            ).fetchall()
        }
        assert "super_admin" in global_roles
        assert "support_admin" in global_roles
        assert "tenant_admin" in tenant_roles
        assert "client" in tenant_roles

        total_instances = connection.execute(
            "SELECT COUNT(*) FROM mt_vpn_instances WHERE tenant_id = ?",
            (default_tenant_id,),
        ).fetchone()[0]
        total_clients = connection.execute(
            "SELECT COUNT(*) FROM mt_vpn_clients WHERE tenant_id = ?",
            (default_tenant_id,),
        ).fetchone()[0]
        assert total_instances == 1
        assert total_clients == 1

        migration_count = connection.execute(
            "SELECT COUNT(*) FROM mt_schema_migrations WHERE name = ?",
            (tenancy_manager.PHASE1_MIGRATION_NAME,),
        ).fetchone()[0]
        assert migration_count == 1


def test_tenancy_initialize_skips_without_workdir():
    global_properties.workdir = ""
    tenancy_manager.initialize(legacy_users={}, legacy_interfaces={})
