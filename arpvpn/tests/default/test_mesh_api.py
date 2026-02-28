import pytest

from arpvpn.common.models.user import User, users
from arpvpn.tests.utils import default_cleanup, get_testing_app, is_http_success


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


@pytest.fixture
def client():
    with get_testing_app().test_client() as client:
        yield client


def create_user(name: str, password: str, role: str) -> User:
    user = User(name, role=role)
    user.password = password
    users[user.id] = user
    return user


def login(client, username: str, password: str):
    response = client.post(
        "/login",
        data={"username": username, "password": password, "remember_me": False},
        follow_redirects=True,
    )
    assert is_http_success(response.status_code)


def test_mesh_api_crud_dry_run_export_import(client):
    create_user("admin", "admin", User.ROLE_ADMIN)
    login(client, "admin", "admin")

    topology_response = client.post(
        "/api/v1/mesh/topologies",
        json={
            "name": "core-mesh",
            "preset": "full_mesh",
            "server_ids": ["edge-a", "edge-b", "edge-c"],
            "description": "main mesh",
        },
    )
    assert topology_response.status_code == 201
    topology_body = topology_response.get_json()
    assert topology_body["ok"] is True
    topology_uuid = topology_body["data"]["uuid"]

    link_response = client.post(
        "/api/v1/mesh/links",
        json={
            "source_server": "edge-a",
            "target_server": "edge-b",
            "topology_uuid": topology_uuid,
            "status": "active",
            "enabled": True,
        },
    )
    assert link_response.status_code == 201
    link_body = link_response.get_json()
    assert link_body["ok"] is True
    link_uuid = link_body["data"]["uuid"]

    route_response = client.post(
        "/api/v1/mesh/routes",
        json={
            "owner_server": "edge-a",
            "cidr": "10.55.0.0/24",
            "via_link_uuid": link_uuid,
            "enabled": True,
        },
    )
    assert route_response.status_code == 201
    route_body = route_response.get_json()
    assert route_body["ok"] is True
    route_uuid = route_body["data"]["uuid"]

    policy_response = client.post(
        "/api/v1/mesh/policies",
        json={
            "name": "allow-edge-a",
            "source_kind": "server",
            "source_id": "edge-a",
            "destinations": ["10.55.0.0/24"],
            "action": "allow",
            "priority": 100,
        },
    )
    assert policy_response.status_code == 201
    policy_body = policy_response.get_json()
    assert policy_body["ok"] is True
    policy_uuid = policy_body["data"]["uuid"]

    overview = client.get("/api/v1/mesh/overview")
    assert is_http_success(overview.status_code)
    overview_body = overview.get_json()
    assert overview_body["ok"] is True
    counts = overview_body["data"]["counts"]
    assert counts["topologies"] == 1
    assert counts["vpn_links"] == 1
    assert counts["route_advertisements"] == 1
    assert counts["access_policies"] == 1

    exported = client.get("/api/v1/mesh/export")
    assert is_http_success(exported.status_code)
    export_body = exported.get_json()
    assert export_body["ok"] is True

    dry_run = client.post("/api/v1/mesh/dry-run", json={"mesh": export_body["data"]["mesh"]})
    assert is_http_success(dry_run.status_code)
    dry_run_body = dry_run.get_json()
    assert dry_run_body["ok"] is True
    assert dry_run_body["data"]["valid"] is True

    imported = client.post(
        "/api/v1/mesh/import",
        json={"mesh": export_body["data"]["mesh"], "allow_conflicts": False},
    )
    assert is_http_success(imported.status_code)
    import_body = imported.get_json()
    assert import_body["ok"] is True
    assert import_body["data"]["imported"] is True

    delete_policy = client.delete(f"/api/v1/mesh/policies/{policy_uuid}")
    assert is_http_success(delete_policy.status_code)

    delete_route = client.delete(f"/api/v1/mesh/routes/{route_uuid}")
    assert is_http_success(delete_route.status_code)

    delete_link = client.delete(f"/api/v1/mesh/links/{link_uuid}")
    assert is_http_success(delete_link.status_code)

    delete_topology = client.delete(f"/api/v1/mesh/topologies/{topology_uuid}")
    assert is_http_success(delete_topology.status_code)


def test_mesh_endpoints_forbidden_for_client_role(client):
    create_user("client01", "clientpass", User.ROLE_CLIENT)
    login(client, "client01", "clientpass")

    list_response = client.get("/api/v1/mesh/topologies")
    assert list_response.status_code == 403

    create_response = client.post(
        "/api/v1/mesh/topologies",
        json={"name": "client-topology", "preset": "point_to_point", "server_ids": ["a", "b"]},
    )
    assert create_response.status_code == 403
