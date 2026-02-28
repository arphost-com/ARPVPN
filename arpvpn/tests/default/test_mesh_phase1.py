from arpvpn.core.config.wireguard import WireguardConfig
from arpvpn.core.mesh import (
    AccessPolicy,
    MeshControlPlane,
    MeshTopology,
    RouteAdvertisement,
    VPNLink,
)


def test_mesh_topology_hub_spoke_sets_valid_hub():
    topology = MeshTopology(
        name="hq-mesh",
        preset=MeshTopology.PRESET_HUB_SPOKE,
        server_ids="hq-1, branch-1, branch-2",
        hub_server_id="unknown-hub",
    )

    assert topology.server_ids == ["hq-1", "branch-1", "branch-2"]
    assert topology.hub_server_id == "hq-1"


def test_vpn_link_sanitizes_server_ids_and_key_metadata():
    link = VPNLink(
        source_server="  HQ Primary ",
        target_server="Branch A",
        key_metadata={
            "local_public_key": "pub-local",
            "remote_public_key": "pub-remote",
            "ignored_key": "ignored",
        },
    )

    assert link.source_server == "hq-primary"
    assert link.target_server == "branch-a"
    assert link.key_metadata == {
        "local_public_key": "pub-local",
        "remote_public_key": "pub-remote",
    }


def test_route_advertisement_normalizes_cidr():
    route = RouteAdvertisement(owner_server="edge-a", cidr="10.10.5.4/16")
    assert route.owner_server == "edge-a"
    assert route.cidr == "10.10.0.0/16"


def test_access_policy_normalizes_destinations_and_priority():
    policy = AccessPolicy(
        name="allow-db",
        source_kind=AccessPolicy.SOURCE_GROUP,
        source_id="ops",
        destinations="10.0.0.20/24,10.0.0.0/24,172.16.10.0/24",
        action=AccessPolicy.ACTION_DENY,
        priority="-3",
    )

    assert policy.source_kind == AccessPolicy.SOURCE_GROUP
    assert policy.source_id == "ops"
    assert policy.destinations == ["10.0.0.0/24", "172.16.10.0/24"]
    assert policy.action == AccessPolicy.ACTION_DENY
    assert policy.priority == AccessPolicy.DEFAULT_PRIORITY


def test_mesh_route_conflict_detection_duplicate_and_overlap():
    mesh = MeshControlPlane()

    route_a = RouteAdvertisement(owner_server="srv-a", cidr="10.0.0.0/24")
    route_b = RouteAdvertisement(owner_server="srv-b", cidr="10.0.0.0/24")
    route_c = RouteAdvertisement(owner_server="srv-c", cidr="10.0.0.128/25")
    mesh.route_advertisements[route_a.uuid] = route_a
    mesh.route_advertisements[route_b.uuid] = route_b
    mesh.route_advertisements[route_c.uuid] = route_c
    mesh.route_advertisements.sort()

    conflicts = mesh.validate_route_advertisements()

    assert len(conflicts["duplicate_ownership"]) == 1
    assert conflicts["duplicate_ownership"][0]["cidr"] == "10.0.0.0/24"
    assert conflicts["duplicate_ownership"][0]["owner_servers"] == ["srv-a", "srv-b"]
    assert len(conflicts["overlapping_cidrs"]) >= 1
    assert mesh.has_route_conflicts() is True


def test_wireguard_config_includes_mesh_control_plane():
    config = WireguardConfig()
    route = RouteAdvertisement(owner_server="srv-a", cidr="192.168.50.0/24")
    config.mesh.route_advertisements[route.uuid] = route
    config.mesh.route_advertisements.sort()

    payload = config.__to_yaml_dict__()
    assert "mesh" in payload

    restored = WireguardConfig.__from_yaml_dict__(payload)
    assert len(restored.mesh.route_advertisements) == 1
    restored_route = next(iter(restored.mesh.route_advertisements.values()))
    assert restored_route.owner_server == "srv-a"
    assert restored_route.cidr == "192.168.50.0/24"
