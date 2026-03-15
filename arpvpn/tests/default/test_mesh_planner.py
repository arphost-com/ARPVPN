from arpvpn.core.mesh import AccessPolicy, MeshControlPlane, MeshTopology, RouteAdvertisement, VPNLink
from arpvpn.core.mesh_planner import build_expected_links_for_topology, build_mesh_plan, evaluate_access_policy


def test_full_mesh_planner_generates_deterministic_pairs_and_allowed_ips():
    mesh = MeshControlPlane()
    topology = MeshTopology(
        name="core",
        preset=MeshTopology.PRESET_FULL_MESH,
        server_ids=["edge-a", "edge-b", "edge-c"],
    )
    mesh.topologies[topology.uuid] = topology
    route = RouteAdvertisement(owner_server="edge-b", cidr="10.55.0.0/24")
    mesh.route_advertisements[route.uuid] = route
    existing_link = VPNLink(source_server="edge-a", target_server="edge-b", topology_uuid=topology.uuid)
    mesh.vpn_links[existing_link.uuid] = existing_link

    plan = build_mesh_plan(mesh)

    assert plan["counts"]["planned_pairs"] == 3
    pair_keys = [item["pair_key"] for item in plan["planned_pairs"]]
    assert pair_keys == ["edge-a__edge-b", "edge-a__edge-c", "edge-b__edge-c"]
    edge_a_to_b = next(item for item in plan["planned_pairs"] if item["pair_key"] == "edge-a__edge-b")
    assert existing_link.uuid in edge_a_to_b["existing_link_ids"]
    peer_plan = next(item for item in edge_a_to_b["peer_plans"] if item["local_server"] == "edge-a")
    assert peer_plan["allowed_ips"] == ["10.55.0.0/24"]


def test_hub_spoke_expected_link_generation_uses_hub_server():
    topology = MeshTopology(
        name="hq",
        preset=MeshTopology.PRESET_HUB_SPOKE,
        server_ids=["hq", "branch-1", "branch-2"],
        hub_server_id="hq",
    )
    assert build_expected_links_for_topology(topology) == [("hq", "branch-1"), ("hq", "branch-2")]


def test_policy_simulation_returns_first_matching_policy():
    mesh = MeshControlPlane()
    deny_policy = AccessPolicy(
        name="deny-db",
        source_kind=AccessPolicy.SOURCE_SERVER,
        source_id="edge-a",
        destinations=["10.20.30.0/24"],
        action=AccessPolicy.ACTION_DENY,
        priority=10,
    )
    allow_policy = AccessPolicy(
        name="allow-any",
        source_kind=AccessPolicy.SOURCE_ALL,
        source_id="*",
        destinations=["0.0.0.0/0"],
        action=AccessPolicy.ACTION_ALLOW,
        priority=100,
    )
    mesh.access_policies[deny_policy.uuid] = deny_policy
    mesh.access_policies[allow_policy.uuid] = allow_policy

    result = evaluate_access_policy(mesh, source_kind="server", source_id="edge-a", destination="10.20.30.5")

    assert result["matched"] is True
    assert result["action"] == "deny"
    assert result["policy"]["name"] == "deny-db"
