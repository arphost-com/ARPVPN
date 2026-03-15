from __future__ import annotations

import ipaddress
from itertools import combinations
from typing import Any, Dict, Iterable, List, Optional, Tuple

from arpvpn.core.mesh import AccessPolicy, MeshControlPlane, MeshTopology, RouteAdvertisement, VPNLink, normalize_server_id


def pair_key(server_a: str, server_b: str) -> str:
    left, right = sorted((normalize_server_id(server_a), normalize_server_id(server_b)))
    return f"{left}__{right}"


def build_expected_links_for_topology(topology: MeshTopology) -> List[Tuple[str, str]]:
    servers = list(topology.server_ids)
    if len(servers) < 2:
        return []
    if topology.preset == MeshTopology.PRESET_FULL_MESH:
        return [(left, right) for left, right in combinations(servers, 2)]
    if topology.preset == MeshTopology.PRESET_HUB_SPOKE:
        hub = topology.hub_server_id or servers[0]
        return [(hub, server_id) for server_id in servers if server_id != hub]
    if len(servers) == 2:
        return [(servers[0], servers[1])]
    return [(servers[index], servers[index + 1]) for index in range(0, len(servers) - 1)]


def _routes_by_owner(mesh: MeshControlPlane) -> Dict[str, List[str]]:
    routes: Dict[str, List[str]] = {}
    for route in mesh.route_advertisements.values():
        if not route.enabled:
            continue
        owner = normalize_server_id(route.owner_server)
        routes.setdefault(owner, [])
        if route.cidr not in routes[owner]:
            routes[owner].append(route.cidr)
    for cidrs in routes.values():
        cidrs.sort()
    return routes


def _existing_links_by_pair(mesh: MeshControlPlane) -> Dict[str, List[VPNLink]]:
    pairs: Dict[str, List[VPNLink]] = {}
    for link in mesh.vpn_links.values():
        pairs.setdefault(pair_key(link.source_server, link.target_server), []).append(link)
    for items in pairs.values():
        items.sort(key=lambda item: (item.topology_uuid, item.uuid))
    return pairs


def build_mesh_plan(mesh: MeshControlPlane) -> Dict[str, Any]:
    routes_by_owner = _routes_by_owner(mesh)
    links_by_pair = _existing_links_by_pair(mesh)
    planned_pairs: List[Dict[str, Any]] = []
    used_link_ids = set()

    for topology in mesh.topologies.values():
        expected_pairs = build_expected_links_for_topology(topology)
        for source_server, target_server in expected_pairs:
            key = pair_key(source_server, target_server)
            existing_links = [
                item for item in links_by_pair.get(key, [])
                if not topology.uuid or item.topology_uuid in ("", topology.uuid)
            ]
            for link in existing_links:
                used_link_ids.add(link.uuid)
            planned_pairs.append(
                {
                    "topology_uuid": topology.uuid,
                    "topology_name": topology.name,
                    "topology_preset": topology.preset,
                    "pair_key": key,
                    "existing_link_ids": [item.uuid for item in existing_links],
                    "link_statuses": [item.status for item in existing_links],
                    "servers": [source_server, target_server],
                    "peer_plans": [
                        {
                            "local_server": source_server,
                            "remote_server": target_server,
                            "peer_name": f"mesh-{source_server}-to-{target_server}",
                            "allowed_ips": routes_by_owner.get(target_server, []),
                        },
                        {
                            "local_server": target_server,
                            "remote_server": source_server,
                            "peer_name": f"mesh-{target_server}-to-{source_server}",
                            "allowed_ips": routes_by_owner.get(source_server, []),
                        },
                    ],
                }
            )

    orphan_links = []
    for link in mesh.vpn_links.values():
        if link.uuid in used_link_ids:
            continue
        orphan_links.append(
            {
                "uuid": link.uuid,
                "source_server": link.source_server,
                "target_server": link.target_server,
                "pair_key": pair_key(link.source_server, link.target_server),
                "status": link.status,
                "topology_uuid": link.topology_uuid,
                "enabled": link.enabled,
            }
        )
    orphan_links.sort(key=lambda item: (item["pair_key"], item["uuid"]))

    return {
        "planned_pairs": planned_pairs,
        "orphan_links": orphan_links,
        "routes_by_owner": routes_by_owner,
        "counts": {
            "topologies": len(mesh.topologies),
            "planned_pairs": len(planned_pairs),
            "orphan_links": len(orphan_links),
            "route_owners": len(routes_by_owner),
        },
    }


def _source_matches(policy: AccessPolicy, source_kind: str, source_id: str) -> bool:
    if policy.source_kind == AccessPolicy.SOURCE_ALL:
        return True
    if policy.source_kind != source_kind:
        return False
    if policy.source_kind == AccessPolicy.SOURCE_SERVER:
        return normalize_server_id(policy.source_id) == normalize_server_id(source_id)
    return str(policy.source_id or "").strip() == str(source_id or "").strip()


def evaluate_access_policy(
    mesh: MeshControlPlane,
    *,
    source_kind: str,
    source_id: str,
    destination: str,
) -> Dict[str, Any]:
    destination_ip = ipaddress.ip_address(str(destination).strip())
    enabled_policies = [policy for policy in mesh.access_policies.values() if policy.enabled]
    enabled_policies.sort(key=lambda item: (item.priority, item.name.lower(), item.uuid))

    for policy in enabled_policies:
        if not _source_matches(policy, source_kind, source_id):
            continue
        for cidr in policy.destinations:
            if destination_ip in ipaddress.ip_network(cidr, strict=False):
                return {
                    "matched": True,
                    "action": policy.action,
                    "reason": f"Matched policy '{policy.name}' ({policy.uuid}).",
                    "policy": policy.__to_yaml_dict__(),
                    "destination": str(destination_ip),
                    "source_kind": source_kind,
                    "source_id": source_id,
                }
    return {
        "matched": False,
        "action": AccessPolicy.ACTION_ALLOW,
        "reason": "No enabled policy matched; default allow applies.",
        "policy": None,
        "destination": str(destination_ip),
        "source_kind": source_kind,
        "source_id": source_id,
    }
