import ipaddress
import re
from logging import warning
from typing import Any, Dict, List, Mapping, Type
from uuid import uuid4 as gen_uuid

from yamlable import YamlAble, yaml_info, Y

from arpvpn.common.models.enhanced_dict import EnhancedDict, K, V


def normalize_server_id(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    normalized = re.sub(r"[^a-z0-9_.-]", "-", normalized)
    normalized = re.sub(r"-{2,}", "-", normalized).strip("-")
    return normalized


def parse_server_ids(data: Any) -> List[str]:
    if not data:
        return []
    if isinstance(data, list):
        chunks = data
    else:
        chunks = re.split(r"[,\n]", str(data))
    server_ids: List[str] = []
    for chunk in chunks:
        server_id = normalize_server_id(chunk)
        if not server_id or server_id in server_ids:
            continue
        server_ids.append(server_id)
    return server_ids


def normalize_ipv4_cidr(cidr: str) -> str:
    return str(ipaddress.IPv4Network(str(cidr).strip(), strict=False))


def parse_cidr_list(data: Any) -> List[str]:
    if not data:
        return []
    if isinstance(data, list):
        chunks = data
    else:
        chunks = re.split(r"[,\n]", str(data))
    cidrs: List[str] = []
    for chunk in chunks:
        value = str(chunk).strip()
        if not value:
            continue
        normalized = normalize_ipv4_cidr(value)
        if normalized in cidrs:
            continue
        cidrs.append(normalized)
    return cidrs


@yaml_info(yaml_tag='mesh_topology')
class MeshTopology(YamlAble):
    PRESET_POINT_TO_POINT = "point_to_point"
    PRESET_HUB_SPOKE = "hub_spoke"
    PRESET_FULL_MESH = "full_mesh"
    PRESETS = (PRESET_POINT_TO_POINT, PRESET_HUB_SPOKE, PRESET_FULL_MESH)

    def __init__(
        self,
        name: str,
        preset: str,
        server_ids: List[str],
        hub_server_id: str = "",
        description: str = "",
        uuid: str = "",
    ):
        self.uuid = uuid or gen_uuid().hex
        self.name = str(name or "").strip() or f"topology-{self.uuid[:8]}"
        if preset not in self.PRESETS:
            warning(f"Invalid topology preset '{preset}', using '{self.PRESET_POINT_TO_POINT}'.")
            self.preset = self.PRESET_POINT_TO_POINT
        else:
            self.preset = preset
        self.server_ids = parse_server_ids(server_ids)
        self.hub_server_id = normalize_server_id(hub_server_id)
        self.description = str(description or "").strip()
        if self.preset == self.PRESET_HUB_SPOKE:
            if not self.server_ids:
                self.hub_server_id = ""
            elif self.hub_server_id not in self.server_ids:
                self.hub_server_id = self.server_ids[0]
        else:
            self.hub_server_id = ""

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return {
            "uuid": self.uuid,
            "name": self.name,
            "preset": self.preset,
            "server_ids": self.server_ids,
            "hub_server_id": self.hub_server_id,
            "description": self.description,
        }

    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        return MeshTopology(
            uuid=dct.get("uuid", ""),
            name=dct.get("name", ""),
            preset=dct.get("preset", cls.PRESET_POINT_TO_POINT),
            server_ids=dct.get("server_ids", []),
            hub_server_id=dct.get("hub_server_id", ""),
            description=dct.get("description", ""),
        )


@yaml_info(yaml_tag='mesh_vpn_link')
class VPNLink(YamlAble):
    STATUS_PENDING = "pending"
    STATUS_ACTIVE = "active"
    STATUS_DEGRADED = "degraded"
    STATUS_ERROR = "error"
    STATUS_DISABLED = "disabled"
    STATUSES = (STATUS_PENDING, STATUS_ACTIVE, STATUS_DEGRADED, STATUS_ERROR, STATUS_DISABLED)

    def __init__(
        self,
        source_server: str,
        target_server: str,
        interface_uuid: str = "",
        status: str = STATUS_PENDING,
        key_metadata: Dict[str, Any] = None,
        topology_uuid: str = "",
        description: str = "",
        enabled: bool = True,
        uuid: str = "",
    ):
        self.uuid = uuid or gen_uuid().hex
        self.source_server = normalize_server_id(source_server)
        self.target_server = normalize_server_id(target_server)
        self.interface_uuid = str(interface_uuid or "").strip()
        if status not in self.STATUSES:
            warning(f"Invalid VPN link status '{status}', using '{self.STATUS_PENDING}'.")
            self.status = self.STATUS_PENDING
        else:
            self.status = status
        self.key_metadata = self._sanitize_key_metadata(key_metadata or {})
        self.topology_uuid = str(topology_uuid or "").strip()
        self.description = str(description or "").strip()
        self.enabled = bool(enabled)

    @staticmethod
    def _sanitize_key_metadata(data: Dict[str, Any]) -> Dict[str, str]:
        allowed = (
            "local_public_key",
            "remote_public_key",
            "preshared_key_fingerprint",
            "algorithm",
            "rotated_at",
        )
        sanitized: Dict[str, str] = {}
        for key in allowed:
            if key not in data:
                continue
            value = str(data.get(key) or "").strip()
            if value:
                sanitized[key] = value
        return sanitized

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return {
            "uuid": self.uuid,
            "source_server": self.source_server,
            "target_server": self.target_server,
            "interface_uuid": self.interface_uuid,
            "status": self.status,
            "key_metadata": self.key_metadata,
            "topology_uuid": self.topology_uuid,
            "description": self.description,
            "enabled": self.enabled,
        }

    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        return VPNLink(
            uuid=dct.get("uuid", ""),
            source_server=dct.get("source_server", ""),
            target_server=dct.get("target_server", ""),
            interface_uuid=dct.get("interface_uuid", ""),
            status=dct.get("status", cls.STATUS_PENDING),
            key_metadata=dct.get("key_metadata", {}),
            topology_uuid=dct.get("topology_uuid", ""),
            description=dct.get("description", ""),
            enabled=dct.get("enabled", True),
        )


@yaml_info(yaml_tag='mesh_route_advertisement')
class RouteAdvertisement(YamlAble):
    def __init__(
        self,
        owner_server: str,
        cidr: str,
        via_link_uuid: str = "",
        description: str = "",
        enabled: bool = True,
        uuid: str = "",
    ):
        self.uuid = uuid or gen_uuid().hex
        self.owner_server = normalize_server_id(owner_server)
        self.cidr = normalize_ipv4_cidr(cidr)
        self.via_link_uuid = str(via_link_uuid or "").strip()
        self.description = str(description or "").strip()
        self.enabled = bool(enabled)

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.cidr, strict=False)

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return {
            "uuid": self.uuid,
            "owner_server": self.owner_server,
            "cidr": self.cidr,
            "via_link_uuid": self.via_link_uuid,
            "description": self.description,
            "enabled": self.enabled,
        }

    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        return RouteAdvertisement(
            uuid=dct.get("uuid", ""),
            owner_server=dct.get("owner_server", ""),
            cidr=dct.get("cidr", "0.0.0.0/32"),
            via_link_uuid=dct.get("via_link_uuid", ""),
            description=dct.get("description", ""),
            enabled=dct.get("enabled", True),
        )


@yaml_info(yaml_tag='mesh_access_policy')
class AccessPolicy(YamlAble):
    SOURCE_PEER = "peer"
    SOURCE_GROUP = "group"
    SOURCE_SERVER = "server"
    SOURCE_ALL = "all"
    SOURCE_KINDS = (SOURCE_PEER, SOURCE_GROUP, SOURCE_SERVER, SOURCE_ALL)

    ACTION_ALLOW = "allow"
    ACTION_DENY = "deny"
    ACTIONS = (ACTION_ALLOW, ACTION_DENY)

    DEFAULT_PRIORITY = 100

    def __init__(
        self,
        name: str,
        source_kind: str,
        source_id: str,
        destinations: List[str],
        action: str = ACTION_ALLOW,
        priority: int = DEFAULT_PRIORITY,
        description: str = "",
        enabled: bool = True,
        uuid: str = "",
    ):
        self.uuid = uuid or gen_uuid().hex
        self.name = str(name or "").strip() or f"policy-{self.uuid[:8]}"
        if source_kind not in self.SOURCE_KINDS:
            warning(f"Invalid access policy source kind '{source_kind}', using '{self.SOURCE_PEER}'.")
            self.source_kind = self.SOURCE_PEER
        else:
            self.source_kind = source_kind
        normalized_source = str(source_id or "").strip()
        if self.source_kind == self.SOURCE_ALL:
            self.source_id = "*"
        elif self.source_kind == self.SOURCE_SERVER:
            self.source_id = normalize_server_id(normalized_source)
        else:
            self.source_id = normalized_source

        if action not in self.ACTIONS:
            warning(f"Invalid access policy action '{action}', using '{self.ACTION_ALLOW}'.")
            self.action = self.ACTION_ALLOW
        else:
            self.action = action
        self.destinations = parse_cidr_list(destinations)
        try:
            parsed_priority = int(priority)
        except (TypeError, ValueError):
            parsed_priority = self.DEFAULT_PRIORITY
        self.priority = parsed_priority if parsed_priority >= 0 else self.DEFAULT_PRIORITY
        self.description = str(description or "").strip()
        self.enabled = bool(enabled)

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return {
            "uuid": self.uuid,
            "name": self.name,
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "destinations": self.destinations,
            "action": self.action,
            "priority": self.priority,
            "description": self.description,
            "enabled": self.enabled,
        }

    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        return AccessPolicy(
            uuid=dct.get("uuid", ""),
            name=dct.get("name", ""),
            source_kind=dct.get("source_kind", cls.SOURCE_PEER),
            source_id=dct.get("source_id", ""),
            destinations=dct.get("destinations", []),
            action=dct.get("action", cls.ACTION_ALLOW),
            priority=dct.get("priority", cls.DEFAULT_PRIORITY),
            description=dct.get("description", ""),
            enabled=dct.get("enabled", True),
        )


@yaml_info(yaml_tag='mesh_topologies')
class MeshTopologyDict(EnhancedDict, YamlAble, Mapping[K, V]):
    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        topologies = MeshTopologyDict()
        topologies.update(dct)
        topologies.sort()
        return topologies

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self

    def sort(self, order_by=lambda pair: pair[1].name.lower()):
        super(MeshTopologyDict, self).sort(order_by)


@yaml_info(yaml_tag='mesh_vpn_links')
class VPNLinkDict(EnhancedDict, YamlAble, Mapping[K, V]):
    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        links = VPNLinkDict()
        links.update(dct)
        links.sort()
        return links

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self

    def sort(self, order_by=lambda pair: (pair[1].source_server, pair[1].target_server, pair[1].uuid)):
        super(VPNLinkDict, self).sort(order_by)


@yaml_info(yaml_tag='mesh_route_advertisements')
class RouteAdvertisementDict(EnhancedDict, YamlAble, Mapping[K, V]):
    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        routes = RouteAdvertisementDict()
        routes.update(dct)
        routes.sort()
        return routes

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self

    def sort(self, order_by=lambda pair: (pair[1].owner_server, pair[1].cidr, pair[1].uuid)):
        super(RouteAdvertisementDict, self).sort(order_by)


@yaml_info(yaml_tag='mesh_access_policies')
class AccessPolicyDict(EnhancedDict, YamlAble, Mapping[K, V]):
    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        policies = AccessPolicyDict()
        policies.update(dct)
        policies.sort()
        return policies

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self

    def sort(self, order_by=lambda pair: (pair[1].priority, pair[1].name.lower(), pair[1].uuid)):
        super(AccessPolicyDict, self).sort(order_by)


@yaml_info(yaml_tag='mesh_control_plane')
class MeshControlPlane(YamlAble):
    def __init__(
        self,
        topologies: MeshTopologyDict = None,
        vpn_links: VPNLinkDict = None,
        route_advertisements: RouteAdvertisementDict = None,
        access_policies: AccessPolicyDict = None,
    ):
        self.topologies = topologies or MeshTopologyDict()
        self.vpn_links = vpn_links or VPNLinkDict()
        self.route_advertisements = route_advertisements or RouteAdvertisementDict()
        self.access_policies = access_policies or AccessPolicyDict()

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return {
            "topologies": self.topologies,
            "vpn_links": self.vpn_links,
            "route_advertisements": self.route_advertisements,
            "access_policies": self.access_policies,
        }

    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        return MeshControlPlane(
            topologies=dct.get("topologies", MeshTopologyDict()),
            vpn_links=dct.get("vpn_links", VPNLinkDict()),
            route_advertisements=dct.get("route_advertisements", RouteAdvertisementDict()),
            access_policies=dct.get("access_policies", AccessPolicyDict()),
        )

    def validate_route_advertisements(self) -> Dict[str, List[Dict[str, Any]]]:
        enabled_routes = [route for route in self.route_advertisements.values() if route.enabled]
        duplicates: List[Dict[str, Any]] = []
        overlaps: List[Dict[str, Any]] = []

        owners_by_cidr: Dict[str, set] = {}
        for route in enabled_routes:
            owners = owners_by_cidr.setdefault(route.cidr, set())
            owners.add(route.owner_server)
        for cidr, owners in sorted(owners_by_cidr.items()):
            if len(owners) <= 1:
                continue
            duplicates.append({
                "cidr": cidr,
                "owner_servers": sorted(owners),
            })

        for i in range(0, len(enabled_routes)):
            first = enabled_routes[i]
            first_network = first.network
            for j in range(i + 1, len(enabled_routes)):
                second = enabled_routes[j]
                if first.owner_server == second.owner_server:
                    continue
                second_network = second.network
                if first_network == second_network:
                    continue
                if not first_network.overlaps(second_network):
                    continue
                overlaps.append({
                    "cidr_a": first.cidr,
                    "owner_server_a": first.owner_server,
                    "cidr_b": second.cidr,
                    "owner_server_b": second.owner_server,
                })

        return {
            "duplicate_ownership": duplicates,
            "overlapping_cidrs": overlaps,
        }

    def has_route_conflicts(self) -> bool:
        conflicts = self.validate_route_advertisements()
        return bool(conflicts["duplicate_ownership"] or conflicts["overlapping_cidrs"])
