import yaml

from arpvpn.core.config.wireguard import (
    LegacyMeshRouteAdvertisement,
    LegacyMeshTopology,
    LegacyMeshVpnLink,
    WireguardConfig,
)


LEGACY_WIREGUARD_YAML = """
!yamlable/wireguard
endpoint: vpn.example.test
interfaces: !yamlable/interfaces {}
iptables_bin: /usr/sbin/iptables
mesh: !yamlable/mesh_control_plane
  access_policies: !yamlable/mesh_access_policies {}
  route_advertisements: !yamlable/mesh_route_advertisements
    route-one: !yamlable/mesh_route_advertisement
      cidr: 192.0.2.0/24
      enabled: true
      owner_server: edge-one
      uuid: route-one
  topologies: !yamlable/mesh_topologies
    topology-one: !yamlable/mesh_topology
      name: Production mesh
      preset: point_to_point
      server_ids: [edge-one, edge-two]
      uuid: topology-one
  vpn_links: !yamlable/mesh_vpn_links
    link-one: !yamlable/mesh_vpn_link
      enabled: true
      source_server: edge-one
      target_server: edge-two
      uuid: link-one
wg_bin: /usr/bin/wg
wg_quick_bin: /usr/bin/wg-quick
"""


def test_legacy_mesh_objects_load_and_round_trip_without_data_loss():
    loaded = yaml.safe_load(LEGACY_WIREGUARD_YAML)

    assert isinstance(loaded, WireguardConfig)
    assert isinstance(loaded.mesh.route_advertisements["route-one"], LegacyMeshRouteAdvertisement)
    assert isinstance(loaded.mesh.topologies["topology-one"], LegacyMeshTopology)
    assert isinstance(loaded.mesh.vpn_links["link-one"], LegacyMeshVpnLink)

    reloaded = yaml.safe_load(yaml.safe_dump(loaded))
    assert reloaded.mesh.route_advertisements["route-one"]["cidr"] == "192.0.2.0/24"
    assert reloaded.mesh.topologies["topology-one"]["server_ids"] == ["edge-one", "edge-two"]
    assert reloaded.mesh.vpn_links["link-one"]["target_server"] == "edge-two"
