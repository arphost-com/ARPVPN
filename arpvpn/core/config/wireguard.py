import os
from ipaddress import IPv4Address
from logging import debug, warning, error
from shutil import which
from typing import Any, Dict, Mapping, Type

import requests

from yamlable import YamlAble, yaml_info, Y

from arpvpn.common.models.enhanced_dict import EnhancedDict, K, V
from arpvpn.common.properties import global_properties
from arpvpn.common.utils.network import get_default_gateway
from arpvpn.common.utils.system import Command
from arpvpn.core.config.base import BaseConfig


WIREGUARD_BINARY_CANDIDATES = {
    "wg": (
        "wg",
        "/usr/bin/wg",
        "/usr/local/bin/wg",
        "/usr/sbin/wg",
        "/sbin/wg",
    ),
    "wg-quick": (
        "wg-quick",
        "/usr/bin/wg-quick",
        "/usr/local/bin/wg-quick",
        "/usr/sbin/wg-quick",
        "/sbin/wg-quick",
    ),
    "iptables": (
        "iptables",
        "/usr/sbin/iptables",
        "/sbin/iptables",
        "/usr/bin/iptables",
        "/bin/iptables",
    ),
}


def detect_wireguard_binary(name: str) -> str:
    for candidate in WIREGUARD_BINARY_CANDIDATES.get(name, (name,)):
        resolved = which(candidate) if os.path.sep not in candidate else None
        if resolved:
            return resolved
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


class _LegacyMeshDict(EnhancedDict, YamlAble, Mapping[K, V]):
    """Compatibility shim for legacy mesh YAML tags found in older config files."""

    @classmethod
    def __from_yaml_dict__(cls, dct, yaml_tag=""):  # type: ignore[override]
        legacy_dict = cls()
        legacy_dict.update(dct or {})
        return legacy_dict

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self


@yaml_info(yaml_tag="mesh_access_policies")
class MeshAccessPolicies(_LegacyMeshDict):
    pass


@yaml_info(yaml_tag="mesh_route_advertisements")
class MeshRouteAdvertisements(_LegacyMeshDict):
    pass


@yaml_info(yaml_tag="mesh_topologies")
class MeshTopologies(_LegacyMeshDict):
    pass


@yaml_info(yaml_tag="mesh_vpn_links")
class MeshVpnLinks(_LegacyMeshDict):
    pass


@yaml_info(yaml_tag="mesh_control_plane")
class MeshControlPlane(BaseConfig):
    def __init__(self):
        self.access_policies = MeshAccessPolicies()
        self.route_advertisements = MeshRouteAdvertisements()
        self.topologies = MeshTopologies()
        self.vpn_links = MeshVpnLinks()

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return {
            "access_policies": self.access_policies,
            "route_advertisements": self.route_advertisements,
            "topologies": self.topologies,
            "vpn_links": self.vpn_links,
        }

    @classmethod
    def __from_yaml_dict__(cls, dct, yaml_tag=""):  # type: ignore[override]
        mesh = MeshControlPlane()
        dct = dct or {}
        mesh.access_policies = dct.get("access_policies", mesh.access_policies)
        mesh.route_advertisements = dct.get("route_advertisements", mesh.route_advertisements)
        mesh.topologies = dct.get("topologies", mesh.topologies)
        mesh.vpn_links = dct.get("vpn_links", mesh.vpn_links)
        return mesh


@yaml_info(yaml_tag='wireguard')
class WireguardConfig(BaseConfig):
    __IP_RETRIEVER_URL = "https://api.ipify.org"
    INTERFACES_FOLDER_NAME = "interfaces"

    endpoint: str
    wg_bin: str
    wg_quick_bin: str
    iptables_bin: str
    @property
    def interfaces_folder(self):
        return global_properties.join_workdir(self.INTERFACES_FOLDER_NAME)

    def __init__(self):
        self.load_defaults()

    def load_defaults(self):
        self.endpoint = ""
        self.iptables_bin = ""
        self.wg_bin = ""
        self.wg_quick_bin = ""
        self.wg_bin = detect_wireguard_binary("wg")
        self.wg_quick_bin = detect_wireguard_binary("wg-quick")
        self.iptables_bin = detect_wireguard_binary("iptables")
        from arpvpn.core.models import interfaces
        self.interfaces = interfaces

    def load(self, config: "WireguardConfig"):
        self.endpoint = config.endpoint or self.endpoint
        if not self.endpoint:
            warning("No endpoint specified. Retrieving public IP address...")
            self.set_default_endpoint()
        self.wg_bin = config.wg_bin or self.wg_bin
        self.wg_quick_bin = config.wg_quick_bin or self.wg_quick_bin
        self.iptables_bin = config.iptables_bin or self.iptables_bin
        if config.interfaces:
            self.interfaces.set_contents(config.interfaces)
        for iface in self.interfaces.values():
            iface.conf_file = os.path.join(self.interfaces_folder, iface.name) + ".conf"
            iface.save()

    def set_default_endpoint(self):
        try:
            response = requests.get(self.__IP_RETRIEVER_URL, headers={"User-Agent": "ARPVPN/2"}, timeout=10)
            response.raise_for_status()
            self.endpoint = response.text[:64].strip()
            IPv4Address(self.endpoint)
            debug(f"Public IP address is {self.endpoint}. This will be used as default endpoint.")
        except Exception as e:
            error(f"Unable to obtain server's public IP address: {e}")
            ip = (Command(f"ip a show {get_default_gateway()} | grep inet | head -n1 | xargs | cut -d ' ' -f2")
                  .run().output)
            self.endpoint = ip.split("/")[0]
            if not self.endpoint:
                error("Unable to automatically set endpoint.")
                return
            warning(f"Server endpoint set to {self.endpoint}: this might not be a public IP address!")

    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag=""
                           ):  # type: (...) -> Y
        config = WireguardConfig()
        config.endpoint = dct.get("endpoint", None) or config.endpoint
        config.wg_bin = dct.get("wg_bin", None) or config.wg_bin
        config.wg_quick_bin = dct.get("wg_quick_bin", None) or config.wg_quick_bin
        config.iptables_bin = dct.get("iptables_bin", None) or config.iptables_bin
        config.interfaces = dct.get("interfaces", None) or config.interfaces
        for iface in config.interfaces.values():
            iface.conf_file = os.path.join(config.interfaces_folder, iface.name) + ".conf"
            iface.save()
        return config

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return {
            "endpoint": self.endpoint,
            "wg_bin": self.wg_bin,
            "wg_quick_bin": self.wg_quick_bin,
            "iptables_bin": self.iptables_bin,
            "interfaces": self.interfaces,
        }

    def apply(self):
        super(WireguardConfig, self).apply()
        for iface in self.interfaces.values():
            was_up = iface.is_up
            iface.down()
            if os.path.exists(iface.conf_file):
                os.remove(iface.conf_file)
            iface.conf_file = os.path.join(self.interfaces_folder, iface.name) + ".conf"
            if was_up:
                iface.up()


config = WireguardConfig()
