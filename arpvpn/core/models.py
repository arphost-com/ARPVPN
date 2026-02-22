import http
import ipaddress
import os
import re
from logging import info, warning, error, debug
from secrets import randbelow
from time import sleep
from typing import Dict, Any, Type, List, Mapping
from uuid import uuid4 as gen_uuid

from coolname import generate_slug
from yamlable import YamlAble, yaml_info, Y

from arpvpn.common.models.enhanced_dict import EnhancedDict, V, K
from arpvpn.common.utils.file import write_lines
from arpvpn.common.utils.system import Command, try_makedir
from arpvpn.core.exceptions import WireguardError
from arpvpn.core.utils.wireguard import get_wg_interface_status


@yaml_info(yaml_tag='interface')
class Interface(YamlAble):
    MIN_PORT_NUMBER = 50000
    MAX_PORT_NUMBER = 65535

    MIN_NAME_LENGTH = 2
    MAX_NAME_LENGTH = 15
    REGEX_NAME = f"^[a-z][a-z\-_0-9]{{{MIN_NAME_LENGTH - 1},{MAX_NAME_LENGTH - 1}}}$"
    REGEX_IPV4_PARTIAL = "([1-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])(\.(\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])){3}"
    REGEX_IPV4 = f"^{REGEX_IPV4_PARTIAL}$"
    REGEX_IPV4_CIDR = f"^{REGEX_IPV4_PARTIAL}\/(3[0-2]|[1-2]\d|\d)$"

    @property
    def wg_quick_bin(self):
        from arpvpn.core.config.wireguard import config
        return config.wg_quick_bin

    def __init__(self, name: str, description: str, gw_iface: str, ipv4_address: str, listen_port: int, auto: bool,
                 on_up: List[str], on_down: List[str], uuid: str = "", private_key: str = "",
                 public_key: str = "", peers: "PeerDict" = None):
        self.name = name
        self.gw_iface = gw_iface
        self.description = description
        self.ipv4_address = ipv4_address
        self.listen_port = listen_port
        self.auto = auto
        self.on_up = on_up
        self.on_down = on_down
        self.uuid = uuid or gen_uuid().hex
        self.peers = peers or PeerDict()
        for peer in self.peers.values():
            peer.interface = self
        from arpvpn.core.utils.wireguard import generate_privkey, generate_pubkey
        from arpvpn.core.config.wireguard import config
        self.conf_file = f"{os.path.join(config.interfaces_folder, self.name)}.conf"
        self.private_key = private_key or generate_privkey()
        if not private_key:
            warning("Generating new public key because no private key was provided.")
            self.public_key = generate_pubkey(self.private_key)
        else:
            self.public_key = public_key or generate_pubkey(self.private_key)

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        """ Called when you call yaml.dump()"""
        return {
            "uuid": self.uuid,
            "name": self.name,
            "description": self.description,
            "gw_iface": self.gw_iface,
            "ipv4_address": self.ipv4_address,
            "listen_port": self.listen_port,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "auto": self.auto,
            "on_up": self.on_up,
            "on_down": self.on_down,
            "peers": self.peers
        }

    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag  # type: str
                           ):  # type: (...) -> Y
        """ This optional method is called when you call yaml.load()"""
        uuid = dct["uuid"]
        name = dct["name"]
        description = dct["description"]
        gw_iface = dct["gw_iface"]
        ipv4_address = dct["ipv4_address"]
        listen_port = dct["listen_port"]
        private_key = dct["private_key"]
        public_key = dct["public_key"]
        auto = dct["auto"]
        on_up = dct.get("on_up", [])
        on_down = dct.get("on_down", [])
        peers = dct.get("peers", None)
        iface = Interface(name=name, description=description, gw_iface=gw_iface, ipv4_address=ipv4_address,
                          listen_port=listen_port, auto=auto, uuid=uuid, private_key=private_key,
                          public_key=public_key, on_up=on_up, on_down=on_down, peers=peers)
        return iface

    def generate_conf(self) -> str:
        """Generate the wireguard configuration for this interface."""
        iface = ("[Interface]\n"
                 f"PrivateKey = {self.private_key}\n"
                 f"Address = {self.ipv4_address}\n"
                 f"ListenPort = {self.listen_port}\n")
        for cmd in self.on_up:
            iface += f"PostUp = {cmd}\n"
        for cmd in self.on_down:
            iface += f"PostDown = {cmd}\n"

        peers = ""
        for peer in self.peers.values():
            peers += (f"\n[Peer]\n"
                      f"PublicKey = {peer.public_key}\n"
                      f"AllowedIPs = {', '.join(peer.server_allowed_ips)}\n")
        return iface + peers

    def save(self):
        """Store the current wireguard configuration for this interface in the file system."""
        debug(f"Saving configuration of interface {self.name} to {self.conf_file}...")
        try_makedir(os.path.dirname(self.conf_file))
        write_lines(self.generate_conf(), self.conf_file)
        debug(f"Configuration saved!")

    @property
    def is_up(self):
        return Command(f"ip a | grep -w {self.name}").run().successful

    @property
    def is_down(self):
        return not self.is_up

    @property
    def status(self):
        return get_wg_interface_status(self.name)

    def up(self):
        info(f"Starting interface {self.name}...")
        if self.is_up:
            warning(f"Unable to bring {self.name} up: already up.")
            return
        self.save()
        result = Command(f"{self.wg_quick_bin} up {self.conf_file}").run_as_root()
        if result.successful:
            info(f"Interface {self.name} started.")
        else:
            error(f"Failed to start interface {self.name}: code={result.code} | err={result.err} | out={result.output}")
            raise WireguardError(result.err)

    def down(self):
        info(f"Stopping interface {self.name}...")
        if self.is_down:
            warning(f"Unable to bring {self.name} down: already down.")
            return
        from arpvpn.core.config.traffic import config
        if config.enabled:
            config.driver.save_data()
        result = Command(f"{self.wg_quick_bin} down {self.conf_file}").run_as_root()
        if result.successful:
            info(f"Interface {self.name} stopped.")
        else:
            error(f"Failed to stop interface {self.name}: code={result.code} | err={result.err} | out={result.output}")
            raise WireguardError(result.err)

    def apply(self):
        self.down()
        self.save()
        self.up()

    def restart(self):
        self.down()
        sleep(1)
        self.up()

    def remove(self):
        self.down()
        self.peers.clear()
        if os.path.exists(self.conf_file):
            os.remove(self.conf_file)
        del interfaces[self.uuid]
        interfaces.sort()

    def edit(self, name: str, description: str, ipv4_address: str,
             port: int, gw_iface: str, auto: bool, on_up: List[str], on_down: List[str]):
        self.name = name
        self.gw_iface = gw_iface
        self.description = description
        self.ipv4_address = ipv4_address
        self.listen_port = port
        self.auto = auto
        self.on_up = on_up
        self.on_down = on_down
        from arpvpn.core.config.wireguard import config
        self.conf_file = f"{os.path.join(config.interfaces_folder, self.name)}.conf"

    def add_peer(self, peer: "Peer"):
        self.peers[peer.uuid] = peer
        self.peers.sort()

    @classmethod
    def generate_valid_name(cls) -> str:
        name = generate_slug(2)[:cls.MAX_NAME_LENGTH]
        for iface in interfaces.values():
            if iface.name == name:
                return cls.generate_valid_name()
        return name

    @classmethod
    def is_name_valid(cls, name: str) -> bool:
        return re.match(cls.REGEX_NAME, name) is not None

    @classmethod
    def is_name_in_use(cls, name: str, interface: "Interface") -> bool:
        iface = interfaces.get_value_by_attr("name", name)
        if iface:
            if iface == interface:
                return False
            return True

    @classmethod
    def is_ip_in_use(cls, ip: str, interface_to_exclude: "Interface" = None) -> bool:
        ip = ip.split("/")[0]
        for iface in filter(lambda i: i != interface_to_exclude, interfaces.values()):
            if iface.ipv4_address.split("/")[0] == ip:
                return True
        for peer in get_all_peers().values():
            if peer.ipv4_address.split("/")[0] == ip:
                return True
        return False

    @classmethod
    def is_network_in_use(cls, interface: ipaddress.IPv4Interface, interface_to_exclude: "Interface" = None) -> bool:
        for iface in filter(lambda i: i != interface_to_exclude, interfaces.values()):
            if interface in ipaddress.IPv4Interface(iface.ipv4_address).network:
                return True
        return False

    @classmethod
    def is_port_in_use(cls, port: int, interface_to_exclude: "Interface" = None) -> bool:
        for iface in filter(lambda i: i != interface_to_exclude, interfaces.values()):
            if iface.listen_port == port:
                return True
        return False

    @classmethod
    def get_unused_port(cls) -> int:
        tries = 100
        for i in range(0, tries):
            port = Interface.MIN_PORT_NUMBER + randbelow(Interface.MAX_PORT_NUMBER - Interface.MIN_PORT_NUMBER + 1)
            if not Interface.is_port_in_use(port):
                return port
        raise WireguardError(f"Unable to obtain a free port (tried {tries} times)", http.HTTPStatus.BAD_REQUEST)


@yaml_info(yaml_tag='peer')
class Peer(YamlAble):
    MODE_CLIENT = "client"
    MODE_SITE_TO_SITE = "site_to_site"
    MODES = (MODE_CLIENT, MODE_SITE_TO_SITE)

    MIN_NAME_LENGTH = 2
    MAX_NAME_LENGTH = 64
    REGEX_NAME = f"^[a-zA-Z][\w\-. ]{{{MIN_NAME_LENGTH - 1},{MAX_NAME_LENGTH - 1}}}$"

    def __init__(self, name: str, description: str, ipv4_address: str, nat: bool, interface: Interface, dns1: str,
                 uuid: str = "", private_key: str = "", public_key: str = "", dns2: str = None,
                 mode: str = MODE_CLIENT, site_to_site_subnets: List[str] = None, full_tunnel: bool = False):
        self.name = name
        self.description = description
        self.ipv4_address = ipv4_address
        self.nat = nat
        self.full_tunnel = bool(full_tunnel)
        self.interface = interface
        self.dns1 = dns1
        self.dns2 = dns2
        if self.is_mode_valid(mode):
            self.mode = mode
        else:
            warning(f"Invalid peer mode '{mode}', using '{self.MODE_CLIENT}' instead.")
            self.mode = self.MODE_CLIENT
        self.site_to_site_subnets = self.parse_site_to_site_subnets(site_to_site_subnets or [])
        self.uuid = uuid or gen_uuid().hex
        from arpvpn.core.utils.wireguard import generate_privkey, generate_pubkey
        self.private_key = private_key or generate_privkey()
        if not private_key:
            warning("Generating new public key because no private key was provided.")
            self.public_key = generate_pubkey(self.private_key)
        else:
            self.public_key = public_key or generate_pubkey(self.private_key)

    @property
    def endpoint(self):
        from arpvpn.core.config.wireguard import config
        return f"{config.endpoint}:{self.interface.listen_port}"

    @property
    def is_site_to_site(self) -> bool:
        return self.mode == self.MODE_SITE_TO_SITE

    @property
    def tunnel_ipv4(self) -> str:
        try:
            return str(ipaddress.IPv4Interface(self.ipv4_address).ip)
        except ValueError:
            return self.ipv4_address.split("/")[0]

    @property
    def server_allowed_ips(self) -> List[str]:
        allowed_ips = [f"{self.tunnel_ipv4}/32"]
        if self.is_site_to_site:
            allowed_ips.extend(self.site_to_site_subnets)
        return allowed_ips

    @property
    def download_allowed_ips(self) -> str:
        if self.is_site_to_site:
            if self.full_tunnel:
                return "0.0.0.0/0"
            if not self.interface:
                return "0.0.0.0/0"
            return str(ipaddress.IPv4Interface(self.interface.ipv4_address).network)
        return "0.0.0.0/0"

    @classmethod
    def is_mode_valid(cls, mode: str) -> bool:
        return mode in cls.MODES

    @staticmethod
    def parse_site_to_site_subnets(data: Any) -> List[str]:
        if not data:
            return []
        if isinstance(data, list):
            chunks = data
        else:
            chunks = re.split(r"[,\n]", str(data))

        subnets = []
        for chunk in chunks:
            subnet = str(chunk).strip()
            if not subnet:
                continue
            normalized = str(ipaddress.IPv4Network(subnet, strict=False))
            if normalized not in subnets:
                subnets.append(normalized)
        return subnets

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        """ Called when you call yaml.dump()"""
        return {
            "uuid": self.uuid,
            "name": self.name,
            "description": self.description,
            "ipv4_address": self.ipv4_address,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "nat": self.nat,
            "full_tunnel": self.full_tunnel,
            "dns1": self.dns1,
            "dns2": self.dns2,
            "mode": self.mode,
            "site_to_site_subnets": self.site_to_site_subnets
        }

    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag  # type: str
                           ):  # type: (...) -> Y
        """ This optional method is called when you call yaml.load()"""
        uuid = dct["uuid"]
        name = dct["name"]
        description = dct["description"]
        ipv4_address = dct["ipv4_address"]
        private_key = dct["private_key"]
        public_key = dct["public_key"]
        nat = dct["nat"]
        full_tunnel = dct.get("full_tunnel", False)
        dns1 = dct["dns1"]
        dns2 = dct.get("dns2", "")
        mode = dct.get("mode", cls.MODE_CLIENT)
        site_to_site_subnets = dct.get("site_to_site_subnets", [])
        return Peer(name=name, description=description, interface=None, ipv4_address=ipv4_address, nat=nat, uuid=uuid,
                    private_key=private_key, public_key=public_key, dns1=dns1, dns2=dns2, mode=mode,
                    site_to_site_subnets=site_to_site_subnets, full_tunnel=full_tunnel)

    def generate_conf(self) -> str:
        """Generate a wireguard configuration file suitable for this client."""

        iface = f"[Interface]\n" \
                f"PrivateKey = {self.private_key}\n"
        iface += f"Address = {self.ipv4_address}\n"
        if self.dns1:
            iface += f"DNS = {self.dns1}"
            if self.dns2:
                iface += f", {self.dns2}\n"
            else:
                iface += "\n"
        peer = f"\n[Peer]\n" \
               f"PublicKey = {self.interface.public_key}\n" \
               f"AllowedIPs = {self.download_allowed_ips}\n" \
               f"Endpoint = {self.endpoint}\n"
        if self.nat:
            peer += "PersistentKeepalive = 25\n"

        return iface + peer

    def edit(self, name: str, description: str, ipv4_address: str, interface: Interface, dns1: str, dns2: str,
             nat: bool, mode: str = MODE_CLIENT, site_to_site_subnets: List[str] = None, full_tunnel: bool = False):
        self.remove()
        self.name = name
        self.description = description
        self.ipv4_address = ipv4_address
        self.interface = interface
        self.interface.add_peer(self)
        self.dns1 = dns1
        self.dns2 = dns2
        self.nat = nat
        self.full_tunnel = bool(full_tunnel)
        self.mode = mode if self.is_mode_valid(mode) else self.MODE_CLIENT
        self.site_to_site_subnets = self.parse_site_to_site_subnets(site_to_site_subnets or [])

    def remove(self):
        if self.uuid not in self.interface.peers:
            return
        del self.interface.peers[self.uuid]
        self.interface.peers.sort()

    @classmethod
    def is_ip_in_use(cls, ip: str, peer_to_exclude: "Peer" = None) -> bool:
        ip = ip.split("/")[0]
        for iface in interfaces.values():
            if iface.ipv4_address.split("/")[0] == ip:
                return True
        for peer in filter(lambda p: p != peer_to_exclude, get_all_peers().values()):
            if peer.ipv4_address.split("/")[0] == ip:
                return True
        return False

    @classmethod
    def generate_valid_name(cls) -> str:
        name = generate_slug(2)[:cls.MAX_NAME_LENGTH]
        for iface in interfaces.values():
            if iface.name == name:
                return cls.generate_valid_name()
        return name

    @classmethod
    def is_name_valid(cls, name: str) -> bool:
        return re.match(cls.REGEX_NAME, name) is not None


@yaml_info(yaml_tag='interfaces')
class InterfaceDict(EnhancedDict, YamlAble, Mapping[K, V]):
    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag  # type: str
                           ):  # type: (...) -> Y
        i = InterfaceDict()
        i.update(dct)
        i.sort()
        return i

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self

    def sort(self, order_by=lambda pair: pair[1].name):
        super(InterfaceDict, self).sort(order_by)


@yaml_info(yaml_tag='peers')
class PeerDict(EnhancedDict, YamlAble, Mapping[K, V]):
    @classmethod
    def __from_yaml_dict__(cls,  # type: Type[Y]
                           dct,  # type: Dict[str, Any]
                           yaml_tag  # type: str
                           ):  # type: (...) -> Y
        p = PeerDict()
        p.update(dct)
        p.sort()
        return p

    def __to_yaml_dict__(self):  # type: (...) -> Dict[str, Any]
        return self

    def sort(self, order_by=lambda pair: pair[1].name):
        super(PeerDict, self).sort(order_by)


def get_all_peers() -> PeerDict[str, Peer]:
    dct = PeerDict()
    for iface in interfaces.values():
        dct.update(iface.peers)
    return dct


interfaces: InterfaceDict[str, Interface]
interfaces = InterfaceDict()
