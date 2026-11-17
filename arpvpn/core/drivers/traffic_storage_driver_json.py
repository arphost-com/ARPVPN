import json
import os
import tempfile
from datetime import datetime
from logging import info, warning
from typing import Dict, Any, Type

from yamlable import yaml_info, Y

from arpvpn.common.properties import global_properties
from arpvpn.core.drivers.traffic_storage_driver import TrafficStorageDriver, TrafficData
from arpvpn.core.models import interfaces, get_all_peers


@yaml_info(yaml_tag='traffic_storage_driver_json')
class TrafficStorageDriverJson(TrafficStorageDriver):

    FILENAME = "traffic.json"

    def __init__(self, timestamp_format: str = TrafficStorageDriver.DEFAULT_TIMESTAMP_FORMAT):
        super().__init__(timestamp_format)
        self._load_cache_signature = None
        self._load_cache_data = None

    @property
    def filepath(self):
        return global_properties.join_workdir(self.FILENAME)

    @classmethod
    def get_name(cls) -> str:
        return "JSON"

    def save_data(self):
        info("Updating traffic data...")
        merged_data = self.get_session_and_stored_data()
        json_data = {}
        for timestamp, data in merged_data.items():
            device_data = {}
            for device, traffic_data in data.items():
                if device in interfaces.keys():
                    # Do not store interface data, since it will be calculated from peers data
                    continue
                device_data[device] = {"rx": traffic_data.rx, "tx": traffic_data.tx}
            json_data[timestamp.strftime(self.timestamp_format)] = device_data
        self._write_atomically(json_data)
        self._load_cache_signature = None
        self._load_cache_data = None
        info("Traffic data updated.")

    def _write_atomically(self, json_data: Dict[str, Any]):
        """Write to a temp file in the same folder and rename it over traffic.json.

        Opening traffic.json itself for writing empties it first, so a kill or
        crash during the dump used to leave an empty file that stopped every
        later start. The rename is atomic, so readers see the old or the new file.
        """
        directory = os.path.dirname(self.filepath) or "."
        handle, temp_path = tempfile.mkstemp(prefix=".traffic-", suffix=".json.tmp", dir=directory)
        try:
            with os.fdopen(handle, "w") as f:
                json.dump(json_data, f)
                f.flush()
                os.fsync(f.fileno())
            if os.path.exists(self.filepath):
                os.chmod(temp_path, os.stat(self.filepath).st_mode & 0o777)
            os.replace(temp_path, self.filepath)
        except BaseException:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    def _set_aside_unreadable_file(self, exc: Exception):
        """Keep an unreadable traffic.json for inspection and start with empty history."""
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        target = f"{self.filepath}.unreadable-{stamp}"
        try:
            os.replace(self.filepath, target)
            warning(f"Traffic data in {self.filepath} could not be read ({exc}); moved it to {target} "
                    "and started with empty traffic history.")
        except OSError as move_error:
            warning(f"Traffic data in {self.filepath} could not be read ({exc}) or moved aside "
                    f"({move_error}); using empty traffic history.")

    def load_data(self) -> Dict[datetime, Dict[str, TrafficData]]:
        data = {}
        if not os.path.exists(self.filepath):
            self._load_cache_signature = None
            self._load_cache_data = None
            return data
        stat_result = os.stat(self.filepath)
        signature = (stat_result.st_mtime_ns, stat_result.st_size)
        if signature == self._load_cache_signature and self._load_cache_data is not None:
            # Callers treat the samples as read-only and only add a top-level
            # entry for the live session, so a shallow copy of the outer dict is
            # enough. A deepcopy here cost about a second per page with a few
            # months of hourly history.
            return dict(self._load_cache_data)
        try:
            with open(self.filepath, "r") as f:
                json_data = json.load(f)
            for k, v in json_data.items():
                device_data = {}
                for device, traffic_data in v.items():
                    device_data[device] = TrafficData(traffic_data["rx"], traffic_data["tx"])
                data[datetime.strptime(k, self.timestamp_format)] = device_data
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            # json.JSONDecodeError and strptime failures are ValueErrors.
            self._set_aside_unreadable_file(exc)
            self._load_cache_signature = None
            self._load_cache_data = None
            return {}
        # Calculate interfaces traffic data
        data_with_interfaces = {
            timestamp: {device: TrafficData(sample.rx, sample.tx, sample.last_handshake)
                        for device, sample in samples.items()}
            for timestamp, samples in data.items()
        }
        peers = get_all_peers()
        for timestamp, peer in data.items():
            for uuid, peer_data in peer.items():
                peer = peers.get(uuid, None)
                if not peer:
                    continue
                iface = peer.interface
                if iface.uuid not in data_with_interfaces[timestamp]:
                    data_with_interfaces[timestamp][iface.uuid] = TrafficData(rx_bytes=peer_data.tx,
                                                                              tx_bytes=peer_data.rx)
                    continue
                data_with_interfaces[timestamp][iface.uuid].tx += peer_data.rx
                data_with_interfaces[timestamp][iface.uuid].rx += peer_data.tx
        self._load_cache_signature = signature
        self._load_cache_data = data_with_interfaces
        return dict(data_with_interfaces)

    def __to_yaml_dict__(self) -> Dict[str, Any]:
        dct = super(TrafficStorageDriverJson, self).__to_yaml_dict__()
        return dct

    @classmethod
    def __from_yaml_dict__(cls: Type[Y], dct: Dict[str, Any], yaml_tag: str = "") -> Y:
        timestamp_format = dct.get("timestamp_format", None)
        return TrafficStorageDriverJson(timestamp_format)
