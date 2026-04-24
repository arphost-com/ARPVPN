import os
from datetime import datetime
from typing import Dict
import json

import pytest

from arpvpn.core.drivers.traffic_storage_driver import TrafficData
from arpvpn.core.drivers.traffic_storage_driver_json import TrafficStorageDriverJson
from arpvpn.core.drivers import traffic_storage_driver_json as traffic_driver_json_module


class TrafficStorageDriverJsonMock(TrafficStorageDriverJson):

    def __init__(self):
        super().__init__()

    def get_session_and_stored_data(self) -> Dict[datetime, Dict[str, TrafficData]]:
        return {
            datetime.strptime("15/09/2021 15:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("15/09/2021 16:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("15/09/2021 17:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("15/09/2021 18:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("15/09/2021 19:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("15/09/2021 20:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("15/09/2021 21:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("15/09/2021 22:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("15/09/2021 23:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("16/09/2021 00:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("16/09/2021 01:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)},
            datetime.strptime("16/09/2021 02:24:34", self.DEFAULT_TIMESTAMP_FORMAT):
                {"39a855187c4c4ca694d8c3f215e76cdd": TrafficData(0, 0), "39a855187c4c4ca694d8c3f215e76cde": TrafficData(0, 0)}
        }


class TestJsonTrafficDriver:

    @pytest.fixture(autouse=True)
    def cleanup(self):
        yield
        driver = getattr(self, "driver", None)
        if driver and os.path.exists(driver.filepath):
            os.remove(driver.filepath)

    def test_load_no_data(self):
        self.driver = TrafficStorageDriverJson()
        data = self.driver.get_session_and_stored_data()
        assert data is not None
        assert len(data) == 0

    def test_store_no_data(self):
        self.driver = TrafficStorageDriverJson()
        self.driver.save_data()
        data = self.driver.load_data()
        assert data is not None
        assert len(data) == 0

    def test_load_data(self):
        self.driver = TrafficStorageDriverJson()
        with open(self.driver.filepath, "w") as f:
            f.write("""
            {"15/09/2021 15:24:34": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "15/09/2021 15:25:02": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "15/09/2021 15:27:58": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "15/09/2021 15:32:14": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "15/09/2021 15:34:26": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "15/09/2021 15:35:15": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "15/09/2021 15:40:04": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "15/09/2021 16:28:00": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "15/09/2021 16:28:06": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "15/09/2021 16:29:39": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "21/09/2021 00:10:30": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "21/09/2021 00:11:34": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "21/09/2021 00:16:07": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "21/09/2021 00:17:01": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:42:26": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:42:46": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:43:01": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:46:28": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:52:52": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:52:56": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:53:05": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:57:40": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:57:53": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:58:27": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:58:51": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 22:59:08": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:00:14": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:01:04": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:02:02": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:13:26": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:32:03": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:34:39": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:39:37": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:40:43": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:45:07": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:46:33": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:48:07": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:48:26": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:48:49": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:49:09": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:51:02": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:51:42": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:52:06": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:52:58": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:53:21": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:53:41": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:54:28": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:56:15": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "28/09/2021 23:56:30": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "29/09/2021 00:09:35": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}, "04/10/2021 19:37:40": {"39a855187c4c4ca694d8c3f215e76cdd": {"rx": 0, "tx": 0}, "39a855187c4c4ca694d8c3f215e76cde": {"rx": 0, "tx": 0}}}
            """)
        data = self.driver.get_session_and_stored_data()
        assert data is not None
        assert len(data) > 0

    def test_store_data(self):
        self.driver = TrafficStorageDriverJsonMock()
        self.driver.save_data()
        data = self.driver.load_data()
        assert data is not None
        assert len(data) > 0

    def test_store_data_keeps_devices_after_interface_entries(self, monkeypatch, tmp_path):
        class OrderedTrafficDriver(TrafficStorageDriverJson):
            def __init__(self):
                super().__init__()

            def get_session_and_stored_data(self):
                timestamp = datetime.strptime("15/09/2021 15:24:34", self.DEFAULT_TIMESTAMP_FORMAT)
                return {
                    timestamp: {
                        "peer-before": TrafficData(1, 2),
                        "iface-uuid": TrafficData(3, 4),
                        "peer-after": TrafficData(5, 6),
                    }
                }

        monkeypatch.setattr(traffic_driver_json_module, "interfaces", {"iface-uuid": object()})
        monkeypatch.setattr(
            traffic_driver_json_module.global_properties,
            "join_workdir",
            lambda filename: str(tmp_path / filename),
        )

        driver = OrderedTrafficDriver()
        driver.save_data()

        with open(driver.filepath, "r", encoding="utf-8") as handle:
            payload = json.load(handle)

        stored_devices = payload["15/09/2021 15:24:34"]
        assert "peer-before" in stored_devices
        assert "peer-after" in stored_devices
        assert "iface-uuid" not in stored_devices

    def test_load_data_keeps_multiple_interfaces_separate(self, monkeypatch, tmp_path):
        class DummyInterface:
            def __init__(self, uuid: str):
                self.uuid = uuid

        class DummyPeer:
            def __init__(self, interface):
                self.interface = interface

        iface_main = DummyInterface("iface-main")
        iface_extra = DummyInterface("iface-extra")
        peer_main = DummyInterface("peer-main")
        peer_extra = DummyInterface("peer-extra")

        monkeypatch.setattr(
            traffic_driver_json_module,
            "interfaces",
            {iface_main.uuid: object(), iface_extra.uuid: object()},
        )
        monkeypatch.setattr(
            traffic_driver_json_module,
            "get_all_peers",
            lambda: {
                peer_main.uuid: DummyPeer(iface_main),
                peer_extra.uuid: DummyPeer(iface_extra),
            },
        )
        monkeypatch.setattr(
            traffic_driver_json_module.global_properties,
            "join_workdir",
            lambda filename: str(tmp_path / filename),
        )

        driver = TrafficStorageDriverJson()
        with open(driver.filepath, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "15/09/2021 15:24:34": {
                        peer_main.uuid: {"rx": 10, "tx": 20},
                        peer_extra.uuid: {"rx": 30, "tx": 40},
                    }
                },
                handle,
            )

        loaded = driver.load_data()
        sample = loaded[datetime.strptime("15/09/2021 15:24:34", driver.DEFAULT_TIMESTAMP_FORMAT)]
        assert sample[iface_main.uuid].rx == 20
        assert sample[iface_main.uuid].tx == 10
        assert sample[iface_extra.uuid].rx == 40
        assert sample[iface_extra.uuid].tx == 30
