from types import SimpleNamespace

import pytest

from arpvpn.tests.utils import default_cleanup
from arpvpn.web import router as web_router


@pytest.fixture(autouse=True)
def cleanup():
    yield
    default_cleanup()


def test_generate_rrd_graph_returns_none_when_no_points(monkeypatch):
    monkeypatch.setattr(web_router, "get_connection_traffic_points", lambda uuid: [])
    assert web_router.generate_rrd_graph_png("abc123", 24 * 60 * 60) is None


def test_generate_rrd_graph_uses_sparse_history_heartbeat_and_masks_unknown(monkeypatch, tmp_path):
    points = [
        (1_700_000_000, 100, 200),
        (1_700_003_600, 250, 400),
        (1_700_007_200, 350, 550),
    ]
    monkeypatch.setattr(web_router, "get_connection_traffic_points", lambda uuid: points)
    monkeypatch.setattr(web_router.global_properties, "join_workdir", lambda _: str(tmp_path))

    commands = []

    def fake_subprocess_run(cmd, capture_output, text, check):
        commands.append(cmd)
        if len(cmd) > 2 and cmd[1] == "graph":
            with open(cmd[2], "wb") as handle:
                handle.write(b"PNGDATA")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(web_router.subprocess, "run", fake_subprocess_run)

    payload = web_router.generate_rrd_graph_png("deadbeef", 24 * 60 * 60)
    assert payload == b"PNGDATA"

    create_cmd = next(cmd for cmd in commands if len(cmd) > 2 and cmd[1] == "create")
    rx_ds = next(item for item in create_cmd if item.startswith("DS:rx:COUNTER:"))
    tx_ds = next(item for item in create_cmd if item.startswith("DS:tx:COUNTER:"))
    rx_heartbeat = int(rx_ds.split(":")[3])
    tx_heartbeat = int(tx_ds.split(":")[3])
    assert rx_heartbeat >= 7200
    assert tx_heartbeat >= 7200

    graph_cmd = next(cmd for cmd in commands if len(cmd) > 2 and cmd[1] == "graph")
    assert "CDEF:rxs=rx,UN,0,rx,IF" in graph_cmd
    assert "CDEF:txs=tx,UN,0,tx,IF" in graph_cmd
    assert "LINE2:rxs#1f77b4:Received rate" in graph_cmd
    assert "LINE2:txs#ff7f0e:Transmitted rate" in graph_cmd
