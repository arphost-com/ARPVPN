from types import SimpleNamespace

from arpvpn.core.models import Interface


def make_interface(name: str = "wg0") -> Interface:
    return Interface(
        name=name,
        description="",
        gw_iface="eth0",
        ipv4_address="10.0.0.1/24",
        listen_port=50000,
        auto=False,
        on_up=[],
        on_down=[],
        private_key="test-private",
        public_key="test-public",
    )


def test_interface_is_up_true_when_ip_link_exists(monkeypatch):
    iface = make_interface("wg0")

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="2: wg0", stderr="")

    monkeypatch.setattr("arpvpn.core.models.run", fake_run)
    assert iface.is_up is True


def test_interface_is_up_false_when_interface_missing(monkeypatch):
    iface = make_interface("wg0")

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="Device \"wg0\" does not exist.")

    monkeypatch.setattr("arpvpn.core.models.run", fake_run)
    assert iface.is_up is False


def test_interface_is_up_false_when_ip_command_missing(monkeypatch):
    iface = make_interface("wg0")

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("ip not found")

    monkeypatch.setattr("arpvpn.core.models.run", fake_run)
    assert iface.is_up is False
