from types import SimpleNamespace

import pytest

from arpvpn.core.config.wireguard import config
from arpvpn.core.exceptions import WireguardError
from arpvpn.core.utils import wireguard


def test_generate_privkey_uses_direct_wg_command(monkeypatch):
    calls = []

    def fake_run(cmd, input, text, stdout, stderr, check):
        calls.append({
            "cmd": cmd,
            "input": input,
            "text": text,
            "stdout": stdout,
            "stderr": stderr,
            "check": check,
        })
        return SimpleNamespace(returncode=0, stdout="private-key\n", stderr="")

    monkeypatch.setattr(config, "wg_bin", "/usr/bin/wg")
    monkeypatch.setattr(wireguard, "run", fake_run)

    assert wireguard.generate_privkey() == "private-key"
    assert calls == [{
        "cmd": ["/usr/bin/wg", "genkey"],
        "input": "",
        "text": True,
        "stdout": wireguard.PIPE,
        "stderr": wireguard.PIPE,
        "check": False,
    }]


def test_generate_pubkey_uses_stdin(monkeypatch):
    calls = []

    def fake_run(cmd, input, text, stdout, stderr, check):
        calls.append({
            "cmd": cmd,
            "input": input,
            "text": text,
            "stdout": stdout,
            "stderr": stderr,
            "check": check,
        })
        return SimpleNamespace(returncode=0, stdout="public-key\n", stderr="")

    monkeypatch.setattr(config, "wg_bin", "/usr/bin/wg")
    monkeypatch.setattr(wireguard, "run", fake_run)

    assert wireguard.generate_pubkey("private-key") == "public-key"
    assert calls == [{
        "cmd": ["/usr/bin/wg", "pubkey"],
        "input": "private-key\n",
        "text": True,
        "stdout": wireguard.PIPE,
        "stderr": wireguard.PIPE,
        "check": False,
    }]


def test_generate_pubkey_raises_wireguard_error_on_failure(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="permission denied")

    monkeypatch.setattr(config, "wg_bin", "/usr/bin/wg")
    monkeypatch.setattr(wireguard, "run", fake_run)

    with pytest.raises(WireguardError, match="permission denied"):
        wireguard.generate_pubkey("private-key")


def test_generate_privkey_raises_wireguard_error_on_exec_exception(monkeypatch):
    def fake_run(*args, **kwargs):
        raise OSError("wg missing")

    monkeypatch.setattr(config, "wg_bin", "/usr/bin/wg")
    monkeypatch.setattr(wireguard, "run", fake_run)

    with pytest.raises(WireguardError, match="wg missing"):
        wireguard.generate_privkey()


def test_is_wg_iface_up_returns_true_on_success(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(config, "wg_bin", "/usr/bin/wg")
    monkeypatch.setattr(wireguard, "run", fake_run)

    assert wireguard.is_wg_iface_up("wg0") is True


def test_is_wg_iface_up_returns_false_on_missing_interface(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="Unable to access interface: No such device")

    monkeypatch.setattr(config, "wg_bin", "/usr/bin/wg")
    monkeypatch.setattr(wireguard, "run", fake_run)

    assert wireguard.is_wg_iface_up("wg0") is False


def test_is_wg_iface_up_returns_false_if_wg_missing(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("wg not found")

    monkeypatch.setattr(config, "wg_bin", "/usr/bin/wg")
    monkeypatch.setattr(wireguard, "run", fake_run)

    assert wireguard.is_wg_iface_up("wg0") is False
