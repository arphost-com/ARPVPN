import re
from shutil import which
from subprocess import PIPE, run

from arpvpn.core.exceptions import WireguardError


def _parse_ip_link_is_up(stdout: str) -> bool:
    text = str(stdout or "")
    flag_match = re.search(r"<([^>]+)>", text)
    if flag_match:
        flags = [item.strip().upper() for item in flag_match.group(1).split(",") if item.strip()]
        if "UP" in flags:
            return True
    return "STATE UP" in text.upper()


def is_wg_iface_up(iface_name: str) -> bool:
    # Prefer `ip link` because it generally works without elevated privileges.
    try:
        ip_result = run(
            ["ip", "link", "show", "dev", iface_name],
            stdout=PIPE,
            stderr=PIPE,
            text=True,
            check=False,
        )
    except Exception:
        ip_result = None
    if ip_result and ip_result.returncode == 0:
        return _parse_ip_link_is_up(ip_result.stdout)
    if ip_result and ip_result.returncode != 0:
        # Common "not found" outputs should be treated as definitively down.
        combined = f"{ip_result.stdout or ''}\n{ip_result.stderr or ''}".lower()
        if (
            "does not exist" in combined or
            "cannot find device" in combined or
            "not found" in combined or
            "no such device" in combined
        ):
            return False

    # Fallback to `wg show` when `ip` is unavailable or inconclusive.
    from arpvpn.core.config.wireguard import config
    wg_bin = config.wg_bin or which("wg")
    if not wg_bin:
        return False
    try:
        result = run(
            [wg_bin, "show", iface_name],
            stdout=PIPE,
            stderr=PIPE,
            text=True,
            check=False,
        )
    except Exception:
        return False
    return result.returncode == 0


def _run_wg_command(args: list[str], stdin_data: str = "") -> str:
    from arpvpn.core.config.wireguard import config

    try:
        result = run(
            [config.wg_bin, *args],
            input=stdin_data,
            text=True,
            stdout=PIPE,
            stderr=PIPE,
            check=False,
        )
    except Exception as exc:
        raise WireguardError(str(exc)) from exc

    if result.returncode != 0:
        raise WireguardError(result.stderr.strip() or result.stdout.strip())

    return result.stdout.strip()


def generate_privkey() -> str:
    return _run_wg_command(["genkey"])


def generate_pubkey(privkey: str) -> str:
    return _run_wg_command(["pubkey"], f"{privkey.strip()}\n")


def get_wg_interface_status(name: str) -> str:
    if is_wg_iface_up(name):
        return "up"
    return "down"
