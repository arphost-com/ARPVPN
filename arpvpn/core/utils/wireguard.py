from subprocess import PIPE, run

from arpvpn.common.utils.system import Command
from arpvpn.core.exceptions import WireguardError


def is_wg_iface_up(iface_name: str) -> bool:
    from arpvpn.core.config.wireguard import config
    return Command(f"{config.wg_bin} show {iface_name}").run_as_root().successful


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
