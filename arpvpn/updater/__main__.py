import os

from arpvpn.updater.core import DEFAULT_REPOSITORY, Updater
from arpvpn.updater.docker_api import DockerClient


def main():
    target = (os.environ.get("ARPVPN_UPDATER_TARGET", "") or "arpvpn").strip()
    data_dir = (os.environ.get("ARPVPN_UPDATER_DATA", "") or "/data").strip()
    buildargs = {}
    for key in ("ARPVPN_UID", "ARPVPN_GID"):
        value = (os.environ.get(key, "") or "").strip()
        if value.isdigit():
            buildargs[key] = value
    updater = Updater(
        data_dir=data_dir,
        target=target,
        docker=DockerClient(os.environ.get("ARPVPN_UPDATER_DOCKER_SOCKET", "/var/run/docker.sock")),
        repository=DEFAULT_REPOSITORY,
        buildargs=buildargs,
    )
    print(f"ARPVPN updater watching {data_dir} for update requests for container '{target}'.", flush=True)
    updater.run_forever()


if __name__ == "__main__":
    main()
