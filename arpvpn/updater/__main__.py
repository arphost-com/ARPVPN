import os

from arpvpn.updater.core import DEFAULT_REPOSITORY, TARBALL_URL, Updater
from arpvpn.updater.docker_api import DockerClient


def tarball_url_from_env() -> str:
    override = (os.environ.get("ARPVPN_UPDATER_TARBALL_URL", "") or "").strip()
    if override and "{tag}" in override and override.split(":", 1)[0] in ("https", "file"):
        return override
    if override:
        print("Ignoring ARPVPN_UPDATER_TARBALL_URL: it must be an https:// or file:// URL containing {tag}.", flush=True)
    return TARBALL_URL


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
        # Release archive location. Only the host admin can set this (it is the
        # updater's own environment, never the web app's). Used for mirrors and
        # for testing with file:// archives; must contain {tag}.
        tarball_url=tarball_url_from_env(),
    )
    print(f"ARPVPN updater watching {data_dir} for update requests for container '{target}'.", flush=True)
    updater.run_forever()


if __name__ == "__main__":
    main()
