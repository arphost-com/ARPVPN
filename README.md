# ARPVPN

[![GitHub](https://img.shields.io/github/license/arphost-com/ARPVPN)](LICENSE.md) ![Python version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=yellow) [![Stable workflow status](https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml/badge.svg)](https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml) [![Latest workflow status](https://github.com/arphost-com/ARPVPN/actions/workflows/latest-test.yaml/badge.svg)](https://github.com/arphost-com/ARPVPN/actions/workflows/latest-test.yaml) [![codecov](https://codecov.io/gh/arphost-com/ARPVPN/branch/main/graph/badge.svg)](https://codecov.io/gh/arphost-com/ARPVPN)

[![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/arphost-com/ARPVPN?color=green&include_prereleases&logo=github)](https://github.com/arphost-com/ARPVPN/releases) [![GitHub all releases](https://img.shields.io/github/downloads/arphost-com/ARPVPN/total?logo=github)](https://github.com/arphost-com/ARPVPN/releases)


ARPVPN aims to provide a clean, simple yet powerful web GUI to manage your WireGuard server, and it's powered by Flask.

**[Read the docs](https://github.com/arphost-com/ARPVPN/tree/main/docs) for further information!**

## Key features

* Management of Wireguard interfaces and peers via web. Interfaces can be created, removed, edited, exported and brought up and down directly from the web GUI. Peers can be created, removed, edited and downloaded at anytime as well.
* Display stored and real time traffic data using charts (storage of traffic data may be manually disabled).
* Display general network information.
* Encrypted user credentials (AES).
* Easy management through the ``arpvpn`` systemd service.

## Installation

### As a `systemd` service

1. Download [any release](https://github.com/arphost-com/ARPVPN/releases).
    
2. Extract it and run the installation script:
    ```bash
    chmod +x install.sh
    sudo ./install.sh
    ```
3. Run ARPVPN:
    ```bash
    sudo systemctl start arpvpn.service
    ```

### Docker

1. Copy the `docker/docker-compose.yaml` file from this repository.
2. Set your GitLab Container Registry image path:
   ```bash
   export ARPVPN_IMAGE="registry.example.com/group/project/arpvpn:stable"
   ```
3. Configure cookie security according to how you expose the UI:
   ```bash
   # Direct HTTP access (for example http://host:8080)
   export ARPVPN_SECURE_COOKIES=0
   # Reverse proxy / HTTPS access
   # export ARPVPN_SECURE_COOKIES=1
   ```
4. Run ARPVPN:
   ```bash
   sudo docker-compose up -d
   ```
NOTE: Check available tags in your GitLab project's Container Registry.

### GitLab CI/CD and Registry setup

Project CI builds and publishes ``arpvpn`` image to GitLab Container Registry.

1. Ensure project runner is Docker executor with ``privileged = true``.
2. Ensure Container Registry is enabled in GitLab.
3. Push to default branch to publish:
   * ``$CI_REGISTRY_IMAGE:stable``
   * ``$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA``

For full setup details, see ``docs/source/gitlab-deployment.rst``.
