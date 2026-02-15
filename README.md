# ARPVPN

[![GitHub](https://img.shields.io/github/license/arphost-com/ARPVPN)](LICENSE.md) ![Python version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11-blue?logo=python&logoColor=yellow) [![Stable workflow status](https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml/badge.svg)](https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml) [![Latest workflow status](https://github.com/arphost-com/ARPVPN/actions/workflows/latest-test.yaml/badge.svg)](https://github.com/arphost-com/ARPVPN/actions/workflows/latest-test.yaml) [![codecov](https://codecov.io/gh/arphost-com/ARPVPN/branch/main/graph/badge.svg)](https://codecov.io/gh/arphost-com/ARPVPN)

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

1. Download the [`docker-compose.yaml` file](https://raw.githubusercontent.com/arphost-com/ARPVPN/main/docker/docker-compose.yaml).
2. Run ARPVPN:
   ```bash
   sudo docker-compose up -d
   ```
NOTE: You can check all available tags [here](https://github.com/arphost-com/ARPVPN/pkgs/container/arpvpn/versions).
