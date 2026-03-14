# ARPVPN

[![GitHub](https://img.shields.io/github/license/arphost-com/ARPVPN)](LICENSE.md) ![Python version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=yellow) [![Stable workflow status](https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml/badge.svg)](https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml) [![Latest workflow status](https://github.com/arphost-com/ARPVPN/actions/workflows/latest-test.yaml/badge.svg)](https://github.com/arphost-com/ARPVPN/actions/workflows/latest-test.yaml) [![codecov](https://codecov.io/gh/arphost-com/ARPVPN/branch/main/graph/badge.svg)](https://codecov.io/gh/arphost-com/ARPVPN)

[![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/arphost-com/ARPVPN?color=green&include_prereleases&logo=github)](https://github.com/arphost-com/ARPVPN/releases) [![GitHub all releases](https://img.shields.io/github/downloads/arphost-com/ARPVPN/total?logo=github)](https://github.com/arphost-com/ARPVPN/releases)


ARPVPN aims to provide a clean, simple yet powerful web GUI to manage your WireGuard server, and it's powered by Flask.

**[Read the docs](https://github.com/arphost-com/ARPVPN/tree/codex/multitenant-v2/docs) for further information!**

## Key features

* Management of Wireguard interfaces and peers via web. Interfaces can be created, removed, edited, exported and brought up and down directly from the web GUI. Peers can be created, removed, edited and downloaded at anytime as well.
* Display stored and real time traffic data using charts (storage of traffic data may be manually disabled).
* Display general network information.
* Encrypted user credentials (AES).
* Multi-user roles (`admin`, `support`, `client`) with staff impersonation of client sessions for troubleshooting.
* API v1 with cookie/session and bearer token auth modes, plus mesh control-plane APIs.
* Easy management through the ``arpvpn`` systemd service.

## API docs

* OpenAPI source: `docs/source/api/openapi.v1.yaml`
* Versioning policy: `API_VERSIONING.md`
* API changelog process: `API_CHANGELOG_PROCESS.md`
* Migration notes: `API_MIGRATION_NOTES.md`
* Threat model: `API_THREAT_MODEL.md`

Cookie-authenticated API writes require a CSRF token from `GET /api/v1/auth/csrf`.
Bearer-token API requests do not require that CSRF header.
Tenant runtime planning for separate VPN stacks is exposed under `/api/v1/tenants/<tenant_id>/runtime`.

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

1. Copy `docker/docker-compose.yaml`, `docker/.env.example`, and `docker/up.sh` from this repository.
2. Create `.env` from the example and set values for your host:
   ```bash
   cp .env.example .env
   ```
   Important variables in `.env`:
   * `ARPVPN_IMAGE` (image/tag to run)
   * `ARPVPN_RUNTIME_USER` (runtime user inside the container, default `arpvpn`)
   * `ARPVPN_CONTAINER_NAME` (container name; set unique value when running multiple stacks)
   * `ARPVPN_COOKIE_SUFFIX` (optional cookie namespace suffix; defaults to container name)
   * `ARPVPN_SESSION_COOKIE_NAME` / `ARPVPN_REMEMBER_COOKIE_NAME` (optional explicit cookie names; auto-derived from container name if omitted)
   * `ARPVPN_SECURE_COOKIES` (`0` for mixed HTTP/HTTPS access, `1` for strict HTTPS)
   * `ARPVPN_HTTP_PORT` (HTTP bind port, defaults to `8085`)
   * `ARPVPN_HTTPS_PORT` (HTTPS bind port, defaults to `8086`)
   * `DATA_FOLDER` (host path mounted to `/data`)
   Suggested image tags by release line:
   * v1 (`main`): `10.10.10.96:5050/arphost/arpvpn:stable`
   * v2 (`codex/multitenant-v2`): `10.10.10.96:5050/arphost/arpvpn:v2-latest`
   For side-by-side testing, use separate `DATA_FOLDER` and host ports for each line.
3. Pull and start:
   ```bash
   ./up.sh pull
   ./up.sh up -d --force-recreate arpvpn
   ```
   `up.sh` and compose create `DATA_FOLDER` automatically if missing and refuse to continue if ownership/permissions are wrong.
4. If `DATA_FOLDER` already exists as `root:root` from a previous deployment, fix it once:
   ```bash
   sudo chown -R "$(id -u):$(id -g)" ./data
   ```
5. Run ARPVPN (without the wrapper) if preferred:
   ```bash
   docker compose up -d --force-recreate arpvpn
   ```
   When `network_mode: host` is enabled, Docker prints a warning that published ports are discarded. This is expected.

TLS can be configured from the UI (`Settings -> Web`):
* `Direct HTTP` for plain HTTP.
* `Self-signed certificate` to generate and apply a local certificate. HTTP (`8085`) and HTTPS (`8086`) both stay available by default.
* `Let's Encrypt certificate` to issue/renew with `certbot` and apply it to ARPVPN.
* `Behind reverse proxy` to keep ARPVPN on HTTP and define the proxy incoming hostname.
* `Redirect HTTP to HTTPS` can be enabled when TLS mode is active to force strict HTTPS behavior.

For Let's Encrypt issuance, your hostname must resolve publicly to the host and inbound port `80/tcp` must be reachable.
NOTE: Check available tags in your GitLab project's Container Registry and pin if needed.

### Deploy multitenant (`codex/multitenant-v2`)

Use this exact flow when you want the multitenant line:

1. Clone the multitenant branch:
   ```bash
   git clone --branch codex/multitenant-v2 ssh://git@10.10.10.96:2424/arphost/ARPVPN.git
   cd ARPVPN/docker
   ```
2. Create `.env` from the example:
   ```bash
   cp .env.example .env
   ```
3. Set these required values in `.env`:
   ```env
   ARPVPN_IMAGE=10.10.10.96:5050/arphost/arpvpn:v2-latest
   ARPVPN_CONTAINER_NAME=arpvpn-v2
   DATA_FOLDER=./data-v2
   ARPVPN_HTTP_PORT=8085
   ARPVPN_HTTPS_PORT=8086
   ARPVPN_SECURE_COOKIES=0
   ```
4. Pull and start:
   ```bash
   ./up.sh pull
   ./up.sh up -d --force-recreate arpvpn
   ```
5. Open the UI:
   * HTTP: `http://<server-ip>:8085`
   * HTTPS: `https://<server-ip>:8086`

Important behavior:
* ARPVPN binds on `0.0.0.0` for both HTTP and HTTPS in Docker mode.
* If `Redirect HTTP to HTTPS` is enabled in UI settings, HTTP requests are redirected to HTTPS.
* Keep `ARPVPN_SECURE_COOKIES=0` if you want HTTP login to work when redirect is disabled.
* If you enable strict HTTPS behavior, use HTTPS URL consistently (do not switch between hostnames/IPs mid-session).

Running multiple multitenant stacks on one host:
* Give each stack unique values for:
  * `ARPVPN_CONTAINER_NAME`
  * `ARPVPN_COOKIE_SUFFIX` (or explicit cookie names)
  * `DATA_FOLDER`
  * `ARPVPN_HTTP_PORT`
  * `ARPVPN_HTTPS_PORT`
  * optional explicit cookie names (`ARPVPN_SESSION_COOKIE_NAME`, `ARPVPN_REMEMBER_COOKIE_NAME`) if you keep the same hostname
* Example second stack:
  ```env
  ARPVPN_CONTAINER_NAME=arpvpn-v2-b
  DATA_FOLDER=./data-v2-b
  ARPVPN_HTTP_PORT=18085
  ARPVPN_HTTPS_PORT=18086
  ```

### GitLab CI/CD and Registry setup

Project CI builds and publishes ``arpvpn`` image to GitLab Container Registry.

1. Ensure project runner is Docker executor with ``privileged = true``.
2. Ensure Container Registry is enabled in GitLab.
3. Push by release line to publish (only after ``unit_tests`` CI job passes):
   * ``main`` + ``v1.*`` tags publish ``stable``/``1.2.x`` and commit/tag images.
   * ``codex/multitenant-v2`` + ``v2.*`` tags publish ``v2-latest`` and commit/tag images.
4. Optional environment/integration tests can be run by setting pipeline variable
   ``RUN_ENV_INTEGRATION_TESTS=1`` (non-blocking; informative only).
5. Optional API contract tests run as ``api_contract_tests`` (non-blocking) and validate
   the OpenAPI document plus the focused API/security regression subset.
6. API endpoint groups can be toggled with environment flags such as
   ``ARPVPN_FEATURE_API_MESH=0`` or ``ARPVPN_FEATURE_API_WIREGUARD=0`` for staged rollout.

For full setup details, see ``docs/source/gitlab-deployment.rst``.

### Clean docker02 validation

When validating fresh release-line behavior on `docker02`, keep only these two working clones:

- `/home/debian/docker/arpvpn`
- `/home/debian/docker/arpvpn-mutlitenant`

For a full clean test:

1. Delete the target directory you want to refresh.
2. `git clone` the branch back into one of those two paths.
3. Run validation from that fresh clone rather than creating extra `arpvpn-*` staging directories.

Fresh end-to-end validation on `docker02` was completed on 2026-03-13 for both `main` and `codex/multitenant-v2`.

## Release lines

This project keeps current and multitenant releases separate:

- `main` is the current `1.2.x` fix-only line.
- `codex/multitenant-v2` is the multitenant `2.x` line.

See [RELEASE_STRATEGY.md](RELEASE_STRATEGY.md) for branch, tag, and image publishing rules.
