# ARPVPN

[![GitHub](https://img.shields.io/github/license/arphost-com/ARPVPN)](LICENSE.md) ![Python version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=yellow) [![Stable workflow status](https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml/badge.svg)](https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml) [![codecov](https://codecov.io/gh/arphost-com/ARPVPN/branch/main/graph/badge.svg)](https://codecov.io/gh/arphost-com/ARPVPN)

[![GitHub release (latest SemVer including pre-releases)](https://img.shields.io/github/v/release/arphost-com/ARPVPN?color=green&include_prereleases&logo=github)](https://github.com/arphost-com/ARPVPN/releases) [![GitHub all releases](https://img.shields.io/github/downloads/arphost-com/ARPVPN/total?logo=github)](https://github.com/arphost-com/ARPVPN/releases)

ARPVPN aims to provide a clean, simple yet powerful web GUI to manage your WireGuard server, and it's powered by Flask.

**[Read the docs](https://github.com/arphost-com/ARPVPN/tree/main/docs) for further information.**

## Key features

- Management of WireGuard interfaces and peers via web. Interfaces can be created, removed, edited, exported and brought up and down directly from the web GUI. Peers can be created, removed, edited and downloaded at any time as well.
- Display stored and real time traffic data using charts.
- Display general network information.
- Encrypted user credentials (AES).
- Multi-user roles (`admin`, `support`, `client`) with staff impersonation of client sessions for troubleshooting.
- API v1 with cookie or session and bearer token auth modes, plus observability and mesh diagnostics APIs.
- Easy management through the `arpvpn` systemd service.

## API docs

- OpenAPI source: `docs/source/api/openapi.v1.yaml`
- Generated Python SDK: `sdk/python`
- Versioning policy: `API_VERSIONING.md`
- API changelog process: `API_CHANGELOG_PROCESS.md`
- Migration notes: `API_MIGRATION_NOTES.md`
- Threat model: `API_THREAT_MODEL.md`

Cookie-authenticated API writes require a CSRF token from `GET /api/v1/auth/csrf`.
Bearer-token API requests do not require that CSRF header.
Regenerate the contract artifacts with:

```bash
python3 scripts/generate_openapi.py
python3 scripts/generate_sdk.py
```

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
   - `ARPVPN_IMAGE` (image or tag to run)
   - `ARPVPN_RUNTIME_USER` (runtime user inside the container, default `arpvpn`)
   - `ARPVPN_CONTAINER_NAME` (container name; set unique value when running multiple stacks)
   - `ARPVPN_COOKIE_SUFFIX` (optional cookie namespace suffix; defaults to container name)
   - `ARPVPN_SESSION_COOKIE_NAME` / `ARPVPN_REMEMBER_COOKIE_NAME` (optional explicit cookie names; auto-derived from container name if omitted)
   - `ARPVPN_SECURE_COOKIES` (`0` for mixed HTTP or HTTPS access, `1` for strict HTTPS)
   - `ARPVPN_HTTP_PORT` (HTTP bind port, defaults to `8085`)
   - `ARPVPN_HTTPS_PORT` (HTTPS bind port, defaults to `8086`)
   - `DATA_FOLDER` (host path mounted to `/data`)
   Suggested image tags:
   - `10.10.10.96:5050/arphost/arpvpn:stable`
   - `10.10.10.96:5050/arphost/arpvpn:1.2.x`
3. Pull and start:
   ```bash
   ./up.sh pull
   ./up.sh up -d --force-recreate arpvpn
   ```
4. If `DATA_FOLDER` already exists as `root:root` from a previous deployment, fix it once:
   ```bash
   sudo chown -R "$(id -u):$(id -g)" ./data
   ```

TLS can be configured from the UI (`Settings -> Web`):
- `Direct HTTP` for plain HTTP.
- `Self-signed certificate` to generate and apply a local certificate. HTTP (`8085`) and HTTPS (`8086`) both stay available by default.
- `Let's Encrypt certificate` to issue or renew with `certbot` and apply it to ARPVPN.
- `Behind reverse proxy` to keep ARPVPN on HTTP and define the proxy incoming hostname.
- `Redirect HTTP to HTTPS` can be enabled when TLS mode is active to force strict HTTPS behavior.

For Let's Encrypt issuance, your hostname must resolve publicly to the host and inbound port `80/tcp` must be reachable.

### GitLab CI/CD and registry setup

Project CI builds and publishes the stable ARPVPN image to GitLab Container Registry.

1. Ensure the project runner uses Docker executor with `privileged = true`.
2. Ensure Container Registry is enabled in GitLab.
3. Push to the default branch to publish after the required `unit_tests` job passes:
   - `$CI_REGISTRY_IMAGE:stable`
   - `$CI_REGISTRY_IMAGE:1.2.x`
   - `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA`
4. Optional environment or integration tests can be run by setting pipeline variable `RUN_ENV_INTEGRATION_TESTS=1`.
5. Optional API contract tests run as `api_contract_tests` and validate the OpenAPI document plus the focused API or security regression subset.
6. API endpoint groups can be toggled with environment flags such as `ARPVPN_FEATURE_API_MESH=0` or `ARPVPN_FEATURE_API_WIREGUARD=0` for staged rollout.
7. Mesh rollout can be split from API rollout with `ARPVPN_FEATURE_MESH_V1=0` and `ARPVPN_FEATURE_ACL_V1=0`.

For full setup details, see `docs/source/gitlab-deployment.rst`.

### Clean docker02 validation

When validating the public line on `docker02`, use `/home/debian/docker/arpvpn`.

Latest docker02 public-line validation completed on 2026-03-26 for contract checks, unit subset, package build, and Docker image build.
