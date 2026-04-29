
# ARPVPN
### by ARPHost, LLC. https://arphost.com

## ARPVPN is a self-hosted WireGuard control plane with a web UI and API for operating client VPN and site-to-site connectivity.

<img width="1382" height="895" alt="Screenshot 2026-04-28 at 7 41 37 PM" src="https://github.com/user-attachments/assets/c824c399-e905-44f8-ab17-86e7f4a09375" />
<img width="1394" height="959" alt="Screenshot 2026-04-28 at 7 41 46 PM" src="https://github.com/user-attachments/assets/b036ffe1-4828-429c-9505-206afdf10caf" />
<img width="1224" height="549" alt="Screenshot 2026-04-28 at 7 15 46 PM" src="https://github.com/user-attachments/assets/8400efb6-4100-4624-b4af-799295bd2b1e" />
<img width="1491" height="866" alt="Screenshot 2026-04-28 at 7 16 25 PM" src="https://github.com/user-attachments/assets/38cad4f9-899d-44be-aaac-196d7b66d3a5" />
<img width="1487" height="887" alt="Screenshot 2026-04-28 at 7 16 14 PM" src="https://github.com/user-attachments/assets/0787937a-138c-4b30-8829-0d8821477a2b" />
<img width="1480" height="892" alt="Screenshot 2026-04-28 at 7 16 45 PM" src="https://github.com/user-attachments/assets/1135b8ad-202c-463f-9544-1b9f73327111" />


## Project Origin and Thanks

ARPVPN was originally forked from [Linguard](https://github.com/joseantmazonsb/linguard), created and open-sourced by **José Antonio Mazón San Bartolomé** ([joseantmazonsb](https://github.com/joseantmazonsb)).

Thank you to José for building Linguard and releasing it as GPL software. ARPVPN is built on top of that foundation and has expanded into a broader operations/API platform.

As of April 27, 2026, Linguard's latest published release on GitHub is `1.1.0` (released October 21, 2021).

Reference baseline from Linguard upstream:
- Repository: https://github.com/joseantmazonsb/linguard
- Original feature summary and installation model are documented in its README.

## What Changed From Linguard to ARPVPN

| Area | Linguard baseline | ARPVPN today |
| --- | --- | --- |
| Core product scope | WireGuard web GUI | WireGuard operations platform (UI + versioned API + SDK artifacts) |
| Peer model | Client peers | Client peers + site-to-site peers + remote subnet support + full-tunnel toggle |
| User model | Basic account model | Role-based model with `admin`, `support`, `tenant_admin`, `client` |
| Multi-tenant lifecycle | Not present | Tenants, tenant members, invitations, runtime planning, tenant config/TLS/runtime APIs |
| Auth model | Session login | Session auth + bearer tokens + refresh/revoke + forced logout + scope-aware auth |
| API security | Basic web protections | CSRF enforcement for cookie APIs, API rate limits, auth lockouts, idempotency, request IDs, audit events |
| MFA | Not in original baseline | TOTP + recovery codes + optional enforcement for client config download |
| TLS operations | External/proxy guidance | Managed TLS modes in app: HTTP, self-signed, Let's Encrypt, reverse proxy, optional HTTP->HTTPS redirect |
| Observability | Traffic charts | Dashboard + detailed statistics + failure diagnostics + RRD graph rendering/caching/prefetch + CSV/JSON exports |
| Automation surface | Limited | `/api/v1` coverage for auth, users, tenants, wireguard, stats, setup, system, tls, themes, config |
| API contract tooling | Not present | OpenAPI source, validation tooling, generated Python SDK, contract checks in CI |
| Packaging/deploy | systemd + docker basics | Hardened container defaults, healthcheck, non-root runtime, CI packaging/publish pipeline |

## Feature Overview

### WireGuard Operations

- Create, edit, remove, start, stop, and restart interfaces.
- Create, edit, remove, enable/disable peers.
- Download interface/peer configs and QR payloads.
- Support client and site-to-site peer modes.
- Managed local route helpers on interfaces.

### Access Control and Identity

- Role-based access: `admin`, `support`, `tenant_admin`, `client`.
- Tenant objects, memberships, and invitation flows.
- Staff impersonation workflows for support use-cases.
- Profile management and password update APIs.

### Security Features

- Password hashing via Werkzeug.
- TOTP MFA and recovery codes.
- API token lifecycle: issue, refresh, revoke, revoke-all, forced logout.
- Rate limiting and auth lockout controls.
- CSRF protection for cookie-authenticated mutating API requests.
- Security headers (CSP, X-Frame-Options, HSTS in strict HTTPS mode).

### Observability and Diagnostics

- Live/session traffic + persisted traffic history.
- Statistics summaries, rollups, and alerts.
- RRD graphs (multiple windows) for peers and interfaces.
- Log-derived diagnostics for auth/interface/TLS/RRD failures.
- CSV/JSON export endpoints for automation.

### API and SDK

- Versioned API prefix: `/api/v1`.
- OpenAPI source of truth: `docs/source/api/openapi.v1.yaml`.
- Generated Python SDK artifact: `sdk/python`.
- API feature-flag toggles via environment variables (auth/system/stats/tls/config/tenants/wireguard groups).

## Quick Start (Docker, Recommended)

Prerequisites:
- Linux host with WireGuard support and Docker + Docker Compose.
- Ability to run containers with `NET_ADMIN`/`NET_RAW` capabilities.

1. Enter the docker folder and copy env template.

```bash
cd docker
cp .env.example .env
```

2. Build and run.

```bash
./up.sh up -d --build --force-recreate arpvpn
```

3. Open the UI.

- `http://<server-ip>:8085`
- `https://<server-ip>:8086`

4. If your mounted data path is not writable by your user, fix ownership once.

```bash
sudo chown -R "$(id -u):$(id -g)" ./data
```

Important Docker `.env` values:
- `ARPVPN_IMAGE`: image/tag to run; default local build is `arpvpn:local`.
- `ARPVPN_UID` / `ARPVPN_GID`: UID/GID created for the image's `arpvpn` user; defaults are `1000:1000`, but set these to match the owner of `DATA_FOLDER` on your host when needed.
- `ARPVPN_RUNTIME_USER`: container runtime user; keep `arpvpn` unless you built a matching custom user/sudo policy.
- `ARPVPN_CONTAINER_NAME`: container name and default cookie namespace source.
- `ARPVPN_COOKIE_SUFFIX`: optional explicit cookie namespace suffix; if unset, ARPVPN uses `ARPVPN_CONTAINER_NAME`, then Docker Compose's `COMPOSE_PROJECT_NAME`, then `arpvpn`.
- `ARPVPN_SESSION_COOKIE_NAME` / `ARPVPN_REMEMBER_COOKIE_NAME`: optional explicit cookie names for side-by-side installs.
- `ARPVPN_HTTP_PORT` / `ARPVPN_HTTPS_PORT`: host-network listener ports, default `8085` and `8086`.
- `ARPVPN_SECURE_COOKIES`: `0` for mixed HTTP/HTTPS access, `1` for strict HTTPS-only cookie behavior.
- `DATA_FOLDER`: host path mounted to `/data`.

The `docker/up.sh` wrapper reads `docker/.env` by default. Set `ENV_FILE=/path/to/envfile` when you want the wrapper and Compose to use a different env file.

Optional runtime tuning env variables:
- `ARPVPN_HIGH_TRAFFIC_THRESHOLD_MB`: peer traffic alert threshold, default `1024`.
- `ARPVPN_RRD_GRAPH_CACHE_TTL_SECONDS`: RRD graph cache TTL, default `10800`.
- `ARPVPN_LOG_DIAGNOSTICS_CACHE_TTL_SECONDS` / `ARPVPN_LOG_DIAGNOSTICS_READ_BLOCK_BYTES`: log diagnostic cache/read sizing.
- `ARPVPN_API_ACCESS_TTL_SECONDS` / `ARPVPN_API_REFRESH_TTL_SECONDS`: API token lifetimes.
- `ARPVPN_API_AUTH_WINDOW_SECONDS` / `ARPVPN_API_AUTH_MAX_ATTEMPTS` / `ARPVPN_API_AUTH_LOCKOUT_SECONDS`: API auth rate/lockout controls.
- `ARPVPN_API_RATE_LIMIT_WINDOW_SECONDS` / `ARPVPN_API_RATE_LIMIT_MAX_REQUESTS`: general API rate limit controls.
- `ARPVPN_FEATURE_API_AUTH`, `ARPVPN_FEATURE_API_STATS`, `ARPVPN_FEATURE_API_SYSTEM`, `ARPVPN_FEATURE_API_TLS`, `ARPVPN_FEATURE_API_CONFIG`, `ARPVPN_FEATURE_API_TENANTS`, `ARPVPN_FEATURE_API_WIREGUARD`: set to `0`/`false` to disable an API group.
- `ARPVPN_AUDIT_SIGNING_KEY`: optional audit event signing key override.
- `ARPVPN_TENANT_RUNTIME_PORT_STRIDE`, `ARPVPN_TENANT_RUNTIME_HTTP_BASE`, `ARPVPN_TENANT_RUNTIME_HTTPS_BASE`, `ARPVPN_TENANT_RUNTIME_VPN_BASE`: tenant runtime port allocation controls.
- `ARPVPN_REPOSITORY_URL` / `ARPVPN_LICENSE_URL`: optional links shown in app metadata/templates.

## Systemd Install

If you deploy from source checkout:

```bash
chmod +x scripts/install.sh
sudo ./scripts/install.sh
sudo systemctl start arpvpn.service
sudo systemctl enable arpvpn.service
```

If you deploy from a release tarball built by `build.sh`, the installer is copied as `install.sh` at the release root.

## First-Time Admin Workflow

1. Open `/signup` and create the first admin account.
2. Complete `/setup` and verify endpoint/TLS choices.
3. Create a WireGuard interface.
4. Add client peers or site-to-site peers.
5. Download peer configs and import on client devices.
6. Validate handshake/traffic health in `/dashboard`, `/wireguard`, and `/statistics`.

## API Usage Notes

### Cookie-authenticated API writes

For mutating calls with session cookies, include CSRF token from:
- `GET /api/v1/auth/csrf`

### Bearer token flow

Issue token pair:

```bash
curl -sS -X POST "http://127.0.0.1:8085/api/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"REPLACE_ME","scope":"all"}'
```

List interfaces with bearer token:

```bash
curl -sS "http://127.0.0.1:8085/api/v1/wireguard/interfaces" \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

Refresh token:

```bash
curl -sS -X POST "http://127.0.0.1:8085/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'
```

## Configuration and Data Layout

Runtime workdir stores state such as:
- `arpvpn.yaml` (main config)
- `.credentials` (encrypted users)
- `.tenants` (encrypted tenants)
- `.invitations` (encrypted invitations)
- interface config files under `interfaces/`
- logs and traffic artifacts

In Docker deployments, this state is typically under host `DATA_FOLDER` mounted to container `/data`.

## Repository Map

High-confidence active components:

- `arpvpn/`: Flask app, WireGuard models/managers, API/UI routes, security, templates/static assets.
- `scripts/`: OpenAPI validation/generation, SDK generation, packaging/install helpers.
- `docker/`: container image, compose runtime, startup wrapper scripts.
- `sdk/python/`: generated API client artifact checked by CI drift detection.
- `docs/source/`: Sphinx docs + OpenAPI spec.

## Development and Quality Gates

Common local commands:

- Validate OpenAPI:

```bash
python3 scripts/validate_openapi.py
```

- Verify generated artifacts are current:

```bash
./scripts/check_api_artifacts.sh
```

## Security Notes

- Keep TLS enabled in production environments.
- Avoid exposing debug Flask mode publicly.
- Keep dependencies current (`poetry.lock` and `requirements.txt`).
- Use strong admin credentials and enable MFA for privileged users.

## License

ARPVPN is distributed under GPL-3.0. See [LICENSE.md](LICENSE.md).
