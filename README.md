
# ARPVPN
### by ARPHost, LLC. https://arphost.com

#### ARPVPN is a self-hosted WireGuard control plane with a web UI and API for operating client VPN and site-to-site connectivity.

<img width="1376" height="1153" alt="Screenshot 2026-05-18 at 6 05 14 AM" src="https://github.com/user-attachments/assets/581a49a7-3c0a-426c-b897-2e2cf99aaa19" />
<img width="1378" height="1156" alt="Screenshot 2026-05-18 at 6 04 55 AM" src="https://github.com/user-attachments/assets/cc4728e7-9c96-40b1-b4c8-923cec704e6a" />

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
- `WIREGUARD_TOOLS_VERSION` / `WIREGUARD_TOOLS_SHA256`: Docker build inputs for the upstream WireGuard Tools release compiled into the image; defaults track the current verified upstream release used by this repo.
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

## Private Deployment Pipeline

`.gitlab-ci.yml` is safe for this public repository because it contains no secret
values. The GitLab workflow only runs in a private GitLab project, and deployment
only runs on a protected default branch with masked/protected CI variables.

Pipeline order:
- Local/API tests and generated artifact checks run first.
- The Docker image is published to the private GitLab registry.
- docker02 staging deploy and smoke validation run automatically.
- Production deploy is a manual GitLab job and uses the same tested image.

Keep SSH keys, registry tokens, hostnames, deploy paths, and health-check URLs in
private CI/CD variables only. See `docs/source/gitlab-deployment.rst`.

## Security Notes

- Keep TLS enabled in production environments.
- Avoid exposing debug Flask mode publicly.
- Keep dependencies current (`poetry.lock` and `requirements.txt`).
- Use strong admin credentials and enable MFA for privileged users.

## Screenshots
<img width="1153" height="1018" alt="Screenshot 2026-05-18 at 5 51 12 AM" src="https://github.com/user-attachments/assets/c8d3ea10-8d8a-4fd9-93a6-5a2004395d0c" />
<img width="1140" height="641" alt="Screenshot 2026-05-18 at 5 53 25 AM" src="https://github.com/user-attachments/assets/1f4d55d3-ee1c-47d6-b5b2-4fedce6d31d2" />
<img width="1154" height="845" alt="Screenshot 2026-05-18 at 5 54 46 AM" src="https://github.com/user-attachments/assets/fb516814-140b-408f-a3d6-0a21ad41bfbf" />
<img width="1124" height="1019" alt="Screenshot 2026-05-18 at 5 54 53 AM" src="https://github.com/user-attachments/assets/6f9b8a89-2bb8-4bea-9d67-cd81373cd4b0" />
<img width="1165" height="896" alt="Screenshot 2026-05-18 at 5 55 47 AM" src="https://github.com/user-attachments/assets/67ef7a14-b2ad-48d4-aed3-e3c40fcde31a" />
<img width="1148" height="931" alt="Screenshot 2026-05-18 at 5 56 17 AM" src="https://github.com/user-attachments/assets/c3a43e04-922a-4c89-8049-2ba0de209af1" />
<img width="1121" height="1092" alt="Screenshot 2026-05-18 at 5 56 42 AM" src="https://github.com/user-attachments/assets/586dbe66-8c3a-471a-aca9-7937edfea66f" />
<img width="1122" height="288" alt="Screenshot 2026-05-18 at 5 56 55 AM" src="https://github.com/user-attachments/assets/c8c2a055-2098-432a-89d1-3a317173bffc" />
<img width="1135" height="1110" alt="Screenshot 2026-05-18 at 5 57 21 AM" src="https://github.com/user-attachments/assets/34592744-c0fa-4822-9f44-1a06eddd02ae" />
<img width="1373" height="1154" alt="Screenshot 2026-05-18 at 5 57 31 AM" src="https://github.com/user-attachments/assets/e5406ae9-058d-4ad7-bcc3-ed456c121f63" />
<img width="1364" height="1161" alt="Screenshot 2026-05-18 at 5 57 49 AM" src="https://github.com/user-attachments/assets/bb973b6c-1f69-4346-a1be-2068a8f8c0bb" />
<img width="1369" height="1176" alt="Screenshot 2026-05-18 at 5 58 02 AM" src="https://github.com/user-attachments/assets/9754090c-242e-4f9b-9316-f593f5b3e0ea" />
<img width="1145" height="1059" alt="Screenshot 2026-05-18 at 6 01 51 AM" src="https://github.com/user-attachments/assets/4ae50a73-bb45-4d34-b1a5-7e7bcda35e7f" />
<img width="1113" height="906" alt="Screenshot 2026-05-18 at 6 01 59 AM" src="https://github.com/user-attachments/assets/d091dc1d-496b-4297-bcce-ca0df1b88a54" />
<img width="1378" height="1156" alt="Screenshot 2026-05-18 at 6 04 55 AM" src="https://github.com/user-attachments/assets/0897f8e0-e53a-49b1-9be6-55616dd0a17a" />
<img width="1376" height="1153" alt="Screenshot 2026-05-18 at 6 05 14 AM" src="https://github.com/user-attachments/assets/64263e09-a6fd-482c-ac50-39fa3aa55145" />
<img width="1393" height="1190" alt="Screenshot 2026-05-18 at 6 05 28 AM" src="https://github.com/user-attachments/assets/6368951e-8f07-49b7-b285-af70af69aacc" />


## License

ARPVPN is distributed under GPL-3.0. See [LICENSE.md](LICENSE.md).
