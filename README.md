
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

## Install

Full guides live in `docs/source/`:
[Installation](docs/source/installation.rst),
[Getting started](docs/source/usage.rst), and
[Troubleshooting](docs/source/troubleshooting.rst).

### Before you start: open the firewall

ARPVPN uses **host networking**, so Docker does not open any firewall ports for it.
Open these on the host firewall (UFW, CSF, firewalld, or your control panel's firewall) and any provider firewall.

| Port | Protocol | Used for |
| --- | --- | --- |
| 8085 | TCP | Web UI over HTTP |
| 8086 | TCP | Web UI over HTTPS, once enabled in setup and the app is restarted |
| Interface listen port (random 50000+) | UDP | WireGuard clients, one per interface |

```bash
sudo ufw allow 8085/tcp
sudo ufw allow 8086/tcp
sudo ufw allow <wireguard-port>/udp
```

In Stack Manager with CSF, add them under **Settings > Firewall**. The project's **Open Ports (CSF)** button cannot see them
because ARPVPN publishes no Docker ports.

### Option 1. Stack Manager

1. Catalog > **Security, Identity & VPN** > **ARPVPN** > Deploy. Defaults are fine.
2. Wait for the first build to finish. It compiles WireGuard tools and takes a few minutes.
3. Open the firewall ports above.
4. Browse to `http://<server-ip>:8085`.

### Option 2. Docker Compose

```bash
git clone https://github.com/arphost-com/ARPVPN.git
cd ARPVPN/docker
cp .env.example .env      # adjust ports or DATA_FOLDER if needed
./up.sh                   # builds and starts; first build takes a few minutes
docker ps --filter name=arpvpn   # wait for "healthy"
```

Then open the firewall ports and browse to `http://<server-ip>:8085`. `up.sh` creates `DATA_FOLDER` with the right owner. If you run
`docker compose` yourself, run `sudo chown -R 1000:1000 <DATA_FOLDER>` first.

### Option 3. systemd

```bash
sudo ./scripts/install.sh
sudo systemctl enable --now arpvpn.service
```

### Main `.env` settings

- `ARPVPN_HTTP_PORT` / `ARPVPN_HTTPS_PORT`: web ports, default `8085` and `8086`.
- `DATA_FOLDER`: host folder for config, users, keys and logs. Back it up.
- `ARPVPN_CONTAINER_NAME`: make it unique when running more than one ARPVPN per host.
- `ARPVPN_SECURE_COOKIES`: `0` allows HTTP and HTTPS logins, `1` is HTTPS only.
- `ARPVPN_IMAGE`, `ARPVPN_UID`, `ARPVPN_GID`, `ARPVPN_RUNTIME_USER`: leave at defaults unless you know you need them.

Every other variable, including API rate limits and feature flags, is listed in the
[installation guide](docs/source/installation.rst).

## Updating

From 3.1.0, administrators update Docker installs from **Settings > Updates**. The tab
shows the newest GitHub release and its changelog and installs it with one click. A
separate `arpvpn-updater` container does the rebuild, so the web container never gets
Docker access, and a failed update rolls back on its own. See
[Getting started](docs/source/usage.rst#updating-arpvpn).

## First Login

1. Open the UI. A new install sends you to `/signup` to create the admin account. There is no default password.
2. On `/setup`, check the **Endpoint** (the public IP or hostname VPN clients connect to) and pick a TLS mode. HTTPS on 8086 starts after **Settings > Restart app** or a container restart.
3. On **WireGuard**, create an interface. Set **Gateway** to the host's internet-facing NIC and open its UDP listen port in the firewall.
4. Add peers, then download the config or scan the QR code in the WireGuard app.
5. A recent handshake on the dashboard means the client is connected.

See [Getting started](docs/source/usage.rst) for the details.

## Can't Reach the Web UI?

Run these on the server.

```bash
docker ps --filter name=arpvpn           # running and healthy?
docker logs --tail 50 arpvpn             # startup errors
curl -sI http://127.0.0.1:8085 | head -1 # answers locally?
```

If it answers locally but not from outside, a firewall is blocking the port. A connection
that times out (rather than being refused) points the same way. Open 8085/8086 as shown
above. More symptoms and fixes are in [Troubleshooting](docs/source/troubleshooting.rst).

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
- Repository/Compose validation, Python tests, OpenAPI checks, and generated artifact checks run on docker02.
- Semgrep, Trivy, Gitleaks, TruffleHog, Dependency-Check, and Bandit block unsafe builds.
- An immutable commit image is published and scanned before docker02 deployment.
- docker02 deploy and smoke jobs require a healthy container, the expected image digest, and safe service-user ownership.
- The tested digest is promoted to the release and ``stable`` tags only after docker02 passes.
- Docker03 production deployment and rollback are manual and use the same validated registry image.
- GitHub synchronization is a separate final manual job after successful production deployment; GitLab remains authoritative.

Keep the GitHub publication token, deploy paths, host-specific ports, and
health-check URLs in protected private CI/CD variables only. The host-local
docker02 and docker03 runners do not require deployment SSH keys. See
`docs/source/gitlab-deployment.rst`.

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
