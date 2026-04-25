# ARPVPN

ARPVPN is a self-hosted WireGuard management panel with a web UI and API.
It is designed for teams that want to manage interfaces and client configs from one place while keeping deployment simple.

## What it does

- Manage WireGuard interfaces and peers from the web UI.
- Generate, download, and QR-export peer configurations.
- Track traffic usage and view dashboard/RRD bandwidth graphs.
- Use role-based accounts (`admin`, `support`, `tenant_admin`, `client`).
- Secure logins with optional TOTP MFA and recovery codes.
- Manage TLS mode directly in the UI (HTTP, self-signed, Let's Encrypt, reverse proxy).

## Quick Start (Docker)

```bash
cd docker
cp .env.example .env
./up.sh up -d --build --force-recreate arpvpn
```

Open:

- `http://<server-ip>:8085`
- `https://<server-ip>:8086`

Important `.env` values:

- `ARPVPN_IMAGE` (default `arpvpn:local`)
- `ARPVPN_CONTAINER_NAME`
- `DATA_FOLDER`
- `ARPVPN_HTTP_PORT`
- `ARPVPN_HTTPS_PORT`
- `ARPVPN_SECURE_COOKIES`

If `DATA_FOLDER` was created by root previously:

```bash
sudo chown -R "$(id -u):$(id -g)" ./data
```

## Install as a Service

```bash
chmod +x install.sh
sudo ./install.sh
sudo systemctl start arpvpn.service
```

## API

- OpenAPI source: `docs/source/api/openapi.v1.yaml`
- Generated Python SDK: `sdk/python`
- Versioning notes: `API_VERSIONING.md`
- Changelog process: `API_CHANGELOG_PROCESS.md`
- Threat model: `API_THREAT_MODEL.md`

Cookie-authenticated API writes require a CSRF token from `GET /api/v1/auth/csrf`.

## Documentation

Sphinx documentation lives in `docs/source`.
