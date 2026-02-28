# ARPVPN API Versioning Strategy

This file defines the v1 API compatibility contract.

## Base path

- Current stable API base path: `/api/v1`
- `v1` changes must preserve backward compatibility for existing request/response fields.

## Compatibility rules

- New fields may be added to response payloads without removing existing fields.
- Existing required request fields must not be removed in v1.
- Breaking behavior or schema changes require a new version path (for example `/api/v2`).
- Deprecated endpoints must remain available for at least one minor release in the same line.

## Auth modes

- Cookie/session auth remains supported for browser UI and same-origin API requests.
- Bearer token auth (`/api/v1/auth/token`, `/api/v1/auth/refresh`) is supported for API clients.

## Role mapping

- `super_admin` maps to ARPVPN `admin`.
- `support_admin` maps to ARPVPN `support`.
- `tenant_admin` maps to ARPVPN `support` in v1 line.
- `client` maps to ARPVPN `client`.

## API source of truth

- OpenAPI source file: `docs/source/api/openapi.v1.yaml`
- Validation script: `scripts/validate_openapi.py`
