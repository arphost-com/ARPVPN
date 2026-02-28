# Release Strategy

This repository uses two release trains to keep the current product stable while multi-tenant work evolves independently.

## Branch Roles

- `main`: current non-multitenant release line (`1.2.x`), fix-only.
- `codex/multitenant-v2`: multitenant development and `2.x` releases.

Do not merge `codex/multitenant-v2` into `main`.

## API Docs and Changelog Discipline

- Keep OpenAPI as source of truth:
  - v1 line: `docs/source/api/openapi.v1.yaml`
  - v2 line: maintain matching v2 OpenAPI file in the v2 branch.
- Validate OpenAPI in CI using `scripts/validate_openapi.py`.
- Follow `API_CHANGELOG_PROCESS.md` for every API change on both lines.

## Version and Tag Policy

- `v1` line tags: `v1.2.1`, `v1.2.2`, ...
- `v2` line tags: `v2.0.0-alpha.1`, `v2.0.0-beta.1`, `v2.0.0`, ...

`v1.*` tags must be created from `main` (or a v1 maintenance branch).
`v2.*` tags must be created from `codex/multitenant-v2`.

## CI Publish Rules

GitLab CI is configured so images are published by release line:

- Publish jobs run only after the `unit_tests` job succeeds.
- Full-suite environment/integration tests run only when `RUN_ENV_INTEGRATION_TESTS=1` and are non-blocking.

- `main` + `v1.*` tags publish:
  - `$CI_REGISTRY_IMAGE:stable`
  - `$CI_REGISTRY_IMAGE:1.2.x`
  - `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA` (branch builds)
  - `$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG` (tag builds)

- `codex/multitenant-v2` + `v2.*` tags publish:
  - `$CI_REGISTRY_IMAGE:v2-latest`
  - `$CI_REGISTRY_IMAGE:v2-$CI_COMMIT_SHORT_SHA` (branch builds)
  - `$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG` (tag builds)

This prevents multitenant builds from overwriting `stable`.

## Hotfix Flow

1. Land fix in `main`.
2. Release `v1.*` as needed.
3. Cherry-pick relevant commits into `codex/multitenant-v2`.

Do not backport multi-tenant schema or behavior into `main`.

## Runtime Isolation

Use separate runtime paths and hostnames for each line:

- v1: `/srv/arpvpn-v1`, production hostname.
- v2: `/srv/arpvpn-v2`, staging/preprod hostname (or dedicated v2 hostname).

Do not share state directories between release lines.

## Protection Recommendations

- Protect `main` and `codex/multitenant-v2`.
- Require merge requests for both protected branches.
- Require at least one reviewer for v1 and v2 changes.
- Restrict tag creation:
  - `v1.*` tags for maintainers of v1 line
  - `v2.*` tags for maintainers of v2 line
