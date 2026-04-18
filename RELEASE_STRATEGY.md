# Release Strategy

This repository is the private ARPVPN line.

## Branch Roles

- `main`: current release line (`2.x`).
- `codex/*`: temporary working branches used for implementation and review.

## API Docs and Changelog Discipline

- Keep OpenAPI as source of truth:
  - `docs/source/api/openapi.v1.yaml`
- Validate OpenAPI in CI using `scripts/validate_openapi.py`.
- Follow `API_CHANGELOG_PROCESS.md` for every API change.

## Version and Tag Policy

- Release tags: `v2.0.0-alpha.1`, `v2.0.0-beta.1`, `v2.0.0`, ...

`v2.*` tags must be created from `main`.

## CI Publish Rules

GitLab CI is configured so images are published for the release line:

- Publish jobs run only after the `unit_tests` job succeeds.
- Full-suite environment/integration tests run only when `RUN_ENV_INTEGRATION_TESTS=1` and are non-blocking.

- `main` + `v2.*` tags publish:
  - `$CI_REGISTRY_IMAGE:latest`
  - `$CI_REGISTRY_IMAGE:2.x`
  - `$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA` (branch builds)
  - `$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG` (tag builds)

## Hotfix Flow

1. Land fix in `main`.
2. Release `v2.*` as needed.
3. If the public single-tenant repository also needs the fix, cherry-pick it there separately.

## Runtime Isolation

Use a dedicated runtime path per tenant deployment and do not share state directories between environments.

## Protection Recommendations

- Protect `main`.
- Require merge requests for protected branches.
- Require at least one reviewer for release-affecting changes.
- Restrict `v2.*` tag creation to maintainers.
