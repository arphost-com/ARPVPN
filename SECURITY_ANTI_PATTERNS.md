# ARPVPN Security Anti-Patterns (From Scan Sheets 1 + 2)

This list is derived from:
- `Scan_Report_-_http___10.10.10.96_8929_arphost_ARPVPN.git (1).csv` (359 rows including header)
- `Scan_Report_-_http___10.10.10.96_8929_arphost_ARPVPN.git (2).csv` (29 rows including header)

Combined findings: **386** (critical: 2, high: 30, medium: 86, low: 263, info: 5).

## Never Introduce These Patterns

| Anti-pattern | Seen in scans | Required safe pattern |
|---|---:|---|
| `subprocess` with `shell=True` | 2 | Use argument arrays with `shell=False`, validate/allowlist commands. |
| Open redirects from request-controlled `next` values | 6 | Redirect only to allowlisted internal routes from `url_for()`. |
| Flask bound to `0.0.0.0` by default | 2 | Default to loopback; only expose publicly via explicit env config/reverse proxy. |
| Unescaped template output via `|safe` on dynamic values | 33 | Keep Jinja auto-escaping; use strict sanitization/allowlists when HTML is required. |
| Dynamic vars in `href/src` or unquoted attributes | 9 | Quote attributes and validate schemes/hosts before rendering links. |
| Hardcoded credentials or placeholder passwords | 12 | Pull secrets from env/secret stores; fail startup if missing secure values. |
| Non-crypto RNG for security material (`random`) | 4 | Use `secrets`/`os.urandom` for tokens, keys, password material. |
| Runtime reliance on `assert` for security checks | 236 | Use explicit exceptions/validation logic in production code paths. |
| Docker images running as root / missing hardening | 4 | Use non-root `USER`, absolute `WORKDIR`, and `HEALTHCHECK`. |
| Test-only insecure config leaking into scans | 4 | Keep in test scope only; annotate/suppress in scans with clear justification. |
| Plaintext `http://` links in docs/templates | 10 | Use `https://` links (or relative paths) except explicit localhost cases. |
| Stale vulnerable dependencies in lockfiles | many CVEs | Keep `pyproject.toml` + `poetry.lock` updated together and patch quickly. |

## Dependency Hygiene Rules

- Treat `poetry.lock` as required whenever dependency constraints change.
- Prefer direct pins/constraints for transitively vulnerable packages when scanner visibility is needed.
- Raise supported Python baseline when secure package versions require it.

## Pre-Commit Security Checklist

- `rg -n "shell=True|\|safe|WTF_CSRF_ENABLED\s*=\s*False|TESTING\s*=\s*True" arpvpn`
- `rg -n "http://" docs arpvpn/web/templates`
- `rg -n "assert\s+" arpvpn --glob '!arpvpn/tests/**'`
- Ensure Dockerfile contains non-root `USER`, absolute `WORKDIR`, and `HEALTHCHECK`.
- Run tests in container before push.
