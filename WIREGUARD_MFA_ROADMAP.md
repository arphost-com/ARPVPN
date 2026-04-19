# WireGuard MFA Roadmap

This roadmap tracks the remaining work around the MFA boundary for ARPVPN.

## Current Direction

- Keep one account-level MFA system in the web app.
- Use that same MFA state for web login.
- Let clients download their WireGuard config from the client area after authenticating through the web UI.
- Avoid introducing a separate WireGuard-specific MFA stack unless the product explicitly needs a different access model.

## Now

- [ ] Confirm the exact policy for config downloads: whether a client can download immediately after a successful MFA login, or whether downloads should require a fresh MFA challenge.
- [ ] Make the client-area wording explicit about where MFA lives and what it protects.

## Next

- [ ] Add a reusable guard for WireGuard peer download and QR endpoints.
- [ ] Apply that guard consistently to the web UI and API download paths.
- [ ] Keep client-owned downloads working while preserving staff visibility and role checks.

## Later

- [ ] Add regression tests for login MFA, client peer download, and QR export.
- [ ] Audit older docs and screenshots for wording that implies a second MFA system.
- [ ] Decide whether any future VPN-access flow should reuse the existing account MFA or live as a separate feature entirely.

## Open Question

- [ ] If the product needs a true in-tunnel 2FA gate for WireGuard traffic, define the access model first. WireGuard itself does not provide an interactive login prompt, so any such feature will need to happen before config issuance or through a separate access-control layer.
