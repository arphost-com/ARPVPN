# WireGuard MFA Roadmap

This roadmap tracks the remaining work around the MFA boundary for ARPVPN.

## Current Direction

- Keep one account-level MFA system in the web app.
- Use that same MFA state to protect web login and client-area access.
- Let clients download their WireGuard config from the client area after authenticating through the web UI.
- Do not add a separate WireGuard-specific MFA stack unless the product later needs a different access model.

## Now

- [ ] Confirm the exact policy for config downloads: whether a client can download immediately after a successful MFA login, or whether downloads should require a fresh MFA challenge.
- [ ] Make the client-area wording explicit that one MFA flow protects web login, client-area access, and WireGuard config downloads.
- [ ] Clarify that WireGuard clients do not get a second login prompt after the tunnel is up.

## Next

- [ ] Add a reusable guard for WireGuard peer download and QR endpoints.
- [ ] Apply that guard consistently to the web UI and API download paths.
- [ ] Keep client-owned downloads working while preserving staff visibility and role checks.
- [ ] Make the client area clear about how to enable MFA before downloading or regenerating a WireGuard config.

## Later

- [ ] Add regression tests for login MFA, client peer download, and QR export.
- [ ] Audit older docs and screenshots for wording that implies a second MFA system.
- [ ] Decide whether any future VPN-access flow should reuse the existing account MFA or live as a separate feature entirely.

## Open Question

- [ ] If the product ever needs a true in-tunnel 2FA gate for WireGuard traffic, define the access model first. WireGuard itself does not provide an interactive login prompt, so any such feature must happen before config issuance or through a separate access-control layer.
