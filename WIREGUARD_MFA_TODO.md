# WireGuard MFA TODO

This list tracks the remaining work around the MFA boundary for ARPVPN.

* [ ] Clarify in the client area that account MFA is configured once in Profile and is reused for web login.
* [ ] Decide whether peer download and QR export should require a fresh MFA check before revealing a config.
* [ ] Decide whether any future WireGuard-specific auth layer should be integrated without duplicating the existing account MFA state.
* [ ] Add regression tests for the documented MFA flow so web login and WireGuard peer access stay aligned.
* [ ] Review whether any existing docs still imply a separate WireGuard 2FA stack.
