# Release notes

## What's new

### 1.2.4

* Fixed TLS listener behavior to keep HTTP (`8085`) and HTTPS (`8086`) available together in self-signed/Let's Encrypt modes.
* Fixed HTTP access when HTTPS is enabled without redirect by only forcing secure cookies in strict-HTTPS mode.
* Updated HTTP-to-HTTPS redirect targets to include the configured HTTPS port when it is not `443`.
* Updated setup defaults to start with self-signed TLS and automatic certificate generation.
* Added TLS status metadata for web listener ports and strict-HTTPS mode to the API.

### 1.2.3

* Fixed production RRD graph support by installing `rrdtool` in the packaged runtime dependencies.
* Improved traffic history APIs/graphs to include current session data even when hourly persistence has not run yet.
* Added coverage to ensure history endpoints still return usable points when only session data is available.
* Reworked application footer to remove GitHub links and use ARPHost branding in light/dark themes.
* Expanded the About page with platform overview, ARPHost information, revision/build details, and WireGuard background.

### 1.2.2

* Added scoped statistics APIs for admins/clients including per-connection history and RRD metadata endpoints.
* Added TLS management APIs for mode switching, self-signed generation, Let's Encrypt issue/renew, and certificate status.
* Standardized API error/success envelopes for JSON APIs and added request ID propagation (`X-Request-ID`).
* Expanded tests and CI hard-gate coverage for statistics and TLS API behavior.

### 1.2.1

* Improved theme consistency on the login screen by fixing browser autofill color overrides.
* Added a configurable option to redirect HTTP requests to HTTPS when TLS mode is active.
* Added an expanded top-right theme switcher and settings-page quick theme controls.

### Previous updates

* Ban time is now editable and applies to individual IP addresses instead of globally (which makes much more sense).

## Fixes

* Fixed a bug with the settings page which caused the display of default/last saved settings everytime the page was reloaded, even though the values were actually being stored in the configuration file and applied.

## Docs

* Added entry for ban time.
