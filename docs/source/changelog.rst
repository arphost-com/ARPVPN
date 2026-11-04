Changelog
=========

All notable changes to this project will be documented here.

.. note::
    ARPVPN is adhered to `Semantic Versioning <https://semver.org/>`__.

3.2.1
-----

* Production is no longer deployed by the GitLab pipeline. ``deploy:production``
  is gone and ``publish:github`` now runs after the docker02 smoke test, so the
  release tag reaches GitHub first and production updates itself from
  **Settings > Updates** like any customer install. ``rollback:production`` stays
  as a manual emergency job. No application changes beyond 3.2.0.

3.2.0
-----

* The web UI is much faster, especially over HTTPS and from far away. uWSGI now
  runs its HTTP/HTTPS router with keep-alive, so the browser reuses one
  connection instead of doing a new TLS handshake for every page, script and
  stylesheet. The worker runs four threads, so one slow page no longer holds
  up every other request. Requests that change settings still run one at a time.
* Existing installs move to the new listener settings by themselves on the
  first start after the update. ARPVPN rewrites ``uwsgi.yaml`` and reloads
  twice, which takes the UI away for a few seconds. Ports and certificates are
  kept.
* Dashboard, Statistics and the peer and interface pages no longer copy the
  whole traffic history on every request. On installs with months of history
  this was most of the time spent building those pages.
* Static files are served under a versioned path and cached by the browser for
  a year. A new release changes the path, so nothing stale is kept.
* The theme choice is rendered into the page instead of fetched from
  ``/api/v1/themes`` on every page load.
* Font Awesome is loaded as a stylesheet instead of the JavaScript build that
  rewrote every icon into SVG after the page loaded.
* ``ARPVPN_HTTP_PORT`` and ``ARPVPN_HTTPS_PORT`` now always win over the ports
  saved in ``arpvpn.yaml``, so saving TLS settings and pressing **Restart app**
  no longer moves the UI to the default ports.
* **Check now** on the Updates tab shows that it is checking and then reports
  the result, instead of looking like nothing happened.

3.1.1
-----

* The ``publish:github`` job now authenticates with the global ``GITHUB_PAT``
  GitLab CI variable instead of a project level ``GITHUB_PUSH_TOKEN`` copy, so
  the GitHub token is rotated in one place. No application changes.

3.1.0
-----

* Added an Updates tab to Settings. It shows the installed version, the newest
  ARPVPN release on GitHub and that release's changelog, and lets an
  administrator install it with one click.
* Added the ``arpvpn-updater`` container to the Docker Compose stack. It holds
  the Docker socket so the web container never does, publishes no ports, drops
  all capabilities except file access to the data folder, and only acts on
  release tags from the ARPVPN GitHub repository. It rebuilds the image from the
  tagged source, replaces the ARPVPN container, and restores the previous
  container automatically if the new one does not become healthy.
* Installs that run a registry image from a deployment pipeline report that
  they are pipeline managed and cannot be updated from the tab.
* The GitHub publication job now also pushes a ``vX.Y.Z`` release tag, which
  is what the Updates tab offers.
* Added ``GET`` and ``POST /api/v1/system/update`` for administrators.

3.0.8
-----

* Updated Pillow to 13.0.0, certifi to 2026.10.23, urllib3 to 2.8.0 and
  Werkzeug to 3.1.9 to clear critical and high advisories reported by the
  repository vulnerability gate. Pillow 13 requires Python 3.11, so the supported Python floor moves from
  3.10 to 3.11. The container image already runs Python 3.14.
* Rewrote the installation guide with Stack Manager, Docker Compose and systemd
  paths, a ports table and host firewall steps, and added Getting started and
  Troubleshooting guides. The README install section now links to them.

3.0.7
-----

* Keep the dashboard focused on operational health by moving all interface and
  peer configuration actions to the dedicated WireGuard management page.
* Propagate WireGuard collector failures and render affected handshake and
  session-traffic values as unavailable instead of false ``never`` and ``0 B``
  readings.
* Render genuine peers without a recorded handshake as ``Never`` rather than
  the ambiguous ``None`` value.

3.0.6
-----

* Load and apply persisted configuration exactly once during application
  startup, before importing request routes, avoiding duplicate configuration
  writes and redundant WireGuard interface apply work.
* Add regression coverage for the single-owner startup initialization order.
* Harden GitHub publication authentication by forcing the allowlisted remote to
  use the non-secret token username, a prompt-insensitive askpass response, and
  an explicit interactive-credential override for GitLab Runner checkouts that
  otherwise suppress askpass execution.

3.0.3
-----

* Preserved legacy ARPVPN Pro mesh route, topology, and VPN-link objects while
  loading and saving existing production configuration.
* Hardened failed-smoke restoration by verifying and reusing the exact locally
  cached previous image when current project credentials cannot pull its older
  registry repository.

3.0.2
-----

* Updated ``cryptography`` and Pillow to patched releases required by the
  blocking repository and image vulnerability gates.
* Removed build-only pip and its vendored package inventory from the final
  runtime image, reducing its attack surface and eliminating vulnerable tooling
  that the application never executes.
* Replaced key-shaped sample configuration values with explicit non-secret
  placeholders so examples cannot be mistaken for deployable credentials.

Pipeline restoration and deployment safety
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Restored private GitLab CI/CD as the authoritative test, security, image, and deployment workflow.
* Added blocking repository and container-image security scans on the docker02 runner.
* Added immutable image-digest deployment, strict docker02 health and ownership smoke checks, and post-staging image promotion.
* Added final manual docker03 production deployment with failed-smoke restoration plus an explicit manual rollback job.
* Added a separate final manual, non-force GitHub synchronization job after successful production deployment.

3.0.1
-----

Performance and UX fixes
~~~~~~~~~~~~~~~~~~~~~~~~

* Removed global background RRD prefetching that could monopolize the single request worker.
* Batched RRD sample updates into one ``rrdtool`` call and limited the graph detail page to its selected time window.
* Reused unchanged traffic-history parsing and shared live WireGuard telemetry reads within request bursts.
* Kept optional peer provisioning disabled by default when creating users and limited peer changes to affected interfaces.
* Added create/delete progress feedback and post/redirect/get completion handling for user management.

3.0.0
-----

Major Upgrade
~~~~~~~~~~~~~

* Upgraded the Docker runtime base image to ``python:3.14-slim-trixie``.
* Upgraded core runtime dependencies, including ``cryptography`` 47.0.0 and ``Faker`` 40.15.0.
* Refreshed the Poetry lockfile and exported runtime requirements with Poetry 2.3.4.
* Upgraded documentation tooling to Sphinx 9.1.0 and sphinx-rtd-theme 3.1.0 for Python 3.12+ doc builds.
* Updated the generated Python SDK dependency floor to ``requests>=2.33.1``.
* Validated the upgraded build on docker02 with API contract tests, server tests, Docker image build, and a healthy container smoke test.

1.1.0
-----

What's new
~~~~~~~~~~

* Ban time is now editable and applies to individual IP addresses instead of globally (which makes much more sense).

Fixes
~~~~~

* Fixed a bug with the settings page which caused the display of default/last saved settings everytime the page was reloaded, even though the values were actually being stored in the configuration file and applied.

Docs
~~~~

* Added entry for ban time.

1.0.1
-----

Fixes
~~~~~

* Fixed a bug related to versioning which caused the app to start in dev mode.

Docs
~~~~

* Removed "Versions" empty section from index.


1.0.0
-----

What's new
~~~~~~~~~~

* QR codes! You can scan a QR code to get the WireGuard configuration of any peer or interface.
* Docker is finally here! For now on, there will be official docker images available for every release.
* Display the IP address of the interface to be used when adding or editing a peer.
* Updating the name of an interface also updates all references inside the "On up" and "On down" text areas.
* Delete buttons have been relocated in the Interface and Peer views.

Fixes
~~~~~

* Fixed a bug when updating the username or password which made the "Logged in {time} ago" sign show no time at all.
* Removed the possibility to add peers if there are no WireGuard interfaces.
* Ensured that peers can only be assigned valid, unused and not reserved IP addressed.
* Ensured that peers' IP addresses are in the same network of their interface.
* Ensured that interfaces can only be assigned valid, unused and not reserved IP addressed.
* Ensured that interfaces' cannot be assigned an IP address belonging to a network which already has an interface.
* Fixed a bug when updating an interface's gateway, which only updated one appearance of the previous gateway in the
  "On up" and "On down" text areas.
* Fixed the behaviour of the ``overwrite`` flag regarding the logging settings which was causing to overwrite the log
  file each time the settings were saved instead of every time ARPVPN boots up.

Docs
~~~~

* Improved documentation about the development environment.
* Fixed a bunch of typos.
* Fixed the Traffic Data Driver table.

0.2.0
-----

* Easy first time setup, which automatically detects the location of the required binaries and sets the public IP as endpoint by default.
* Everything in one place: workdir-based architecture.
* Removed option to log to standard output.
* Includes a ready-to-go uWSGI configuration file.
* Removed the ``arpvpn.sample.yaml`` file in favour of the first time setup.
* Settings are now accessible through the side navbar.
