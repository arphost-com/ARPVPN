Troubleshooting
===============

Start with the quick checks, then find your symptom below. Commands assume the container
is named ``arpvpn``. For a systemd install, use ``journalctl -u arpvpn`` and
``/var/www/arpvpn/data/arpvpn.log`` instead of the Docker commands.

Quick checks
------------

Run these on the server.

.. code-block:: bash

    # Is the container running and healthy?
    docker ps --filter name=arpvpn

    # Recent startup output and errors
    docker logs --tail 100 arpvpn

    # Application log
    tail -n 100 <DATA_FOLDER>/arpvpn.log

    # Is something listening on the web ports?
    sudo ss -ltnp | grep -E ':8085|:8086'

    # Does the UI answer locally?
    curl -sI http://127.0.0.1:8085 | head -1

Then from a different machine:

.. code-block:: bash

    curl -m 5 -sI http://<server-public-ip>:8085 | head -1

How to read the results:

* Local curl works but the remote one times out. A firewall is dropping the port. See
  `The web UI is not reachable on the public IP`_.
* Nothing listens on 8085. The app is not running. Check ``docker logs`` and the sections
  on startup errors below.
* The container is still ``health: starting`` right after a first deploy. The image is
  probably still building or the app is still starting. Wait a few minutes.

The web UI is not reachable on the public IP
--------------------------------------------

ARPVPN binds to all interfaces (``0.0.0.0``), so if it answers on ``127.0.0.1`` it is
running correctly. The block is almost always the firewall.

ARPVPN uses host networking. Docker does not open firewall ports for host network
containers, so CSF, UFW, firewalld, or a provider firewall will drop port 8085 until you
allow it.

* **Stack Manager / CSF.** The project's **Open Ports (CSF)** button does nothing for
  ARPVPN because the compose file has no published ports. Add ``8085`` (and ``8086``) to
  **TCP IN** in **Settings > Firewall** and press **Save + Restart**. Confirm with
  ``sudo csf -l | grep 8085``.
* **Hosting control panels** often run their own firewall on top of the system one.
  If the panel has a firewall page, add the ports there too.
* **UFW.** ``sudo ufw allow 8085/tcp`` and ``sudo ufw allow 8086/tcp``, then check with
  ``sudo ufw status``.
* **firewalld.** ``sudo firewall-cmd --permanent --add-port=8085/tcp && sudo firewall-cmd --reload``
* **Provider firewall or NAT.** Open or forward the port there too.

Also check:

* **LFD blocked you.** CSF's login failure daemon can block your own IP after failed SSH
  or panel logins. Check with ``sudo csf -g <your-ip>`` and remove it with
  ``sudo csf -dr <your-ip>``.
* **IPv6.** The listener is IPv4 only. Browse to the IPv4 address, or make sure the
  hostname you use has an ``A`` record.
* **Rootless Docker, Docker Desktop, or Podman.** Host networking there is not the real
  host network. Use rootful Docker on Linux.

Port 8086 (HTTPS) refuses connections
-------------------------------------

HTTPS is off on a fresh install. It starts only when all of these are true.

1. A TLS mode other than *Direct HTTP* or *Behind reverse proxy* was chosen in setup or
   **Settings**.
2. The certificate was generated or issued without errors. Check ``arpvpn.log``.
3. The application was restarted afterwards with **Settings > Restart app** or
   ``docker restart arpvpn``.
4. Port 8086 is open in the firewall.

Until then use ``http://<server-ip>:8085``.

Redirected to an address that does not load
-------------------------------------------

With **Redirect HTTP requests to HTTPS** on, visitors are sent to the **TLS / External
hostname**. If that field is empty or invalid, ARPVPN falls back to the server's detected
local IP, which is a private address on NAT'd servers. Set the field to the public
hostname or IP in **Settings**, or turn the redirect off while you fix it. You can also
edit ``web.tls_server_name`` and ``web.redirect_http_to_https`` in
``<DATA_FOLDER>/arpvpn.yaml`` and restart the container.

The UI moved to a different port after saving settings
-------------------------------------------------------

Fixed in 3.2.0. ``ARPVPN_HTTP_PORT`` and ``ARPVPN_HTTPS_PORT`` now always win over the
ports saved in ``arpvpn.yaml``. On older versions, set ``web.http_port`` and
``web.https_port`` in ``<DATA_FOLDER>/arpvpn.yaml`` to the same values as the
environment variables.

The web UI is slow
------------------

Check the version on the **About** page first. 3.2.0 changed how the web server runs and
most installs got several times faster, so update from the **Updates** tab if you are on
an older release.

Then check that ``<DATA_FOLDER>/uwsgi.yaml`` uses the router settings. It should contain
``http:`` (and ``https:`` once HTTPS is on), ``http-keepalive: 1`` and ``threads: 4``.

.. code-block:: bash

    grep -E '^ *(http|https|http-socket|https-socket|threads|http-keepalive):' <DATA_FOLDER>/uwsgi.yaml

If it still shows ``http-socket`` or ``https-socket``, the automatic switch did not run.
Look for ``Unable to update`` in ``arpvpn.log``, fix the file ownership if needed
(``sudo chown 1000:1000 <DATA_FOLDER>/uwsgi.yaml``) and restart the container. The
switch reloads the web server twice, so the UI is gone for a few seconds on that first
start. A file named ``uwsgi.router-pending.yaml`` in the data folder means the second
reload has not happened yet, and the next restart finishes it.

Other things that make the UI slow:

* **Statistics** reads the whole traffic history, so it gets slower as the history grows.
  The history lives in ``<DATA_FOLDER>/traffic.json``.
* The first load of a page after an update downloads the new scripts and styles once.
  After that the browser keeps them.
* Pages load scripts and icons from ``code.jquery.com``, ``cdn.jsdelivr.net`` and
  ``cdnjs.cloudflare.com``. If the browser cannot reach them, pages wait for those
  requests to time out.

The container keeps restarting
------------------------------

Look at ``docker logs arpvpn``.

``ERROR: /data is not writable by runtime user UID:GID 1000:1000``
    Docker created the data folder as root. Fix it with
    ``sudo chown -R 1000:1000 <DATA_FOLDER>`` and restart. ``up.sh`` and the Stack Manager
    template do this for you, so this usually means the stack was started some other way.

``ERROR: WireGuard command preflight failed``
    The runtime user cannot run ``wg`` through sudo. Keep ``ARPVPN_RUNTIME_USER=arpvpn``.
    If you changed ``ARPVPN_UID`` or ``ARPVPN_GID``, rebuild the image.

``Address already in use``
    Another service already uses 8085 or 8086. Find it with
    ``sudo ss -ltnp | grep -E ':8085|:8086'`` and either stop it or change
    ``ARPVPN_HTTP_PORT`` / ``ARPVPN_HTTPS_PORT``.

The first deploy fails during the build
---------------------------------------

The image is built from source on the first deploy. Common causes:

* The host cannot reach ``github.com``, ``git.zx2c4.com``, ``pypi.org`` or the Debian
  mirrors. Test with ``curl -sI https://git.zx2c4.com``.
* Not enough disk space or memory for the build. Leave at least 2 GB free.
* ``Unable to download WireGuard Tools`` means ``git.zx2c4.com`` did not answer or returned
  an error. It is occasionally down for a few minutes; run the build again later.
* A ``WireGuard Tools checksum mismatch`` error means ``WIREGUARD_TOOLS_VERSION`` was
  changed without the matching ``WIREGUARD_TOOLS_SHA256``.

Login problems
--------------

* **Login form keeps coming back with no error over HTTP.** ``ARPVPN_SECURE_COOKIES=1``
  only allows HTTPS logins. Use HTTPS or set it to ``0``.
* **"CSRF token" errors behind a reverse proxy.** Use TLS mode *Behind reverse proxy*,
  set the incoming hostname, and make sure the proxy passes the ``Host`` header.
* **Two ARPVPN installs on one hostname log each other out.** Give each a unique
  ``ARPVPN_CONTAINER_NAME`` or ``ARPVPN_COOKIE_SUFFIX``.
* **Locked out after failed attempts.** Wait for the ban time set in **Settings**
  (``login_ban_time``, 120 seconds by default).

VPN clients connect but nothing works
-------------------------------------

**Handshake shows Never.** The client never reached the server.

* The interface's UDP listen port is not open in the firewall or provider firewall.
* The **Endpoint** in setup is a private IP or a hostname that does not resolve to the
  server. Fix it in **Settings**, then download the client config again.
* The interface is stopped. Start it on the **WireGuard** page.

**Handshake works but no traffic passes.**

* The interface **Gateway** is wrong. It must be the host's internet-facing interface.
  Check with ``ip route show default``.
* IP forwarding is off on the host. Check ``sysctl net.ipv4.ip_forward`` and enable it
  with ``sudo sysctl -w net.ipv4.ip_forward=1`` (persist it in ``/etc/sysctl.d/``).
* UFW drops forwarded traffic by default. Either set ``DEFAULT_FORWARD_POLICY="ACCEPT"``
  in ``/etc/default/ufw`` or allow the route, for example
  ``sudo ufw route allow in on wg0 out on eth0``, then ``sudo ufw reload``.
* CSF or another firewall is dropping forwarded traffic. With CSF make sure Docker mode
  is on and the VPN subnet is allowed.
* The peer's **Full tunnel** setting does not match what you expect.

**Pages load slowly or time out on big uploads through the tunnel.** Usually MTU. Try
``MTU = 1380`` in the client config.

Updates tab problems
--------------------

**"The ARPVPN updater container is not running".** The stack has no ``arpvpn-updater``
service, or it stopped. Check with ``docker ps --filter name=updater``. Installs made
before 3.1.0 need the updated compose file once; see the upgrading steps in
:doc:`installation`.

**"Unable to check GitHub for updates".** The server cannot reach ``github.com`` over
HTTPS. ARPVPN still works; only the check fails.

**"This install runs a registry image".** The install was deployed from a container
registry by a pipeline. Update it through that pipeline.

**Build fails within seconds with "Syntax error - can't find = in".** The updater in
ARPVPN 3.1.0 to 3.2.1 repacks the GitHub release in a way Docker 29 cannot read, so
Docker parses the wrong file as the Dockerfile. Nothing is changed when this happens.
Update once by hand to 3.2.2 or newer (see the upgrading steps in :doc:`installation`);
from then on the tab works.

**The update failed.** The progress log on the tab shows the step that failed. The full
log is ``<DATA_FOLDER>/.updater/update.log`` and ``docker logs arpvpn-updater`` shows the
same. A failed build changes nothing. A new version that does not become healthy is
rolled back automatically, and the tab says so.

Getting help
------------

When you contact ARPHost support include:

* How you installed (Stack Manager, Docker Compose, or systemd) and the ARPVPN version from **About**.
* The output of the quick checks above.
* The last 100 lines of ``docker logs arpvpn`` and ``arpvpn.log`` with keys and passwords removed.
