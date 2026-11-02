Installation
============

ARPVPN can be installed three ways. Pick one.

* **Stack Manager** (easiest on an ARPHost server). Deploy the ARPVPN template from the catalog.
* **Docker Compose** by hand, using the ``docker/`` folder in this repository.
* **systemd** directly on the host, without Docker.

Whichever you pick, read :ref:`network-and-firewall` before you start. Almost every
"I can't reach the web UI" report comes down to a firewall port that was never opened.

Requirements
------------

* A Linux host with a kernel that includes WireGuard (Linux 5.6 or newer, which covers
  current Debian, Ubuntu, AlmaLinux, and Rocky releases). Check with ``sudo modprobe wireguard``.
* Root or sudo on the host.
* For Docker installs, Docker Engine 24 or newer with the Compose plugin. Rootful Docker
  is required. Rootless Docker, Docker Desktop, and Podman do not give the container real
  host networking, so the web UI and VPN will not be reachable from outside.
* Outbound HTTPS from the host to ``github.com``, ``git.zx2c4.com``, ``pypi.org`` and
  ``deb.debian.org`` the first time the image is built.

.. _network-and-firewall:

Network ports and the firewall
------------------------------

ARPVPN runs with **host networking**. The container shares the host's network stack and
listens directly on the host's interfaces. There is no Docker ``ports:`` mapping.

This matters because Docker only opens firewall holes for *published* ports. With host
networking nothing is published, so you must open the ports in the host firewall yourself.

+-----------------------------+----------+---------------------------------------------------------------+
| Port                        | Protocol | Purpose                                                       |
+=============================+==========+===============================================================+
| ``8085``                    | TCP      | Web UI and API over HTTP. Set by ``ARPVPN_HTTP_PORT``.        |
+-----------------------------+----------+---------------------------------------------------------------+
| ``8086``                    | TCP      | Web UI and API over HTTPS. Set by ``ARPVPN_HTTPS_PORT``.      |
|                             |          | Listens once HTTPS is enabled in setup and the app has been   |
|                             |          | restarted. See :doc:`usage`.                                  |
+-----------------------------+----------+---------------------------------------------------------------+
| One port per interface      | UDP      | WireGuard. Each interface you create gets its own listen port |
| (random 50000+ by default)  |          | shown on the WireGuard page. Clients connect here.            |
+-----------------------------+----------+---------------------------------------------------------------+

ConfigServer Firewall (CSF), including Stack Manager's Firewall panel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add the web ports to ``TCP_IN`` and the WireGuard port to ``UDP_IN``, then restart CSF.
In Stack Manager use **Settings > Firewall**, add the ports to the TCP IN and UDP IN fields,
and press **Save + Restart**. From a shell:

.. code-block:: bash

    # Edit /etc/csf/csf.conf and append the ports to TCP_IN and UDP_IN, for example
    # TCP_IN = "22,80,443,8085,8086"
    # UDP_IN = "53,51820"
    sudo csf -r

.. warning::
    Stack Manager's **Open Ports (CSF)** button on the project page does not work for
    ARPVPN. It only opens ports listed under ``ports:`` in the compose file, and ARPVPN has
    none because it uses host networking. Open the ports in **Settings > Firewall** instead.

UFW
~~~

.. code-block:: bash

    sudo ufw allow 8085/tcp
    sudo ufw allow 8086/tcp
    sudo ufw allow 51820/udp   # use your interface's real listen port
    # UFW drops routed traffic by default; allow VPN clients out to the internet
    sudo ufw route allow in on wg0 out on eth0   # use your interface names
    sudo ufw reload

firewalld
~~~~~~~~~

.. code-block:: bash

    sudo firewall-cmd --permanent --add-port=8085/tcp
    sudo firewall-cmd --permanent --add-port=8086/tcp
    sudo firewall-cmd --permanent --add-port=51820/udp
    sudo firewall-cmd --reload

Cloud and upstream firewalls
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If the server sits behind a provider firewall, security group, or NAT router, open or
forward the same ports there too.

Option 1. Install with Stack Manager
------------------------------------

1. In Stack Manager open the template catalog, go to **Security, Identity & VPN**, and
   choose **ARPVPN**.
2. Review the environment values. The defaults work for a single install.

   * ``ARPVPN_HTTP_PORT`` and ``ARPVPN_HTTPS_PORT`` are the host ports the UI listens on.
     Change them only if 8085 or 8086 is already used on the host.
   * ``DATA_FOLDER`` is where ARPVPN keeps its configuration, users, keys, and logs.
     Back this folder up.
   * Leave ``ARPVPN_UID``, ``ARPVPN_GID`` and ``ARPVPN_RUNTIME_USER`` alone unless you know
     you need them.

3. Deploy. The first deploy builds the image from the public GitHub repository. This takes
   several minutes because WireGuard tools are compiled from source. The UI is not
   available until the build finishes and the container reports healthy. Watch progress
   in the project's log view.
4. Open the firewall ports as described in :ref:`network-and-firewall`. Do not rely on the
   **Open Ports (CSF)** button for this project.
5. Browse to ``http://<server-public-ip>:8085`` and continue with :doc:`usage`.

Option 2. Install with Docker Compose
-------------------------------------

1. Clone the repository (or unpack a release archive) and enter the ``docker`` folder.

   .. code-block:: bash

       git clone https://github.com/arphost-com/ARPVPN.git
       cd ARPVPN/docker
       cp .env.example .env

2. Edit ``.env`` if you need different ports or a different data folder. See
   :ref:`docker-env-reference` below.
3. Build and start. ``up.sh`` creates the data folder with the right owner before
   starting, which avoids the most common permission error.

   .. code-block:: bash

       ./up.sh

   This is the same as ``./up.sh up -d --build --force-recreate arpvpn``. The first build
   takes several minutes.

4. Confirm it is running and healthy.

   .. code-block:: bash

       docker ps --filter name=arpvpn
       curl -sI http://127.0.0.1:8085 | head -1

   The status column should change from ``health: starting`` to ``healthy`` and curl
   should return an HTTP status line.

5. Open the firewall ports as described in :ref:`network-and-firewall`.
6. Browse to ``http://<server-public-ip>:8085`` and continue with :doc:`usage`.

If you run ``docker compose`` directly instead of ``up.sh``, create the data folder first
and give it to UID 1000, otherwise Docker creates it as root and the container exits with
``/data is not writable``.

.. code-block:: bash

    sudo mkdir -p /srv/arpvpn/data
    sudo chown -R 1000:1000 /srv/arpvpn/data

.. _docker-env-reference:

Docker ``.env`` reference
~~~~~~~~~~~~~~~~~~~~~~~~~

Common settings:

* ``ARPVPN_IMAGE`` is the image to run. The default ``arpvpn:local`` is built from the checkout.
* ``ARPVPN_HTTP_PORT`` / ``ARPVPN_HTTPS_PORT`` are the listener ports, default ``8085`` and ``8086``.
  If you change them, also set ``web.http_port`` and ``web.https_port`` in
  ``<DATA_FOLDER>/arpvpn.yaml`` to the same values so saving TLS settings in the UI keeps
  the same ports.
* ``DATA_FOLDER`` is the host path mounted at ``/data``.
* ``ARPVPN_CONTAINER_NAME`` should be unique per stack when running more than one ARPVPN on a host.
* ``ARPVPN_SECURE_COOKIES`` is ``0`` to allow both HTTP and HTTPS logins, ``1`` for HTTPS only.
  With ``1`` you cannot log in over plain HTTP.
* ``ARPVPN_UID`` / ``ARPVPN_GID`` set the UID and GID of the container's ``arpvpn`` user at
  build time. Change them only if ``DATA_FOLDER`` must be owned by a different user, and
  rebuild after changing them.
* ``ARPVPN_RUNTIME_USER`` should stay ``arpvpn``.

Cookie and side by side settings:

* ``ARPVPN_COOKIE_SUFFIX`` sets the cookie namespace. It defaults to the container name.
* ``ARPVPN_SESSION_COOKIE_NAME`` / ``ARPVPN_REMEMBER_COOKIE_NAME`` set explicit cookie names.

Tuning, all optional:

* ``ARPVPN_HIGH_TRAFFIC_THRESHOLD_MB`` peer traffic alert threshold, default ``1024``.
* ``ARPVPN_RRD_GRAPH_CACHE_TTL_SECONDS`` graph cache lifetime, default ``10800``.
* ``ARPVPN_LOG_DIAGNOSTICS_CACHE_TTL_SECONDS`` / ``ARPVPN_LOG_DIAGNOSTICS_READ_BLOCK_BYTES`` log diagnostics sizing.
* ``ARPVPN_API_ACCESS_TTL_SECONDS`` / ``ARPVPN_API_REFRESH_TTL_SECONDS`` API token lifetimes.
* ``ARPVPN_API_AUTH_WINDOW_SECONDS`` / ``ARPVPN_API_AUTH_MAX_ATTEMPTS`` / ``ARPVPN_API_AUTH_LOCKOUT_SECONDS`` API login lockout.
* ``ARPVPN_API_RATE_LIMIT_WINDOW_SECONDS`` / ``ARPVPN_API_RATE_LIMIT_MAX_REQUESTS`` API rate limit.
* ``ARPVPN_FEATURE_API_AUTH``, ``ARPVPN_FEATURE_API_STATS``, ``ARPVPN_FEATURE_API_SYSTEM``,
  ``ARPVPN_FEATURE_API_TLS``, ``ARPVPN_FEATURE_API_CONFIG``, ``ARPVPN_FEATURE_API_TENANTS``,
  ``ARPVPN_FEATURE_API_WIREGUARD`` set to ``0`` to turn off an API group.
* ``ARPVPN_AUDIT_SIGNING_KEY`` overrides the audit event signing key.
* ``ARPVPN_TENANT_RUNTIME_PORT_STRIDE``, ``ARPVPN_TENANT_RUNTIME_HTTP_BASE``,
  ``ARPVPN_TENANT_RUNTIME_HTTPS_BASE``, ``ARPVPN_TENANT_RUNTIME_VPN_BASE`` tenant runtime port planning.
* ``ARPVPN_REPOSITORY_URL`` / ``ARPVPN_LICENSE_URL`` links shown in the app.

``up.sh`` reads ``docker/.env``. Set ``ENV_FILE=/path/to/file`` to use another one.

Option 3. Install as a systemd service
--------------------------------------

1. From a checkout or an extracted release archive, run the installer as root.
   In a release archive the installer is ``install.sh`` at the top level.

   .. code-block:: bash

       chmod +x scripts/install.sh
       sudo ./scripts/install.sh

2. Start and enable the service.

   .. code-block:: bash

       sudo systemctl enable --now arpvpn.service
       sudo systemctl status arpvpn.service

3. Open the firewall ports as described in :ref:`network-and-firewall`.
4. Browse to ``http://<server-public-ip>:8085`` and continue with :doc:`usage`.

The working directory is ``/var/www/arpvpn/data`` and the log is
``/var/www/arpvpn/data/arpvpn.log``.

Upgrading
---------

* **Stack Manager**: use the project's **Update** action. It rebuilds from GitHub and
  recreates the container. Your ``DATA_FOLDER`` is kept.
* **Docker Compose**: ``git pull`` in the checkout, then ``./up.sh`` again.
* **systemd**: run the newer installer, then ``sudo systemctl restart arpvpn``.

Back up ``DATA_FOLDER`` before every upgrade.

Running more than one ARPVPN on a host
--------------------------------------

Give each install its own ``DATA_FOLDER``, ``ARPVPN_CONTAINER_NAME``, cookie suffix,
``ARPVPN_HTTP_PORT`` and ``ARPVPN_HTTPS_PORT``, and make sure WireGuard interfaces in
different installs use different UDP ports.
