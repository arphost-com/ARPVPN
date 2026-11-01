Getting started
===============

This walks through a fresh install from the first page load to a working client.

1. Create the admin account
---------------------------

Open ``http://<server-public-ip>:8085``. A new install serves plain HTTP only. HTTPS on
port 8086 is turned on during setup (step 2). On a new install you are sent to ``/signup``. Create the first
account. It becomes the administrator. There is no default username or password.

2. Run setup
------------

After signing up you land on ``/setup``. The important fields are below.

* **Endpoint** is the public IP or hostname VPN clients will connect to. ARPVPN fills in
  the server's detected public IP. If the server is behind NAT, or you want clients to use
  a DNS name, change it now. This value is written into every client config.
* **TLS mode** picks how the web UI is served.

  * *Self-signed certificate* (preselected) adds HTTPS on 8086 with a generated
    certificate. Browsers show a certificate warning for HTTPS.
  * *Let's Encrypt certificate* adds HTTPS on 8086 with a trusted certificate. It needs a
    public DNS name pointing at the server and TCP 80 reachable from the internet while
    the certificate is issued.
  * *Direct HTTP* serves 8085 only.
  * *Behind reverse proxy* keeps ARPVPN on HTTP and expects a proxy such as Nginx Proxy
    Manager or Caddy to terminate TLS. Set the proxy's public hostname in
    **Reverse proxy incoming hostname**.

* **TLS / External hostname** is the name used for certificates and HTTPS redirects. Use
  the public hostname or public IP, never a private address.
* **Redirect HTTP requests to HTTPS** sends port 8085 visitors to 8086. Leave it off until
  you have confirmed HTTPS works.

Click **Next** to save.

.. important::
    HTTPS on port 8086 does not start until the application restarts. After setup, go to
    **Settings** and press **Restart app**, or restart the container
    (``docker restart arpvpn``). The same applies after any later TLS change. Until then
    only ``http://...:8085`` works.

3. Create a WireGuard interface
-------------------------------

Go to **WireGuard** and add an interface.

* **Name** is the Linux interface name, for example ``wg0``.
* **Gateway** is the host's internet-facing network interface (often ``eth0``, ``ens18``
  or ``enp1s0``). VPN traffic is NATed out through it.
* **IPv4** is the interface address and VPN subnet, for example ``10.8.0.1/24``.
* **Listen port** is the UDP port clients connect to. A random port above 50000 is
  suggested. **Open this UDP port in the firewall** (see :ref:`network-and-firewall`).
* **Auto** brings the interface up when ARPVPN starts.

Save and start the interface.

4. Add peers
------------

Add a peer for each device or site.

* **Mode** is *Client* for a laptop or phone, *Site-to-site* for a router or another
  network. Site-to-site peers take **Remote site subnets**.
* **IPv4** is the peer's address inside the VPN subnet, for example ``10.8.0.2/32``.
* **Full tunnel** sends all of the client's traffic through the VPN. Leave it off for
  split tunnel access to the VPN subnet only.
* **DNS** servers are written into the client config.

5. Connect a client
-------------------

From the peer page download the ``.conf`` file or show the QR code, then import it into
the official WireGuard app on the device. Turn the tunnel on.

6. Check it works
-----------------

The **Dashboard** and **WireGuard** pages show the latest handshake and traffic for each
peer. A recent handshake means the client reached the server. If the handshake stays at
*Never*, see :doc:`troubleshooting`.

Users and roles
---------------

ARPVPN has four roles.

* ``admin`` manages everything.
* ``support`` is staff access for helping customers, including impersonation.
* ``tenant_admin`` manages users and peers within one tenant.
* ``client`` sees and downloads only their own VPN configs.

Add users under **Users**, or send invitations. Turn on MFA for admin accounts in
**Profile**.

.. _updating-arpvpn:

Updating ARPVPN
---------------

Open **Settings** and choose the **Updates** tab. It shows the installed version, the
newest release on GitHub and what changed, and marks the tab **New** when an update is
waiting. ARPVPN checks GitHub at most once an hour; **Check now** checks right away.

Click **Install** to update. The updater container downloads that release from GitHub,
builds a new image, and replaces the ARPVPN container. The build takes several minutes,
and the page loses its connection for about a minute while ARPVPN restarts, then reloads
on the new version. If the new version does not start cleanly, the previous container is
put back automatically and the tab shows what went wrong.

Your configuration, users, keys and traffic history live in ``DATA_FOLDER`` and are kept.
Back that folder up before updating anyway. WireGuard tunnels drop briefly during the
restart.

Only administrators can see the Updates tab. On installs deployed by a pipeline, or
without the updater container, the tab still shows whether a new release exists and
explains how that install is updated instead.

Day to day
----------

* **Statistics** shows traffic history, graphs, and alerts. Data can be exported as CSV
  or JSON.
* **Settings** holds TLS, login limits, traffic collection, the **Restart app** button, and
  the **Updates** tab.
* The REST API lives under ``/api/v1``. See :doc:`api`.
