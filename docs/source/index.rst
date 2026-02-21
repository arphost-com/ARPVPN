ARPVPN
========

.. image:: https://img.shields.io/github/license/arphost-com/ARPVPN
    :target: https://github.com/arphost-com/ARPVPN/blob/main/LICENSE.md
    :alt: License: GPL-3.0

.. image:: https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=yellow
    :alt: Supported python versions: 3.10, 3.11, 3.12

.. image:: https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml/badge.svg
    :target: https://github.com/arphost-com/ARPVPN/actions/workflows/stable-test.yaml
    :alt: Stable workflow status

.. image:: https://github.com/arphost-com/ARPVPN/actions/workflows/latest-test.yaml/badge.svg
    :target: https://github.com/arphost-com/ARPVPN/actions/workflows/latest-test.yaml
    :alt: Latest workflow status

.. image:: https://codecov.io/gh/arphost-com/ARPVPN/branch/main/graph/badge.svg
    :target: https://codecov.io/gh/arphost-com/ARPVPN
    :alt: Code coverage status

.. image:: https://img.shields.io/github/v/release/arphost-com/ARPVPN?color=green&include_prereleases&logo=github)
    :target: https://github.com/arphost-com/ARPVPN/releases
    :alt: Latest release (including pre-releases)

.. image:: https://img.shields.io/github/downloads/arphost-com/ARPVPN/total?logo=github)
    :target: https://github.com/arphost-com/ARPVPN/releases
    :alt: Downloads counter (from all releases)

ARPVPN aims to provide a clean, simple yet powerful web GUI to manage your WireGuard server, and it's powered by Flask.

Key features
------------

* Management of Wireguard interfaces and peers via web. Interfaces can be created, removed, edited, exported and brought up and down directly from the web GUI. Peers can be created, removed, edited and downloaded at anytime as well.
* Display stored and real time traffic data using charts (storage of traffic data may be manually disabled).
* Display general network information.
* Encrypted user credentials (AES).
* Easy management through the ``arpvpn`` systemd service.

Contents
--------

.. toctree::
    :maxdepth: 2

    installation
    screenshots
    in-depth
    gitlab-deployment
    contributing
    changelog

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
