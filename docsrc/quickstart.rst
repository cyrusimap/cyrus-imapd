================
Quickstart Guide
================


.. toctree::

    imap/quickstart/introduction

.. Coming Soon
.. -----------

Quick install
=============

A quick guide to getting a basic installation of Cyrus up and running in 5 minutes.

The first place to start with a new installation of Cyrus IMAP is with
your OS distribution of choice and their packaging, where available.

If there is no Cyrus IMAP |imap_current_stable_version| package available yet
from your distro, download the official source tarball from GitHub_.  The
:ref:`compiling` guide will help you get it built and installed.

.. _GitHub: https://github.com/cyrusimap/cyrus-imapd/releases


1. Install Cyrus package(s)
-----------------------------------

Install the Cyrus IMAP package(s), either from your distribution's package
manager, or from a release tarball.

Your distribution might have split Cyrus IMAP into several packages.  Check
their documentation if you're not sure what you need.

2. Setup the cyrus:mail user and group
--------------------------------------

.. include:: /assets/cyrus-user-group.rst

3. Setting up authentication with SASL
--------------------------------------

.. include:: /assets/setup-sasl-sasldb.rst

4. Setup mail delivery from your MTA
------------------------------------

Your Cyrus IMAP server will want to receive the emails accepted by your
SMTP server (ie Sendmail, Postfix, Exim). See :ref:`Mail delivery from your MTA <mta_lda_delivery>`.

5. Protocol ports
-----------------

.. include:: /assets/services.rst

6. Configuring Cyrus
--------------------

(Nearly there)

.. include:: /assets/setup-dir-struct.rst

Following installation, a fairly comprehensive set of sample
configuration files may be found in
``/usr/share/doc/cyrus-doc/examples/``.  Select one from each of the
``cyrus_conf`` and ``imapd_conf`` directories, and install as
``/etc/cyrus.conf`` and ``/etc/imapd.conf`` respectively.

A basic description of these files:

*   Stand-alone server configurations (pick one):

    *   small.conf
            A simple small server
    *   normal.conf
            A more typical server
    *   prefork.conf
            As above, but with several server processes pre-forked for
            faster connection initialization.

    ..  note::  The ``normal.conf`` file in the ``imapd_conf`` directory
        is intended to work with any of the above files from the
        ``cyrus_conf`` directory.
        
*   Cyrus Aggregation - Murder -- configurations (these constitute a
    set, with at least one of each required):

    *   murder-mupdate.conf
            The Mupdate Master server; holds the canonical copy of the
            ``mailboxes.db`` database.
    *   murder-backend.conf
            A backend server which holds the actual mailboxes and
            interacts with frontend proxies and/or clients.
    *   murder-frontend.conf
            A frontend server which holds no mailboxes, but either
            refers clients to the proper backend server for each
            requests, or proxies those requests directly.

*   Replication configurations (these constitute a set, with one master
    and at least one replica required):

    *   normal-master.conf
            The master server which uses the ``sync_client`` program to
            send mailbox updates to each replica on a rolling or
            periodic basis.
    *   normal-replica.conf
            A typical replica server, which accepts updates from the
            master.

    .. note::
        When working with replication or aggregation (Murder), the
        example files in ``cyrus_conf`` and ``imapd_conf`` of the same
        name are intended to be used together.

You should review each of these and then install as desired to
``/etc/``, making changes as needed.  In particular, you'll need to set
passwords for the various users used to authenticate between instances
in a Murder or Replication environment.

For example::

    install -m 600 doc/examples/cyrus_conf/normal.conf /etc/cyrus.conf
    install -m 600 doc/examples/imapd_conf/normal.conf /etc/imapd.conf
    vi /etc/imapd.conf
    ...
    vi /etc/cyrus.conf
    ...

7. Launch Cyrus
---------------

If using a distribution package, you probably now have an init script
installed, that you can invoke with your system's usual service control
mechanism.

If you built from source, you will need to write your own init script.
The simplest one will simply start/stop the :cyrusman:`master(8)` binary,
with suitable options, as root (master will drop root privileges itself
as soon as it possibly can).
