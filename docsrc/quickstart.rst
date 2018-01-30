:orphan:

================
Quickstart Guide
================


.. toctree::

    imap/quickstart/introduction

Coming Soon
===========

.. note::

    The deb packages referenced below are not yet available.  Sorry!

Quick install
=============

A quick guide to getting a basic installation of Cyrus up and running in 5 minutes.

The first place to start with a new installation of Cyrus IMAP is with
your OS distribution of choice and their packaging, where available.  If
there is no Cyrus IMAP 3.0 package available yet from your distro,
download the `latest stable package`_ : version |imap_current_stable_version|.

.. _latest stable package: ftp://ftp.cyrusimap.org/cyrus-imapd/debs/

We only provide limited options for reference packages, so use a
supported distribution whenever possible.  At this time the only
official Cyrus packages are for Debian Jessie (with backports enabled).

Please download both the packages (\*.deb) and the signature files.
Installation is a two step process:

1. Install Cyrus reference packages
-----------------------------------

First, invoke the ``dpkg -i`` command with the list of all packages::

    $ sudo dpkg -i \
        cyrus-common_3.0.1-jessie_amd64.deb  \
        cyrus-doc_3.0.1-jessie_all.deb  \
        cyrus-imapd_3.0.1-jessie_amd64.deb  \
        cyrus-pop3d_3.0.1-jessie_amd64.deb  \
        cyrus-admin_3.0.1-jessie_all.deb  \
        cyrus-murder_3.0.1-jessie_amd64.deb  \
        cyrus-replication_3.0.1-jessie_amd64.deb  \
        cyrus-nntpd_3.0.1-jessie_amd64.deb  \
        cyrus-caldav_3.0.1-jessie_amd64.deb  \
        cyrus-clients_3.0.1-jessie_amd64.deb  \
        cyrus-dev_3.0.1-jessie_amd64.deb  \
        libcyrus-imap-perl_3.0.1-jessie_amd64.deb

That step will produce an error, as there will doubtless be unmet
dependencies.  Not to worry, there's a fix for that...

2. Use "apt-get install -f" to complete installation
----------------------------------------------------

Now invoke ``apt-get install -f`` to pull in the dependencies and
complete the installation::

    $ sudo apt-get install -f

The packaging should pull along all necessary support libraries, etc..

3. Setup the cyrus:mail user and group
--------------------------------------

.. include:: /assets/cyrus-user-group.rst

4. Setting up authentication with SASL
--------------------------------------

.. include:: /assets/setup-sasl-sasldb.rst

5. Setup mail delivery from your MTA
------------------------------------

Your Cyrus IMAP server will want to receive the emails accepted by your
SMTP server (ie Sendmail, Postfix, etc). In Cyrus, this happens via a
protocol called LMTP, which is usually supported by your SMTP server.

.. include:: /assets/setup-sendmail.rst

.. include:: /assets/setup-postfix.rst

6. Protocol ports
-----------------

.. include:: /assets/services.rst

7. Configuring Cyrus
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

8. Launch Cyrus
---------------

If using our packages on Debian Jessie, you will have a SystemV
compatible init script installed, with systemd support.  Start Cyrus
with the following command::

    systemctl start cyrus-imapd

Tada!  You should now have a working Cyrus IMAP server.

Feature overview
----------------

The features (compile-time configuration options) supported in our
reference packages are:

Cyrus Server configured components
    * event notification : yes
    * gssapi             : /usr
    * autocreate         : yes
    * idled              : yes
    * httpd              : yes
    * kerberos V4        : no
    * murder             : yes
    * nntpd              : yes
    * replication        : yes
    * sieve              : yes
    * calalarmd          : no
    * objectstore        : no
    * backup             : no

External dependencies
    * ldap              : yes
    * openssl           : yes
    * zlib              : yes
    * pcre              : yes
    * clamav            : yes
    * snmp              : yes
    * caringo           : no
    * openio            : no
    * nghttp2           : no
    * brotli            : no
    * xml2              : yes
    * ical              : yes
    * icu4c             : no
    * shapelib          : no

Database support
    * mysql             : no
    * postgresql        : no
    * sqlite            : yes
    * lmdb              : no

Search engine
    * squat             : yes
    * sphinx            : no
    * xapian            : yes
    * xapian_flavor     : vanilla

Hardware support
    * SSE4.2            : yes

Installation directories
    * prefix            : /usr
    * sysconfdir        : /etc
