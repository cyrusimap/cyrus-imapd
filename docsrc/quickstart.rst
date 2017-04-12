================
Quickstart Guide
================


.. toctree::

    imap/quickstart/introduction

.. Coming Soon
.. -----------

Quick install
-------------

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

1. First, invoke the ``dpkg -i`` command with the list of all packages::

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

2.  Now invoke ``apt-get install -f`` to pull in the dependencies and
    complete the installation::

    $ sudo apt-get install -f

The packaging should pull along all necessary support libraries, etc..

CONFIGURATION
-------------

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

You should review each of these and then install as desired to
``/etc/``, making changes as needed.  In particular, you'll need to set
passwords for the various users used to authenticate between instances
in a Murder or Replication environment.

.. Note::
    Continue with instructions in :ref:`The cyrus:mail user <basicserver_cyrus_user>`

Feature overview
----------------

The features (configuration options) supported in our reference
packages are:

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
    * jmap               : yes
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
