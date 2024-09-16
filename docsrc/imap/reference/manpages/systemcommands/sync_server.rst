.. cyrusman:: sync_server(8)

.. author: David Carter (dpc22@cam.ac.uk)
.. author: Ken Murchison (ken@oceana.com)
.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-sync_server:

===============
**sync_server**
===============

Server side of the synchronization (replication) engine

Synopsis
========

.. parsed-literal::

    **sync_server** [ **-C** *config-file* ] [ **-p** *ssf*]


Description
===========

**sync_server** is the server side of the replication system.  It
runs on the target (replica) system and listens for connections from
:cyrusman:`sync_client(8)` which provides instructions for synchronizing
the replica system with the master system.

**sync_server** |default-conf-text|

Options
=======

.. program:: sync_server

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -p  ssf

  Tell **sync_server** that an external layer exists.  An SSF (security
  strength factor) of 1 means an integrity protection layer exists.
  Any higher SSF implies some form of privacy protection.

Examples
========

**sync_server** is commonly included in the SERVICES section of
:cyrusman:`cyrus.conf(5)` like so:

.. parsed-literal::
    SERVICES {
        imap        cmd="imapd -U 30" listen="imap" prefork=0
        imaps       cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100
        pop3        cmd="pop3d -U 30" listen="pop3" prefork=0
        pop3s       cmd="pop3d -s -U 30" listen="pop3s" prefork=0 maxchild=100
        lmtpunix    cmd="lmtpd" listen="/var/run/cyrus/socket/lmtp" prefork=0 maxchild=20
        sieve       cmd="timsieved" listen="sieve" prefork=0
        notify      cmd="notifyd" listen="/var/run/cyrus/socket/notify" proto="udp" prefork=1
        httpd       cmd="httpd" listen=8080 prefork=1 maxchild=20
        **syncserver  cmd="sync_server" listen="csync"**
    }


Files
=====

/etc/imapd.conf,
/etc/cyrus.conf

See Also
========

:cyrusman:`sync_client(8)`,
:cyrusman:`imapd.conf(5)`,
:cyrusman:`cyrus.conf(5)`
