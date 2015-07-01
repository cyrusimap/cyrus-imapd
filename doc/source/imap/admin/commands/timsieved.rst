.. _imap-admin-commands-timsieved:

=============
**timsieved**
=============

CMU hack for getting sieve scripts onto the server

Synopsis
========

.. parsed-literal::

    **timsieved** [ **-C** *config-file* ]

Description
===========

**timsieved** is a server that allows users to remotely manage their 
sieve scripts kept on the server.  It accepts commands on its standard 
input and responds on its standard output. It MUST be invoked by 
:manpage:`master(8)` with those descriptors attached to a remote client 
connection.

Cyrus admins who authenticate and authorize as themselves (e.g. don't
proxy) manage global scripts.

**timsieved** |default-conf-text|

Options
=======

.. program:: timsieved

.. option:: -C config-file

    |cli-dash-c-text|

Examples
========

**timsieved** is commonly included in the SERVICES section of
:manpage:`cyrus.conf(5)` like so:

.. parsed-literal::
    SERVICES {
        imap        cmd="imapd -U 30" listen="imap" prefork=0
        imaps       cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100
        pop3        cmd="pop3d -U 30" listen="pop3" prefork=0
        pop3s       cmd="pop3d -s -U 30" listen="pop3s" prefork=0 maxchild=100
        lmtpunix    cmd="lmtpd" listen="/var/run/cyrus/socket/lmtp" prefork=0 maxchild=20
        **sieve       cmd="timsieved" listen="sieve" prefork=0**
        notify      cmd="notifyd" listen="/var/run/cyrus/socket/notify" proto="udp" prefork=1
        httpd       cmd="httpd" listen=8080 prefork=1 maxchild=20
    }


Files
=====

/etc/imapd.conf,
/etc/cyrus.conf

See Also
========

:manpage:`master(8)`,
:manpage:`imapd.conf(5)`,
:manpage:`cyrus.conf(5)`
