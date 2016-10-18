.. _imap-admin-systemcommands-lmtpd:

=========
**lmtpd**
=========

LMTP server process

Synopsis
========

.. parsed-literal::

    **lmtpd** [ **-C** *config-file* ]  [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ] [ **-a** ]

Description
===========

**lmtpd** is an LMTP server used to deliver mail to the IMAP mailstore.
It accepts commands on its standard input and responds on its standard
output. It MUST be invoked by :cyrusman:`master(8)` with those
descriptors attached to a remote client connection.

**lmtpd** |default-conf-text|

Options
=======

.. program:: lmtpd

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -U  uses

    The maximum number of times that the process should be used for new
    connections before shutting down.  The default is 250.

.. option:: -T  timeout

    The number of seconds that the process will wait for a new
    connection before shutting down.  Note that a value of 0 (zero)
    will disable the timeout.  The default is 60.

.. option:: -D

    Run external debugger specified in debug_command.

.. option:: -a

    Preauthorize connections initiated on an internet socket, instead
    of requiring LMTP AUTH.  This should only be used for connections
    coming from trusted hosts.

Examples
========

**lmtpd** is commonly included in the SERVICES section of
:cyrusman:`cyrus.conf(5)` like so:

.. parsed-literal::
    SERVICES {
        imap        cmd="imapd -U 30" listen="imap" prefork=0
        imaps       cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100
        **lmtpunix    cmd="lmtpd" listen="/var/run/cyrus/socket/lmtp" prefork=0 maxchild=20**
        sieve       cmd="timsieved" listen="sieve" prefork=0
        notify      cmd="notifyd" listen="/var/run/cyrus/socket/notify" proto="udp" prefork=1
        httpd       cmd="httpd" listen=8080 prefork=1 maxchild=20
    }

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`master(8)`
