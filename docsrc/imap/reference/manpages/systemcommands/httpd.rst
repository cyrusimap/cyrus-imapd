.. cyrusman:: httpd(8)

.. _imap-admin-systemcommands-httpd:

=========
**httpd**
=========

HTTP server process

Synopsis
========

.. parsed-literal::

    **httpd** [ **-C** *config-file* ] [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ]
        [ **-s** ] [ **-p** *ssf* ] [ **-q** ]

Description
===========

**httpd** is an HTTP server. It accepts commands on its standard input
and responds on its standard output. It MUST invoked by
:cyrusman:`master(8)` with those descriptors attached to a remote client
connection.

**httpd** |default-conf-text|

If the directory ``<configdirectory>/log/``\ *user* exists, then
**httpd** will create protocol telemetry logs for sessions
authenticating as *user*. The telemetry logs will be stored in the
``log/``\ *user* directory with a filename of the **httpd** process-id.

Options
=======

.. program:: httpd

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

.. option:: -s

    Serve HTTP over SSL (https).  All data to and from **httpd**
    is encrypted using the Secure Sockets Layer.

.. option:: -p  ssf

    Tell **httpd** that an external layer exists.  An *SSF* (security
    strength factor) of 1 means an integrity protection layer exists.
    Any higher SSF implies some form of privacy protection.

.. option:: -q

    Ignore quotas on DAV appends. |v3-new-feature|

Examples
========

**httpd** is commonly included in the SERVICES section of
:cyrusman:`cyrus.conf(5)` like so:

.. parsed-literal::

    SERVICES {
        imap        cmd="imapd -U 30" listen="imap" prefork=0
        imaps       cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100
        lmtpunix    cmd="lmtpd" listen="/var/run/cyrus/socket/lmtp" prefork=0 maxchild=20
        sieve       cmd="timsieved" listen="sieve" prefork=0
        notify      cmd="notifyd" listen="/var/run/cyrus/socket/notify" proto="udp" prefork=1
        **httpd       cmd="httpd" listen=8080 prefork=1 maxchild=20**
    }

History
=======

A beta release of **httpd** was first introduced in the *caldav* branch
of Cyrus in version 2.4.17, and was included in the mainline releases
beginning in version 2.5.0.

The quota override option, **-q**, was introduced with Cyrus version
3.0.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`master(8)`
