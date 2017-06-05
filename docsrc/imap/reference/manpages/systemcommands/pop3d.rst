.. cyrusman:: pop3d(8)

.. author: Nic Bernstein (Onlight)

.. _pop3-admin-commands-pop3d:

=========
**pop3d**
=========

POP3 server process

Synopsis
========

.. parsed-literal::

    **pop3d** [ **-C** *config-file* ] [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ]
        [ **-s** ] [ **-k** ] [ **-p** *ssf* ]

Description
===========

**pop3d** is an POP3 server.  It accepts commands on its standard
input and responds on its standard output.  It MUST be invoked by
:cyrusman:`master(8)` with those descriptors attached to a remote client
connection.

**pop3d** |default-conf-text|

If the directory ``log``\/*user* exists under the directory specified in
the ``configdirectory`` configuration option, then **pop3d** will create
protocol telemetry logs for sessions authenticating as *user*.

The telemetry logs will be stored in the ``log``/\ *user* directory with
a filename of the **pop3d** process-id.

Options
=======

.. program:: pop3d

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

    Serve POP3 over SSL (pop3s).  All data to and from **pop3d** is
    encrypted using the Secure Sockets Layer.

.. option:: -k

    Serve MIT's KPOP (Kerberized POP) protocol instead.

.. option:: -p  ssf

    Tell **pop3d** that an external layer exists.  An *SSF* (security
    strength factor) of 1 means an integrity protection layer exists.
    Any higher SSF implies some form of privacy protection.

Examples
========

**pop3d** is commonly included in the SERVICES section of
:cyrusman:`cyrus.conf(5)` like so:

.. parsed-literal::
    SERVICES {
        imap        cmd="imapd -U 30" listen="imap" prefork=0
        imaps       cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100
        **pop3        cmd="pop3d -U 30" listen="pop3" prefork=0**
        **pop3s       cmd="pop3d -s -U 30" listen="pop3s" prefork=0 maxchild=100**
        lmtpunix    cmd="lmtpd" listen="/var/run/cyrus/socket/lmtp" prefork=0 maxchild=20
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
