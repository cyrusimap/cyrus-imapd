.. cyrusman:: imapd(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-imapd:

=========
**imapd**
=========

IMAP server process

Synopsis
========

.. parsed-literal::

    **imapd** [ **-C** *config-file* ] [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ]
        [ **-s** ] [ **-N** ] [ **-p** *ssf* ]

Description
===========

**imapd** is an IMAP4rev1 server.  It accepts commands on its standard
input and responds on its standard output.  It MUST be invoked by
:cyrusman:`master(8)` with those descriptors attached to a remote client
connection.

**imapd** |default-conf-text|

If the file ``msg/shutdown`` is created under the directory specified in
the ``configdirectory`` configuration option, then **imapd** will shut
down the connection, sending the first line contained in the file to the
client as the reason.  New connections are denied.

If the file ``msg/motd`` is created under the directory specified in the
``configdirectory`` configuration option, then **imapd** will send the
first line contained in the file to clients upon connect as an ALERT
message which IMAP-compliant clients are required to display.

This option serves to annoy users mostly.  Unfortunately clients tend to
connect far more frequently than is apparent, generating a seperate
server ALERT for each connection.  Many clients do not display these
properly, if they do anything with them at all.

If the directory ``log``\/*user* exists under the directory specified in
the ``configdirectory`` configuration option, then **imapd** will create
protocol telemetry logs for sessions authenticating as *user*.

The telemetry logs will be stored in the ``log``/\ *user* directory with
a filename of the **imapd** process-id.

Options
=======

.. program:: imapd

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

    Serve IMAP over SSL (imaps).  All data to and from **imapd** is
    encrypted using the Secure Sockets Layer.

.. option:: -N

    Bypass password checking.  (Not recommended unless you know what
    you're doing.)

.. option:: -p  ssf

    Tell **imapd** that an external layer exists.  An *SSF* (security
    strength factor) of 1 means an integrity protection layer exists.
    Any higher SSF implies some form of privacy protection.

Examples
========

**imapd** is commonly included in the SERVICES section of
:cyrusman:`cyrus.conf(5)` like so:

.. parsed-literal::
    SERVICES {
        **imap        cmd="imapd -U 30" listen="imap" prefork=0**
        **imaps       cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100**
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
