.. _imap-admin-systemcommands-mupdate:

===========
**mupdate**
===========

MUPDATE server process

Synopsis
========

.. parsed-literal::

    **mupdate** [ **-C** *config-file* ] [ **-m** ] [ **-a** ]

Description
===========

**mupdate** is the mailboxdb aggregation server.  It accepts commands 
on its standard input and responds on its standard output.  It MUST be 
invoked by :cyrusman:`master(8)` with those descriptors attached to a 
remote client connection.

**mupdate** |default-conf-text|

If the directory ``log``\/*user* exists under the directory specified in
the ``configdirectory`` configuration option, then **mupdate** will create
protocol telemetry logs for sessions authenticating as *user*.

The telemetry logs will be stored in the ``log``/\ *user* directory with
a filename of the **mupdate** process-id.

Options
=======

.. program:: mupdate

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -m

    Run as the MUPDATE master.  Default is to act as slave.

.. option:: -a

    [autoselect] Check ``mupdate_server`` setting in
    :cyrusman:`imapd.conf(5)` to see if this is the designated master
    server, and act as master if this is the case.  Otherwise act as
    slave.

Examples
========

**mupdate** is commonly included in the SERVICES section of
:cyrusman:`cyrus.conf(5)` like so:

.. parsed-literal::
    SERVICES {
        imap        cmd="imapd -U 30" listen="imap" prefork=0
        imaps       cmd="imapd -s -U 30" listen="imaps" prefork=0 maxchild=100
        lmtpunix    cmd="lmtpd" listen="/var/run/cyrus/socket/lmtp" prefork=0 maxchild=20
        sieve       cmd="timsieved" listen="sieve" prefork=0
        notify      cmd="notifyd" listen="/var/run/cyrus/socket/notify" proto="udp" prefork=1
        httpd       cmd="httpd" listen=8080 prefork=1 maxchild=20
        # (mupdate master, only one in the entire cluster)
        **mupdate     cmd="mupdate -m" listen="mupdate" prefork=1**
        #
        # (mupdate slave, run on each frontend host in the cluster)
        # mupdate     cmd="mupdate" listen="mupdate" prefork=1
    }

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`master(8)`
