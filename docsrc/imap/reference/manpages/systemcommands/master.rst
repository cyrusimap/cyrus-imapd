.. cyrusman:: master(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-master:

==========
**master**
==========

The Cyrus IMAP master process.

Synopsis
========

.. parsed-literal::

    **master** [ **-C** *config-file* ] [ **-M** *alternate cyrus.conf* ]
        [ **-l** *listen queue* ] [ **-p** *pidfile* ] [ **-r** *ready_file* ]
        [ **-j** *janitor period* ] [ **-d** | **-D** ] [ **-L** *logfile* ]

Description
===========

**master** is the process that controls all of the Cyrus
processes. This process is responsible for creating all imapd, pop3d,
lmtpd and timsieved child processes. This process also performs scheduled
cleanup/maintenance.

If this process dies, then no new sessions will be started.

It kills itself and all child processes when it receives a SIGTERM.

**master** |default-conf-text|

Options
=======

.. program:: master

.. option:: -C  alternate imapd.conf

    |cli-dash-c-text|

.. option:: -M  alternate cyrus.conf

    Specifies an alternate cyrus.conf for use by master.

.. option:: -l  listen queue backlog

    Increase the listen queue backlog. By default, the listen queue is
    set to 32.   On systems with a high connection rate, it may be
    desirable to increase this value. refer to :manpage:`listen(2)` for
    details.

.. option:: -j  janitor full-sweeps per second

    Sets the number of times per second the janitor should sweep the
    entire child table.  Leave it at the default of 1 unless you have a
    really high fork rate (and you have not increased the child hash
    table size when you compiled Cyrus from its default of 10000
    entries).

.. option:: -p  pidfile

    Use *pidfile* as the pidfile.  If not specified, defaults to
    ``master_pid_file`` from :cyrusman:`imapd.conf(5)`, which
    defaults to ``{configdirectory}/master.pid``

.. option:: -r  ready_file

    Use *ready_file* as the ready file.  If not specified, uses
    ``master_ready_file`` from :cyrusman:`imapd.conf(5)`, which
    defaults to ``{configdirectory}/master.ready``

.. option:: -d

    Start in daemon mode (run in background and disconnect from
    controlling terminal).

.. option:: -D

    Don't close stdin/stdout/stderr. Primarily useful for debugging.
    Note that **-d** and **-D** cannot be used together; consider using
    **-L** instead.

.. option:: -L  logfile

    Redirect stdout and stderr to the given *logfile*.

Configuration
=============

Upon execution, **master** reads its configuration information
out of the :cyrusman:`cyrus.conf(5)` file, or an alternative if **-M**
is used.

**master** rereads its configuration file when it receives a
hangup signal, SIGHUP.  Services and events may be added, deleted or
modified when the configuration file is reread.  Any active services
removed from the configuration file will be allowed to run until
completion.  Services added or modified to listen on a privileged port
may not be able to bind the port, depending on your system
configuration.  In this case a full restart is needed.

**master** propagates the hangup signal, SIGHUP, to its child
service processes, so that they stop waiting for incoming connections
and exit, allowing them to be recycled.  This is useful to make
services take into account a new version of the
:cyrusman:`imapd.conf(5)` file.  Children that are servicing a client
connection when SIGHUP is received are allowed to run until the client
logouts before being recycled. It may take a long time until the client
logouts, so a log message is generated for processes that have not been
recycled within 30s.

Notes
=====

The environment variable **CYRUS_VERBOSE** can be set to log additional
debugging information. Setting the value to 1 results in base level logging.
Setting it higher results in more log messages being generated.

The :cyrusman:`cyr_info(8)` utility's ``proc`` subcommand can be used to
list the active processes that **master** is managing.

Files
=====

/etc/cyrus.conf,
/etc/imapd.conf,
/var/run/master.pid

See Also
========

:cyrusman:`cyrus.conf(5)`, :cyrusman:`imapd.conf(5)`, :cyrusman:`imapd(8)`,
:cyrusman:`pop3d(8)`, :cyrusman:`lmtpd(8)`, :cyrusman:`timsieved(8)`,
:cyrusman:`idled(8)`, :cyrusman:`cyr_info(8)`
