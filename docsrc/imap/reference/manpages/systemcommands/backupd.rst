.. cyrusman:: backupd(8)

.. _imap-reference-manpages-systemcommands-backupd:

===========
**backupd**
===========

Cyrus Backups server process

Synopsis
========

.. parsed-literal::

    **backupd** [ **-C** *config-file* ] [ **-U** *uses* ] [ **-T** *timeout* ] [ **-D** ]
        [ **-s** ] [ **-N** ] [ **-p** *ssf* ]

Description
===========

**backupd** is the Cyrus Backups server.  It accepts Cyrus replication protocol
commands on its standard input and responds on its standard output.  It MUST be
invoked by :cyrusman:`master(8)` with those descriptors attached to a
replication client connection, typically :cyrusman:`sync_client(8)`.

**backupd** |default-conf-text|

**backupd** is generally configured to run on a dedicated backup server,
containing backup storage, but no IMAP service or mailbox storage.

You must configure at least one *backuppartition*.  User backups will be
distributed among the configured partitions.  Note that there is no
relationship between mailbox partitions and *backuppartitions*.

If the directory ``log``\/*user* exists under the directory specified in the
``configdirectory`` configuration option, then **backupd** will create
protocol telemetry logs for sessions authenticating as *user*.  The telemetry
logs will be stored in the ``log``\/*user* directory with a filename of the
**backupd** process-id.

Options
=======

.. program:: backupd

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

.. option:: -p  ssf

    Tell **backupd** that an external layer exists.  An *SSF* (security
    strength factor) of 1 means an integrity protection layer exists.
    Any higher SSF implies some form of privacy protection.


Examples
========

**backupd** is commonly included in the SERVICES section of
:cyrusman:`cyrus.conf(5)` like so:

.. parsed-literal::
    SERVICES {
        **backupd        cmd="backupd" listen="csync" prefork=0**
    }

History
=======

Files
=====

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`master(8)`,
:cyrusman:`sync_client(8)`
