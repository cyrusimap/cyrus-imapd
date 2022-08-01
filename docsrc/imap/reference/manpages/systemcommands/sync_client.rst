.. cyrusman:: sync_client(8)

.. author: David Carter (dpc22@cam.ac.uk)
.. author: Ken Murchison (ken@oceana.com)
.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-sync_client:

===============
**sync_client**
===============

Client side of the synchronization (replication) engine

Synopsis
========

.. parsed-literal::

    **sync_client** [ **-v** ] [ **-l** ] [ **-L** ] [ **-z** ] [ **-C** *config-file* ] [ **-S** *server-name* ]
        [ **-f** *input-file* ] [ **-F** *shutdown_file* ] [ **-w** *wait_interval* ]
        [ **-t** *timeout* ] [ **-d** *delay* ] [ **-r** ] [ **-n** *channel* ] [ **-u** ] [ **-m** ]
        [ **-p** *partition* ] [ **-A** ] [ **-N** ] [ **-s** ] [ **-O** ] *objects*...

Description
===========

**sync_client** is the client side of the replication system.  It runs
on the client (master) system and connects to the target (replica)
system and generates an appropriate sequence of transactions to
synchronize the replica system with the master system.

**sync_client** |default-conf-text|

Options
=======

.. program:: sync_client

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -A, --all-users

    All users mode.
    Sync every user on the server to the replica (doesn't do non-user
    mailboxes at all... this could be considered a bug and maybe it
    should do those mailboxes independently)

.. option:: -d delay, --delay=delay

    Minimum delay between replication runs in rolling replication mode.
    Larger values provide better efficiency as transactions can be
    merged. Smaller values mean that the replica system is more up to
    date and that you don't end up with large blocks of replication
    transactions as a single group. Default: 3 seconds.

.. option:: -f input-file, --input-file=input-file

    In mailbox or user replication mode: provides list of users or
    mailboxes to replicate.  In rolling replication mode, specifies an
    alternate log file (**sync_client** will exit after processing the
    log file).

.. option:: -F shutdown-file, --shutdown-file=shutdown-file

    Rolling replication checks for this file at the end of each
    replication cycle and shuts down if it is present. Used to request
    a nice clean shutdown at the first convenient point. The file is
    removed on shutdown. Overrides ``sync_shutdown_file`` option in
    :cyrusman:`imapd.conf(5)`.

.. option:: -l, --verbose-logging

    Verbose logging mode.

.. option:: -L, --local-only

    Perform only local mailbox operations (do not do mupdate operations).
    |v3-new-feature|

.. option:: -m, --mailboxes

    Mailbox mode.
    Remaining arguments are list of mailboxes which should be replicated.

.. option:: -n channel, --channel=channel

    Use the named channel for rolling replication mode.  If multiple
    channels are specified in ``sync_log_channels`` then use one of them.
    This option is probably best combined with **-S** to connect to a
    different server with each channel.

.. option:: -N, --skip-locked

    Use non-blocking sync_lock (combination of IP address and username)
    to skip over any users who are currently syncing.

.. option:: -o, --connect-once

    Only attempt to connect to the backend server once rather than
    waiting up to 1000 seconds before giving up.

.. option:: -O, --no-copyback

    No copyback mode. Replication will stop if the replica reports a CRC
    error, rather than doing a full mailbox sync. Useful if moving users to a
    new server, where you don't want any errors to cause the source servers
    to change the account.

.. option:: -p partition, --dest-partition=partition

    In mailbox or user replication mode: provides the name of the
    partition on the replica to which the mailboxes/users should be
    replicated.

.. option:: -r, --rolling

    Rolling (repeat) replication mode. Pick up a list of actions
    recorded by the :cyrusman:`lmtpd(8)`, :cyrusman:`imapd(8)`,
    :cyrusman:`pop3d(8)` and :cyrusman:`nntpd(8)` daemons from the file
    specified in ``sync_log_file``. Repeat until ``sync_shutdown_file``
    appears.  Alternative log and shutdown files can be specified with
    **-f** and **-F**.

    In this invocation, sync_client will background itself to run as a
    daemon.

.. option:: -R, --foreground-rolling

    As for **-r**, but without backgrounding.

.. option:: -1, --rolling-once

    As for **-R**, but only process a single log file before exiting.

.. option:: -s, --sieve-mode

    Sieve mode.
    Remaining arguments are list of users whose Sieve files should be
    replicated. Principally used for debugging purposes: not exposed to
    :cyrusman:`sync_client(8)`.

.. option:: -S servername, --server=servername

    Tells **sync_client** with which server to communicate.  Overrides
    the ``sync_host`` configuration option.

.. option:: -t timeout, --timeout=timeout

    Timeout for single replication run in rolling replication.
    **sync_client** will negotiate a restart after this many seconds.
    Default: 600 seconds

.. option:: -u, --userids

    User mode.
    Remaining arguments are list of users who should be replicated.

.. option:: -v, --verbose

    Verbose mode.  Use twice (**-v -v**) to log all protocol traffic to
    stderr.

.. option:: -w interval, --delayed-startup=interval

    Wait this long before starting. This option is typically used so
    that we can attach a debugger to one end of the replication system
    or the other.

.. option:: -z, --require-compression

    Require compression.
    The replication protocol will always try to enable deflate
    compression if both ends support it.  Set this flag when you want
    to abort if compression is not available.

.. option:: -a, --stage-to-archive

    Request the stage-to-archive feature. If the remote end has the
    ``archive_enabled`` option set, then it will stage incoming replication on
    the archive partition instead of the spool partition. If the remote end
    does not support it, replication will proceed as though **-a** was not
    provided.  This option is useful when standing up a new replica of an
    existing server, as most of the stored mail is likely older than the
    archive threshold and so is destined for the archive partition anyway. By
    staging on that partition, Cyrus can avoid a cross-partition copy for every
    message.

Examples
========

On a replication master, the following would be added to the START
section of :cyrusman:`cyrus.conf(5)`:

    ::

        syncclient		cmd="/usr/lib/cyrus/bin/sync_client -r"

[NB: More examples needed]

History
=======

The **-L** feature, local updates only, was added in version 3.0.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`sync_server(8)`, :cyrusman:`cyrus.conf(5)`,
:cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`
