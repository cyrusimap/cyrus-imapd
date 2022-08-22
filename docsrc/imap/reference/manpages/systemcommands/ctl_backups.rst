.. cyrusman:: ctl_backups(8)

.. program:: ctl_backups

.. _imap-reference-manpages-systemcommands-ctl_backups:

===============
**ctl_backups**
===============

Perform administrative operations directly on Cyrus backups.

Synopsis
========

.. parsed-literal::

    **ctl_backups** [OPTIONS] compact [MODE] *backup*...
    **ctl_backups** [OPTIONS] list [LIST OPTIONS] [[MODE] *backup*...]
    **ctl_backups** [OPTIONS] lock [LOCK OPTIONS] [MODE] *backup*
    **ctl_backups** [OPTIONS] reindex [MODE] *backup*...
    **ctl_backups** [OPTIONS] stat [MODE] *backup*...
    **ctl_backups** [OPTIONS] verify [MODE] *backup*...

Description
===========

**ctl_backups** is a tool for performing administrative operations on Cyrus
backups.

**ctl_backups** |default-conf-text|

In all invocations, *backup* is interpreted according to the specified MODE.
See :ref:`ctl-backups-modes` below.

**ctl_backups** provides the following sub-commands:

.. option:: compact

    Reduce storage required by the named backups.  Compact behaviour is
    influenced by the **backup_compact_minsize**, **backup_compact_maxsize**,
    **backup_compact_work_threshold**, and **backup_retention_days**
    configuration settings.  See :cyrusman:`imapd.conf(5)` for details.

    This should generally be invoked regularly, such as by adding an
    entry to the EVENTS section of :cyrusman:`cyrus.conf(5)`.  See
    :ref:`ctl-backups-examples` for an example.

    If the **backup_keep_previous** configuration setting is enabled,
    compact will preserve the original data and index files (renaming
    them with a timestamp).  This is useful for debugging.

.. option:: list

    List backups.  See :ref:`ctl-backups-list-options` for options specific
    to the **list** sub-command.  Columns are separated by tabs, and are:

    * end time of latest chunk
    * size of backup data file on disk
    * userid to which the backup belongs
    * path to backup data file

    If no :ref:`mode <ctl-backups-modes>` or backups are specified, lists all
    known backups (as if invoked with the **-A** mode).

.. option:: lock

    Obtain and hold a lock on the named backup.  Useful for operating on
    Cyrus backup files using non-Cyrus tools (such as UNIX tools or custom
    scripts) in relative safety.  See :ref:`ctl-backups-lock-options` for details.

.. option:: reindex

    Rebuild the indexes for the named backups, based on the raw backup data.
    This is useful if their index files have been corrupted, or if the index
    format has changed.

    If the **backup_keep_previous** configuration setting is enabled,
    reindex will preserve the original index file (renaming it with a
    timestamp).  This is useful for debugging.

.. option:: stat

    Display stats for the named backups.  Columns are separated by tabs, and
    are:

    * userid or filename
    * compressed (i.e. on disk) size
    * uncompressed size
    * compactable size
    * compression ratio
    * utilisation ratio
    * start time of latest chunk
    * end time of latest chunk

    The compactable size is an approximation of how much uncompressed data would
    remain after **compact** is performed.  The utilisation ratio is this figure
    expressed as a percentage of the uncompressed size.  Note that this
    approximation is an underestimate.  That is to say, a backup that has just
    been compacted will probably still report less than 100% utilisation.

.. option:: verify

    Verify consistency of the named backups by performing deep checks on both
    the raw backup data and its index.

Options
=======

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -F, --force

    Force the operation to occur, even if it is determined to be unnecessary.
    This is mostly useful with the **compact** sub-command.

.. option:: -S, --stop-on-error

    Stop-on-error.  With this option, if a sub-command fails for any
    particular backup, **ctl_backups** will immediately exit with an error,
    without processing further backups.

    The default is to log the error, and continue with the next backup.

.. option:: -V, --no-verify

    Don't verify backup checksums for read-only operations.

    The read-only operations **list** and **stat** will normally perform a
    "quick" verification of the backup file being read, which checks the
    checksums of the most recent chunk.  This can be slow for backups
    whose most recent backup chunk is very large.

    With this option, the verification step will be skipped.

.. option:: -j, --json

    Produce output in JSON format.  The default is plain text.

.. option:: -v, --verbose

    Increase the verbosity.  Can be specified multiple times.

.. option:: -w, --wait-for-locks

    Wait for locks.  With this option, if a backup named on the command line is
    locked, execution will block until the lock becomes available.

    The default is to skip backups that are currently locked.


.. _ctl-backups-list-options:

List Options
============

Options that apply only to the **list** sub-command.

.. option:: -t [hours], --stale[=hours]

    List stale backups only, that is, backups that have received no updates
    in *hours*.  If *hours* is unspecified, it defaults to 24.

.. _ctl-backups-lock-options:

Lock Options
============

Options that apply only to the **lock** sub-command.

.. option:: -c, --create

    Exclusively create the named backup while obtaining the lock.  Exits
    immediately with an error if the named backup already exists.

    When the lock is successfully obtained, continue as per the other options.

.. option:: -p, --pause

    Locks the named backup, and then waits for EOF on the standard input
    stream.  Unlocks the backup and exits once EOF is received.  This is the
    default mode of operation.

.. option:: -s, --sqlite3

    Locks the named backup, and with the lock held, opens its index file in
    the :manpage:`sqlite3(1)` program.  The lock is automatically released when
    sqlite3 exits.

.. option:: -x command, --execute=command

    Locks the named backup, and with the lock held, executes *command* using
    **/bin/sh** (as per :manpage:`system(3)`).  The lock is automatically
    released when *command* completes.

    The filenames of the backup data and index are made available to *command*
    in the environment variables **$ctl_backups_lock_data_fname** and
    **$ctl_backups_lock_index_fname**, respectively.

.. _ctl-backups-modes:

Modes
=====

.. option:: -A, --all

    Run sub-command over all known backups.

    Known backups are recorded in the database specified by the **backup_db**
    and **backup_db_path** configuration options.

.. option:: -D, --domains

    Backups specified on the command line are interpreted as domains.  Run
    sub-command over known backups for users in these domains.

.. option:: -P, --prefixes

    Backups specified on the command line are interpreted as userid prefixes.
    Run sub-command over known backups for users matching these prefixes.

.. option:: -f, --filenames

    Backups specified on the command line are interpreted as filenames.  Run
    sub-command over the matching backup files.  The backup files do not need
    to be known about in the backups database.

.. option:: -m, --mailboxes

    Backups specified on the command line are interpreted as mailbox names.
    Run sub-command over known backups containing these mailboxes.

.. option:: -u, --userids

    Backups specified on the command line are interpreted as userids.  Run
    sub-command over known backups for matching users.

    This is the default if no mode is specified.

.. _ctl-backups-examples:

Examples
========

Scheduling **ctl_backups compact** to run each morning using the EVENTS
section of :cyrusman:`cyrus.conf(5)`:

.. parsed-literal::
    EVENTS {
        checkpoint    cmd="ctl_cyrusdb -c" period=30

        **compact       cmd="ctl_backups compact -A" at=0400**
    }


History
=======

Files
=====

See Also
========

:cyrusman:`imapd.conf(5)`,
:manpage:`sqlite3(1)`,
:manpage:`system(3)`
