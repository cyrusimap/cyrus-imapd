.. _cyrus-backups:

=============
Cyrus Backups
=============

.. contents::


Introduction
========================

Cyrus Backups are a replication-based backup service for Cyrus IMAP servers.
This is currently an experimental feature. If you have the resources to try it
out alongside your existing backup solutions, feedback would be appreciated.

This document is intended to be a guide to the configuration and
administration of Cyrus Backups.

This document is a work in progress and at this point is incomplete.

This document assumes that you are familiar with compiling, installing,
configuring and maintaining Cyrus IMAP servers generally, and will only discuss
backup-related portions in detail.

This document assumes a passing familiarity with
:ref:`Cyrus Replication <replication>`.

Limitations
===========

Cyrus Backups are experimental and incomplete.

The following components exist and appear to work:

-  backupd, and therefore inbound replication
-  autovivification of backup storage for new users, with automatic partition
   selection
-  rebuilding of backup indexes from backup data files
-  compaction of backup files to remove stale data and combine chunks for
   better compression
-  deep verification of backup file/index state
-  examination of backup data
-  locking tool, for safe non-cyrus operations on backup files
-  recovery of data back into a Cyrus IMAP server

The following components don't yet exist in a workable state -- these tasks
must be massaged through manually (with care):

-  reconstruct of backups.db from backup files

The following types of information are currently backed up and recoverable

-  mailbox state and annotations
-  messages
-  mailbox message records, flags, and annotations

The following types of information are currently backed up, but tools to
recover them don't yet exist:

-  sieve scripts (but not active script status)
-  subscriptions
-  seen data

The following types of information are not currently backed up

-  quota information

Architecture
============

Cyrus Backups are designed to run on one or more standalone, dedicated backup
servers, with suitably-sized storage partitions. These servers generally do
not run an IMAP daemon, nor do they have conventional mailbox storage.

Your Cyrus IMAP servers synchronise mailbox state to the Cyrus Backup server(s)
using the Cyrus replication (aka sync, aka csync) protocol.

Backup data is stored in two files per user: a data file, containing gzipped
chunks of replication commands; and an SQLite database, which indexes the
current state of the backed up data. User backup files are stored in a hashed
subdirectory of their containing partition.

A twoskip database, backups.db, stores mappings of users to their backup file
locations

Installation
============

Requirements
------------

-  At least one Cyrus IMAP server, serving and storing user data.
-  At least one machine which will become the first backup server.

Cyrus Backups server
--------------------

#. Compile cyrus with the ``--enable-backup`` configure option and install it.
#. Set up an :cyrusman:`imapd.conf(5)` file for it with the following options
   (default values shown):

    backup\_db: twoskip
        The twoskip database format is recommended for backups.db
    backup\_db\_path: {configdirectory}/backups.db
        The backups db contains a mapping of user ids to their backup locations
    backup\_staging\_path: {temp\_path}/backup
        Directory to use for staging message files during backup operations.
        The replication protocol will transfer as many as 1024 messages in a
        single sync operation, so, conservatively, this directory needs to
        contain enough storage for 1024 \* your maximum message size \* number
        of running backupd's, plus some wiggle room.
    backup\_retention\_days: 7
        Number of days for which backup data (messages etc) should be kept
        within the backup storage after the corresponding item has been
        deleted/expunged from the Cyrus IMAP server.
    backuppartition-\ *name*: /path/to/this/partition
        You need at least one backuppartition-\ *name* to store backup data.
        These work similarly to regular/archive IMAP partitions, but note that
        there is no relationship between backup partition names and
        regular/archive partition names. New users will be have their backup
        storage provisioned according to the usual partition selection rules.
    backup\_compact\_minsize: 0
        The ideal minimum data chunk size within backup files, in kB. The
        compact tool will try to combine chunks that are smaller than this
        into neighbouring chunks. Larger values tend to yield better
        compression ratios, but if the data is corrupted on disk, the entire
        chunk will become unreadable. Zero turns this behaviour off.
    backup\_compact\_maxsize: 0
        The ideal maximum data chunk size within backup files, in kB. The
        compact tool will try to split chunks that are larger than this into
        multiple smaller chunks. Zero turns this behaviour off.
    backup\_compact\_work\_threshold: 1
        The number of chunks within a backup file that must obviously need
        compaction before the compact tool will attempt to compact the file.
        Larger values are expected to reduce compaction I/O load at the expense
        of delayed recovery of storage space.

#. Create a user for authenticating to the backup system, and add it to the
   ``admins`` setting in :cyrusman:`imapd.conf(5)`
#. Add appropriate ``sasl_*`` settings for your authentication method to
   :cyrusman:`imapd.conf(5)`
#. Set up a :cyrusman:`cyrus.conf(5)` file for it::

    SERVICES {
        # backupd is probably the only service entry your backup server needs
        backupd cmd="backupd" listen="csync" prefork=0
    }

    EVENTS {
        # this is required
        checkpoint cmd="ctl_cyrusdb -c" period=30

        # arrange for compact to run at some interval
        compact cmd="ctl_backups compact -A" at=0400
    }

#. Start up the server, and use :cyrusman:`synctest(1)` to verify that you can
   authenticate to backupd

Cyrus IMAP servers
------------------

Your Cyrus IMAP servers must be running version 3 or later of Cyrus, and must
have been compiled with the ``--enable-replication`` configure option.  It does
*not* need to be recompiled with the ``--enable-backup`` option.

It's recommended to set up a dedicated replication channel for backups, so that
your backup replication can coexist independently of your other replication
configurations

Add settings to :cyrusman:`imapd.conf(5)` like (default values shown):

*channel*\ \_sync\_host: backup-server.example.com
    The host name of your Cyrus Backup server
*channel*\ \_sync\_port: csync
    The port on which your Cyrus Backup server's backupd process listens
*channel*\ \_sync\_authname: ...
    Credentials for authenticating to the Cyrus Backup server
*channel*\ \_sync\_password: ...
    Credentials for authenticating to the Cyrus Backup server

Using rolling replication
+++++++++++++++++++++++++

You can configure backups to use rolling replication.  Depending on the sync
repeat interval you configure, this can be used to keep your backups very
current -- potentially as current as your other replicas.

To configure rolling replication, add additional settings to
:cyrusman:`imapd.conf(5)` like:

sync\_log: 1
    Enable sync log if it wasn't already.
sync\_log\_channels: *channel*
    Add a new channel "*channel*" to whatever was already here. Suggest calling
    this "backup"
*channel*\ \_sync\_repeat\_interval: 1
    Minimum time in seconds between rolling replication runs. Smaller value
    means livelier backups but more network I/O. Larger value reduces I/O.

Update :cyrusman:`cyrus.conf(5)` to add a :cyrusman:`sync_client(8)` invocation
to the DAEMON section specifying (at least) the ``-r`` and ``-n channel``
options.

See :cyrusman:`imapd.conf(5)` for additional *sync\_* settings that can
be used to affect the replication behaviour.  Many can be prefixed with
a channel to limit their affect to only backups, if necessary.

Using scheduled replication (push)
++++++++++++++++++++++++++++++++++

You can configure backups to occur on a schedule determined by the IMAP
server.

To do this, add :cyrusman:`sync_client(8)` invocations to the EVENTS section
of :cyrusman:`cyrus.conf(5)` (or cron, etc), specifying at least the
``-n channel`` option (to use the channel-specific configuration), plus
whatever other options you need for selecting users to back up. See the
:cyrusman:`sync_client(8)` manpage for details.

You could also invoke :cyrusman:`sync_client(8)` in a similar way from a
custom script running on the IMAP server.

Using scheduled replication (pull)
++++++++++++++++++++++++++++++++++

You can configure backups to occur on a schedule determined by the
backup server.  For example, you may have a custom script that examines
the existing backups, and provokes fresh backups to occur if they are
determined to be out of date.

To to this, enable XBACKUP on your IMAP server by adding the following
setting to :cyrusman:`imapd.conf(5)`:

xbackup\_enabled: yes
    Enables the XBACKUP command in imapd.

Your custom script can then authenticate to the IMAP server as an admin
user, and invoke the command ``XBACKUP pattern [channel]``.  A replication
of the users or shared mailboxes matching the specified pattern will occur
to the backup server defined by the named channel.  If no channel is
specified, default sync configuration will be used.

For example::

    C: 1 XBACKUP user.* backup
    S: * OK USER anne
    S: * OK USER bethany
    S: * NO USER cassandane (Operation is not supported on mailbox)
    S: * OK USER demi
    S: * OK USER ellie
    S: 1 OK Completed

This replicates all users to the channel *backup*.


Administration
==============

Storage requirements
--------------------

It's not really known yet how to predict the storage requirements for a backup
server. Experimentation in dev environment suggests around 20-40% compressed
backup file size relative to the backed up data, depending on compact settings,
but this is with relatively tiny mailboxes and non-pathological data.

The backup staging spool conservatively needs to be large enough to hold an
entire sync's worth of message files at once. Which is your maximum message
size \* 1024 messages \* the number of backupd processes you're running, plus
some wiggle room probably. In practice it'll probably not hit this limit
unless someone is trying to. (Most users, I suspect, don't have 1024
maximum-sized messages in their account, or don't receive them all at once
anyway.)

Certain invocations of ctl\_backups and cyr\_backup also require staging spool
space, due to the way replication protocol (and thus backup data) parsing
handles messages. So keep this in mind I suppose.

Initial backups
---------------

Once a Cyrus Backup system is configured and running, new users that are
created on the IMAP servers will be backed up seamlessly without administrator
intervention.

The very first backup taken of a pre-existing mailbox will be big -- the entire
mailbox in one hit. It's suggested that, when initially provisioning a Cyrus
Backup server for an existing Cyrus IMAP environment, that the
:cyrusman:`sync_client(8)` commands be run carefully, for a small group of
mailboxes at a time, until all/most of your mailboxes have been backed up at
least once. Also run the :cyrusman:`ctl_backups(8)` ``compact`` command on the
backups, to break up big chunks, if you wish.  Only then should you enable
rolling/scheduled replication.

Restoring from backups
----------------------

The :cyrusman:`restore(8)` tool will restore mailboxes and messages from a
specified backup to a specified destination server. The destination server must
be running a replication-capable :cyrusman:`imapd(8)` or
:cyrusman:`sync_server(8)`. The restore tool should be run from the backup
server containing the specified backup.

File locking
------------

All :cyrusman:`backupd(8)`/:cyrusman:`ctl_backups(8)`/:cyrusman:`cyr_backup(8)`
operations first obtain a lock on the relevant backup file.  ctl\_backups and
cyr\_backup will try to do this without blocking (unless told otherwise),
whereas backupd will never block.

Moving backup files to different backup partitions
--------------------------------------------------

There's no tool for this (yet). To do it manually, stop backupd, copy the files
to the new partition, then use :cyrusman:`cyr_dbtool(8)` to update the user's
backups.db entry to point to the new location. Run the
:cyrusman:`ctl_backups(8)` ``verify`` command on both the new filename (``-f``
mode) and the user's userid (``-u`` mode) to ensure everything is okay, then
restart backupd.

Provoking a backup for a particular user/user group/everyone/etc right now
--------------------------------------------------------------------------

Just run :cyrusman:`sync_client(8)` by hand with appropriate options (as cyrus
user, of course). See its man page for ways of specifying items to replicate.

If the IMAP server with the user's mail has been configured with the
``xbackup_enabled: yes`` option in :cyrusman:`imapd.conf(5)`, then an admin
user can cause a backup to occur by sending the IMAP server an ``XBACKUP``
command.

What about tape backups?
------------------------

As long as backupd, ctl\_backups and cyr\_backup are not currently running (and
assuming no-one's poking around in things otherwise), it's safe to take/restore
a filesystem snapshot of backup partitions. So to schedule, say, a nightly tape
dump of your Cyrus Backup server, make your cron job shut down Cyrus, make the
copy, then restart Cyrus.

Meanwhile, your Cyrus IMAP servers are still online and available.  Regular
backups will resume once your backupd is running again.

If you can work at a finer granularity than file system, you don't need to shut
down backupd. Just use the :cyrusman:`ctl_backups(8)` ``lock`` command to hold
a lock on each backup while you work with its files, and the rest of the backup
system will work around that.

Restoring is more complicated, depending on what you actually need to do:
when you restart the backupd after restoring a filesystem snapshot, the next
time your Cyrus IMAP server replicates to it, the restored backups will be
brought up to date. Probably not what you wanted -- so don't restart backupd
until you've done whatever you were doing.

Multiple IMAP servers, one backup server
----------------------------------------

This is fine, as long as each user being backed up is only being backed up by
one server (or they are otherwise synchronised). If IMAP servers have different
ideas about the state of a user's mailboxes, one of those will be in sync with
the backup server and the other will get a lot of replication failures.

Multiple IMAP servers, multiple backup servers
----------------------------------------------

Make sure your :cyrusman:`sync_client(8)` configuration(s) on each IMAP server
knows which users are being backed up to which backup servers, and selects
them appropriately. See the :cyrusman:`sync_client(8)` man page for options for
specifying users, and run it as an event (rather than rolling).

Or just distribute it at server granularity, such that backup server A serves
IMAP servers A, B and C, and backup server B serves IMAP servers D, E, F, etc.

One IMAP server, multiple backup servers
----------------------------------------

Configure one channel plus one rolling :cyrusman:`sync_client(8)` per backup
server, and your IMAP server can be more or less simultaneously backed up to
multiple backup destinations.

Reducing load
-------------

To reduce load on your client-facing IMAP servers, configure sync log chaining
on their replicas and let those take the load of replicating to the backup
servers.

To reduce network traffic, do the same thing, specifically using replicas that
are already co-located with the backup server.

Other setups
------------

The use of the replication protocol and :cyrusman:`sync_client(8)` allows a lot
of interesting configuration possibilities to shake out. Have a rummage in the
:cyrusman:`sync_client(8)` man page for inspiration.

Tools
=====

ctl\_backups
------------

This tool is generally for mass operations that require few/fixed arguments
across multiple/all backups

Supported operations:

compact
    Reduce backups' disk usage by:

    * combining small chunks for better gzip compression -- especially
      important for hot backups, which produce many tiny chunks
    * removing deleted content that has passed its retention period
list
    List known backups.
lock
    Lock a single backup, so you can safely work on it with non-cyrus tools.
reindex
    Regenerate indexes for backups from their data files. Useful if index
    becomes corrupted by some bug, or invalidated by working on data with
    non-cyrus tools.
stat
    Show statistics about backups -- disk usage, compression ratio, etc.
verify
    Deep verification of backups. Verifies that:

    * Checksums for each chunk in index match data
    * Mailbox states are in the chunk that the index says they're in
    * Mailbox states match indexed states
    * Messages are in the chunk the index says they're in
    * Message data checksum matches indexed checksums

See the :cyrusman:`ctl_backups(8)` man page for more information.

cyr\_backup
-----------

This tool is generally for operations on a single mailbox that require multiple
additional arguments

Supported operations

list [ chunks \| mailboxes \| messages \| all ]
    Line-per-item listing of information stored in a backup.
show [ chunks \| mailboxes \| messages ] items...
    Paragraph-per-item listing of information for specified items. Chunk items
    are specified by id, mailboxes by mboxname or uniqueid, messages by guid.
dump [ chunk \| message ] item
    Full dump of one item. chunk dumps the uncompressed content of a chunk
    (i.e. a bunch of sync protocol commands). message dumps a raw rfc822
    message (useful for manually restoring)

See the :cyrusman:`cyr_backup(8)` man page for more information.

restore
-------

This tool is for restoring mail from backup files.

Required arguments are a destination server (in ip:port or host:port format),
a backup file, and mboxnames, uniqueids or guids specifying the mailboxes or
messages to be restored.

If the target mailbox does not already exist on the destination server, options
are available to preserve the mailbox and message properties as they existed
in the backup. This is useful for rebuilding a lost server from backups, such
that client state remains consistent.

If the target mailbox already exists on the destination server, restored
messages will be assigned new, unused uids and will appear to the client as new
messages.

See the :cyrusman:`restore(8)` man page for more information.
