.. _replication:

============================================
Replication: Installation and Administration
============================================

Architecture
============

:ref:`Overall structure of replication <architecture_replication>`.

Terminology
===========
Host
    A computer chassis, slot or cabinet.  A machine.

Server or Service
    A program or process which "serves" a particular protocol.
    Typically a server will listen on a network port or Unix socket
    for communications from a client (local or remote).

Client
    A program or process which talks to a server or servers for a given
    protocol.  The initiator of a client/server session.

Instance
    A particular instance or iteration of a program, which may be one,
    or one of many, providing similar services to different consumers.

Master
    In this document, Master always means the source of data to be
    replicated.

Replica
    The target of data replication is the Replica, which refers both to
    an instance of sync_server and to the resultant dataset.

Operating Modes
===============

Cyrus replication supports two modes of operation: Rolling and
Periodic. The difference is that rolling replication is a more or less
continuous process whereas periodic replication occurs on demand,
triggered by some manual or automated process such as
:manpage:`cron(8)`.

Rolling Replication
-------------------

Rolling replication is enabled by setting ``sync_log`` to True in
:cyrusman:`imapd.conf(5)`.  With ``sync_log: true``, any process which
alters the mail spool will update the ``sync_log`` files with details
as to which mailbox(es) or users have been affected by their actions.
In this way the ``sync_log`` acts as a command file for the
:cyrusman:`sync_client(8)` process(es).

The log files are stored in ``{configdirectory}/sync/log`` for single
channel systems (see :ref:`replication-channels` for more information)
and are rotated on a regular basis by Cyrus.  Multi-channel deployments
will have a separate ``sync_log`` file for each, stored as
``{configdirectory}/sync/<channel>/log``.

Upon completing a log file, ``sync_client`` will go to sleep, or, if
processing took longer than ``sync_repeat_interval`` seconds, will
start over again on the next log.

.. Note::
    Any unsuccessful run of sync_client will result in the incomplete
    remains of the original log file being left behind as "log-<$PID>".
    This may be re-run as needed.

.. Note::
    Please also see :ref:`below for other uses of sync_log
    <replication-other-uses>`.

Periodic Replication
--------------------

With ``sync_log`` set to the default False, replication must be
triggered either by manually running :cyrusman:`sync_client(8)`, or by
doing so via ``cron`` or an entry in :cyrusman:`cyrus.conf(5)`.

In either event, command line switches control the operation of
``sync_client``.

Once the process completes its work, it will exit.

Idempotency
-----------

Synchronization itself is idempotent in either mode, so log files may
be "replayed" without concern of damage to the replica's mail spools.

Sync Chains
-----------

Cyrus supports chained replication, in which one replica replicates to
another.  I.e. A replicates to B; B replicates to C.  If you wish to
use this approach, please see the ``sync_log_chain`` setting:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob sync_log_chain
        :end-before: endblob sync_log_chain

Note that sync_log_chain is to be set on the middle server(s) in a
chain, not on the first or last.

Transport
=========

Older versions (pre-3.0) of Cyrus used the dedicated ``csync``
transport -- typically over TCP port 2005 -- and server process --
:cyrusman:`sync_server(8)` -- for replication. This is no longer
necessary.

From v3.0 forward, the :cyrusman:`sync_client(8)` will default to using
IMAP protocol for transport, and an IMAP instance on the replica will
process the synchronization instructions.  If you wish, you may
override this by setting the ``sync_try_imap`` setting in
:cyrusman:`imapd.conf(5)` to False.

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob sync_try_imap
        :end-before: endblob sync_try_imap

Installation
============

One must :ref:`build Cyrus IMAPd <compiling>` with the
``--enable-replication`` configure option. This builds the replication
client/server applications and utilities.

.. Note::
    Those using their distribution's packages may need to install a
    separate package for replication support.  For example, on Debian
    and derived distros, install the ``cyrus-replication`` package.

Requirements
------------

1. At least one Cyrus IMAP server instance to be the **master**.
2. At least one Cyrus IMAP server instance to be the **replica**.

.. Note::
    Sample configurations for both "master" and "replica" instances are
    included in the standard distribution.

Replica server configuration
----------------------------

The **replica** is a standalone server instance which listens for and
processes synchronization messages from a single **master** server. The
replica server needs to be configured to accept synchronization
messages via IMAP or the (deprecated) :cyrusman:`sync_server(8)`
process.

.. Important::
    Within a Cyrus :ref:`Murder <architecture_murder>` environment,
    replicas must **not** be configured to invoke
    :cyrusman:`ctl_mboxlist(8)` on startup (pushing the local mailbox
    list to the **Mupdate Master**).  This may only be done on the
    Master instance.

.. Important::
    It is critically important that all partitions existing on a master
    server instance also be present on all replica instances.  Failure
    to ensure this will result in crashes and could lead to lost data
    on the replicas.

1. :ref:`Configure a standalone server <installing>`.

2. If using the deprecated sync_server scheme, add the following line
   to the ``/etc/services`` file. Note that the port number is
   arbitrary as long as its not being used by any other services on the
   network.

    ::

        csync     2005/tcp

3. If using the deprecated sync_server scheme, add a line similar to
   the following in the SERVICES section of :cyrusman:`cyrus.conf(5)`:

    ::

        syncserver       cmd="/usr/cyrus/bin/sync_server" listen="csync"

4. Start/restart ``/usr/cyrus/bin/master``.

Master server configuration
---------------------------

The **master** server is a standalone or backend Cyrus IMAP server
instance which is actively serving mailboxes to clients. This server
needs to be configured to synchronize its mailstore with a **replica**
server via an instance of :cyrusman:`sync_client(8)`.

If using the deprecated sync_server scheme, add the following line to
the ``/etc/services`` file.

::

   csync     2005/tcp

.. Note::
    The port number **MUST** be the same as that used on the replica
    server.

Specify the hostname of the replica server and how to authenticate to
it in :cyrusman:`imapd.conf(5)` using these options:

    * sync_host
    * sync_port
    * sync_authname
    * sync_realm
    * sync_password

.. Note::
    ``sync_authname`` **MUST** be an ``admin`` user on the replica.

.. Note::
    ``sync_realm`` and ``sync_password`` may not be necessary
    depending on the SASL mechanism used for authentication.

.. Note::
    See :ref:`replication-channels`, below, for details on how to use
    these settings to control syncing to multiple replicas.

.. Important::
    If using sync_log_channels for any other purpose, such as
    specifying the sync_log used by :cyrusman:`squatter(8)` command,
    you must *also* either specify a sync_log channel for replication,
    or specify the default "" (the two-character string U+22 U+22).

Add invocation specifications to :cyrusman:`cyrus.conf(5)` to spawn
:cyrusman:`sync_client(8)` as desired (for each channel used) as
described below in Rolling Replication or Periodic Replication.

Compression
-----------

If one runs replication over a WAN link, the trade-off between
bandwidth and CPU usage will tilt strongly in favour of enabling
compression to save bandwidth at a slight increase in CPU cost.  Set
the ``sync_compress`` value in :cyrusman:`imapd.conf(5)`::

    sync_compress: On

or pass the ``-z`` flag to :cyrusman:`sync_client(8)` in the service
spec in :cyrusman:`cyrus.conf(5)`::

    syncclient       cmd="/usr/cyrus/bin/sync_client -r -z"

Rolling Replication Configuration
---------------------------------

**Rolling Replication** means that the master instance continuously
synchronizes itself with a replica.

To configure rolling replication, perform the following:

1.  Enable the ``sync_log`` option in :cyrusman:`imapd.conf(5)`. This
    allows the imapd, pop3d, nntpd, and lmtpd services to log
    synchronization actions which will be periodically serviced by
    sync_client::

        sync_log: On

2.  Optionally, adjust the ``sync_repeat_interval`` in
    :cyrusman:`imapd.conf(5)`::

        sync_repeat_interval: 300

3.  Add a line similar to the following in the STARTUP section of
    :cyrusman:`cyrus.conf(5)`::

        syncclient       cmd="/usr/cyrus/bin/sync_client -r"

Start/restart ``/usr/cyrus/bin/master``.

.. Hint::
    In a multi-channel mesh, the channel to be used by a given
    sync_client must be specified via the "-n <channel>" argument on
    the command line::

        syncclient       cmd="/usr/cyrus/bin/sync_client -r -n channel1"

Terminating Rolling Replication
-------------------------------

To be able to stop rolling replication at any time, configure the
``sync_shutdown_file`` option in :cyrusman:`imapd.conf(5)` to point to
a non-existant file, the appearance of this file will trigger a
shutdown of a :cyrusman:`sync_client(8)` instance::

    sync_shutdown_file: /var/lib/imap/syncstop

Tweaking Rolling Replication
----------------------------

The default frequency of replication runs is 3 seconds.  Lengthening
this produces higher efficiency at the cost of slightly more stale data
on the replica.  Alter this via the sync_repeat_interval in
:cyrusman:`imapd.conf(5)` or by using the "-d" argument in the
invocation of :cyrusman:`sync_client(8)`.

Periodic Replication Configuration
----------------------------------

In Periodic Replication the sync_client instance must be spawned
from time to time, causing replication to start at that time.  This may
be handled via a :manpage:`cron(8)` job, or by adding an entry to the
EVENTS section of :cyrusman:`cyrus.conf(5)` like any of these::

    EVENTS {
        <...>
        # Periodically sync ALL user mailboxes every 4 hours
        syncclient       cmd="/usr/cyrus/bin/sync_client -A" period=240

        # Periodically sync changes at specific times
        syncclient       cmd="/usr/cyrus/bin/sync_client -A" at=0800
        syncclient       cmd="/usr/cyrus/bin/sync_client -A" at=1200
        syncclient       cmd="/usr/cyrus/bin/sync_client -A" at=1800
        <...>
    }

.. Note::
    When using the "-A" flag (sync all users) no non-user
    mailboxes are synced.  As the man page :cyrusman:`imapd.conf(5)`
    notes, "... this could be considered a bug and maybe it should do
    those mailboxes independently."

Tweaking Replication
--------------------

You may control the number of messages replicated in each batch, via
the ``sync_batchsize`` setting:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob sync_batchsize
        :end-before: endblob sync_batchsize

.. _replication-channels:

Channels
========

The Cyrus replication scheme is very flexible, and supports meshes in
which masters running on various hosts may replicate to instances on
other hosts.  This is achieved by use of the Channels feature of the
replication system.

To employ channels, prefix any of the following sync\_ configuration
options in :cyrusman:`imapd.conf(5)` with the channel name and an
underscore "_" character as needed::

    sync_authname
    sync_password
    sync_realm
    sync_host
    sync_port
    sync_repeat_interval
    sync_shutdown_file

Then add the setting ``sync_log_channels`` with a list of the channels::

    sync_log_channels: chan1 chan2 chan3

For example, a site using the same auth credentials for all servers has
no need to specify unique per-channel settings for ``sync_authname``,
``sync_password`` or ``sync_realm``, but might do the following for the
rest of the sync related settings in :cyrusman:`imapd.conf(5)`::

    sync_authname: replman
    sync_password: <secret>
    sync_log_channels: repl1 repl2 offsite
    ##
    # The main replica
    repl1_sync_host: mailrepl1.example.org
    repl1_sync_repeat_interval: 180
    repl1_shutdown_file: /run/cyrus/sync/repl1_shutdown
    ##
    # A second replica used to feed the tape backup system
    repl2_sync_host: mailrepl2.example.org
    repl2_sync_repeat_interval: 180
    repl2_shutdown_file: /run/cyrus/sync/repl2_shutdown
    ##
    # An offsite replica which needs a different port and uses a slower
    # cycle rate
    offsite_sync_port: 19205
    offsite_sync_host: mailoffsite.example.org
    offsite_sync_repeat_interval: 360
    offsite_shutdown_file: /run/cyrus/sync/offsite_shutdown

Then these entries in :cyrusman:`cyrus.conf(5)` would complete the
exercise::

    repl1sync       cmd="/usr/cyrus/bin/sync_client -r -n repl1"
    repl2sync       cmd="/usr/cyrus/bin/sync_client -r -n repl2"
    offsitesync     cmd="/usr/cyrus/bin/sync_client -r -n offsite"

Again, this is just an example for illustration.  The system provides so
much flexibility, and one can combine channels with chaining to achieve
even more.

.. _replication-other-uses:

Other Considerations
====================

.. Important::
    This section is currently under development.  If you believe you
    are impacted by these considerations, please check back with each
    release and follow the mailing list.

The infrastructure provided by ``sync_log`` has now been leveraged by
the Rolling Indexing capability introduced in v3.0.  See
:cyrusman:`squatter(8)` for more details (see the fourth mode synopsis).

Specifically, the following new settings have been added to
:cyrusman:`imapd.conf(5)` in support of this new use of ``sync_log``:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob sync_log_unsuppressable_channels
        :end-before: endblob sync_log_unsuppressable_channels

Administration
==============

Manual replication
------------------

To manually synchronize any part of the mailstore, run
:cyrusman:`sync_client(8)` with the appropriate command line options.
Note that manual synchronization DOES NOT interfere with rolling
replication.

For example:

::

    [root@skynet ~]# /usr/lib/cyrus-imapd/sync_client -S cyrus-replica.example.org -v -u john.doe@example.org
    USER john^doe@example.org

One can run :cyrusman:`cyr_synclog(8)` instead, which will insert the
record into the rolling replication log.

Failover
--------

.. :todo:
    Hmm! How does failover work?
    Clue: It's not automated (yet)...
