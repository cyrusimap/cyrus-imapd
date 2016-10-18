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

Installation
============

One must :ref:`build Cyrus IMAPd <installguide>` with the
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

Replica server configuration
----------------------------

The **replica** is a standalone server instance which listens for and
processes synchronization messages from a single **master** server. The
replica server needs to be configured to accept synchronization
messages via the :cyrusman:`sync_server(8)` process.

.. Important::
    Within a Cyrus :ref:`Murder <architecture_murder>` environment,
    replicas must **not** be configured to invoke
    :cyrusman:`ctl_mboxlist(8)` on startup (pushing the local mailbox
    list to the **Mupdate Master**).  This may only be done on the
    Master instance.

1. :ref:`Configure a standalone server <installguide>`.

2. Add the following line to the ``/etc/services`` file. Note that the
   port number is arbitrary as long as its not being used by any other
   services on the network.

    ::

        csync     2005/tcp

3. Add a line similar to the following in the SERVICES section of
   :cyrusman:`cyrus.conf(5)`:

    ::

        syncserver       cmd="/usr/cyrus/bin/sync_server" listen="csync"
  
4. Start/restart ``/usr/cyrus/bin/master``.

Master server configuration
---------------------------

The **master** server is a standalone or backend Cyrus IMAP server
instance which is
actively serving mailboxes to clients. This server needs to be
configured to synchronize its mailstore with a **replica** server via an
instance of :cyrusman:`sync_client(8)`.

Add the following line to the ``/etc/services`` file.

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

Rolling Replication
-------------------

**Rolling Replication** means that the master instance continuously
synchronizes itself with a replica.

To configure rolling replication, perform the following:

1.  Enable the ``sync_log`` option in :cyrusman:`imapd.conf(5)`. This
    allows the imapd, pop3d, nntpd, and lmtpd services to log
    synchronization actions which will be periodically serviced by
    sync_client::

        sync_log: On

2. Optionally, adjust the ``sync_repeat_interval`` in :cyrusman:`imapd.conf(5)`::

        sync_repeat_interval: 300

3.  Add a line similar to the following in the STARTUP section of
    :cyrusman:`cyrus.conf(5)`::

        syncclient       cmd="/usr/cyrus/bin/sync_client -r"
  
Start/restart ``usr/cyrus/bin/master``.

.. Hint::
    In a multi-channel mesh, the channel to be used by a given
    sync_client must be specified via the "-n <channel>" argument on the
    command line::

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

Periodic Replication
--------------------

In Periodic Replication the sync_client instance must be spawned
from time to time, causing replication to start at that time.  This may
be handled via a :manpage:`cron(8)` job, or by adding an entry to the
EVENTS section of :cyrusman:`cyrus.conf(5)` like any of these::

    EVENTS {
        <...>
        # Peridoically sync ALL user mailboxes every 4 hours
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

    sync_log_channels: repl1 repl2 offsite
    ##
    # The main replica
    repl1_sync_host: mailrepl1.example.org
    repl1_sync_repeat_interval: 180
    repl1_shutdown_file: /var/lib/imap/sync/repl1_shutdown
    ##
    # A second replica used to feed the tape backup system
    repl2_sync_host: mailrepl2.example.org
    repl2_sync_repeat_interval: 180
    repl2_shutdown_file: /var/lib/imap/sync/repl2_shutdown
    ##
    # An offsite replica which needs a different port and uses a slower
    # cycle rate
    offsite_sync_port: 19205
    offsite_sync_host: mailoffsite.example.org
    offsite_sync_repeat_interval: 360
    offsite_shutdown_file: /var/lib/imap/sync/offsite_shutdown

Then these entries in :cyrusman:`cyrus.conf(5)` would complete the
exercise::

    repl1sync       cmd="/usr/cyrus/bin/sync_client -r -n repl1"
    repl2sync       cmd="/usr/cyrus/bin/sync_client -r -n repl2"
    offsitesync     cmd="/usr/cyrus/bin/sync_client -r -n offsite"

Again, this is just an example for illustration.  The system provides so
much flexibility, and one can combine channels with chaining to acheive
even more.

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
