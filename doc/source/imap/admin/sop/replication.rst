.. _replication:

============================================
Replication: Installation and Administration
============================================

Architecture
============

:ref:`Overall structure of replication <architecture_replication>`.

Installation
============

You will need to :ref:`build Cyrus IMAPd <installguide>` with the ``--enable-replication`` configure option. This builds the replication client/server applications and utilities.

Requirements
------------

1. At least one standalone Cyrus IMAP server to be the **master**.
2. At least one machine that will become the first **replica** server.

Replica server configuration
----------------------------

The **replica** server is a standalone server which listens for and processes synchronization messages from a **master** server. The replica server needs to be configured to accept synchronization messages. The replica server *MUST NOT* be configured to be part of a :ref:`Murder <architecture_murder>` (it should only be configured into the Murder at the point at which it replaces a failed backend master).

1. :ref:`Configure a standalone server <installguide>`.

2. Add the following line to the ``/etc/services`` file. Note that the port number is arbitrary as long as its not being used by any other services on your network.

    ::

        csync     2005/tcp

3. Add a line similar to the following in the SERVICES section of :cyrusman:`cyrus.conf(5)`:

    ::

        syncserver       cmd="/usr/cyrus/bin/sync_server" listen="csync"
  
4. Start/restart ``/usr/cyrus/bin/master``.

Master server configuration
---------------------------

The **master** server is the standalone, or backend server which is actively serving mailboxes to clients. This server needs to be configured to synchronize its mailstore with a **replica** server.

Add the following line to the ``/etc/services`` file.

::

   csync     2005/tcp
   
Note that the port number MUST be the same as that used on the replica server.

Specify the hostname of the replica server and how to authenticate to it in :cyrusman:`imap.conf(5)` using these options:
    * sync_host
    * sync_authname
    * sync_realm
    * sync_password
    
Note that sync_authname MUST be an admin user on the replica server. Also note that sync_realm and sync_password may not be necessary depending on the SASL mechanism used for authentication.

Compression
-----------

If you are running replication over a remote link, then the trade-off between bandwidth and CPU usage will tilt strongly in favour of enabling compression to save bandwidth at a slight increase in CPU cost. You can set the ``sync_compress`` value in :cyrusman:`imapd.conf(5)`, or pass the ``-z`` flag to :cyrusman:`sync_client(8)`.

::

    sync_compress: 1

Rolling replication
-------------------

**Rolling replication** means that the master server continuously synchronizes itself with the replica. 

To configure rolling replication, perform the following:

Enable the ``sync_log`` option in :cyrusman:`imapd.conf(5)`. This allows the imapd, pop3d, nntpd, and lmtpd services to log synchronization actions which will be periodically serviced by sync_client.

Optionally, adjust the ``sync_repeat_interval`` in :cyrusman:`imapd.conf(5)`.

Add a line similar to the following in the STARTUP section of :cyrusman:`cyrus.conf(5)`:

::

  syncclient       cmd="/usr/cyrus/bin/sync_client -r"
  
Start/restart ``usr/cyrus/bin/master``.

Administration
==============

Manual replication
------------------

To manually synchronize any part of the mailstore, run :cyrusman:`sync_client(8)` with the appropriate command line options. Note that you CAN manually synchronize even if rolling replication has been configured.

For example:

::

    [root@cyrus-master ~]# /usr/lib/cyrus-imapd/sync_client -S cyrus-replica.example.org -v -u john.doe@example.org
    USER john^doe@example.org
    
You can also run :cyrusman:`cyr_synclog(8)` instead, which will insert the record into the rolling replication log.

Failover
--------

.. :todo:
    Hmm! How does failover work?
