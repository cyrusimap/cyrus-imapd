.. _architecture:

==================================
System Architecture
==================================

High Level Architecture
=======================

A birds-eye view of Cyrus.

.. image:: images/architecture.jpg
    :height: 400 px
    :width: 636 px
    :alt: High level architecture diagram.
    :align: center

Mail is delivered over smtp to the MTA_ (Message/Mail Transfer Agent). This then is delivered to **Cyrus imapd** over lmtp_ (Local Mail Transfer Protocol). 

Cyrus processes the inbound message and makes it available to the user over POP3, IMAP or even NNTP. Cyrus does not provide outbound SMTP services: these are hooked back into the MTA.

Cyrus usually uses **saslauthd** (Cyrus SASL) to provide authentication services. It is not the only way to provide authentication, but it is the usual option.

Cyrus stores the mailspool, indexes and search data on disk. While these are inherently files, their structure and function is database-centric and should be treated as such. *(Do not attempt to manually edit these files. That way lies madness.)* Cyrus itself provides no inherent backup capacity: this must be configured externally using tools best suited for your environment.

For administrative actions on your server - such as creating users, editing mailbox details, etc - use :ref:`cyradm <imap-admin-commands-cyradm>`. This is a command, not a daemon, and it communicates with cyrus imapd via the IMAP protocol, and authenticating as an admin user.

For security between the user and cyrus, usually SSL is applied.

.. todo:
    - undecided on whether to include idled in here. At the moment I've left it out.
    
.. _MTA: https://en.wikipedia.org/wiki/Message_transfer_agent
.. _lmtp: https://en.wikipedia.org/wiki/Local_Mail_Transfer_Protocol
.. _nginx: http://nginx.org/en/

.. _architecture_murder:
Cyrus Murder
============

Cyrus Murder provides the ability to split the IMAP mailbox namespace across multiple back ends. Cyrus murder is not :ref:`replication <architecture_replication>`; it is load and resource sharing for performance.

.. image:: images/image2-murder.jpg
    :height: 416 px
    :width:  496 px
    :alt: Cyrus Murder architecture.
    :align: center
    
Consider a set of front ends (F1..Fn) which contain no user data. They are essentially stateless. Any user can access their mailbox from any front end. They are IMAP proxies.

There is also a set of back ends (B1..Bn) which manage access to user data. Unlike the front ends, the back ends are unique: they each hold a subset of data across all users. These are IMAP servers.

So when a user logs in to a front end (say F1), how does F1 know which back end to fetch the user's data from? This is where **mupdate** comes in: mupdate holds the mapping of users to back ends. Any time the back ends have a change to their user data, they send the change to mupdate which then notifies all the front ends of the latest mapping.

A user's data is not necessarily all stored on a single back end, either: it can be split across disk partitions or back ends.

The mapping on mupdate goes something like this:

===============  ===============
<user>.<folder>  <backend>!<disk partition>
===============  ===============
u1               b2!default
u2               b2!default
u2.Trash         b1!data
u3               b1!bigdisk
===============  ===============

Mupdate is multithreaded. 

Should each datastore be configured to contain the complete set of all data, and any front end can also behave as a back end (and vice versa), this is known as **Unified Murder**: where everything has everything.

.. todo:
    Migrate information from https://cyrusimap.org/mediawiki/index.php/Cyrus_Murder_Design

.. _architecture_replication:    
Replication
===========
Replication is not :ref:`Cyrus Murder<architecture_murder>`. Replication provides high availability and hot backups. It is designed to replicate the mailstore on a standalone Cyrus install, or multiple backend servers in a :ref:`murder <architecture_murder>` configuration. (It is not for replicating front ends or mupdate master servers.)

.. image:: images/image3-replication.jpg
    :height: 385 px 
    :width:  507 px
    :alt: Cyrus replication architecture
    :align: center
    
A master is configured with a number of **channels**: each channel defines the set of replicas the master is replicating to, and the configuration (credentials on the replica host, port and hostname) for how to communicate to that replica.

Each channel (ie: each replica) has its own set of log files on the master, and its own **sync_client** which processes those log files and sends them to the replica's **sync_server**.

When a master generates a change, it calls **sync_log**. This writes the change to all the log files (one per channel). The log files are rotated every few seconds. The $PID on the log file set is that of the particular sync_client who processed the change. 

Replication is idempotent: you can safely run the same log multiple times.

Channels
--------

A channel is a (real thing? virtual construct? To the best of my knowledge, there isn't a channel config file per se). 

A channel is a way of describing the linkage between a master and one of its replicas. It encompasses the configuration on the master to know which sync logs to write to, and the configuration on the master to know the imap credentials on the replica to allow it to send details to the replica. It is the port configuration on the replica to know where to listen for change updates.

There's two standard channel configurations:

1. Single master keeping all replicas up to date.
2. Single master updates the replicas via chaining. (master updates replica 1, which updates replica 2)

The only real benefit to chaining is bandwidth use reduction - if
you have two replicas in a different datacentre, you can chain them and
avoid sending all the data over the link twice.  You can always re-
establish replication to the second replica by creating a direct channel
and running sync_client -A to make sure everything is up-to-date.

Log file
--------
The log file is a list of either users or mailboxes which have been altered.  When sync_log is enabled, all of the daemons which might alter a mailbox or user will write a line to this log each time they do so.  That means the obvious suspects -- imapd, pop3d, timsieved, lmtpd, etc. -- but also cyr_expire and friends.

So when sync_client processes a sync_log, it needs to look at an actual copy of the user/mailbox in order to determine its current state, and needs to look at both copies to work out what to replicate between them.

Sync client supports doing a single user with '-u', a single mailbox with '-m', etc.  All the entries in the sync_log file are triggers to replicate with that same value, so a line ``USER vader@darth.net`` is the same as running ``sync_client -u vader@darth.net``.



