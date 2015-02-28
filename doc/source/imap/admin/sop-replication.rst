Setting up Replication
======================

Configuring Server
------------------

The *server* is the replica or slave.


Configuring Client
------------------

The *client* is the master server and pushes the mailbox content to the replica server.

Initially synchronizing mailboxes
---------------------------------

::

    [root@cyrus-master ~]# /usr/lib/cyrus-imapd/sync_client -S cyrus-replica.example.org -v -u john.doe@example.org
    USER john^doe@example.org

.. todo:: unix hierarchy separator matters? What does the above command actually do?

