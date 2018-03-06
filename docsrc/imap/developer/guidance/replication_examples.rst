.. _imap-developer-guidance-replication-examples:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Cyrus IMAP Server: Replication Examples
=======================================

Introduction
------------

The replication system creates a link between two Cyrus mailstores: a
master and a replica system. Both systems can be live mailstores with
active users: here in Cambridge we install systems in pairs.

Typically half of the users will be using each system, and each system
replicates to its partner. In the event of a failover everyone uses the
remaining system in a pair. This is typically safe as the IMAP/POP/SMTP
servers define which of the two systems is the live server for any given
account, and the replica just plays a game of follow my leader.

Occasionally I think about introducing some form of sanity check so that
we have to explicitly issue a command to the remaining backend system as
well as the proxies in the event of a failover.

A short example of replication in action
----------------------------------------

::

    Index:

      #: Annotation
      C: Command issued by client
      S: Command issued by server

    # Authentication between systems is done using SSH key based authentication:

    C: $ ssh -x cyrus-2 /usr/local/cyrus/bin/sync_server
    S: * Sync Server v0.0 [EXPERIMENTAL]

    # Create new auth_state and ask for all information about given list of
    # folders (namely user.dpc22). Returns:
    #
    #   "**" unsolicited response for each mailbox. Returns:
    #      Folder UniqueID, Name, ACL, UIDlast, timestamp for last seen update.
    #
    #   "*" response for each mail message in folder:
    #      UID, GUID, flags (other than \Seen state)

    C: user_some dpc22 user.dpc22
    S: ** 6b98205c796c6c61 user.dpc22 \
    S:     "dpc22   lrswipcda       anonymous       0      " 4151 1062945305
    S: * 1 000000000000000000000000 ()
    S: * 3697 0101003f4c56b00545000000 ()
    S: * 3919 0101003f4c56b04b2900000d ()
    S: * 3937 0101003f4c56b0514900001f ()
    S: * 4066 0101003f4c56b07422000002 ()
    S: * 4089 0101003f4c56b07e56000023 (\answered)
    S: * 4118 0101003f4c56b08328000016 ()
    S: * 4131 0101003f4c56b084d7000002 ()
    S: * 4136 0101003f4c56b087f3000001 ()
    S: * 4140 0101003f4c56b08c9d000026 ()
    S: OK User_Some finished

    # Select a folder to work with

    C: select user.dpc22
    S: OK 6b98205c796c6c61 4151 1062945305

    # Remove message with UID "1" from folder list (message which has been
    # sitting in my inbox since January, has no GUID defined)

    C: expunge 1
    S: OK Expunge Complete

    # Set some user flags on message UID "4140"

    C: setflags 4140 (hello world)
    S: OK Updated flags on 1 messages okay

    # Demonstrate that something has changed:

    C: status
    S: * 3697 0101003f4c56b00545000000 ()
    S: * 3919 0101003f4c56b04b2900000d ()
    S: * 3937 0101003f4c56b0514900001f ()
    S: * 4066 0101003f4c56b07422000002 ()
    S: * 4089 0101003f4c56b07e56000023 (\answered)
    S: * 4118 0101003f4c56b08328000016 ()
    S: * 4131 0101003f4c56b084d7000002 ()
    S: * 4136 0101003f4c56b087f3000001 ()
    S: * 4140 0101003f4c56b08c9d000026 (hello world)
    S: OK 4151

    # Now lets correct the damage that we just inflicted:

    C: $ replicate -s cyrus-2 -v -v -m user.dpc22
    S: MAILBOXES user.dpc22
    S: USER_SOME dpc22 user.dpc22
    S: SELECT user.dpc22
    S: SETFLAGS [1 msgs]
    S: UPLOAD [1 msgs]
    S: SETSEEN dpc22 ...
    S: ENDUSER

    C: $ ssh -x cyrus-2 /usr/local/cyrus/bin/sync_server
    S: * Sync Server v0.0 [EXPERIMENTAL]
    S: user_some dpc22 user.dpc22
    S: ** 6b98205c796c6c61 user.dpc22 \
    S:    "dpc22   lrswipcda       anonymous       0      " 4156 1062968731
    S: * 1 000000000000000000000000 ()
    S: * 3697 0101003f4c56b00545000000 ()
    S: * 3919 0101003f4c56b04b2900000d ()
    S: * 3937 0101003f4c56b0514900001f ()
    S: * 4066 0101003f4c56b07422000002 ()
    S: * 4089 0101003f4c56b07e56000023 (\answered)
    S: * 4118 0101003f4c56b08328000016 ()
    S: * 4131 0101003f4c56b084d7000002 ()
    S: * 4136 0101003f4c56b087f3000001 ()
    S: * 4140 0101003f4c56b08c9d000026 ()
    S: OK User_Some finished

    # Back where we started: the replication engine reinserted message UID 0
    # which was missing, and removed "hello world" from message UID 4140

Tracking messages between folders
---------------------------------

::

    # I've just saved a message from my inbox into a folder named "zzz",
    # creating the folder the process.

    C: $ replicate -s cyrus-2 -v -v -m user.dpc22 user.dpc22.zzz

    Replication action on two MAILBOX objects:

    S: MAILBOXES user.dpc22 user.dpc22.zzz

    Ask server for contents of the two folders:

    S:   USER_SOME dpc22 ...

    Reserve message with given GUID in user.dpc22 so that it can be moved

    S:   RESERVE user.dpc22 ...

    Remove message from source folder (reserved copy left behind)

    S:   SELECT user.dpc22
    S:   EXPUNGE [1 msgs]
    S:   SETSEEN dpc22 ...

    Create target folder and copy in message that we reserved (doesn't have to
    be uploaded again)

    S:   CREATE user.dpc22.zzz 7f6f384c3f5ba99a
    S:      "dpc22        lrswipcda       anonymous       0       " 0 1062971802
    S: SELECT user.dpc22.zzz
    S: UPLOAD [1 msgs]
    S: SETSEEN dpc22 ...
    S: ENDUSER
