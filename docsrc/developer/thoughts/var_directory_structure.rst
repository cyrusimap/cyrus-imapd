.. _imap-developer-guidance-var_directory_structure:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Cyrus IMAP Server: var directory structure
==========================================

Directory structure under /var/spool/imap
-----------------------------------------

::

    stage./
      Normal staging directory

    sync./
      Staging directory for replication system
      Includes
        sync./locks/*

      which are lock files for each user on the system to prevent two
      replication runs from trying to update the same account at the same time
      (nothing disastrous should happen even without this lock, but the second
      job in will get a bit confused if the target end changes under its feet,
      and will probably drop back to a recovery mode.

    user/
      Familiar user.userid space.

Directory structure under /var/imap
-----------------------------------

Complete list::

      drwxr-xr-x    2 cyrus    cyrus         232 Sep  7 08:21 db
      drwxr-x---    2 cyrus    cyrus         112 Sep  7 19:51 db.backup1
      drwxr-x---    2 cyrus    cyrus         112 Sep  7 19:21 db.backup2
      -rw-r-----    1 cyrus    cyrus    20799488 Sep  7 19:51 deliver.db
      drwxr-xr-x    2 cyrus    cyrus          48 Sep  7 10:16 log
      -rw-r-----    1 cyrus    cyrus     1995000 Sep  7 19:38 mailboxes.db
      -rw-r--r--    1 cyrus    cyrus          10 Jun  2 10:08 master_machine
      -rw-r--r--    1 cyrus    cyrus          71 Sep  7 08:21 master_uuid
      drwxr-xr-x    2 cyrus    cyrus          48 Jun  2 10:08 msg
      drwxr-xr-x    2 cyrus    cyrus        1872 Sep  7 19:55 proc
      drwxr-xr-x   28 cyrus    cyrus         672 Jun  2 10:08 quota
      drwxr-xr-x    2 cyrus    cyrus         224 Sep  7 08:21 socket
      drwxr-xr-x    2 cyrus    cyrus          72 Sep  7 10:19 sync
      drwxr-xr-x   28 cyrus    cyrus         672 Jun  2 10:08 user

Most of that will be familiar. New entries are::

    master_machine
      Defines machine number in replication cluster. Used as sanity check
      against master_uuid file. Sample content:

        machine=1

    master_uuid
      Full information about UUID schema in use. See ./uuid for details.
      Sample content:

         schema=1
         machine=1
         timestamp_generation=0
         master_start_time=1062919294

    sync/current
      Transaction log from IMAP, POP and LMTP daemons, typically feed into
      sync_client running as asynchronous replication engine.

      Rotated to be sync/current-<pid> by asynchronous runner.
