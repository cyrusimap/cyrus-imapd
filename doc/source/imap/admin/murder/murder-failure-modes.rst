==========================
Cyrus Murder Failure Modes
==========================

This page is for documenting what happens when a part of the Cyrus Murder fails, how to recover from failures, and commons DOs and DON'Ts of Murder operation.

What happens when the Murder mupdate master is unavailable?
===========================================================

1. Incoming IMAP connections to frontends are still allowed, as are most mailbox operations (see below for exceptions).
2. Mail delivery via the frontends is deferred (lmtpproxyd cannot locate mailbox).
3. Deleting a mailbox (or folder) works, presumably because this operation cannot create future conflicts in the mailbox list. However, the frontends will still think the mailbox (or folder) exists because they only get updates from the mupdate master.
4. Creating a mailbox (or folder) fails with an error message like "can not connect to mupdate server for reservation on 'user.foo.test'".


What happens when the Murder mupdate master is available again?
===============================================================

Frontends will automatically reconnect to the mupdate master after 20 seconds (see **mupdate_retry_delay** in :cyrusman:`imapd.conf(5)`) and synchronize.

Backends will NOT automatically sync any changes to the mupdate master. If any mailbox changes occurred on a backend (a distinct possibility if IMAP clients were still connected), you will need to manually synchronize the mailbox list from the backend to the mupdate master. As the cyrus user, run ``ctl_mboxlist -mw`` on each backend to see the list of changes that would be made. If the list looks correct, then run ``ctl_mboxlist -m`` to actually push those changes to the mupdate master.

What if my mupdate master blows up and I have to recover it?
============================================================

It is either easy, or hard depending on your setup.

Easy recovery
-------------

You can restore the murder master mailbox list from your text backup (created with ``ctl_mboxlist -d``)

Don't have a backup? Well it is still easy if you have a frontend. The mailboxes.db on your frontend and your murdermaster are in the same format.

1. Stop Cyrus on a frontend
2. Stop Cyrus on your murder master
3. Copy mailboxes.db from frontend to murder master
4. Start everything backup
5. Use ctl_mboxlist -m on each backend to update the murder master with any missing changes.

If you are using skiplist for your mailboxes.db then you can just copy the file. If you are using a berkeley format then things are trickier since there is environmental state. It should be possible to run db_recover on both databases, then delete the db folder the mailboxes.db from the murder master and copy those from the frontend (this has not been tested)

Hard recovery
-------------

It's not currently possible to recover the master's mailboxes.db with a dump from ``ctl_mboxlist -d``. The mailboxes.db recovered on the master with ``ctl_mboxlist -u`` won't have the "remote" flag set. 

1. Stop Cyrus on your frontends.
2. Delete the mailboxes.db on the frontends and the mupdate master.
3. Use ``ctl_mboxlist -m`` on each backend to populate the mailboxes.db on the mupdate master.
4. Start Cyrus on the frontends.

