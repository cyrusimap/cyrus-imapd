.. _murder-mail-delivery:

==========================
Cyrus Murder Mail Delivery
==========================

There are several alternate ways to handle mail delivery in a Cyrus murder, which may improve performance depending on your set up and mail volume.

Standard Way
============

In a standard set up (as suggested by the documentation) each time a message arrives at a frontend, lmtpproxyd will contact the master server to determine which backend the mailbox is on.

Pros:

* Most people do it this way
* Easy to set up

Cons:

* Murder master can become overloaded if you have large amount of incoming mail
* Mail delivery hangs if murder master is unavailable.

Query local mailboxes.db
========================

Each frontend will generally have its own copy of the mailboxes.db file and lmtpproxyd can be set to query the localhost for the backend of a specific mailbox.

Pros:

* Resolve mailbox location faster
* An increase in messages does not increase load on murder master
* Mail can be delivered if murder master is unavailable

Cons:

* More complicated setup
* There are currently two ways to setup lmtpproxyd to query the localhost: normal and alternate.

If using the alternate method, then mupdate needs to be reconfigured to keep mail delivery going during a murder master outage. Add ``-m`` to the mupdate arguments in :cyrusman:`cyrus.conf(5)`, restart, and mupdate will no longer contact the murder master. Mail delivery will work. Once the murder master has been fixed, remove ``-m`` so the local mupdate will start receiving updates again. Since this involves restarting Cyrus, we ran lmtpproxyd on its own machines (without imap/pop users)

Contact local mupdate server
============================

Mupdate is running on each frontend to receive updates from the murder master. Lmtpproxyd can be configured to query the local mupdate process instead of the one on the master server.

The steps are briefly outlined below

1. Create a config file for lmtpproxyd. Copy your current imapd.conf file and set ``mupdate_server: localhost``. Edit cyrus.conf and tell lmtpproxyd about the new config file. ``cmd="lmtpproxyd -C /etc/lmtp.conf"``
2. Make sure you can login to mupdate locally. Test with mupdatetest. Example: ``mupdatetest -u frontend -a frontend -m PLAIN localhost``
3. Depending on how restrictive your setup is, you may have to create a config file for mupdate.

