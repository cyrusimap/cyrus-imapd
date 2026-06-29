.. _imap-developer-guidance-locking:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Cyrus IMAP Server: Locking
==========================

Mailboxes
---------

For mailboxes, we lock in this order:

*   Mailbox Namelock (shared) <== possibly reversible with
    conversationsdb
*   user conversations db
*   cyrus.index

If you want to do any mailboxes.db transactions, they need to open
and close without changing any mailbox locking during the transaction.

Likewise seen and statuscache are always done without changing mailbox
locking during their transaction.

Annotations databases are a mess.

Xapian
------

*   Xapian per-user NAMELOCK (shared or exclusive)
*   xapianactive file lock (shared or exclusive)

Shared namelock holds the following invariants:

*   xapianactive file contents are not changed
*   directories mentioned in xapianactive are not cleaned up

Xapianactive exclusive lock holds the following invariants:

*   owner may write to first database mentioned in xapianactive

Xapianactive shared lock holds:

*   all databases in xapianactive are readable and a consistent
    read can be made across all of them, even with multiple requests
    while the lock is held.


Locking orders
++++++++++++++

SHARED case:

*   user conversations db <=== possibly reversible with SHARED xapian
    namelock
*   SHARED xapian namelock
*   xapianactive lock (shared to search, exclusive to write)
*   cyrus.index may be locked either side of the xapianactive lock,
    because the conversationsdb lock protects it from races.

EXCLUSIVE case:

*   EXCLUSIVE xapian namelock
    That's it.  While you've got this, you can add or delete items from
    the xapianactive file, and delete paths on disk for directories
    that you have removed (either during or after locking).  No other
    locks are permitted.


If you hold a SHARED xapian namelock, you may write to a .NEW folder
for a xapianactive entry that you created without taking any additional
locks, because nothing can clean it under you, and nothing else can
read it.  This is how the repack case works.

Lock lifetime
-------------

*   Shared mailbox namelock:
    *   possibly hours
*   conversations db and below
    *   short as possible

Mailbox namelock holds the following invariants:

*   cyrus.index may not be repacked, however flags and modseqs may be
    updated
*   cyrus.annotations records may change (kind of buggy and bad,
    ideally we'd always write new ones if we changed them and keep the
    old ones)
*   cyrus.cache may be appended, but never changed
*   spool files may not be deleted (already can't be changed)
