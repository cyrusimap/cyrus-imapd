.. _imap-developer-guidance-namelocks:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.

Cyrus IMAP Server: Namelocks
============================

Intro
-----

Name locks are an addition to the cyrus internals to address a range of
race conditions and complexities. These ills are most easily avoided by
ensuring that only one process can do certain operations at once. Name
locks also mean crashes can't leave the mailbox "broken" forever.

Unfortunately, locks can't be retained over a rewrite-rename cycle, and
every meta file in a regular mailbox gets rewritten upon occasion. Even
cyrus.header gets a rewrite when a new userflag is added.

The "RESERVED FLAG" method of handling mailbox creation is a nasty
brutish method that breaks on process crashes, causing a full
mailboxes.db sweep to be necessary on restart, and making that name
unusable until the entire server is restarted. It's also unusable for
serialisation of operations without making the mailbox "disappear" to
other clients.

Mailbox names are supposed to be exclusive per server, not just per
partition, so any lock has to apply to the entire server.

**MURDER Considerations:** Due to the way the mupdate protocol works,
RESERVED records are still created over mupdate. This sucks, and a
better way would be to support an "EXCLUSIVE CREATE" command, where the
create only succeeds if the record doesn't already exist. Then a task
could create the mailbox on the local server and retain an exclusive
namelock while trying to assert the name on the mupdate server. If this
failed (someone else got in first) then the mailbox could be cleaned up
locally before releasing the exclusive namelock, meaning other users on
the local server would never see it existing.

Implementation
--------------

It's a simple matter of having a file under $configdirectory/lock - in a
directory tree using the same hashing structure as the mailbox tree.
This directory can be symlinked or mounted to a tmpfs since the locks
need not persist across restarts. Due to race conditions while cleaning
up, the easiest approach is to only ever delete lock files during
restart, so the unlock code doesn't try to remove them. Lock files are
zero byte in size, and are locked using the flock or fcntl primitives
used by the rest of cyrus.

API
---

Lock types:

-  LOCK\_SHARED - shared lock on the name. Required whenever you have an
   open mailbox with that name
-  LOCK\_EXCLUSIVE - exclusive lock on the name. Required to create or
   finish deleting a mailbox, and required when repacking the
   cyrus.index and cyrus.cache files.
-  LOCK\_NONBLOCKING - attempt to take an exclusive lock on the name,
   but if it's not available, return immediately with r ==
   IMAP\_MAILBOX\_LOCKED rather than blocking until the lock is
   available.

The ``mboxname`` is always an **internal name**, so convert it first.

Example:
~~~~~~~~

::

    struct mboxlock *lock = NULL;
    int locktype = LOCK_SHARED; /* or LOCK_EXCLUSIVE or LOCK_NONBLOCKING */

    r = mboxname_lock("user.brong", &lock, locktype);
    if (!r) {
        do_stuff();
        mboxname_release(&lock);
    }

If mboxname\_lock fails, lock will remain NULL. It should always be
initialised to NULL before being passed to mailbox\_lock. It will be set
back to NULL by mboxname\_release.

Re-locking considerations
~~~~~~~~~~~~~~~~~~~~~~~~~

It is not possible to hold multiple locks to the same name within the
same process. If you call mboxname\_lock with the same name within a
process, and the **same locktype** then a reference counter is
incremented and the same lock is returned. If you use a **different
locktype** (i.e. one shared, the other exclusive. Non-blocking is
considered exclusive for this test) then IMAP\_MAILBOX\_LOCKED will be
returned to avoid breaking the locking semantics. This is a restriction
of the underlying fcntl/flock subsystem.

On the way out, the reference counter is decremented with each release
and the lock isn't freed until the counter gets back to zero.
