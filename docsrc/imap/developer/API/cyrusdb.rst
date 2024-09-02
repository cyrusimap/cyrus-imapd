.. _imap-developer-api-cyrusdb:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.  Converted via the pandoc tool from Markdown.

CyrusDB API
===========

The interface
-------------

    The bulk, especially the beginning, of this document is from an
    `email <https://lists.andrew.cmu.edu/pipermail/cyrus-devel/2018-February/004217.html>`__
    Bron sent to the
    `cyrus-devel <https://lists.andrew.cmu.edu/pipermail/cyrus-devel/>`__
    mailing list on 27 February 2018 05:50:39GMT.

The cyrusdb interface is a common API for accessing key-value
datastores from within cyrus code. It's part of the libcyrus shared
object (but not libcyrus_min), used by all cyrus binaries. The use of
the cyrusdb API abstracts the details of the underlying data store,
allowing sites to use different database types depending on their
needs, and allowing Cyrus developers to use a common API for data
storage needs.

The entire cyrusdb source lives in the lib/ directory of the cyrus-imapd repository, in the following files:

::

    lib/cyrusdb.h
    lib/cyrusdb.c
    lib/cyrusdb_flat.c
    lib/cyrusdb_quotalegacy.c
    lib/cyrusdb_skiplist.c
    lib/cyrusdb_sql.c
    lib/cyrusdb_twoskip.c

cyrusdb.h
+++++++++

*   interface definitions (all access to cyrusdb databases happens
    through the functions defined here)
*   the ``struct cyrusdb_backend`` data structure which defines the
    interface implemented by each backend.
*   constants for flags to the cyrusdb_open call, and return codes.
    Cyrusdb functions all return their own CYRUSDB_* error codes, which
    are not compatible with the r = IMAP_* return codes used throughout
    much of the rest of the codebase.

cyrusdb.c
+++++++++

*   implementations of the wrapper functions around the backends,
    including default implementations of some functions which are
    common to many backends but overridden by some.
*   a wrapper to initialise and cleanup the state of each backend
    (if needed) during Cyrus set up / tear down.

cyrusdb_*.c
+++++++++++

*   the actual implementations of each backend! We'll look at some
    in a sec.

Configuration
-------------

The name of the backend for each of the main internal databases can be
configured in imapd.conf, for example: ``annotation_db: skiplist``. This
is then read in imap/global.h and imap/global.c during startup, so that
the global variable ``config_annotation_db`` gets set to the configured
backend name:

::

        config_annotation_db = config_getstring(IMAPOPT_ANNOTATION_DB);

(Beware the misleading naming here: ``config_annotation_db`` is a string
describing the *backend* used by the database, not, say, its location on
disk.)

Internally, the main module for each database sets up struct of pointers
to the cyrusdb functions it implements, which is registered in
``lib/cyrusdb.c``

``lib/cyrusdb.c`` provides backend-agnostic wrapper functions for
interacting with cyrusdb databases.

A full example
--------------

::

      struct db *db = NULL;
      struct txn *tid = NULL;
      const char *filename = NULL;
      int flags = CYRUSDB_CREATE;

      cyrus_init(alt_config, "toolname", 0);

      filename = config_getstring(IMAPOPT_ANNOTATION_DB_PATH);

      r = cyrusdb_open(config_annotation_db, filename, flags, &db);

      r = cyrusdb_fetch(db, key, keylen, &data, &datalen, &tid);

      r = cyrusdb_commit(db, tid);

      r = cyrusdb_close(db);

      cyrus_done();

Note that you always open a database first, and close it at the end. You
must always call cyrus\_init() and cyrus\_done() to properly initialize
and clean up the ``cyrusdb`` environments.

This example also uses a transaction, meaning that the database is
locked in exclusive mode between the 'fetch' (the first use of the
transaction) and the commit.

Tools
-----

There are also some tools to work with and support cyrus databases:

imap/ctl_cyrusdb
++++++++++++++++

:cyrusman:`ctl_cyrusdb(8)`

*   performs maintenance on the cyrusdb subsystem. This is called in two places:

    *   START: "ctl_cyrusdb -r" (recovery).
        This is the ONLY PLACE that code is guaranteed to be run at
        startup on every cyrus installation, so you'll find quite a lot
        of detritus has built up in this codepath over the years.
    *   EVENTS: "ctl_cyrusdb -c" (checkpoint).
        This is run regularly (period=180 at Fastmail, examples in the
        codebase have period=5 or period=30). Both this codepath and
        cyr_expire tend to run periodically on cyrus systems, and
        cleanup code is spread between those two locations.

imap/cvt_cyrusdb
++++++++++++++++

:cyrusman:`cvt_cyrusdb(8)`

*   used for converting a database between versions.
    This is often used to prepare for upgrade, particularly in the past
    when Cyrus supported berkeley DB which didn't upgrade cleanly
    across OS versions, it was common to use cvt_cyrusdb to turn
    databases into a very portable format (flat or skiplist) before
    upgrading, upgrade the OS, convert back to the fast format
    (berkeley) and then restart.

imap/cyr_dbtool
+++++++++++++++

:cyrusman:`cyr_dbtool(8)`

*   once known as brontool, this is the first piece of Cyrus code
    I ever wrote! It's a fairly dumb wrapper around the CyrusDB
    interface, and able to be used to read, write, or iterate any parts
    of a database. Its interactive mode is not special-character clean,
    but it can also be used in batch mode, which uses IMAP atom-string
    literal8 for input/output, and hence can roundtrip data reliably.

There are also tools like: :cyrusman:`ctl_conversationsdb(8)`,
:cyrusman:`dav_reconstruct(1)` and :cyrusman:`ctl_mboxlist(8)` which
can be used to manage individual databases through a more specific
interface which understands the context as well as just the raw
key/value.

How to use CyrusDB
------------------

Assuming that ``cyrus_init()`` has been called, which calls
``cyrusdb_init()``, you can assume that databases will work in any
Cyrus code.

The first step is to open a database. Databases have a filename - this
might be a literal filename on the backend, a directly containing data,
or an opaque token used by the backend to locate a datasource.

::

    int flags = 0;
    struct db *mydb = NULL;
    int r = cyrusdb_open("skiplist", "/tmp/database.db", flags, &mydb);
    if (!r) return mydb;  // if (r == CYRUSDB_OK) { ... }
    /* XXX: error handling */

Accepted flags:

CYRUSDB_CREATE - if the named database doesn't exist, create a blank
database.

CYRUSDB_MBOXSORT - use the abomination called improved_mboxlist_sort
which re-orders a couple of characters to allow "foo.bar" to sort
before "foo bar", for perfectly good reasons, but we're going to fix it
a better way. Not every engine supports arbitrary collation, and if
many engines corrupt horribly if the same database is opened with
different choices for this flag. Ouch.

CYRUSDB_CONVERT - if set and the database fails to open, attempt a
magic detection on the file content and try to convert the database to
the requested backend type before opening it. In-place upgrades! If
this is NOT set, then instead the magic detection will still be
performed, but the open database will be returned using the correct
engine for that database rather than converted. Magic detection only
currently works for single-file database formats.

CYRUSDB_NOCOMPACT - if the database format supports automatic
compacting, don't use it. Handy for when you want to read without
causing any possible issues (e.g. read-only filesystem during recovery)
or when performance is critical and you don't want to risk waiting
while a recompact happens.

All the remaining functions take that "struct db" pointer.

There's also a ``cyrusdb_lockopen()`` interface which takes a
transaction pointer and returns with the transaction already active.
This isn't actually being used yet, but is intended to allow slightly
more efficient single-operation database use. Right now, open returns
an unlocked database, but may need to lock as part of the setup, so
keeping that lock would avoid one extra unlock/lock cycle.

Reading, Writing, & Transactions
--------------------------------

CyrusDB supports both transactional and non-transactional access.
Transactions are always exclusive. This is arguably a deficiency in the
interface, particularly since many engines implement a non-exclusive
(read) lock internally anyway.

Reading
+++++++

There are now 4 interfaces to read data. Two of which are original
cyrusdb and two of which are more recently added.

original:

    ``cyrusdb_fetch()``
        fetch a single value by exact key.
    ``cyrusdb_foreach()``
        given a prefix, iterate over all the keys with that prefix
        (including exactly that key) in order.

newer:

    ``cyrusdb_fetchnext()``
        given an exact key, fetch the following key and value
        (regardless of whether the key exists), e.g given keys "f" and
        "g", fetchnext "foo" would return "g", as would fetchnext "f".
        This can be used to implement foreach (indeed, the skips do
        exactly that).

    ``cyrusdb_forone()``
        given an exact key, act like ``cyrusdb_foreach`` but only for
        that one key.

        This is a convenience wrapper around fetch to
        allow doing things like::

            r = cyrusdb_forone(mydb, "folder", 6, p, cb, rock, &tid);
            if (!r) r = cyrusdb_foreach(mydb, "folder.", 7, p, cb, rock, &tid);

        Which does precisely "folder" and its children without visiting
        any other keys that have "folder" as a prefix.

Since the cyrusdb interface always takes both a pointer and a length,
it's also possible to use::

    char *key = "folder.";
    r = cyrusdb_forone(mydb, key, 6, p, cb, rock, &tid);
    if (!r) r = cyrusdb_foreach(mydb, key, 7, p, cb, rock, &tid);

OK, foreach. Foreach is very tricky, because it takes TWO callbacks.
The callbacks have an identical signature, but different return codes!

::

    typedef int foreach_p(void *rock,
    const char *key, size_t keylen,
    const char *data, size_t datalen);

    typedef int foreach_cb(void *rock,
    const char *key, size_t keylen,
    const char *data, size_t datalen);

The difference is this: ``foreach_p`` is called with the database
locked, always - even if called without a transaction. ``foreach_p``
returns 1 or 0. 0 means "skip this record", 1 means "process this
record". This is useful to pre-filter records when called without a
transaction, because otherwise you lock and unlock all the time.

NULL for ``foreach_p`` is treated like a test which always returns '1',
so you can pass NULL if you don't need filtering.

If ``foreach_p`` returns 1, then with an unlocked transaction, the
database is now unlocked BEFORE calling ``foreach_cb``, the callback.
``foreach_cb`` returns a CYRUSDB\_ response. If zero, the foreach will
continue. If non-zero, the foreach will abort and return the non-zero
response. This is both useful for error cases, and useful for
short-circuiting, if you only care that a key exists, you can do
something like::

    static int exists_cb(void rock attribute((unused)), [...])
    {
        return CYRUSDB_DONE; /* one is enough */
    }

and then use ``exists_cb`` as your ``foreach_cb`` and check if the
return code is CYRUSDB_DONE to know if the foreach found a key.

If foreach is called with a transaction pointer, then it is your
responsibility as the caller to also pass that pointer (and a pointer
to the database) in that rock, so that callees can make further
operations within the same transaction. A foreach with a transaction
does NOT unlock before calling its callback.

About Transactions
++++++++++++++++++

You may have noticed that 'tid' at the end. Every function for acting
on the database takes as its last argument a ``struct txn **``.

The cyrusdb interface works in two modes - transactional and
non-transactional. The value of the 'tid' parameter decides which mode
is used. There are three possible values:

*   NULL - non-transactional request.
    Do whatever you need for internal locking, but starts with an
    unlocked database and ends with an unlocked database.

    .. Note::

        At least skiplist and twoskip implement a hack where if the
        database IS locked for a non-transactional read request, they
        will act as if you'd passed the current transaction in for the
        NULL case. This is a hack around layering violations and kind
        of sucks.

*   &NULL - e.g::

        struct txn *tid = NULL;
        const char *data = NULL;
        size_t datalen = 0;
        int r = cyrusdb_fetch(mydb, key, keylen, &data, &datalen, &tid);

    After calling this, tid will have an opaque value allocated by the
    database backend, which must be passed to all further cyrusdb
    operations on that database until either ``cyrusdb_commit()`` or
    ``cyrusdb_abort()`` are called.

*   &tid - e.g::

        if (r == CYRUSDB_NOTFOUND) {
            r = cyrusdb_store(mydb, key, keylen, "DEFAULT", 7, &tid); // set a default value
        }

    Given an existing transaction, perform this call in the context of the transaction.

If you are currently in a transaction, you MUST pass the same
transaction to every database call. It is not possible to mix or nest
transactions.

There is one exception in the skiplist backend:

    If you pass NULL to a fetch or foreach while the database is in a
    transaction, it will silently do the read in the current
    transaction rather than returning an error.

Writing
+++++++

There are three write operations:

::

    cyrusdb_create
    cyrusdb_store
    cyrusdb_delete

``cyrusdb_store`` will either create or overwrite an existing key.
``cyrusdb_create`` will abort if the key already exists.
``cyrusdb_delete`` takes a flag 'force' which just makes it return
CYRUSDB_OK (0) rather than CYRUSDB_NOTFOUND if the key doesn't exist.
Strangely, 'force' is after &tid, making it the only cyrusdb API that
does that, but hey - keeps you on your toes.

&tid behaves exactly the same for the write APIs. If not passed, then
the database engine will behave as it if creates a writable
transaction, does the operation, then commits all within the
``cyrusdb_*`` call.

Gotchas!
--------

*   ``\0`` is permitted in both keys and values, though 'flat' and
    'quotalegacy' have 8-bit cleanliness issues.

*   zero-length keys are not supported

*   zero-length values are theoretically supported, but a little
    interesting. Certainly, pass "" rather than NULL as the value when
    writing or things will get weird. I'm pretty sure at least the
    \*skip databases assert on these kinds of weirdness.

*   unlocked foreach: this is the land of the gotcha! They key and data
    pointers (const char \*) passed to your ``foreach_cb`` are only
    valid UNTIL YOU TOUCH THE DATABASE. A common cause of rare and hard
    to diagnose bugs is writing something to the same database in the
    same process (OR EVEN READING FROM IT AGAIN). I cannot emphasise
    this enough. If you want to zero-copy access that data, you need to
    access it first, before touching that DB again. Otherwise the map
    in which the data was a pointer may have been replaced as the next
    read found a new file and mapped it in!

    also: if you're implementing a backend. Unlocked foreach must find
    future records created by the current callback. Consider a database
    containing 4 keys::

        A B C D

    If you are at key B and insert a key BB, then it must be iterated over.
    If you insert AA while at B, it must NOT be iterated over.

*   Opening the same database multiple times.
    In the bad old days, opening the same database multiple times in
    the same process led to locking bugs (fcntl is braindead). Each
    database engine is responsible for making sure this doesn't happen.
    Most engines keep a linked lists of open databases. If you try to
    open the same database again, they will just return the existing
    opened copy and bump a refcount. Beware. If a database is locked
    and you try to lock again - thinking you were opening it brand new,
    it will assertion fail and/or error.

I think that covers about everything! Cyrusdb is used just about
everywhere that sorted key-value databases give what's needed,
including mailboxes.db, annotations.db (global and per mailbox
databases), seen state (non-owner), subscriptions, cyrus.indexed.db for
Xapian, and the rather massive (and increasingly inaccurately named)
user.conversations.

Future plans are to increase the usage of cyrusdb databases, possibly
by building an indexing layer on top and using that instead of the
sqldb interface used for sqlite databases by DAV code, and possibly
also moving other custom file formats into a cyrusdb to allow easier
stateless server builds on a distributed backend.


API Reference
-------------

All functions follow the normal C API of returning '0' on success, and
an error code on failure

cyrusdb\_init(void)
+++++++++++++++++++

Is called once per process. Don't call this yourself, use
``cyrus_init()``. No other calls will be made until this is called.

cyrusdb\_done(void)
+++++++++++++++++++

The opposite of ``cyrusdb_init()`` - called once per process to do any
cleaning up after all database usage is finished. Don't call this
yourself, use ``cyrus_done()``.

cyrusdb\_sync(const char \*backend)
+++++++++++++++++++++++++++++++++++

Perform a checkpoint of the database environment. Used by berkeley
backend. Is called by ``ctl_cyrusdb -c`` on a regular basis

cyrusdb\_open(const char \*backend, const char \*fname, int flags, struct db \*\*retdb)
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Opens the database with the specified 'file name' (or other descriptor,
for example the sql backend is not a filename), and if successful
returns an opaque database structure

Flags:

-  CYRUSDB\_CREATE - create the database if it doesn't exist
-  CYRUSDB\_MBOXSORT - sort '.' first, so folder listing is correct

Errors:

-  CYRUSDB\_IOERROR - if there is any error reading the file, or any
   corruption detected while loading the file

cyrusdb\_close(struct db \*db)
++++++++++++++++++++++++++++++

Close the named database. Will release any locks if they are still held,
but it's bad practice to close without committing or aborting, so the
backend should log an error

Errors:

-  CYRUSDB\_IOERROR - if there are any errors during close

cyrusdb\_fetch(struct db \*db, const char \*key, size\_t keylen, const char \*\*data, size\_t \*datalen, struct txn \*\*tidptr)
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

cyrusdb\_fetchlock(struct db \*db, const char \*key, size\_t keylen, const char \*\*data, size\_t \*datalen, struct txn \*\*tidptr)
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Fetch the value for the exact key given by key and keylen. If data is
not NULL, set datalen and return a valid pointer to the start of the
value.

Fetchlock is identical to fetch, but gives a hint to the database that
the record is likely to be modified soon.

NOTE: it is possible to store a key with a zero length data record, in
which case \*datalen will be set to zero, and \*data will be set to a
non-NULL value

It is an error to call fetch with a NULL key or a zero keylen

It is an error to call fetch with a NULL datalen and a non-NULL data,
however it is acceptable to call with a NULL data and a non-NULL datalen
if you are only interested in the length

Errors:

-  CYRUSDB\_IOERROR - if any error occurs reading from the database
-  CYRUSDB\_LOCKED - if tidptr is incorrect
-  CYRUSDB\_NOTFOUND - if there is no record that matches the key

cyrusdb\_foreach(struct db \*db, const char \*prefix, size\_t prefixlen, foreach\_p \*goodp, foreach\_p \*procp, void \*rock, struct txn \*\*tidptr)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

cyrusdb\_forone(struct db \*db, const char \*key, size\_t keylen, foreach\_p \*goodp, foreach\_p \*procp, void \*rock, struct txn \*\*tidptr)
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

``cyrusdb_foreach()`` iterates over all records matching the given
prefix, in database order (which may be MBOXLIST sort, depending on the
parameters given to open

It is legal to give a NULL pointer as prefix if prefixlen is zero, in
which case it will return all records in the database. It is an error to
give a non-zero prefixlen with a NULL prefix.

``cyrusdb_forone()`` "iterates" over the single record matched by the
given key. If you've already built callbacks for processing each record
from a foreach, this lets you use the same interface to process a single
record.

``goodp`` - this function is only used for deciding if the record needs
to be further processed. It can be used for basic filtering, and returns
true (non-zero) to process, or zero to skip and move straight to the
next record. Because goodp can't make any database changes, it doesn't
break the lock, so it's faster to use goodp to filter records if you
don't need to process all of them. NULL is a legal value for goodp, and
means that all records will be processed.

``procp`` - procp is the main callback function. If you use foreach in
non-transactional mode, the database is unlocked before calling procp,
and locked again afterwards. You are allowed to add, delete or modify
values in the same database from within procp. If procp returns
non-zero, the foreach loop breaks at this point, and the return value of
the foreach becomes the return value of procp. If procp returns zero,
the foreach loop will continue at the NEXT record by sort order,
regardless of whether the current record has changed or been removed.
procp MUST NOT be NULL.

Errors:

-  procp\_result - whatever your callback returns
-  CYRUSDB\_IOERROR - if any error occurs while reading
-  CYRUSDB\_LOCKED - if tidptr is incorrect

cyrusdb\_create(struct db \*db, const char \*key, size\_t keylen, const char \*data, size\_t datalen, struct txn \*\*tidptr)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

cyrusdb\_store(struct db \*db, const char \*key, size\_t keylen, const char \*data, size\_t datalen, struct txn \*\*tidptr)
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Create a new record or replace an existing one. The only difference
between these two is that ``cyrusdb_create`` will return an error if the
record already exists, while ``cyrusdb_store`` will replace it

If tidptr is NULL, create/store will take a write lock for the duration
of the action.

Any failure during create/store will abort the current transaction as
well as returning an error

It is legal to pass NULL for the data field ONLY if datalen is zero. It
is not legal to pass NULL for key or zero for keylen

Errors:

-  CYRUSDB\_IOERROR - any error to write to the database
-  CYRUSDB\_LOCKED - if tidptr is incorrect
-  CYRUSDB\_EXISTS - if ``cyrusdb_create`` is called on an existing key
-  CYRUSDB\_AGAIN - if a deadlock is created. The current transaction
   has been aborted, but a retry may succeed

cyrusdb\_delete(struct db \*db, const char \*key, size\_t keylen, struct txn \*\*tidptr, int force)
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Delete the given record from the database. If force is true, then
succeed even if the record doesn't currently exist.

It is not legal to pass NULL for key or zero for keylen

Errors:

-  CYRUSDB\_IOERROR - any error to write to the database
-  CYRUSDB\_LOCKED - if tidptr is incorrect
-  CYRUSDB\_NOTFOUND - if force is not set and the key doesn't exist
-  CYRUSDB\_AGAIN - if a deadlock is created. The current transaction
   has been aborted, but a retry may succeed

cyrusdb\_commit(struct db \*db, struct txn \*tid)
+++++++++++++++++++++++++++++++++++++++++++++++++

Commit the current transaction. tid will not be valid after this call,
regardless of success

If the commit fails, it will attempt to abort the transaction

Errors:

-  CYRUSDB\_IOERROR - any error to write to the database
-  CYRUSDB\_LOCKED - if tidptr is incorrect
-  CYRUSDB\_AGAIN - if a deadlock is created. The current transaction
   has been aborted, but a retry may succeed

cyrusdb\_abort(struct db \*db, struct txn \*tid)
++++++++++++++++++++++++++++++++++++++++++++++++

Abort the current transaction. tid will not be valid after this call,
regardless of success

Attempt to roll back all changes made in the current transaction.

Errors:

-  CYRUSDB\_IOERROR - any error to write to the database
-  CYRUSDB\_LOCKED - if tidptr is incorrect

cyrusdb\_dump(struct db \*db, int detail)
+++++++++++++++++++++++++++++++++++++++++

Optional function to dump the internal structure of the database to
stdout for debugging purposes. Don't use.

cyrusdb\_consistent(struct db \*db)
+++++++++++++++++++++++++++++++++++

Check if the DB is internally consistent. Looks pretty bogus, and isn't
used anywhere. Don't use.
