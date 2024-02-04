.. _imap-developer-api-cyrusdb2:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.  Converted via the pandoc tool from HTML.

cyrusdb API
===========

Intro
-----

The ``cyrusdb`` API is a common interface to a key-value store, used
throughout the Cyrus code. It allows a choice of different backends for
different access patterns, while ensuring a consistent interface.

This document will describe the interface, and how to use the cyrusdb
interface from within parts of Cyrus code, as well as how to implement
your own backend

If you pass incorrect values to these APIs, you will get an assertion
failure in most cases. That's generally considered safer than silently
breaking things. Exceptions are noted below.

Code Layout
-----------

The implementation of each interface is in ``lib/cyrusdb_NAME.c``, for
example lib/cyrusdb\_flat.c. General functions are in ``lib/cyrusdb.c``
and the interface in ``lib/cyrusdb.h``.

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

About Transactions
------------------

The cyrusdb interface works in two modes - transactional and
non-transactional. The value of the 'tid' parameter decides which mode
is used. There are three possible values:

-  NULL - non-transactional. Will create a temporary lock for the
   duration of the current action - either a write lock for "store" or a
   read lock for "fetch". If you call "foreach", the lock will be
   dropped between each record fetched
-  Pointer to NULL - transactional, transaction not yet started. Will
   always take a write lock on the database, and update the pointer to
   point to the new transaction.
-  Pointer to a valid transaction. Will keep using this transaction

If you are currently in a transaction, you MUST pass the same
transaction to every database call. It is not possible to mix or nest
transactions. There is one exception in the skiplist backend: *If you
pass NULL to a fetch or foreach while the database is in a transaction,
it will silently do the read in the current transaction rather than
returning an error*

API Reference
-------------

All functions follow the normal C API of returning '0' on success, and
an error code on failure

cyrusdb\_init(void)
~~~~~~~~~~~~~~~~~~~

Is called once per process. Don't call this yourself, use
``cyrus_init()``. No other calls will be made until this is called.

cyrusdb\_done(void)
~~~~~~~~~~~~~~~~~~~

The opposite of ``cyrusdb_init()`` - called once per process to do any
cleaning up after all database usage is finished. Don't call this
yourself, use ``cyrus_done()``.

cyrusdb\_sync(const char \*backend)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Perform a checkpoint of the database environment. Used by berkeley
backend. Is called by ``ctl_cyrusdb -c`` on a regular basis

cyrusdb\_open(const char \*backend, const char \*fname, int flags, struct db \*\*retdb)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Opens the database with the specified 'file name' (or other descriptor,
for example the sql backend is not a filename), and if successful
returns an opaque database structure

Flags:

-  CYRUSDB\_CREATE - create the database if it doesn't exist

Errors:

-  CYRUSDB\_IOERROR - if there is any error reading the file, or any
   corruption detected while loading the file

cyrusdb\_close(struct db \*db)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Close the named database. Will release any locks if they are still held,
but it's bad practice to close without committing or aborting, so the
backend should log an error

Errors:

-  CYRUSDB\_IOERROR - if there are any errors during close

cyrusdb\_fetch(struct db \*db, const char \*key, size\_t keylen, const char \*\*data, size\_t \*datalen, struct txn \*\*tidptr)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

cyrusdb\_fetchlock(struct db \*db, const char \*key, size\_t keylen, const char \*\*data, size\_t \*datalen, struct txn \*\*tidptr)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

cyrusdb\_forone(struct db \*db, const char \*key, size\_t keylen, foreach\_p \*goodp, foreach\_p \*procp, void \*rock, struct txn \*\*tidptr)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

cyrusdb\_store(struct db \*db, const char \*key, size\_t keylen, const char \*data, size\_t datalen, struct txn \*\*tidptr)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Commit the current transaction. tid will not be valid after this call,
regardless of success

If the commit fails, it will attempt to abort the transaction

Errors:

-  CYRUSDB\_IOERROR - any error to write to the database
-  CYRUSDB\_LOCKED - if tidptr is incorrect
-  CYRUSDB\_AGAIN - if a deadlock is created. The current transaction
   has been aborted, but a retry may succeed

cyrusdb\_abort(struct db \*db, struct txn \*tid)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Abort the current transaction. tid will not be valid after this call,
regardless of success

Attempt to roll back all changes made in the current transaction.

Errors:

-  CYRUSDB\_IOERROR - any error to write to the database
-  CYRUSDB\_LOCKED - if tidptr is incorrect

cyrusdb\_dump(struct db \*db, int detail)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional function to dump the internal structure of the database to
stdout for debugging purposes. Don't use.

cyrusdb\_consistent(struct db \*db)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Check if the DB is internally consistent. Looks pretty bogus, and isn't
used anywhere. Don't use.
