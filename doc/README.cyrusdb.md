# The CyrusDB Interface

> This document is from an [email](https://lists.andrew.cmu.edu/pipermail/cyrus-devel/2018-February/004217.html) Bron sent to the [cyrus-devel](https://lists.andrew.cmu.edu/pipermail/cyrus-devel/) mailing list.


The cyrusdb interface is a common API for accessing key-value
datastores from within Cyrus code.  It's part of the libcyrus shared
object (but not libcyrus_min), used by all Cyrus binaries.  The use of
the cyrusdb API abstracts the details of the underlying data store,
allowing sites to use different database types depending on their
needs, and allowing Cyrus developers to use a common API for data
storage needs.

The entire cyrusdb source lives in the `lib/` directory of the
`cyrus-imapd` repository, in the following files:

- [`lib/cyrusdb.h`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.h)
- [`lib/cyrusdb.c`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c)
- [`lib/cyrusdb_flat.c`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb_flat.c)
- [`lib/cyrusdb_quotalegacy.c`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb_quotalegacy.c)
- [`lib/cyrusdb_skiplist.c`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb_skiplist.c)
- [`lib/cyrusdb_sql.c`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb_sql.c)
- [`lib/cyrusdb_twoskip.c`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb_twoskip.c)

### `cyrusdb.h`

* interface definitions (all access to cyrusdb databases happens through the functions defined here)
* the [`struct cyrusdb_backend`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.h#L94) data structure which defines the interface implemented by each backend.
* constants for flags to the [`cyrusdb_open`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.h#L251) call, and return codes.  Cyrusdb functions all return their own `CYRUSDB_*` error codes, which are not compatible with the `r = IMAP_*` return codes used throughout much of the rest of the codebase.

### `cyrusdb.c`

* implementations of the wrapper functions around the backends, including default implementations of some functions which are common to many backends but overridden by some.
* a wrapper to initialise and cleanup the state of each backend (if needed) during Cyrus set up / tear down.

### `cyrusdb_*.c`

* the actual implementations of each backend!  We'll look at some in a sec.

## Tools
There are also some tools to work with and support Cyrus databases:

### `imap/ctl_cyrusdb`

Performs maintenance on the cyrusdb subsystem.  This is called in two places:
  - START: `ctl_cyrusdb -r` (recovery).  This is the *ONLY PLACE* that code is guaranteed to be run at startup on every Cyrus installation, so you'll find quite a lot of detritus has built up in this codepath over the years.
  - EVENTS: `ctl_cyrusdb -c` (checkpoint).  This is run regularly (`period=180` at Fastmail, examples in the codebase have `period=5` or `period=30`). Both this codepath and `cyr_expire` tend to run periodically on Cyrus systems, and cleanup code is spread between those two locations.

### `imap/cvt_cyrusdb`

Used for converting a database between versions.  This is often used
to prepare for upgrade, particularly in the past when Cyrus supported
Berkeley DB which didn't upgrade cleanly across OS versions, it was
common to use `cvt_cyrusdb` to turn databases into a very portable
format (`flat` or `skiplist`) before upgrading, upgrade the OS,
convert back to the fast format (Berkeley DB) and then restart.

### `imap/cyr_dbtool`

Once known as `brontool`, this is the first piece of Cyrus code I ever wrote!  It's a fairly dumb wrapper around the CyrusDB interface, and able to be used to read, write, or iterate any parts of a database.  Its interactive mode is not special-character clean, but it can also be used in batch mode, which uses IMAP atom-string literal8 for input/output, and hence can roundtrip data reliably.

There are also tools like: `ctl_conversationsdb`, `dav_reconstruct`
and `ctl_mboxlist` which can be used to manage individual databases
through a more specific interface which understands the context as
well as just the raw key/value.

## How to use CyrusDB

Assuming that [`cyrus_init()`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.h#L247) has been called, which calls [`cyrusdb_init()`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L328), you can assume that databases will work in any Cyrus code.

The first step is to open a database.  Databases have a filename -
this might be a literal filename on the backend, a directly containing
data, or an opaque token used by the backend to locate a datasource.

```c
int flags = 0;
struct db *mydb = NULL;
int r = cyrusdb_open("skiplist", "/tmp/database.db", flags, &mydb);
if (!r) return mydb;  // if (r == CYRUSDB_OK) { ... }
/* XXX: error handling */
```

#### Accepted flags

* `CYRUSDB_CREATE` - if the named database doesn't exist, create a
  blank database.
  
* `CYRUSDB_MBOXSORT` - use the abomination called
  `improved_mboxlist_sort` which re-orders a couple of characters to
  allow "foo.bar" to sort before "foo bar", for perfectly good
  reasons, but we're going to fix it a better way.  Not every engine
  supports arbitrary collation, and if many engines corrupt horribly
  if the same database is opened with different choices for this flag.
  Ouch.
  
* `CYRUSDB_CONVERT` - if set and the database fails to open, attempt a
  magic detection on the file content and try to convert the database
  to the requested backend type before opening it.  In-place upgrades!
  If this is NOT set, then instead the magic detection will still be
  performed, but the open database will be returned using the correct
  engine for that database rather than converted.  Magic detection
  only currently works for single-file database formats.

* `CYRUSDB_NOCOMPACT` - if the database format supports automatic
  compacting, don't use it.  Handy for when you want to read without
  causing any possible issues (e.g. read-only filesystem during
  recovery) or when performance is critical and you don't want to risk
  waiting while a recompact happens.
  

All the remaining functions take that [`struct db`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L83) pointer.

There's also
a
[`cyrusdb_lockopen()`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L179) interface 
which takes a transaction pointer and returns with the transaction
already active.  This isn't actually being used yet, but is intended
to allow slightly more efficient single-operation database use.  Right
now, open returns an unlocked database, but may need to lock as part
of the setup, so keeping that lock would avoid one extra unlock/lock
cycle.


## Reading, writing, transactions

CyrusDB supports both transactional and non-transactional access.
Transactions are always exclusive.  This is arguably a deficiency in
the interface, particularly since many engines implement a
non-exclusive (read) lock internally anyway.

There are now 4 interfaces to read data.  Two of which are original
cyrusdb and two of which are more recently added.

* original
  - [`cyrusdb_fetch()`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L194)   - fetch a single value by exact key.
  - [`cyrusdb_foreach()`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L229) - given a prefix, iterate over all the keys with that prefix (including exactly that key) in order.

* newer:
  - [`cyrusdb_fetchnext()`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L216) - given an exact key, fetch the following key and value (regardless of whether the key exists), e.g given keys "f" and "g", fetchnext "foo" would return "g", as would fetchnext "f".  This can be used to implement foreach (indeed, the skips do exactly that).
  - [`cyrusdb_forone()`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L241) - given an exact key, act like `cyrusdb_foreach` but only for that one key.  This is a convenience wrapper around fetch to allow doing things like:
```c
r = cyrusdb_forone(mydb, "folder", 6, p, cb, rock, &tid);
if (!r) r = cyrusdb_foreach(mydb, "folder.", 7, p, cb, rock, &tid);
```

Which does precisely *"folder"* and its children without visiting any other keys that have *"folder"* as a prefix.

Since the cyrusdb interface always takes both a pointer and a length, it's also possible to use:
```c
char *key = "folder.";
r = cyrusdb_forone(mydb, key, 6, p, cb, rock, &tid);
if (!r) r = cyrusdb_foreach(mydb, key, 7, p, cb, rock, &tid);
```

You may have noticed that `tid` at the end.  Every function for acting on the database takes as its last argument a [`struct txn **`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.h#L49).  You can pass one of three things to this:

* `NULL` - non-transactional request.  Do whatever you need for
  internal locking, but starts with an unlocked database and ends with
  an unlocked database.  NOTE: at least skiplist and twoskip implement
  a hack where if the database IS locked for a non-transactional read
  request, they will act as if you'd passed the current transaction in
  for the NULL case.  This is a hack around layering violations and
  kind of sucks.
  `&NULL` - e.g:
```c
   struct txn *tid = NULL;
   const char *data = NULL;
   size_t datalen = 0;
   int r = cyrusdb_fetch(mydb, key, keylen, &data, &datalen, &tid);
```

After calling this, tid will have an opaque value allocated by the
database backend, which must be passed to all further cyrusdb
operations on that database until either `cyrusdb_commit()` or
`cyrusdb_abort()` are called.
`&tid` - e.g.

```c
    if (r == CYRUSDB_NOTFOUND) {
        r = cyrusdb_store(mydb, key, keylen, "DEFAULT", 7, &tid); // set a default value
    }
```

Given an existing transaction, perform this call in the context of the transaction.

OK, foreach.  Foreach is very tricky, because it takes TWO callbacks.  The callbacks have an identical signature, but different return codes!

```c
typedef int foreach_p(void *rock,
                      const char *key, size_t keylen,
                      const char *data, size_t datalen);

typedef int foreach_cb(void *rock,
                       const char *key, size_t keylen,
                       const char *data, size_t datalen);
```

The difference is this:  `foreach_p` is called with the database
locked, **always** - even if called without a transaction.
`foreach_p` returns `1` or `0`.  `0` means *"skip this record"*, `1`
means *"process this record"*.  This is useful to pre-filter records
when called without a transaction, because otherwise you lock and
unlock all the time.

`NULL` for `foreach_p` is treated like a test which always returns `1`, so you can pass `NULL` if you don't need filtering.

If `foreach_p` returns `1`, then with an unlocked transaction, the
database is now unlocked BEFORE calling `foreach_cb`, the callback.
`foreach_cb` returns a `CYRUSDB_` response.  If zero, the foreach will
continue.  If non-zero, the `foreach` will abort and return the
non-zero response.  This is both useful for error cases, and useful
for short-circuiting, if you only care that a key exists, you can do
something like:

```c
static int exists_cb(void *rock __attribute__((unused)), [...])
{
    return CYRUSDB_DONE; /* one is enough */
}
```

and then use `exists_cb` as your `foreach_cb` and check if the return code is `CYRUSDB_DONE` to know if the foreach found a key.

If `foreach` is called with a transaction pointer, then it is your responsibility as the caller to also pass that pointer (and a pointer to the database) in that rock, so that callees can make further operations within the same transaction.  A foreach with a transaction does NOT unlock before calling its callback.

### Writing
There are three write operations:

- [`cyrusdb_create`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L258)
- [`cyrusdb_store`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L268)
- [`cyrusdb_delete`](https://github.com/cyrusimap/cyrus-imapd/blob/master/lib/cyrusdb.c#L278)

`cyrusdb_store` will either create or overwrite an existing key.
`cyrusdb_create` will abort if the key already exists.
`cyrusdb_delete` takes a flag `force'`which just makes it return
`CYRUSDB_OK (0)` rather than `CYRUSDB_NOTFOUND` if they key doesn't
exist.  Strangely, `force` is after `&tid`, making it the only cyrusdb
API that does that, but hey - keeps you on your toes.

`&tid` behaves exactly the same for the write APIs.  If not passed, then the database engine will behave as it if creates a writable transaction, does the operation, then commits all within the `cyrusdb_*` call.

### Gotchas!

* `NULL` is permitted in both keys and values, though `flat` and `quotalegacy` have 8-bit cleanliness issues.
* zero-length keys are not supported.
* zero-length values are theoretically supported, but a little
interesting.  Certainly, pass "" rather than `NULL` as the value when
writing or things will get weird.  I'm pretty sure at least the *skip
databases assert on these kinds of weirdness.
* unlocked `foreach`: this is the land of the gotcha!  They key and
data pointers (`const char *`) passed to your `foreach_cb` are only
valid **UNTIL YOU TOUCH THE DATABASE**. A common cause of rare and
hard to diagnose bugs is writing something to the same database in the
same process (**OR EVEN READING FROM IT AGAIN**).  I cannot emphasise
this enough.  If you want to zero-copy access that data, you need to
access it first, before touching that DB again.  Otherwise the map in
which the data was a pointer may have been replaced as the next read
found a new file and mapped it in!
Also: if you're implementing a backend.  Unlocked `foreach` must find future records created by the current callback.  Consider a database containing 4 keys:

```
A B C D
```

if you are at key `B` and insert a key `BB`, then it must be iterated over.  If you insert `AA` while at `B`, it must **NOT** be iterated over.

* Opening the same database multiple times.  In the bad old days,
  opening the same database multiple times in the same process led to
  locking bugs (`fcntl` is braindead).  Each database engine is
  responsible for making sure this doesn't happen.  Most engines keep
  a linked lists of open databases.  If you try to open the same
  database again, they will just return the existing opened copy and
  bump a refcount.  Beware.  If a database is locked and you try to
  lock again - thinking you were opening it brand new, it will
  assertion fail and/or error.


I think that covers about everything!

Cyrusdb is used just about everywhere that sorted key-value databases
give what's needed, including `mailboxes.db`, `annotations.db` (global and
per mailbox databases), seen state (non-owner), subscriptions,
`cyrus.indexed.db` for `Xapian`, and the rather massive (and increasingly
inaccurately named) `user.conversations`.

Future plans are to increase the usage of cyrusdb databases, possibly
by building an indexing layer on top and using that instead of the
sqldb interface used for sqlite databases by DAV code, and possibly
also moving other custom file formats into a cyrusdb to allow easier
stateless server builds on a distributed backend.
