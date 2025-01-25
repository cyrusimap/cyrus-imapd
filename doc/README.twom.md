This document describes the twom database format and implementation

A [skiplist](https://en.wikipedia.org/wiki/Skip_list) data structure provides
O(log N) lookup through probabilisticly creating different linked lists that
skip over multiple records, approximating a binary search.  The lowest "level"
linked list always visits every record in the database's sort order.

The twom database format is a serialised representation of a skiplist data
structure, repesenting an ordered list of key/value pairs in a single mmaped
file.  Links between records are stored as offsets within the file.  When new
records are added, the offsets on the previous records in the link are updated
by overwriting their location in the file.

Twom (and its predecessor twoskip) uses two offsets for the lowest level linked
list.  They are updated in alternating order, meaning that if there is a crash,
the previous value for "next record in order" is always available.

The twom database header always contains the size of the database after the last
commit, so any offset past that size points to a record that was being created
but is not yet committed.  Because there's always a pointer at the lowest level
that contains the old state of linked list, it is possible to recover from a
crash by following that lower offset to find the next record.

The twom "recovery1" function does precisely this, keeping track of any
higher-level offsets that are too large, and updating them when it finds the
next record of at-least as large level.  This fully repairs the database with
a single scan and a number of writes equivalent to the number of offsets that had
been touched by the incomplete transaction.  This is so fast that twom implement
transaction abort by acting as if it was doing crash recovery.

Along with a three phase commit, this makes the twom file format
incredibly robust.
The three phases are:

1. before writing any new record to the end of file, mark the header as DIRTY, and fsync
2. once all new records are written, fsync the entire file (still marked dirtry)
3. mark the header NOT-DIRTY along with the new file length, and fsync

This means that so long as the final header write is atomic, transactions
are always completely safe.


## The Twom format

Why the name?  It’s twoskip, but with mmap and MVCC.  Two Ms.  And the “tombstone” records, rather than just causing the skiplist to be rewritten without the deleted record in it, remain in the linked lists right until a repack, with an ANCESTOR pointer back to the previous entity with that key.

This tombstone allows the MVCC transaction, because you can walk the current lowest level linked list, and any time you find a record with an offset in the future of the file size at the time you started the transaction, walk back up the ancestor chain (which is a single linked list backward through the file, to the original ADD record which was the first time the key was seen in this file).  By stopping at the highest offset which is lower than the file size when the transaction started, you always see a consistent view of what was in the database at that time.

With MVCC transactions, we can then re-implement the repack operation; instead of having to lock the file for the entire repack, we can take a read-only lock and yield it many times while walking the original records and adding them to the new file in sorted order, and then (still releasing locks as many times as we like) read the remainder of the file and replay the operations (adds, replaces and deletes) to the new file.  This doesn’t require any exclusive lock at any point, so readers can continue throughout the repack, even until the rename - and either get the old file or the new file.

### Twom Header:

The header is packed directly into the first 96 bytes of the file.  All numbers are stored little-endian

* Magic: 16 bytes ("\241\002\213\015twomfile\0\0\0\0")
* UUID: 16 bytes - random data that identifies a database
* Version: 4 bytes - a 32 bit number identifying the format revision
* Flags: 4 bytes - a 32 bit number with a bitfield of flags set on the database
* Generation: 8 bytes - a 64 bit counter of how many times the file has been repacked
* Num Records: 8 bytes - a 64 bit counter of how many non-deleted key-value records are in the file
* Num Commits: 8 bytes - a 64 bit counter of how many transactions are in the file
* Dirty Size: 8 bytes - a 64 bit number representing the sum of the sizes of all active DELETE records plus all records which are an ancestor.
* Repack Size: 8 bytes - a 64 bit number which is the offset at which all the records were repacked in exactly the correct order.  After this point there may be replaces or deletes.
* Current Size: 8 bytes - a 64 bit number which is the offset of the end of last commit which is persisted to disk.
* Max Level: 4 bytes - a 32 bit number (though maximum value is 31) of the highest level of any record in the file other than the DUMMY record.
* Checksum: 4 bytes - a 32 bit checksum over the preceeding 92 bytes.

### The Dummy Record

The "DUMMY" is just a record with no key or value, and with the highest possible level in the file.  It has a fixed offset (96 bytes into the file), and is the starting point for iteration and lookups, as it contains the contains offsets to the first data record at each level.

### Records

After the Dummy Record, new records are appended to the file.  There are 6 other types of record:

* ADD / FATADD
* REPLACE / FATREPLACE
* DELETE
* COMMIT

A transaction consists of one or more of the first 5 types of record, followed by a single COMMIT record.
The FAT variants of each record are 16 bytes longer, and have 64 bit lengths for both key and value,
allowing massive data storage.  The regular ADD and replace have 16 bit length for key and 32 bit length
for value.

All ADD, REPLACE, and DELETE records are linked into the skiplist, either directly or via an ANCESTOR
pointer from a record which is in the skiplist.  COMMIT records are not linked to anything, each COMMIT
only contains an offset back to the size of the file before the commit (meaning that it points back to
the start of the range of records that it commits).

### Navigating the code - data structures:

Structures named `twom_` are public, `tm_` are entirely internal.

- `struct twom_db` - this is refcounted and contains pointers to all the refcounted resources that it has open.  When you open a DB again, you get another pointer to the same file, and when you open a transaction or a location on the database, you hold a reference that the file won’t be closed under you.
- `struct twom_txn` - a transaction on the database.
    - If this is an exclusive transaction (not TWOM_SHARED) then you can write to the file and either abort or commit.  A transaction dirties the file on first write.  An exclusive transaction forces the file to remain locked exclusively for the duration of the transaction.
    - If this is read-only transaction, it can be either MVCC or not.  If it is MVCC, then it never changes file, it always reads from the same file, though it may still need to refresh the length if the lock has been released.  Read-only transactions can release the lock, either explicitly using `twom_db_yield` or implicitly every N transactions to avoid starving other database users.
    - Has a reference counted on the file into which it points, to ensure it isn’t released if this is an MVCC transaction.
- `struct tm_loc` - a location in the database.  This contains an offset for the current record, the locations of the immediately preceeding record at every level, and the length of the file when it was calculated (a change in file length means that back pointers may have been changed and the location is no longer valid).  If the current record has a DELETE before it, will also contain a `deleted_offset` value.
    - Has a reference counted on the file into which it points, which is required to allow relocation without having to copy the key content.
- `struct tm_file` an mmaped file.  Has the file handle and tracks the lock on it.  Also has a parsed version of the header of the file, which is updated every time it’s locked.  (strictly this isn’t necessary, we could do it all with MMAP reads directly from the file).
    - Also contains pointers to the checksum and comparison functions for this file.  These CANNOT BE CHANGED after file creation, but can either use the ones built into twom, or you can pass external functions at file creation time.
    - Refcounted by txn and loc above.
- `struct twom_cursor` a wrapper around a loc and a txn, used by public API for cursor operations.

## Locking

Twom uses fcntl for locking, specifically a two-phase locking system, as described in [a stackoverflow post](https://stackoverflow.com/questions/27625597/how-to-implement-a-writer-preferring-read-write-lock-for-nix-processes).

Copying the key parts here:

<blockquote>
Assume that two arbitraty lock-files are already opened into descriptors fd_sh and fd_ex. Then to gain shared access:

    flock(fd_ex, LOCK_SH) - allow multiple readers to pass through this lock but block writers
    flock(fd_sh, LOCK_SH) - used to block activated writer while readers are working
    flock(fd_ex, LOCK_UN) - minimize time when readers hold this lock
    DO USEFUL WORK
    flock(fd_sh, LOCK_UN)

To gain exclusive access:

    flock(fd_ex, LOCK_EX) - only one process can go through this lock
    flock(fd_sh, LOCK_EX) - effectively wait for all readers to finish
    flock(fd_sh, LOCK_UN) - readers finished, lock is unnecessary (can be done after the work, doesn't matter)
    DO USEFUL WORK
    flock(fd_ex, LOCK_UN)

Such method gives writers much more chances to get the lock because readers hold fd_ex very small time necessary just to lock fd_sh in shared mode which in turn is very quick in the absence of working writer. So first writer will go through step 1 in rather small time and on step 2 will wait for only that readers which already have the lock. 
</blockquote>

Except instead of using two file descriptors, we use fcntl with two ranges:

1) the 'fd_ex' above is the range 0-16, called 'headlock'
2) the 'fd_sh' above is the range DUMMY_OFFSET for DUMMY_SIZE, called 'datalock'

We reverse the exclusive case above though, and release fd_ex first before doing the work, so we that readers can line up for a chance to all get a read before the next writer.  This is slightly more reader-friendly, but still allows a writer to get in once all the waiting readers have moved past the first lock.

3) the 'repacklock' which is the range OFFSET_GENERATION-8 (40-48)

We also have a third range lock which is held by any process doing a repack.  Owning this lock gives you exclusive rights to the file filename.NEW, so while it's held you can unlink any existing file with that name, and create a new one to start repacking to.  This is taken while holding a read-lock on the file and is taken with a non-blocking fcntl; so if two processes race for it, only one will succeed.

## Navigating the code - functions

I’ll just describe the key functions, all the basic refcounting and low level pointer checking is pretty self explanitory, but:

`_setloc`

This updates a previous record’s pointer - the level 0 pointer either goes to “the one past the end already” (multiple updates in the same transaction) or “the lower one” (leapfrog situation).

`_recsum` 

Recalculates the checksum for a record, MUST be called after updating one or more pointers with `_setloc` .

`locate()` 

Starts from an empty `tm_loc` record and ensures it has all the correct backloc pointers for the immediately prior record.

It starts at the DUMMY record, and for every level from the highest down, walks the linked list at that level until it finds the record or a later one, then repeats for the next level, retaining the last record in backloc.

If it matches exactly, `offset` will be set to the record and `is_exactmatch` will be 1, otherwise `offset`  will be the record before the gap where it should be, and `is_exactmatch` will be zero.

At the lowest level, it also tracks whether the current item was preceeded by a DELETE record and ancestor pair, and in that case also sets `deleted_offset` to the prior delete record.  This is only useful when `is_exactmatch` is true,
which is suppresses returning the value and is used for some other checks.

`relocate()`

Given an existing located `tm_loc` record, if the file has changed size or the transaction has a new file, use the offset to find the existing key, and call `locate`above to reset the location back to the same spot.  NOTE: this may change `is_exactmatch` depending on whether the record has been created or deleted since, and may also give new offset, new backloc values, and even change the `tm_file` pointer in the `tm_loc` object.  If the file handle has changed and this location held the last reference, it may cause the file to be unmapped and closed (e.g. after a repack by another process).

`advance_loc()`

Given a location, find the next record, while updating all the backloc pointers.  This is used by cursors to advance through the file.  Starts with `relocate()` above to ensure that the pointers are fresh.

`find_loc()`

An efficiency wrapper around `locate()`.  Has the same API, but if the file hasn’t changed and the requested key is any of:

- the same key as the location
- the immediate next key in the file
- in the gap between those two

Then it will more efficiently find the location rather than having do a full locate from the start of the file.  If it’s not any of those, or the location is invalid due to the file having been extended or replaced, then it falls back to a full `locate()`.

`store_here()` 

The single function through which all creates, updates and deletes are made.  Will set the file dirty if it’s not already and sync, then append the record, and update all the pointers.

Has smarts for pointers into the existing mmap so you can safely call it with pointers returned by `fetch` or a cursor, and even if the file gets extended and re-mapped, they will work.

`recovery1()` and `consistent1()`

Walks every single record at level 0, keeping backpointers and checking that the keys are in correct order, and all the higher level linked lists are linked correctly to every record that reaches up to their level.  The difference being that consistent will return an error if anything is wrong, while recovery will fix the error!  Also re-calculates the header counters, and likewise compares or fixes them.  Obviously recovery needs an exclusive lock while consistent can run with a shared lock, and recovery will also clear the DIRTY flag when done.

`write_lock()` 

Actually does a bit more than you would expect by the name.  Will create a header if the file is empty, will detect if the existing filehandle is no longer pointing to the inode of the named file and re-open the new copy of the file (refcounting to support MVCC above) - and will release any READ lock on the file first since read transactions can recover fine from that and also support reading from writelocked files.

Will run recovery if the file is DIRTY.

`read_lock()` 

The wimpier cousin of write_lock.  If the file is empty or dirty, it will try for a `write_lock` to fix it, or just error if the database is readonly.

Still takes a writeable mmap unless the database was opened readonly, since that avoids having to unmap and remap later if the caller then takes a write_lock later.

`opendb()` 

A wrapper around opening a database; will use read or write locks as appropriate.  Doesn’t create directories even if creating a database, that’s in the cyrusdb wrapper.

`abort_locked()` 

If called on a dirty file, will use `recovery()` to repair all the pointers as if it was recovering from a crash.

`commit_locked()`

If called on a dirty file, will add a trailing COMMIT record, sync the file, then update the header to record the new file length and remove the dirty flag and sync again.

`twom_cursor_next()`

The rest of the functions are pretty simple, but this one has some smarts.  It handles releasing every N records, finding the new file if not in mvcc and updating the end pointer as well so new changes appear; then re-locking.

It also has the MVCC logic for walking the ancestor list until you find a record which was in the file when the transaction started (or not; in which case it’s absent).  Likewise if you find a tombstone record (`!hasval[TYPE(ptr)]`) then skip.

Foreach is then just implemented as a wrapper around the cursor, and there’s both txn and non-txn (create their own temporary txn) versions of each of the APIs.

`twom_db_repack`

Finally, the repacker!  This creates an MVCC transaction on the database file, then creates a new file called `fname.NEW` and exclusively locks it with a write transaction.  It checks the file to make sure it didn’t lose the race, and then this process has an exclusive lock against other rewriters, so it proceeds to copy each record from the MVCC transaction, in order, to the new database file.

This process needs a read lock, but it can release it frequently (every few thousand records), so it doesn’t starve writers, and it doesn’t block readers at all!

Once all the records in the MVCC transaction are done, it then replays every record added to the file afterwards, again releasing the lock occasionally until it reaches the end still in a shared lock on the active database file.  This blocks any more writes.  With that shared lock held, it updates the header on the new file to have the same UUID as the old file, and a generation one higher and fsyncs the contents.

Finally, it renames the file into place and fsyncs the directory.  At this point, all other processes will discover that the file has changed, and open the new file before progressing.  The one exception is any other MVCC reader, which will retain the old file descriptor and keep reading from it until they are done.  The operating system will keep that content around, so it will work fine - and once the final reader releases its handle, the file will be cleaned up.
