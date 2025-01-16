This document describes the twom database format for key-value store within Cyrus.

## Skiplists

A [skiplist](https://en.wikipedia.org/wiki/Skip_list) is a data structure gives O(log N) access to data; by creating multiple linked lists.  Every node contains a pointer to the immediately next node in a sorted order, however some nodes also contain links that “skip over” some number of nodes, hence “skip”.  I won’t describe in detail how skiplists work here, as that’s described well in other places.

## The original cyrus skiplist format

This format is purely just an in-memory skiplist, where new “allocations” are just appending a set of bytes to a file, and the pointers for are all relative pointers, offsets within the file.

Since there is no way to “free” a pointer in this format, garbage collection is done by creating a new file and copying all the records into the new file.  This was done with a special INORDER record type, which was otherwise identical to an ADD but only occurred after a repack.

## The twoskip file format

Twoskip added an extra innovation to the skiplist format - a second linked list at the bottom level, which includes every single record in order - but with a twist.  The two pointers leapfrog each other, so it’s always the lowest pointer which is updated each time.  This means that if there’s a crash, the pointer which doesn’t point past the old size of the file will always point to the record which used to be the next in the valid records - so a repair is just a matter of walking all the valid level 0 pointers, and zeroing out any future pointers plus fixing up the higher level  pointers.  This is so fast that transaction `abort()` is implemented as just running recovery on the file.

Along with a three phase commit, this makes the twoskip file format incredibly robust.  The three phases are:

1. before writing any new record to the end of file, mark the header as DIRTY, and fsync
2. once all new records are written, fsync the entire file (still marked dirtry)
3. mark the header NOT-DIRTY along with the new file length, and fsync

This means that so long as the final header write is atomic, transactions are always completely safe.

## Twoskip downsides:

- Three fsyncs per transaction is kinda expensive!
- Every write causes the file to be extended, as twoskip format uses exact file size and doesn’t allocate slop.
- A single write does amplify into 1+N (the level of the record) writes; the append of the new record, and the updates of the immediately previous records in the skiplist at each level.  Since half the records are level 1, half that level 2, etc - the average write updates three separate previous records.  In a recently repacked file, the previous records are likely to be adjacent or nearly so for the lower levels, but this becomes less so over time, so repacks are valuable for both data locality and size reduction.
- The repack operation requires the database to be remain exclusively locked for the duration, which is slow on large files (particularly along with the above lack of slop).

## The Twom format

Why the name?  It’s twoskip, but with mmap and MVCC.  Two Ms.  And the “tombstone” records, rather than just causing the skiplist to be rewritten without the deleted record in it, remain in the linked lists right until a repack, with an ANCESTOR pointer back to the previous entity with that key.

This tombstone allows the MVCC transaction, because you can walk the current lowest level linked list, and any time you find a record with an offset in the future of the file size at the time you started the transaction, walk back up the ancestor chain (which is a single linked list backward through the file, to the original ADD record which was the first time the key was seen in this file).

With MVCC transactions, we can then re-implement the repack operation; instead of having to lock the file for the entire repack, we can take a read-only lock and yield it many times while walking the original records and adding them to the new file in sorted order, and then (still releasing locks as many times as we like) read the remainder of the file and replay the operations (adds, replaces and deletes) to the new file.  This doesn’t require any exclusive lock at any point, so readers can continue throughout the repack, even until the rename - and either get the old file or the new file.

Remaining issues:

- We still use 3 fsyncs - there’s no way around this without risking a crash leaving a file in a broken state.  We could theoretically still get a clean read after a single failure by checking for end pointers during the “locate” phase and falling back to the lowest level pointers - but if we then started another write; there would be invalid pointers somewhere in the file and it would corrupt over time.  Nope.
- The write amplification issue is still the same, twom is basically the same format as twoskip, just with the addition of ancestor pointers and richer tombstones.

### Navigating the code - data structures:

Structures named `twom_` are public, `tm_` are entirely internal.

- `struct twom_db` - this is refcounted and contains pointers to all the refcounted resources that it has open.  When you open a DB again, you get another pointer to the same file, and when you open a transaction or a location on the database, you hold a reference that the file won’t be closed under you.
- `struct twom_txn` - a transaction on the database.
    - If this is an exclusive transaction (not TWOM_SHARED) then you can write to the file and either abort or commit.  A transaction dirties the file on first write.  An exclusive transaction forces the file to remain locked exclusively for the duration of the transaction.
    - If this is read-only transaction, it can be either MVCC or not.  If it is MVCC, then it never changes file, it always reads from the same file, though it may still need to refresh the length if the lock has been released.  Read-only transactions can release the lock, either explicitly using `twom_yield` or implicitly every N transactions to avoid starving other database users.
    - Has a reference counted on the file into which it points, to ensure it isn’t released if this is an MVCC transaction.
- `struct tm_loc` - a location in the database.  This contains an offset for the current record, the locations of the immediately preceeding record at every level, and the length of the file when it was calculated (a change in file length means that back pointers may have been changed and the location is no longer valid).  If the current record has a DELETE before it, will also contain a `deleted_offset` value.
    - Has a reference counted on the file into which it points, which is required to allow relocation without having to copy the key content.
- `struct tm_file` an mmaped file.  Has the file handle and tracks the lock on it.  Also has a parsed version of the header of the file, which is updated every time it’s locked.  (strictly this isn’t necessary, we could do it all with MMAP reads directly from the file).
    - Also contains pointers to the checksum and comparison functions for this file.  These CANNOT BE CHANGED after file creation, but can either use the ones built into twom, or you can pass external functions at file creation time.
    - Refcounted by txn and loc above.
- `struct twom_cursor` a wrapper around a loc and a txn, used by public API for cursor operations.

## Locking

Twom uses a two-phase locking system, as described in [a stackoverflow post](https://stackoverflow.com/questions/27625597/how-to-implement-a-writer-preferring-read-write-lock-for-nix-processes).

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
