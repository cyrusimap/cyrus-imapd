.. _imap-developer-api-mailbox:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.  Converted via the pandoc tool from HTML.

Mailbox API
===========

Intro
-----

The Mailbox API is implemented in ``imap/mailbox.h`` and
``imap/mailbox.c``. It wraps the data structures of the
``cyrus.header``, ``cyrus.index`` and ``cyrus.cache`` files in a
psuedo-object-oriented way, allowing easy changes to the mailbox while
keeping the internal cached data structures consistent.

Opening and closing
-------------------

::

    struct mailbox *mailbox = NULL;
    int r;
    const char *mboxname = "user.brong";

    r = mailbox_open_iwl(mboxname, &mailbox);
    // or
    r = mailbox_open_irl(mboxname, &mailbox);
    // or
    r = mailbox_open_exclusive(mboxname, &mailbox);
    if (r) return r;

    do_stuff(mailbox);

    mailbox_close(&mailbox);

It is always necessary to obtain an index lock when opening a mailbox,
because the index header read must be consistent. The locks are as
follows:

+----------------------------+-------------+--------------+
| Function                   | Namelock    | Index Lock   |
+============================+=============+==============+
| mailbox\_open\_iwl         | Shared      | Exclusive    |
+----------------------------+-------------+--------------+
| mailbox\_open\_irl         | Shared      | Shared       |
+----------------------------+-------------+--------------+
| mailbox\_open\_exclusive   | Exclusive   | Exclusive    |
+----------------------------+-------------+--------------+

It should never be necessary to call ``mailbox_open_exclusive``, but
it's included for completeness. Use ``mailbox_open_iwl`` if you expect
to need to write to the index (or even if you're not sure) and
``mailbox_open_irl`` when you know you're only reading from the file and
wish to allow other readers to work concurrently.

Many actions are delayed until the mailbox is closed, or even until the
*last* mailbox is closed for things that require an exclusive namelock
to perform like deletion or repack. See below under "delayed actions"
for more detail.

To avoid opening the same file multiple times, the mailbox API refcounts
open mailboxes. If you open the same mailbox again (i.e. a URL fetch or
status command on the currently select mailbox) then the same mailbox
will be returned. It must be unlocked (see below or the open command
will return IMAP\_MAILBOX\_LOCKED). The matching close will reduce the
refcount, and only the final close will do the cleanup actions.

Locking and unlocking
---------------------

You can keep a mailbox "open", maintaining the namelock, while releasing
the index lock to allow other processes to make changes to the mailbox.
By holding the namelock, you know that record numbers won't change, and
the underlying message files won't be deleted.

``mailbox_close`` will call ``mailbox_unlock_index`` if the index is
still locked, so it is not necessary to explicitly unlock the index
before closing.

::

    r = mailbox_unlock_index(mailbox, NULL);

    // sleep on user input...

    r = mailbox_lock_index(mailbox, LOCK_SHARED);
    // or
    r = mailbox_lock_index(mailbox, LOCK_EXCLUSIVE);

For example, ``mailbox_unlock_index`` and ``mailbox_lock_index`` are
used extensively by the index module, allowing an imap client to
maintain a long lived connection selected to a mailbox and know that
messages won't magically disappear from under it - yet at the same time
allow new mail delivery to happen or other imap connections to query the
mailbox.

If you have built an accurate statuscache item for the locked mailbox,
you can pass this as the second parameter to mailbox\_index\_unlock. If
there have been any changes, mailbox\_index\_unlock will invalidated the
statuscache. If you give it the new value, then it will store that value
instead. For example:

::

    struct statusdata sdata;
    index_status(state, &sdata);
    /* RECENT is zero for everyone else because we wrote a new
     * recentuid! */
    sdata.recent = 0;
    mailbox_unlock_index(state->mailbox, &sdata);

See "delayed actions" below for delayed actions performed during an
unlock.

Creating, renaming and deleting
-------------------------------

**WARNING:** These functions only change the mailbox files on disk. They
don't update the mailboxes.db records or contact murder servers. In most
cases you are probably looking for the ``mboxlist_`` functions instead.

Creating a mailbox is somewhat longwinded - as there are many optional
parameters.

::

    int mailbox_create(const char *name, const char *part, const char *acl,
                       const char *uniqueid, int options, unsigned uidvalidity,
                       struct mailbox **mailboxptr);

Most interesting to note is that on success, ``mailboxptr`` will contain
the same mailbox that ``mailbox_open_exclusive`` above would have
returned, with an exclusive namelock and an exclusive index lock. This
allows you to perform other consistency operations after creating the
mailbox with a full guarantee that no other process will even be able to
know of the mailbox's existence! You can still roll-back by deleting the
mailbox and the next process will get the namelock and see no mailbox
with that name.

::

    int mailbox_rename_copy(struct mailbox *oldmailbox,
                            const char *newname, const char *newpart,
                            const char *userid, int ignorequota,
                            struct mailbox **newmailboxptr);

Very similar to mailbox\_create - the new mailbox is created with an
exclusive name lock and returned. The old mailbox must be passed in with
an **exclusive index lock** but is fine with a shared namelock, as it
will be passed to ``mailbox_delete``.

::

    int mailbox_delete(struct mailbox **mailboxptr);

Just like ``mailbox_close`` above, this closes the mailbox. Before it
does so, it sets the OPT\_MAILBOX\_DELETED option flag in the index
header. The interesting work is actually done in ``mailbox_close``. See
below under "delayed actions".

``mailbox_delete`` requires an exclusive index lock, but can complete
quite happily with only a shared namelock.

Reading and writing records
---------------------------

Ok - so you have a mailbox, it's opened, and the index is locked. Time
to start reading and writing some records!

At the mailbox level there is no concept of "message numbers" from imap,
only "record numbers". The canonical variable name to refer to record
numbers is ``recno``. All records are read and written using
``struct index_record`` values.

Here at the API definitions used for reading and writing:

::

    int mailbox_read_index_record(struct mailbox *mailbox,
                                  uint32_t recno,
                                  struct index_record *record);
    int mailbox_rewrite_index_record(struct mailbox *mailbox,
                                     struct index_record *record);
    int mailbox_append_index_record(struct mailbox *mailbox,
                                    struct index_record *record);
    int mailbox_commit(mailbox);

An example of iterating through a mailbox

::

    uint32_t recno;
    struct index_record record;
    int make_changes;

    /* DEPRECATED */
    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
        if (mailbox_read_index_record(mailbox, recno, &record))
            fatal("invalid record", EC_SOFTWARE); // or return an error
        if (record.internal_flags & FLAG_INTERNAL_EXPUNGED)
            continue; // skip expunged records
        make_changes = do_stuff(mailbox, &record);
        if (make_changes)
            mailbox_rewrite_index_record(mailbox, &record);
    }

    /* the new way */
    int make_change;
    const struct index_record *record;
    struct mailbox_iter *iter;

    iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    while ((record = mailbox_iter_step(iter))) {
        make_changes = do_stuff(mailbox, record);
        if (make_changes)
            mailbox_rewrite_index_record(mailbox, record);
    }
    mailbox_iter_done(&iter);

NOTE: ``mailbox_rewrite_index_record`` doesn't need a recno, as that's
cached inside the index\_record struct.

NOTE: You need an exclusively locked index to use rewrite or append, but
only a shared index lock to use read.

There are a range of consistency checks done to ensure that a rewrite
doesn't violate IMAP semantics (an expunged message can never be
unexpunged, UIDs can't change, etc) and the internal tracking counts and
quota data are updated as well. They will be committed at unlock time,
see "delayed actions"

If you don't set the ``record.silent`` field to a true value before
rewriting or appending, the ``record.modseq`` and
``record.last_updated`` values will be changed. This allows condstore to
work correctly.

Appending
~~~~~~~~~

To append a record, the file must have already been copied into place
(XXX - plan to move to a stage based system where the mailbox API
handles the staging, but that's not finished yet) and been parsed into
the record struct. The UID must be set already, and must be greater than
the UID of any existing record in the mailbox. There are a range of
consistency checks done.

The internal consistency counts are updated by append as well.

Committing
~~~~~~~~~~

When you have finished making any changes, you need to "commit". This
will write the updated values for any index header fields, rewite the
``cyrus.header`` file if needed and fsync all changes to disk.

It is a fatal error to unlock (or close) a mailbox that has had changes
without committing, as it can leave the mailbox in a corrupted state.

Cache records
~~~~~~~~~~~~~

Cache records are accessed through ``record.crec`` which is not filled
by read\_index\_record. The cache file is only read and mapped into
memory as needed, so you if you want to access cache records, the basic
API is as follows:

::

    int mailbox_cacherecord(struct mailbox *mailbox,
                            struct index_record *record);
    const char *cacheitem_base(struct index_record *record, int field);
    unsigned cacheitem_size(struct index_record *record, int field);
    struct buf *cacheitem_buf(struct index_record *record, int field);

You must always call ``mailbox_cacherecord`` on a record before trying
to access any of the cache items. "``field``" above is the individual
field (there are 10) in the cache record. There's more information on
those fields in the mailbox internal format documentation.

::

    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
        if (mailbox_read_index_record(mailbox, recno, &record))
            fatal("invalid record", EC_SOFTWARE); // or return an error
        if (record.internal_flags & FLAG_INTERNAL_EXPUNGED)
            continue; // skip expunged records
        if (mailbox_cacherecord(mailbox, &record))
            fatal("failed to read cache", EC_SOFTWARE);
        ...
        envelope_length = cacheitem_size(&record, CACHE_ENVELOPE);
    }

See ``imap/mailbox.h`` for the full list of constants.

Delayed Actions
---------------

Here's the bit you've been waiting for! What happens during unlock and
close

first, unlock
~~~~~~~~~~~~~

Anything that makes any changes sets the mailbox->has\_changed flag. If
this is set, then before the index gets unlocked:

-  the updatenotifier (idle) is called
-  ``sync_log_mailbox`` (replication) gets called
-  the statuscache value gets erased (or replaced if you passed in an
   updated value).

then: close
~~~~~~~~~~~

next the index is unlocked (see above)

third, any "unlink" commands scheduled for email files are run. These
can't be done until after the mailbox\_commit to ensure consistency -
the file isn't deleted until the record is written as unlinked! But we
save the unlink until now so that other tasks aren't waiting for the
index lock while the unlinks run. Unlink is expensive in IO and time.

finally we check for MAILBOX\_NEEDS\_REPACK or MAILBOX\_DELETED option
flags. If either is sets, then we make a non-blocking attempt to get an
exclusive namelock. If the non-blocking attempt fails, then another
process has the mailbox open, so save the cleanup for them! If it
succeeds, then go ahead with either ``mailbox_delete_cleanup`` or
``mailbox_index_repack`` as appropriate.

After this it's just a matter of releasing malloc'd memory and finally
releasing the name lock.
