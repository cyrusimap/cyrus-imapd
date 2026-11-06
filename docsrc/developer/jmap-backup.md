# JMAP Backup restores

*Internal developer reference for the Cyrus team.*

The `https://cyrusimap.org/ns/jmap/backup` extension, enabled by
`jmap_nonstandard_extensions`, undoes recent changes to an account by
reviving data Cyrus still holds: expunged records whose files have not been
cleaned up, and deleted mailboxes not yet removed by `cyr_expire`.  Nothing
is read from an external backup.  All four methods are in
`imap/jmap_backup.c`.

| Method                    | Collections walked                                |
|---------------------------|---------------------------------------------------|
| `Backup/restoreContacts`  | every addressbook under the account's home set    |
| `Backup/restoreCalendars` | every calendar under the home set, deleted ones too |
| `Backup/restoreNotes`     | the `notesmailbox` mailbox only                   |
| `Backup/restoreMail`      | every mail mailbox in the account, deleted ones too |

## Arguments and response

- `undoPeriod` (required): an RFC 5545 duration.  The *cutoff* is now minus
  this duration; only changes after the cutoff are undone.
- `performDryRun`: count what would be restored without changing anything.
  It is echoed in the response.
- `verboseLogging`: log each decision at `LOG_INFO` instead of `LOG_DEBUG`.
  The events are `jmap.backup.*`; `backup.reason` says why a record or
  collection was selected or skipped.
- `undoAll` (not mail): undo creates and updates as well as destroys.
- `restoreDrafts`, `restoreNonDrafts` (mail only, both default true).

Mail responds with `numDraftsRestored` and `numNonDraftsRestored`; the
others with `numCreatesUndone`, `numUpdatesUndone` and `numDestroysUndone`.

On success each method raises the deletedmodseq of its collection type
(`mboxname_setmodseq(..., MBOXMODSEQ_ISDELETE)`), so a client holding an
older state gets `cannotCalculateChanges` from `/changes` and resyncs instead
of missing the restored objects.

## Contacts, calendars and notes

These share one algorithm, `restore_collection_cb()`, run on each
collection.  Records are grouped by *resource name*, which identifies one
object across all its versions:

- Contacts and events: the DAV resource name, from the CardDAV or CalDAV
  database, or from the `filename` parameter of the record's
  Content-Disposition for a version the database no longer lists.
- Notes: the `X-Universally-Unique-Identifier` header of a message whose
  `X-Uniform-Type-Identifier` is `com.apple.mail-note`.  Other messages in
  the notes mailbox have no resource name and are never restored.

### Choosing what to undo

Records are scanned newest first (descending record number), and the first
decision made for a resource name stands, except that older records can
supply the version to recreate.  A live record is the current version; an
expunged one is a tombstone.  `savedate` is when a version was written and
`last_updated` on a tombstone is when it was expunged.

| Record seen                                   | Effect on the resource                       |
|-----------------------------------------------|----------------------------------------------|
| live, saved after cutoff                      | *create*; destroy this version               |
| live, saved before cutoff                     | unchanged; ignored                           |
| tombstone, saved after cutoff, `undoAll`, first seen | *create*, already destroyed; destroy this version |
| tombstone saved before cutoff (or any tombstone without `undoAll`), expunged after cutoff, first seen | *destroy*; recreate this version |
| tombstone saved before cutoff, resource already a *create* | becomes *update*; recreate this version |
| any tombstone once a version to recreate is chosen | ignored                                 |
| tombstone expunged before cutoff, first seen  | ignored                                      |

Then, per resource:

- *destroy*: recreate the chosen version.  Always done.
- *update* (`undoAll` only): recreate the pre-cutoff version and expunge the
  newer one, flagged `DFLAG_UNBIND` because it was replaced.  If the
  resource had since been destroyed, this one step undoes both, and both
  counters go up.
- *create* (`undoAll` only): expunge the post-cutoff version.  A resource
  created and destroyed entirely after the cutoff is left alone.

Without `undoAll`, a resource created and destroyed after the cutoff comes
back, because only destroys are being undone.

With `undoAll`, a collection whose `changes_epoch` is later than the cutoff
fails the whole method with `cannotCalculateChanges`: its history no longer
reaches back far enough.

Recreating appends the old record's file as a new record (`recreate_resource()`)
with its flags minus `\Deleted` and `DFLAG_UNBIND`, plus `$restored`, and
with its annotations.  An update keeps the old record's `createdmodseq`.
Work is done under a write lock released every 512 resources.

### Contacts

Only existing addressbooks are scanned; a deleted addressbook is not
restored.  Every contact recreated by undoing a destroy is added as a member
of a new group vCard per addressbook, named `Restored YYYY-MM-DD`, with
` (n)` appended if that name is taken.  No group is created on a dry run.

### Calendars

The scheduling Inbox and Outbox, and calendars the user cannot add items to,
are skipped.

A calendar deleted after the cutoff is restored whole, into the live
calendar with the same `DAV:displayname` if there is one, or else into a new
calendar with that displayname and the old `calendar-color`.  Every record in
the deleted calendar is appended, expunged ones included, so older versions
of an event are recreated along with its latest one.  The deleted calendar is then
removed permanently.  Calendars deleted before the cutoff are ignored.

Undoing a change to an event with an ORGANIZER sends iTIP through
`sched_defer()`, as if the user had made the change:

- If the user is the organizer, attendees get a REQUEST for a recreated
  event, or a CANCEL for an expunged one.
- If the user is an attendee, the organizer gets a REPLY, except when
  expunging an event the user never replied to (PARTSTAT absent or
  NEEDS-ACTION).
- Undoing an update increments SEQUENCE, and the event is stored through
  `caldav_store_resource()` so that it gets a new schedule tag.

Events without an ORGANIZER are recreated like any other resource.

## Mail

Mail has no resource name or version history, so `Backup/restoreMail` works
from Email identity instead: GUID (the JMAP Email id), Message-ID, and for
memos, In-Reply-To.  It never undoes creates or updates.

### Scanning

`restore_message_list_cb()` walks the account's whole mailbox tree, deleted
mailboxes included, skipping the notes mailbox, the `\Scheduled` mailbox,
non-mail mailboxes, and mailboxes deleted before the cutoff.

A record is *destroyed* if it has `\Deleted` or is expunged and was last
updated after the cutoff (its removal time), or if it is in a mailbox
deleted after the cutoff (removal time is the deletion time).  Destroyed
records from before the cutoff are ignored.  Any other record is *live*.

A GUID with a live record anywhere is never restored.

As a side effect, `$restored` is removed from every record, so only the
latest restore is marked.  A mailbox also drops the flag from its flag list
if nothing was restored at all.

### Choosing what to restore

- **Non-drafts** (grouped by GUID): every copy removed at the latest removal
  time is restored, so an Email in several mailboxes comes back to all of
  them, but an Email moved between mailboxes comes back only where it was
  last.

- **Drafts** (grouped by Message-ID): nothing is restored if any live
  message, or any destroyed non-draft, has the same Message-ID, since the
  draft was either still open or has been sent.  Otherwise, of the five most
  recently removed versions without a live copy, the largest is restored.

- **Memos** (non-drafts with `$memo`, grouped by the Message-ID in their
  In-Reply-To): handled after all other mail is restored, so a restored
  parent counts as existing.  Nothing is restored if a memo for the same
  parent is live, or if no live message has the parent's Message-ID.
  Otherwise the most recently removed memo is restored, the newest one
  breaking a tie, and `$hasmemo` is set on every live copy of the parent.
  On a dry run, a memo whose parent would itself be restored is not counted.

Message-IDs and In-Reply-To values are compared by their first msg-id, as
parsed by `message_iter_msgid()`.

### Restoring

Restores are applied mailbox by mailbox, in UID order, by appending each
record's file as a new record with its flags minus `\Deleted`, plus
`$restored`, and with its shared and private annotations.  The annotator is
not run.

A record from a deleted mailbox is restored into the live mailbox of the
same name, which is created if needed, along with any missing ancestors,
and given the deleted mailbox's special-use.  The deleted mailbox itself is
left for `cyr_expire`.

Mailbox locks are released every 512 records so that the user can keep
working during a long restore.
