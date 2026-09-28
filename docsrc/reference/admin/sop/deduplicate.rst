.. _deduplicating-spool:

Deduplicating the Mail Spool
============================

When messages with identical content end up in the spool as distinct
inodes (typically after a user-by-user migration that bypasses
``singleinstancestore``, or after a restore that imported each mailbox
tree separately, or you are just enabling ``singleinstancestore``), 
the disk usage of the affected partition grows
beyond what the message count would suggest. The
:cyrusman:`deduplicate(8)` utility scans every mailbox index,
identifies record files that share a Cyrus GUID (the SHA-1 of the
message content), and hardlinks them onto a single inode per
filesystem.

It is the offline complement to the inline ``singleinstancestore``
option: that option avoids creating duplicates at delivery time,
while ``deduplicate`` collapses duplicates that already exist.

Workflow
--------

``deduplicate`` runs in two phases against the same database file.

1. **Build phase.**  Scan every mailbox index and record one entry per
   distinct spool file into a Cyrus key/value database (default
   backend: ``twoskip``). This phase only reads the spool::

       cyrus $ deduplicate -B -f /var/lib/cyrus/dedup.db

   To scan a subset, pass mailbox patterns as arguments::

       cyrus $ deduplicate -B -f /var/lib/cyrus/dedup.db user.alice.*

   The build refuses to overwrite an existing database file. Remove
   the file first for a clean rebuild.

2. **Dry run, then link phase.**  Inspect what would be linked, then
   commit::

       cyrus $ deduplicate -L -f /var/lib/cyrus/dedup.db -d -c -v
       would link /var/spool/imap/b/user/bob/1. -> /var/spool/imap/a/user/alice/3.
       ...
       1048576 bytes would be saved by hardlinking
       1 inodes would be freed by hardlinking

       cyrus $ deduplicate -L -f /var/lib/cyrus/dedup.db -c -v
       link /var/spool/imap/b/user/bob/1. -> /var/spool/imap/a/user/alice/3.
       ...
       1048576 bytes saved by hardlinking
       1 inodes freed by hardlinking

   The link phase exits non-zero if any copy could not be relinked
   for reasons other than expected staleness (a file or mailbox that
   vanished between build and link). Inspect standard error before
   re-running.

   The byte count from **-c** is a sum of exact file sizes, not a
   disk-usage measurement: storage allocates space in fixed-size
   units, and most files do not land exactly on that boundary, so the
   space actually freed (e.g. as seen in ``df`` before and after) is
   usually somewhat higher than the number reported here.

Scheduling
----------

The link phase acquires the destination mailbox's write lock
while it replaces each spool file, so any long-running deliver,
expunge, or reconstruct on that mailbox will delay the link. Schedule
``deduplicate -L`` during low-traffic periods.

Re-running ``deduplicate -L`` against an already-deduplicated tree is
a no-op (records already sharing the surviving inode are skipped), so
it is safe to re-run after an interrupted pass.

Caveats
-------

* Hardlinks cannot cross filesystems. Duplicates spread across
  separate partitions cannot be collapsed by this tool.
* When a duplicate is collapsed onto the survivor's inode, the
  resulting directory entry inherits the survivor's ownership,
  permissions, and timestamps. Cyrus deployments conventionally
  store every spool file under one ``cyrus`` UID with mode 0600 so
  this is normally invisible. Custom layouts should verify.
* If the link phase is killed partway, a temporary file named
  ``<path>.dedup`` may be left behind in the affected spool
  directory. It is a hardlink of the canonical copy, so it occupies
  no additional space. It is removed automatically if a later run
  relinks the same message, and is safe to remove by hand.

See Also
--------

* :cyrusman:`deduplicate(8)` for the full option reference.
