.. cyrusman:: deduplicate(8)

.. _imap-reference-manpages-systemcommands-deduplicate:

===============
**deduplicate**
===============

Hardlink message spool files that share a Cyrus GUID

Synopsis
========

.. parsed-literal::

    **deduplicate** [ **-C** *config-file* ] [ **-D** *backend* ] **-B** **-f** *db* [ **-e** ] [ **-x** ] [ **-v**... ] [ **-p** *partition* ] [ *mailbox*... ]
    **deduplicate** [ **-C** *config-file* ] [ **-D** *backend* ] **-L** **-f** *db* [ **-c** ] [ **-d** ] [ **-V** ] [ **-v**... ]
    **deduplicate** [ **-C** *config-file* ] [ **-D** *backend* ] **-P** **-f** *db* [ **-d** ] [ **-v**... ]
    **deduplicate** [ **-C** *config-file* ] [ **-D** *backend* ] **-Z** **-f** *db*

Description
===========

**deduplicate** finds message spool files whose Cyrus GUID (the SHA-1
of the message content) is identical, and collapses the duplicate
copies into a single inode using hardlinks.

It complements the inline ``singleinstancestore`` option from
:cyrusman:`imapd.conf(5)` by recovering duplicates that arise *after*
delivery: independent deliveries of the same message to two users,
mailboxes imported from another host, partitions restored from
backup, or any case where the server-internal "link on copy"
mechanism could not see a common source file.

**deduplicate** runs in two phases so the expensive scan is paid
once and the destructive link pass can be inspected, dry-run, and
re-run without re-scanning:

#. **Build phase** (**-B**). Walk every mailbox index and write a
   per-GUID record into a Cyrus-format key/value database. This
   phase only reads from the spool.

#. **Link phase** (**-L**). Iterate the database and, for each
   GUID, replace the duplicate copies that live on the same
   filesystem with a single hardlinked inode. This phase modifies
   the spool.

In every mode the database file is named with the mandatory **-f**
option.

**deduplicate** |default-conf-text|

Options
=======

.. program:: deduplicate

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -f db, --filename=db

    The path of the deduplicate database. Required in every mode:
    build mode creates it, the other modes read (and, for prune,
    rewrite) it.

.. option:: -B, --build

    Build mode. Scan every mailbox index (or just *mailbox...* if
    arguments are given) and write a GUID-keyed skiplist to *db*.

.. option:: -L, --link

    Link mode. Read *db* and hardlink record files that share a
    GUID and live on the same filesystem.

.. option:: -P, --prune

    Prune mode. Drop singleton (one-record) GUID entries from *db*,
    since they have nothing to deduplicate against, and compact the
    database. Deletions are committed in batches, so an interrupted
    prune leaves a consistent, partially pruned database that is safe
    to re-run. With **-d** the entries that would be pruned are
    reported and nothing is changed.

.. option:: -Z, --dump

    Dump mode. Print *db* in human-readable form: the format version,
    the mailbox dictionary (id to uniqueid), and one line per record
    under each GUID (uid, mailbox id, and the resolved uniqueid). The
    on-disk records are packed binary, so this is the way to inspect a
    deduplicate database: :cyrusman:`cyr_dbtool(8)` shows only raw
    bytes.

.. option:: -D backend, --backend=backend

    The ``cyrusdb`` backend used to store the database. Defaults
    to ``twoskip``.

.. option:: -p partition, --partition=partition

    Build mode. Only scan mailboxes stored on this partition (as
    named by a ``partition-*`` option in :cyrusman:`imapd.conf(5)`),
    instead of every partition. Since hardlinks cannot cross
    filesystems, this is mainly useful to scope a scan to mailboxes
    that could actually be linked together, or to run separate scans
    per partition in parallel.

.. option:: -c, --count

    Link mode. After the link phase, print the number of bytes
    reclaimed and the number of inodes freed. An inode's data is
    freed only when its last link is collapsed away, so both counts
    reflect actual disk reclaimed, not the number of paths relinked.
    The byte count is the sum of exact file sizes, not allocated disk
    blocks. Storage has its own allocation unit, and few files land
    exactly on that boundary, so actual space freed on disk is
    typically a bit higher than the number reported here.

.. option:: -d, --dry-run

    Link mode. Report what would be hardlinked, applying the same
    verification and accounting logic as the live run, but make no
    changes to the filesystem. Combine with **-c** to preview the
    projected savings.

.. option:: -V, --verify

    Link mode. Before each link, read both files in full and verify
    they are byte-for-byte identical. Very slow, and unnecessary in
    practice: a matching GUID is enough unless you are guarding
    against hash collisions or on-disk corruption.

.. option:: -e, --skip-expunged

    Build mode. Skip expunged but not-yet-unlinked records. These are
    included by default: an expunged record still has a spool file on
    disk until :cyrusman:`cyr_expire(8)` unlinks it, so hardlinking it
    onto a live duplicate reclaims that space in the meantime (and is
    safe, since both names resolve to identical content until the unlink).
    Pass this flag to confine the scan to live records. Already-unlinked
    records have no file and are always skipped regardless.

.. option:: -v, --verbose

    Print per-record (build) or per-link / per-prune (link, prune)
    output. Quiet (errors only) by default. Once (**-v**) enables
    that output. In build mode, repeating it adds more detail:
    twice (**-vv**) adds the mailbox name and UID, three times
    (**-vvv**) also adds the ``st_dev:st_ino`` and hardlink count of
    the record's spool file, since the *(device id, inode)* pair uniquely
    identifies a file even across multi-filesystem deployments.

.. option:: -x, --skip-deleted

    Build mode. Skip the delayed-delete hierarchy (``DELETED.*``).
    These are ordinary mailboxes with real spool files, but
    :cyrusman:`cyr_expire(8)` purges them once ``delete_prune`` has
    elapsed, so hardlinking their files only reclaims space until that
    purge runs. Use this flag when ``delete_prune`` is short, to avoid
    churning on files that are about to be removed anyway. Omit it (the
    default) when ``delete_prune`` is long, so the duplicated space is
    reclaimed for the whole retention window. Collapsing a deleted
    copy onto a live one never endangers it, since both names resolve
    to identical content until **cyr_expire** removes one.

.. option:: -h, --help

    Print usage to standard output and exit successfully.

Notes
=====

**Database format.** The database keys are message GUIDs, and the
values are packed binary records naming every copy of that message
by mailbox and UID. The format is internal and versioned: the link,
dump and prune phases refuse a database written by an incompatible
version of the tool, and :cyrusman:`cyr_dbtool(8)` shows only raw
bytes, so use **-Z** to inspect a database. Spool paths are not
stored. The link phase resolves each record against the live
mailboxes list, so mailboxes renamed or moved between partitions
(and messages moved to an archive partition) between build and link
still resolve correctly. Copies that are already hardlinked
together are recorded normally and simply skipped at link time.

**Re-running -B over an existing database.** Build mode refuses to
overwrite an existing *db* and exits with an error. A build that
fails removes its own partial output, so a clean rerun is possible
immediately. A build killed outright (``SIGKILL``, power loss) may
leave a partial file behind, which every mode refuses to read.
Remove the file and rebuild.

**Resilience.** A mailbox that fails to open during the build phase
is logged and skipped. The scan continues with the remaining
mailboxes. Database errors are not skipped: they abort the build,
which removes its partial output. Remote, intermediate, and
deleted-tombstone entries in the mailboxes list carry no local spool
and are skipped silently. This is distinct from the **-x** flag,
which skips the delayed-delete (``DELETED.*``) hierarchy of real
mailboxes.

**Filesystem scope.** Hardlinks cannot cross filesystems. The link
phase groups the copies of each message by filesystem and operates
within each one independently. Duplicates spread across separate
partitions will not be collapsed.

**Permissions and timestamps.** When a duplicate is collapsed onto
the survivor's inode, the resulting directory entry inherits the
survivor's ownership, permissions, and timestamps. Cyrus deployments
conventionally store every spool file under a single ``cyrus`` UID
with mode 0600, so this is normally invisible, but custom layouts
should verify before running.

**Concurrency.** The build phase holds each mailbox's read lock only
long enough to scan its index. The database writes for that mailbox's
messages happen afterward, with no lock held, so a large mailbox does
not hold off delivery, expunge, or other writers for the whole scan.
The link phase holds the destination mailbox's
write lock (the same lock used by :cyrusman:`cyr_expire(8)` and
:cyrusman:`reconstruct(8)`) while it replaces a spool file, and the
replacement is atomic, so delivery, expunge, reconstruct or a second
**deduplicate** run cannot race it. An active imapd serving a FETCH
keeps reading its old inode (which has identical content), so there
is no client-visible disruption. Long-running operations on a
mailbox will block the link phase until they release their locks.
Schedule **deduplicate -L** during quiet periods.

**Interrupted runs.** If the link phase is killed partway, a
temporary file named ``<path>.dedup`` may be left behind in the
affected spool directory. It is a hardlink of the canonical copy,
so it occupies no additional space. It is removed automatically if a
later run relinks the same message, and is safe to remove by hand.

Exit Status
===========

In link mode, copies that disappeared between build and link (a file
already removed by :cyrusman:`cyr_expire(8)`, a deleted mailbox, a
message replaced or already relinked) are reported to standard error
but are expected on a live server and do not affect the exit status.
**deduplicate** exits non-zero if the database cannot be read or
validated, if the build cannot complete, or if any copy could not be
relinked for reasons other than such staleness.

Examples
========

.. parsed-literal::

    **deduplicate -B -f** */var/lib/cyrus/dedup.db*

..

        Build the skiplist over every mailbox using the default
        twoskip backend.

.. parsed-literal::

    **deduplicate -B -f** */var/lib/cyrus/dedup.db* *user.alice.\\**

..

        Build the skiplist over alice's mailbox tree only.

.. parsed-literal::

    **deduplicate -L -f** */var/lib/cyrus/dedup.db* **-d -c**

..

        Dry-run the link phase and print the disk space and inodes
        that would be reclaimed. Nothing is modified.

.. parsed-literal::

    **deduplicate -L -f** */var/lib/cyrus/dedup.db* **-c**

..

        Run the link phase and print only the total bytes and inodes
        reclaimed. Per-link output is already suppressed by default.

.. parsed-literal::

    **deduplicate -Z -f** */var/lib/cyrus/dedup.db*

..

        Inspect the contents of the database (version, mailbox
        dictionary and per-GUID records) before running the link
        phase.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`cyr_dbtool(8)`,
:cyrusman:`cyr_expire(8)`,
:cyrusman:`reconstruct(8)`,
:cyrusman:`mbexamine(8)`,
:cyrusman:`imapd.conf(5)`
