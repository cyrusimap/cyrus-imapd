.. cyrusman:: chk_cyrus(8)

.. author: Nic Bernstein (Onlight)
.. author: Jeroen van Meeuwen (Kolab Systems)

.. _imap-reference-manpages-systemcommands-chk_cyrus:

=============
**chk_cyrus**
=============

Perform a consistency check of the Cyrus IMAP mail spool.

Synopsis
========

.. parsed-literal::

    **chk_cyrus** [ **-C** *config-file* ] [ **-P** *partition* | **-M** *mailbox* ]

    **chk_cyrus** [ **-C** *config-file* ] **-l** *level* [ *audit-options* ]

Description
===========

**chk_cyrus** is used to perform a consistency check on the cyrus
datastore, and output a list of files/directories that are expected to
exist, but do not.  Status messages are output to stderr, the list of
files/directories is output to stdout.  This list can be passed to a
backup program to aid a partial restoration, for instance.

Given **-l**, **chk_cyrus** instead runs in *audit mode*, described
below.  Without **-l** its behaviour is exactly as it has always been, so
existing invocations are unaffected.

**chk_cyrus** |default-conf-text|

Audit mode
==========

Audit mode checks the consistency of ``mailboxes.db`` against itself,
against the mailbox directories on disk, and against the messages within
them.  It answers the question the rest of Cyrus does not: which
directories on disk have no database entry?

The **-l** level selects how much is checked, and how much it costs:

==== =========================================================
0    ``mailboxes.db`` keyspace only; no filesystem access
1    also database entries against the UUID directories on disk
2    also index record exists against data file exists
3    also file size matches the index record
4    also file GUID matches the index record
==== =========================================================

Level 0 touches no disk at all, which makes it cheap enough to run often.
Note that a repair (**--fix**) may still touch disk: assigning a missing
jmapid opens the mailbox, because the id is derived from its modseq.

Levels 0 and 1 are decidable from local state, and are where **--delete**
and **--fix** act.  Levels 2 to 4 concern message and meta files, where a
damaged file cannot be repaired from anything on this server, and where a
local resolution does exist :cyrusman:`reconstruct(8)` already owns it.
Those levels are therefore **report-only**, and combining them with
**--delete** or **--fix** is an error.

Nothing is modified without **--really**.  Directories and files newer
than ten minutes are never removed, since they may belong to an operation
still in flight.

Findings are printed one per line.  With **--json** each is a JSON object
with a stable ``code`` field, suitable for a driver to act on; absent
fields are omitted rather than emitted as null.  Findings reporting
damaged message files carry the mailbox, uid, and the GUID the index says
the file should have, which is what an external tool needs in order to
fetch a replacement from a replica or from backup.

Options
=======

.. program:: chk_cyrus

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -P partition, --partition=partition

    Limit to partition *partition*.  May not be specified with **-M**.

.. option:: -M mailbox, --mailbox=mailbox

    Only check mailbox *mailbox*.  May not be specified with **-P**.

    .. IMPORTANT::

        The mailbox must be specified in the internal format, so rather
        than specifying ``user/john/Trash@example.org``, you will want
        to specify ``example.org!user.john.Trash``.

.. option:: -l level, --level=level

    Run in audit mode at the given level, 0 to 4.  See `Audit mode`_.

.. option:: -j, --json

    Emit findings as JSON, one object per line, instead of text.

.. option:: -u userid, --user=userid

    Restrict the audit to a single user.

.. option:: --userlist=file

    Read the usernames expected on this server from *file*, one per line.

    This distinguishes a user whose INBOX has gone -- which needs a human,
    since an INBOX cannot be recreated in UUID space -- from folders left
    behind by a user who has moved away, which is routine cleanup.

    Without it, every user found in the database is assumed to belong
    here, so structural damage is still reported but removing a user is
    never proposed.  Removing a whole user is never done by **chk_cyrus**
    in any case: it rests entirely on external truth, so it is reported
    and left to :cyrusman:`sync_reset(8)`.

.. option:: --skip-user=userid

    Exclude a user from the audit.  May be given more than once.  Useful
    for users known to be mid-rename or mid-migration.

.. option:: -d, --delete

    Remove orphans that are decidable from local state: directories with
    no database entry, database keys with no directory, unrecognised keys,
    and J records that name no mailbox.  Only meaningful at level 0 or 1.

.. option:: -f, --fix

    Repair damage that is decidable from local state: a missing I record,
    and a missing or unassigned jmapid.  Only meaningful at level 0 or 1.
    May not be combined with **--delete**.

.. option:: -y, --really

    Actually make the changes.  Without it **--delete** and **--fix**
    report what they would do and change nothing.

.. option:: --prune-tombstones=days

    Remove tombstone records, and the matching name history, older than
    *days*.

    There is no default and no pruning happens without this option.  A
    tombstone removed before a replica has synchronised past it means that
    replica never learns the name is gone, so the safe threshold depends
    on your replication topology.

Examples
========

.. parsed-literal::

    **chk_cyrus -P** *default*

..

        Perform consistency checks on *default* partition.

.. parsed-literal::

    **chk_cyrus -C** */usr/local/etc/imapd-slot1.conf* **-P** *default*

..

        Perform consistency checks on *default* partition using specified
        configuration file.

.. parsed-literal::

    **chk_cyrus -M** *user.marysmith*

..

        Perform consistency checks on mailbox *user.marysmith*.

.. parsed-literal::

    **chk_cyrus -l** *0*

..

        Check the ``mailboxes.db`` keyspace for internal inconsistencies,
        without touching the filesystem.

.. parsed-literal::

    **chk_cyrus -l** *1* **--json**

..

        Also compare database entries against the mailbox directories on
        disk, reporting findings as JSON for another tool to act on.

.. parsed-literal::

    **chk_cyrus -l** *1* **--delete**

..

        Report what removing the orphans would do, without doing it.  Add
        **--really** to actually remove them.

See Also
========
:cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`,
:cyrusman:`reconstruct(8)`, :cyrusman:`ctl_mboxlist(8)`
