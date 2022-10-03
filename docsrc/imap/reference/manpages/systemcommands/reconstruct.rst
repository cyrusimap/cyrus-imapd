.. cyrusman:: reconstruct(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-reconstruct:

===============
**reconstruct**
===============

Reconstruct mailboxes

Synopsis
========

.. parsed-literal::

    **reconstruct** [ **-C** *config-file* ] [ **-p** *partition* ] [ **-x** ] [ **-r** ]
        [ **-f** ] [ **-U** ] [ **-s** ] [ **-q** ] [ **-G** ] [ **-R** ] [ **-o** ]
        [ **-O** ] [ **-M** ] *mailbox*...

    **reconstruct** [ **-C** *config-file* ] [ **-p** *partition* ] [ **-x** ] [ **-r** ]
        [ **-f** ] [ **-U** ] [ **-s** ] [ **-q** ] [ **-G** ] [ **-R** ] [ **-o** ]
        [ **-O** ] [ **-M** ] **-u** *user*...

    **reconstruct** [ **-C** *config-file* ] [ **-p** *partition* ] [ **-r** ]
        [ **-q** ] **-V** *version* *mailbox*...

    **reconstruct** [ **-C** *config-file* ] [ **-p** *partition* ] [ **-r** ]
        [ **-q** ] **-V** *version* **-u** *user*...

    **reconstruct** [ **-C** *config-file* ] **-P** *cyrus-header-paths*...

Description
===========

**reconstruct** rebuilds one or more IMAP mailboxes.  It can be
used to recover from almost any sort of data corruption.

If **reconstruct** can find existing header and index files, it
attempts to preserve any data in them that is not derivable from the
message files themselves. The state **reconstruct** attempts to
preserve includes the flag names, flag state, and internaldate.

**reconstruct** derives all other information from the message files.

**reconstruct** |default-conf-text|  Any mailbox directory underneath
the path specified in the ``partition-news`` configuration option is
assumed to be in news format.

**reconstruct** does not adjust the quota usage recorded in any quota
root files.  After running **reconstruct**, it is advisable to run
:manpage:`quota(8)` with the **-f** switch in order to fix the quota
root files.

When upgrading versions of Cyrus software, it may be necessary to run
**reconstruct** with the **-V** option, to rebuild indexes to a
given version (or *max* for the most recent).  Note that the **-V**
option cannot be combined with most other reconstruct options.  If
a mailbox needs reconstructing you should do that first, and then
upgrade it with **-V** once it's good.

Options
=======

.. program:: reconstruct

.. option:: -C  config-file

    |cli-dash-c-text|

.. option:: -p  partition

    Search for the listed (non-existant) mailboxes on the indicated
    *partition*. Create the mailboxes in the database in addition to
    reconstructing them. (not compatible with the use of wildcards)

.. option:: -x

    When processing a mailbox which is not in the mailbox list (e.g.
    via the **-p** or **-f** options), do not import the metadata from
    the mailbox, instead create it anew (this specifically affects at
    least the mailbox's seen state unique identifier, user flags, and
    ACL).

.. option:: -r

    Recursively reconstruct all sub-mailboxes of the mailboxes or
    mailbox prefixes given as arguments.

.. option:: -f

    Examine the filesystem underneath mailbox, adding all directories
    with a ``cyrus.header`` found there as new mailboxes.  Useful for
    restoring mailboxes from backups.

.. option:: -s

    Don't stat underlying files.  This makes reconstruct run faster, at
    the expense of not noticing some issues (like zero byte files or
    size mismatches).  "**reconstruct -s**" should be quite fast.

.. option:: -q

    Emit less verbose information to syslog.

.. option:: -n

    Don't make any changes.  Problems are reported, but not fixed.

.. option:: -G

    Force re-parsing of the underlying message (checks GUID
    correctness). Reconstruct with -G should fix all possible
    individual message issues, including corrupted data files.

.. option:: -I

    If two mailboxes exist with the same UNIQUEID and reconstruct visits
    both of them, -I will cause the second mailbox to have a new UNIQUEID
    created for it.  If you don't specify -I, you will just get a syslog
    entry telling you of the clash.

.. option:: -R

    Perform a UID upgrade operation on GUID mismatch files.  Use this
    option if you think your index is corrupted rather than your
    message files, or if all backup attempts have failed and you're
    happy to be served the missing files.

.. option:: -U

    Use this option if you have corrupt message files in your spool and
    have been unable to restore them from backup.  This will make the
    mailbox IOERROR free and fix replication.

    WARNING:
    this deletes corrupt message files for ever - so make sure you've
    exhausted other options first!

.. option:: -o

    Ignore odd files in your mailbox disk directories.  Probably useful
    if you are using some tool which adds additional tracking files.

.. option:: -O

    Delete odd files.  This is the opposite of **-o**.

.. option:: -M

    Prefer mailboxes.db over cyrus.header - will rewrite ACL or
    uniqueid from the mailboxes.db into the header file rather than the
    other way around.  |v3-new-feature|

.. option:: -V version

    Change the ``cyrus.index`` minor version to a specific *version*.
    This can be useful for upgrades or downgrades. Use a magical
    version of *max* to upgrade to the latest available database format
    version.

.. option:: -u

    Instead of mailbox prefixes, give usernames on the command line

.. option:: -P

    Instead of mailbox prefixes, give paths to cyrus.header files on
    the command line.  The paths can be mailbox directories, or
    explicit cyrus.header filenames.
    This will ONLY create/repair mailboxes.db records using data in
    cyrus.header and cyrus.index.

Examples
========

.. parsed-literal::

    **reconstruct -r -f** *tech.support*

..

        Recursively reconstruct all mailboxes within the *tech.support*
        hierarchy, restoring any directories containing ``cyrus.header``
        files.

.. only:: html

    ::

        tech.support uid 9634 rediscovered - appending
        tech.support uid 9635 rediscovered - appending
        tech.support uid 9642 rediscovered - appending
        tech.support
        tech.support.Archive
        tech.support.Spam


.. parsed-literal::

    **reconstruct -r -f** *tech.support.Archive.2%*
..

        Recursively reconstruct all mailboxes within the
        *tech.support.Archive* hierarchy with names beginning with '2',
        restoring any directories containing ``cyrus.header``
        files.

.. only:: html

    ::

        tech.support.Archive.2001
        tech.support.Archive.2002
        tech.support.Archive.2003
        tech.support.Archive.2004
        tech.support.Archive.2005
        tech.support.Archive.2006
        tech.support.Archive.2007
        tech.support.Archive.2008
        tech.support.Archive.2009
        tech.support.Archive.2010
        tech.support.Archive.2011
        tech.support.Archive.2012
        tech.support.Archive.2013

.. parsed-literal::

    **reconstruct -r -f -u** *jsmith*

..

        Recursively reconstruct all mailboxes belonging to *jsmith*,
        restoring any directories containing ``cyrus.header`` files.

.. only:: html

    ::

        user.jsmith
        user.jsmith.Archive
        user.jsmith.Drafts
        user.jsmith.Lists
        user.jsmith.Outbox
        user.jsmith.Sent
        user.jsmith.Spam
        user.jsmith.Trash

History
=======

The options **-k** (keep flags) and **-g** (clear GUID) have been
deprecated in Cyrus version 2.4.

The **-u** and **-V** options were added in Cyrus version 2.5.

The **-M** option was added in Cyrus version 3.0.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
