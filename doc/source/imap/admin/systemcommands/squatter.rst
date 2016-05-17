.. _imap-admin-systemcommands-squatter:

============
**squatter**
============

Create SQUAT indexes for mailboxes

Synopsis
========

.. parsed-literal::

    **squatter** [ **-C** *config-file* ] [ **-r** ] [ **-s** ] [ **-i** ] [ **-a** ] [ **-v** ] *mailbox*...
    **squatter** [ **-C** *config-file* ] [ **-r** ] [ **-s** ] [ **-i** ] [ **-a** ] [ **-v** ]  **-u** *user*...
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-s** ] [ **-d** ] [ **-n** *channel* ] **-R**
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-s** ] **-f** *synclogfile*


Description
===========

**squatter** creates a new text index for one or more IMAP mailboxes.
The index is a unified index of all of the header and body text
of each message in a given mailbox.  This index is used to significantly
reduce IMAP SEARCH times on a mailbox.

.. Note::
    The name **squatter** is a historical (pre v3) relic from the days
    when the only indexing engine supported by Cyrus was SQUAT.  Post v3
    the *search_engine* setting in *imapd.conf* determines which
    search engine is used.

By default, **squatter** creates  an index of ALL messages in the
mailbox, not just those since the last time that it was run.  The
**-i** option is used to select incremental updates.  Any messages
appended to the mailbox after **squatter** is run, will NOT be included
in the index.  To include new messages in the index, **squatter** must
be run again.

In the first synopsis, **squatter** recursively indexes the specified
mailbox(es), incrementally updating indexes.

In the second synopsis, **squatter** recurses from the specified user(s),
rather than from specified mailbox(es).

In the third synopsis, **squatter** runs in rolling mode.  In this mode
**squatter** backgrounds itself and runs as a daemon, listening to a
sync log channel (chosen using **-n** option, and set up using the
*sync_log_channels* setting in :cyrusman:`imapd.conf(5)`).  Very soon
after messages are delivered or uploaded to mailboxes **squatter** will
incrementally index the affected mailbox.

In the fourth synopsis, **squatter** reads a single sync log file and
performs incremental indexing on the mailboxes listed therein.  This is
sometimes useful for cleaning up after problems with rolling mode.

.. Note::
    Incremental updates are very inefficient with the SQUAT search
    engine.  If using SQUAT for large and active mailboxes, you should
    run **squatter** periodically as an EVENT in ``cyrus.conf(5)``.
    Incremental updates are much more efficient with Sphinx, so if using
    Sphinx you should run **squatter -R** as a START in
    ``cyrus.conf(5)``.

.. Note::
    Messages and mailboxes that have not been indexed CAN still be
    SEARCHed, just not as quickly as those with an index.  Also,
    some advanced features of Sphinx like stemming will not work unless
    messages have been indexed.

**squatter** |default-conf-text|

Options
=======

.. program:: squatter

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -R

    Run in rolling mode; **squatter** runs as a daemon listening to a
    sync log channel and continuously incrementally indexing mailboxes.
    See also **-d** and **-n**.
    |v3-new-feature|

.. option:: -S seconds

    After processing each mailbox, sleep for "seconds" before continuing.
    Can be used to provide some load balancing.  Accepts fractional amounts.
    |v3-new-feature|

.. option:: -T directory

    When indexing, work on a temporary copy of the search engine databases
    in *directory*.  That directory would typically be on some very
    fast filesystem, like an SSD or tmpfs.  This option may not work with all
    search engines, but it's only effect is to speed up initial indexing.
    |v3-new-feature|

.. option:: -u

    Extra options refer to usernames (e.g. foo@bar.com) rather than
    mailbox names.
    |v3-new-feature|

.. option:: -d

    In rolling mode, don't background and do emit log messages on
    standard error.  Useful for debugging.
    |v3-new-feature|

.. option:: -f synclogfile

    Read the *synclogfile* and incrementally index all the mailboxes
    listed therein, then exit.
    |v3-new-feature|

.. option:: -n channel

    In rolling mode, specify the name of the sync log *channel* that
    **squatter** will listen to.  The default is "squatter".
    |v3-new-feature|

.. option:: -o

    In compact mode, if only one source database is selected, just copy
    it to the destination rather than compacting.
    |v3-new-feature|

.. option:: -F

    In compact mode, filter the resulting database to only include
    messages which are not expunged in mailboxes with existing
    name/uidvalidity.
    |v3-new-feature|

.. option:: -A

    In compact mode, audit the resulting database to ensure that every
    non-expunged message in all the user's mailboxes which is specified
    by cyrus.indexed.db is present in the xapian database.
    |v3-new-feature|

.. option:: -r

    Recursively create indexes for all sub-mailboxes of the mailboxes or
    mailbox prefixes given as arguments.

.. option:: -s

    Skip mailboxes whose index file is older than their current squat
    file (within a small time delta).

.. option:: -i

    Incremental updates where indexes already exist.

.. option:: -a

    Only create indexes for mailboxes which have the shared
    */vendor/cmu/cyrus-imapd/squat* annotation set to "true".

    The value of the */vendor/cmu/cyrus-imapd/squat* annotation is
    inherited by all children of the given mailbox, so an entire
    mailbox tree can be indexed (or not indexed) by setting a single
    annotation on the root of that tree with a value of "true" (or
    "false").  If a mailbox does not have a
    */vendor/cmu/cyrus-imapd/squat* annotation set on it (or does not
    inherit one), then the mailbox is not indexed. In other words, the
    implicit value of */vendor/cmu/cyrus-imapd/squat* is "false".

.. option:: -v

    Increase the verbosity of progress/status messages.

Examples
========

Sample entries from the EVENTS section of :cyrusman:`cyrus.conf(5)` for
periodic **squatter** runs:

    ::

        # reindex changed mailboxes (fulltext) approximately every three hours
        squatter1	cmd="/usr/bin/ionice -c idle /usr/lib/cyrus/bin/squatter -s" period=180

        # reindex all mailboxes (fulltext) daily
        squattera	cmd="/usr/lib/cyrus/bin/squatter" at=0117

[NB: More examples needed]

History
=======

Support for additional search enginges was added in version 3.0.

The following command-line switches were added in version 3.0:

    .. parsed-literal::

        **-R -u -d -O -F -A**

The following command-line settings were added in version 3.0:

    .. parsed-literal::

        **-S** *<seconds>*, **-T** *<directory>*, **-f** *<synclogfile>*, **-n** *<channel>*

Files
=====

/etc/imapd.conf,
/etc/cyrus.conf

See Also
========

:cyrusman:`imapd.conf(5)`, :cyrusman:`cyrus.conf(5)`
