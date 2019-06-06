.. cyrusman:: squatter(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-squatter:

============
**squatter**
============

Create SQUAT and Xapian indexes for mailboxes

Synopsis
========

.. parsed-literal::

    general:
    **squatter** [ **-C** *config-file* ] [**mode**] [**options**] [**source**]

    i.e.:
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] [ **-S** *seconds* ]
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] [ **-i** ] [ **-N** *name* ] [ **-S** *seconds* ] [ **-r** ]  *mailbox*...
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] [ **-i** ] [ **-N** *name* ] [ **-S** *seconds* ] [ **-r** ]  **-u** *user*...
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] **-R** [ **-n** *channel* ] [ **-d** ] [ **-S** *seconds* ]
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] **-f** *synclogfile* [ **-S** *seconds* ]
    **squatter** [ **-C** *config-file* ] [ **-v** ] **-I** *file*
    **squatter** [ **-C** *config-file* ] [ **-v** ] **-t** *srctier(s)*... **-z** *desttier* [ **-F** ] [ **-T** *dir* ] [ **-X** ] [ **-o** ]  [ **-S** *seconds* ] [ **-u** *user*... ]



Description
===========

.. Note::
    The name "**squatter**" once referred both to the SQUAT indexing
    engine and to the command used to create indexes.  Now that Cyrus
    supports more than one index type -- SQUAT and Xapian, as of this
    writing -- the name "**squatter**" refers to the command used to
    control index creation.  The terms "SQUAT" or "SQUAT index(es)"
    refers to the indexes used by the older SQUAT indexing engine.
    Post v3 the *search_engine* setting in *imapd.conf* determines
    which search engine is used.

**squatter** creates a new text index for one or more IMAP mailboxes.
The index is a unified index of all of the header and body text
of each message in a given mailbox.  This index is used to significantly
reduce IMAP SEARCH times on a mailbox.

**mode** is one of indexer, indexfrom (-I), search, rolling, synclog or compact.

By default, **squatter** creates an index of ALL messages in the
mailbox, not just those since the last time that it was run.  The
**-i** option is used to select incremental updates.  Any messages
appended to the mailbox after **squatter** is run, will NOT be included
in the index.  To include new messages in the index, **squatter** must
be run again, or on a regular basis via crontab, an entry in the EVENTS
section of :cyrusman:`cyrus.conf(5)` or use *rolling* mode (**-R**).

In the first synopsis, **squatter** indexes all mailboxes.

In the second synopsis, **squatter** indexes the specified mailbox(es).
The mailboxes are space-separated.

In the third synopsis, **squatter** indexes the specified user(s)
mailbox(es).

For the latter two index modes (mailbox, user) one
may optionally specify **-r** to recurse from the specified start, or
**-a** to limit action only to mailboxes which have the shared
*/vendor/cmu/cyrus-imapd/squat* annotation set to "true".

In the fourth synopsis, **squatter** runs in rolling mode.  In this
mode **squatter** backgrounds itself and runs as a daemon (unless
**-d** is set), listening to a sync log channel chosen using the **-n**
option, and set up using the *sync_log_channels* setting in
:cyrusman:`imapd.conf(5)`.  Very soon after messages are delivered or
uploaded to mailboxes **squatter** will incrementally index the
affected mailbox (see notes, below).

In the fifth synopsis, **squatter** reads a single sync log file and
performs incremental indexing on the mailbox(es) listed therein.  This
is sometimes useful for cleaning up after problems with rolling mode.

In the sixth synopsis, **squatter** reads *file* containing *mailbox*
*uid* tuples and performs indexing on the specified messages.

In the seventh synopsis, **squatter** will compact indices from
*srctier(s)* to *desttier*, optionally reindexing (**-X**) or filtering
expunged records (**-F**) in the process.  The optional **-T** flag may
be used to specify a directory to use for temporary files.  The **-o**
flag may be used to direct that a single index be copied, rather than
compacted, from *srctier* to *desttier*.  The **-u** flag may be used
to restrict operation to the specified user(s).

For all modes, the **-S** option may be specified, causing squatter to
pause *seconds* seconds after each mailbox, to smooth loads.

.. Note::
    Incremental updates are very inefficient with the SQUAT search
    engine.  If using SQUAT for large and active mailboxes, you should
    run **squatter** periodically as an EVENT in ``cyrus.conf(5)``.

.. Note::
    Messages and mailboxes that have not been indexed CAN still be
    SEARCHed, just not as quickly as those with an index.

**squatter** |default-conf-text|

Options
=======

.. program:: squatter

.. option:: -C config-file

    |cli-dash-c-text|

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

.. option:: -d

    In rolling mode, don't background and do emit log messages on
    standard error.  Useful for debugging.
    |v3-new-feature|

.. option:: -F

    In compact mode, filter the resulting database to only include
    messages which are not expunged in mailboxes with existing
    name/uidvalidity.
    |v3-new-feature|

.. option:: -f synclogfile

    Read the *synclogfile* and incrementally index all the mailboxes
    listed therein, then exit.
    |v3-new-feature|

.. option:: -h

    Display this usage information.

.. option:: -I file

    Read from *file* and index individual messages described by
    mailbox/uid tuples contained therein.

.. option:: -i

    Incremental updates where indexes already exist.

.. option:: -N name

    Only index mailboxes beginning with *name* while iterating through
    the mailbox list derived from other options.

.. option:: -n channel

    In rolling mode, specify the name of the sync log *channel* that
    **squatter** will listen to.  The default is "squatter".  This
    channel **must** be defined in :cyrusman:`imapd.conf(5)` before
    being used.
    |v3-new-feature|

.. option:: -o

    In compact mode, if only one source database is selected, just copy
    it to the destination rather than compacting.
    |v3-new-feature|

.. option:: -R

    Run in rolling mode; **squatter** runs as a daemon listening to a
    sync log channel and continuously incrementally indexing mailboxes.
    See also **-d** and **-n**.
    |v3-new-feature|

.. option:: -r

    Recursively create indexes for all sub-mailboxes of the user,
    mailboxes or mailbox prefixes given as arguments.

.. option:: -S seconds

    After processing each mailbox, sleep for "seconds" before
    continuing. Can be used to provide some load balancing.  Accepts
    fractional amounts. |v3-new-feature|

.. option:: -T directory

    When indexing, work on a temporary copy of the search engine
    databases in *directory*.  That directory would typically be on
    some very fast filesystem, like an SSD or tmpfs.  This option may
    not work with all search engines, but it's only effect is to speed
    up initial indexing.
    Xapian only.
    |v3-new-feature|

.. option:: -t srctier...

    In compact mode, the comma separated source tier(s) for the compacted
    indices.  At least one source tier must be specified in compact mode.
    Xapian only.
    |v3-new-feature|

.. option:: -u

    Extra options refer to usernames (e.g. foo@bar.com) rather than
    mailbox names.  Usernames are space-separated.
    |v3-new-feature|

.. option:: -v

    Increase the verbosity of progress/status messages.  Sometimes additional messages
    are emitted on the terminal with this option and the messages are unconditionally sent
    to syslog.  Sometimes messages are sent to syslog, only if -v is provided.  In rolling and
    synclog modes, -vv sends even more messages to syslog.

.. option:: -X

    Reindex all the messages before compacting.  This mode reads all
    the lists of messages indexed by the listed tiers, and re-indexes
    them into a temporary database before compacting that into place.
    Xapian only.
    |v3-new-feature|

.. option:: -z desttier

    In compact mode, the destination tier for the compacted indices.
    This must be specified in compact mode.
    Xapian only.
    |v3-new-feature|

Examples
========

**squatter** is typically deployed via entries in
:cyrusman:`cyrus.conf(5)`, in either the DAEMON or EVENTS sections.

For the older SQUAT search engine, which offers poor performance in
rolling mode (-R) we recommend triggering periodic runs via entries in
the EVENTS section, as follows:

Sample entries from the EVENTS section of :cyrusman:`cyrus.conf(5)` for
periodic **squatter** runs:

    ::

        EVENTS {
            # reindex changed mailboxes (fulltext) approximately every three hours
            squatter1   cmd="/usr/bin/ionice -c idle /usr/lib/cyrus/bin/squatter -i" period=180

            # reindex all mailboxes (fulltext) daily
            squattera   cmd="/usr/lib/cyrus/bin/squatter" at=0117
        }

For the newer Xapian search engine, and with sufficiently fast storage,
the rolling mode (-R) offers advantages.  Use of rolling mode requires
that **squatter** be invoked in the DAEMON section.

Sample entries for the DAEMON section of :cyrusman:`cyrus.conf(5)` for
rolling **squatter** operation:

    ::

        DAEMON {
          # run a rolling squatter using the default sync_log channel "squatter"
          squatter cmd="squatter -R"

          # run a rolling squatter using a specific sync_log channel
          squatter cmd="squatter -R -n indexer"
        }

..  Note::

    When using the *-R* rolling mode, you MUST enable sync_log
    operation in :cyrusman:`imapd.conf(5)` via the `sync_log: on`
    setting, and MUST define a sync_log channel via the
    `sync_log_channels:` setting.  If also using replication, you must
    either explicitly specify your replication sync_log channel via the
    `sync_log_channels` directive with a name, or specify the default
    empty name with "" (the two-character string U+22 U+22).  [Please
    see :cyrusman:`imapd.conf(5)` for details].

..  Note::

    When configuring rolling search indexing on a **replica**, one must
    consider whether sync_logs will be written at all.  In this case,
    please consider the setting `sync_log_unsuppressable_channels` to
    ensure that the sync_log channel upon which one's squatter instance
    depends will continue to be written.  See :cyrusman:`imapd.conf(5)`
    for details.

..  Note::

    When using the Xapian search engine, you must define various
    settings in :cyrusman:`imapd.conf(5)`.  Please read all relevant
    Xapian documentation in this release before using Xapian.

[NB: More examples needed]

History
=======

Support for additional search engines was added in version 3.0.

The following command-line switches were added in version 3.0:

    .. parsed-literal::

        **-F -R -X -d -f -o -u**

The following command-line settings were added in version 3.0:

    .. parsed-literal::

        **-S** *<seconds>*, **-T** *<directory>*, **-f** *<synclogfile>*, **-n** *<channel>*, **-t** *srctier*..., **-z** *desttier*

Files
=====

/etc/imapd.conf,
/etc/cyrus.conf

See Also
========

:cyrusman:`imapd.conf(5)`, :cyrusman:`cyrus.conf(5)`
