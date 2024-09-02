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
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] [ **-S** *seconds* ] [ **-Z** ]
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] [ **-i** ] [ **-N** *name* ] [ **-S** *seconds* ] [ **-r** ] [ **-Z** ] *mailbox*...
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] [ **-i** ] [ **-N** *name* ] [ **-S** *seconds* ] [ **-r** ] [ **-Z** ] **-u** *user*...
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] **-R** [ **-n** *channel* ] [ **-d** ] [ **-S** *seconds* ] [ **-Z** ]
    **squatter** [ **-C** *config-file* ] [ **-v** ] [ **-a** ] **-f** *synclogfile* [ **-S** *seconds* ] [ **-Z** ]
    **squatter** [ **-C** *config-file* ] [ **-v** ] **-t** *srctier(s)*... **-z** *desttier* [ **-B** ] [ **-F** ] [ **-U** ] [ **-T** *reindextiers* ] [ **-X** ] [ **-o** ] [ **-S** *seconds* ] [ **-u** *user*... ]



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

**mode** is one of indexer, search, rolling, synclog, compact or audit.

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

In the sixth synopsis, **squatter** will compact indices from
*srctier(s)* to *desttier*, optionally reindexing (**-X**) or filtering
expunged records (**-F**) in the process.  The optional **-T** flag may be
used to specify members of srctiers which must be reindexed.  These files are
eventually copied with `rsync -a` and then removed by `rm`.
`rsync` can increase the load average of the system, especially when the
temporary directory is on `tmpfs`.  To throttle `rsync` it is possible to
modify the call in `imap/search_xapian.c` and pass `-\\-bwlimit=<number>` as further
parameter.  The **-o** flag may be used to direct that a single index be
copied, rather than compacted, from *srctier* to *desttier*.  The **-u** flag
may be used to restrict operation to the specified user(s).

For all modes, the **-S** option may be specified, causing **squatter** to
pause *seconds* seconds after each mailbox, to smooth loads.

When using the Xapian engine the **-Z** option may be specified, for
the indexing modes.  This tells **squatter** to consult the Xapian
internally indexed GUIDs, rather than relying on what's stored in
`cyrus.indexed.db`, allowing for recovery from broken
`cyrus.indexed.db` at the sacrifice of efficiency.

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

.. option:: -a, --squat-annot

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

.. option:: -A, --audit

    Audits the specified mailboxes (or all), reports any unindexed messages.
    |master-new-feature|

.. option:: -d, --nodaemon

    In rolling mode, don't background and do emit log messages on
    standard error.  Useful for debugging.
    |v3-new-feature|

.. option:: -B, --skip-locked

    In compact mode, use non-blocking lock to start and skip any
    users who have their xapianactive file locked at the time (i.e
    another reindex task)
    |master-new-feature|

.. option:: -F, --filter

    In compact mode, filter the resulting database to only include
    messages which are not expunged in mailboxes with existing
    name/uidvalidity.
    |v3-new-feature|

.. option:: -f synclogfile, --synclog=synclogfile

    Read the *synclogfile* and incrementally index all the mailboxes
    listed therein, then exit.
    |v3-new-feature|

.. option:: -h, --help

    Display this usage information.

.. option:: -i, --incremental

    Incremental updates where indexes already exist.

.. option:: -N name, --name=name

    Only index mailboxes beginning with *name* while iterating through
    the mailbox list derived from other options.

.. option:: -n channel, --channel=channel

    In rolling mode, specify the name of the sync log *channel* that
    **squatter** will listen to.  The default is "squatter".  This
    channel **must** be defined in :cyrusman:`imapd.conf(5)` before
    being used.
    |v3-new-feature|

.. option:: -o, --copydb

    In compact mode, if only one source database is selected, just copy
    it to the destination rather than compacting.
    |v3-new-feature|

.. option:: -p, --allow-partials

    When indexing, allow messages to be partially indexed. This may
    occur if attachment indexing is enabled but indexing failed for
    one or more attachment body parts. If this flag is set, the
    message is partially indexed and squatter continues. Otherwise
    squatter aborts with an error. Also see **-P**.
    Xapian only.
    |master-new-feature|

 .. option:: -P, --reindex-partials

    When reindexing, then attempt to reindex any partially indexed
    messages (see **-p**). Setting this flag implies **-Z**.
    Xapian only.
    |master-new-feature|

 .. option:: -L, --reindex-minlevel=level

    When reindexing, index all messages that have an index level
    less than level. Currently, Cyrus only supports two index levels:
    A message for which attachment indexing was never attempted has
    index level 1. A message that has indexed attachments, or does not
    contain attachments, has index level 3. Consequently, running
    squatter with minlevel set to 3 will cause it to attempt reindexing
    all messages, for which attachment indexing never was attempted.
    Future Cyrus versions may introduce additional levels. Setting
    this flag implies **-Z**.
    Xapian only.
    |master-new-feature|

.. option:: -R, --rolling

    Run in rolling mode; **squatter** runs as a daemon listening to a
    sync log channel and continuously incrementally indexing mailboxes.
    See also **-d** and **-n**.
    |v3-new-feature|

.. option:: -r, --recursive

    Recursively create indexes for all sub-mailboxes of the user,
    mailboxes or mailbox prefixes given as arguments.

.. option:: -s delta, --squat-skip=delta

    Skip mailboxes that have not been modified since last index. This is
    achieved by comparing the last modification time of a mailbox to
    the last time the squat index of this mailbox got updated. If the
    mailbox modification time plus delta is less than the squat
    index modification time, then the mailbox is skipped. The argument
    value delta is defined in seconds and must be greater than or equal
    to zero. The historical default delta was 60, and this remains a
    good general choice, but for technical reasons it must now be
    specified explicitly.
    Squat only.

.. option:: -S seconds, --sleep=seconds

    After processing each mailbox, sleep for "seconds" before
    continuing. Can be used to provide some load balancing.  Accepts
    fractional amounts. |v3-new-feature|

.. option:: -T reindextiers, --reindex-tier=reindextiers

    In compact mode, a comma-separated subset of the source tiers
    (see **-t**) to be reindexed.  Similar to **-X** but allows
    limiting the tiers that will be reindexed.
    |v3-new-feature|

.. option:: -t srctiers, --srctier=srctiers

    In compact mode, the comma-separated source tier(s) for the compacted
    indices.  At least one source tier must be specified in compact mode.
    Xapian only.
    |v3-new-feature|

.. option:: -u name, --user=name

    Extra options refer to usernames (e.g. foo@bar.com) rather than
    mailbox names.  Usernames are space-separated.
    |v3-new-feature|

.. option:: -U, --only-upgrade

    In compact mode, only compact if re-indexing.
    Xapian only.
    |master-new-feature|

.. option:: -v, --verbose

    Increase the verbosity of progress/status messages.  Sometimes additional messages
    are emitted on the terminal with this option and the messages are unconditionally sent
    to syslog.  Sometimes messages are sent to syslog, only if -v is provided.  In rolling and
    synclog modes, -vv sends even more messages to syslog.

.. option:: -X, --reindex

    Reindex all the messages before compacting.  This mode reads all
    the lists of messages indexed by the listed tiers, and re-indexes
    them into a temporary database before compacting that into place.
    Xapian only.
    |v3-new-feature|

.. option:: -z desttier, --compact=desttier

    In compact mode, the destination tier for the compacted indices.
    This must be specified in compact mode.
    Xapian only.
    |v3-new-feature|

.. option:: -Z, --internalindex

    When indexing messages, use the Xapian internal cyrusid rather than
    referencing the ranges of already indexed messages to know if a
    particular message is indexed.  Useful if the ranges get out of
    sync with the actual messages (e.g. if files on a tier are lost)
    Xapian only.
    |master-new-feature|

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

.. only:: html

    :ref:`configuring-xapian`
