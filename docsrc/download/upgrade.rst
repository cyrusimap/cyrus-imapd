.. highlight:: none

.. _upgrade:

=================
Upgrading to 3.14
=================

.. note::

  This guide assumes that you are familiar and comfortable with administration
  of a Cyrus installation, and system administration in general.

  It assumes you are installing from source or tarball. If you want to install
  from package, use the upgrade instructions from the package provider.

..  contents:: Upgrading: an overview
    :local:

1. Preparation
--------------

Things to consider **before** you begin:

Versions to upgrade from
########################

Before upgrading to 3.14, your deployment should be running
**3.12.0 (or later)**

If your existing deployment is older than this, you should first upgrade
to 3.12, let it run for a while, resolve any issues that come up, and only
then upgrade to 3.14.

.. _upgrade_3.14_wont_start:

Configuration that 3.14 will not start with
###########################################

Check these settings before starting 3.14.  Make the changes while still
running 3.12 where possible.

Invalid configdirectory
~~~~~~~~~~~~~~~~~~~~~~~

:imapdconf:`configdirectory` must be an absolute path other than ``/``.

.. _upgrade_overlapping_partitions:

Overlapping partitions
~~~~~~~~~~~~~~~~~~~~~~

:cyrusman:`master(8)` will refuse to start if multiple partitions appear to be
identical or overlap.  (:issue:`5573`)  If you are configured this way, this
is already probably unsafe, and you should correct your configuration before
attempting to upgrade.

Removed event parameter
~~~~~~~~~~~~~~~~~~~~~~~

Remove ``vnd.fastmail.counters`` from :imapdconf:`event_extra_params`.  An
unknown value there is a fatal configuration error.  If your push consumers
need the per-type states, add ``vnd.fastmail.jmapStates``, which reports the
same information as a map of JMAP data type to state string.

Removed httpd modules
~~~~~~~~~~~~~~~~~~~~~

Remove ``ischedule``, ``domainkey``, ``rss`` and ``cgi`` from
:imapdconf:`httpmodules`, including service-specific overrides and any
alternate configuration files used by httpd.  iSchedule is now used only
between the backends of a Cyrus Murder, where it needs no configuration beyond
:imapdconf:`proxyservers`.

Removed services
~~~~~~~~~~~~~~~~

NNTP and fud have been removed.  Remove any ``SERVICES`` entries in
:cyrusman:`cyrus.conf(5)` that run ``fud`` or ``nntpd``.  Master refuses to
start if a configured service executable is missing.

Other configuration updates
###########################

Remove scheduled ``fetchnews`` jobs from the ``EVENTS`` section of
:cyrusman:`cyrus.conf(5)`.  A stale entry fails when the event runs.

Values stored in the ``/vendor/cmu/cyrus-imapd/news2mail`` annotation are
ignored.  If you want to remove them, do so under 3.12 with
``cyradm> mboxconfig <mailbox> news2mail ""``.

.. _objectstore_removal:

Objectstore
~~~~~~~~~~~

In the very unlikely event that you're using objectstore, you'll need to stop.
That probably means replicating to a new Cyrus install without objectstore
configured.  Our view is that this is so unlikely that we are not preparing
detailed instructions.  If you are in this situation, contact us on the
:ref:`mailing list <feedback-mailing-lists>`.

Deprecated options and changed defaults
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run ``cyr_info conf-lint`` (see step 5) to find options that are now
deprecated.  The :ref:`release notes <imap-release-notes-3.14>` list them.
None of them stops Cyrus from starting, but all of them are now ignored.

There's a new default :imapdconf:`tls_eccurve` list.  If you've got this
setting naming a single curve, you may wish to clear the setting and get the
list.  If you enable :imapdconf:`http_allow_0rtt`,
:imapdconf:`tls_session_timeout` must not be 0, and you may want
``tls_sessions_db: twom``, or :imapdconf:`tls_sessions_db_path` on a tmpfs.

URLAUTH has been removed.  Users' mboxkey databases can be deleted.

If you set :imapdconf:`replicaonly` on a server, clients that could previously
make local changes there (which then diverged from the master) now get errors
instead.

.. _upgrade_3.14_logging:

Logging
#######

Audit logging is now always on.  Sites that did not previously enable
``auditlog`` will see ``event=auditlog.*`` entries in syslog, many at "info".
Your logging volume will increase.  Make sure your logging setup is ready for
it, and consider limiting which syslog priorities are kept.

Login and audit log lines are now written as ``logfmt``.  Anything that parses
those lines will need updating.

.. _upgrade_3.14_first_start:

The first start
###############

The first time :cyrusman:`ctl_cyrusdb(8)` ``-r`` runs under 3.14, which is
normally in the ``START`` section of :cyrusman:`cyrus.conf(5)`, it scans
``mailboxes.db`` and opens local mailboxes whose entries lack a unique id or
JMAP mailbox id.  For each mailbox that needs a new JMAP id, it updates the
header and index as well as the database entry.

No 3.12 mailbox has a JMAP mailbox id, so on an upgrade from 3.12 this is
every local mailbox on the server.  You should expect that:

* The first start takes time in proportion to the number of mailboxes.  When
  run as a ``START`` command, the work finishes before services start.  Later
  starts are as quick as before.
* Creating a JMAP id raises the mailbox's modseq, so clients will see every
  mailbox as changed, and replication will pick up a change to every mailbox.
* Each new id is logged as ``ctl_cyrusdb.mailboxid.created``.

If you would rather watch this happen than wait on your init system, run
``ctl_cyrusdb -r`` by hand, as the ``cyrus`` user, before starting Cyrus.

If you replicate, upgrade the replica first and let it start before upgrading
the source server.  Recovery skips replica-only mailboxes.  They receive their
ids through replication after the source server creates them.

.. _upgrade_3.14_compact_ids:

Compact ids
###########

Nothing is required when upgrading.  But the new :imapdconf:`compact_ids`
option has a setting, ``always``, which will be the only behavior in the next
major release, so now is a good time to migrate.  For every user:

1. Upgrade all of their mailboxes to index version 20, with
   ``reconstruct -V max -u <userid>``.
2. Upgrade their conversations database, with
   ``ctl_conversationsdb -U <userid>``.
3. Enable compact ids, with ``ctl_conversationsdb -I on <userid>``.

Only when every user has been migrated, set ``compact_ids: always``.  After
that, compact ids cannot be turned off for any user.  Set it identically on
all servers that replicate to one another or that participate in the same
Murder.

Turning on compact ids changes a user's JMAP ids, so JMAP clients will need to
fetch their data again.

.. _upgrade_3.14_search:

Search indexes
##############

Existing Xapian indexes keep working.  You should consider rebuilding them
with :cyrusman:`squatter(8)` if any of these matter to you:

* Calendar events are now indexed under search parts of their own.  Events
  already indexed are indexed that way only once the index is rebuilt.
* :cyrusman:`squatter(8)` now records the highest createdmodseq it has
  indexed, which JMAP ``Email/queryChanges`` relies on.  An index that was
  fully built once and has been kept up to date by a rolling squatter needs
  nothing.  Other indexes may give inconsistent ``Email/queryChanges``
  results until they are rebuilt.
* The "category" comparator of ``Email/query`` needs an index of version 17 or
  later to group by ``messageId``, ``references`` or ``inReplyTo``.  3.12
  wrote version 17, so this concerns only indexes last built by an older
  version.  See also :ref:`upgrade_email_query_reindex`.

.. _upgrade_timezones:

Time zone data
##############

Cyrus now builds and installs its own time zone data.  An existing
:imapdconf:`zoneinfo_dir` setting still wins, and existing time zone data
keeps working.  The TZDist chapter of the CalDAV installation guide describes
how to switch to the data Cyrus installs.

Packagers: ``vzic`` is now a build-time dependency for the time zone data.  See
the same chapter of the installation guide, or configure with
``--without-vzic`` to keep shipping time zone data separately.

Replication
###########

If you use :imapdconf:`sync_cache_db_path`, a replica may be silently missing
users whose folders are all tombstoned in its ``mailboxes.db``.  Any whole-user
sync repairs such a user: run ``sync_client -u <user>`` or ``sync_client -A``.

Replication no longer deletes the wrong mailbox when a mailbox name has been
reused, but only once both ends have been upgraded.

.. _upgrade_3.14_freebusy:

Sharing and access control
##########################

Free/busy-only shares
~~~~~~~~~~~~~~~~~~~~~

Granting free/busy access to a calendar now also grants lookup, without which
the grant did nothing.  Existing free/busy-only shares keep the ACL they were
granted, which is still missing ``l``, so they carry on not working until
repaired.  Either re-share them, or add the lookup right anywhere ``9`` was
granted without it::

    cyradm> setaclmailbox user.example.#calendars.Default sharee +l

Sieve fileinto
~~~~~~~~~~~~~~

A Sieve script that files into a mailbox its owner doesn't own, whether
another user's or a shared mailbox, now needs the ``i`` (insert) right there.
``p`` (post) used to be enough.  Messages that lack the right are delivered
to the script owner's INBOX instead.  Grant ``i`` to the users who rely on
this.

Sieve script compilation
~~~~~~~~~~~~~~~~~~~~~~~~

Review Sieve scripts that use ``ihave`` or expand message text in ``notify``
templates before reinstalling them.  ``ihave`` now enables only the extensions
successfully tested, and templates that use ``$text[...]$`` must enable the
``body`` extension.

Special-use mailboxes
~~~~~~~~~~~~~~~~~~~~~

Existing special-use mailboxes that aren't direct children of a user's INBOX
keep their attributes, but a non-admin can only rename them to a direct child
of INBOX.  Move them up, or set :imapdconf:`allowspecialusesubfolder`.

Calendar privacy
~~~~~~~~~~~~~~~~

Cyrus no longer uses the ``X-JMAP-PRIVACY`` iCalendar property to determine
event privacy.  If you rely on it, migrate your iCalendar data to use
``CLASS`` before serving it with 3.14.

Tools and scripts
#################

* :cyrusman:`reconstruct(8)` no longer re-injects message files that are
  missing from the index but have a UID the mailbox has already handed out.
  Scripts that rely on that must add ``-k``.
* If you access users' mailboxes as an admin and set
  :imapdconf:`admins_get_internal_seen`, use ``EXAMINE`` or fetch message
  content with ``BODY.PEEK`` or ``BINARY.PEEK`` to preserve the owner's
  ``\Seen`` flags.
* If you act on AclChange events, you will start seeing them for sharing
  changes made over JMAP and DAV.  Their "user" field is empty.
* If you relied on an annotator callout processing appends to non-email
  mailboxes, you will need to find another solution.
* If you used ``XSTATS``, use the Prometheus metrics instead.
* ``installsieve`` is gone.  Use :cyrusman:`sieveshell(1)`.

.. _upgrade_3.14_clients:

Client-visible changes
######################

Review these changes for clients and integrations before upgrading the server.

IMAP and SASL:

* On TLS 1.3, the channel binding for -PLUS SASL mechanisms is now
  ``tls-exporter`` (:rfc:`9266`).  Clients that send ``tls-unique`` over
  TLS 1.3 will fail to authenticate with those mechanisms.  Clients that don't
  use channel binding are unaffected.
* Non-admin users must log in as ``user+dav`` to see or operate on calendars,
  address books and other non-email mailboxes over IMAP, including with the
  ``VENDOR.CMU-DAV`` LIST selection option.
* ``FETCH THREADID`` returns ``THREADID NIL`` for a message with no
  conversation, as :rfc:`8474` requires.  It used to return ``THREADID (NIL)``.
* Cyrus advertises IMAP PREVIEW and accepts ``FETCH PREVIEW`` only when
  :imapdconf:`jmap_preview_annot` is set and begins with ``/shared/``.
* Cyrus advertises SEARCH=FUZZY only when :imapdconf:`search_engine` is
  ``xapian``.  With other engines, Cyrus accepts and ignores the FUZZY search
  key, and :imapdconf:`search_fuzzy_always` has no effect.
* URLAUTH has been removed.

JMAP, all types:

* Every method call but ``Core/echo`` must carry an ``accountId``.
* ``/query`` and ``/queryChanges`` return ``total`` only when the request sets
  ``calculateTotal``.  These methods and ``SearchSnippet/get`` no longer
  echo the request's arguments, so a result reference to ``/filter`` no
  longer resolves.
* ``/set`` rejects an update that changes an immutable or server-set property
  with ``invalidProperties``.  Sending such a property with its current value
  is still allowed.
* Duplicate JSON member names are ``notJSON``; overlapping patch paths are
  ``invalidPatch``; a missing ``sinceState`` is ``invalidArguments``; and
  ``/copy`` reports ``fromAccountNotFound`` for an unusable ``fromAccountId``.
* Clients must stop sending the ``https://cyrusimap.org/ns/jmap/admin``
  capability.
* ``UserCounters/get`` is gone.  Use ``UserState/get``.
* The ``urn:ietf:params:jmap:blob`` capability reports ``maxSizeBlobSet`` in
  octets, not kilobytes, and ``maxDataSources`` is spelled that way.
  ``Blob/lookup`` returns ``unknownDataType`` for a type whose capability is
  not in ``using``.

JMAP Mail:

* ``shareWith`` on a Mailbox needs the ``urn:ietf:params:jmap:mail:share``
  capability, and its values are MailboxRights objects.  The ``mayRead``,
  ``mayWrite`` and ``mayAdmin`` rights are gone, and ``myRights`` no longer
  includes ``mayAdmin``.
* Setting ``shareWith`` on a Mailbox requires administrative access to it, or
  to its parent when creating one.
* The ``imageSize`` and ``isDeleted`` body properties, and SearchSnippet
  attachments, need ``https://cyrusimap.org/ns/jmap/mail`` in ``using``.
* ``Email/query`` keyword filters apply to the Email as a whole: "notKeyword"
  matches only if no copy of the Email has the keyword, and "hasKeyword"
  combined with "inMailbox" matches an Email whose flagged copy is in another
  mailbox.
* ``Email/query`` advertised a sort by "emailstate" that never worked.  It is
  spelled "emailState", and now works.
* A Mailbox created without a ``sortOrder`` gets 0, not 10.
* JMAP rejects mailbox names that Cyrus cannot represent.  Cyrus also
  validates domains and user IDs in mailbox names more strictly.
* An email can be moved into or out of the scheduled mailbox only by its
  EmailSubmission.  Other attempts are ``forbidden``.
* ``EmailSubmission/set`` returns ``invalidProperties`` for an unknown
  ``emailId``, and ``noRecipients`` for an empty ``rcptTo``.
* ``MDN/send`` requires ``identityId`` and an ``onSuccessUpdateEmail``
  argument that sets ``$mdnsent``, as :rfc:`9007` requires.
* The fallback identity for a user without a domain now uses
  ``userid@defaultdomain`` when :imapdconf:`defaultdomain` is set.  ``MDN/send``
  and ``SieveScript/test`` use the same address and now prefer
  ``defaultdomain`` to ``servername``.

JMAP Calendars and Contacts:

* JMAP for Calendars accepts only JSCalendar 2.0 names.  For example, on
  Calendar, use ``mayShare`` rather than ``mayAdmin``; on CalendarEvent, use
  ``iCalendar`` rather than ``cyrusimap.org:iCalProps``.
* ``CalendarEvent/query`` no longer accepts ``inCalendars``; use one or more
  ``inCalendar`` conditions, combined with an "OR" operator.
* ``CalendarEvent/get`` computes ``utcStart`` and ``utcEnd`` of floating
  events in Etc/UTC unless its new ``timeZone`` argument names another zone.
  It used the calendar's time zone.
* ``CalendarEvent/set`` rejects a ``recurrenceOverrides`` patch on a property
  that an override may not change, such as ``uid`` or ``recurrenceRule``.
  These were ignored.
* ``Calendar/set`` and ``AddressBook/set`` reject an empty name.
* ``ContactCard/set`` rejects a photo that is not an image, and members on a
  card whose kind is not "group".  Editing an existing card whose photo is not
  an image fails until the photo is replaced.
* ``ContactCard/set`` files a new card with no ``addressBookIds`` in the address
  book marked ``isDefault``.  dblookup uses that address book when the request
  does not name a mailbox.
* The legacy ``Contact/*`` and ``ContactGroup/*`` methods are gone.  Use
  ``ContactCard/*``.
* JMAP vCard blobIds issued by earlier versions are no longer accepted.

CalDAV and CardDAV:

* A scheduling CalDAV PUT no longer returns an ETag.
* xCal, the PATCH method, and the ``application/event+json`` media type are no
  longer supported.
* CalDAV ignores the ``Schedule-Sender-Address`` and ``Schedule-Sender-Name``
  request headers.
* A login as ``user+default`` shows the user's default calendar or address
  book, rather than the collection named "Default", if those differ.
* DELETE and MOVE need both the ``t`` and ``e`` rights.
* CardDAV refuses to delete the address book marked ``isDefault``.
* DAV rejects collection names that Cyrus cannot represent.

How are you planning on upgrading?
##################################

Ideally, you will do a sandboxed test installation of 3.14 using a snapshot
of your existing data before you switch off your existing installation.

Other possibilities are upgrading by replication, or upgrading in place.

**The rest of the instructions are written assuming a sandboxed 3.14
installation**, but you should read and understand them regardless of how
you intend to perform the upgrade.

Upgrade by replicating
~~~~~~~~~~~~~~~~~~~~~~

If you're familiar with replication, you can set up your existing installation
to replicate data to a new 3.14 installation and failover to the new
installation when you're ready. The replication protocol has been kept mostly
backwards compatible.

Upgrade in place
~~~~~~~~~~~~~~~~

If you are upgrading in place, you will need to shut down Cyrus entirely while
you install the new package.  You should probably also block logins or firewall
off internet access until you're completely finished so that you aren't
surprised by users reconnecting before the upgraded server is ready for them.

Run Cyrus maintenance commands as the ``cyrus`` user.  For example, run
``sudo -u cyrus cyr_info conf-lint -C /etc/imapd.conf -M /etc/cyrus.conf``.

2. Install new 3.14 Cyrus
-------------------------

Download the release :ref:`3.14 package tarball <getcyrus>`.

Cyrus 3.14 needs newer versions of some libraries than 3.12 did, and some that
were optional are now required:

* OpenSSL 3.0 or later
* libical 4.0.0 or later (or a compatible development snapshot reporting at
  least 3.99.99), libxml2, SQLite3 and ``xxd``, since HTTP and DAV support
  are now part of every build.  Drop the ``--enable-http`` and
  ``--enable-calalarmd`` configure options from build scripts.
* For Xapian search, Xapian 2.0.0 or later, or a recent 1.5.x snapshot, and a
  C++17 compiler.  Xapian 1.4 is no longer supported, although configure only
  rejects versions older than that.
* perl 5.28.0 or later, with the ``Moo`` and ``App::Cmd`` modules
* ``gperf``
* ``vzic``, to build the time zone data (see :ref:`upgrade_timezones`)

Your platform may not package versions this recent, in which case you will
need to build them yourself.

See :ref:`compiling` for the dependency list and Debian package names.

If you're on another platform and can provide the list of dependencies, please
let us know via a
`GitHub issue <https://github.com/cyrusimap/cyrus-imapd/issues>`_
or documentation pull request, or send mail to the
:ref:`developer list<feedback-mailing-lists>`.

Follow the :ref:`general install instructions <installing>`.

.. note::

    It's best to ensure your new Cyrus *will not* start up automatically
    if your server restarts in the middle of the upgrade.

    How this is best achieved will depend upon your OS and distro, but may
    involve something like ``systemctl disable cyrus-imapd`` or
    ``update-rc.d cyrus-imapd disable``

3. Shut down existing Cyrus
---------------------------

Shut down your existing Cyrus installation with its init script or
whatever method you normally use.

This is necessary to guarantee a clean data snapshot.

4. Backup and Copy existing data
--------------------------------

We recommend backing up all your data before continuing.

* Sieve scripts
* Config files
* Mail spool
* :ref:`Cyrus Databases <databases>`

Copy all of this to the new instance, using ``rsync`` or similar tools.

.. note::

    Cyrus keeps its data and databases in various locations, some of
    which may be tailored by your configuration.  Please consult
    :ref:`imap-admin-locations` for guidance on where data lives in your
    current installation.

For example, to copy from an existing Debian or Ubuntu installation
using their standard locations, you might execute this series of
commands on the *new* server (where "oldimap" is the name of the old
server)::

    rsync -aHv oldimap:/var/lib/cyrus/. /var/lib/cyrus/.
    rsync -aHv oldimap:/var/spool/cyrus/. /var/spool/cyrus/.

You don't need to copy the following databases as Cyrus 3.14 will
recreate these for you automatically:

* duplicate delivery (deliver.db),
* TLS cache (tls_sessions.db),
* PTS cache (ptscache.db),
* STATUS cache (statuscache.db).

.. note::
    You may wish to consider relocating these four databases to ephemeral
    storage, such as ``/run/cyrus`` (Debian/Ubuntu) or ``/var/run/cyrus``
    or whatever suitable tmpfs is provided on your distro.  It will place
    less IO load on your disks and run faster.

5. Copy config files and update
-------------------------------

Again, check the locations on your specific installation.  For example,
on FreeBSD systems, the configuration files :cyrusman:`imapd.conf(5)`
and :cyrusman:`cyrus.conf(5)` are in ``/usr/local/etc``, rather than
``/etc/``.  Run this command on the *old* server::

    scp /etc/cyrus.conf /etc/imapd.conf newimap:/etc/

Using the :cyrusman:`cyr_info(8)` command, check to see if your
imapd.conf file contains any deprecated options. Run this command on
the new server::

    cyr_info conf-lint -C <path to imapd.conf> -M <path to cyrus.conf>

You need to provide both imapd.conf and cyrus.conf so that conf-lint knows
the names of all your services and can check service-specific overrides.

To check your entire system's configuration you can use the conf-all
action. This command takes all the system defaults, along with anything
you have provided overrides for in your config files::

    cyr_info conf-all -C <path to imapd.conf> -M <path to cyrus.conf>

Add ``-s 3.12.0`` to highlight the options that are new, or whose behavior
has changed, since 3.12.

6. Upgrade specific items
-------------------------

If you have not already done so, check your configuration against
:ref:`upgrade_3.14_wont_start` and make the changes that apply to your site.

7. Start new 3.14 Cyrus and verify
----------------------------------

Start Cyrus using your regular service manager or init script.  Allow time for
:ref:`upgrade_3.14_first_start`, then check the service logs for errors and
verify that Cyrus 3.14 can access the migrated data before allowing client
traffic.

If something has gone wrong, contact us on the
:ref:`mailing list <feedback-mailing-lists>`.
You can revert to backups and keep processing mail using your old version
until you're able to finish your 3.14 installation.

.. note::

    If you've disabled your system startup scripts, as recommended in
    step 2, remember to re-enable them.  Use something like ``systemctl
    enable cyrus-imapd`` or ``update-rc.d cyrus-imapd enable``

8. Reconstruct databases and cache
----------------------------------

The following steps can each take a long time, so we recommend
running them one at a time (to reduce locking contention and high I/O load).

To upgrade all the mailboxes to the latest version, which is 20 in Cyrus 3.14.
This will take hours, possibly days.  Once a mailbox has been upgraded, 3.12
can no longer read it, so do this only when you are sure you won't be going
back.

::

    reconstruct -V max

To upgrade a user's conversations database to the latest version::

    ctl_conversationsdb -U <userid>

or, for every user::

    ctl_conversationsdb -U -r

DAV databases from 3.12 are migrated automatically when opened.
Use ``dav_reconstruct`` if you need to repair a DAV database from its mailbox
data.

If you suspect incorrect quota usage, recalculate it with::

    quota -f

If you use :imapdconf:`reverseacls` and see stale or missing entries for shared
mailboxes, you can rebuild the reverse-ACL data in ``mailboxes.db``.
``ctl_cyrusdb -r`` performs this work when the setting changes.  To force a
rebuild:

    1. Shut down Cyrus
    2. Change :imapdconf:`reverseacls` to `0`
    3. Run :cyrusman:`ctl_cyrusdb(8)` with the `-r` switch (or just start
       Cyrus, assuming your :cyrusman:`cyrus.conf(5)` contains a
       `ctl_cyrusdb -r` entry in the START section).  The old RACL entries
       will be removed
    4. (If you started Cyrus, shut it down again)
    5. Change `reverseacls` back to `1`
    6. Start up Cyrus (or run `ctl_cyrusdb -r`).  The RACL entries will
       be rebuilt

There are fixes and improvements to search indexing in 3.14.  See
:ref:`upgrade_3.14_search` for whether to rebuild your search indexes with
:cyrusman:`squatter(8)`.  This will probably take a long time.

9. Enable optional features
---------------------------

See the :ref:`3.14 release notes <imap-release-notes-3.14>` for the full list
of new features.

* To use the ``twom`` database backend, set the backend for each database type
  you want to convert.  With :imapdconf:`cyrusdb_autoconvert`, databases are
  converted as they are opened; otherwise convert them by hand.  No default
  has changed.
* To send metadata and annotation change events to notifyd, add ``metadata``
  to :imapdconf:`event_groups`.  The IMAP notifications of those changes need
  idled.
* To have :cyrusman:`master(8)` wait for idled before starting services, add
  ``wait=y`` to the idled entry in the ``DAEMON`` section of
  :cyrusman:`cyrus.conf(5)`.
* To allow WebDAV locks longer than five minutes, raise
  :imapdconf:`dav_writelock_max_timeout`.
* To accept SMTPUTF8 in lmtpd, disable both :imapdconf:`munge8bit` and
  :imapdconf:`reject8bit`.

.. _upgrade_3.14_murder:

Special note for Murder configurations
--------------------------------------

If you upgrade murder frontends before you upgrade all the backends,
they may advertise features to clients which the backends don't support,
which will cause the commands to fail when they are proxied to the backend.

Generally accepted wisdom when upgrading a Murder configuration is to
upgrade all your back end servers first. This can be done one at a time.

Upgrade your mupdate master and front ends last.

When a 3.12 backend uses XFER to move mailboxes to a 3.14 backend that
advertises replication, it transfers mailbox data through replication.  The
3.14 backend creates the destination indexes and can inherit an older index
version from an existing parent mailbox.  When XFER falls back to the legacy
dump and undump path, a 3.12 source recognises a 3.14 destination as supporting
version 19 and can transfer version 19 indexes directly.  To convert any
remaining older indexes, run ``reconstruct -V max`` on the destination when
ready to adopt version 20.

Earlier upgrades
----------------

These notes concern upgrades to versions before 3.14.  They are kept here
because the release notes of those versions refer to them.

.. _upgrade_email_query_reindex:

JMAP Email/query filter conditions
##################################

3.12 added the JMAP Email/query filter conditions ``messageId``,
``references``, and ``inReplyTo``.

It is recommended to rebuild the Xapian index with :cyrusman:`squatter(8)` to
make use of these filter conditions. Otherwise, email queries having these
filters fall back to reading the MIME headers from disk, resulting in slower
search.

.. _upgrade_pcre2_support:

PCRE2 support
#############

Since 3.10, Cyrus prefers PCRE2 over PCRE if both are installed.  If you have
both installed and wish to use PCRE rather than PCRE2, run configure with
``--disable-pcre2``.

If you haven't specifically installed libpcre2-dev (or whatever your system's
equivalent is), you might still have parts of pcre2 installed due to other
packages on your system depending on it.  This can confuse configure into
thinking you have a usable PCRE2 when you don't.  Either properly install
libpcre2-dev so Cyrus can use it, or configure Cyrus with ``--disable-pcre2``
so that it ignores the partial installation.

Please note that on Debian-based systems, PCRE (the old one, no longer
maintained) is called "pcre3".  Yes, this is confusing.
