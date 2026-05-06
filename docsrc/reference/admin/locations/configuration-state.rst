.. _imap-admin-locations-config:

Configuration file locations
============================

The main configuration file for Cyrus IMAP is :cyrusman:`imapd.conf(5)`
and its path is compiled into the executable files, based upon the
``--sysconfdir`` build flag.  For many utilities, this may be
overridden at runtime via the **-C** flag, followed by the name of the
configuration file to use.  For example:

.. parsed-literal::

    **ctl_mboxlist** **-C** */usr/local/etc/imapd.conf*  **-d** **-f** *mailboxes.dump*

The main configuration directory is referred to as ``<configdirectory>``
in Cyrus IMAP documentation, and is set via the :imapdconf:`configdirectory`
entry in :cyrusman:`imapd.conf(5)`.

While Cyrus itself has no default values for this setting, most
distributions use ``/var/lib/imap`` or ``/var/lib/cyrus``.

State Databases
---------------
Despite the name, most of what's stored in ``<configdirectory>`` is state
information.  Here's a list of files typically located therein:

    * :ref:`imap-concepts-deployment-db-annotations`
    * :ref:`imap-concepts-deployment-db-deliver`
    * :ref:`imap-concepts-deployment-db-mailboxes`
    * :ref:`imap-concepts-deployment-db-fetchnews`
    * :ref:`imap-concepts-deployment-db-pts`
    * :ref:`imap-concepts-deployment-db-quotas`
    * :ref:`imap-concepts-deployment-db-status`
    * :ref:`imap-concepts-deployment-db-tls`
    * :ref:`imap-concepts-deployment-db-userdeny`
    * :ref:`imap-concepts-deployment-db-zoneinfo`

The links above document the purpose, DB type and choices for those
files.  You may adjust the locations of these database files via various
settings in :cyrusman:`imapd.conf(5)`:

    * :imapdconf:`annotation_db_path`
    * :imapdconf:`duplicate_db_path`
    * :imapdconf:`mboxlist_db_path`
    * :imapdconf:`newsrc_db_path`
    * :imapdconf:`ptscache_db_path`
    * :imapdconf:`quota_db_path`
    * :imapdconf:`statuscache_db_path`
    * :imapdconf:`tls_sessions_db_path`
    * :imapdconf:`userdeny_db_path`
    * :imapdconf:`zoneinfo_db_path`

Ephemeral Databases
^^^^^^^^^^^^^^^^^^^

Several of the state databases may be located in RAM-backed locations,
such as ``/run`` or ``/var/run`` or where ever your OS roots such
filesystems (i.e. ``tmpfs`` on Linux or ``mfs`` on FreeBSD). Cyrus 3.0 will
recreate the following databases for you automatically:

* duplicate delivery (deliver.db),
* TLS cache (tls_sessions.db),
* PTS cache (ptscache.db),
* STATUS cache (statuscache.db).

Relocating these DBs to ephemeral storage will place less IO load on
your disks and tend to run faster.

.. note::
    Please be warned that some packagers place tasks such as
    ``tlsprune`` (:cyrusman:`tls_prune(8)`) in the ``START{}`` stanza
    of :cyrusman:`cyrus.conf(5)`.  This will cause a startup problem if
    the ``tls_sessions_db`` is not present.  The solution to this is to
    remove the ``tlsprune`` task from ``START{}`` and schedule it in
    ``EVENTS{}``, further down.

State Directories
=================

In addition to the files, are several directories:

    * lock (per-mailbox lock files)
    * log (per-user telemetry log directories)
    * proc (per-process state data)
    * ptclient (PT Loader Unix-domain socket)
    * quota (per-quotaroot quota state data)
    * sieve (per-user sieve message filter scripts)
    * socket (per-service Unix-domain sockets)
    * sync (per-replica directories with sync log files)
    * user (per-user DBs, see next section)

As with the DB files, above, many of these, too, may be relocated via
settings in :cyrusman:`imapd.conf(5)`:

    * :imapdconf:`mboxname_lockpath`
    * :imapdconf:`proc_path`
    * :imapdconf:`ptloader_sock`
    * :imapdconf:`quota_db_path`
    * :imapdconf:`sieveusehomedir`
    * :imapdconf:`sievedir`
    * :imapdconf:`idlesocket`
    * :imapdconf:`lmtpsocket`
    * :imapdconf:`notifysocket`

.. note::

    If your configuration uses :imapdconf:`quota_db: quotalegacy <quota_db>`,
    then ``quota_db_path`` points to the base of the quota directory
    hierarchy.  If you use any other DB type, then this will be
    the actual filename.

Per-user State Directories
==========================

There are several things tracked per-user, and the data files for these
items, such as subscriptions and seen state, are stored in
<configdirectory>/user.  These files may not be relocated from <configdirectory>.  They
are:

    * :ref:`imap-concepts-deployment-db-seen`
    * :ref:`imap-concepts-deployment-db-sub`
    * :ref:`imap-concepts-deployment-db-xapianactive`
    * :ref:`imap-concepts-deployment-db-mboxkey`
    * :ref:`imap-concepts-deployment-db-userdav`

Please follow those links for more information on these files.
