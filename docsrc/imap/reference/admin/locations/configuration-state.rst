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

The main configuration directory is referred to as ``<confdir>`` in
most Cyrus IMAP documentation, and is set via the ``configdirectory``
entry in :cyrusman:`imapd.conf(5)`:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob configdirectory
        :end-before: endblob configdirectory

While Cyrus itself has no default values for this setting, most
distributions use ``/var/lib/imap`` or ``/var/lib/cyrus``.

State Databases
---------------
Despite the name, most of what's stored in ``<confdir>`` is state
information.  Here's a list of files typically located therein:

    * :ref:`imap-concepts-deployment-db-annotations`
    * :ref:`imap-concepts-deployment-db-backups`
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

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob annotation_db_path
	:end-before: endblob annotation_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob backup_db_path
	:end-before: endblob backup_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob duplicate_db_path
	:end-before: endblob duplicate_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob mboxlist_db_path
	:end-before: endblob mboxlist_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob newsrc_db_path
	:end-before: endblob newsrc_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob ptscache_db_path
	:end-before: endblob ptscache_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob quota_db_path
	:end-before: endblob quota_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob statuscache_db_path
	:end-before: endblob statuscache_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob tls_sessions_db_path
	:end-before: endblob tls_sessions_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob userdeny_db_path
	:end-before: endblob userdeny_db_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob zoneinfo_db_path
	:end-before: endblob zoneinfo_db_path

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

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob mboxname_lockpath
	:end-before: endblob mboxname_lockpath

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob proc_path
	:end-before: endblob proc_path

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob ptloader_sock
	:end-before: endblob ptloader_sock

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob quota_db_path
	:end-before: endblob quota_db_path

.. note::

    If your configuration uses ``quota_db: quotalegacy``, then
    ``quota_db_path`` points to the base of the quota directory
    hierarchy.  If you use any other DB type, then this will be
    the actual filename. 

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob sieveusehomedir
	:end-before: endblob sieveusehomedir

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob sievedir
	:end-before: endblob sievedir

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob idlesocket
	:end-before: endblob idlesocket

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob lmtpsocket
	:end-before: endblob lmtpsocket

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob notifysocket
	:end-before: endblob notifysocket

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob sphinx_socket
	:end-before: endblob sphinx_socket

Per-user State Directories
==========================

There are several things tracked per-user, and the data files for these
items, such as subscriptions and seen state, are stored in
<confdir>/user.  These files may not be relocated from <confdir>.  They
are:

    * :ref:`imap-concepts-deployment-db-seen`
    * :ref:`imap-concepts-deployment-db-sub`
    * :ref:`imap-concepts-deployment-db-xapianactive`
    * :ref:`imap-concepts-deployment-db-mboxkey`
    * :ref:`imap-concepts-deployment-db-userdav`

Please follow those links for more information on these files.
