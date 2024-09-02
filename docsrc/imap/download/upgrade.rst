.. highlight:: none

.. _upgrade:

=================
Upgrading to 3.10
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

Before upgrading to 3.10, your deployment should be running one of:

* 3.6.3 (or later)
* 3.8.1 (or later)

If your existing deployment predates these releases, you should first upgrade
to one of these versions, let it run for a while, resolve any issues that
come up, and only then upgrade to 3.10.

Installation from tarball
#########################

You will need to install from our packaged tarball. We provide a full list of
libraries that Debian requires, but we aren't able to test all platforms: you
may find you need to install additional or different libraries to support v3.8.

Storage changes
###############

In 3.6 and later, mailboxes and user metadata directories are organised on
disk by UUID rather than by mailbox name.

At startup (or when you first run the updated `ctl_cyrusdb -r` manually),
:cyrusman:`ctl_cyrusdb(8)` will upgrade mailboxes.db to accommodate both
old-style and new-style storage, if it didn't already.

By default, new top-level mailboxes will be created in the new style.
Mailboxes that already exist in the old style will remain in the old style
until you convert them with :cyrusman:`relocate_by_id(8)`.  New mailboxes
below the top level will be created in the same style as their parent mailbox.

The new :cyrusman:`cyr_ls(8)` tool can be used to examine the on-disk
contents of a given mailbox name.  :cyrusman:`mbpath(8)` can be used to find
where on disk a given mailbox and its metadata are.

If you want new top level mailboxes to be created in the old style, you
can enable the `mailbox_legacy_dirs` :cyrusman:`imapd.conf(5)` option, which
defaults to **off**.  With this turned on, you may still use `relocate_by_id`
to convert them to the new style.

Since 3.6, sieve scripts are stored in the '#sieve' mailbox (configurable with
the `sieve_folder` :cyrusman:`imapd.conf(5)` option).  No manual steps are
necessary for upgrade: Cyrus recognises the old style storage and will
convert to the new style automatically as necessary.


JMAP/CalDAV changes
###################

.. _upgrade_3.8.0_jmap_caldav_changes:

X-JMAP-PRIVACY (since 3.8)
~~~~~~~~~~~~~~~~~~~~~~~~~~

Prior to 3.8, Cyrus determined the JMAP CalendarEvent privacy of an iCalendar
VEVENT by the CLASS property. Since 3.8, this now gets determined by the newly
introduced X-JMAP-PRIVACY property, but the CalDAV indexes may already have
entries for the old mapping and need to be upgraded.

Sites that use JMAP should upgrade their CalDAV database index by calling
the newly introduced JMAP method `Admin/rewriteCalendarEventPrivacy`.
This method:

- requires the `https://cyrusimap.org/ns/jmap/admin` request capability
- must be called as an admin user (regular user calls are rejected)
- takes the optional `userIds` argument, whis is a JSON array of
  userids to migrate. In absence of this argument, all users are migrated

Site that do not use JMAP should upgrade their CalDAV database by

- calling ``DELETE FROM ical_objs WHERE comp_flags >= 1024;`` on a user's
  dav.db
- followed by calling `dav_reconstruct` for that user

.. _upgrade_jmap_default_alarms:

Default alarms
~~~~~~~~~~~~~~

Prior to 3.10, JMAP default alarms were stored on a calendar mailbox
in the following annotations:

- ``{urn:ietf:params:xml:ns:caldav}default-alarm-vevent-datetime``
- ``{urn:ietf:params:xml:ns:caldav}default-alarm-vevent-date``

When upgrading to 3.10, installations that use the experimental JMAP calendars
API must run a migration tool to separate CalDAV default alarm annotations from
JMAP annotations.  This tool will remove the annotations from the calendar
mailbox and move their contents to the Cyrus-internal annotation
``/vendor/cmu/cyrus-jmap/defaultalerts``

CalDAV annotations on the calendar home are left as-is and are not migrated.
Typically, Apple CalDAV clients store default alarms at this location.

To migrate, call the ``Admin/migrateCalendarDefaultAlarms`` JMAP method as an
admin user.  JMAP clients need to use the
``https://cyrusimap.org/ns/jmap/admin`` capability for this method.

This method has the following arguments:

- ``userIds: Id[]|null (default: null)``: the list of users for which to
  migrate default alarms. If null, then alarms are migrated for all users.

- ``keepCaldavAlarms: Boolean (default: false)``: If true, the DAV annotations
  are migrated but not removed from the calendar mailbox. There should be
  no need to keep them, except if installations or their CalDAV clients
  made use of these CalDAV annotations themselves.

The method response contains:

- ``migrated: Id[String[SetError|null]]``: For each userid, this is a map of
  calendar id to either null on success, or an error.

- ``notMigrated: Id[SetError]``: For each userid, contains an error that
  prevented migrating this users default alarms.

CalendarEventNotifications
~~~~~~~~~~~~~~~~~~~~~~~~~~

The default maximum count of CalendarEventNotifications is set to 200
per account. Installations that need any other count or want to not
prune notifications must update the ``jmap_max_calendareventnotifs``
:cyrusman:`imapd.conf(5)` option.

.. _upgrade_3.8.0_sieve_changes:

.. _upgrade_sieve_changes:

Sieve changes
#############

3.10 no longer supports the deprecated ``denotify`` action or ``notify``
actions using the legacy (pre-:rfc:`5435`) syntax.

Existing bytecode containing these actions will still be executed.

Scripts that contain the deprecated ``denotify`` action should be rewritten
to remove them.

Scripts that contain notify actions using the legacy syntax should be rewritten
to use the syntax in :rfc:`5435`.

.. _upgrade_master_pid_ready_files:

master.pid and master.ready files
#################################

If you have something that monitors syslog looking for master's "ready for
work" message, you might consider switching to monitoring the master.ready
file instead, perhaps using Linux inotify.

The master pidfile name is now read from imapd.conf, and defaults to
``{configdirectory}/master.pid``.  If you have something that looks for this
file, you should either update it to look in the new default location, or set
``master_pid_file`` in :cyrusman:`imapd.conf(5)` to override the default.  The
``-p`` option to :cyrusman:`master(8)` can still be used to override it.

.. _upgrade_pcre2_support:

PCRE2 support
#############

Cyrus 3.10 will prefer PCRE2 over PCRE if both are installed.  If you have both
installed and wish to use PCRE rather than PCRE2, run configure with
``--disable-pcre2``.

If you haven't specifically installed libpcre2-dev (or whatever your system's
equivalent is), you might still have parts of pcre2 installed due to other
packages on your system depending on it.  This can confuse configure into
thinking you have a usable PCRE2 when you don't.  Either properly install
libpcre2-dev so Cyrus can use it, or configure Cyrus with ``--disable-pcre2``
so that it ignores the partial installation.

Please note that on Debian-based systems, PCRE (the old one, no longer
maintained) is called "pcre3".  Yes, this is confusing.

Cyrus Backups feature is deprecated as of 3.10
##############################################

Deployments that rely on the experimental Cyrus Backup feature should
start planning for an alternative backup solution, as this feature will
be removed in the future.

How are you planning on upgrading?
##################################

Ideally, you will do a sandboxed test installation of 3.10 using a snapshot of
your existing data before you switch off your existing installation. The rest
of the instructions are assuming a sandboxed 3.10 installation.

Upgrade by replicating
~~~~~~~~~~~~~~~~~~~~~~

If you're familiar with replication, and your current installation is 2.4 or
newer, you can set up your existing installation to replicate data to a new
3.10 installation and failover to the new installation when you're ready. The
replication protocol has been kept backwards compatible.

If your old installation contains mailboxes or messages that are older than
2.4, they may not have GUID fields in their indexes (index version too old),
or they may have their GUID field set to zero.  3.10 will not accept message
replications without valid matching GUIDs, so you need to fix this on your
old installation first.

You can check for affected mailboxes by examining the output from the
:cyrusman:`mbexamine(8)` tool:

* mailboxes that report a 'Minor Version:' less than 10 will need to have
  their index upgraded using :cyrusman:`reconstruct(8)` with the
  `-V <version>` parameter to be at least 10.
* mailboxes containing messages that report 'GUID:0' will need to have
  their GUIDs recalculated using :cyrusman:`reconstruct(8)` with the `-G`
  parameter.

If you have a large amount of data, these reconstructs will take a long time,
so it's better to identify the mailboxes needing attention and target them
specifically.  But if you have a small amount of data, it might be less work
to just `reconstruct -G -V max` everything.

Upgrade in place
~~~~~~~~~~~~~~~~

If you are upgrading in place, you will need to shut down Cyrus
entirely while you install the new package.  If your old installation
was using Berkeley DB format databases, you will need to convert or
upgrade the databases **before** you upgrade.  Cyrus 3.10 does not
support Berkeley DB at all.

.. note::

    If you are upgrading from Cyrus version 2.5 or earlier,
    and your system is configured with the following combination
    in :cyrusman:`imapd.conf(5)`::

        fulldirhash: yes
        hashimapspool: either yes or no
        unixhierarchysep: yes

    then you will not be able to upgrade-in-place.  This is due to
    a change in how directory hashes are calculated for users whose
    localpart contains a dot, which was introduced in 3.0.0.  After
    an in-place upgrade, Cyrus will not be able to find these users'
    metadata and/or mailboxes.

    If you have this configuration, you will need to upgrade by
    replicating, not in place.

Do What As Who?
###############

Since the various files, databases, directories, etc. used by Cyrus
must be readable and writable as the ``cyrus`` user, please make sure
to **always** perform Cyrus commands *as* the ``cyrus`` user, and not
as ``root``.  In our documentation, we will always reference Cyrus
commands in this form -- :cyrusman:`cyr_info(8)` -- before using
examples of them, so you'll know that those commands **must** be run as
the ``cyrus`` user.

Doing so in most systems is as simple as using either the ``su`` or
``sudo`` commands, like so::

    su cyrus -c "/usr/local/bin/cyr_info conf-lint -C /etc/imapd.conf -M /etc/cyrus.conf"
    sudo -u cyrus /usr/local/bin/cyr_info conf-lint -C /etc/imapd.conf -M /etc/cyrus.conf

In this document, however, there are also several command examples which
*should* or **must** be run as ``root``.  These are always standard \*nix
commands, such as ``rsync`` or ``scp``.

We strongly recommend that you read this entire document before upgrading.

2. Install new 3.10 Cyrus
-------------------------

Download the release :ref:`3.10 package tarball <getcyrus>`.

Fetch the libraries for your platform. The full list (including all optional
packages) for Debian is::

    sudo apt-get install -y autoconf automake autotools-dev bash-completion \
    bison build-essential comerr-dev debhelper flex g++ git gperf groff \
    heimdal-dev libbsd-resource-perl libclone-perl libconfig-inifiles-perl \
    libcunit1-dev libdatetime-perl libdigest-sha-perl libencode-imaputf7-perl \
    libfile-chdir-perl libglib2.0-dev libical-dev libio-socket-inet6-perl \
    libio-stringy-perl libjansson-dev libldap2-dev libmysqlclient-dev \
    libnet-server-perl libnews-nntpclient-perl libpam0g-dev libpcre2-dev \
    libsasl2-dev libsqlite3-dev libssl-dev libtest-unit-perl libtool \
    libunix-syslog-perl liburi-perl libxapian-dev libxml-generator-perl \
    libxml-xpath-perl libxml2-dev libwrap0-dev libzephyr-dev lsb-base \
    net-tools perl php-cli php-curl pkg-config po-debconf tcl-dev transfig \
    uuid-dev vim wamerican wget xutils-dev zlib1g-dev sasl2-bin rsyslog sudo \
    acl telnet

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

You don't need to copy the following databases as Cyrus 3.10 will
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

**Important config** options: ``unixhierarchysep:`` and ``altnamespace:``
defaults in :cyrusman:`imapd.conf(5)` changed in 3.0, which will affect you
if you are upgrading to 3.10 from something earlier than 3.0. Implications
are outlined in the Note in :ref:`imap-admin-namespaces-mode` and
:ref:`imap-switching-alt-namespace-mode`.  Please also see "Sieve Scripts,"
below.

* unixhierarchysep: on
* altnamespace: on

In :cyrusman:`cyrus.conf(5)` move idled from the START section to the
DAEMON section.

Installations that passed fractional durations such as "1.5d" to any of the
-E, -X, -D, or -A :cyrusman:`cyr_expire(8)` arguments must adapt these to only
use integer durations such as "1d12h".  You may have such entries in the EVENTS
section of :cyrusman:`cyrus.conf(5)`, or cron etc.

6. Upgrade specific items
-------------------------

* Special-Use flags

   If your 2.4 :cyrusman:`imapd.conf(5)` made use of the ``xlist-XX``
   directive(s), you can convert these to per-user special-use annotations
   in your new install with the :cyrusman:`cvt_xlist_specialuse(8)` tool

.. warning::

    **Berkeley db format no longer supported since 3.0**

    If you have any databases using Berkeley db, they'll need to be
    converted to skiplist or flat *in your existing installation*. And
    then optionally converted to whatever final format you'd like in
    your 3.10 installation.

    Databases potentially affected: mailboxes, annotations, conversations,
    quotas.

    On old install, prior to migration::

       cvt_cyrusdb /<configdirectory>mailboxes.db berkeley /tmp/new-mailboxes.db skiplist

    If you don't want to use flat or skiplist for 3.10, you can use
    :cyrusman:`cvt_cyrusdb(8)` to swap to new format::

       cvt_cyrusdb /tmp/new-mailboxes.db skiplist /<configdirectory>/mailboxes.db <new file format>

.. note::
    The :cyrusman:`cvt_cyrusdb(8)` command does not accept relative paths.

7. Start new 3.10 Cyrus and verify
----------------------------------

::

    sudo ./master/master -d

Check ``/var/log/syslog`` for errors so you can quickly understand potential
problems.

When you're satisfied version 3.10 is running and can see all its data
correctly, start the new Cyrus up with your regular init script.

If something has gone wrong, contact us on the
:ref:`mailing list <feedback-mailing-lists>`.
You can revert to backups and keep processing mail using your old version
until you're able to finish your 3.10 installation.

.. note::

    If you've disabled your system startup scripts, as recommended in
    step 2, remember to re-enable them.  Use something like ``systemctl
    enable cyrus-imapd`` or ``update-rc.d cyrus-imapd enable``

8. Reconstruct databases and cache
----------------------------------

The following steps can each take a long time, so we recommend
running them one at a time (to reduce locking contention and high I/O load).

To upgrade all the mailboxes to the latest version. This will take hours,
possibly days.

::

    reconstruct -V max

3.10 contains fixes for conversations bugs.  The fixes are all backwards
compatible, but a conversations DB rebuild will be good, e.g.
``ctl_conversationsdb -R -r -v``.

If a user's conversations remain broken, you can wipe and recreate all their
CIDs with ``ctl_conversationsdb -z $username`` followed by
``ctl_conversationsdb -b $username``

To check (and correct) quota usage::

    quota -f

If you've been using CalDAV/CardDAV/all of the DAV from earlier releases, then
the user.dav databases need to be reconstructed due to format changes.::

    dav_reconstruct -a

If have the `reverseacls` feature enabled in :cyrusman:`imapd.conf(5)`, you may
need to regenerate the data it uses (which is stored in `mailboxes.db`).  This
is automatically regenerated at startup by ``ctl_cyrusdb -r`` if the
`reverseacls` setting has changed. So, to force a regeneration:

    1. Shut down Cyrus
    2. Change `reverseacls` to `0` in :cyrusman:`imapd.conf(5)`
    3. Run :cyrusman:`ctl_cyrusdb(8)` with the `-r` switch (or just start
       Cyrus, assuming your :cyrusman:`cyrus.conf(5)` contains a
       `ctl_cyrusdb -r` entry in the START section).  The old RACL entries
       will be removed
    4. (If you started Cyrus, shut it down again)
    5. Change `reverseacls` back to `1`
    6. Start up Cyrus (or run `ctl_cyrusdb -r`).  The RACL entries will
       be rebuilt

There were fixes and improvements to caching and search indexing in 3.6.  If
you are upgrading to 3.10 from something earlier than 3.6, you should consider
running :cyrusman:`reconstruct(8)` across all mailboxes to rebuild caches, and
:cyrusman:`squatter(8)` to rebuild search indexes.  This will probably take a
long time, so you may wish to only do it per-mailbox as inconsistencies are
discovered.  However, if you have been running a 3.5 development version, you
should make sure to do this for all mailboxes, due to bugs that were introduced
and then fixed during 3.5 development.

3.10 contains fixes to bugs in the Squat search backend.  If you use the Squat
search backend, your search indexes may benefit from a full (not incremental)
reindex using :cyrusman:`squatter(8)`.

9. Do you want any new features?
--------------------------------

3.10 comes with many lovely new features. Consider which ones you want to
enable.  Check the :ref:`3.10 release notes <imap-release-notes-3.10>` for the
full list.

10. Upgrade complete
--------------------

Your upgrade is complete, congratulations!

Special note for Murder configurations
--------------------------------------

If you upgrade murder frontends before you upgrade all the backends,
they may advertise features to clients which the backends don't support,
which will cause the commands to fail when they are proxied to the backend.

Generally accepted wisdom when upgrading a Murder configuration is to
upgrade all your back end servers first. This can be done one at a time.

Upgrade your mupdate master and front ends last.

Please note that you will be unable to set ANNOTATION-STORAGE or MAILBOX
quotas (formerly known as X-ANNOTATION-STORAGE and X-NUM_FOLDERS) in a
mixed-version murder environment until your frontends are upgraded to 3.10
(or later).  Upgraded frontends know how to negotiate with older backends, but
older frontends do not know how to negotiate with newer backends.

If you wish to use XFER to transfer mailboxes from an existing backend to your
new 3.10 backend, you should first upgrade your existing backends to 3.8, 3.6.1,
3.4.5, 3.2.11, or 3.0.18.  These releases contain a patch such that XFER will
correctly recognise 3.8 and later destinations.  Without this patch, XFER will
not recognise 3.10, and will downgrade mailboxes to the oldest supported format
(losing metadata) in transit.

If your existing backends are 2.4 or 2.5, there are equivalent patches for
recognising 3.8+ on the cyrus-imapd-2.4 and cyrus-imapd-2.5 git branches, but
these are not in any released version.
