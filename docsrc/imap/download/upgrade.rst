.. highlight:: none

.. _upgrade:

=================
Upgrading to 3.12
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

Before upgrading to 3.12, your deployment should be running
**3.10.1 (or later)**

If your existing deployment is older than this, you should first upgrade
to 3.10.1, let it run for a while, resolve any issues that come up, and only
then upgrade to 3.12.

Installation from tarball
#########################

You will need to install from our packaged tarball. We provide a full list of
libraries that Debian requires, but we aren't able to test all platforms: you
may find you need to install additional or different libraries to support 3.12.

JMAP/CalDAV changes
###################

.. _upgrade_email_query_reindex:

New JMAP Email/query filter conditions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

3.12 adds the JMAP Email/query filter conditions ``messageId``, ``references``,
and ``inReplyTo``.

It is recommended to rebuild the Xapian index with :cyrusman:`squatter(8)` to
make use of these filter conditions. Otherwise, email queries having these
filters fall back to reading the MIME headers from disk, resulting in slower
search.

.. _upgrade_pcre2_support:

PCRE2 support
#############

Cyrus 3.12 will prefer PCRE2 over PCRE if both are installed.  If you have both
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

How are you planning on upgrading?
##################################

Ideally, you will do a sandboxed test installation of 3.12 using a snapshot
of your existing data before you switch off your existing installation.

Other possibilities are upgrading by replication, or upgrading in place.

**The rest of the instructions are written assuming a sandboxed 3.12
installation**, but you should read and understand them regardless of how
you intend to perform the upgrade.

Upgrade by replicating
~~~~~~~~~~~~~~~~~~~~~~

If you're familiar with replication, and your current installation is 2.4 or
newer, you can set up your existing installation to replicate data to a new
3.12 installation and failover to the new installation when you're ready. The
replication protocol has been kept mostly backwards compatible.

If your old installation contains mailboxes or messages that are older than
2.4, they may not have GUID fields in their indexes (index version too old),
or they may have their GUID field set to zero.  3.12 will not accept message
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

If your old installation is on 3.0 or older and is using mailbox annotations,
you will have problems replicating to newer versions due to missing MODSEQ
(:issue:`4967`).  There is an experimental patch in the comments on this issue
that might help for a one-off replication run into an empty replica, but it
will not help for updating a replica that already has data.

Upgrade in place
~~~~~~~~~~~~~~~~

If you are upgrading in place, you will need to shut down Cyrus entirely while
you install the new package.  You should probably also block logins or filewall
off internet access until you're completely finished so that you aren't
surprised by users reconnecting before the upgraded server is ready for them.

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

2. Install new 3.12 Cyrus
-------------------------

Download the release :ref:`3.12 package tarball <getcyrus>`.

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

You don't need to copy the following databases as Cyrus 3.12 will
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

6. Upgrade specific items
-------------------------

Nothing special required when upgrading from 3.10.

7. Start new 3.12 Cyrus and verify
----------------------------------

::

    sudo ./master/master -d

Check ``/var/log/syslog`` for errors so you can quickly understand potential
problems.

When you're satisfied version 3.12 is running and can see all its data
correctly, start the new Cyrus up with your regular init script.

If something has gone wrong, contact us on the
:ref:`mailing list <feedback-mailing-lists>`.
You can revert to backups and keep processing mail using your old version
until you're able to finish your 3.12 installation.

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

There are fixes and improvements to caching and search indexing in 3.12.
You should consider running :cyrusman:`reconstruct(8)` across all mailboxes to
rebuild caches, and :cyrusman:`squatter(8)` to rebuild search indexes.  This
will probably take a long time, so you may wish to only do it per-mailbox as
inconsistencies are discovered.

9. Do you want any new features?
--------------------------------

3.12 comes with many lovely new features. Consider which ones you want to
enable.  Check the :ref:`3.12 release notes <imap-release-notes-3.12>` for the
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
new 3.12 backend, you should first upgrade your existing backends to 3.10, 3.8,
3.6.1, 3.4.5, 3.2.11, or 3.0.18.  These releases contain a patch such that XFER
will correctly recognise 3.8 and later destinations.  Without this patch, XFER
will not recognise 3.12, and will downgrade mailboxes to the oldest supported
format (losing metadata) in transit.
