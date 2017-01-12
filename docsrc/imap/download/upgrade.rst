.. _upgrade:

================
Upgrading to 3.0
================

.. note::

    This guide assumes that you are familiar and comfortable with administration of a
    Cyrus installation, and system administration in general.

..  contents:: Upgrading: an overview
    :local:

1. Preparation
--------------

Things to consider **before** you begin:

Installation from tarball
#########################

It takes some time before platform packages are up to date. It is likely you will need to install from our packaged tarball, at least initially. We provide a full list of libraries that Debian requires, but we aren't able to test all platforms: you may find you need to install additional or different libraries to support v3.0.

How are you planning on upgrading?
##################################

Ideally, you will do a sandboxed test installation of 3.0 using a snapshot of your existing data before you switch off your existing installation. The rest of the instructions are assuming a sandboxed 3.0 installation.

If you're familiar with replication, and your current installation is 2.4 or newer, you can set up your existing
installation to replicate data to a new 3.0 installation and failover to the new installation when you're
ready. The replication protocol has been kept backwards compatible.

Most risky is upgrading in-place. Please don't do this, for your sanity and ours.

2. Install new 3.0 Cyrus
------------------------

Download the release :ref:`3.0 package tarball<install-diy>`.

Fetch the libraries for your platform. The list for Debian is::

    sudo apt-get install -y autoconf automake autotools-dev bash-completion bison build-essential comerr-dev \
    debhelper flex g++ git gperf groff heimdal-dev libbsd-resource-perl libclone-perl libconfig-inifiles-perl \
    libcunit1-dev libdatetime-perl libdb-dev libdigest-sha-perl libencode-imaputf7-perl libfile-chdir-perl \
    libglib2.0-dev libical-dev libio-socket-inet6-perl libio-stringy-perl libjansson-dev libldap2-dev \
    libmysqlclient-dev libnet-server-perl libnews-nntpclient-perl libpam0g-dev libpcre3-dev libsasl2-dev \
    libsnmp-dev libsqlite3-dev libssl-dev libtest-unit-perl libtool libunix-syslog-perl liburi-perl \
    libxapian-dev libxml-generator-perl libxml-xpath-perl libxml2-dev libwrap0-dev libzephyr-dev lsb-base \
    net-tools perl php5-cli php5-curl pkg-config po-debconf tcl-dev \
    transfig uuid-dev vim wamerican wget xutils-dev zlib1g-dev sasl2-bin rsyslog sudo acl telnet

If you're on another platform and can provide the list of dependencies, please
let us know via a `GitHub issue <https://github.com/cyrusimap/cyrus-imapd/issues>`_ or documentation pull request or send mail to the :ref:`developer list<feedback>`.

Follow the :ref:`general install instructions <basicserver>`.

.. note::

    It's best to ensure your new Cyrus initially *will not* start up listening for new
    inbound/outbound imap connections, not until you've completed your migration.

    How this is best achieved will depend upon your OS and distro, but may involve
    something like ``systemctl disable cyrus-imapd`` or ``update-rc.d cyrus-imapd disable``

3. Shut down existing Cyrus
---------------------------

Shut down your existing Cyrus as user cyrus.

This is necessary to guarantee a clean data snapshot.

4. Backup existing data
-----------------------

We recommend backing up all your data before continuing.

* Sieve scripts
* Config files
* Mail spool
* :ref:`Cyrus Databases <databases>`

(You do already have a backup strategy in place, right? Once you're on 3.0, you can
use the new inbuilt :ref:`backup tools <cyrus-backups>`.)

5. Copy config files and update
-------------------------------

Copy your existing :cyrusman:`imapd.conf(5)` and :cyrusman:`cyrus.conf(5)` into the new 3.0 locations.

Update imapd.conf (edit as root) so that the new data directories are in the right spot (you don't want to mix
your existing data with your new install).

Check to see if your config file contains any deprecated options::

    cyr_info conf-lint -C <path to cyrus.conf> -M <path to imapd.conf>

Check to see that the sum of your system's config values is correct. This command
takes all the system defaults, along with anything you have provided overrides for
in your config files::

    cyr_info conf-all -C <path to cyrus.conf> -M <path to imapd.conf>

**Important config** options: ``unixhierarchysep:`` and ``altnamespace:``
defaults have changed in :cyrusman:`imapd.conf(5)`. Implications are
outlined in the Note in :ref:`imap-admin-namespaces-mode` and
:ref:`imap-switching-alt-namespace-mode`.

* unixhierarchysep: on
* altnamespace: on

.. note::
    If your installation is using groups, don't turn ``reverseacls:`` on. Reverseacl support
    only works well for sites without groups.


6. Copy all data to new location
--------------------------------

Before you launch Cyrus for the first time, create the Cyrus directory structure: use :cyrusman:`mkimap(8)`.

::

    sudo -u cyrus ./tools/mkimap

Copy your data files to the new Cyrus 3.0 locations you just specified.

* Sieve scripts

   Location set via ``sieveusehomedir:`` and ``sievedir:`` directives

* Config files

   Location set via ``configdirectory:`` directive

* Mail spool

   Location set via ``partition-XX`` directive(s), of which there may be
   several

* Metadata

   Location set via ``metapartition-XX`` directive(s), of which there may
   be several

* :ref:`Cyrus Databases <databases>`

   Location set via ``XX_db_path:`` directives (i.e.
   ``tls_sessions_db_path: /run/cyrus/tls_sessions.db``)

You don't need to copy the following databases as Cyrus 3.0 will
recreate these for you automatically:

* duplicate delivery (deliver.db),
* TLS cache (tls_sessions.db),
* PTS cache (ptscache.db),
* STATUS cache (statuscache.db).

.. note::
    If you're upgrading from versions older than 2.4, you may wish to
    consider relocating these four databases to ephemeral storage, such
    as ``/run/cyrus`` (Debian/Ubuntu) or ``/var/run/cyrus`` or whatever
    suitable tmpfs is provided on your distro.

.. note::
    Please be warned that some packages place tasks such as ``tlsprune``
    (:cyrusman:`tls_prune(8)`) in the ``START{}`` stanza of
    :cyrusman:`cyrus.conf(5)`.  This will cause a startup problem if the
    ``tls_sessions_db`` is not present.  The solution to this is to
    remove the ``tlsprune`` task from ``START{}`` and schedule it in
    ``EVENTS{}``, further down.
    
.. warning::

    **Berkeley db format no longer supported**

    If you have any databases using Berkeley db, they'll need to be
    converted to skiplist or flat *in your existing installation*. And
    then optionally converted to whatever final format you'd like in
    your 3.0 installation.

    Databases potentially affected: mailboxes, annotations, conversations, quotas.

    On old install, prior to migration::

       cvt_cyrusdb /<confdir>mailboxes.db berkeley /tmp/new-mailboxes.db skiplist

    If you don't want to use flat or skiplist for 3.0, you can use the
    new 3.0 :cyrusman:`cvt_cyrusdb(8)` to swap to new format::

       cvt_cyrusdb /tmp/new-mailboxes.db skiplist /<confdir>/mailboxes.db <new file format>

.. note::
    The :cyrusman:`cvt_cyrusdb(8)` command does not accept relative paths.


7. Start new 3.0 Cyrus and verify
---------------------------------

::

    sudo ./master/master -d

Check ``/var/log/syslog`` for errors so you can quickly understand potential problems.

When you're satisfied version 3.0 is running and can see all its data correctly,
connect the new Cyrus back up to send and receive mail and you're
back in business.

If something has gone wrong, contact us on the :ref:`mailing list <feedback>`.
You can switch your old installation back on
and keep processing mail until you're able to finish your 3.0 installation.

8. Reconstruct databases and cache
----------------------------------

The following steps can each take a long time, so we recommend
running them one at a time (to reduce locking contention and high I/O load).

To upgrade all the mailboxes to the latest version. This will take hours, possibly days.

::

    reconstruct -V max

New configuration: if turning on conversations, you need to create conversations.db for each user.
This is required for jmap.::

     ctl_conversationsdb -b -r

To check (and correct) quota usage::

    quota -f

If you're using CalDAV/CardDAV/all of the DAV, then all the user.dav databases need
to be reconstructed due to format changes.::

    dav_reconstruct -a

9. Do you want any new features?
--------------------------------

3.0 comes with many lovely new features. Consider which ones you want to enable.
Here are some which may interest you. Check the :ref:`3.0 release notes <imap-release-notes-3.0>`
for the full list.

* :ref:`JMAP <developer-jmap>`
* :ref:`Backups <cyrus-backups>`
* :ref:`Xapian for searching <imapinstall-xapian>`
* Cross-domain support. See ``crossdomains`` in :cyrusman:`imapd.conf(5)`

10. Upgrade complete
--------------------

Your upgrade is complete! We have a super-quick survey (3 questions only,
anonymous responses) we would love for you to fill out, so we can get a feel for
how many Cyrus installations are out there, and how the upgrade process went.

|3.0 survey link|

.. |3.0 survey link| raw:: html

    <a href="https://cyrusimap.typeform.com/to/YI9P0f" target="_blank">
    I'll fill in the survey right now</a> (opens in a new window)


Special note for Murder configurations
--------------------------------------

Generally accepted wisdom when upgrading a Murder configuration is to
upgrade your back end servers first. This can be done one at a time.

Then upgrade your front ends and the mupdate master.
