===================
Notes for Packagers
===================

Sample configuration files
==========================

There are several samples of :cyrusman:`cyrus.conf(5)` located in the
``doc/examples`` directory of the distribution tarball.  Please install
these to your preferred documentation directory (i.e.
``/usr/share/doc/cyrus-imapd``) as a reference for your users.

Predefined configurations
=========================

The configuration file for master: cyrus.conf
---------------------------------------------

When installing a predefined :cyrusman:`cyrus.conf(5)` for your users,
please pay attention to new features and how these may impact users.
For example, for some time now, Cyrus has supported placing several
standard DB files in temporary, or ephemeral, storage, such as memory
backed filesystems like tmpfs (see below).  This both boosts efficiency
and ensures DB consistency in event of a crash or other system
disruptive events. But, in light of this, actions which depend on the
existence of these database files *should not* be placed in the
**START** section of :cyrusman:`cyrus.conf(5)`.

Section Purpose
###############

A new section, DAEMON, was added to :cyrusman:`cyrus.conf(5)` in
version 2.5.  Please consult :cyrusman:`cyrus.conf(5)` for details.
Please refer to the notes in **Section Descriptions** pertaining to the
distinctions between **START**, **EVENTS** and **DAEMON** sections.

In brief, the sorts of things which should go into the different
sections are:

*   **START**

    * Programs which should be spawned by :cyrusman:`master(8)` which
      are expected to cleanup after themselves
    * do not rely on any ephemeral files or resources
    * :cyrusman:`master(8)` will not start until all entries in
      **START** have either ended or backgrounded themselves.

*   **SERVICES**

    * Service daemons managed by :cyrusman:`master(8)`
    * :cyrusman:`master(8)` will listen on ports or sockets as specified
      and dispatch new child processes as needed, destroy old or stale
      processes, etc.

*   **EVENTS**

    * Periodic processes which will be started by :cyrusman:`master(8)`
      as specified.

*   **DAEMON**

    * Programs which should be spawned by :cyrusman:`master(8)` which
      it should shut down and clean up after.

The configuration file for the various programs: imapd.conf
-----------------------------------------------------------

There is no sample for the :cyrusman:`imapd.conf(5)` file, as it must
vary so much from site to site.  Here, therefore, we'll attempt to
point you towards some reasonable settings which take advantage of
recent improvements and features, and may help guide you and your users
to a better performing Cyrus installation.

Ephemeral files and temporary filesystems
#########################################

In addition to Unix domain sockets and lock files, several databases
used by Cyrus programs may be located in temporary filesystems, such as
those backed by RAM (i.e. tmpfs, md, etc.).  Here's a list of such
files.  In this example, the filesystem ``/run`` is on tmpfs::

    proc_path: /run/cyrus/proc
    mboxname_lockpath: /run/cyrus/lock
    duplicate_db_path: /run/cyrus/deliver.db
    statuscache_db_path: /run/cyrus/statuscache.db
    ptscache_db_path: /run/cyrus/ptscache.db
    tls_sessions_db_path: /run/cyrus/tls_sessions.db
    lmtpsocket: /run/cyrus/socket/lmtp
    idlesocket: /run/cyrus/socket/idle
    notifysocket: /run/cyrus/socket/notify

.. note::

    Any process which depends on these files already existing **should
    not** be placed in the **START** section of
    :cyrusman:`cyrus.conf(5)`, or the server will not start as
    expected.

New default settings
####################

With the introduction of version 3.0, the defaults for some settings
have changed.  Please consult :ref:`upgrade` for details.

Services in ``/etc/services``
=============================

Listing named services through ``/etc/services`` aids in cross-system consistency and cross-platform interoperability. Furthermore, it enables administrators and users to refer to the service by name (for example in ``/etc/cyrus.conf``, 'listen=mupdate' can be specified instead of 'listen=3905').

Some of the services Cyrus IMAP would like to see available through ``/etc/services`` have not been assigned an IANA port number, and few have configuration options.

The following lists services Cyrus IMAP should have available in ``/etc/services``:

* **csync**

    The Cyrus IMAP synchronisation server port, for replication clients to connect to.

    * Description: *Cyrus IMAP Replication Daemon*
    * Suggested Port(s): **2005/tcp**

.. note::
    **Default in /etc/imapd.conf**

    While **2005/tcp** is the suggested default port for **csync**, the value of the port number is specified through the **sync_port** option in ``/etc/imapd.conf`` (generated from ``lib/imapoptions``). Note that when changing the suggested port for **csync** we recommend you also patch ``lib/imapoptions`` prior to building Cyrus IMAP.

* **lmtp**

    Some platforms do not specify the service port for LMTP –like Solaris and Debian. Fedora-based Linux distributions allocate port **24/tcp** for LMTP Mail Delivery, however. Whatever port packagers choose to use, please note they should be the same across all platforms deployed in a single environment.

    * Description: *LMTP Mail Delivery*
    * Suggested Port(s): **24/tcp** (Fedora-based platforms), **2003/tcp** (other platforms)

* **mupdate**

    The Cyrus IMAP Murder Mailbox Update protocol (MUPDATE) ensures mailboxes

    * Description: *Mailbox Update (MUPDATE) protocol*
    * Recommended Port(s): **3905/tcp**

.. note::
    Default in ``/etc/imapd.conf``

    **3905/tcp** is the suggested default port for mupdate, as it is the default value specified for the **mupdate_port** option available in ``/etc/imapd.conf`` (generated from ``lib/imapoptions``). Note that when changing the suggested port for mupdate we recommend you also patch ``lib/imapoptions`` prior to building Cyrus IMAP.

* **sieve**

    * Description: *ManageSieve protocol*
    * IANA Port: **4190/tcp**

.. note::
    **Port 2000/tcp**

    **2000/tcp** is actually sieve-filter with description *Sieve Mail Filter Daemon*.

* **smmap**

    * Description: *Cyrus smmapd (quota check) service*
    * Suggested Port(s): **/tcp**
