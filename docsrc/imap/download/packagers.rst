Notes for Packagers
===================

Binary naming
-------------

Prevent namespace clashes. We suggest renaming all binaries with ``cyr_`` at
the front, including renaming the ``ctl_*`` to ``cyr_``.

The Cyrus team are looking to fix this in the core bundle in upcoming releases
so packagers have less to do.

Sample configuration files
--------------------------

There are several samples of :cyrusman:`cyrus.conf(5)` and
:cyrusman:`imapd.conf(5)` located in the ``doc/examples`` directory of
the distribution tarball.  Please install these to your preferred
documentation directory (i.e. ``/usr/share/doc/cyrus-imapd``) as a
reference for your users.

Predefined configurations
-------------------------

The configuration file for master: cyrus.conf
`````````````````````````````````````````````

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
```````````````````````````````````````````````````````````

The sample :cyrusman:`imapd.conf(5)` files must be adapted for use from
site to site.  Here, therefore, we'll attempt to point you towards some
reasonable settings which take advantage of recent improvements and
features, and may help guide you and your users to a better performing
Cyrus installation.

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

A new stable series means the defaults for some settings may have changed.
Please consult :ref:`upgrade` for details.

New or improved features
########################

A new stable series means new features, and improvements to existing features.
Some of these may be features which previously were not considered ripe for
packaging, but merit new consideration.

Please see :ref:`imap-release-notes-3.2` for details, and consider enabling
these features in the :cyrusman:`imapd.conf(5)` you ship in your packages.

Services in ``/etc/services``
-----------------------------

Listing named services through ``/etc/services`` aids in cross-system
consistency and cross-platform interoperability. Furthermore, it enables
administrators and users to refer to the service by name (for example in
``/etc/cyrus.conf``, 'listen=mupdate' can be specified instead of
'listen=3905').

Some of the services Cyrus IMAP would like to see available through
``/etc/services`` have not been assigned an IANA port number, and few have
configuration options.

..  include:: /assets/services.rst
