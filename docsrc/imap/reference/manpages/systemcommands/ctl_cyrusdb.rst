.. cyrusman:: ctl_cyrusdb(8)

.. author: Nic Bernstein (Onlight)
.. author: Jeroen van Meeuwen (Kolab Systems)

.. _imap-reference-manpages-systemcommands-ctl_cyrusdb:

===============
**ctl_cyrusdb**
===============

Perform administrative operations directly on Cyrus IMAP databases.

Synopsis
========

.. parsed-literal::

    **ctl_cyrusdb** [ **-C** *config-file* ] **-c**
    **ctl_cyrusdb** [ **-C** *config-file* ] **-r** [ **-x** ]

Description
===========

**ctl_cyrusdb** is used to perform various administrative operations on
the Cyrus IMAP databases.

**ctl_cyrusdb** |default-conf-text|
|def-confdir-text| Cyrus databases.

Options
=======

.. program:: ctl_cyrusdb

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -r, --recover

    Recover the database after an application or system failure. Also
    performs database cleanups like removing mailbox reservations (and
    the associated mailbox files).

    All mailbox files are also checked to make sure the file format
    matches the configured database type in imapd.conf.  If not, the
    file is automatically converted using the same logic as cvt_cyrusdb.

    If the ``reverseacls`` option in :cyrusman:`imapd.conf(5)` is enabled,
    and the RACL entries in the database are an old version or do not
    exist, they will be generated.  Conversely, if RACL entries do exist
    in the database, but the ``reverseacls`` option is disabled, then the
    entries will be cleaned up.

.. option:: -x, --no-cleanup

    Used with ``-r`` to only recover the database, and prevent any
    cleanup.

.. option:: -c, --checkpoint

    Checkpoint and archive (a copy of) the database.

    Changes to the database which are part of the committed transactions
    are written to disk.

    The archive is created via a *hot* backup, and inactive log files
    are removed.

Examples
========

.. parsed-literal::

    **ctl_cyrusdb -r**

..

        Recover databases, performing cleanup.  This is commonly used in
        the **START** section of :cyrusman:`cyrus.conf(5)`.

.. only:: html

    ::

        START {
            # do not delete this entry!
            recover     cmd="/usr/local/bin/ctl_cyrusdb -r"
          <...>


.. parsed-literal::

    **ctl_cyrusdb -x -r**

..

        Recover database only.


.. parsed-literal::

    **ctl_cyrusdb -c**

..

        Checkpoint databases.  Commonly used in the **EVENTS** section of
        :cyrusman:`cyrus.conf(5)`.

.. only:: html

    ::

        EVENTS {
            # this is required
            checkpoint	cmd="/usr/local/bin/ctl_cyrusdb -c" period=30
          <...>

Files
=====
/etc/imapd.conf
/etc/cyrus.conf

See Also
========
:cyrusman:`cyrus.conf(5)`, :cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`
