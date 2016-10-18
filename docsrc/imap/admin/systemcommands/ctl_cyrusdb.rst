.. _imap-admin-systemcommands-ctl_cyrusdb:

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

.. option:: -r

    Recover the database after an application or system failure. Also
    performs database cleanups like removing mailbox reservations (and
    the associated mailbox files).

    All mailbox files are also checked to make sure the file format
    matches the configured database type in imapd.conf.  If not, the
    file is automatically converted using the same logic as cvt_cyrusdb.

.. option:: -x

    Used with ``-r`` to only recover the database, and prevent any
    cleanup.

.. option:: -c

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
