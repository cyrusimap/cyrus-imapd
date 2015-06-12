.. _imap-admin-commands-ctl_cyrusdb:

===============
``ctl_cyrusdb``
===============

Perform administrative operations directly on Cyrus IMAP databases.

Synopsis
========

.. parsed-literal::

    ctl_cyrusdb [OPTIONS]

Description
===========

``ctl_cyrusdb`` is used to perform various administrative operations on
the Cyrus IMAP databases.


Options
=======

.. program:: ctl_cyrusdb

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -r

    Recover the database after an application or system failure. Also
    performs database cleanups like removing mailbox reservations (and
    the associated mailbox files).

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

See Also
========

    *   :manpage:`cyrus.conf(5)`
    *   :manpage:`imapd.conf(5)`
    *   :ref:`imap-admin-commands-cyrus-master`
