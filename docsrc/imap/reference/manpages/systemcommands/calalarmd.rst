.. cyrusman:: calalarmd(8)

.. _imap-reference-manpages-systemcommands-calalarmd:

=============
**calalarmd**
=============

Daemon for sending calendar alarms

Synopsis
========

.. parsed-literal::

    **calalarmd** [ **-C** *config-file* ]

Description
===========

This man page is a stub.

**calalarmd** |default-conf-text|

Options
=======

.. program:: calalarmd

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -d

    Debug mode (doesn't fork)

.. option:: -t **time**

    Run a single scan as of **time**

.. option:: -U

    Upgrade

Examples
========

**calalarmd** is commonly included in the DAEMON section of
:cyrusman:`cyrus.conf(5)` like so::

    DAEMON {
        calalarmd			cmd="/usr/lib/cyrus/bin/calalarmd"
    }

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`cyrus.conf(5)`,
:cyrusman:`master(8)`
