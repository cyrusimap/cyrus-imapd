.. cyrusman:: idled(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-idled:

=========
**idled**
=========

Provide near real-time updates for IMAP IDLE

Synopsis
========

.. parsed-literal::

    **idled** [ **-C** *config-file* ]

Description
===========

**idled** is a long lived datagram daemon which receives notifications of
mailbox changes and signals the appropriate **imapd** to report the
changes to the client.

**Idled** is usually started from :cyrusman:`master(8)`.

**idled** |default-conf-text|

Options
=======

.. program:: idled

.. option:: -C config-file

    |cli-dash-c-text|

Examples
========

**idled** is commonly included in the DAEMON section of
:cyrusman:`cyrus.conf(5)` like so::

    DAEMON {
        idled                   cmd="/usr/lib/cyrus/bin/idled"
    }

With **wait=y**, :cyrusman:`master(8)` starts services only once
**idled** is ready to receive notifications.  See
:cyrusman:`cyrus.conf(5)`.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`,
:cyrusman:`cyrus.conf(5)`,
:cyrusman:`master(8)`
