.. cyrusman:: jmap_expire(8)

.. author: Robert Stepanek (Fastmail)

.. _imap-reference-manpages-systemcommands-jmap_expire:

===============
**jmap_expire**
===============

Expire stale JMAP data such as calendar event notifications.

Synopsis
========

.. parsed-literal::

    **jmap_expire** [ **-C** *config-file* ]
    [ **-E** *notif-expire-duration* ]
    [ **-X** *notif-unlink-duration* ]
    [ **-h** or **--help**]
    [ **-l** or **--lock** *lock-duration*]
    [ **-u** *username* ]
    [ **-v** ]

Description
===========

**jmap_expire** is used to run a number of regular maintenance tasks for
JMAP mailboxes and databases, specifically:

- expires and unlinks JMAP CalendarEventNotification objects

**jmap_expire** requires at least one of the **-E -X** optionss.

Option arguments that denote durations may be specified using any
combination of zero or positive integers with the following units:
seconds `s`, minutes `m`, hours `h`, days `d` (a 24 hour day without leap second).
For example, the value `1d3m2s` denotes a duration of one day, three
minutes and 2 seconds. The default unit is seconds.

Options
=======

.. program:: jmap_expire

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -E duration, --notif-expire=duration

    Flags JMAP notifications in the *jmapnotificationfolder* mailbox as
    expired if their creation time is older than *duration*.

    The duration must be zero or positive. Setting this flag causes the
    JMAP notification to not be visible anymore to JMAP methods, but preserves
    them on the file system. This is required to allow Cyrus replica to
    synchronize their state. Also see the **--notif-unlink** option.

.. option:: -X duration, --notif-unlink=duration

    Removes already previously expired JMAP notifications in the
    *jmapnotificationfolder* mailbox if their last modification time
    is older than *duration*.  This unlinks the notification from the file
    system and is not reversible.

    The duration must be zero or positive and should be higher than the
    synchronization interval of any Cyrus replica.

.. option:: -h, --help

    Show help information how to use this program.

.. option:: -l --lock=duration

    Attempt to lock a mailbox at most *duration* seconds for each
    operation (e.g expire, unlink). Without this option, each
    mailbox is exclusively locked as long as it takes to complete
    the requested operation. For large mailboxes, this may get other
    processes stuck waiting for the mailbox. With this option, the
    mailbox typically is unlocked after the given duration, but this
    can not be guaranteed for mailboxes with hundreds of thousands
    of entries.

    The duration must be at least one second and at most one hour.

    Any remaining work for the operation and mailbox is left until
    the next execution of jmap_expire.

.. option:: -u username, --user=username

    Only process JMAP data belonging to this user, e.g.  "someone@example.com".
    Multiple occurrences of this option cause **jmap_expire** to operate on
    all given user names.

.. option:: -v, --verbose

    Enable verbose output. Multiple occurrences of this option increase
    the verbosity level, up to 3 times.

Examples
========

.. parsed-literal::

    **jmap_expire** **-E** *7d* **-X** *1d*

..

        Expire JMAP notifications for all users where the notification
        was created one week ago or earlier. Expunge all notifications
        that were expired until yesterday.

.. parsed-literal::

    **jmap_expire** **--notif-expire**=*1d* **--lock=2s** **-u** *me@example.com*

..

        Expire JMAP notifications in the *jmapnotificationfolder* mailbox
        of user *me@example.com*. Release the mailbox lock after at most
        2 seconds and leave any remaining work for future runs of **jmap_expire**.

History
=======

This was introduced in Cyrus version 3.7.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`
