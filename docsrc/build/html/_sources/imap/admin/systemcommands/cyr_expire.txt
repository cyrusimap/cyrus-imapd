.. _imap-admin-systemcommands-cyr_expire:

==============
**cyr_expire**
==============

Expire messages and duplicate delivery database entries

Synopsis
========

.. parsed-literal::

    **cyr_expire** [ **-C** *config-file* ] [ **-A** *archive-duration* ]
    [ **-D** *delete-duration* ] [ **-E** *expire-duration* ] [ **-X** *expunge-duration* ]
    [ **-p** *mailbox-pre‐fix* ] [ **-u** *username* ] [ **-t** ] [ **-v** ]

Description
===========

**cyr_expire** is used to run a number of regular maintenance tasks
on Cyrus databases, specifically:

- expire messages from mailboxes, and
- expire entries from the duplicate delivery database, and
- cleanse mailboxes of partially expunged messages (when using the "delayed" expunge mode), and
- remove deleted mailboxes (when using the "delayed" delete mode), and
- expire entries from conversations databases.

The expiration of messages is controlled by the
``/vendor/cmu/cyrus-imapd/expire`` mailbox annotation which specifies
the age (in days) of messages in the given mailbox that should be
deleted.  A value of 0 means that no expiration is to be performed on
that mailbox.

The value of the ``/vendor/cmu/cyrus-imapd/expire`` annotation is
inherited by all children of the mailbox on which it is set, so an
entire mailbox tree can be configured by setting a single annotation on
the root of that tree.  If a mailbox does not have a
``/vendor/cmu/cyrus-imapd/expire`` annotation set on it (or does not
inherit one), then no messages are expired from the mailbox.

The annotation can be examined using the **info** command of
:cyrusman:`cyradm(8)`, and modified using the **mboxconfig** and
**setinfo** commands of :cyrusman:`cyradm(8)`.

Expiration of duplicate delivery database entries for a given mailbox
is also controlled by the ``/vendor/cmu/cyrus-imapd/expire`` annotation
which applies to that mailbox.  Unlike message expiration, if no
annotation applies to the mailbox then duplicate database entries are
expired using the value given to the **-E** option.

Expiration of conversations database entries occurs if the
**conversations** option is present in :cyrusman:`imapd.conf(5)`.
Expiration can be disabled using the **-c** option.  The period used to
expire entries is controlled by the **conversations_expire_days**
option in :cyrusman:`imapd.conf(5)`.

**cyr_expire** |default-conf-text|

**cyr_expire** requires at least one of **-A -D -E -X** or **-t** to be
supplied.

Options
=======

.. program:: cyr_expire

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -A archive-duration

    Archive non-flagged messages older than *archive-duration* to the
    archive partition, allowing mailbox messages to be split between fast
    storage and slow large storage.  Only does anything if
    ``archivepartition-*`` has been set in your config.

    |v3-new-feature|

.. option:: -D delete-duration

    Remove previously deleted mailboxes older than *delete-duration*
    (when using the "delayed" delete mode).
    The value can be a floating point number, and may have a suffix to
    specify the unit of time.  If no suffix, the value is number of days.
    Valid suffixes are **d** (days), **h** (hours), **m** (minutes) and
    **s** (seconds).

.. option:: -E expire-duration

    Prune the duplicate database of entries older than *expire-duration*.
    This value is only used for entries which do not have a corresponding
    ``/vendor/cmu/cyrus-imapd/expire`` mailbox annotation.
    Format is the same as delete-duration.

.. option:: -X expunge-duration

    Expunge previously deleted messages older than *expunge-duration*
    (when using the "delayed" expunge mode).
    Format is the same as delete-duration.

.. option:: -c

    Do not expire conversation database entries, even if the conversations
    feature is enabled.

    |v3-new-feature|

.. option:: -x

    Do not expunge messages even if using delayed expunge mode.  This
    reduces IO traffic considerably, allowing ``cyr_expire`` to be run
    frequently to clean up the duplicate database without overloading
    the machine.

.. option:: -p mailbox-prefix

    Only find mailboxes starting with this prefix,  e.g.
    "user.justgotspammedlots".

.. option:: -u userid

    Only find mailboxes belonging to this user,  e.g.
    "justgotspammedlots@example.com".

.. option:: -t

    Remove any user flags which are not used by remaining (not expunged)
    messages.

.. option:: -v

    Enable verbose output.

.. option:: -a

    Skip the annotation lookup, so all ``/vendor/cmu/cyrus-imapd/expire``
    annotations are ignored entirely.  It behaves as if they were not
    set, so only *expire-days* is considered for all mailboxes.

Examples
========

.. parsed-literal::

    **cyr_expire -E** *3* **-D** *60* **-X** *60*

..

        Purge duplicates database of all entries older than *3* days, remove
        deleted mailboxes older than *60* days and deleted messages older than
        *60* days.


.. parsed-literal::

    **cyr_expire -x -c -A** *7d*

..

        Perform migration of message older than *7* days to Archive
        partition whilst not altering conversation database nor
        expunging messages.

History
=======

Archive partition and conversation support was first introduced in Cyrus
version 3.0.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`, :cyrusman:`cyradm(8)`
