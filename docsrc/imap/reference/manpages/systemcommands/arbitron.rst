.. cyrusman:: arbitron(8)

.. author: Nic Bernstein (Onlight)
.. author: Jeroen van Meeuwen (Kolab Systems)

.. _imap-reference-manpages-systemcommands-arbitron:

============
**arbitron**
============

Report readership statistics for mailboxes on the server.

Synopsis
========

.. parsed-literal::

    **arbitron** [ **-C** *config-file* ] [ **-o** ] [ **-u** ] [ **-l** ] [ **-p** *months* ]
             [ **-d** *days* | **-D** *mmddyyyy*\ [\ **:**\ *mmddyyyy*] ] *mailbox*...

Description
===========

**arbitron** collects and reports readership statistics for mailboxes
on the server. It also optionally prunes the mailboxes of ``\Seen``
state for dormant users.

**arbitron** produces one line of output per mailbox, reporting the
mailbox name followed by a space, followed by the number of readers
(and if **-u** is specified, followed by a colon and a comma-separated
list of the reader's user IDs), and if **-o** is not specified, another
space and the number of subscribers (and if **-u** is specified,
followed by a colon and a comma-separated list of the subscribers
userids).

.. IMPORTANT::

    This format is subject to change in future versions.

Each "reader" is a distinct authorization identity which has the
:ref:`imap-admin-access-control-right-s` right to the mailbox and which
has **SELECT**\ ed the mailbox within either the past **-d** *days* or
the specified **-D** *date*\ [\ **:**\ *range*\ ].

Users are not counted as reading their own personal mail‐boxes. Personal
mailboxes are not reported unless there is at least one reader other
than the mailboxes owner.

**arbitron** |default-conf-text|

Options
=======

.. program:: arbitron

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -D mmddyyyy[:mmddyyyy], --date=mmddyyyy[:mmddyyyy]

    Count as a reader an authorization identity which has used the
    mailbox within the given date range.

    The start date and optionally the end date are specified as 2-digit
    month of the year, 2-digit day of the month, and 4-digit year.

    If the end date is not specified, the current system time will be
    used as the end time.

    .. NOTE::

        Please note that the date notation is American [\ *mmddyyyy*\ ]
        not [\ *ddmmyyyy*\ ].

.. option:: -d days, --days=days

    Count as a reader an authorization identity which has used the
    mailbox within the past *days* days.

.. option:: -l, --detailed

    Enable long reporting (comma delimited table consisting of mbox,
    userid, r/s, start time, end time).

.. option:: -o, --no-subscribers

    Report "the old way" -- not including subscribers.

.. option:: -p months, --prune-seen=months

    Prune ``\Seen`` state for users who have not used the mailbox within
    the past *months* months. The default is infinity.

.. option:: -u, --include-userids

    Include userids of mailbox readers in the report.  If the report
    will contain mailbox subscribers (see **--no-subscribers**), also
    include userids of the subscribers.

Examples
========

.. parsed-literal::

    **arbitron -l**

..

        Long-format list.

.. only:: html

    ::

        tech.Commits,john,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.archive,mary,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.archive,john,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.archive,sam,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-1,john,r,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-1,mary,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-1,john,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-1,sam,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-2,mary,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-2,john,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-2,sam,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-3,mary,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-3,john,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-3,sam,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.project-3,todd,s,04-28-2015 09:45:35,05-28-2015 09:45:35
        tech.Commits.Other,mary,r,04-28-2015 09:45:20,05-28-2015 09:45:20
        tech.Commits.Other,john,r,04-28-2015 09:45:20,05-28-2015 09:45:20
        tech.Commits.Other,mary,s,04-28-2015 09:45:20,05-28-2015 09:45:20
        tech.Commits.Other,john,s,04-28-2015 09:45:20,05-28-2015 09:45:20
        tech.Commits.Other,sam,s,04-28-2015 09:45:20,05-28-2015 09:45:20

.. parsed-literal::

    **arbitron -o**

..

        Old format (no subscribers) short list.

.. only:: html

    ::

        tech.Commits 0
        tech.Commits.archive 0
        tech.Commits.project-1 1
        tech.Commits.project-1 0
        tech.Commits.project-1 0
        tech.Commits.Other 2

.. parsed-literal::

    **arbitron**

..

        Normal short list.

.. only:: html

    ::

        tech.Commits 0 2
        tech.Commits.archive 0 4
        tech.Commits.project-1 1 4
        tech.Commits.project-2 0 4
        tech.Commits.project-3 0 5
        tech.Commits.Other 2 4

.. parsed-literal::

    **arbitron -d** *14*

..

        Normal short list format for the past *14* days.

.. only:: html

    ::

        tech.Commits 0 2
        tech.Commits.archive 0 4
        tech.Commits.project-1 1 4
        tech.Commits.project-2 0 4
        tech.Commits.project-3 0 5
        tech.Commits.Other 2 4

.. parsed-literal::

    **arbitron -D** *04012015*\ :\ *04152015*

..

        Normal short list Within date range of 12 - 15 April, 2015.

.. only:: html

    ::

        tech.Commits 0 2
        tech.Commits.archive 0 4
        tech.Commits.project-1 0 4
        tech.Commits.project-2 1 4
        tech.Commits.project-3 0 5
        tech.Commits.Other 0 4

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
