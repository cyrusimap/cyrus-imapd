.. _imap-admin-commands-arbitron:

============
``arbitron``
============

Report readership statistics for mailboxes on the server.

Synopsis
========

.. parsed-literal::

    arbitron [OPTIONS] mailbox...

Description
===========

Arbitron collects and reports readership statistics for mailboxes on the
server. It also optionally prunes the mailboxes of ``\Seen`` state for
dormant users.

Arbitron produces one line of output per mailbox, reporting the mailbox
name followed by a space, followed by the number of readers (and if
``-u`` is specified, followed by a colon and a comma-separated list of
the reader's user IDs), and if ``-o`` is not specified, another space
and the number of subscribers (and if ``-u`` is specified, followed by a
colon and a comma-separated list of the subscribers userids).

.. IMPORTANT::

    This format is subject to change in future versions.

Each "reader" is a distinct authorization identity which has the
:ref:`imap-admin-access-control-right-s` right to the mailbox and which
has ``SELECT``ed the mailbox within either the past ``days`` days or
the specified date range.

Users are not counted as reading their own personal mail‐boxes. Personal
mailboxes are not reported unless there is at least one reader other
than the mailboxes owner.

Arbitron reads its configuration options out of the
:manpage:`imapd.conf(5)` file unless specified otherwise by ``-C``.

Options
=======

.. program:: arbitron

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -o

    Report "the old way" -- not including subscribers.

.. option:: -l

    Enable long reporting.

.. option:: -d days

    Count as a reader an authorization identity which has used the
    mailbox within the past ``days`` days.

.. option:: -D mmddyyyy[:mmddyyyy]

    Count as a reader an authorization identity which has used the
    mailbox within the given date range.

    The start date and optionally the end date are specified as 2-digit
    month of the year, 2-digit day of the month, and 4-digit year.

    If the end date is not specified, the current system time will be
    used as the end time.

    .. NOTE::

        Please note that the date notation is very American.

.. option:: -p months

    Prune ``\Seen`` state for users who have not used the mailbox within
    the past ``months`` months. The default is infinity.

Examples
========

See Also
========

    *   :manpage:`imapd.conf(5)`
