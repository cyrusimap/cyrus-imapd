.. cyrusman:: quota(8)

.. author: Jeroen van Meeuwen (Kolab Systems)
.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-quota:

=========
**quota**
=========

Report and optionally fix storage and message quota usage.

Synopsis
========

.. parsed-literal::

    **quota** [ **-C** *config-file* ] [ **-d** *domain* ] [ **-f** ] [ **-u** ] [ *mailbox-spec*... ]

Description
===========

**quota** generates a report listing quota roots, giving their limits and
usage.

If the **-f** option is specified, **quota** first fixes any
inconsistencies in the quota subsystem, such as mailboxes with the wrong
quota root or quota roots with the wrong quota usage reported.

If an optional *domain* is specified with the **-d** option, the quota
listing (and any inconsistency fixing) is performed only in that domain
rather than all mailboxes.

If one or more *mailbox-spec* arguments are specified, these are interpreted
as mailbox prefixes, and the quota listing (and inconsistency fixing) is
limited to quota roots with names that start with one of the given prefixes.
If the **-u** is provided, *mailbox-spec* arguments are instead interpreted
as userids, and the quota listing (and inconsistency fixing) is limited to
quota roots for only the specified users.

.. WARNING::

    Running **quota** with both the **-f** option and *mailbox-spec*
    arguments is not recommended.

**quota** |default-conf-text|

Options
=======

.. program:: quota

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -d domain, --domain domain

    List and/or fix quota only in *domain*.

.. option:: -f, --fix

    Detect and fix any inconsistencies in the quota subsystem before generating
    a report.

.. option:: -n, --report-only

    Check for any inconsistencies in the quota subsystem but don't actually
    fix them.  Use with **-f** and **-q** to only see what's incorrect.

.. option:: -q, --quiet

    Operate quietly. If **-f** is specified, then don't print the quota
    values, only print messages when things are changed.

.. option:: -J, --json

    Output the quota values as JSON for automated tooling support

.. option:: -u, --userids

    Interpret *mailbox-spec* arguments as userids.  The default is to
    interpret them as mailbox prefixes

.. option:: mailbox-spec

    Only report and/or fix quota in mailboxes matching the specified
    *mailbox-spec* arguments.  See also **-u**.

Examples
========

.. parsed-literal::

    **quota**

..

        List quotas for all users and mailboxes.

.. only:: html

    ::

        Quota     % Used     Used              Resource Root
        1048576       21   228429              STORAGE example.org!user.jane
                             9459              MESSAGE example.org!user.jane
                                1 X-ANNOTATION-STORAGE example.org!user.jane
                               26        X-NUM-FOLDERS example.org!user.jane
                           169791              STORAGE example.org!user.jane.Archive
                             4137              MESSAGE example.org!user.jane.Archive
                                0 X-ANNOTATION-STORAGE example.org!user.jane.Archive
                                1        X-NUM-FOLDERS example.org!user.jane.Archive
        1048576       42   448944              STORAGE example.org!user.john
                             9088              MESSAGE example.org!user.john
                                2 X-ANNOTATION-STORAGE example.org!user.john
                               35        X-NUM-FOLDERS example.org!user.john

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
