.. cyrusman:: mbtool(8)

.. _imap-reference-manpages-systemcommands-mbtool:

==========
**mbtool**
==========

intro

Synopsis
========

.. parsed-literal::

    **mbtool** [ **-C** *config-file* ] **-r** *mailbox*...
    **mbtool** [ **-C** *config-file* ] **-t** *mailbox*...

Description
===========

**mbtool** is a tool for performing various actions on the indexes of a
list of mailboxes. The only actions currently supported are **-t**,
which will normalize the ``internaldate`` time stamp of each record in
the index to GMT, and **-r** which will create a new unique ID for each
mailbox.

Only one action may be given and at least mailbox must be listed.

It is intended that **mbtool** will be extended over time to perform
more such actions.

**mbtool** |default-conf-text|

Options
=======

.. program:: mbtool

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -t, --normalize-internaldate

    Normalize ``internaldate`` on all index records of all listed
    *mailbox*\ es to match the *Date:* header if they're off by more
    than a day, which can be used to fix up a mailbox which has been
    restored from backup and lost its internaldate information.

.. option:: -r, --new-uniqueid

    Create a new unique ID for all listed *mailbox*\ es.  Only works
    for legacy mailboxes.

Examples
========

.. parsed-literal::

    **mbtool -r** user.jsmith

..

        Create new UUID for mailbox *user.jsmith*.

.. parsed-literal::

    **mbtool -t** user.jsmith

..

        Normalize ``internaldate`` on all index records in 
        *user.jsmith*.

.. only:: html

    ::

        Working on user.jsmith...
        00000001: Tue, 08 Jul 2014 16:45:18 -0500 => Mon, 07 Jul 2014 20:44:18 +0000
        00000002: Tue Jul 08 16:45:13 CDT 2013 => Fri, 30 Aug 2013 19:46:03 +0000
        <...>

..


Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
