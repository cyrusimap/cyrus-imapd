.. cyrusman:: ctl_mboxlist(8)

.. author: Nic Bernstein (Onlight)
.. author: Jeroen van Meeuwen (Kolab Systems)

.. _imap-reference-manpages-systemcommands-ctl_mboxlist:

================
**ctl_mboxlist**
================

Perform operations on the mailbox list database

Synopsis
========

.. parsed-literal::

    **ctl_mboxlist** [ **-C** *config-file* ] **-d** [ **-x** ] [**-y**] [ **-p** *partition* ] [ **-f** *filename* ]
    **ctl_mboxlist** [ **-C** *config-file* ] **-u** [ **-f** *filename* ] [ **-L** ]
    **ctl_mboxlist** [ **-C** *config-file* ] **-m** [ **-a** ] [ **-w** ] [ **-i** ] [ **-f** *filename* ]
    **ctl_mboxlist** [ **-C** *config-file* ] **-v** [ **-f** *filename* ]

Description
===========

**ctl_mboxlist** is used to perform various administrative operations on
the mailbox list database.

**ctl_mboxlist** |default-conf-text|
|def-confdir-text| mailboxes database.


Options
=======

.. program:: ctl_mboxlist

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -d, --dump

    Dump the contents of the database to standard output in JSON format.

.. option:: -x, --remove-dumped

    When performing a dump, remove the mailboxes dumped from the mailbox
    list (mostly useful when specified with **-p**).

.. option:: -y, --include-intermediaries

    When performing a dump, also list intermediary mailboxes which would
    be hidden from IMAP.

.. option:: -p partition, --partition=partition

    When performing a dump, dump only those mailboxes that live on
    *partition*.

.. option:: -f filename, --filename=filename

    Use the database specified by *filename* instead of the default
    (*configdirectory/mailboxes.db**).

.. option:: -L, --legacy

    When performing an undump, use the legacy dump parser instead of the
    JSON parser.  This might be useful for importing a dump produced
    by an older version of Cyrus.

.. option:: -u, --undump

    Load ("undump") the contents of the database from standard input.  The
    input MUST be a valid JSON file, unless the -L option is also supplied.

    .. IMPORTANT::
        USE THIS OPTION WITH CARE.  If you have modified the dump file since it
        was dumped, or if the file was not produced by **-d** in the first
        place, or was produced on a different server, you can easily break your
        mailboxes.db.  Undump will refuse to process a syntactically-invalid
        dump file, but it can't do much to protect you from a valid file
        containing bad data.

.. option:: -m, --sync-mupdate

    For backend servers in the Cyrus Murder, synchronize the local
    mailbox list file with the MUPDATE server.

.. option:: -a, --authoritative

    When used with **-m**, assume the local mailboxes file is authoritative,
    that is, only change the mupdate server, do not delete any local
    mailboxes.

    .. IMPORTANT::
        USE THIS OPTION WITH CARE, as it allows namespace collisions into
        the murder.

.. option:: -w, --warn-only

    When used with **-m**, print out what would be done but do not perform
    the operations.

.. option:: -i, --interactive

    When used with **-m**, asks for verification before deleting local
    mailboxes.

.. option:: -v, --verify

    Verify the consistency of the mailbox list database and the spool
    partition(s). Mailboxes present in the database and not located on a
    spool partition, and those located on a spool partition (directory
    containing a valid cyrus.header file) and not present in the database
    will be reported.  Note that this function is very I/O intensive.

Examples
========

.. parsed-literal::

    **ctl_mboxlist -d**

..

        Dump the mailboxes list to standard output in JSON format

.. parsed-literal::

    **ctl_mboxlist -u** < *newmboxlist.dump*

..

        Undump (restore) the mailboxes database from *newmboxlist.dump*,
        where *newmboxlist.dump* is a JSON file produced by **ctl_mboxlist -d**

        .. Note::
            Be very careful with this option.

.. parsed-literal::

    **ctl_mboxlist -m**

..

        Synchronize our mailboxes database with the MUPDATE server.  (One may
        commonly put a command like this into the **START** section of
        :cyrusman:`cyrus.conf(5)` on backend nodes of a Murder cluster to cause
        the backend to synchronize its mailbox list with the mupdate master upon
        startup).

.. only:: html

    ::

        START {
            ##
            # Master sends mailbox updates to mupdate.
            # Replication client runs on Master.
            # Comment these 2 lines out on replicas
            mupdatepush		cmd="/usr/lib/cyrus/bin/ctl_mboxlist -m"
            syncclient		cmd="/usr/lib/cyrus/bin/sync_client -r"
            <...>
        }
..

.. parsed-literal::

    **ctl_mboxlist -m -w**

..

        The same as above, but only show us what would be done, don't actually
        do it.

.. parsed-literal::

    **ctl_mboxlist -m -a**

..

        Populate the Mupdate server from our copy of the mailboxes database.

        .. Note::
            Be very careful with this option, as it can create conflicts in the
            Murder.

.. parsed-literal::

    **ctl_mboxlist -m -i**

..

        Synchronize our mailboxes database with the MUPDATE server interactively,
        asking for verification before deleting any local mailboxes.


Files
=====

/etc/imapd.conf, <configdirectory>/mailboxes.db

See Also
========

:cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`
