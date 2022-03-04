.. cyrusman:: cyr_ls(8)

.. author: Ken Murchison (Fastmail)

.. _imap-reference-manpages-systemcommands-cyr_ls:

==========
**cyr_ls**
==========

List Cyrus mailbox directory contents

Synopsis
========

.. parsed-literal::

    **cyr_ls** [ **-C** *config-file* ] [ **-l** ] [ **-m** ] [ **-R** ] [ **-1** ] [ *mailbox-name* ]

Description
===========

List information about the directory corresponding to the given
mailbox name (the current directory by default)

**cyr_ls** |default-conf-text| It uses <configdirectory>/mailboxes.db
to locate the mailboxes on disk.

Options
=======

.. program:: cyr_ls

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -l

    Use a long listing format.

.. option:: -m

    Output the path to the metadata files (if different from the
    message files).

.. option:: -R

    List submailboxes recursively.

.. option:: -1

    List one file per line.

Examples
========

.. parsed-literal::

    **cyr_ls** *user/jsmith*

..

        Display the directory contents for mailbox *user/jsmith*.

.. only:: html

    ::

        1.  cyrus.cache  cyrus.index  cyrus.header
        Sent             Trash

Files
=====

/etc/imapd.conf,
<configdirectory>/mailboxes.db

See Also
========

:cyrusman:`imapd.conf(5)`
