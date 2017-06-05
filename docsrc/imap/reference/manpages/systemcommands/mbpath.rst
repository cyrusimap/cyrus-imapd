.. cyrusman:: mbpath(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-mbpath:

==========
**mbpath**
==========

Translate mailbox names to filesystem paths

Synopsis
========

.. parsed-literal::

    **mbpath** [ **-C** *config-file* ] [ **-q** ] [ **-s** ] [ **-m** ] [ *mailbox-names*... ]

Description
===========

Given a mailbox name or a space separated list of mailbox names,
**mbpath** outputs the filesystem path to the mailbox.


**mbpath** |default-conf-text| It uses <configdirectory>/mailboxes.db
to locate the mailbox on disk.

Options
=======

.. program:: mbpath

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -q

    Suppress any error output.

.. option:: -s

    If any error occurs, stop processing the list of mailboxes and exit.

.. option:: -m

    Output the path to the metadata files (if different from the
    message files).

Examples
========

.. parsed-literal::

    **mbpath** *user.jsmith*

..

        Display the path for mailbox *user.jsmith*.

.. only:: html

    ::

        /var/spool/cyrus/user/jsmith

.. parsed-literal::

    **mbpath -m** *user.jsmith*

..

        Display the metadata path for mailbox *user.jsmith*.

.. only:: html

    ::

        /var/spool/meta/imap/user/jsmith

Files
=====

/etc/imapd.conf,
<configdirectory>/mailboxes.db

See Also
========

:cyrusman:`imapd.conf(5)`
