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

    **mbpath** [ **-C** *config-file* ] [ **-l** ] [ **-m** ] [ **-q** ] [ **-s** ] [ **-u** | **-p** ] [ **-a** | **-A** | **-M** | **-S** | **-U** ] [ *mailbox-names*... ]

Description
===========

Given a mailbox name or a space separated list of mailbox names,
**mbpath** outputs the filesystem path(s) of the mailbox.  By default,
the mailboxes' data partition paths are shown (same as **-D**).
See `Selectors`_ for selecting which filesystem path(s) to output.

**mbpath** |default-conf-text| It uses <configdirectory>/mailboxes.db
to locate the mailboxes on disk.

Options
=======

.. program:: mbpath

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -l

    Local mailboxes only (exits with error for remote or nonexistent mailboxes)

.. option:: -m

    Output the path to the metadata files (if different from the
    message files).  Legacy, use **-M**.

.. option:: -q

    Suppress any error output.

.. option:: -s

    If any error occurs, stop processing the list of mailboxes and exit.

.. option:: -u

    The specified *mailbox-names* are users, not mailboxes.

.. option:: -p

    The specified *mailbox-names* are UNIX mailbox paths, not mailboxes.

Selectors
=========

.. option:: -A

    Show the mailbox archive path

.. option:: -D

    Show the mailbox data path (*default*)

.. option:: -M

    Show the mailbox metadata path (same as **-m**)

.. option:: -S

    Show the user sieve scripts path

.. option:: -U

    Show the user files path (seen, sub, etc)

.. option:: -a

    Show all paths, as if all selectors were specified

Examples
========

.. parsed-literal::

    **mbpath** *user.jsmith*

..

        Display the data path for mailbox *user.jsmith*.

.. only:: html

    ::

        /var/spool/cyrus/user/jsmith

.. parsed-literal::

    **mbpath -M** *user.jsmith*

..

        Display the metadata path for mailbox *user.jsmith*.

.. only:: html

    ::

        /var/spool/meta/imap/user/jsmith

.. parsed-literal::

    **mbpath -u -S** *jsmith*

..

        Display the sieve scripts path for user *jsmith*.

.. only:: html

    ::

        /var/spool/sieve/j/jsmith

Files
=====

/etc/imapd.conf,
<configdirectory>/mailboxes.db

See Also
========

:cyrusman:`imapd.conf(5)`
