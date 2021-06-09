.. cyrusman:: relocate_by_id(8)

.. author: Ken Murchison (Fastmail)

.. _imap-reference-manpages-systemcommands-relocate_by_id:

==================
**relocate_by_id**
==================

Relocate mailbox trees by their mailbox ids

Synopsis
========

.. parsed-literal::

    **relocate_by_id** [ **-C** *config-file* ] [ **-n** ] [ **-q** ] [ **-u** ] [ *mailbox-names*... ]

Description
===========

Given a mailbox name or a space separated list of mailbox names,
**relocate_by_id** relocates the mailbox and its submailboxes to
directory trees hashed by mailbox id rather than hashed by mailbox name.

**relocate_by_id** |default-conf-text| It uses <configdirectory>/mailboxes.db
to locate the mailboxes on disk.

Options
=======

.. program:: relocate_by_id

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -n

    Do NOT make any changes.  Just list which directories will be relocated.

.. option:: -q

    Run quietly.  Suppress any error output.

.. option:: -u

    The specified *mailbox-names* are users, not mailboxes.
    User metadata directories will also be relocated.

Examples
========

.. parsed-literal::

    **relocate_by_id -u** *jsmith*

..

        Relocate all mailbox and metadata directories for user *jsmith*.

Files
=====

/etc/imapd.conf,
<configdirectory>/mailboxes.db

See Also
========

:cyrusman:`imapd.conf(5)`
