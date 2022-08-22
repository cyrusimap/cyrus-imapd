.. cyrusman:: cyr_userseen(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-cyr_userseen:

================
**cyr_userseen**
================

is used to clear seen state information for the mail store.

..  warning::

    This command *does not* take a constraining argument but acts on the
    *entire* mail store, removing *all* user seen state for all
    mailboxes and all users.

Synopsis
========

.. parsed-literal::

    **cyr_userseen** [ **-C** *config-file* ] [ **-d** ]

Description
===========

**cyr_userseen** will clear all user seen state for the mail store.

Running without any options will show what *would* be done, but will
not actually alter existing state.

**cyr_userseen** |default-conf-text|

Options
=======

.. program:: cyr_userseen

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -d, --delete

    Actually delete all user seen state information.

Examples
========

.. parsed-literal::

    **cyr_userseen**

..

        Display what would be changed were the **-d** flag used.

.. only:: html

    ::

        removing seen for bovik on user.bovik
        removing seen for bovik on user.bovik.Archives
        removing seen for bovik on user.bovik.Archives.2011
        removing seen for bovik on user.bovik.Archives.2012
        removing seen for bovik on user.bovik.Archives.2014
        removing seen for bovik on user.bovik.Deleted Messages
        removing seen for bovik on user.bovik.Drafts
        removing seen for bovik on user.bovik.Junk
        removing seen for bovik on user.bovik.Sent
        removing seen for bovik on user.bovik.Templates
        removing seen for bovik on user.bovik.Trash

..

.. parsed-literal::

    **cyr_userseen -d**

..

        Delete all user seen state for all mailboxes in mail store.

Files
=====

/etc/imapd.conf

See Also
========

:cyrusman:`imapd.conf(5)`
