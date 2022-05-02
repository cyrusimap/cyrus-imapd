.. cyrusman:: ctl_conversationsdb(8)

.. author: Nic Bernstein (Onlight)

.. _imap-reference-manpages-systemcommands-ctl_conversationsdb:

=======================
**ctl_conversationsdb**
=======================

Perform operations on the conversations databases

Synopsis
========

.. parsed-literal::

    **ctl_conversationsdb** [ -C *config-file* ] **-d** *userid* > text
    **ctl_conversationsdb** [ -C *config-file* ] **-u** *userid* < text
    **ctl_conversationsdb** [ -C *config-file* ] [ **-v** ] [ **-z** | **-b** | **-R** ] *userid*
    **ctl_conversationsdb** [ -C *config-file* ] [ **-v** ] [ **-z** | **-b** | **-R** ] **-r**

Description
===========

**ctl_conversationsdb** is used to perform various administrative
operations on a conversations database and associated information in
*cyrus.index* files.

**ctl_conversationsdb** |default-conf-text|

|def-confdir-text| conversations database.

In the first synopsis, the **-d** option dumps the contents of a
conversations database to standard output in an ASCII format.  In the
second synopsis, the resulting *file* is fed back in, using the
**-u** option to "undump" from standard input.  This pair of commands
is useful for disaster recovery, or for changing the backend used to
store the conversations database.

The third synopsis is used to reconstruct conversations information
in various ways for a specific user, and the fourth to reconstruct
conversations information for all users.  See ``OPTIONS`` below for
details.

|v3-new-command|

Options
=======

.. program:: ctl_conversationsdb

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -d, --dump

    Dump the conversations database which corresponds to the user *userid*
    to standard output in an ASCII format.  The resulting file can be
    used to recreate a database using the **-u** option.

.. option:: -u, --undump

    "Undumps" the conversations database corresponding to the user *userid*,
    i.e. replaces all the entries with data from ASCII records parsed
    from standard input.  The output from the **-d** option can be used
    as input.

.. option:: -v, --verbose

    Be more verbose when running.

.. option:: -r, --recursive

    Be recursive; apply the main operation to every user.  Warning: do
    not combine with **-u**, it will not do what you expect.

.. option:: -z, --clear

    Remove all conversation information from the conversations database
    for user *userid*, and from all the user's mailboxes.  The
    information can all be recalculated (eventually) from message
    headers, using the **-b** option.

.. option:: -b, --rebuild

    Rebuild all conversation information in the conversations database
    for user *userid*, and in all the user's mailboxes, from the header
    information in messages.  Does not affect messages which already
    have conversation information.

    This is a bulk mode version of what happens to each message when it
    arrives, and can be used to add missing conversation information
    for past messages, e.g. after using **-z** or after upgrading
    Cyrus from older versions.  Note: this operation uses information
    from *cyrus.cache* files so it does not need to read every single
    message file.

.. option:: -R, --update-counts

    Recalculate counts of messages stored in existing conversations in
    the conversations database for user *userid*.  This is a limited
    subset of **-b**; in particular it does not create conversations or
    assign messages to conversations.

.. option:: -S, --split

    If given with **-b**, allows splitting of conversations during the
    rewrite.   Only do this if changing the maximum conversation size
    and you need to split those existing conversations.

Examples
========

[NB: Examples needed]

History
=======

|v3-new-command|

Files
=====

/etc/imapd.conf, <configurationdir>/conversations.db

See Also
========
:cyrusman:`imapd.conf(5)`, :cyrusman:`master(8)`
