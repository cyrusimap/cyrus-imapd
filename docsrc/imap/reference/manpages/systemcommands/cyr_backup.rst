.. cyrusman:: cyr_backup(8)

.. _imap-reference-manpages-systemcommands-cyr_backup:

==============
**cyr_backup**
==============

Inspect contents of Cyrus backups.

Synopsis
========

.. parsed-literal::

    **cyr_backup** [OPTIONS] [MODE] *backup* list chunks
    **cyr_backup** [OPTIONS] [MODE] *backup* list mailboxes
    **cyr_backup** [OPTIONS] [MODE] *backup* list messages
    **cyr_backup** [OPTIONS] [MODE] *backup* list all
    **cyr_backup** [OPTIONS] [MODE] *backup* show mailboxes [ *mboxname* | *uniqueid* ]...
    **cyr_backup** [OPTIONS] [MODE] *backup* show messages *guid*...
    **cyr_backup** [OPTIONS] [MODE] *backup* dump chunk *id*
    **cyr_backup** [OPTIONS] [MODE] *backup* dump message *guid*
    **cyr_backup** [OPTIONS] [MODE] *backup* json chunks
    **cyr_backup** [OPTIONS] [MODE] *backup* json mailboxes
    **cyr_backup** [OPTIONS] [MODE] *backup* json messages
    **cyr_backup** [OPTIONS] [MODE] *backup* json headers *guid*...

Description
===========

**cyr_backup** is a tool for inspecting the contents of a Cyrus backup.

**cyr_backup** |default-conf-text|

In all invocations, *backup* is interpreted according to the specified MODE.
See :ref:`cyr-backup-modes` below.

**cyr_backup** provides the following sub-commands:

.. option:: list

    .. parsed-literal::
        **cyr_backup** [OPTIONS] [MODE] *backup* list chunks
        **cyr_backup** [OPTIONS] [MODE] *backup* list mailboxes
        **cyr_backup** [OPTIONS] [MODE] *backup* list messages
        **cyr_backup** [OPTIONS] [MODE] *backup* list all

    List chunks, mailboxes, or messages contained in *backup*.

.. option:: show

    .. parsed-literal::
        **cyr_backup** [OPTIONS] [MODE] *backup* show mailboxes [ *mboxname* | *uniqueid* ]...
        **cyr_backup** [OPTIONS] [MODE] *backup* show messages *guid*...

    **show mailboxes** shows the contents (i.e. the contained messages) of
    mailboxes matching each given *mboxname* or *uniqueid* in the named
    *backup*.  The uid, expunged time, and guid of each message are shown.

    **show messages** shows details of messages matching each given *guid* in
    the named *backup*.  The guid, containing mailboxes, and MIME headers of
    each message are shown.

.. option:: dump

    .. parsed-literal::
        **cyr_backup** [OPTIONS] [MODE] *backup* dump chunk *id*
        **cyr_backup** [OPTIONS] [MODE] *backup* dump message *guid*

    Dump the contents of the specified chunk or message contained in the named
    *backup* to standard out.  Chunks are output as uncompressed backup data
    format (which is a replication protocol stream).  Messages are output in
    their on-disk format (typically MIME).

    **dump chunk** is mainly useful for diagnostic purposes.

    **dump message** may be useful as part of a manual message restoration
    process, when the restoration destination does not support the
    :cyrusman:`restore(8)` command.

.. option:: json

    .. parsed-literal::
        **cyr_backup** [OPTIONS] [MODE] *backup* json chunks
        **cyr_backup** [OPTIONS] [MODE] *backup* json mailboxes
        **cyr_backup** [OPTIONS] [MODE] *backup* json messages
        **cyr_backup** [OPTIONS] [MODE] *backup* json headers *guid*...

    Dump information about the chunks, mailboxes or messages contained in the
    named *backup* to standard out, in JSON format.

.. _cyr-backup-options:

Options
=======

.. program:: cyr_backup

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -v, --verbose

    Increase the verbosity.  Can be specified multiple times.

.. _cyr-backup-modes:

Modes
=====

.. option:: -f, --filename

    *backup* is interpreted as a filename.  The named file does not need to be
    known about in the backups database.

.. option:: -m, --mailbox

    *backup* is interpreted as a mailbox name.  There must be a known backup
    for the user whose mailbox this is.

    Known backups are recorded in the database specified by the **backup_db**
    and **backup_db_path** configuration options.

.. option:: -u, --userid

    *backup* is interpreted as a userid.  There must be a known backup for
    the specified user.

    This is the default if no mode is specified.

Examples
========

History
=======

Files
=====

See Also
========

:cyrusman:`restore(8)`
