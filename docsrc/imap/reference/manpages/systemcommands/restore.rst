.. cyrusman:: restore(8)

.. program:: restore

.. _imap-reference-manpages-systemcommands-restore:

===========
**restore**
===========

Restore content from Cyrus backups.

Synopsis
========

.. parsed-literal::

    **restore** [OPTIONS] *server* [MODE] *backup* [ *mboxname* | *uniqueid* | *guid* ]...

Description
===========

**restore** is a tool for restoring messages and mailboxes from a Cyrus backup
to a Cyrus IMAP server.  It must be run from the server containing the backup
storage.

**restore** |default-conf-text|

*server* specifies the destination server to which content should be restored.
It should be of the form '*host*\ [:\ *port*\ ]', where *host* is either a
hostname, an IPv4 address, or an IPv6 address, and where the optional *port* is
either a known service name (see :manpage:`services(5)`) or a decimal port
number.  If *port* is omitted, ``imap`` will be tried first, followed by
``csync``.

The destination server must point to either an :cyrusman:`imapd(8)` instance
with the replication capability enabled, or a :cyrusman:`sync_server(8)`
instance.  In either case it must be Cyrus version 3.0 or newer.

**restore** will authenticate to the destination server according to the
**restore_authname**, **restore_password** and **restore_realm** configuration
options.  The credentials should correspond with one of the destination
server's **admins**.

*backup* is interpreted according to the specified MODE.
See :ref:`restore-modes` below.

If neither **-a** nor **-F** options were provided, then the remaining
arguments constitute a list of objects to be restored.  These may be mailboxes
(specified by either *mboxname* or *uniqueid*) or messages (specified by their
*guid*).  The objects may be specified in any order, and both mailboxes and
individual messages may be restored in one go.  :cyrusman:`cyr_backup(8)` can
be used to identify objects to restore from a Cyrus backup.

Selected mailboxes will have their messages restored to a mailbox of the same
name, which will be created if necessary.  Individually-selected messages will
be restored to the mailboxes in which they previously existed.  In both cases
the **-M** option can be used to override the destination mailbox (see below),
but note the consequences of doing this when multiple mailbox objects have
been specified, or when the **-r** option is in use.

Mailboxes that are created during the restoration process will have their ACL
set to the one stored in the backup.  The **-A** option can be used to override
this.  Mailboxes that are not created during the restoration process (i.e. when
restoring into mailboxes that already exists) will not have their ACLs altered.

Options
=======

.. option:: -A [acl], --override-acl[=acl]

    Apply specified *acl* to restored mailboxes, rather than their ACLs as
    stored in the backup.

    If *acl* is the empty string (e.g. ``-A ""``) or is unspecified, mailboxes
    will be restored with the default ACL for their destination owner.  This
    is mostly useful when restoring folders from one user's backup into a
    different user's mailbox.

.. option:: -C config-file

    |cli-dash-c-text|

.. option:: -D, --keep-deletedprefix

    Don't trim **deletedprefix** from mailbox names prior to restoring.  This
    is mainly useful for rebuilding failed servers, where deleted mailboxes
    should be restored as deleted mailboxes, not as new ones.

    The default is to trim the prefix before restoring.

    If the original server from which the backups were produced had
    **delete_mode** set to *immediate*, then the mailboxes in the backup will
    not have such a prefix, and this option won't have any useful effect.

    See :cyrusman:`imapd.conf(5)` for information about the **deletedprefix**
    and **delete_mode** configuration options.

.. option:: -F input-file, --input-file=input-file

    Get the list of mailboxes or messages from *input-file* instead of from
    the command line arguments.

    *input-file* should contain one object specification (either an *mboxname*,
    a *uniqueid*, or a *guid*) per line.  Empty lines, and lines beginning with
    a '#' character, are ignored.

.. option:: -L, --local-only

    Local operations only.  Actions required to restore the requested mailboxes
    and messages will be performed on the destination server only.
    :cyrusman:`mupdate(8)` actions will not occur.

    The default is for mupdate actions to occur if the destination server is
    part of a murder.

    This option has no effect if the destination server is not part of a murder.

.. option:: -M mboxname, --dest-mailbox=mboxname

    Messages are restored to the mailbox with the specified *mboxname*.  If no
    mailbox of this name exists, one will be created.

    If multiple mailbox objects are to be restored, whether due to being
    specified on the command line, in an *input-file*, or via the **-r**
    option, then the collective contents of all such mailboxes will be
    restored to the single mailbox *mboxname*.  This may not be what you want!

    The default when restoring mailboxes is to restore their respective
    contents into mailboxes of the same names.

    The default when restoring individual messages is to restore them into
    their original mailboxes.

.. option:: -P partition, --dest-partition=partition

    Restore mailboxes to the specified *partition*

.. option:: -U, --keep-uidvalidity

    Try to preserve uidvalidity and other related fields, such that the
    restored mailboxes and messages appear like they never left, and IMAP
    clients can avoid expensive state updates.

    This can only occur if the mailboxes to be restored **do not** already
    exist on the destination server.  As such, this option is mainly useful
    when rebuilding a failed server.

    If the destination mailboxes already exist, restored messages will be
    appended as if newly delivered, regardless of whether the **-U** option
    was specified.

.. option:: -X, --skip-expunged

    Do not restore messages that are marked as expunged in the *backup*.

    See also **-x**.

.. option:: -a, --all-mailboxes

    Try to restore all mailboxes in the specified *backup*.

.. option:: -n, --dry-run

    Do nothing.  The work required to perform the restoration will be
    calculated (and reported depending on verbosity level), but no
    restoration will take place, and no connection will be made to
    the destination server.

    Note that the *server* argument is still mandatory with this option.

.. option:: -r, --recursive

    Recurse into submailboxes.  When restoring mailboxes, also restore
    any mailboxes contained within them.

    The default is to restore only explicitly-specified mailboxes.

.. option:: -v, --verbose

    Increase the verbosity level.  This option can be specified multiple times
    for additional verbosity.

.. option:: -w seconds, --delayed-startup=seconds

    Wait *seconds* before starting.  This is useful for attaching a debugger.

.. option:: -x, --only-expunged

    Only restore messages that are marked as expunged in the *backup*.

    This can be convenient for restoring messages that were accidentally
    deleted by the user, without needing to track down individual message
    guids.

    See also **-X**.

.. option:: -z, --require-compression

    Require compression for server connection.  The restore will abort
    if compression is unavailable.

.. _restore-modes:

Modes
=====

.. option:: -f backup, --file=backup

    *backup* is interpreted as a filename.  The named file does not need to be
    known about in the backups database.

.. option:: -m backup, --mailbox=backup

    *backup* is interpreted as a mailbox name.  There must be a known backup
    for the user whose mailbox this is.

    Known backups are recorded in the database specified by the **backup_db**
    and **backup_db_path** configuration options.

.. option:: -u backup, --userid=backup

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

:cyrusman:`imapd.conf(5)`,
:manpage:`services(5)`,
:cyrusman:`cyr_backup(8)`,
:cyrusman:`imapd(8)`,
:cyrusman:`mupdate(8)`,
:cyrusman:`sync_server(8)`
