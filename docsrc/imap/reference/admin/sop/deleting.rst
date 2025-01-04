.. _imap-admin-sop-restoring-expunged-messages:

============================================
Deleting and Undeleting Messages and Folders
============================================

Terminology & Definitions
=========================

This section clarifies some of the subtle nuances between delete,
expunge and expire in different contexts, used throughout this chapter.

Message context
---------------

Delete

    sets the ``\Deleted`` flag on the message using
    ``STORE +Flags \Deleted`` via IMAP client

Expunge

    delete messages from the cyrus folder index that have the
    ``\Deleted`` flag set using EXPUNGE via IMAP client. With
    ``expunge_mode: delayed``, this doesn't delete the file from
    the filesystem.

Unexpunge

    recover messages into the cyrus folder index based on filesystem
    content (only possible with ``expunge_mode: delayed``)

Undelete

    remove the ``\Deleted`` flag on the message using
    ``STORE -Flags \Deleted`` via IMAP client.

Folder context
--------------

Delete

    deletes the folder and all messages inside it using ``DELETE``
    via IMAP client. If using ``delete_mode: delayed``, this renames
    the folder, rather than deletes the folder, as discussed below.

    Otherwise, the folder and messages are removed from the mailbox
    list and the filesystem.

Undelete

    rename the deleted folder back to the original location using
    ``renamemailbox`` in ``cyradm``.

Expiring Deleted Messages and Folders
=====================================

In the EVENTS block of cyrus.conf, you should have a line similar to the
following::

    delprune  cmd="cyr_expire -E 1 -D 7 -X 7 -a" at=2300

-D 7

    permanently deletes from the filesystem mailboxes and folders that
    were deleted more than 7 days ago.

-E 1

    prunes entries older than 1 day from the duplicate delivery
    suppression database.

-X 7

    permanently deletes from the filesystem expunged messages that were
    expunged more than 7 days ago.

To use delayed deletion of mailboxes, you need the following entry in
:cyrusman:`imapd.conf(5)`:

.. parsed-literal::

    delete_mode: delayed

.. versionadded:: 2.3.9

The default prefix for deleted mailboxes is ``DELETED`` but it probably
doesn't hurt to specify it in :cyrusman:`imapd.conf(5)` as well:

.. parsed-literal::

    deletedprefix: DELETED

.. versionadded:: 2.3.9

Undeleting Folders
==================

The following assumes that you are using the UNIX hierarchy separator.
If it's off then replace '/' in the names with '.'

With the previous configuration options in place, whenever a mail folder
or mailbox is deleted, it will be renamed to
``DELETED/mailfoldername/4D5C6B7A`` where ``4D5C6B7A`` is a hex-encoded
timestamp and ``DELETED`` is the prefix for deleted mailboxes.

``4D5C6B7A`` can be converted back to a human-readable time using a
simple one-liner in Perl:

.. parsed-literal::

    $ :command:`perl -le 'print scalar(localtime(hex("4D5C6B7A")));'`
    Thu Feb 17 00:27:38 2011

.. NOTE::

    The ACL on the deleted folder remains the same so undeleting it is
    as simple as renaming it as a sub-folder of the recreated mailbox or
    back to the original folder name depending on whether the mailbox
    has been recreated or not. If you have to add an ACL to be able to
    delete the mailbox, you may wish to remove the ACL after the
    undelete has been finished.

The following examples assume a mailbox for john@example.org has been
deleted:

.. parsed-literal::

    cyradm> :command:`listmailbox user/john*@example.org`

If there's no output from the above command, the mailbox has not been
recreated since being deleted and you can rename the mailbox and any
folders back to the original name as follows. If the mailbox has been
recreated, you will probably want to rename the deleted folders into a
subfolder of the new mailbox, for example
``user/john/4D88AF31@example.org`` becomes
``user/john/restored@example.org`` and
``user/john/Sent/4D88AF34@example.org`` becomes
``user/john/restored/Sent@example.org``

In either case the commands are similar but with the latter option you
need to insert the extra "/restored" after the ``user/john``:

.. parsed-literal::

    cyradm> :command:`listmailbox DELETED/user/john*@example.org`
    DELETED/user/john/4D88AF31@example.org (\HasNoChildren)
    DELETED/user/john/Drafts/4D88AF34@example.org (\HasNoChildren)
    DELETED/user/john/Sent/4D88AF34@example.org (\HasNoChildren)
    DELETED/user/john/Trash/4D88AF35@example.org (\HasNoChildren)
    cyradm> :command:`renamemailbox DELETED/user/john/4D88AF31@example.org user/john@example.org`
    cyradm> :command:`renamemailbox DELETED/user/john/Drafts/4D88AF34@example.org user/john/Drafts@example.org`
    cyradm> :command:`renamemailbox DELETED/user/john/Sent/4D88AF34@example.org user/john/Sent@example.org`
    cyradm> :command:`renamemailbox DELETED/user/john/Trash/4D88AF35@example.org user/john/Trash@example.org`

Unfortunately there's no easy way to rename the entire mailbox back
including all the subfolders and the hex timestamp can vary between
folders in the same mailbox if it was a mailbox with some large folders.

This is because it's the time that particular folder was deleted, not
when the first folder was deleted.

Undeleting messages in a mailbox
================================

The following examples assume you have an installation of cyrus where
there are binaries in ``/usr/lib/cyrus-imapd/`` - if not, adjust path to
suit.

List messages available to unexpunge:

.. parsed-literal::

    # :command:`/usr/lib/cyrus-imapd/unexpunge -l user/john@example.org`

Each message will give you something like the following:

.. parsed-literal::

    UID: 11422
        Size: 7786
        Sent: Mon Mar 10 12:00:00 2014
        Recv: Mon Mar 10 16:06:32 2014
        Expg: Mon Mar 10 16:53:55 2014
        From: john doe <john.doe@example.org>
        To  : <info-cyrus@lists.andrew.cmu.edu>
        Cc  :
        Bcc :
        Subj: {44}
    re: some random subject of length 44 chars."

To unexpunge a single message:

.. parsed-literal::

    # :command:`/usr/lib/cyrus-imapd/unexpunge -udv user/john@example.org 11422`
    restoring expunged messages in mailbox 'user/john@example.org'
    Unexpunged user/john@example.org: 11422 => 11438
    restored 1 expunged messages

To unexpunge all the messages and mark them as undeleted as well:

.. parsed-literal::

    # :command:`/usr/lib/cyrus-imapd/unexpunge -adv user/john@example.org`

.. NOTE::

    This isn't recursive. It will only restore the messages in the
    folder specified.

To find other folders, :ref:`imap-reference-manpages-systemcommands-ctl_mboxlist` can be
used.

.. parsed-literal::

    # :command:`/usr/lib/cyrus-imapd/ctl_mboxlist -d | grep example.org`
    example.org!user.john    0 default john@example.org   lrswipkxtecda
    example.org!user.john.Lists  0 default john@example.org   lrswipkxtecda
    example.org!user.john.Lists.cyrus    0 default john@example.org   lrswipkxtecda
    example.org!user.john.Deleted Messages   0 default john@example.org   lrswipkxtecda

.. TODO::

    The above output format no longer applies.

Run the unexpunge command for every folder that needs to have mail
undeleted.

For folder names that have spaces ' ', the spaces need to be escaped
with a backslash.

.. parsed-literal::

    # :command:`/usr/lib/cyrus-imapd/unexpunge -adv user/john/Deleted\ Messages@example.org`
