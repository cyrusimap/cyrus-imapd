.. _imap-features-delayed-delete:

==============
Delayed Delete
==============

It is not uncommon for a folder or hierarchy of folders in IMAP to
contain large amounts of information -- after all, IMAP preserves a copy
of the messages on the server unless it is specifically deleted.

Three challenges arise when users delete folders especially if an
organization is required to comply with archiving regulations;

#.  How to restore the folder if the deletion was accidental?

#.  How to ensure the folder being deleted remains available for
    inclusion in the next backup cycle?

#.  The deletion of a hierarchy with a lot of messages can create an I/O
    storm unlinking many individual files and some directories.

Cyrus IMAP introduces *delayed deletion* of folders, which leaves the
deleted folder (or hierarchy thereof) on the filesystem, such that
purging the folder hierarchy from the filesystem;

*   becomes a separate event (perhaps triggered during the weekend),

*   can be delayed such that users have a chance to report accidental
    deletion and administrators can recover without requiring a restore
    from backup,

*   can be delayed as to ensure that the next backup cycle includes the
    deleted folder hierarchy.

-----------------------------------------
Configuring Cyrus IMAP for Delayed Delete
-----------------------------------------

To enable or disable Delayed Delete, please check the following settings
in :cyrusman:`imapd.conf(5)`.

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob delete_mode
        :end-before: endblob delete_mode

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob deletedprefix
        :end-before: endblob deletedprefix

.. seealso::

    *   :ref:`imap-features-delayed-expunge`
    *   :ref:`imap-admin-deleted-expired-expunged-purged`

Back to :ref:`imap-features`
