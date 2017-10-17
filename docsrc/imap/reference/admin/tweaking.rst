===================
Tweaking Cyrus IMAP
===================

.. _admin-tweaking-cyrus-imapd-storage-tiering:

Storage Tiering
===============

Various opportunities exist to tier storage. With storage
tiering, we mean to distribute payload over different levels of storage,
where levels mean to refer to storage cost, performance and capacity, in
a way that makes optimal use of the storage solution(s) -- with an eye
on excellent performance yet remain cost-effective.

Imagine that you have the following levels of storage:

*   A **low-cost** solution with large capacity,

    such as many consumer-grade 4 TB HDDs,

*   A **high-cost** solution with little capacity,

    such as a few business-grade 512 GB SSDs.

The following options are available to split up the payload for a Cyrus
IMAP server:

#.  Partitioning the mail spool;

    where you divide a single backend server's mail spool in to multiple
    :term:`partitions`, presumably at least two, and make sure that
    mail folders end up on the correct partition.

    You would have one partition mounted off of the fast storage contain
    the *day-to-day* payload, such as user's INBOX folders, while the
    partition mounted off of the slower, cheap storage holds less
    frequently used data, such as archive folders.

    .. seealso::

        *   :ref:`admin-tweaking-cyrus-imap-storage-tiering-partitioning`

#.  Distributing the mail spool;

    where you would have one server hold *day-to-day* payload, and other
    servers hold less frequently used data, such as archive folders.

    Note that distribution of the mail spool requires a Cyrus IMAP
    Murder topology, so that access to the mailboxes remains
    transparent.

    Also note that such archive folders may be hosted using not only
    a low-cost storage tier, but perhaps also using a less resourceful
    compute node.

    .. seealso::

        *   :ref:`admin-tweaking-cyrus-imap-storage-tiering-distributing`

#.  Caching I/O using `dm-cache`_;

    This mechanism is a feature of Linux distributions that ship a
    kernel version of 3.9 or later, called `dm-cache`_, and allows
    multiple disk volumes to be used as tiered caching storage.

    Using this technology, frequently accessed data can automatically be
    promoted to the fast storage, while less frequently accessed data
    can automatically be demoted to the cheaper storage.

#.  Using metadata partitions;

    While the access patterns for data and metadata are different, so
    could their storage locations be.

    In this scenario, you would distinguish between a mail folder's
    message content and metadata -- the metadata consists of mail
    headers, indexes created for the purpose of searching, and such,
    while mail messages are stored in separate files.

    When a mail folder is opened, and the messages in the folder are
    listed, no mail message content is touched -- the results come
    entirely from metadata.

    It is only when the individual mail message is being fetched, that
    the message file is opened.

.. _admin-tweaking-cyrus-imap-storage-tiering-partitioning:

Partitioning the Mail Spool
---------------------------

.. _admin-tweaking-cyrus-imap-storage-tiering-distributing:

Distributing the Mail Spool
---------------------------

.. _admin-tweaking-cyrus-imap-storage-tiering-metadata:

Using Metadata Partitions
-------------------------

Synchronous File Operations
===========================

A default Kolab Groupware installation comes with a set of settings
suitable for the vast majority of our users -- mostly home users and
other small(er) deployments.

It is typical for these installations to **not** have battery-backed I/O
controllers, and/or some other form of enterprise-level storage.

To prevent data from being corrupted during a power outage, the default
for our Cyrus IMAP packages is to ensure the mail spool
(:file:`/var/spool/cyrus/`) and configuration directory
(:file:`/var/lib/imap/`) and all files contained therein have the
*synchronous* filesystem flag set.

To gain performance, execute the following:

#.  Remove the synchronous flag from the directories and files:

    .. parsed-literal::

        :command:`chattr -RV -S /var/lib/imap/ /var/spool/cyrus/`

#.  In :file:`/etc/sysconfig/cyrus-imapd` (or
    :file:`/etc/default/cyrus-imapd`), change the following:

    .. parsed-literal::

        CHATTRSYNC=1

    to:

    .. parsed-literal::

        CHATTRSYNC=0

.. _dm-cache: http://en.wikipedia.org/wiki/Dm-cache


Mailbox locking
---------------
Cyrus IMAP uses fcntl(2) based file locking for mailboxes, for example during
SELECT commands. To mitigate race conditions it locks mailbox names even
for non-existing mailboxes. For example, if user foo issued the following
command

    .. parsed-literal::

       SELECT INBOX.x

for non-existing mailbox x, it creates a lock file

    .. parsed-literal::

       $CYRUS_CONFDIR/lock/user/foo/x.lock

which might be left on the filesystem after completion of the command.

This has in practice not shown to be an issue. If this is a concern however,
keeping the lock file directory in a tmpfs allows for both fast locking and
to purge stale locks during controlled Cyrus downtimes.
