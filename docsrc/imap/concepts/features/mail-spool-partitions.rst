.. _imap-features-mail-spool-partitions:

=====================
Mail Spool Partitions
=====================

.. NOTE::

    Cyrus IMAP documentation is a work in progress. The completion of
    this particular part of the documentation is pending the resolution
    of :task:`44`.

A mail spool is divided in partitions. The partition Cyrus IMAP ships
with by default is called ``default``.

Partitions can give you the oppoprtuniy to tier your storage, and/or use
multiple filesystems to apply restrictions to information (contained
within mailboxes), such as the absolute maximum quantity of storage
used.

.. seealso::

    *   :ref:`imap-deployment-storage`
    *   :ref:`imap-features-mailbox-distribution`

Storage Tiering with Partitions
===============================

As an example, one could imagine a set of disks configured as follows:

*   Some small but fast (expensive) disks for the main storage array,
*   Some large but slow (cheap) disks for archives.

Mounting a filesystem on the fast disks under
:file:`/var/spool/imap/fast/`, and mounting a filesystem on the slow
disks under :file:`/var/spool/imap/slow/`, you could configure the
following in :cyrusman:`imapd.conf(5)`:

.. parsed-literal::

    defaultpartition: fast
    partition-fast: /var/spool/imap/fast/
    partition-slow: /var/spool/imap/slow/

Next, you could set the quota on ``user/john@example.org`` to a measely
1 gigabyte:

.. parsed-literal::

    $ :command:`cyradm -u localhost`
    verify error:num=18:self signed certificate
    IMAP Password:
    localhost> :command:`sq user/john@example.org 1048576`

You could then also give *John* a mailbox ``Archive`` for him to clean
up his :ref:`imap-features-namespaces-personal` without loosing access
to his existing mail:

.. parsed-literal::

    $ :command:`cyradm -u localhost`
    verify error:num=18:self signed certificate
    IMAP Password:
    localhost> :command:`cm user/john/Archive@example.org slow`
    localhost> :command:`sq user/john/Archive@example.org none`

*John* now has unlimited storage in his ``Archive`` folder on the cheap
slow disks, while his day-to-day email is on the expensive fast disks.

Restricting Storage Used with Partitions
========================================

.. IMPORTANT::

    It is not recommended to use partitions for the purposes of
    restricting the amount of storage used by (sets of) mailboxes,
    unless you can also grow the filesystem (preferrably online) and you
    have (automated) means to determine what is to end up on each
    partition.

If a customer ``example.org`` purchases 5 GB of storage, and
``example.com`` purchases 500 GB of storage, then two partitions sized
5 GB and 500 GB respectively could be used to restrict the users of each
customers without individually restricting each user (to a percentage of
the total storage).

.. WARNING::

    Monitoring the storage used is critical, because actually running
    out of disk space is very costly -- and not a problem the customer
    themselves could recover from.

Back to :ref:`imap-features`
