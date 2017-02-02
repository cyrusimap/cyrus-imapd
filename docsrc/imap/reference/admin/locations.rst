.. _imap-admin-locations:

==========================
File & Directory Locations
==========================

Cyrus IMAP maintains several directories for configuration, state and
data storage.  The locations of these directories and, in many cases,
of individual files, may be controlled by settings in
:cyrusman:`imapd.conf(5)`.

.. toctree::
    :maxdepth: 1
    :glob:

    locations/*

Partitions
==========

Partitioning is a means to divide storage resources into separate pools
and may be defined for the following types of data:

    * :ref:`imap-features-mail-spool-partitions`
    * :ref:`imap-features-metadata-partitions`
    * :ref:`cyrus-backups`
    * Archive Data

Please consult the documents linked above for more information on these.

You may also find more examples and possible scenarios in the
document on :ref:`imap-features-mailbox-distribution`.

In general, Cyrus allows one to maintain several separate partitions for
each of these data types, and to establish rules governing distribution
of data within each pool.

Working With Partitions
=======================

All partition operations are controlled via settings in
:cyrusman:`imapd.conf(5)`, and thus require server restarts to effect.
There are no administrative commands to manipulate partitions.

Here are the settings for each class of partition:

Mail Spool Partitions
---------------------

While Cyrus itself has no default values for these settings, most
distributions use ``default`` and ``/var/spool/imap`` or
``/var/spool/cyrus``:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob defaultpartition
        :end-before: endblob defaultpartition

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob partition-name
        :end-before: endblob partition-name

Metadata Partitions
-------------------

Metadata is information used to process the mailbox data, rather than
the contents of the messages withing the mailbox.  Examples include
headers, caches, indexes, etc.

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob metapartition-name
        :end-before: endblob metapartition-name

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob metapartition_files
        :end-before: endblob metapartition_files

Backup Partitions
-----------------

Cyrus Backups are a replication-based backup service for Cyrus IMAP servers.

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob backuppartition-name
        :end-before: endblob backuppartition-name

Archive Partitions
------------------

Cyrus Archiving will migrate mailbox data from the normal mail spool
partitions to separate archive partitions, based upon criteria such as
age and size.  Typical use cases would be to keep so-called "hot" data,
such as recent messages, on fast drives, such as SSDs, and migrate
"cold" data, such as older or large messages, to slower but cheaper
media.

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob archivepartition-name
        :end-before: endblob archivepartition-name

Back to :ref:`imap-admin`
