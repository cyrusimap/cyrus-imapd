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
    * :ref:`imap-features-archive-partitions`

Please consult the documents linked above for more information on these.

You may also find more examples and possible scenarios in the
document on :ref:`imap-features-mailbox-distribution`.

In general, Cyrus allows one to maintain several separate partitions for
each of these data types, and to establish rules governing distribution
of data within each pool.

Types of Partitions
-------------------

Cyrus supports several different types of partitions:

*   Mail Spool Partitions
*   Metadata Partitions
*   Archive Partitions
*   Search Partitions

Each of these are discussed in their own sections of the documentation.
All share in common a few aspects in how they are configured.  For each
partition defined, you must tell Cyrus where the partition is rooted in
the filesystem.  This is accomplished via a "*partition*-*name*:" directive
for each partition, where "*partition*" specifies the partition type and
"*name*" is the actual name of the partition.

Here are some sample declarations of each different type of partition
supported within Cyrus.  For the purposes of this example, we'll
stipulate the following:

*   There are two main storage pools, "fast" and "slow," which are on
    SSDs and traditional disks, respectively.
*   The mailboxes are divided alphabetically, with A to M in one group
    and N to Z in the other.

.. parsed-literal::

    # The Mail Spool Partitions
    partition-atom: /var/spool/cyrus/fast/mail/atom/
    partition-ntoz: /var/spool/cyrus/fast/mail/ntoz/

    # The Metadata Partitions
    metapartition-atom: /var/spool/cyrus/fast/meta/atom/
    metapartition-ntoz: /var/spool/cyrus/fast/meta/ntoz/

    # Archive Partitions
    archivepartition-atom: /var/spool/cyrus/slow/mail/atom/
    archivepartition-ntoz: /var/spool/cyrus/slow/mail/ntoz/

    # Search Partitions
    defaultsearchtier: tier1
    tier1searchpartition-atom: /var/spool/cyrus/slow/search/atom/
    tier1searchpartition-ntoz: /var/spool/cyrus/slow/search/ntoz/

Working With Partitions
=======================

All partition operations are controlled via settings in
:cyrusman:`imapd.conf(5)`, and thus require server restarts to effect.
There are no administrative commands to manipulate partitions.

Here are the settings for each class of partition:

Mail Spool Partitions
---------------------

While Cyrus itself has no default values for these settings, most
distributions use ``default`` and ``/var/spool/cyrus`` or
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

Search Partitions
-----------------

Modern Cyrus uses the Xapian search engine to index messages for
server-side search support.  Index data are stored in search "tiers"
which are themselves related to search partitions.  There are two key
settings for search tiers:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob defaultsearchtier
        :end-before: endblob defaultsearchtier

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob searchpartition-name
        :end-before: endblob searchpartition-name

Back to :ref:`imap-admin`
