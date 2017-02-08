.. _imap-admin-locations-spool:

Spool Directories
=================

Default Spool location
----------------------

The main Cyrus IMAP mail data directory structure is the spool, and its
location is defined by ``partition-name`` entries in
:cyrusman:`imapd.conf(5)`.

Additionally, on servers with more than one spool partition, that
partition in which new user mailboxes are to be created is specified by
the ``defaultpartition`` directive.

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob partition-name
        :end-before: endblob partition-name

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob defaultpartition
        :end-before: endblob defaultpartition

.. note::

    There is nothing magical about the name "default" and in fact any
    name may be used for the default-partition.  We'll use the name
    "main" in this documentation.

* Sample::

    defaultpartition: main
    partition-main: /var/spool/imap


Additional Spool locations
--------------------------

Multiple partitions may be used for various reasons, such as to
distribute load between different storage pools or technologies.  Please
consult :ref:`imap-features-mail-spool-partitions` for more details and
use cases.

To define additional mail spools, add more ``partition-name`` entries
to :cyrusman:`imapd.conf(5)` as needed.  Building on our sample, above,
for example:

* Sample::

    defaultpartition: main
    partition-main: /var/spool/imap
    partition-fast: /var/spool/imapfast
    partition-archive: /var/spool/imaparchive

Metadata Partitions
===================

In addition to the mailbox and message data, Cyrus stores various
metadata in the mail spool, such as indexes, annotations, etc.  It may
be useful in some circumstances to separate this metadata into its own
partitions.  For each partition to be split in this way, one must
define a metadata partition for each data partition, using the same
name, so Cyrus knows how to relate them to each other.

As well as specifying locations for the metadata, one must also tell
Cyrus which metadata files to place in these special partitions.  The
default behaviour is to locate *all* metadata in the data partition(s).

The configuration directives to do so are quite similar to
those for data partitions:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob metapartition_files
        :end-before: endblob metapartition_files

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob metapartition-name
        :end-before: endblob metapartition-name

Again, building on our examples above:

* Sample::

    defaultpartition: main
    partition-main: /var/spool/imap
    partition-fast: /var/spool/imapfast
    partition-archive: /var/spool/imaparchive
    metapartition_files: header index cache expunge squat annotations
    metapartition-main: /var/spool/imapmeta/main
    metapartition-fast: /var/spool/imapmeta/fast
    metapartition-archive: /var/spool/imapmeta/archive
