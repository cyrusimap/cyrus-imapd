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
    partition-main: /var/spool/cyrus


Additional Spool locations
--------------------------

.. include:: /assets/mailspool-parts-explain.rst

Metadata Partitions
===================

.. include:: /assets/metadata-parts-explain.rst

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
    partition-main: /var/spool/cyrus
    partition-am: /var/spool/cyrus-am
    partition-nz: /var/spool/cyrus-nz
    partition-shared: /var/spool/cyrus-shared
    metapartition_files: header index cache expunge squat annotations
    metapartition-main: /var/spool/cyrusmeta/main
    metapartition-am: /var/spool/cyrusmeta/am
    metapartition-nz: /var/spool/cyrusmeta/nz
    metapartition-shared: /var/spool/cyrusmeta/shared
