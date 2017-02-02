.. _imap-admin-locations-spool:

Spool Directories
=================

Default Spool location
----------------------

The main Cyrus IMAP mail data directory structure is the spool, and its
default location is defined by the ``defaultpartition`` and
``partition-default`` entries in :cyrusman:`imapd.conf(5)`.

Despite their similar names, these two configuration values have
distinct meanings.  The first is the name of the default spool
partition, the second is the path to it:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob defaultpartition
        :end-before: endblob defaultpartition

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob partition-name
        :end-before: endblob partition-name

.. note::

    There is nothing magical about the name "default" and in fact any
    name may be used for the default-partition.  We assume the name
    "default" in this documentation.

Multiple 
