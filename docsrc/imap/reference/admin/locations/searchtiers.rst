.. _imap-admin-searchtiers:

Search Tiers
============

The Xapian search engine supports searching from multiple databases at
once, creating a tiered database structure.  To use Xapian, these tiers
must be defined in :cyrusman:`imapd.conf(5)` with the
`defaultsearchtier` and `searchpartition-name` settings.

Default Search Tier name
------------------------

Specify the name of the default search tier using the `defaultsearchtier`
setting:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob defaultsearchtier
        :end-before: endblob defaultsearchtier

Search Tier Partition location
------------------------------

Each search tier to be used requires a partition location be specified
via a `searchpartition-name` setting, wherein "name" is replaced
with the name of the mail spool for which this search partition is to
be used, and prepended by the name of the tier with which it is
associated::

    {tier}searchpartition-{spool}

Again, building on our examples from :ref:`imap-admin-locations-spool`,
here we have three spool partitions defined, so we need three search
partitions for each tier.  In this example, with just a single tier, we
will be adding three search partitions.

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
    search_engine: xapian
    search_index_headers: no
    search_batchsize: 8192
    defaultsearchtier: temp
    tempsearchpartition-main: /var/spool/search/main
    tempsearchpartition-am: /var/spool/search/am
    tempsearchpartition-nz: /var/spool/search/nz
    tempsearchpartition-shared: /var/spool/search/shared

These settings are in :cyrusman:`imapd.conf(5)`:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob searchpartition-name
        :end-before: endblob searchpartition-name
