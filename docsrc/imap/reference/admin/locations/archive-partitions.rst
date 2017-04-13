.. _imap-features-archive-partitions:

==================
Archive Partitions
==================

Archive partitions are defined by the ``archivepartition-name`` option
in :cyrusman:`imapd.conf(5)`:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob archivepartition-name
        :end-before: endblob archivepartition-name

As is the case with :ref:`metadata <imap-features-metadata-partitions>`
partitions, however, archive partitions do not stand alone.  They are
closely bound to :ref:`imap-admin-locations-spool` as defined by the
accompanying ``partition-name`` directive.

.. include:: /assets/mailspool-parts-explain.rst

So, to add archiving to the system described above, we would need
something like this (again, building on our previous examples):

* Sample::

    defaultpartition: main
    partition-main: /var/spool/imap
    partition-am: /var/spool/imap-am
    partition-nz: /var/spool/imap-nz
    partition-shared: /var/spool/imap-shared
    archive_enabled: yes
    archivepartition-main: /var/spool/imaparchive/main
    archivepartition-am: /var/spool/imaparchive/am
    archivepartition-nz: /var/spool/imaparchive/nz
    archivepartition-shared: /var/spool/imaparchive/shared
