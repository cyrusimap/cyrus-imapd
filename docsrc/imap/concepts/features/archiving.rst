.. _imap-features-archiving:

=========
Archiving
=========

Description
===========

When we talk about "Archiving" in Cyrus (from 3.0 onwards) we're not
talking about data retention, what we're really talking about is
time-tiered storage.  Elsewhere in these documents we discuss
:ref:`storage tiering <imap-deployment-storage-performance>` based on
things like space limitations or :ref:`scalability
<imap-deployment-storage-scalability>`.  Archiving is somewhat like
this, but with an accompanying configuration syntax which determines
the management of the tiered data on an ongoing basis.

Purpose
=======

The general intent of archiving, as deployed within Cyrus, is to allow
administrators to dictate that there be two tiers of data storage for
each mail spool partition: "current" and "archive."  The common use case
is to use higher speed storage media for the former, and lower cost
media for the latter; Current goes on SSDs, and Archive goes on
traditional spinning media.

Enabling
========

Archive operation in Cyrus is enabled via the ``archive_enabled``
setting in :cyrusman:`imapd.conf(5)`:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob archive_enabled
        :end-before: endblob archive_enabled

Defining
========

The configuration suite provides directives to define these partitions:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob archivepartition-name
        :end-before: endblob archivepartition-name

Controlling
===========

And to control the criteria used to manage migration of data between
partitions:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob archive_after
        :end-before: endblob archive_after

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob archive_maxsize
        :end-before: endblob archive_maxsize

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob archive_keepflagged
        :end-before: endblob archive_keepflagged

.. note::

    Further explanation is probably required for the
    ``archive_maxsize`` option.  The value is a threshold.  Messages
    larger than this threshold will be immediately put onto the archive
    partition, rather than waiting ``archive_days`` number of days.
    This is to keep the high speed storage available for the largest
    number of "current" messages.

    So ``archive_maxsize`` is not the maximum size of messages which
    will be archived, but rather is the threshold above which they will
    immediately be.

Performing
==========

Finally, the actual migration is handled by invoking
:cyrusman:`cyr_expire(8)` with its ``-A`` flag, as shown here in
a sample snippet from :cyrusman:`cyrus.conf(5)` (but could also be done
via ``cron``)::

    EVENTS {
        ...
        archive      cmd="cyr_expire -A 7d" at=0403
        ...
    }
