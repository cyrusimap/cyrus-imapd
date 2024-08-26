.. _imap-admin-quotas:

======
Quotas
======

Cyrus IMAP features a flexible Quota scheme with support for limiting
various resources, such as storage or number of folders or messages.

.. toctree::
    :maxdepth: 1
    :glob:

    quotas/*

.. _imap-admin-quotas-repair:

Monitor and Repair
==================

Quotas may be monitored and repaired via the :cyrusman:`quota(8)`
command:

    * :ref:`imap-reference-manpages-systemcommands-quota`

.. _imap-admin-quotas-config:

Controlling Quota Behavior
==========================

How restrictive quotas will be may be tailored to the needs of different
sites, via the use of several settings in :cyrusman:`imapd.conf(5)`:

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob lmtp_over_quota_perm_failure
        :end-before: endblob lmtp_over_quota_perm_failure


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob lmtp_strict_quota
        :end-before: endblob lmtp_strict_quota


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quotawarnpercent
        :end-before: endblob quotawarnpercent


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quotawarnsize
        :end-before: endblob quotawarnsize


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quotawarnmsg
        :end-before: endblob quotawarnmsg


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob autocreate_quota
        :end-before: endblob autocreate_quota


    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob autocreate_quota_messages
        :end-before: endblob autocreate_quota_messages

.. _imap-admin-quotas-database:

Quota Database
==============

Quota information is stored either in a database (i.e. twoskip,
skiplist) or in "quotalegacy" format, which is a filesystem hierarchy.
This is controlled by the ``quota_db`` setting in
:cyrusman:`imapd.conf(5)`.  Here's more about the pertinent settings:

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quota_db
        :end-before: endblob quota_db

    .. include:: /imap/reference/manpages/configs/imapd.conf.rst
        :start-after: startblob quota_db_path
        :end-before: endblob quota_db_path

.. _imap-admin-quotas-convert-db:

Converting Quotas Database
==========================

The :cyrusman:`cvt_cyrusdb(8)` utility may be used to convert between
formats.  It's usage with ``quotalegacy`` is a special case, in that
the first argument ("<old db>") will be the path to the *base* of the
``quotalegacy`` directory structure, not to a particular file.

For example, given this typical layout:

::

    /var/lib/imap/
    |            /quota/
    |                  /A/
    |                    /user/
    |                         /bob/

The proper ``cvt_cyrusdb`` command would be:

::

    cvt_cyrusdb /var/lib/imap/quota quotalegacy /var/lib/imap/quotas.db twoskip

.. _imap-admin-quotas-end:

Back to :ref:`imap-admin`
