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
command.

.. _imap-admin-quotas-config:

Controlling Quota Behavior
==========================

How restrictive quotas will be may be tailored to the needs of different
sites, via the use of several settings in :cyrusman:`imapd.conf(5)`:

    * :imapdconf:`lmtp_over_quota_perm_failure`
    * :imapdconf:`lmtp_over_quota_perm_failure`
    * :imapdconf:`lmtp_strict_quota`
    * :imapdconf:`quotawarnpercent`
    * :imapdconf:`quotawarnsize`
    * :imapdconf:`quotawarnmsg`
    * :imapdconf:`autocreate_quota`
    * :imapdconf:`autocreate_quota_messages`

.. _imap-admin-quotas-database:

Quota Database
==============

Quota information is stored either in a database (i.e. twoskip,
skiplist) or in "quotalegacy" format, which is a filesystem hierarchy.
This is controlled by the :imapdconf:`quota_db` and
:imapdconf:`quota_db_path` settings in
:cyrusman:`imapd.conf(5)`.

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
