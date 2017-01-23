.. _imap-admin-locations-hashing:

Directory Hashing
=================

Cyrus IMAP uses directory hashing for per-user state information,
including quotas (with ``quota_db: quotalegacy``), sieve, subscriptions
and seen information.  Sites with lots of users may wish to hash their
mail spool, too.  Cyrus provides mechanisms for this.  This pair of
settings for :cyrusman:`imapd.conf(5)` control hashing behavior:

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob hashimapspool
	:end-before: endblob hashimapspool

.. include:: /imap/reference/manpages/configs/imapd.conf.rst
	:start-after: startblob fulldirhash
	:end-before: endblob fulldirhash

Regardless of those settings, the per-user state information will
always be hashed.
