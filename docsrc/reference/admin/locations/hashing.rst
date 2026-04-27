.. _imap-admin-locations-hashing:

Directory Hashing
=================

Cyrus IMAP uses directory hashing for per-user state information,
including quotas (with :imapdconf:`quota_db: quotalegacy <quota_db>`),
sieve, subscriptions and seen information.  Sites with lots of users may
wish to hash their mail spool, too.  Cyrus provides mechanisms for this.

Hashing behaviour is controlled by the :imapdconf:`hashimapspool` and
:imapdconf:`fulldirhash` settings.

Regardless of those settings, the per-user state information will
always be hashed.
