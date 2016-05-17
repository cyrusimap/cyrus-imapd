.. _imap-features-delayed-expunge:

===============
Delayed Expunge
===============

When a user or IMAP client expunges a message or an entire folder,
messages become unavailable to the user.

When the deletion is accidental, administrators may have to recover the
messages from some place. When the messages are purposefully deleted,
the user may have done so not with the best of intentions.

In any case, the time between a message arriving and being deleted may
not be sufficient to ensure the message is replicated, included in the
next backup cycle, and generally available for recovery or compliance
with the regulatory environment.

Cyrus IMAP introduces *delayed expunge*, which ensures message files are
not immediately unlinked from the filesystem, and instead makes purging
the message files from the filesystem a separate event.

This enables administrators to quickly recover access to messages that
have been accidentally deleted, as well as allows the environment to
ensure messages remain available for includion in the next backup cycle.

------------------------------------------
Configuring Cyrus IMAP for Delayed Expunge
------------------------------------------

To enable or disable Delayed Expunge, please check the following
settings in :cyrusman:`imapd.conf(5)`.

    .. include:: /imap/admin/configs/imapd.conf.rst
        :start-after: startblob expunge_mode
        :end-before: endblob expunge_mode

.. seealso::

    *   :ref:`imap-admin-systemcommands-unexpunge`
    *   :ref:`imap-features-delayed-delete`
    *   :ref:`imap-admin-deleted-expired-expunged-purged`

Back to :ref:`imap-features`
