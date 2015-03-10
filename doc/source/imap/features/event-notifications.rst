===================
Event Notifications
===================

.. NOTE::

    Cyrus IMAP documentation is a work in progress. The completion of
    this particular part of the documentation is pending the resolution
    of :task:`43`.

:rfc:`5465` outlines an extension the IMAP NOTIFY extensions.

Available Event Notifications
=============================

*   :ref:`imap-features-event-notifications-aclchange`
*   :ref:`imap-features-event-notifications-flagsclear`
*   :ref:`imap-features-event-notifications-flagsset`
*   :ref:`imap-features-event-notifications-login`
*   :ref:`imap-features-event-notifications-logout`
*   :ref:`imap-features-event-notifications-mailboxcreate`
*   :ref:`imap-features-event-notifications-mailboxdelete`
*   :ref:`imap-features-event-notifications-mailboxrename`
*   :ref:`imap-features-event-notifications-mailboxsubscribe`
*   :ref:`imap-features-event-notifications-mailboxunsubscribe`
*   :ref:`imap-features-event-notifications-messageappend`
*   :ref:`imap-features-event-notifications-messagecopy`
*   :ref:`imap-features-event-notifications-messageexpire`
*   :ref:`imap-features-event-notifications-messageexpunge`
*   :ref:`imap-features-event-notifications-messagemove`
*   :ref:`imap-features-event-notifications-messagenew`
*   :ref:`imap-features-event-notifications-messageread`
*   :ref:`imap-features-event-notifications-messagetrash`
*   :ref:`imap-features-event-notifications-quotaexceed`
*   :ref:`imap-features-event-notifications-quotawithin`
*   :ref:`imap-features-event-notifications-quotachange`

Example Event Notifications
===========================

.. _imap-features-event-notifications-aclchange:

AclChange
---------

The ACL Change notification is emitted when a command ``SETACL`` is
issued.

.. literalinclude:: ../../_static/event_notifications/AclChange.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-flagsclear:

FlagsClear
----------

The FlagsClear notification is emitted when all flags are removed from a
message.

This includes ``\Deleted``, ``\Seen`` and ``\Flagged``, and as such are,
in part, the counter-parts to
:ref:`imap-features-event-notifications-messagetrash`,
:ref:`imap-features-event-notifications-messageread`, and
:ref:`imap-features-event-notifications-flagsset`.

.. TODO::

    *   Include an example event notification emitted for multiple
        messages being cleared the flags of.

    *   Include an example event notification emitted for multiple flags
        being cleared.

.. literalinclude:: ../../_static/event_notifications/FlagsClear.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-flagsset:

FlagsSet
--------

The FlagsSet notification is emitted when flags are set on a message,
but not including the ``\Deleted`` and ``\Seen`` flags, which emit
:ref:`imap-features-event-notifications-messagetrash` and
:ref:`imap-features-event-notifications-messageread` event notifications
respectively.

.. TODO::

    *   Include an example event notification emitted for multiple
        messages being set flags on.

    *   Include an example event notification emitted for multiple flags
        being set.

.. literalinclude:: ../../_static/event_notifications/FlagsSet.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-login:

Login
-----

.. literalinclude:: ../../_static/event_notifications/Login.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-logout:

Logout
------

.. literalinclude:: ../../_static/event_notifications/Logout.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxcreate:

MailboxCreate
-------------

.. literalinclude:: ../../_static/event_notifications/MailboxCreate.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxdelete:

MailboxDelete
-------------

.. literalinclude:: ../../_static/event_notifications/MailboxDelete.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxrename:

MailboxRename
-------------

.. literalinclude:: ../../_static/event_notifications/MailboxRename.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxsubscribe:

MailboxSubscribe
----------------

.. literalinclude:: ../../_static/event_notifications/MailboxSubscribe.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxunsubscribe:

MailboxUnSubscribe
------------------

.. literalinclude:: ../../_static/event_notifications/MailboxUnSubscribe.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messageappend:

MessageAppend
-------------

.. literalinclude:: ../../_static/event_notifications/MessageAppend.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messagecopy:

MessageCopy
-----------

.. literalinclude:: ../../_static/event_notifications/MessageCopy.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messageexpire:

MessageExpire
-------------

.. _imap-features-event-notifications-messageexpunge:

MessageExpunge
--------------

.. literalinclude:: ../../_static/event_notifications/MessageExpunge.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messagemove:

MessageMove
-----------

.. literalinclude:: ../../_static/event_notifications/NessageMove.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messagenew:

MessageNew
----------

.. literalinclude:: ../../_static/event_notifications/MessageNew.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messageread:

MessageRead
-----------

.. literalinclude:: ../../_static/event_notifications/MessageRead.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messagetrash:

MessageTrash
------------

.. literalinclude:: ../../_static/event_notifications/MessageTrash.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-quotaexceed:

QuotaExceed
-----------

.. _imap-features-event-notifications-quotawithin:

QuotaWithin
-----------

.. _imap-features-event-notifications-quotachange:

QuotaChange
-----------

Back to :ref:`imap-features`
