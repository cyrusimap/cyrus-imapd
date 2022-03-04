.. _imap-features-event-notifications:

===================
Event Notifications
===================

:rfc:`5423` standardizes the emission of message store event
notifications, and :rfc:`5465` outlines the IMAP NOTIFY extensions.

.. versionadded:: 2.5.0

Available Event Notifications
=============================

* Message Events
    *   :ref:`imap-features-event-notifications-messageappend`
    *   :ref:`imap-features-event-notifications-messagecopy`
    *   :ref:`imap-features-event-notifications-messageexpire`
    *   :ref:`imap-features-event-notifications-messageexpunge`
    *   :ref:`imap-features-event-notifications-messagemove`
    *   :ref:`imap-features-event-notifications-messagenew`
* Flag Events
    *   :ref:`imap-features-event-notifications-flagsclear`
    *   :ref:`imap-features-event-notifications-flagsset`
    *   :ref:`imap-features-event-notifications-messageread`
    *   :ref:`imap-features-event-notifications-messagetrash`
* Mailbox Events
    *   :ref:`imap-features-event-notifications-aclchange`
    *   :ref:`imap-features-event-notifications-mailboxcreate`
    *   :ref:`imap-features-event-notifications-mailboxdelete`
    *   :ref:`imap-features-event-notifications-mailboxrename`
* Subscription Events
    *   :ref:`imap-features-event-notifications-mailboxsubscribe`
    *   :ref:`imap-features-event-notifications-mailboxunsubscribe`
* Quota Events
    *   :ref:`imap-features-event-notifications-quotaexceed`
    *   :ref:`imap-features-event-notifications-quotawithin`
    *   :ref:`imap-features-event-notifications-quotachange`
* Calendar Events
    *   :ref:`imap-features-event-notifications-calendaralarm`
* Access Accounting
    *   :ref:`imap-features-event-notifications-login`
    *   :ref:`imap-features-event-notifications-logout`
* Apple Push
    *   :ref:`imap-features-event-notifications-applepushservice`


Example Event Notifications
===========================

.. _imap-features-event-notifications-aclchange:

AclChange
---------

The ACL Change notification is emitted when a command ``SETACL`` is
issued.

.. NOTE::

    This event notification is added to Cyrus IMAP outside of any RFC.

.. literalinclude:: ../../../_static/event_notifications/AclChange.json
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

.. literalinclude:: ../../../_static/event_notifications/FlagsClear.json
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

.. literalinclude:: ../../../_static/event_notifications/FlagsSet.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-login:

Login
-----

.. literalinclude:: ../../../_static/event_notifications/Login.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-logout:

Logout
------

.. literalinclude:: ../../../_static/event_notifications/Logout.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxcreate:

MailboxCreate
-------------

.. literalinclude:: ../../../_static/event_notifications/MailboxCreate.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxdelete:

MailboxDelete
-------------

.. NOTE::

    A mailbox deletion event notification is issued once for each top-
    level mailbox in a hierarchy being deleted.

..
    Mar 10 13:59:36 kolab notifyd[18204]: EVENT, , , ,  "{"event":"MailboxDelete","timestamp":"2015-03-10T13:59:36.279+01:00","service":"imaps","mailboxID":"imap://jane.doe@example.org@kolab.example.org/INBOX;UIDVALIDITY=1425991710","uri":"imap://jane.doe@example.org@kolab.example.org/INBOX;UIDVALIDITY=1425991710","pid":18210,"user":"cyrus-admin","vnd.cmu.sessionId":"kolab.example.org-18210-1425992375-1-10616182148387168471"}"

.. literalinclude:: ../../../_static/event_notifications/MailboxDelete.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxrename:

MailboxRename
-------------

.. literalinclude:: ../../../_static/event_notifications/MailboxRename.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxsubscribe:

MailboxSubscribe
----------------

.. literalinclude:: ../../../_static/event_notifications/MailboxSubscribe.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-mailboxunsubscribe:

MailboxUnSubscribe
------------------

.. literalinclude:: ../../../_static/event_notifications/MailboxUnSubscribe.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messageappend:

MessageAppend
-------------

.. literalinclude:: ../../../_static/event_notifications/MessageAppend.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messagecopy:

MessageCopy
-----------

.. literalinclude:: ../../../_static/event_notifications/MessageCopy.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messageexpire:

MessageExpire
-------------

.. _imap-features-event-notifications-messageexpunge:

MessageExpunge
--------------

.. literalinclude:: ../../../_static/event_notifications/MessageExpunge.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messagemove:

MessageMove
-----------

.. IMPORTANT::

    The ``MessageMove`` event is an event type not documented in an RFC.

.. literalinclude:: ../../../_static/event_notifications/MessageMove.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messagenew:

MessageNew
----------

.. literalinclude:: ../../../_static/event_notifications/MessageNew.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messageread:

MessageRead
-----------

.. literalinclude:: ../../../_static/event_notifications/MessageRead.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-messagetrash:

MessageTrash
------------

.. literalinclude:: ../../../_static/event_notifications/MessageTrash.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-quotachange:

QuotaChange
-----------

.. NOTE::

    This event may be followed by a
    :ref:`imap-features-event-notifications-quotawithin` event
    notification, if the quota change leads the quota root to allow more
    resources than currently in use.

.. literalinclude:: ../../../_static/event_notifications/QuotaChange.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-quotaexceed:

QuotaExceed
-----------

The ``user`` parameter in the event notification is the user to whom the
quota applies, that is being exceeded, otherwise known as the owner of
the :ref:`imap-features-namespaces-personal`.

.. NOTE::

    Quota being exceeded on shared folders cannot include an "owner" for
    the quota root.

.. literalinclude:: ../../../_static/event_notifications/QuotaExceed.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-quotawithin:

QuotaWithin
-----------

The ``QuotaWithin`` event typically follows a
:ref:`imap-features-event-notifications-mailboxdelete` [#]_,
:ref:`imap-features-event-notifications-messageexpunge` [#]_,
:ref:`imap-features-event-notifications-messagemove` [#]_, or
:ref:`imap-features-event-notifications-quotachange` [#]_.

.. literalinclude:: ../../../_static/event_notifications/QuotaWithin.json
    :language: json
    :linenos:

.. rubric:: Footnotes for QuotaWithin

.. [#]

    A ``QuotaWithin`` event follows a ``MailboxDelete`` event if the
    mailbox deleted resides inside a quota root, and lowers the
    resources used to below the existing quota thresholds.

.. [#]

    A ``QuotaWithin`` event follows a ``MessageExpunge`` event if the
    messages purged reside inside a quota root, and amount to a number
    or size that lowers the amount of resources used to below the
    existing quota thresholds.

.. [#]

    A ``QuotaWithin`` event follows a ``MessageMove`` event if the
    source folder of the messages moved resides inside a quota root, and
    the target folder to which the messages have been moved does not
    reside within the same quota root, and the number or size of the
    messages moves lowers the amount of resources used in the quota root
    for the source folder of the messages to below the existing
    quota thresholds.

.. [#]

    A ``QuotaWithin`` event follows a ``QuotaChange`` event if the quota
    change raised the threshold on the amount of resources used within
    the quota root to a level higher than the existing amount of
    resources used.

.. _imap-features-event-notifications-calendaralarm:

CalendarAlarm
-------------

The ``CalendarAlarm`` event occurs when a calendar event triggers an
alarm.

.. literalinclude:: ../../../_static/event_notifications/CalendarAlarm.json
    :language: json
    :linenos:

.. _imap-features-event-notifications-applepushservice:

ApplePushService
----------------

While Cyrus supports the Apple Push Service, Apple has only licensed Apple Push
for mail to a couple of large mail providers: Fastmail and Yahoo. If you own an
OS X Server license, you also get a key for personal use. But it's not
a supported option for third party developers at this time.

The ``ApplePushService`` event occurs when

.. literalinclude:: ../../../_static/event_notifications/ApplePushService.json
    :language: json
    :linenos:

apsVersion
    Version of the Apple Push Service this message is compliant with.

apsAccountId
    Service Provider's accountID with the Apple Push Service.

apsDeviceToken
    Unique identifier for the user's device registered with Apple.

apsSubtopic
    TODO: describe this

Back to :ref:`imap-features`
