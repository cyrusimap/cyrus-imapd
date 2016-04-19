.. _cyrus-eventsource:

==================
Cyrus Event Source
==================

Overview
========

Cyrus can be configured to send events to another program any time something changes in a mailbox. The event contains details about the type of action that occurred, identifying information about the message and other useful information. Cyrus generates events for pretty much everything – every user action, data change, and other interesting things like calendar alarms. 

The notifications are compliant with :rfc:`5423`, though Cyrus includes some additional events outside of the RFC.

By default, Cyrus ships with :cyrusman:`notifyd(8)` which listens for events from Cyrus. Mostly it is used for sending email notifications triggered by Sieve scripts, or by calendar alarms triggered by ``calalarmd``.

Compile options
===============

You can control what kind of events Cyrus generates during the ``configure`` step of compilation.

**--enable_event_notification**: Set this to "yes" to have Cyrus generate mailbox related events. This is enabled by default.

**--enable-apple-push-service**: Set this to "yes" to enable support for the Apple Push service. This is *disabled* by default.

Configuration options
=====================

These need to be set in :cyrusman:`imapd.conf(5)`.

.. include:: configs/imapd.conf.rst
        :start-after: startblob event_content_inclusion_mode
        :end-before: endblob event_content_inclusion_mode
        
.. include:: configs/imapd.conf.rst
        :start-after: startblob event_content_size
        :end-before: endblob event_content_size
 
.. include:: configs/imapd.conf.rst
        :start-after: startblob event_exclude_flags
        :end-before: endblob event_exclude_flags 

.. include:: configs/imapd.conf.rst
        :start-after: startblob event_exclude_specialuse
        :end-before: endblob event_exclude_specialuse 

.. include:: configs/imapd.conf.rst
        :start-after: startblob event_extra_params
        :end-before: endblob event_extra_params 

.. include:: configs/imapd.conf.rst
        :start-after: startblob event_groups
        :end-before: endblob event_groups 

.. include:: configs/imapd.conf.rst
        :start-after: startblob event_notifier
        :end-before: endblob event_notifier 

Event Types
===========

These are detailed in :ref:`imap-features-event-notifications`.

Accessing events
================

While Cyrus only communicates with a single notification process, it doesn't have to be its standard :cyrusman:`notifyd(8)`. It's possible to write your own, providing it conforms with :rfc:`5465`.

Apple Push Service
==================

While Cyrus supports the `Apple Push Service`_, each provider needs its own account with Apple to use the Push Service. 

Should you wish to support the Apple Push Service, you will need to write your own notifier daemon with APS support.

.. _Apple Push Service: https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW9

