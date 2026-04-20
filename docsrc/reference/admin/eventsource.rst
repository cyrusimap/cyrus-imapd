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

``--enable_event_notification``: Set this to "yes" to have Cyrus generate mailbox related events. This is enabled by default.

``--enable-apple-push-service``: Set this to "yes" to enable support for the Apple Push service. This is *disabled* by default as Apple does not provide licenses for Push support to developers at this stage.

Configuration options
=====================

These need to be set in :cyrusman:`imapd.conf(5)`.

* :ref:`imapd-conf-event_content_inclusion_mode`
* :ref:`imapd-conf-event_content_size`
* :ref:`imapd-conf-event_exclude_flags`
* :ref:`imapd-conf-event_exclude_specialuse`
* :ref:`imapd-conf-event_extra_params`
* :ref:`imapd-conf-event_groups`
* :ref:`imapd-conf-event_notifier`

Event Types
===========

These are detailed in :ref:`imap-features-event-notifications`.

Accessing events
================

While Cyrus only communicates with a single notification process, it doesn't have to be its standard :cyrusman:`notifyd(8)`. It's possible to write your own, providing it conforms with :rfc:`5465`.

Apple Push Service
==================

While Cyrus supports the Apple Push Service, Apple has only licensed Apple Push
for mail to a couple of large mail providers: Fastmail and Yahoo. If you own an
OS X Server license, you also get a key for personal use. But it's not generally
a supported option for third party developers that we're aware of,
unfortunately.

We have discussed pulling the XAPPLEPUSH code out from upstream Cyrus, but right
now it remains against the day that Apple do decide to open up access.
