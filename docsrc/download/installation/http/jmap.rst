====
JMAP
====

About JMAP
==========

`JMAP <http://jmap.io/>`_ is an alternate mechanism for synchronising a mail
client with a mail server, intended as a replacement for IMAP. It is a
transport-agnostic, stateless JSON-based API, aiming to be compatible with the
IMAP data model, but with reduced data usage and more efficient synchronisation.

Configuration
=============

.. todo::

    Stop duplication in this and developer-jmap by moving a chunk of this
    information into /assets and include instead.

JMAP support needs to be compiled in to the server using additional
compile flags. Depending on your distribution, your package provider may
have already done so. If not, check the
:ref:`JMAP developer guide <developer-jmap>` for instructions on how to do
so manually, assuming you have the source.

Once it's compiled, JMAP needs to be enabled in :cyrusman:`imapd.conf(5)`.

Enable :ref:`conversation support <imap-concepts-deployment-db-conversations>`

    * In :cyrusman:`imapd.conf(5)`, set :imapdconf:`conversations: 1 <conversations>`,
      :imapdconf:`conversations_db: twoskip <conversations_db>`
    * Create a conversations.db for each user using
      :cyrusman:`ctl_conversationsdb(8)`: ``ctl_conversationsdb -b -r``

JMAP clients
============

The official JMAP website maintains a list of `known clients with JMAP support
<http://jmap.io/software.html>`_.

The Cyrus :ref:`JMAP developer guide <developer-jmap>` has information on using
the sample test clients.

.. _jmap-implementation:

JMAP implementation status
==========================

The JMAP implementation in Cyrus is at various stages of maturity.

Implemented
-----------

* The core protocol (:rfc:`8620`), except for PushSubscription
* JMAP for Mail (:rfc:`8621`)
* JMAP Blob Management Extension (:rfc:`9404`)
* JMAP for Quotas (:rfc:`9425`)
* JMAP for Sieve Scripts (:rfc:`9661`)
* A JMAP Subprotocol for WebSocket (:rfc:`8887`)
* JMAP for Contacts (:rfc:`9610`)
* JMAP Sharing (:rfc:`9670`)

In development
--------------

* JMAP for Calendars (:draft:`draft-ietf-jmap-calendars`)
* Handling MDN with JMAP (:rfc:`9007`)

Not implemented
---------------
* JMAP for Tasks (:draft:`draft-ietf-jmap-tasks`)
* JMAP SMIME Signature Verification Extensions(:rfc:`9219`)
