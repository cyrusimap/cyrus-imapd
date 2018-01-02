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

.. sidebar:: JMAP configuration

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob conversations
       :end-before: endblob conversations

   |

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
      :start-after: startblob conversations_db
      :end-before: endblob conversations_db

Once it's compiled, JMAP needs to be enabled in :cyrusman:`imapd.conf(5)`.

Enable :ref:`conversation support <imap-concepts-deployment-db-conversations>`

    * In :cyrusman:`imapd.conf(5)`, set ``conversations: 1``, ``conversations_db: twoskip``
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

Working
-------

* **Contacts**
    * All JMAP methods are implemented. JMAP blobs are not supported.

* **Calendars**
    * All JMAP methods are implemented. JMAP blobs are not supported.

* **Messages**
    * Most JMAP methods are implemented. The following methods are not planned for implementation:

      * copyMessages
      * reportMessages
      * getVacationResponse
      * setVacationResponse
      * getIdentityUpdates
      * setIdentities

Not yet implemented
-------------------

* **Remote mailboxes**

* **Events**
    * Changes on mailbox entries trigger notifications. However, the JMAP event service is not implemented.
