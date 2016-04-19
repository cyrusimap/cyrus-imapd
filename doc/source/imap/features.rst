.. _imap-features:

=============
IMAP Features
=============

The following documents show the full power of each feature that is included with Cyrus IMAP.

Exceptions notwithstanding, most of this documentation does not involve
the :ref:`imap-rfc-support`.

Security and Authentication
---------------------------

.. toctree::
    :maxdepth: 1
    
    features/authentication-kerberos
    features/authentication-ldap
    features/authentication-sql
    features/access-control
    features/sealed-system

Mailbox Management
------------------

.. toctree::
    :maxdepth: 1
    
    features/automatic-creation-of-mailboxes
    features/namespaces
    features/mailbox-annotations
    features/mailbox-distribution
    
Message Management
------------------
 
.. toctree::
    :maxdepth: 1
    
    features/delayed-delete
    features/delayed-expunge
    features/message-annotations
    features/duplicate-message-delivery-suppression
    features/shared-seen-state
    features/server-side-filtering
    features/event-notifications
    
Storage
-------

.. toctree::
    :maxdepth: 1
    
    features/mail-spool-partitions
    features/mailbox-metadata-partitions
    features/quota
    features/single-instance-store
    
Load Management
---------------

.. toctree::
    :maxdepth: 1
    
    features/server-aggregation
    
