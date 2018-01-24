.. _imap-features:

========
Features
========

The Cyrus IMAP (Internet Message Access Protocol) server provides
access to personal mail, system-wide bulletin boards, news-feeds,
calendar and contacts through the IMAP, NNTP, CalDAV and CardDAV
protocols. The Cyrus IMAP server is a scalable enterprise groupware
system designed for use from small to large enterprise environments
using technologies based on well-established Open Standards.

A full Cyrus IMAP implementation allows a seamless mail and bulletin
board environment to be set up across one or more nodes. It differs
from other IMAP server implementations in that it is run on *sealed
nodes*, where users are not normally permitted to log in. The mailbox
database is stored in parts of the filesystem that are private to the
Cyrus IMAP system. All user access to mail is through software using
the IMAP, IMAPS, POP3, POP3S, KPOP, CalDAV and/or CardDAV protocols.

The private mailbox database design gives the Cyrus IMAP server large
advantages in efficiency, scalability, and administratability. Multiple
concurrent read/write connections to the same mailbox are permitted.
The server supports access control lists on mailboxes and storage
quotas on mailbox hierarchies.

The following documents show the full power of each feature that is
included with Cyrus IMAP.

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
    features/virtual-domains
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

Calendar and Contact (DAV) Collection Management
------------------------------------------------

.. toctree::
    :maxdepth: 1

    features/caldav-collections
    features/dav-components
    features/dav-collection-mgmt
    features/carddav

Storage
-------

.. toctree::
    :maxdepth: 1

    features/mail-spool-partitions
    features/mailbox-metadata-partitions
    features/archiving
    features/quota
    features/single-instance-store

Load Management
---------------

.. toctree::
    :maxdepth: 1

    features/server-aggregation
