.. _databases:

=========
Databases
=========

Overview
========

Cyrus stores a lot of information. Rather than use traditional relational
database servers, its information is stored on disk in structured files.

These files should only be accessed via Cyrus API, not via a file editor.

File type and file location can be changed by updating the relevant entries
in :cyrusman:`imapd.conf(5)`. Files, by default, are stored in the configdirectory.

Changing the :ref:`storage type <storagetypes>` for a file will cause
Cyrus to automatically convert the file to the new format.

The data in these files can usually be rebuilt from the mail files themselves by
:ref:`running reconstruct <reconstructing-mailboxes>`.

File list
=========

One per system:

* `Mailbox List (mailboxes.db)`_
* `Annotations (annotations.db)`_
* `Quotas (quotas.db)`_
* `Duplicate Delivery (deliver.db)`_
* `TLS cache (tls_sessions.db)`_
* `PTS cache (ptscache.db)`_
* `STATUS cache (statuscache.db)`_
* `User Access (user_deny.db)`_
* `Backups (backups.db)`_
* `News database (fetchnews.db)`_
* `Zoneinfo db (zoneinfo.db)`_

One per user:

* `Conversations (<userid>.conversations)`_
* `Counters (<userid>.counters)`_
* `DAV Index (<userid>.dav)`_
* `Mailbox Keys (<userid>.mboxkey)`_
* `Seen State (<userid>.seen)`_
* `Subscriptions (<userid>.sub)`_
* `Search Indexes (cyrus.squat, <userid>.xapianactive)`_

.. _imap-concepts-deployment-db-mailboxes:

Mailbox List (mailboxes.db)
---------------------------

This database contains the master list of all mailboxes on the system. The database is indexed by mailbox name and each data record contains the mailbox type, the partition on which the mailbox resides and the ACL on the mailbox. The format of each record is as follows::

    Key: <Mailbox Name>

    Data: <Type Number>SP<Partition>SP<ACL (space-separated userid/rights pairs)>

File type can be: `twoskip`_ (default), `flat`_, `skiplist`_, `sql`_, `twoskip`_, or `lmdb`_.

.. _imap-concepts-deployment-db-annotations:

Annotations (annotations.db)
----------------------------

This database contains mailbox and server annotations. The database is indexed by mailbox name (empty for server annotations) + annotation name + userid (empty for shared annotations) and each data record contains the value size, value data, content-type of the data and timestamp of the record. The format is each record is as follows::

    Key: <Mailbox Name>\0<Annotation Name>\0<Userid>\0

    Data: <Value Size (4 bytes)><Value>\0<Content-Type>\0<Timestamp (4 bytes)>

File type can be `twoskip`_  (default), `skiplist`_, or `lmdb`_.

.. _imap-concepts-deployment-db-quotas:

Quotas (quotas.db)
------------------

This database contains the master list of quotaroots on the system. The database is indexed by quota root and each data record contains the current usage of all mailboxes under the quota root and the limit of the quota root. The format of each record is as follows::

    Key: <Quota Root>

    Data: <Usage (in bytes)>SP<Limit (in Kbytes)>

File type can be: `quotalegacy`_ (default), `flat`_, `skiplist`_, `sql`_, `twoskip`_, or `lmdb`_.


**Legacy Quotas**

The legacy quota database uses a distributed system in which each quota root is stored in a separate file named by quota root and the contents had the following format in older versions::

    <Usage (in bytes)>\n
    <Limit (in Kbytes)>\n

Newer versions are stored as a DList file with keys for each type of quota, and values with both usage and limit for each type.  A limit value of -1 means no limit.

The translation to/from this data record format is handled by the quota_legacy cyrusdb backend.

.. _imap-concepts-deployment-db-deliver:

Duplicate Delivery (deliver.db)
-------------------------------

This database is used for duplicate delivery suppression, retrieving usenet articles by message-id, and tracking Sieve redirects and vacation responses. The database is indexed by message-id + recipient (either mailbox or email address) and each data record contains the timestamp of the record and the UID of the message within the mailbox (if delivered locally). The format of each record is as follows::

    Key: <Message-ID>\0<Recipient>\0

    Data: <Timestamp (4 bytes)><Message UID (4 bytes)>

File type can be: `twoskip`_ (default), `skiplist`_, `sql`_, or `lmdb`_.


.. _imap-concepts-deployment-db-tls:

TLS cache (tls_sessions.db)
---------------------------

This database caches SSL/TLS sessions so that subsequent connections using the same session-id can bypass the SSL/TLS handshaking, resulting is shorter connection times. The database is indexed by session-id and each data record contains the timestamp of the record and the ASN1 representation of the session data. The format of each record is as follows::

    Key: <Session-ID (multi-byte)>

    Data: <Timestamp (4 bytes)><Session Data (multi-byte)>

File type can be: `twoskip`_ (default), `skiplist`_, `sql`_, or `lmdb`_.


.. _imap-concepts-deployment-db-pts:

PTS cache (ptscache.db)
-----------------------

This database caches authentication state records, resulting in shorter authentication/canonicalization times. The database is indexed by userid and each data record contains an authentication state for the userid. The format of each record is as follows::

    Key: <Userid>

    Data: <Auth State (multi-byte)>

File type can be: `twoskip`_ (default), `skiplist`_, or `lmdb`_.


.. _imap-concepts-deployment-db-status:

STATUS cache (statuscache.db)
-----------------------------

This database caches IMAP STATUS information resulting in less I/O when the STATUS information hasn't changed (mailbox and \Seen state unchanged). The database is indexed by mailbox name + userid and each data record contains the database version number, a bitmask of the stored status items, the mtime, inode, and size of the cyrus.index file at the time the record was written, the total number of messages in the mailbox, the number of recent messages, the next UID value, the mailbox UID validity value, the number of unseen messages, and the highest modification sequence in the mailbox. The format of each record is as follows::

    Key: <Mailbox Name>\0<Userid>\0

    Data: <Version>SP<Bitmask of Items>SP<Mtime of Index>SP<Inode of Index>SP<Size of Index>SP<- of Messages>SP<- of Recent Messages>SP<Next UID>SP<UID Validity>SP<- of Unseen Messages>SP<Highest Mod Sequence>

File type can be: `twoskip`_ (default), `skiplist`_, `sql`_, or `lmdb`_.


.. _imap-concepts-deployment-db-userdeny:

User Access (user_deny.db)
--------------------------

This database contains a list of users that are denied access to Cyrus services. The database is indexed by userid and each data record contains the database version number (currently 2), a list of wildmat patterns specifying Cyrus services to be denied, and a text message to be displayed to the user upon denial. The service names to be matched are those as used in cyrus.conf(5). The format of each record is as follows::

    Key: <Userid>

    Data: <Version>TAB<Deny List (comma-separated wildmat patterns)>TAB<Deny Message>

File type can be: `flat`_ (default), `skiplist`_, `sql`_, `twoskip`_, or `lmdb`_.

.. _imap-concepts-deployment-db-backups:

Backups (backups.db)
--------------------

This database maps userids to the location of their backup files.  It only exists
on Cyrus Backup servers (compiled with the `--enable-backup` configure option).

File type can be: `twoskip`_ (default), `skiplist`_, `sql`_, `twoskip`_, or `lmdb`_.

.. _imap-concepts-deployment-db-conversations:

Conversations (<userid>.conversations)
--------------------------------------

This file contains all the message-id fields from every email that has been seen
in the past three months, mapping to the conversation IDs in which this message
ID has been seen, and the timestampe when it was last seen.

It also has a records for each conversation ID with details about which folders
have that converations ID in them, and counts of messages and flags.

Finally there are records for each folder with the counts of conversations in
that folder.

File type can be: `skiplist`_ (default), `sql`_, `twoskip`_, or `lmdb`_.

.. _imap-concepts-deployment-db-counters:

Counters (<userid>.counters)
----------------------------

File format not selectable.

TODO

.. _imap-concepts-deployment-db-fetchnews:

News database (fetchnews.db)
----------------------------

File format not selectable.

.. _imap-concepts-deployment-db-search:

Search Indexes (cyrus.squat, <userid>.xapianactive)
---------------------------------------------------

This is either cyrus.squat in each folder, or if you're using xapian a single
<userid>.xapianactive file listing active databases by tier name and number.

File type can be: `twoskip`_ (default), `flat`_, `skiplist`_, or `lmdb`_.

.. _imap-concepts-deployment-db-zoneinfo:

Zoneinfo db (zoneinfo.db)
-------------------------

This database is used for the timezone service and contains records
relating to timezones and their aliases.  The database is indexed by
timezone ID and each data record contains the database version
number, a record type, a timestamp, and an optional list of strings
(either aliases for a timezone or the reference timezone for an
alias).  The format of each record is as follows::

    Key: <TZID>

    Data: <Version>SP<Record Type>SP<Timestamp>SP<Data Strings (TAB-separated)>

File type can be: `twoskip`_ (default), `flat`_, `skiplist`_, or `lmdb`_.

.. _imap-concepts-deployment-db-seen:

Seen State (<userid>.seen)
--------------------------

This database is a per-user database and maintains the list of messages that the user has read in each mailbox. The database is indexed by mailbox unique-id and each data record contains the database version number, the timestamp of when a message was last read, the message unique-id of the last read message, the timestamp of the last record change and a list of message unique-ids which have been read. The format of each record is as follows::

    Key: <Mailbox UID>

    Data: <Version>SP<Last Read Time>SP<Last Read UID>SP<Last Change Time>SP<List of Read UIDs>

File type can be: `twoskip`_ (default), `flat`_, `skiplist`_, or `lmdb`_.

.. _imap-concepts-deployment-db-sub:

Subscriptions (<userid>.sub)
----------------------------

This database is a per-user database and contains the list of mailboxes to which the user has subscribed. The database is indexed by mailbox name and each data record contains no data. The format of each record is follows::

    Key: <Mailbox Name>

    Data: None

File type can be: `flat`_ (default), `skiplist`_, `twoskip`_, or `lmdb`_.

.. _imap-concepts-deployment-db-xapianactive:

Search Index DB List (<userid>.xapianactive)
--------------------------------------------

TODO


.. _imap-concepts-deployment-db-mboxkey:

Mailbox Keys (<userid>.mboxkey)
-------------------------------

This database is a per-user database and contains the list of mailbox access keys which are used for generating URLAUTH-authorized URLs. The database is indexed by mailbox name and each data record contains the database version number and the associated access key. The format of each record is follows::

    Key: <Mailbox Name>

    Data: <Version (2 bytes)><Access Key (multi-byte)>

File type can be: `twoskip`_ (default), `skiplist`_, or `lmdb`_.

.. _imap-concepts-deployment-db-userdav:

DAV Index (<userid>.dav)
------------------------

This embedded SQLite database is per-user and primarily maintains a
mapping from DAV resource names (URLs) to the corresponding Cyrus
mailboxes and IMAP message UIDs.  The database is designed to have
one table per resource type (iCalendar, vCard, etc) with each table
containing metadata specific to that resource type.

CalDAV
######

The format of the iCalendar table used by CalDAV is as follows::

    CREATE TABLE ical_objs (
        rowid INTEGER PRIMARY KEY,
        creationdate INTEGER,
        mailbox TEXT NOT NULL,
        resource TEXT NOT NULL,
        imap_uid INTEGER,
        lock_token TEXT,
        lock_owner TEXT,
        lock_ownerid TEXT,
        lock_expire INTEGER,
        comp_type INTEGER,
        ical_uid TEXT,
        organizer TEXT,
        dtstart TEXT,
        dtend TEXT,
        comp_flags INTEGER,
        sched_tag TEXT,
        UNIQUE( mailbox, resource )
    );


Because CalDAV Scheduling requires the server to locate a resource
by iCalendar UID regardless of which calendar collection (mailbox)
it resides in, the iCalendar table has an additional index as follows::

  CREATE INDEX idx_ical_uid ON ical_objs ( ical_uid );


CardDAV
#######

The format of the vCard table used by CardDAV is as follows::

    CREATE TABLE vcard_objs (
        rowid INTEGER PRIMARY KEY,
        creationdate INTEGER,
        mailbox TEXT NOT NULL,
        resource TEXT NOT NULL,
        imap_uid INTEGER,
        lock_token TEXT,
        lock_owner TEXT,
        lock_ownerid TEXT,
        lock_expire INTEGER,
        version INTEGER,
        vcard_uid TEXT,
        kind INTEGER,
        fullname TEXT,
        name TEXT,
        nickname TEXT,
        email TEXT,
        UNIQUE( mailbox, resource )
    );


.. _storagetypes:

Storage types
=============

Flat
----

Only for debugging. The file format is human-readable, but it is
slow for reads and writes, and is easily corrupted.

Twoskip
-------

**Recommended**. A robust implementation of `https://en.wikipedia.org/wiki/Skip_list <Skip List>`_.
Developers interested in the details can find more information at `http://opera.brong.fastmail.fm.user.fm/talks/twoskip/twoskip-yapc12.pdf <these talk slides>`_.

Skiplist
--------

An implementation of the `https://en.wikipedia.org/wiki/Skip_list <Skip List>`_
data structure. Deprecated in favour of `Twoskip`_ as it is not robust in
the face of disk failure.

lmdb
----

`http://symas.com/mdb <Lightning Memory-Mapped Database (lmdb)>`_ is a
high-performance transactional key-value store.

Fast while in memory, but slow when the database is loaded. Best for databases
that are held open for a long time: `Mailbox List (mailboxes.db)`_

sql
---

It is possible to store data in a normal relational SQL database. Generally
`Twoskip`_ is preferred as it is less operational overhead (the files can live
alongside Cyrus itself without requiring a separate server and DBA expertise
to manage). In addition, Cyrus performs much of the backups/replication/transactional
robustness that a SQL server provides, so the tradeoff is less compelling.

quotalegacy
-----------

Only valid for the `Quotas (quotas.db)`_.  Has the advantage of
virtually no lock contention.
