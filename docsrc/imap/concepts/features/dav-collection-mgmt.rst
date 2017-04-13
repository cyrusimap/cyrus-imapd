.. _imap-features-dav-collection-mgmt:

=========================
DAV Collection Management
=========================

..  Information on provisioning new collections, via the web GUI and/or
    third-party interfaces

Calendars and addressbooks are maintained as "Collections" within the
Cyrus mail store.  They appear as mailboxes within the heirarchy, as
set by the ``calendarprefix:`` option in :cyrusman:`imapd.conf(5)`
(default is ``#calendars``), but should rarely be directly accessed or
created using either :cyrusman:`cyradm(8)` or other mailbox-centric tools.

Collections have special attributes, so should be created and
maintained either through protocol -- i.e. with purpose-built calendar
or address book clients -- or with the provided web GUI.

.. seealso::
    :ref:`caldav` for more information on creating and managing Calendars
    :ref:`carddav` for more information on creating and managing Addressbooks


Back to :ref:`imap-features`
