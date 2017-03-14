.. _imap-features-caldav-collection-mgmt:

============================
CalDAV Collection Management
============================

..  Information on provisioning new collections, via the web GUI and/or
    third-party interfaces

Calendars and addressbooks are maintained as "Collections" within the
Cyrus mail store.  They appear as mailboxes within the heirarchy, as
set by the ``calendarprefix:`` option in :cyrusman:`imapd.conf(5)`
(default is ``#calendars``), but should rarely be directly manipulated
using either :cyrusman:`cyradm(8)` or other mailbox-centric tools.

Collections have special attributes, so should be created and
maintained either through protocol -- i.e. with purpose-built calendar
or address book clients -- or with the provided web GUI.

To access the Cyrus web GUI for CalDAV Collection Management, point
a web browser at https://<servername>/dav/calendars/user/%3Cusername%3E

For example:

    https://myserver:8008/dav/calendars/user/bovik/

Using this GUI, one may:

    * Create new collections, with whichever components are required
    * Alter existing collections with different components
    * Subscribe or Download existing collections via prepared URLs
    * Set visibility attributes such as Public or Transparent
    * Delete existing collections

Back to :ref:`imap-features`
