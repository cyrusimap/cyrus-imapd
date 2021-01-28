.. _caldav:

======
CalDAV
======

Configuration
=============

.. sidebar:: calendarprefix

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob calendarprefix
       :end-before: endblob calendarprefix

When enabled, the CalDAV module allows Cyrus to function as a calendar and
scheduling server. This module uses a subset of the mailbox hierarchy as
calendar collections, the toplevel of which is specified by the ``calendarprefix``
option. The public calendar hierarchy will reside at the toplevel of the shared
mailbox namespace. A user's personal calendar hierarchy will be a child of
their Inbox.

For example, using the default value for calendarprefix, a
calendar named Default for user "murch" would reside in the mailbox named
``user.murch.#calendars.Default``.

.. warning::

    Note that mailboxes in the calendar hierarchies (those under
    calendarprefix) **should not** be accessed with an IMAP client as doing so will
    leave a mailbox in a state unsuitable for CalDAV. To this end, calendar
    mailboxes will not returned by Cyrus imapd in response to an IMAP client's
    request for the available calendar list, but Cyrus imapd can not otherwise
    prevent an IMAP client from accessing them.

.. sidebar:: caldav_allowscheduling

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob caldav_allowscheduling
       :end-before: endblob caldav_allowscheduling

By default, the CalDAV module will automatically perform scheduling operations
when a scheduling object (invite or reply) is stored on or deleted from the
server. Support for the calendar-auto-schedule feature can be disabled with the
``caldav_allowscheduling`` option.

Administration
==============

The CalDAV module will *automatically* create the required calendars for a user
the first time that the user authenticates to the CalDAV server. Note that the
user MUST have an existing IMAP Inbox in order for the calendars to be created.

.. sidebar:: autocreate options

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
      :start-after: startblob caldav_create_default
      :end-before: endblob caldav_create_default
   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
      :start-after: startblob caldav_create_attach
      :end-before: endblob caldav_create_attach
   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
      :start-after: startblob caldav_create_sched
      :end-before: endblob caldav_create_sched

Autocreate of the various calendars can be disabled with the
"caldav_create_default/sched/attach" options, if you have an alternate
mechanism to create calendars.

There is also a Cyrus web GUI for managing calendar resources.
It allows you to:

    * Create new collections, with whichever components are required
    * Alter existing collections with different components
    * Subscribe or download existing collections via prepared URLs
    * Set visibility attributes such as Public or Transparent
    * Delete existing collections

The Cyrus web GUI for CalDAV Collection Management is disabled by
default, but can be enabled with the "caldav_allowcalendaradmin" option.

.. sidebar:: caldav_allowcalendaradmin

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
      :start-after: startblob caldav_allowcalendaradmin
      :end-before: endblob caldav_allowcalendaradmin

To access the Cyrus web GUI for CalDAV Collection Management, point
a web browser at ``https://<servername>/dav/calendars/user/<username>``

.. _calendar_ACL:

Calendar access controls
------------------------

The CalDAV module uses the same access controls as the other Cyrus services. The
:cyrusman:`cyradm(8)` tool can be used to adjust ACLs on calendars as needed.
The tables below show how the access controls are used by the CalDAV module.

.. raw:: html

    <table border>
      <caption>Mapping of IMAP Rights to WebDAV Privileges & HTTP Methods</caption>
      <tr>
        <th>IMAP rights</th>
        <th colspan=2>WebDAV privileges</th>
        <th>HTTP methods</th>
      </tr>
      <tr>
        <td>l - lookup
          <br>r - read</td>
        <td>DAV:read</td>
        <td>DAV:read-current-user-privilege-set
          <br>CALDAV:read-free-busy</td>
        <td>GET/HEAD
          <br>COPY/MOVE <small>(on source)</small>
            <br>PROPFIND
              <br>REPORT</td>
      </tr>
      <tr>
        <td><s>s - seen</s></td>
        <td colspan=2/>
        <td/>
      </tr>
      <tr>
        <td>w - write
          <br>n - write shared annotation</td>
        <td colspan=2>DAV:write-properties</td>
        <td>PROPPATCH
          <br>COPY/MOVE <small>(on destination)</small></td>
      </tr>
      <tr>
        <td>i - insert</td>
        <td colspan=2>DAV:write-content</td>
        <td>PUT
          <br>PATCH
            <br>COPY/MOVE <small>(on destination resource)</small>
              <br>LOCK
                <br>UNLOCK <small>(lock owner ONLY)</small></td>
      </tr>
      <tr>
        <td>p - post</td>
        <td rowspan=2>DAV:bind</td>
        <td>CYRUS:add-resource</td>
        <td>POST</td>
      </tr>
      <tr>
        <td>k - create mailbox</td>
        <td>CYRUS:make-collection</td>
        <td>MKCOL
          <br>MKCALENDAR
            <br>COPY/MOVE <small>(on destination collection)</small></td>
      </tr>
      <tr>
        <td>x - delete mailbox</td>
        <td rowspan=2>DAV:unbind</td>
        <td>CYRUS:remove-collection</td>
        <td>DELETE <small>(collection)</small>
          <br>MOVE <small>(on source collection)</small></td>
      </tr>
      <tr>
        <td>t - delete message
          <br>e - expunge</td>
        <td>CYRUS:remove-resource</td>
        <td>DELETE <small>(resource)</small>
          <br>MOVE <small>(on source resource)</small></td>
      </tr>
      <tr>
        <td>a - admin</td>
        <td>CYRUS:admin</td>
        <td>DAV:read-acl
          <br>DAV:write-acl
	  <br>DAV:share
          <br>DAV:unlock</td>
        <td>ACL
          <br>PROPFIND <small>(DAV:acl property ONLY)</small>
          <br>UNLOCK <small>(ANY lock)</small></td>
      </tr>
      <tr>
        <td colspan=4><i>Regular Calendar Collections ONLY &#151;
            read freebusy time?</i></td>
      </tr>
      <tr>
        <td>9 - freebusy</td>
        <td colspan=2>CALDAV:read-free-busy</td>
        <td>REPORT <small>(CALDAV:free-busy-query ONLY)</small>
          <br>GET/HEAD <small>(<a href="#freebusy-url">Freebusy URLs</a> ONLY)</small></td>
      </tr>
      <tr>
        <td colspan=4><i>Scheduling Outbox ONLY &#151;
            implicitly create/send iTIP message?</i></td>
      </tr>
      <tr>
        <td>9 - freebusy</td>
        <td rowspan=3>CALDAV:schedule-send</td>
        <td>CALDAV:schedule-send-freebusy</td>
        <td>POST
          <br><small>(by organizer on scheduling Outbox)</small></td>
      </tr>
      <tr>
        <td>8 - invite</td>
        <td>CALDAV:schedule-send-invite</td>
        <td>PUT/PATCH/DELETE
          <br><small>(by organizer on calendar resource/collection)</small></td>
      </tr>
      <tr>
        <td>7 - reply</td>
        <td>CALDAV:schedule-send-reply</td>
        <td>PUT/PATCH/DELETE
          <br><small>(by attendee on calendar resource/collection)</small></td>
      </tr>
      <tr>
        <td colspan=4><i>Scheduling Inbox ONLY &#151;
            implicitly deliver/process incoming iTIP message?</i></td>
      </tr>
      <tr>
        <td>9 - freebusy</td>
        <td rowspan=3>CALDAV:schedule-deliver</td>
        <td>CALDAV:schedule-query-freebusy</td>
        <td rowspan=3/>
      </tr>
      <tr>
        <td>8 - invite</td>
        <td>CALDAV:schedule-deliver-invite</td>
      </tr>
      <tr>
        <td>7 - reply</td>
        <td>CALDAV:schedule-deliver-reply</td>
      </tr>
    </table>
    <br>

    <br>
    <table border>
      <caption>Default WebDAV Privileges by Collection</caption>
      <tr>
        <th>Collection</th>
        <th>User ID</th>
        <th>WebDAV Privileges</th>
        <th>IMAP rights</th>
      </tr>
      <tr>
        <td rowspan=2>Regular Calendar Collection</td>
        <td>owner</td>
        <td>DAV:all + CALDAV:read-free-busy</td>
        <td align='right'>lrwipkxtan9</td>
      </tr>
      <tr>
        <td>anyone</td>
        <td>CALDAV:read-free-busy</td>
        <td align='right'>9</td>
      </tr>
      <tr>
        <td rowspan=2>Managed Attachments Collection</td>
        <td>owner</td>
        <td>DAV:all</td>
        <td>lrwipkxtan</td>
      </tr>
      <tr>
        <td>anyone</td>
        <td>DAV:read</td>
        <td>lr</td>
      </tr>
      <tr>
        <td rowspan=2>Scheduling Inbox</td>
        <td>owner</td>
        <td>DAV:all + CALDAV:schedule-deliver</td>
        <td>lrwipkxtan789</td>
      </tr>
      <tr>
        <td>anyone</td>
        <td>CALDAV:schedule-deliver</td>
        <td align='right'>789</td>
      </tr>
      <tr>
        <td>Scheduling Outbox</td>
        <td>owner</td>
        <td>DAV:all + CALDAV:schedule-send</td>
        <td>lrwipkxtan789</td>
      </tr>
    </table>

|

Freebusy URL
============

When enabled in conjunction with the CalDAV module, the Freebusy URL module
allows non-CalDAV and/or remote calendaring clients to query the freebusy
information of Cyrus CalDAV users.

Access to the freebusy information is controlled by the "freebusy" ACL (9) on a
user's home calendar collection. (e.g. a mailbox named
``user.murch.#calendars``). To enable unauthenticated users (non-Cyrus) to
access freebusy information, the freebusy ACL must be given to "anyone".

Freebusy information, consolidating the data of all user's calendars, is
accessed via URLs of the following form:
``https://<servername>/freebusy/user/<userid>``.  Querying individual CalDAV
collections, when they have explicitly "freebusy" ACL (9) set, is done via
``https://<servername>/freebusy/user/<userid>/<collection>``.


Query parameters can be added to the URL per Section 4 of
`Freebusy Read URL <http://www.calconnect.org/pubdocs/CD0903%20Freebusy%20Read%20URL.pdf>`_,
allowing the user to choose to set the start, end, period and format of
their query results.

Time Zone Distribution Service (TZDist)
=======================================

What is TZDist
--------------

The TZDist module allows Cyrus to function as a Time Zone Distribution
Service (:rfc:`7808` and :rfc:`7809`), providing time zone data for CalDAV
and calendaring clients, without having to wait for their client vendor and/or
OS vendor to update the timezone information. The responsibility for keeping
the time zone information up to date then falls upon the Cyrus administrator.

TZDist is optional: without Cyrus having TZDist enabled, calendar clients should
still be able to get their timezone information from their client or their OS.

TZDist strips known VTIMEZONEs from incoming iCalendar data (as
advertised by the ``calendar-no-timezone`` DAV option from :rfc:`7809`).

Configuration
-------------

.. sidebar:: zoneinfo config

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob zoneinfo_db_path
       :end-before: endblob zoneinfo_db_path

   |

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob zoneinfo_db
       :end-before: endblob zoneinfo_db

   |

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob zoneinfo_dir
       :end-before: endblob zoneinfo_dir

The TZDist module requires the ``zoneinfo_dir`` setting in :cyrusman:`imapd.conf(5)`
to be set to the directory where your time zone data is stored.

The data is indexed by a database whose location is specified by the
``zoneinfo_db_path`` option, using the format specified by the ``zoneinfo_db``
option.

Administration
--------------

The TZDist module is designed to use the IANA Time Zone Database data (a.k.a.
Olson Database) converted to the iCalendar format.

`vzic <https://github.com/libical/vzic>`_ does convert the IANA TZ DB to iCalendar
format.  For each time zone it creates a separate file with its own TZID property.
The TZID property can have a vendor prefix, that is fixed when compiling vzic by the
``TZID_PREFIX`` Makefile variable, which defaults to `/citadel.org/%D_1/`.  Cyrus
IMAP requires that the vendor prefix is the empty string.

The `cyrus-timezones package<https://github.com/cyrusimap/cyrus-timezones>`_ provides
a vzic, which sets TZID_PREFIX to the emtpy string.

The steps to populate the ``zoneinfo_dir`` directory are:

1. Acquire and build your choice of ``vzic`` tool.

2. Download the latest version of the
   `Time Zone Database data from IANA <http://www.iana.org/time-zones>`_. Note
   you only need the **data**, not the code.

3. Expand the downloaded time zone data into a temporary directory of your choice.

4. Copy leap-seconds.list from the temporary directory to ``<zoneinfo_dir>``.

5. Populate ``zoneinfo_dir`` with iCalendar data:

   *Initial Install Only*

   a. Convert the raw data into iCalendar format by running vzic as follows:
      ``vzic --pure --olson-dir <location-of-raw-data> --output-dir <zoneinfo_dir>``

      This will create and install iCalendar data directly into the
      ``<zoneinfo_dir>`` directory.

   *Updating Data Only*

   b. Convert the raw data into iCalendar format by running vzic as follows:
      ``vzic --pure --olson-dir <location-of-raw-data>``

      This will create a zoneinfo/ subdirectory in your current location

   c. Merge new/updated iCalendar data into the ``<zoneinfo_dir>`` directory
      by running vzic-merge.pl in your current location:
      ``vzic-merge.pl``

6. Rebuild the Cyrus zoneinfo index by running :cyrusman:`ctl_zoneinfo(8)` as
   follows:
   ``ctl_zoneinfo -r <version-string>``

   where <version-string> contains description of the recently downloaded time
   zone data, colon, and the version of the data (e.g. "IANA Time Zone Database:2020a").

7. Check that the zoneinfo index database and all iCalendar data files/links
   are readable by the cyrus user.

iSchedule
=========

About iSchedule
---------------


.. note::

    iSchedule support in Cyrus is a work in progress.

`iSchedule <https://tools.ietf.org/id/draft-desruisseaux-ischedule>`_
allows CalDAV servers to:

* query an event participant's free/busy status prior to invitation in order
  to set up a good meeting time, which cannot be done over email.
* keep participant's local event current by updating the status of other
  participants automatically. This is not done when scheduling over email as it
  would result in too much mail traffic and extra manual overhead for the users.

.. sidebar:: caldav_allowscheduling

    |change-default-config|

   .. include:: /imap/reference/manpages/configs/imapd.conf.rst
       :start-after: startblob caldav_allowscheduling
       :end-before: endblob caldav_allowscheduling

iSchedule is automatically enabled in Cyrus if both the CalDAV module and the
``caldav_allowscheduling`` options are enabled in a
:ref:`Cyrus Murder <murder>`. In this instance, Cyrus uses iSchedule to move
scheduling messages from frontend to backend servers.

Support for scheduling with external servers is currently under development
as there is the burden of authorization to verify the authenticity and
integrity of these messages to prevent inadvertent or malicious data leaks
or corruption.

What mechanism to use for authorization is under discussion with the `CalConnect
<https://www.calconnect.org/>`_ standards body, whether this is `DKIM
<http://www.dkim.org/>`_ or some other type of message signature.
