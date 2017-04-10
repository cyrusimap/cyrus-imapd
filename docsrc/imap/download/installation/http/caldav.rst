.. _caldav:

=================
CalDAV Management
=================

CalDAV Configuration
====================

.. sidebar:: calendarprefix

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

Note that mailboxes in the calendar hierarchies (those under calendarprefix)
will NOT be returned by Cyrus imapd in response to an IMAP client's request for
the available mailbox list, but Cyrus imapd will not otherwise prevent an IMAP
client from accessing them.

.. sidebar:: caldav_allowscheduling

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

There is also a Cyrus web GUI for managing calendar resources.
It allows you to:

    * Create new collections, with whichever components are required
    * Alter existing collections with different components
    * Subscribe or download existing collections via prepared URLs
    * Set visibility attributes such as Public or Transparent
    * Delete existing collections

To access the Cyrus web GUI for CalDAV Collection Management, point
a web browser at ``https://<servername>/dav/calendars/user/<username>``


Similarly, for addressbook management, use a URL of the form
``https://<servername>/dav/addressbooks/user/<username>``

Using the CardDAV GUI, one may:

    * Create new collections
    * Delete existing collections
    * Download existing collections via prepared URLs

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
          <br>GET/HEAD <small>(<a href="#Freebusy">Freebusy URLs</a> ONLY)</small></td>
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

Freebusy URL module
===================

When enabled in conjuction with the CalDAV module, the Freebusy URL module
allows non-CalDAV and/or remote calendaring clients to query the freebusy
information of Cyrus CalDAV users.

Access to the freebusy information is controlled by the "freebusy" ACL (9) on a
user's home calendar collection. (e.g. a mailbox named
``user.murch.#calendars``). To enable unauthenticated users (non-Cyrus) to
access freebusy information, the freebusy ACL must be given to "anyone".

Freebusy information is accessed via URLs of the following form:
``https://<servername>/freebusy/user/<userid>``

Query parameters can be added to the URL per Section 4 of
`Freebusy Read URL <http://www.calconnect.org/pubdocs/CD0903%20Freebusy%20Read%20URL.pdf>`_,
allowing the user to choose to set the start, end, period and format of
their query results.
