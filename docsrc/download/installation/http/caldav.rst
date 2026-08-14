.. _caldav:

======
CalDAV
======

Configuration
=============

When ``caldav`` is included in the :imapdconf:`httpmodules` option, the
CalDAV module allows Cyrus to function as a calendar and scheduling server.
This module uses a subset of the mailbox hierarchy as calendar collections,
the toplevel of which is specified by the :imapdconf:`calendarprefix`
option. The public calendar hierarchy will reside
at the toplevel of the shared mailbox namespace. A user's personal calendar
hierarchy will be a child of their Inbox.

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

By default, the CalDAV module will automatically perform scheduling operations
when a scheduling object (invite or reply) is stored on or deleted from the
server. Support for the calendar-auto-schedule feature can be disabled with the
:imapdconf:`caldav_allowscheduling` option.

Administration
==============

The CalDAV module will *automatically* create the required calendars for a user
the first time that the user authenticates to the CalDAV server. Note that the
user MUST have an existing IMAP Inbox in order for the calendars to be created.

Autocreate of the various calendars can be disabled with the
:imapdconf:`caldav_create_default`, :imapdconf:`caldav_create_attach`, and
:imapdconf:`caldav_create_sched` options, if you have an alternate
mechanism to create calendars.

There is also a Cyrus web GUI for managing calendar resources.
It allows you to:

    * Create new collections, with whichever components are required
    * Alter existing collections
    * Subscribe or download existing collections via prepared URLs
    * Set visibility attributes such as Public or Transparent
    * Delete existing collections

To delete the value of a property, click on ✎ and then submit empty new value.

The Name, Description, Color, and Order properties are used only for UI
purposes.  “None color” means, that no calendar color is communicated
to the calendar user agents.  Transparent calendars are skipped by
server-side freebusy calculations.  The Time Zone on calendars
is used to calculate the freebusy state on events with floating
times.  Public toggles the `lrw9` rights for the `anyone` user.

The Cyrus web GUI for CalDAV Collection Management is disabled by
default, but can be enabled with the :imapdconf:`caldav_allowcalendaradmin`
option.

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
        <th colspan=3>WebDAV privileges</th>
        <th>HTTP methods</th>
      </tr>
      <tr>
        <td style="vertical-align:middle">l - lookup
          <br>r - read</td>
        <td colspan=2 rowspan=2 style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.1">DAV:read</a></td>
        <td style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.7">DAV:read-current-user-privilege-set</a></td>
        <td>GET/HEAD
          <br>COPY/MOVE
            <br><small>(on source)</small>
              <br>PROPFIND
                <br>REPORT</td>
      </tr>
      <tr>
        <td style="vertical-align:middle">9 - freebusy
          <br><small>(regular calendar collections ONLY)</small></td>
        <td style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc4791#section-6.1.1">CALDAV:read-free-busy</a></td>
        <td>GET/HEAD
          <br><small>(<a href="#freebusy-url">Freebusy URLs</a> ONLY)</small>
            <br>REPORT
              <br><small>(<a href="https://datatracker.ietf.org/doc/html/rfc4791#section-7.10">CALDAV:free-busy-query</a> ONLY)</small></td>
      </tr>
      <tr>
        <td><s>s - seen</s>
          <br><s>p - post</s></td>
        <td colspan=4/>
        <td/>
      </tr>
      <tr>
        <td style="vertical-align:middle">w - write</td>
        <td rowspan=6 style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.2">DAV:write</a></td>
        <td rowspan=2 style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.3">DAV:write-properties</a></td>
        <td>CY:write-properties-collection</td>
        <td rowspan=2>PROPPATCH
          <br>COPY/MOVE
            <br><small>(on destination)</small></td>
      </tr>
      <tr>
        <td>n - write shared annotation</td>
        <td>CY:write-properties-resource</td>
      </tr>
      <tr>
        <td style="vertical-align:middle">i - insert</td>
        <td rowspan=2 style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.9">DAV:bind</a></td>
        <td style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.4">DAV:write-content</a></td>
        <td>POST
          <br><small>(<a href="https://datatracker.ietf.org/doc/html/rfc5995#section-3.1">Add Member URI</a>)</small>
            <br>PUT
              <br>PATCH
                <br>COPY/MOVE
                  <br><small>(on destination resource)</small>
                    <br>LOCK
                      <br>UNLOCK
                        <br><small>(lock owner ONLY)</small></td>
      </tr>
      <tr>
        <td style="vertical-align:middle">k - create mailbox</td>
        <td style="vertical-align:middle">CY:make-collection</td>
        <td>MKCOL
          <br>MKCALENDAR
            <br>COPY/MOVE
              <br><small>(on destination collection)</small></td>
      </tr>
      <tr>
        <td style="vertical-align:middle">x - delete mailbox</td>
        <td rowspan=2 style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.10">DAV:unbind</a></td>
        <td style="vertical-align:middle">CY:remove-collection</td>
        <td>DELETE
          <br><small>(collection)</small>
            <br>MOVE
              <br><small>(on source collection)</small></td>
      </tr>
      <tr>
        <td style="vertical-align:middle">t - delete message
          <br>e - expunge</td>
        <td style="vertical-align:middle">CY:remove-resource</td>
        <td>DELETE
          <br><small>(resource)</small>
            <br>MOVE
              <br><small>(on source resource)</small></td>
      </tr>
      <tr>
        <td style="vertical-align:middle">a - administer</td>
        <td colspan=2 style="vertical-align:middle">CY:admin</td>
        <td style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.6">DAV:read-acl</a>
          <br><a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.8">DAV:write-acl</a>
          <br><a href="https://datatracker.ietf.org/doc/html/draft-pot-webdav-resource-sharing-00#section-7">DAV:share</a>
          <br><a href="https://datatracker.ietf.org/doc/html/rfc3744#section-3.5">DAV:unlock</a></td>
        <td>ACL
          <br>PROPFIND
            <br><small>(<a href="https://datatracker.ietf.org/doc/html/rfc3744#section-5.5">DAV:acl property</a> ONLY)</small>
              <br>UNLOCK
                <br><small>(ANY lock)</small></td>
      </tr>
      <tr>
        <td colspan=5 align='center'><b>Scheduling Outbox ONLY &#151;
            implicitly create/send iTIP message?</b></td>
      </tr>
      <tr>
        <td style="vertical-align:middle">9 - freebusy</td>
        <td rowspan=3 colspan=2 style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc6638#section-6.2.1">CALDAV:schedule-send</a></td>
        <td style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc6638#section-6.2.4">CALDAV:schedule-send-freebusy</a></td>
        <td>POST
          <br><small>(by organizer on scheduling Outbox)</small></td>
      </tr>
      <tr>
        <td style="vertical-align:middle">8 - invite</td>
        <td style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc6638#section-6.2.2">CALDAV:schedule-send-invite</a></td>
        <td>PUT
          <br>PATCH
            <br>DELETE
              <br><small>(by organizer on calendar resource/collection)</small></td>
      </tr>
      <tr>
        <td style="vertical-align:middle">7 - reply</td>
        <td style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc6638#section-6.2.3">CALDAV:schedule-send-reply</a></td>
        <td>PUT
          <br>PATCH
            <br>DELETE
              <br><small>(by attendee on calendar resource/collection)</small></td>
      </tr>
      <tr>
        <td colspan=5 align='center'><b>Scheduling Inbox ONLY &#151;
            implicitly deliver/process incoming iTIP message?</b></td>
      </tr>
      <tr>
        <td style="vertical-align:middle">9 - freebusy</td>
        <td rowspan=3 colspan=2 style="vertical-align:middle">
          <a href="https://datatracker.ietf.org/doc/html/rfc6638#section-6.1.1">CALDAV:schedule-deliver</a></td>
        <td><a href="https://datatracker.ietf.org/doc/html/rfc6638#section-6.1.4">CALDAV:schedule-query-freebusy</a></td>
        <td rowspan=3/>
      </tr>
      <tr>
        <td style="vertical-align:middle">8 - invite</td>
        <td><a href="https://datatracker.ietf.org/doc/html/rfc6638#section-6.1.2">CALDAV:schedule-deliver-invite</a></td>
      </tr>
      <tr>
        <td style="vertical-align:middle">7 - reply</td>
        <td><a href="https://datatracker.ietf.org/doc/html/rfc6638#section-6.1.3">CALDAV:schedule-deliver-reply</a></td>
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
        <td align='right'>lrwikxtan9</td>
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
        <td>lrwikxtan</td>
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
        <td>lrwikxtan789</td>
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
        <td>lrwikxtan789</td>
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

The TZDist module requires the :imapdconf:`zoneinfo_dir` setting to be set
to the directory where your time zone data is stored.

If ``configure`` found the ``vzic`` timezone compiler, ``make install``
generates that data from the IANA time zone database bundled in ``tzdata/``
and installs it under ``<datadir>/cyrus-imapd/zoneinfo`` -- e.g.
``/usr/cyrus/share/cyrus-imapd/zoneinfo`` -- and :imapdconf:`zoneinfo_dir`
defaults to that directory.  In that case there is nothing to configure, and
you can skip to :ref:`tzdist_administration`, which you still need when a new
IANA release comes out.

The ``configure`` summary reports the directory as "time zone data" and
"zoneinfo_dir".  Note that this default is compiled in rather than stored in
the config file, so :cyrusman:`cyr_info(8)` ``conf-all`` reports
:imapdconf:`zoneinfo_dir` as empty unless it is set in
:cyrusman:`imapd.conf(5)` explicitly.

An upgraded installation keeps the :imapdconf:`zoneinfo_dir` it has configured,
and its existing data stays in use.  To switch over to the data the build
installs, remove the setting from :cyrusman:`imapd.conf(5)` and rebuild the
index as :ref:`tzdist_administration` describes.

Pass ``--with-vzic=PATH`` to ``configure`` if ``vzic`` is not on your
``PATH``, or ``--without-vzic`` to build no time zone data at all and manage
:imapdconf:`zoneinfo_dir` entirely yourself as described below.  Setting
``--with-zoneinfo-dir=PATH`` overrides the default regardless.

.. _tzdist_vzic:

.. note::

    ``vzic`` hard-codes three settings when it is itself compiled, and
    ``configure`` cannot tell how the ``vzic`` it found was built.  Cyrus needs
    it built with ``TZID_PREFIX="" CREATE_SYMLINK=0 IGNORE_TOP_LEVEL_LINK=0``:

    ``TZID_PREFIX``
        The vendor prefix ``vzic`` writes on every ``TZID``, ``/citadel.org/%D_1/``
        by default.  Cyrus needs bare IANA names, and does not recognise a
        prefixed one.

    ``CREATE_SYMLINK``
        Whether a time zone alias becomes a symlink to the zone it aliases
        rather than a VTIMEZONE of its own.  ``make install`` installs the
        files it finds, so an alias needs its own VTIMEZONE to be installed at
        all.

    ``IGNORE_TOP_LEVEL_LINK``
        Whether to skip the aliases that have no region, such as ``EST5EDT``.
        A ``vzic`` built with ``IGNORE_TOP_LEVEL_LINK=1`` writes no data at all
        for them, and Cyrus cannot tell that from an IANA release that never
        had them.  Build ``vzic`` with ``IGNORE_TOP_LEVEL_LINK=0`` to serve
        those time zones.

The data is indexed by a database whose location is specified by the
:imapdconf:`zoneinfo_db_path` option, using the format specified by the
:imapdconf:`zoneinfo_db` option.

.. _tzdist_administration:

Administration
--------------

The time zone data in :imapdconf:`zoneinfo_dir` is the IANA Time Zone Database
(a.k.a. Olson Database) converted to the iCalendar format.  More than TZDist
reads it: CalDAV and JMAP Calendars expect a VTIMEZONE for every IANA name, and
JMAP Calendars also uses the guessing database built from it to name the custom
time zones that clients send -- see :cyrusman:`cyr_guesstz(8)`.

Cyrus bundles a copy of the database in ``tzdata/`` and converts it during the
build, so a stock build starts out with current data.  What the build cannot do
is keep it current: IANA publishes several releases a year, and installing them
must be done by the packager or the administrator.

Take one of the two routes below, then rebuild the index.

Updating the bundled data
#########################

``tzdata/`` holds one unmodified IANA release.  ``tools/update-tzdata.sh``
replaces it with a newer one -- it downloads the data-only tarball from IANA,
unpacks it over ``tzdata/`` and stages the result -- so that ``make install``
produces the new data from then on::

    tools/update-tzdata.sh 2026d
    make && make install

This is also how the bundled copy gets updated for everybody, so a pull request
with that commit is welcome.

Managing zoneinfo_dir yourself
##############################

If you would rather not have the build touch your time zone data -- configure
with ``--without-vzic`` -- then populate :imapdconf:`zoneinfo_dir` by hand.

`vzic <https://github.com/libical/vzic>`_ converts the IANA TZ DB to iCalendar
format, writing a separate file with its own TZID property for each time zone.
Build it with ``TZID_PREFIX="" CREATE_SYMLINK=0 IGNORE_TOP_LEVEL_LINK=0``, as
:ref:`the note above <tzdist_vzic>` describes.

The steps are:

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

6. Copy the **version** file from the raw data to ``<zoneinfo_dir>``, and
   rebuild the timezone guessing database that JMAP CalendarEvent objects
   use::

       cyr_guesstz -z <zoneinfo_dir> <zoneinfo_dir>/guesstz.db

   See :cyrusman:`cyr_guesstz(8)`.  Skip this if Cyrus was built
   ``--without-guesstz``.

Rebuilding the index
####################

Either route ends here, whether the data came from the build or from your own
``vzic`` run:

1. Rebuild the index by running :cyrusman:`ctl_zoneinfo(8)`::

       ctl_zoneinfo -r <version-string>

   where <version-string> contains a description of the time zone data, a
   colon, and the version of the data, e.g. ``"IANA Time Zone
   Database:2026c"``.  The version Cyrus built with is in the **version** file
   in :imapdconf:`zoneinfo_dir`.

2. Check that the zoneinfo index database and all iCalendar data files/links
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

iSchedule is automatically enabled in Cyrus if both the CalDAV module and the
:imapdconf:`caldav_allowscheduling` options are enabled in a
:ref:`Cyrus Murder <murder>`. In this instance, Cyrus uses iSchedule to move
scheduling messages from frontend to backend servers.

Support for scheduling with external servers is currently under development
as there is the burden of authorization to verify the authenticity and
integrity of these messages to prevent inadvertent or malicious data leaks
or corruption.

What mechanism to use for authorization is under discussion with the `CalConnect
<https://www.calconnect.org/>`_ standards body, whether this is `DKIM
<http://www.dkim.org/>`_ or some other type of message signature.
