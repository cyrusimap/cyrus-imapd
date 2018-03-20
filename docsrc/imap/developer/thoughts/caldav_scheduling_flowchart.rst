.. _imap-developer-thoughts-caldavflow:

..  Note: This document was converted from the original by Nic Bernstein
    (Onlight).  Any formatting mistakes are my fault and not the
    original author's.  Converted via the pandoc tool from HTML.

Cyrus CalDAV Scheduling Flowchart
=================================

caldav\_put() - create/modify via HTTP PUT on a resource or POST (add-member) on a calendar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Check if the new resource is a scheduling resource (contains
   ORGANIZER property). If not, skip to step 4.
#. Check for (and load) any existing resource.
#. Check if the authenticated user matches ORGANIZER:

   -  If yes:

      -  If only voter (VPOLL) responses changed, goto
         `sched\_pollstatus() <#sched_pollstatus>`__.
      -  Otherwise, goto `sched\_request() <#sched_request>`__.

   -  Otherwise, goto `sched\_reply() <#sched_reply>`__.

#. Store the new/modified resource.

caldav\_delete\_sched() - remove via HTTP DELETE on a resource
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Check if the existing resource is a scheduling resource (has
   Schedule-Tag). If not, we are done.
#. Load the existing resource.
#. Check if the authenticated user matches ORGANIZER. If yes, goto
   `sched\_request() <#sched_request>`__, otherwise goto
   `sched\_reply() <#sched_reply>`__.

caldav\_post() - busytime query via HTTP POST on Scheduling Outbox
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Check the ACL on the owner's Scheduling Outbox. If the authenticated
   user doesn't have the DACL\_SCHEDFB right, fail.
#. `sched\_busytime\_query() <#sched_busytime_query>`__.

--------------

sched\_pollstatus - perform a voter response update
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#.

--------------

sched\_request() - perform an organizer request / attendee status update
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Check the ACL on the owner's Scheduling Outbox. If the authenticated
user doesn't have the DACL\_INVITE right, fail.

If the request includes a resource, then set METHOD:REQUEST, otherwise
set METHOD:CANCEL.

Create an iTIP message template, copying over any CALSCALE property and
VTIMEZONE components.

If not an attendee status update and the existing resource is a
scheduling resource: Foreach component in the existing resource, add it
and its SEQUENCE to our hash table keyed by RECURRENCE-ID (for
comparison against new/modified resource).

Create a hash table of attendees. This will hold attendee-specific iTIP
messages.

Foreach component in the new/modified resource:

a. Lookup (by RECURRENCE-ID) and remove the component from the hash
   table of existing components.
b. If the component exists compare all of DTSTART, DTEND, DURATION,
   RRULE, RDATE, EXDATE to those of the new component.
c. If the component is new or changed, then
   `process\_attendees() <#process_attendees>`__.

Foreach remaining component in the hash table of existing components do
`sched\_cancel() <#sched_cancel>`__.

Foreach iTIP message in our hash table of ATTENDEES,
`sched\_deliver() <#sched_deliver>`__ the iTIP message.

Foreach component in the new/modified resource update the
SCHEDULE-STATUS of each ATTENDEE.

process\_attendees() - create a suitable iTIP request message for each attendee
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Foreach ATTENDEE in the component, remove the SCHEDULE-STATUS parameter,
and set PROPSTAT=NEEDS-ACTION if required.

Make a copy of the component and
`clean\_component() <#clean_component>`__.

Foreach ATTENDEE in the cleaned component:

a. Check the CalDAV Scheduling parameters. If SCHEDULE-AGENT != SERVER,
   skip to the next attendee.
b. Lookup attendee in our hash table.
c. If it doesn't exist, create a clone of our iTIP template and insert
   it into our hash table of attendees.
d. Add the component to the attendee's iTIP message.
e. Add the component “number” to our mask of new components appearing in
   the attendee's iTIP message.

If the component is not the "master", foreach attendee do
`sched\_exclude() <#sched_exclude>`__.

sched\_exclude() - exclude an attendee from a recurrence instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. If the component did not appear in the attendee's iTIP message, add
   an EXDATE property (based on the RECURRENCE-ID of the component) to
   the master component of the attendee's iTIP message.

sched\_cancel() - cancel an organizer event/task
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Set STATUS:CANCELLED on the component.
#. `process\_attendees() <#process_attendees>`__.

--------------

sched\_reply() - perform an attendee reply
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Check the CalDAV Scheduling parameters on ORGANIZER. If SCHEDULE-AGENT
!= SERVER, we are done.

Check the ACL on the owner's Scheduling Outbox. If the authenticated
user doesn't have the DACL\_REPLY right, fail.

Create a new iTIP (METHOD:REPLY) message, copying over any CALSCALE
property and VTIMEZONE components.

Foreach component in the existing resource:

a. `trim\_attendees() <#trim_attendees>`__.
b. Add the trimmed component and the attendee's PARTSTAT to our hash
   table keyed by RECURRENCE-ID (for comparison against new/modified
   resource).

Foreach component in the new/modified resource:

`trim\_attendees() <#trim_attendees>`__.

Lookup (by RECURRENCE-ID) and remove the component from the hash table
of existing components.

If the component exists:

i.  If component is VPOLL, add voter responses to REPLY via
    `sched\_vpoll\_reply(). <#sched_vpoll_reply>`__
ii. Otherwise, compare the PARTSTAT of the ATTENDEE to that of the new
    component.

If the component is new or the PARTSTAT has changed:

i.   `clean\_component() <#clean_component>`__.
ii.  Add the component to our iTIP message.
iii. Add the component “number” to our mask of new components appearing
     in our iTIP message.

Foreach remaining component in the hash table of existing components do
`sched\_decline() <#sched_decline>`__.

`sched\_deliver() <#sched_deliver>`__ our iTIP message.

Foreach component in the new/modified resource that appeared in our iTIP
message, update the SCHEDULE-STATUS of the ORGANIZER.

trim\_attendees() - remove all attendees other than the one replying
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Clone the component and remove all ATTENDEE properties other than the
   one corresponding to the owner of the calendar.
#. Return the ATTENDEE property of owner, his/her PARTSTAT parameter,
   and the RECURRENCE-ID of the component.

sched\_vpoll\_reply() - add voter responses to VPOLL reply
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#.

sched\_decline() - decline a recurrence instance for an attendee
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Set PARTSTAT of ATTENDEE to DECLINED.
#. `clean\_component() <#clean_component>`__.
#. Add the component to our iTIP message.

--------------

clean\_component() - sanitize a component for use in an iTIP message
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Update DTSTAMP.
#. Remove any VALARM components.
#. For a reply/decline only, remove scheduling parameters from
   ORGANIZER.

sched\_deliver() - deliver an iTIP message to a recipient
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Lookup the recipient.
#. If local to our server goto
   `sched\_deliver\_local() <#sched_deliver_local>`__, otherwise goto
   `sched\_deliver\_remote() <#sched_deliver_remote>`__.

--------------

sched\_deliver\_local() - deliver an iTIP message to a local user
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Check the ACL on the owner's Scheduling Inbox. If the sender doesn't
have the proper right (DACL\_INVITE for request/cancel, DACL\_REPLY for
reply), fail.

Search the recipient's calendars for a resource having the specified
UID.

If the resource doesn't exist:

a. If the iTIP method is REPLY, fail (we are done).
b. If the iTIP method is CANCEL, ignore it (we are done).
c. Otherwise, create a new (empty) attendee object and target the
   recipient's Default calendar.

Otherwise, load the existing resource.

Update the new/existing resource:

a. If the iTIP method is CANCEL, set STATUS:CANCELLED on all existing
   components.
b. If the iTIP method is REPLY, do
   `deliver\_merge\_reply() <#deliver_merge_reply>`__.
c. If the iTIP method is REQUEST, do
   `deliver\_merge\_request() <#deliver_merge_request>`__.
d. If the iTIP method is POLLSTATUS, do
   `deliver\_merge\_pollstatus() <#deliver_merge_pollstatus>`__.

Store the new/updated resource in the recipient's target calendar.

Record the delivery status (SCHEDULE-STATUS).

If the iTIP message is something other than just a PARTSTAT update from
an attendee, store the iTIP message as a new resource in the recipient's
Inbox.

If the iTIP method is REPLY, send an update other attendees via
`sched\_pollstatus() <#sched_pollstatus>`__ (VPOLL only) or
`sched\_request() <#sched_request>`__.

deliver\_merge\_reply() - update an organizer resource with an attendee reply
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Foreach component in the existing resource, add it to our hash table
keyed by RECURRENCE-ID (for comparison against iTIP message).

Foreach component in the iTIP message:

Lookup (by RECURRENCE-ID) the component from the hash table of existing
components.

If the component doesn't exist (new recurrence overridden by ATTENDEE)
create a new recurring component:

i.   Clone the existing master component.
ii.  Remove the RRULE property.
iii. Add the RECURRENCE-ID from the iTIP message.
iv.  Replace the DTSTART, DTEND, SEQUENCE properties with those from the
     iTIP message.
v.   Add the new component to our existing resource.

Get the sending ATTENDEE from the iTIP message.

Find the matching ATTENDEE in the existing component.

If not found (ATTENDEE added themselves to this recurrence), add new
ATTENDEE to the component.

Set the ATTENDEE PARTSTAT, RSVP, and SCHEDULE-STATUS parameters in the
existing component.

If the component is VPOLL, update the voter responses in the existing
component via
`deliver\_merge\_vpoll\_reply() <#deliver_merge_vpoll_reply>`__.

Return the sending ATTENDEE.

deliver\_merge\_vpoll\_reply() - update an organizer resource with voter responses
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Foreach sub-component in the existing resource, replace any voter
   response(s) with those from the reply.

deliver\_merge\_request() - create/update an attendee resource with an organizer request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Foreach VTIMEZONE component in the existing resource, add it to our hash
table keyed by TZID (for comparison against iTIP message).

Foreach VTIMEZONE component in the iTIP message:

a. Lookup (by TZID) the VTIMEZONE component from the hash table of
   existing components.
b. If the component exists, remove it from the existing object.
c. Add the VTIMEZONE from the iTIP message to our existing object.

Foreach component in the existing resource, add it to our hash table
keyed by RECURRENCE-ID (for comparison against iTIP message).

Foreach component in the iTIP message:

Clone a new component from the iTIP component.

Lookup (by RECURRENCE-ID) the component from the hash table of existing
components.

If the component exists:

i.   Compare the SEQUENCE of the new component to the existing component
     to see if it has changed.
ii.  Copy any COMPLETED, PERCENT-COMPLETE, or TRANSP properties from the
     existing component to the new component.
iii. Copy any ORGANIZER SCHEDULE-STATUS parameter from the existing
     component to the new component.
iv.  Remove the existing component from the existing object.

Add the new component to the existing object.

deliver\_merge\_pollstatus() - update voter responses on a voter resource
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Foreach sub-component in the existing resource, add it to our hash table
keyed by POLL-ITEM-ID (for comparison against iTIP message). The
sub-component entry includes a hash table of VOTERs.

Foreach sub-component in the iTIP message:

a. Lookup (by POLL-ITEM-ID) the sub-component from the hash table of
   existing sub-components.
b. If the component exists, foreach VOTER in the sub-component in the
   iTIP message:

   i.  Lookup VOTER in the hash table of existing sub-component.
   ii. Add/update VOTER response.

--------------

sched\_deliver\_remote() - deliver an iTIP message to a remote user
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. If the recipient is local to our Murder, goto
   `isched\_send() <#isched_send>`__, otherwise goto
   `imip\_send() <#imip_send>`__.
#. Retrieve status of iTIP message delivery.

isched\_send() - deliver an iTIP message to a remote user via iSchedule (HTTP)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

imip\_send() - deliver an iTIP message to a remote user via iMIP (SMTP)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

sched\_busytime\_query() - perform a busytime query
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

busytime\_query\_local() - perform a busytime query on a local user
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

busytime\_query\_remote() - perform a busytime query on a remote user
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
